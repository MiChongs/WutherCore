//! proxy-core —— RPKernel 顶层 CLI。
//!
//! 子命令：
//! * `run -c <yaml>`：启动内核（Mixed 入站 + API + capture 诊断）。
//! * `check <yaml>`：仅做配置加载与编译，输出错误。
//! * `explain <yaml>`：输出编译后的 RuntimePlan（JSON，便于排错）。
//! * `migrate mihomo <old.yaml> -o <friendly.yaml>`：旧配置迁移。

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use core_api::ApiServer;
use core_config::loader::load_from_path;
use core_feeds::{FeedDiskCache, FeedManager, FeedSink, FeedUpdate};
use core_store::Store;
use core_ruleset::{RulesetManager, RulesetSpec, RulesetType};
use core_inbound::run_mixed;
use core_inbound::MixedListener;
use core_inbound::ensure_best_effort_privilege;
use core_runtime::{Runtime, UrlTestConfig, UrlTester};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "proxy-core", version, about = "RPKernel —— Friendly YAML 代理内核")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// 启动内核（前台运行）。
    Run {
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
    },
    /// 仅做配置校验。
    Check { config: PathBuf },
    /// 输出编译后的 RuntimePlan（JSON）。
    Explain { config: PathBuf },
    /// 配置迁移工具。
    Migrate {
        /// 源配置类型，目前支持 `mihomo`。
        kind: String,
        /// 输入文件路径。
        input: PathBuf,
        /// 输出 Friendly YAML 路径。
        #[arg(short, long)]
        output: PathBuf,
    },
    /// 订阅相关操作。
    Feeds {
        #[command(subcommand)]
        action: FeedsCmd,
    },
    /// 持久化 store 操作（节点学习数据、domain_best、pin、group manual 等）。
    Store {
        #[command(subcommand)]
        action: StoreCmd,
    },
    /// 外部规则集操作（mihomo yaml/txt/list、sing-box json、自定义 payload）。
    Ruleset {
        #[command(subcommand)]
        action: RulesetCmd,
    },
}

#[derive(Subcommand, Debug)]
enum RulesetCmd {
    /// 列出配置中所有规则集。
    List { config: PathBuf },
    /// 立刻拉取并解析所有规则集，输出条目数与匹配器统计。
    Refresh {
        config: PathBuf,
        #[arg(long, default_value = "data/rulesets")]
        cache_dir: PathBuf,
    },
    /// 双向转换：yaml/txt/list/json/rrs 互转（含 RPKernel 自研 RRS）。
    ///
    /// 例：
    ///   proxy-core ruleset convert geosite-cn.yaml geosite-cn.rrs
    ///   proxy-core ruleset convert ruleset.json ruleset.txt
    ///   proxy-core ruleset convert input.rrs output.yaml --output-format yaml
    Convert {
        /// 输入文件路径。
        input: PathBuf,
        /// 输出文件路径；输出格式按扩展名自动识别，可被 --output-format 覆盖。
        output: PathBuf,
        /// 显式指定输入格式（yaml/txt/json/rrs/mrs/srs）；缺省时自动嗅探。
        #[arg(long)]
        input_format: Option<String>,
        /// 显式指定输出格式（yaml/txt/json/rrs）；缺省时按 output 扩展名。
        #[arg(long)]
        output_format: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum StoreCmd {
    /// 显示 store 路径、大小与各表行数。
    Info {
        #[arg(long, default_value = "data/state/rpkernel.redb")]
        path: PathBuf,
    },
    /// 清空所有学习数据（保留 schema 版本）。
    Reset {
        #[arg(long, default_value = "data/state/rpkernel.redb")]
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum FeedsCmd {
    /// 列出配置中所有订阅源。
    List { config: PathBuf },
    /// 立刻拉取并解析所有订阅，输出节点统计；不启动内核。
    Refresh {
        config: PathBuf,
        /// 缓存目录（默认 ./data/feeds）
        #[arg(long, default_value = "data/feeds")]
        cache_dir: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    // 进程级 rustls 加密提供者注册 —— **必须在任何 ClientConfig::builder() 调用之前**。
    // rustls 0.23 在多个依赖（quinn / hickory-resolver / reqwest）同时启用时，
    // 全局默认 CryptoProvider 会变得"模糊"：未显式安装时 builder() 会 panic
    // ("no process-level CryptoProvider available")，所有 TLS 出站直接死锁，
    // URLTest 的现象就是 30 个节点全 5005ms 超时。
    // 使用 ring 作为唯一安装的提供者；已安装时返回 Err，忽略即可。
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 早期初始化（无 LogBus）—— 让 CLI 子命令也能打日志；
    // run 子命令在 Runtime 构造后会再 init_with_bus 接到 /logs WS。
    core_observe::init_tracing();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { config } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(cmd_run(config))
        }
        Cmd::Check { config } => cmd_check(config),
        Cmd::Explain { config } => cmd_explain(config),
        Cmd::Migrate { kind, input, output } => cmd_migrate(kind, input, output),
        Cmd::Feeds { action } => {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(cmd_feeds(action))
        }
        Cmd::Store { action } => cmd_store(action),
        Cmd::Ruleset { action } => {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(cmd_ruleset(action))
        }
    }
}

async fn cmd_ruleset(action: RulesetCmd) -> anyhow::Result<()> {
    match action {
        RulesetCmd::List { config } => {
            let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
            if plan.route.sets.is_empty() {
                println!("配置中未声明 route.sets");
                return Ok(());
            }
            for (name, s) in &plan.route.sets {
                let src = s
                    .url
                    .clone()
                    .or_else(|| s.path.clone())
                    .unwrap_or_else(|| format!("payload({} 行)", s.payload.len()));
                println!(
                    "{name:>20}  type={}  format={}  every={:?}  src={}",
                    s.r#type,
                    s.format.as_deref().unwrap_or("auto"),
                    s.every,
                    src
                );
            }
            Ok(())
        }
        RulesetCmd::Refresh { config, cache_dir } => {
            let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
            if plan.route.sets.is_empty() {
                println!("配置中未声明 route.sets");
                return Ok(());
            }
            let specs = build_ruleset_specs(&plan.route.sets);
            let idx = core_ruleset::RulesetIndex::new();
            let mgr = RulesetManager::new(specs.clone(), Some(cache_dir), idx.clone());
            for (name, spec) in &specs {
                match mgr.refresh_once(name, spec).await {
                    Ok(u) => {
                        println!(
                            "{name:>20}  {} 条 {}",
                            u.size,
                            if u.from_cache { "(cache)" } else { "(online)" }
                        );
                        if let Some(m) = idx.get(name) {
                            let s = m.stats();
                            println!(
                                "    domains={} suffixes={} keywords={} regex={} cidr_v4={} cidr_v6={} ports={} processes={}",
                                s.domains, s.suffixes, s.keywords, s.regex, s.cidr_v4, s.cidr_v6, s.ports, s.processes
                            );
                        }
                    }
                    Err(e) => println!("{name:>20}  FAILED: {e}"),
                }
            }
            Ok(())
        }
        RulesetCmd::Convert { input, output, input_format, output_format } => {
            let body = std::fs::read(&input).context("read input")?;
            let in_path = input.to_string_lossy().to_string();
            let in_fmt = core_ruleset::detect_format(input_format.as_deref(), Some(&in_path), &body);
            let entries = core_ruleset::parse_ruleset(in_fmt, &body)
                .map_err(|e| anyhow::anyhow!("解析失败 ({:?}): {e}", in_fmt))?;
            let out_fmt = output_format
                .as_deref()
                .or_else(|| output.extension().and_then(|e| e.to_str()))
                .unwrap_or("rrs")
                .to_ascii_lowercase();
            let out_bytes: Vec<u8> = match out_fmt.as_str() {
                "rrs" | "rpkernel" => core_ruleset::rrs::encode(&entries),
                "yaml" | "yml" => core_ruleset::rrs::entries_to_yaml(&entries).into_bytes(),
                "txt" | "list" | "text" => core_ruleset::rrs::entries_to_txt(&entries).into_bytes(),
                "json" | "singbox" | "sing-box" => {
                    core_ruleset::rrs::entries_to_singbox_json(&entries).into_bytes()
                }
                other => anyhow::bail!(
                    "不支持的输出格式 \"{other}\"；支持：yaml / txt / json / rrs"
                ),
            };
            std::fs::write(&output, &out_bytes).context("write output")?;
            println!(
                "已转换：{} ({}) → {} ({}) | {} 条规则 | 输入 {} bytes → 输出 {} bytes",
                input.display(),
                format_label(in_fmt),
                output.display(),
                out_fmt,
                entries.len(),
                body.len(),
                out_bytes.len()
            );
            Ok(())
        }
    }
}

/// 把 [`core_config::model::RuleSetSpec`]（YAML 反序列化产物）翻译成
/// [`core_ruleset::RulesetSpec`] —— `cmd_ruleset` Refresh 子命令与 `cmd_run`
/// 启动路径共用此函数，避免字段对应散落两份。
fn build_ruleset_specs(
    sets: &std::collections::BTreeMap<String, core_config::model::RuleSetSpec>,
) -> std::collections::BTreeMap<String, RulesetSpec> {
    sets.iter()
        .map(|(name, s)| {
            let typ = match s.r#type.to_ascii_lowercase().as_str() {
                "ipcidr" | "ip" => RulesetType::Ipcidr,
                "classical" => RulesetType::Classical,
                "mixed" => RulesetType::Mixed,
                _ => RulesetType::Domain,
            };
            (
                name.clone(),
                RulesetSpec {
                    url: s.url.clone(),
                    path: s.path.clone(),
                    payload: s.payload.clone(),
                    r#type: typ,
                    format: s.format.clone(),
                    every: s.every,
                    via: s.via.clone(),
                },
            )
        })
        .collect()
}

fn format_label(f: core_ruleset::RulesetFormat) -> &'static str {
    use core_ruleset::RulesetFormat::*;
    match f {
        Yaml => "yaml",
        Text => "txt",
        SingboxJson => "json",
        Mrs => "mrs",
        Srs => "srs",
        Rrs => "rrs",
        Unknown => "?",
    }
}

fn cmd_store(action: StoreCmd) -> anyhow::Result<()> {
    match action {
        StoreCmd::Info { path } => {
            if !path.exists() {
                println!("store 不存在：{}", path.display());
                return Ok(());
            }
            let s = Store::open(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
            let st = s.approximate_stats().map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("store: {}", st.path);
            println!("  size:              {} bytes", st.size_bytes);
            println!("  smart_node_stats:  {}", st.smart_node_stats);
            println!("  smart_domain_best: {}", st.smart_domain_best);
            println!("  smart_negative:    {}", st.smart_negative);
            println!("  smart_pin:         {}", st.smart_pin);
            println!("  group_manual:      {}", st.group_manual);
            println!("  feed_meta:         {}", st.feed_meta);
            Ok(())
        }
        StoreCmd::Reset { path } => {
            if !path.exists() {
                println!("store 不存在：{}", path.display());
                return Ok(());
            }
            let s = Store::open(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
            s.reset().map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("已清空所有学习数据：{}", path.display());
            Ok(())
        }
    }
}

async fn cmd_feeds(action: FeedsCmd) -> anyhow::Result<()> {
    match action {
        FeedsCmd::List { config } => {
            let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
            for (name, d) in &plan.feeds {
                println!(
                    "{name:>20}  url={}  every={:?}  via={}",
                    d.url, d.every, d.via
                );
            }
            Ok(())
        }
        FeedsCmd::Refresh { config, cache_dir } => {
            let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
            if plan.feeds.is_empty() {
                println!("配置中没有 feeds，跳过");
                return Ok(());
            }
            let cache = FeedDiskCache::new(&cache_dir).context("create feed cache")?;
            let mgr = FeedManager::new(plan.feeds.clone(), Some(cache));
            for (name, detail) in &plan.feeds {
                match mgr
                    .refresh_once(name, detail, std::time::Duration::from_secs(30))
                    .await
                {
                    Ok(update) => {
                        println!(
                            "{name:>20}  {} 个节点  {} bytes  {}",
                            update.nodes.len(),
                            update.raw_bytes,
                            if update.from_cache { "(disk-cache)" } else { "(online)" }
                        );
                        for n in update.nodes.iter().take(5) {
                            println!("    - {} [{}://{}:{}]", n.name, n.protocol.as_str(), n.host, n.port);
                        }
                        if update.nodes.len() > 5 {
                            println!("    ... 还有 {} 个", update.nodes.len() - 5);
                        }
                    }
                    Err(e) => println!("{name:>20}  FAILED: {e}"),
                }
            }
            Ok(())
        }
    }
}

fn cmd_check(config: PathBuf) -> anyhow::Result<()> {
    let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("OK: {} 节点 / {} 分组 / {} 条规则",
        plan.nodes.len(), plan.groups.len(), plan.route.steps.len());
    Ok(())
}

fn cmd_explain(config: PathBuf) -> anyhow::Result<()> {
    let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{}", serde_json::to_string_pretty(&plan)?);
    Ok(())
}

fn cmd_migrate(kind: String, input: PathBuf, output: PathBuf) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(&input).context("read input")?;
    let friendly = match kind.as_str() {
        "mihomo" | "clash" => core_config::migrate::migrate_mihomo(&text)
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        other => anyhow::bail!("尚不支持的迁移源: {other}（目前支持 mihomo）"),
    };
    std::fs::write(&output, friendly).context("write output")?;
    println!("已写入 {}", output.display());
    Ok(())
}

async fn cmd_run(config: PathBuf) -> anyhow::Result<()> {
    let plan = load_from_path(&config).map_err(|e| anyhow::anyhow!("{e}"))?;
    info!(name = %plan.name, profile = ?plan.profile, "config loaded");

    // 启动钩子：检测特权 + Android 优先尝试 su 提权再降级。
    let priv_report = ensure_best_effort_privilege().await;
    if !priv_report.is_elevated() {
        warn!(
            target: "privilege",
            "running unprivileged: low ports / TUN / route changes will be limited"
        );
    }

    // 诊断 capture / mesh
    match core_capture::diagnose(&plan.capture, &plan.mesh) {
        Ok(report) => info!(target: "capture", report = ?report, "diagnose"),
        Err(e) => warn!(target: "capture", error = %e, "diagnose failed"),
    }
    info!(target: "mesh", "{}", core_mesh::diagnose(&plan.mesh));

    // 打开持久化 store（默认 data/state/rpkernel.redb）。
    let store = match Store::open("data/state/rpkernel.redb") {
        Ok(s) => {
            info!(target: "store", path = %s.path().display(), "store opened");
            Some(s)
        }
        Err(e) => {
            warn!(target: "store", error = %e, "store open failed; running in-memory only");
            None
        }
    };

    // 先建好共享的 RulesetIndex —— 让 RouteEngine（runtime 内）与 capture
    // supervisor 共用同一份索引；下方的 RulesetManager 会往里灌编译好的
    // RulesetMatcher。
    let ruleset_index = core_ruleset::RulesetIndex::new();

    let runtime = Arc::new(Runtime::build_with(
        plan.clone(),
        store,
        Some(ruleset_index.clone()),
    ));

    // 用 LogBus 重新初始化 tracing layer —— 让 /v1/logs 与 Clash 兼容 /logs WS 流式输出。
    // try_init 内部对重复初始化是 no-op，所以早期 fmt layer 仍生效，
    // 我们这里再追加 BusLayer。
    core_observe::init_tracing_with_bus(Some(runtime.logs.clone()));

    // RulesetManager —— 把配置 route.sets 翻成 core-ruleset 的 RulesetSpec
    // 并启动后台轮询拉取。这一步必须在 runtime / capture 之间，确保启动 INFO
    // 日志能看到全部规则集。之前缺少这步会导致 set:geoip-cn 等规则永远不命中。
    let _ruleset_mgr_handle = {
        let specs = build_ruleset_specs(&plan.route.sets);
        let count = specs.len();
        let cache_dir = std::path::PathBuf::from("data/ruleset");
        let mgr =
            RulesetManager::new(specs, Some(cache_dir.clone()), ruleset_index.clone());
        mgr.clone().start();
        if count == 0 {
            info!(target: "ruleset", "no route.sets configured; manager idle");
        } else {
            info!(
                target: "ruleset",
                count,
                cache_dir = %cache_dir.display(),
                "ruleset manager started (initial fetch + periodic refresh in background)"
            );
        }
        mgr
    };

    // URLTest：默认每分钟周期探测全部出站（DIRECT/BLOCK 跳过）。
    let urltest = UrlTester::new(UrlTestConfig::default());
    runtime.set_urltest(urltest.clone());
    let _urltest_handle = core_runtime::spawn_periodic(
        urltest.clone(),
        runtime.clone(),
        std::time::Duration::from_secs(60),
    );

    // 始终创建 FeedManager —— 即便 feeds 为空，dashboard 的 /providers/proxies
    // 仍能拿到一致的（空）provider 列表；start() 在空配置下是 noop，不 spawn 任何 task。
    let feed_mgr_handle = {
        let cache = FeedDiskCache::new("data/feeds").ok();
        let mgr = FeedManager::new(plan.feeds.clone(), cache);
        mgr.set_sink(Arc::new(RuntimeFeedSink { runtime: runtime.clone() }));
        let m = mgr.clone();
        m.start();
        if plan.feeds.is_empty() {
            info!(target: "feeds", "no feeds configured; manager idle");
        } else {
            info!(target: "feeds", count = plan.feeds.len(), "feed manager started (auto-fetch on schedule)");
        }
        mgr
    };

    // 启动 capture supervisor（如果配置开启）—— 复用上面建好的 ruleset_index。
    let mut capture_handle: Option<Arc<core_capture::CaptureSupervisor>> = None;
    match core_capture::CaptureSupervisor::build(&plan.capture, &plan.mesh) {
        Ok(Some(sup)) => {
            // 注入 IpSetProvider，把 ruleset 的 cidr_v4/cidr_v6 暴露给 supervisor.allow_ip。
            sup.set_ip_set_provider(Arc::new(RulesetIpSetProvider {
                index: ruleset_index.clone(),
            }));
            if let Err(e) = sup.start(runtime.clone()).await {
                warn!(target: "capture", error = %e, "capture supervisor start failed");
            } else {
                capture_handle = Some(sup);
            }
        }
        Ok(None) => {}
        Err(e) => warn!(target: "capture", error = %e, "capture supervisor build failed"),
    }

    let mut handles = Vec::new();

    // Mixed 入站
    if let Some(mixed) = &plan.listen.mixed {
        let addr = mixed.socket_addr().map_err(|e| anyhow::anyhow!("{e}"))?;
        let auth = if plan.listen.auth.is_empty() {
            None
        } else {
            Some(plan.listen.auth.clone())
        };
        let listener = MixedListener { listen: addr, auth };
        let rt = runtime.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_mixed(listener, rt).await {
                warn!(target: "inbound", error = %e, "mixed listener exited");
            }
        }));
        info!(addr = %addr, "mixed inbound: HTTP+SOCKS5 ready");
    } else {
        info!("listen.local 未配置，跳过 Mixed 入站");
    }

    // 控制面板/API
    if plan.ui.on {
        if let Some(panel) = &plan.listen.panel {
            let addr = panel.socket_addr().map_err(|e| anyhow::anyhow!("{e}"))?;
            let server = ApiServer {
                addr,
                runtime: runtime.clone(),
                secret: plan.ui.secret.clone(),
                clash_compat: plan.ui.api.clash_compat,
                urltest: urltest.clone(),
                capture: capture_handle.clone(),
                feeds: Some(feed_mgr_handle.clone()),
            };
            handles.push(tokio::spawn(async move {
                if let Err(e) = server.run().await {
                    warn!(target: "api", error = %e, "api server exited");
                }
            }));
            info!(addr = %addr, "api server ready (/v1 + clash-compat)");
        }
    }

    info!("RPKernel started, press Ctrl-C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("shutdown signal, bye.");
    if let Some(sup) = capture_handle {
        if let Err(e) = sup.stop().await {
            warn!(target: "capture", error = %e, "capture stop failed");
        }
    }
    feed_mgr_handle.stop();
    runtime.shutdown().await;
    for h in handles {
        h.abort();
    }
    Ok(())
}

/// 把 [`core_ruleset::RulesetIndex`] 适配为 [`core_capture::IpSetProvider`]。
///
/// `route_address_set: ["geoip-cn"]` → 查 ruleset_index 的 `geoip-cn`，
/// 命中 cidr_v4 / cidr_v6 即视为白/黑名单元素。
#[derive(Debug)]
struct RulesetIpSetProvider {
    index: Arc<core_ruleset::RulesetIndex>,
}

impl core_capture::IpSetProvider for RulesetIpSetProvider {
    fn contains(&self, name: &str, ip: std::net::IpAddr) -> bool {
        let Some(matcher) = self.index.get(name) else {
            return false;
        };
        matcher.matches("", Some(ip), None, None)
    }
    fn names(&self) -> Vec<String> {
        self.index.names()
    }
}

/// FeedSink 实现：把订阅刷新结果直接交给 Runtime 注册。
struct RuntimeFeedSink {
    runtime: Arc<Runtime>,
}

#[async_trait]
impl FeedSink for RuntimeFeedSink {
    async fn on_update(&self, update: FeedUpdate) {
        self.runtime.apply_feed_nodes(&update.name, update.nodes);
    }
}
