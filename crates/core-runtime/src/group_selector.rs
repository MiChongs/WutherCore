//! 策略组 —— 完整对齐 mihomo `adapter/outboundgroup/*.go` 的 7 种策略：
//!
//! | mihomo type           | WutherCore ChooseStrategy        | 行为                                                 |
//! |-----------------------|--------------------------------|------------------------------------------------------|
//! | `select`              | `Manual`                       | 用户/API 选择；alive fallback                        |
//! | `url-test`            | `Smart` / `Fast`               | URLTest 最低延迟 + tolerance + singledo              |
//! | `fallback`            | `Stable`                       | 顺序找首个 alive；fixed 选择优先                     |
//! | `load-balance`        | `Spread`                       | consistent-hashing / round-robin / sticky-sessions   |
//! | `relay` (chain)       | `Chain`                        | 按 path 顺序拼链                                     |
//!
//! ## 关键能力（与 mihomo 等价）
//!
//! * `filter` / `exclude_filter` 正则数组（多条用 backtick 分隔）
//! * `exclude_type` 协议黑名单（`http|https`）
//! * 每流 `FlowMeta { host, src_ip, dst_ip }` 用作 LB key（src+dst 哈希）
//! * `onDialFailed` / `onDialSuccess` —— 累计 `failed_times`，超过 `max_failed_times`
//!   且时间窗内 → 触发 `health_check_now()`（外部 URLTester 接管）
//! * 死节点感知：所有策略统一调 `tester.alive_for_url()` 跳过 dead
//! * `MarshalJSON`：与 Clash dashboard `/proxies/<group>` 一致字段
//!   `{ type, now, all, testUrl, expectedStatus, fixed, hidden, icon, strategy? }`

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::AHasher;
use core_config::model::ChooseStrategy;
use core_config::runtime_plan::GroupPlan;
use core_smart::{SmartContext, SmartSelector};
use parking_lot::{Mutex, RwLock};
use regex::Regex;
use tracing::debug;

use crate::health::UrlTester;

/* ============================================================
FlowMeta：策略组选点的输入上下文
============================================================ */

/// 一次 dial 的元数据 —— LoadBalance / Smart 等需要 host / src 用作 hash key。
#[derive(Debug, Clone, Default)]
pub struct FlowMeta {
    /// 目标 host（域名优先；纯 IP 时退化为 IP literal）
    pub host: String,
    /// 已解析过的 IP literal（fake-ip / 真实 IP 都行）；可选
    pub dst_ip: Option<std::net::IpAddr>,
    /// 入站客户端来源（用于 sticky-sessions）；可选
    pub src_ip: Option<std::net::IpAddr>,
    /// 目标端口
    pub port: u16,
    /// "tcp" / "udp"
    pub network: &'static str,
}

impl FlowMeta {
    pub fn for_host(host: impl Into<String>, port: u16, network: &'static str) -> Self {
        Self {
            host: host.into(),
            dst_ip: None,
            src_ip: None,
            port,
            network,
        }
    }
    /// 用于 LB key —— mihomo `getKey(metadata)`：host 是 IP 取 IP；
    /// 否则取 eTLD+1（这里简化为最后两段 dot 子串）。
    pub fn lb_key(&self) -> String {
        if self.host.is_empty() {
            return self.dst_ip.map(|i| i.to_string()).unwrap_or_default();
        }
        if self.host.parse::<std::net::IpAddr>().is_ok() {
            return self.host.clone();
        }
        etld_plus_one(&self.host)
    }
    /// 用于 sticky-sessions key —— mihomo `getKeyWithSrcAndDst`：src+dst。
    pub fn lb_key_sticky(&self) -> String {
        let dst = self.lb_key();
        let src = self.src_ip.map(|i| i.to_string()).unwrap_or_default();
        format!("{src}{dst}")
    }
}

/// 极简 eTLD+1：取最后两段（`.cn` / `.uk` 等二级公共后缀这里不展开，与 mihomo
/// 在没有 publicsuffix 数据库的情况下行为略有差异，但对 LB hash 不影响命中）。
fn etld_plus_one(host: &str) -> String {
    let h = host.trim_end_matches('.');
    let parts: Vec<&str> = h.rsplitn(3, '.').collect();
    if parts.len() <= 2 {
        return h.to_string();
    }
    format!("{}.{}", parts[1], parts[0])
}

/* ============================================================
GroupOptions：扩展 GroupPlan 用不上的 mihomo 选项
============================================================ */

/// 与 mihomo `GroupCommonOption` 同语义的运行期选项。
/// 从 `GroupPlan` 派生默认值；未来可由 YAML schema 注入。
#[derive(Debug, Clone)]
pub struct GroupOptions {
    /// 默认探测 URL（覆盖 UrlTester::default_url 用）
    pub url: Option<String>,
    /// expected-status 表达式（"200/204/401-429"），空则任意
    pub expected_status: String,
    /// LoadBalance 策略：`consistent-hashing` / `round-robin` / `sticky-sessions`
    pub lb_strategy: LbStrategy,
    /// URLTest tolerance（毫秒）
    pub tolerance: u32,
    /// 节点名 filter 正则；多条用 backtick "`" 分隔
    pub filter: String,
    /// 节点名 exclude_filter 正则
    pub exclude_filter: String,
    /// 协议黑名单：`http|https|direct`
    pub exclude_type: String,
    /// `onDialFailed` 累计阈值
    pub max_failed_times: u32,
    /// 累计失败时间窗（毫秒）
    pub test_timeout_ms: u64,
    /// 是否禁用 UDP（disable-udp）
    pub disable_udp: bool,
    /// 仅 dashboard 显示用
    pub hidden: bool,
    pub icon: String,
}

impl Default for GroupOptions {
    fn default() -> Self {
        Self {
            url: None,
            expected_status: String::new(),
            lb_strategy: LbStrategy::ConsistentHashing,
            tolerance: 50,
            filter: String::new(),
            exclude_filter: String::new(),
            exclude_type: String::new(),
            max_failed_times: 5,
            test_timeout_ms: 5_000,
            disable_udp: false,
            hidden: false,
            icon: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbStrategy {
    ConsistentHashing,
    RoundRobin,
    StickySessions,
}

impl LbStrategy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "consistent-hashing" | "consistent_hashing" => Some(Self::ConsistentHashing),
            "round-robin" | "round_robin" => Some(Self::RoundRobin),
            "sticky-sessions" | "sticky_sessions" => Some(Self::StickySessions),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConsistentHashing => "consistent-hashing",
            Self::RoundRobin => "round-robin",
            Self::StickySessions => "sticky-sessions",
        }
    }
}

/* ============================================================
GroupBase：成员过滤 + onDialFailed/Success + healthCheck 调度
============================================================ */

#[derive(Debug, Default)]
struct FailureWindow {
    times: AtomicI32,
    first_at_ms: parking_lot::Mutex<Option<Instant>>,
    health_checking: parking_lot::Mutex<bool>,
}

/// LB 状态机 —— round-robin 索引、sticky-sessions LRU。
#[derive(Debug)]
struct LbState {
    rr: AtomicUsize,
    /// (key_hash → member_index) + 最近 N 次访问时间，简易 LRU。
    sticky: Mutex<StickyLru>,
}

#[derive(Debug)]
struct StickyLru {
    cap: usize,
    ttl: Duration,
    map: HashMap<u64, (usize, Instant)>,
}

impl StickyLru {
    fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            cap,
            ttl,
            map: HashMap::new(),
        }
    }
    fn get(&mut self, k: u64) -> Option<usize> {
        let now = Instant::now();
        if let Some((idx, when)) = self.map.get(&k).copied() {
            if now.duration_since(when) < self.ttl {
                self.map.insert(k, (idx, now));
                return Some(idx);
            }
            self.map.remove(&k);
        }
        None
    }
    fn put(&mut self, k: u64, idx: usize) {
        if self.map.len() >= self.cap {
            // 简单回收：删一个最老的。
            if let Some((&oldk, _)) = self.map.iter().min_by_key(|(_, (_, w))| *w) {
                self.map.remove(&oldk);
            }
        }
        self.map.insert(k, (idx, Instant::now()));
    }
}

impl Default for LbState {
    fn default() -> Self {
        Self {
            rr: AtomicUsize::new(0),
            sticky: Mutex::new(StickyLru::new(1024, Duration::from_secs(600))),
        }
    }
}

/* ============================================================
GroupSelector
============================================================ */

#[derive(Debug)]
pub struct GroupSelector {
    plan: GroupPlan,
    opts: RwLock<GroupOptions>,
    /// 编译后的 filter 正则（多条 OR）
    filter_regs: RwLock<Vec<Regex>>,
    exclude_filter_regs: RwLock<Vec<Regex>>,
    exclude_type_set: RwLock<Vec<String>>,
    /// `select` / `fallback` / `url-test` 都用得上的"用户固定选择"；
    /// 与 mihomo `selected` 字段同语义。
    manual_pick: RwLock<Option<String>>,
    /// 失败窗口
    failure: FailureWindow,
    /// LB 状态
    lb: LbState,
    /// "上次选择"持久 cache，便于 Now() 不抖动 —— sticky 场景。
    last_pick: RwLock<Option<String>>,
}

impl GroupSelector {
    pub fn new(plan: GroupPlan) -> Self {
        Self::with_options(plan, GroupOptions::default())
    }

    pub fn with_options(plan: GroupPlan, opts: GroupOptions) -> Self {
        let me = Self {
            plan,
            opts: RwLock::new(GroupOptions::default()),
            filter_regs: RwLock::new(Vec::new()),
            exclude_filter_regs: RwLock::new(Vec::new()),
            exclude_type_set: RwLock::new(Vec::new()),
            manual_pick: RwLock::new(None),
            failure: FailureWindow::default(),
            lb: LbState::default(),
            last_pick: RwLock::new(None),
        };
        me.set_options(opts);
        me
    }

    pub fn name(&self) -> &str {
        &self.plan.name
    }
    pub fn plan(&self) -> &GroupPlan {
        &self.plan
    }
    pub fn members(&self) -> &[String] {
        &self.plan.members
    }
    pub fn options(&self) -> GroupOptions {
        self.opts.read().clone()
    }

    /// 热改 GroupOptions —— `/configs PUT` 或 dashboard 修改 strategy/filter 时调。
    pub fn set_options(&self, opts: GroupOptions) {
        let filter_regs = compile_regs_backtick(&opts.filter);
        let exclude_regs = compile_regs_backtick(&opts.exclude_filter);
        let etypes: Vec<String> = if opts.exclude_type.is_empty() {
            Vec::new()
        } else {
            opts.exclude_type
                .split('|')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        };
        *self.filter_regs.write() = filter_regs;
        *self.exclude_filter_regs.write() = exclude_regs;
        *self.exclude_type_set.write() = etypes;
        *self.opts.write() = opts;
    }

    /// 应用 filter / exclude_filter / exclude_type 后的成员快照。
    /// `protocol_of` 闭包用于查询 outbound 协议名（运行时有 OutboundRegistry）；
    /// 测试场景可以传 `|_| ""`。
    pub fn filtered_members(&self, protocol_of: impl Fn(&str) -> &str) -> Vec<String> {
        let filt = self.filter_regs.read();
        let excl = self.exclude_filter_regs.read();
        let etypes = self.exclude_type_set.read();
        let mut out: Vec<String> = self
            .plan
            .members
            .iter()
            .filter(|n| {
                if !etypes.is_empty() {
                    let proto = protocol_of(n).to_lowercase();
                    if etypes.iter().any(|e| *e == proto) {
                        return false;
                    }
                }
                if !filt.is_empty() && !filt.iter().any(|r| r.is_match(n)) {
                    return false;
                }
                if !excl.is_empty() && excl.iter().any(|r| r.is_match(n)) {
                    return false;
                }
                true
            })
            .cloned()
            .collect();
        if out.is_empty() {
            // 兼容 mihomo："filter 空命中时回退原 members"（不会让 group 完全不可用）。
            out = self.plan.members.clone();
        }
        out
    }

    pub fn has_unresolved_feed_placeholders(&self) -> bool {
        self.plan.members.iter().any(|m| is_feed_placeholder(m))
    }

    pub fn set_manual(&self, node: impl Into<String>) {
        let n = node.into();
        *self.last_pick.write() = Some(n.clone());
        *self.manual_pick.write() = Some(n);
    }
    /// 清除当前固定选择 —— 与 mihomo `PUT /proxies/<group> {"name":""}` 等价。
    /// `last_pick` 保留以便下次 pick 仍能给出一个稳定的"近期成员"参考。
    pub fn clear_manual(&self) {
        *self.manual_pick.write() = None;
    }
    pub fn current_manual(&self) -> Option<String> {
        self.manual_pick.read().clone()
    }
    pub fn last_pick(&self) -> Option<String> {
        self.last_pick.read().clone()
    }

    /* ====================================================================
    核心选点入口 —— 与 mihomo `Unwrap(metadata, touch)` 等价。
    ==================================================================== */

    /// 选出一个节点；策略全量分支。
    pub fn pick(
        &self,
        meta: &FlowMeta,
        smart: &Arc<SmartSelector>,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        self.pick_eligible(meta, smart, tester, |_| true)
    }

    /// 选出一个满足额外能力约束的节点。
    ///
    /// TUN UDP 会用这个入口过滤不支持 UDP relay 的 outbound。这里不把
    /// unsupported 节点留给后续 dial 再 fallback，避免 UDP 流量静默绕到 DIRECT。
    pub fn pick_eligible(
        &self,
        meta: &FlowMeta,
        smart: &Arc<SmartSelector>,
        tester: Option<&Arc<UrlTester>>,
        eligible: impl Fn(&str) -> bool,
    ) -> Option<String> {
        let mut members = self.filtered_members(|_| "");
        let unresolved_feeds = members.iter().filter(|m| is_feed_placeholder(m)).count();
        if unresolved_feeds > 0 {
            members.retain(|m| !is_feed_placeholder(m));
        }
        let before_eligibility = members.len();
        members.retain(|m| eligible(m));
        if members.is_empty() {
            tracing::warn!(
                target: "group::pick",
                group = %self.plan.name,
                strategy = ?self.plan.choose,
                host = %meta.host,
                unresolved_feeds,
                candidates_before_eligibility = before_eligibility,
                network = meta.network,
                "no selectable members after filter/provider expansion -> caller will fall back",
            );
            return None;
        }
        let url = self.opts.read().url.clone().unwrap_or_else(|| {
            tester
                .map(|t| t.current_config().default_url)
                .unwrap_or_default()
        });
        let started = std::time::Instant::now();
        let chosen = match self.plan.choose {
            ChooseStrategy::Manual => self.pick_manual(&members, &url, tester.map(|t| t.as_ref())),
            ChooseStrategy::Smart => self.pick_smart(meta, &members, smart),
            ChooseStrategy::Fast => self.pick_url_test(&members, &url, tester),
            ChooseStrategy::Stable => self.pick_fallback(&members, &url, tester),
            ChooseStrategy::Spread => self.pick_load_balance(meta, &members, &url, tester),
            ChooseStrategy::Chain => self.pick_chain(&members),
        };
        match &chosen {
            Some(n) => tracing::debug!(
                target: "group::pick",
                group = %self.plan.name,
                strategy = ?self.plan.choose,
                host = %meta.host,
                candidates = members.len(),
                picked = %n,
                fixed = ?self.manual_pick.read(),
                elapsed_us = started.elapsed().as_micros() as u64,
                "decided",
            ),
            None => tracing::warn!(
                target: "group::pick",
                group = %self.plan.name,
                strategy = ?self.plan.choose,
                host = %meta.host,
                candidates = members.len(),
                "no node chosen",
            ),
        }
        if let Some(ref n) = chosen {
            *self.last_pick.write() = Some(n.clone());
        }
        chosen
    }

    /// 兼容旧签名：仅按 host 选点。
    pub fn pick_by_host(
        &self,
        host: &str,
        smart: &Arc<SmartSelector>,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        let meta = FlowMeta::for_host(host, 443, "tcp");
        self.pick(&meta, smart, tester)
    }

    /* ====================================================================
    Selector / Manual —— mihomo selector.go
    ==================================================================== */

    fn pick_manual(
        &self,
        members: &[String],
        url: &str,
        tester: Option<&UrlTester>,
    ) -> Option<String> {
        // 1. 用户固定选了一个 → 在过滤后的成员里查它是否仍然存在。
        if let Some(p) = self.manual_pick.read().clone() {
            if members.iter().any(|m| m == &p) {
                // alive 校验：与 mihomo selector.go 一致，找不到 alive 也用它。
                let _ = (url, tester);
                return Some(p);
            }
        }
        // 2. 没设 / 已失效 → 取第一个（mihomo `proxies[0]`）。
        members.first().cloned()
    }

    /* ====================================================================
    URLTest / Fast —— mihomo urltest.go fast(touch)
    ==================================================================== */

    fn pick_url_test(
        &self,
        members: &[String],
        url: &str,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        let opts = self.opts.read();
        let tol = opts.tolerance;
        // fixed selected：与 mihomo `selected` 完全一致 —— 只要 alive，就忠于它。
        if let Some(s) = self.manual_pick.read().clone() {
            if members.iter().any(|m| m == &s) {
                if tester.map(|t| t.alive_for_url(&s, url)).unwrap_or(true) {
                    return Some(s);
                }
            }
        }
        if let Some(t) = tester {
            if let Some(p) = t.pick_fast(self.name(), members, url, tol) {
                return Some(p);
            }
        }
        // 没有 tester / 全 dead → 退回成员首位
        members.first().cloned()
    }

    /* ====================================================================
    Fallback / Stable —— mihomo fallback.go findAliveProxy
    ==================================================================== */

    fn pick_fallback(
        &self,
        members: &[String],
        url: &str,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        // selected fixed：只要 alive 就用它；dead 则清掉 fixed 让顺序找
        // ⚠️ 必须先 let-bind 让 read guard 在语句结束时立刻释放 —— Rust 2021 下
        //   `if let Some(s) = self.manual_pick.read().clone() { ... }` 的临时
        //   RwLockReadGuard 会存活到 if-let body 结束；body 内 `self.manual_pick.write()`
        //   就会同线程死锁 parking_lot 的 RwLock。
        let manual_now: Option<String> = self.manual_pick.read().clone();
        if let Some(s) = manual_now {
            if members.iter().any(|m| m == &s) {
                if tester.map(|t| t.alive_for_url(&s, url)).unwrap_or(true) {
                    return Some(s);
                }
                // dead → 释放 fixed（此时 read guard 已 drop，write 不会死锁）
                *self.manual_pick.write() = None;
            }
        }
        // 顺序找首个 alive
        for m in members {
            if tester.map(|t| t.alive_for_url(m, url)).unwrap_or(true) {
                return Some(m.clone());
            }
        }
        members.first().cloned()
    }

    /* ====================================================================
    LoadBalance / Spread —— mihomo loadbalance.go
    ==================================================================== */

    fn pick_load_balance(
        &self,
        meta: &FlowMeta,
        members: &[String],
        url: &str,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        let strat = self.opts.read().lb_strategy;
        match strat {
            LbStrategy::ConsistentHashing => self.lb_consistent_hashing(meta, members, url, tester),
            LbStrategy::RoundRobin => self.lb_round_robin(members, url, tester),
            LbStrategy::StickySessions => self.lb_sticky(meta, members, url, tester),
        }
    }

    fn lb_consistent_hashing(
        &self,
        meta: &FlowMeta,
        members: &[String],
        url: &str,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        let key = hash_str(&meta.lb_key());
        let buckets = members.len() as i32;
        if buckets <= 0 {
            return None;
        }
        // 与 mihomo jumpHash 同算法。
        let mut k = key;
        for _ in 0..5 {
            let idx = jump_hash(k, buckets) as usize;
            let m = &members[idx];
            if tester.map(|t| t.alive_for_url(m, url)).unwrap_or(true) {
                return Some(m.clone());
            }
            k = k.wrapping_add(1);
        }
        // 全数遍历回退
        for m in members {
            if tester.map(|t| t.alive_for_url(m, url)).unwrap_or(true) {
                return Some(m.clone());
            }
        }
        members.first().cloned()
    }

    fn lb_round_robin(
        &self,
        members: &[String],
        url: &str,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        let n = members.len();
        if n == 0 {
            return None;
        }
        let start = self.lb.rr.fetch_add(1, Ordering::Relaxed) % n;
        for off in 0..n {
            let i = (start + off) % n;
            let m = &members[i];
            if tester.map(|t| t.alive_for_url(m, url)).unwrap_or(true) {
                return Some(m.clone());
            }
        }
        members.first().cloned()
    }

    fn lb_sticky(
        &self,
        meta: &FlowMeta,
        members: &[String],
        url: &str,
        tester: Option<&Arc<UrlTester>>,
    ) -> Option<String> {
        let key = hash_str(&meta.lb_key_sticky());
        let n = members.len();
        if n == 0 {
            return None;
        }
        let mut g = self.lb.sticky.lock();
        // 1. LRU 命中
        if let Some(idx) = g.get(key) {
            if idx < n {
                let m = &members[idx];
                if tester.map(|t| t.alive_for_url(m, url)).unwrap_or(true) {
                    return Some(m.clone());
                }
            }
        }
        // 2. jumpHash 重选
        let mut k = key.wrapping_add(now_nanos());
        for _ in 0..5 {
            let idx = jump_hash(k, n as i32) as usize;
            let m = &members[idx];
            if tester.map(|t| t.alive_for_url(m, url)).unwrap_or(true) {
                g.put(key, idx);
                return Some(m.clone());
            }
            k = k.wrapping_add(1);
        }
        // 3. 全 dead → first
        g.put(key, 0);
        members.first().cloned()
    }

    /* ====================================================================
    Smart —— 走 SmartSelector
    ==================================================================== */

    fn pick_smart(
        &self,
        meta: &FlowMeta,
        members: &[String],
        smart: &Arc<SmartSelector>,
    ) -> Option<String> {
        let ctx = SmartContext {
            group: self.plan.name.clone(),
            host: meta.host.clone(),
            prefer: self.plan.prefer.clone(),
            avoid: self.plan.avoid.clone(),
        };
        Some(smart.choose(&ctx, members).node)
    }

    /* ====================================================================
    Chain / Relay
    ==================================================================== */

    fn pick_chain(&self, members: &[String]) -> Option<String> {
        // chain 第一跳 = path[0]；具体 outbound 拼接由 dispatcher / runtime.dial 完成。
        self.plan
            .path
            .first()
            .cloned()
            .or_else(|| members.first().cloned())
    }

    /* ====================================================================
    Health-check 反馈：与 mihomo onDialFailed/onDialSuccess 等价。
    ==================================================================== */

    /// 一次成功 dial —— 重置失败计数。
    pub fn on_dial_success(&self) {
        self.failure.times.store(0, Ordering::Release);
        *self.failure.first_at_ms.lock() = None;
    }

    /// 一次失败 dial。`trigger_health_check` 在窗口内累计达到阈值时被回调；
    /// 调用方一般传 `|| tester.test_many(...)` 触发 URLTest。
    pub fn on_dial_failed(&self, _err: &str, mut trigger_health_check: impl FnMut()) {
        let opts = self.opts.read();
        let max = opts.max_failed_times.max(1);
        let window = Duration::from_millis(opts.test_timeout_ms.max(1));
        drop(opts);

        // 立刻进健康检查的特殊情况：错误是 connection refused —— 这里不解析错误内容，
        // 始终走计数路径。
        let prev = self.failure.times.fetch_add(1, Ordering::AcqRel);
        let now = Instant::now();
        if prev == 0 {
            *self.failure.first_at_ms.lock() = Some(now);
        } else {
            let first = *self.failure.first_at_ms.lock();
            if let Some(first) = first {
                if now.duration_since(first) > window {
                    // 超窗 → reset 计数
                    self.failure.times.store(1, Ordering::Release);
                    *self.failure.first_at_ms.lock() = Some(now);
                    return;
                }
            }
        }
        let cur = (prev as u32) + 1;
        if cur >= max {
            // 防重入：同一时刻只触发一次健康检查。
            let mut hc = self.failure.health_checking.lock();
            if !*hc {
                *hc = true;
                drop(hc);
                debug!(
                    target: "group::health",
                    group = %self.plan.name,
                    failed = cur,
                    "max_failed_times reached, trigger health-check"
                );
                trigger_health_check();
                let mut hc = self.failure.health_checking.lock();
                *hc = false;
                self.failure.times.store(0, Ordering::Release);
                *self.failure.first_at_ms.lock() = None;
            }
        }
    }

    /// 强制触发一次健康检查（dashboard `PUT /providers/proxies/<group>` / 调试用）。
    pub fn force_invalidate_pick_cache(&self, tester: &Arc<UrlTester>) {
        tester.invalidate_fast_pick(self.name());
    }

    /* ====================================================================
    Dashboard JSON —— 对齐 Clash `/proxies/:name` 字段
    ==================================================================== */

    pub fn to_clash_json(&self) -> serde_json::Value {
        let opts = self.opts.read();
        let strategy = match self.plan.choose {
            ChooseStrategy::Manual => "Selector",
            ChooseStrategy::Smart => "URLTest",
            ChooseStrategy::Fast => "URLTest",
            ChooseStrategy::Stable => "Fallback",
            ChooseStrategy::Spread => "LoadBalance",
            ChooseStrategy::Chain => "Relay",
        };
        let now = self
            .last_pick
            .read()
            .clone()
            .or_else(|| self.manual_pick.read().clone())
            .unwrap_or_else(|| self.plan.members.first().cloned().unwrap_or_default());
        let mut body = serde_json::json!({
            "type": strategy,
            "name": self.plan.name,
            "now": now,
            "all": self.plan.members,
            "udp": !opts.disable_udp,
            "alive": true,
            "history": [],
            "extra": {},
            "hidden": opts.hidden,
            "icon": opts.icon,
            "fixed": self.manual_pick.read().clone().unwrap_or_default(),
            "expectedStatus": opts.expected_status,
            "testUrl": opts.url.clone().unwrap_or_default(),
        });
        if matches!(self.plan.choose, ChooseStrategy::Spread) {
            if let Some(obj) = body.as_object_mut() {
                obj.insert(
                    "strategy".into(),
                    serde_json::Value::String(opts.lb_strategy.as_str().into()),
                );
            }
        }
        body
    }
}

/* ============================================================
utils
============================================================ */

fn compile_regs_backtick(s: &str) -> Vec<Regex> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split('`')
        .filter(|p| !p.is_empty())
        .filter_map(|p| Regex::new(p).ok())
        .collect()
}

fn is_feed_placeholder(name: &str) -> bool {
    name.strip_prefix("feed:")
        .map(|rest| !rest.trim().is_empty())
        .unwrap_or(false)
}

fn hash_str(s: &str) -> u64 {
    let mut h = AHasher::default();
    s.hash(&mut h);
    h.finish()
}

/// jumpHash —— Jump Consistent Hash（与 mihomo `jumpHash` 实现一致）。
fn jump_hash(mut key: u64, buckets: i32) -> i32 {
    let mut b: i64 = -1;
    let mut j: i64 = 0;
    while j < buckets as i64 {
        b = j;
        key = key.wrapping_mul(2862933555777941757).wrapping_add(1);
        let next = ((b + 1) as f64) * ((1u64 << 31) as f64) / (((key >> 33) + 1) as f64);
        j = next as i64;
    }
    b as i32
}

fn now_nanos() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_config::model::ChooseStrategy;
    use core_config::runtime_plan::GroupPlan;

    fn plan(choose: ChooseStrategy, members: &[&str]) -> GroupPlan {
        GroupPlan {
            name: "g".into(),
            choose,
            members: members.iter().map(|s| s.to_string()).collect(),
            prefer: vec![],
            avoid: vec![],
            check: None,
            sticky: None,
            path: vec![],
        }
    }

    fn smart() -> Arc<SmartSelector> {
        Arc::new(SmartSelector::new(
            core_config::model::SmartGoal::Balanced,
            core_config::model::SmartSticky::Off,
        ))
    }

    fn meta(host: &str) -> FlowMeta {
        FlowMeta::for_host(host, 443, "tcp")
    }

    #[test]
    fn manual_first_then_picked() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["a", "b", "c"]));
        let s = smart();
        assert_eq!(g.pick(&meta("x"), &s, None).as_deref(), Some("a"));
        g.set_manual("c");
        assert_eq!(g.pick(&meta("x"), &s, None).as_deref(), Some("c"));
    }

    #[test]
    fn manual_invalid_pick_falls_back_to_first() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["a", "b"]));
        let s = smart();
        g.set_manual("ghost");
        assert_eq!(g.pick(&meta("x"), &s, None).as_deref(), Some("a"));
    }

    #[test]
    fn unresolved_feed_placeholder_is_not_selectable() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["feed:primary", "node-a"]));
        let s = smart();

        assert_eq!(g.pick(&meta("x"), &s, None).as_deref(), Some("node-a"));
        assert!(g.has_unresolved_feed_placeholders());
    }

    #[test]
    fn all_unresolved_feed_placeholders_return_none() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["feed:primary"]));
        let s = smart();

        assert_eq!(g.pick(&meta("x"), &s, None), None);
    }

    #[test]
    fn url_test_uses_fast_pick_when_tester_present() {
        let g = GroupSelector::new(plan(ChooseStrategy::Fast, &["a", "b", "c"]));
        let s = smart();
        let tester = UrlTester::new(crate::health::UrlTestConfig::default());
        // 种 stats：a=300, b=100, c=200
        let url = tester.current_config().default_url;
        tester.ensure_stats("a", &url).record(300, true);
        tester.ensure_stats("b", &url).record(100, true);
        tester.ensure_stats("c", &url).record(200, true);
        let pick = g.pick(&meta("x"), &s, Some(&tester)).unwrap();
        assert_eq!(pick, "b");
    }

    #[test]
    fn fallback_skips_dead_and_finds_first_alive() {
        let g = GroupSelector::new(plan(ChooseStrategy::Stable, &["a", "b", "c"]));
        let s = smart();
        let tester = UrlTester::new(crate::health::UrlTestConfig::default());
        let url = tester.current_config().default_url;
        tester.ensure_stats("a", &url).record(0, false);
        tester.ensure_stats("b", &url).record(0, false);
        tester.ensure_stats("c", &url).record(150, true);
        let pick = g.pick(&meta("x"), &s, Some(&tester)).unwrap();
        assert_eq!(pick, "c");
    }

    #[test]
    fn fallback_fixed_dead_clears_to_resume_search() {
        let g = GroupSelector::new(plan(ChooseStrategy::Stable, &["a", "b"]));
        let s = smart();
        let tester = UrlTester::new(crate::health::UrlTestConfig::default());
        let url = tester.current_config().default_url;
        tester.ensure_stats("a", &url).record(0, false);
        tester.ensure_stats("b", &url).record(150, true);
        g.set_manual("a");
        let pick = g.pick(&meta("x"), &s, Some(&tester)).unwrap();
        assert_eq!(pick, "b");
        // fixed 已被清
        assert!(g.current_manual().is_none());
    }

    #[test]
    fn loadbalance_consistent_hashing_is_stable_per_host() {
        let mut p = plan(ChooseStrategy::Spread, &["a", "b", "c", "d"]);
        p.choose = ChooseStrategy::Spread;
        let g = GroupSelector::new(p);
        g.set_options(GroupOptions {
            lb_strategy: LbStrategy::ConsistentHashing,
            ..GroupOptions::default()
        });
        let s = smart();
        let p1 = g.pick(&meta("example.com"), &s, None).unwrap();
        let p2 = g.pick(&meta("example.com"), &s, None).unwrap();
        let p3 = g.pick(&meta("example.com"), &s, None).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(p2, p3);
    }

    #[test]
    fn loadbalance_round_robin_cycles() {
        let g = GroupSelector::new(plan(ChooseStrategy::Spread, &["a", "b", "c"]));
        g.set_options(GroupOptions {
            lb_strategy: LbStrategy::RoundRobin,
            ..GroupOptions::default()
        });
        let s = smart();
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(g.pick(&meta("h"), &s, None).unwrap());
        }
        // 至少包含全部 a,b,c
        assert!(seen.contains(&"a".to_string()));
        assert!(seen.contains(&"b".to_string()));
        assert!(seen.contains(&"c".to_string()));
    }

    #[test]
    fn loadbalance_sticky_returns_same_for_same_src_dst() {
        let g = GroupSelector::new(plan(ChooseStrategy::Spread, &["a", "b", "c", "d"]));
        g.set_options(GroupOptions {
            lb_strategy: LbStrategy::StickySessions,
            ..GroupOptions::default()
        });
        let s = smart();
        let mut m = FlowMeta::for_host("h", 443, "tcp");
        m.src_ip = Some("10.0.0.1".parse().unwrap());
        let p1 = g.pick(&m, &s, None).unwrap();
        let p2 = g.pick(&m, &s, None).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn chain_returns_path_first() {
        let mut p = plan(ChooseStrategy::Chain, &["a", "b"]);
        p.path = vec!["hop1".into(), "hop2".into()];
        let g = GroupSelector::new(p);
        let s = smart();
        assert_eq!(g.pick(&meta("h"), &s, None).as_deref(), Some("hop1"));
    }

    #[test]
    fn filter_regex_keeps_matched() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["HK-1", "JP-2", "US-3"]));
        g.set_options(GroupOptions {
            filter: "^HK".into(),
            ..GroupOptions::default()
        });
        let mems = g.filtered_members(|_| "");
        assert_eq!(mems, vec!["HK-1".to_string()]);
    }

    #[test]
    fn exclude_filter_drops_matched() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["HK-1", "JP-2", "US-3"]));
        g.set_options(GroupOptions {
            exclude_filter: "JP".into(),
            ..GroupOptions::default()
        });
        let mems = g.filtered_members(|_| "");
        assert_eq!(mems, vec!["HK-1".to_string(), "US-3".to_string()]);
    }

    #[test]
    fn exclude_type_drops_protocol() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["a", "b"]));
        g.set_options(GroupOptions {
            exclude_type: "ss|http".into(),
            ..GroupOptions::default()
        });
        let mems = g.filtered_members(|n| if n == "a" { "ss" } else { "vmess" });
        assert_eq!(mems, vec!["b".to_string()]);
    }

    #[test]
    fn filter_empty_match_falls_back_to_full_members() {
        let g = GroupSelector::new(plan(ChooseStrategy::Manual, &["a", "b"]));
        g.set_options(GroupOptions {
            filter: "^never_match$".into(),
            ..GroupOptions::default()
        });
        let mems = g.filtered_members(|_| "");
        assert_eq!(mems, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn on_dial_failed_triggers_after_max() {
        let g = GroupSelector::new(plan(ChooseStrategy::Stable, &["a"]));
        g.set_options(GroupOptions {
            max_failed_times: 3,
            test_timeout_ms: 10_000,
            ..GroupOptions::default()
        });
        let triggered = std::sync::atomic::AtomicUsize::new(0);
        g.on_dial_failed("x", || {
            triggered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        g.on_dial_failed("x", || {
            triggered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        assert_eq!(triggered.load(std::sync::atomic::Ordering::SeqCst), 0);
        g.on_dial_failed("x", || {
            triggered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        assert_eq!(triggered.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn on_dial_success_resets_window() {
        let g = GroupSelector::new(plan(ChooseStrategy::Stable, &["a"]));
        g.set_options(GroupOptions {
            max_failed_times: 2,
            ..GroupOptions::default()
        });
        let triggered = std::sync::atomic::AtomicUsize::new(0);
        g.on_dial_failed("x", || {
            triggered.fetch_add(1, Ordering::SeqCst);
        });
        g.on_dial_success();
        g.on_dial_failed("x", || {
            triggered.fetch_add(1, Ordering::SeqCst);
        });
        // 仍未触发：第一次失败窗口已被 success 重置。
        assert_eq!(triggered.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn jump_hash_is_consistent() {
        // 改变桶数时只有 1/N 流量会"换桶"——这里只验证同 key 同 buckets 必回相同 idx。
        let k = hash_str("example.com");
        assert_eq!(jump_hash(k, 8), jump_hash(k, 8));
    }

    #[test]
    fn etld_plus_one_basic() {
        assert_eq!(etld_plus_one("a.b.example.com"), "example.com");
        assert_eq!(etld_plus_one("example.com"), "example.com");
        assert_eq!(etld_plus_one("localhost"), "localhost");
    }

    #[test]
    fn to_clash_json_includes_strategy_for_loadbalance() {
        let g = GroupSelector::new(plan(ChooseStrategy::Spread, &["a"]));
        g.set_options(GroupOptions {
            lb_strategy: LbStrategy::StickySessions,
            ..GroupOptions::default()
        });
        let v = g.to_clash_json();
        assert_eq!(v["type"], "LoadBalance");
        assert_eq!(v["strategy"], "sticky-sessions");
    }
}
