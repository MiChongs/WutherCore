//! Smart 选择器 —— §6.3 选择流程 + §6.4 评分公式。
//!
//! 评分项：
//! * latency 0.32, success 0.26, stability 0.16, site_memory 0.10,
//!   load 0.08, preference 0.05, cost 0.03 - cooldown - capability。

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use core_config::model::{SmartGoal, SmartSticky};
use core_store::{
    AsyncWriter, Store,
    blobs::{DomainBestBlob, NegativeBlob},
    schema::{SMART_DOMAIN_BEST, SMART_NEGATIVE, SMART_NODE_STATS, SMART_PIN},
    store::BatchOp,
};
use dashmap::DashMap;
use parking_lot::RwLock;

use crate::{
    cache::{DomainBest, NegativeCache},
    explain::{ChoiceExplain, NodeScore},
    metrics::{NodeStatSnapshot, NodeStats},
};

#[derive(Debug, Clone)]
pub struct SmartContext {
    pub group: String,
    pub host: String,
    /// 用户偏好（地区/名称包含项），命中加分。
    pub prefer: Vec<String>,
    pub avoid: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SmartChoice {
    pub node: String,
    pub explain: ChoiceExplain,
}

#[derive(Debug, Clone, Copy)]
struct Weights {
    latency: f64,
    success: f64,
    stability: f64,
    site_memory: f64,
    load: f64,
    preference: f64,
    cost: f64,
}

impl Weights {
    fn for_goal(goal: SmartGoal) -> Self {
        match goal {
            SmartGoal::Speed => Self {
                latency: 0.45,
                success: 0.18,
                stability: 0.10,
                site_memory: 0.10,
                load: 0.12,
                preference: 0.04,
                cost: 0.01,
            },
            SmartGoal::Stability => Self {
                latency: 0.20,
                success: 0.34,
                stability: 0.24,
                site_memory: 0.10,
                load: 0.06,
                preference: 0.04,
                cost: 0.02,
            },
            SmartGoal::LowCost => Self {
                latency: 0.20,
                success: 0.20,
                stability: 0.10,
                site_memory: 0.05,
                load: 0.05,
                preference: 0.05,
                cost: 0.35,
            },
            SmartGoal::Privacy => Self {
                latency: 0.30,
                success: 0.30,
                stability: 0.18,
                site_memory: 0.02,
                load: 0.10,
                preference: 0.07,
                cost: 0.03,
            },
            SmartGoal::Balanced => Self {
                latency: 0.32,
                success: 0.26,
                stability: 0.16,
                site_memory: 0.10,
                load: 0.08,
                preference: 0.05,
                cost: 0.03,
            },
        }
    }
}

pub struct SmartSelector {
    nodes: DashMap<String, Arc<NodeStats>>,
    domain_best: DomainBest,
    negative: NegativeCache,
    goal: RwLock<SmartGoal>,
    #[allow(dead_code)]
    sticky: RwLock<SmartSticky>,
    explain_log: RwLock<Vec<ChoiceExplain>>,
    writer: Option<Arc<AsyncWriter>>,
}

impl std::fmt::Debug for SmartSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmartSelector")
            .field("nodes", &self.nodes.len())
            .field("goal", &*self.goal.read())
            .finish()
    }
}

impl SmartSelector {
    pub fn new(goal: SmartGoal, sticky: SmartSticky) -> Self {
        Self {
            nodes: DashMap::new(),
            domain_best: DomainBest::new(Duration::from_secs(10 * 60)),
            negative: NegativeCache::new(),
            goal: RwLock::new(goal),
            sticky: RwLock::new(sticky),
            explain_log: RwLock::new(Vec::with_capacity(256)),
            writer: None,
        }
    }

    /// 启动时调用：从 [`Store`] 加载所有节点统计与 domain_best 缓存，并绑定
    /// 异步写入器；之后每次 record_success / record_failure / pin / 选择
    /// 都会把更新通过 mpsc 推给 writer，由 writer 批量落盘。
    pub fn with_store(goal: SmartGoal, sticky: SmartSticky, store: Arc<Store>) -> Self {
        let mut me = Self::new(goal, sticky);
        // 1) 加载节点统计
        if let Ok(rows) = store.iter_json::<core_store::NodeStatsBlob>(SMART_NODE_STATS) {
            for (k, blob) in rows {
                me.nodes.insert(k, Arc::new(NodeStats::from_blob(&blob)));
            }
        }
        // 2) 加载 domain_best 缓存（若值未到期则回填）
        if let Ok(rows) = store.iter_json::<DomainBestBlob>(SMART_DOMAIN_BEST) {
            let now = unix_now();
            for (k, blob) in rows {
                if now.saturating_sub(blob.set_at_secs) <= 60 * 60 {
                    me.domain_best.put(&k, &blob.node);
                }
            }
        }
        // 3) 加载 negative cache
        if let Ok(rows) = store.iter_json::<NegativeBlob>(SMART_NEGATIVE) {
            let now = unix_now();
            for (node, blob) in rows {
                if blob.until_secs > now {
                    let dur = Duration::from_secs(blob.until_secs - now);
                    me.negative.cool(&node, dur, blob.reason);
                }
            }
        }
        let writer = AsyncWriter::spawn(store);
        me.writer = Some(writer);
        me
    }

    /// 优雅停止：把所有内存脏数据 flush 到 redb。
    pub async fn shutdown(&self) {
        if let Some(w) = &self.writer {
            // 把所有节点统计完整快照入队（保证停机时拥有最新状态）。
            let mut ops: Vec<BatchOp> = Vec::with_capacity(self.nodes.len());
            for entry in self.nodes.iter() {
                ops.push(BatchOp::PutNodeStats(
                    entry.key().clone(),
                    entry.value().to_blob(),
                ));
            }
            if !ops.is_empty() {
                let _ = w.enqueue_batch(ops);
            }
            w.shutdown().await;
        }
    }

    pub fn set_goal(&self, goal: SmartGoal) {
        *self.goal.write() = goal;
    }

    pub fn ensure_node(&self, name: &str) -> Arc<NodeStats> {
        if let Some(s) = self.nodes.get(name) {
            return s.clone();
        }
        let s = Arc::new(NodeStats::new());
        self.nodes.insert(name.to_string(), s.clone());
        s
    }

    pub fn record_success(&self, node: &str, latency: Duration) {
        let stats = self.ensure_node(node);
        stats.record_success(latency);
        if let Some(w) = &self.writer {
            let _ = w.enqueue(BatchOp::PutNodeStats(node.to_string(), stats.to_blob()));
        }
    }
    pub fn record_failure(&self, node: &str, reason: impl Into<String>) {
        let r = reason.into();
        let stats = self.ensure_node(node);
        stats.record_failure(r.clone());
        self.negative.cool(node, Duration::from_secs(30), r.clone());
        if let Some(w) = &self.writer {
            let until_secs = unix_now() + 30;
            let _ = w.enqueue_batch(vec![
                BatchOp::PutNodeStats(node.to_string(), stats.to_blob()),
                BatchOp::PutNegative(
                    node.to_string(),
                    NegativeBlob {
                        until_secs,
                        reason: r,
                    },
                ),
            ]);
        }
    }

    /// URLTest 探测成功：写历史 + 走 record_success 链路（含异步落盘）。
    pub fn record_probe_for(&self, node: &str, latency: Duration) {
        let stats = self.ensure_node(node);
        stats.record_probe(latency);
        if let Some(w) = &self.writer {
            let _ = w.enqueue(BatchOp::PutNodeStats(node.to_string(), stats.to_blob()));
        }
    }

    /// URLTest 探测失败：写失败历史 + 冷却 + 落盘。
    pub fn record_probe_failure_for(&self, node: &str, reason: impl Into<String>) {
        let r = reason.into();
        let stats = self.ensure_node(node);
        stats.record_probe_failure(r.clone());
        self.negative.cool(node, Duration::from_secs(30), r.clone());
        if let Some(w) = &self.writer {
            let until_secs = unix_now() + 30;
            let _ = w.enqueue_batch(vec![
                BatchOp::PutNodeStats(node.to_string(), stats.to_blob()),
                BatchOp::PutNegative(
                    node.to_string(),
                    NegativeBlob {
                        until_secs,
                        reason: r,
                    },
                ),
            ]);
        }
    }

    pub fn pin(&self, host: &str, group: &str, node: &str) {
        let etld = etld_plus_one(host);
        let key = DomainBest::key(group, &etld);
        self.domain_best.put(&key, node);
        if let Some(w) = &self.writer {
            let _ = w.enqueue_batch(vec![
                BatchOp::PutDomainBest(
                    key,
                    DomainBestBlob {
                        node: node.to_string(),
                        set_at_secs: unix_now(),
                    },
                ),
                BatchOp::PutPin(format!("{group}|{}", etld), node.to_string()),
            ]);
        }
    }

    /// 主入口：在候选 `members` 中挑选最优节点。
    pub fn choose(&self, ctx: &SmartContext, members: &[String]) -> SmartChoice {
        let mut filtered: Vec<&String> = members
            .iter()
            .filter(|n| !ctx.avoid.iter().any(|a| n.contains(a)))
            .collect();
        if filtered.is_empty() {
            filtered = members.iter().collect();
        }

        let weights = Weights::for_goal(*self.goal.read());
        let etld = etld_plus_one(&ctx.host);
        let key = DomainBest::key(&ctx.group, &etld);
        let cache_hit = self.domain_best.get(&key);

        let mut scores: Vec<NodeScore> = filtered
            .iter()
            .map(|name| self.score_node(name, ctx, &weights, cache_hit.as_deref()))
            .collect();
        scores.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let picked = scores
            .first()
            .map(|s| s.node.clone())
            .unwrap_or_else(|| members.first().cloned().unwrap_or_default());

        if !picked.is_empty() {
            self.domain_best.put(&key, &picked);
            if let Some(w) = &self.writer {
                let _ = w.enqueue(BatchOp::PutDomainBest(
                    key.clone(),
                    DomainBestBlob {
                        node: picked.clone(),
                        set_at_secs: unix_now(),
                    },
                ));
            }
        }

        let explain = ChoiceExplain {
            group: ctx.group.clone(),
            host: ctx.host.clone(),
            picked: picked.clone(),
            cache_hit,
            scores,
        };
        // 限制 explain_log 长度
        {
            let mut g = self.explain_log.write();
            if g.len() >= 256 {
                g.remove(0);
            }
            g.push(explain.clone());
        }

        SmartChoice {
            node: picked,
            explain,
        }
    }

    pub fn recent_explains(&self) -> Vec<ChoiceExplain> {
        self.explain_log.read().clone()
    }

    fn score_node(
        &self,
        name: &str,
        ctx: &SmartContext,
        w: &Weights,
        cache_hit: Option<&str>,
    ) -> NodeScore {
        let stats = self.ensure_node(name).snapshot();
        let latency_score = clamp((100.0 - stats.p50_latency_ms / 6.0).max(0.0), 0.0, 100.0);
        let success_score = stats.success_rate * 100.0;
        let stability_score = clamp(
            100.0 - (stats.jitter_ms / 3.0 + stats.timeout_rate * 100.0),
            0.0,
            100.0,
        );
        let site_memory_score = if cache_hit == Some(name) { 100.0 } else { 50.0 };
        let load_score = clamp(100.0 - (stats.active_conn as f64).min(80.0), 0.0, 100.0);
        let preference_score = if ctx.prefer.iter().any(|p| name.contains(p)) {
            85.0
        } else {
            50.0
        };
        let cost_score = 50.0; // MVP：未提取倍率信息。
        let cooldown_penalty = match self.negative.is_cool(name) {
            Some(_) => 60.0,
            None => 0.0,
        };
        let capability_penalty = 0.0;

        let score = w.latency * latency_score
            + w.success * success_score
            + w.stability * stability_score
            + w.site_memory * site_memory_score
            + w.load * load_score
            + w.preference * preference_score
            + w.cost * cost_score
            - cooldown_penalty
            - capability_penalty;

        let reason = build_reason(name, &stats, cache_hit, &ctx.prefer);

        NodeScore {
            node: name.into(),
            score,
            latency_score,
            success_score,
            stability_score,
            site_memory_score,
            load_score,
            preference_score,
            cost_score,
            cooldown_penalty,
            capability_penalty,
            reason,
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[allow(dead_code)]
fn _unused_imports() {
    let _ = SMART_PIN;
}

fn etld_plus_one(host: &str) -> String {
    // MVP：取最后两段当作 eTLD+1。
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() <= 2 {
        host.to_lowercase()
    } else {
        let last = parts[parts.len() - 1];
        let second = parts[parts.len() - 2];
        format!("{second}.{last}").to_lowercase()
    }
}

fn build_reason(
    name: &str,
    s: &NodeStatSnapshot,
    cache_hit: Option<&str>,
    prefer: &[String],
) -> String {
    let mut parts = Vec::new();
    if cache_hit == Some(name) {
        parts.push("命中 domain_best 缓存".to_string());
    }
    if prefer.iter().any(|p| name.contains(p)) {
        parts.push(format!("匹配偏好 {prefer:?}"));
    }
    parts.push(format!("p50≈{:.0}ms", s.p50_latency_ms));
    parts.push(format!("成功率≈{:.0}%", s.success_rate * 100.0));
    if let Some(err) = &s.last_error {
        parts.push(format!("最近失败: {err}"));
    }
    parts.join(" / ")
}

fn clamp(v: f64, lo: f64, hi: f64) -> f64 {
    v.max(lo).min(hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_picks_lower_latency() {
        let sel = SmartSelector::new(SmartGoal::Balanced, SmartSticky::Site);
        sel.record_success("HK-1", Duration::from_millis(50));
        sel.record_success("US-1", Duration::from_millis(300));
        let ctx = SmartContext {
            group: "main".into(),
            host: "www.example.com".into(),
            prefer: vec![],
            avoid: vec![],
        };
        let choice = sel.choose(&ctx, &["HK-1".into(), "US-1".into()]);
        assert_eq!(choice.node, "HK-1");
        assert!(choice.explain.scores.len() == 2);
    }

    #[tokio::test]
    async fn stats_persist_across_restart() {
        let path = std::env::temp_dir().join(format!(
            "wuthercore-smart-store-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        {
            let store = core_store::Store::open(&path).unwrap();
            let sel = SmartSelector::with_store(SmartGoal::Balanced, SmartSticky::Site, store);
            sel.record_success("HK-1", Duration::from_millis(80));
            sel.record_success("HK-1", Duration::from_millis(60));
            sel.record_failure("US-1", "timeout");
            sel.shutdown().await;
            drop(sel);
        }

        let store2 = core_store::Store::open(&path).unwrap();
        let sel2 = SmartSelector::with_store(SmartGoal::Balanced, SmartSticky::Site, store2);
        let hk_snap = sel2.ensure_node("HK-1").snapshot();
        let us_snap = sel2.ensure_node("US-1").snapshot();
        assert!(
            hk_snap.samples >= 2,
            "samples should persist, got {}",
            hk_snap.samples
        );
        assert!(hk_snap.success_rate > 0.5);
        assert!(us_snap.last_error.is_some());
    }

    #[test]
    fn cooldown_pushes_node_down() {
        let sel = SmartSelector::new(SmartGoal::Balanced, SmartSticky::Site);
        sel.record_success("HK-1", Duration::from_millis(50));
        sel.record_failure("HK-1", "tcp reset");
        sel.record_success("US-1", Duration::from_millis(300));
        let ctx = SmartContext {
            group: "main".into(),
            host: "www.example.com".into(),
            prefer: vec![],
            avoid: vec![],
        };
        let choice = sel.choose(&ctx, &["HK-1".into(), "US-1".into()]);
        assert_eq!(choice.node, "US-1");
    }
}
