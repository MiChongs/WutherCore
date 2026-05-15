//! Store —— redb 数据库句柄 + 同步读写 API。

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use redb::{Database, ReadableTable};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use tracing::{debug, info};

use crate::{blobs::*, schema::*};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("redb: {0}")]
    Db(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(String),
}

impl From<redb::Error> for StoreError {
    fn from(e: redb::Error) -> Self {
        Self::Db(e.to_string())
    }
}
impl From<redb::DatabaseError> for StoreError {
    fn from(e: redb::DatabaseError) -> Self {
        Self::Db(e.to_string())
    }
}
impl From<redb::TransactionError> for StoreError {
    fn from(e: redb::TransactionError) -> Self {
        Self::Db(e.to_string())
    }
}
impl From<redb::TableError> for StoreError {
    fn from(e: redb::TableError) -> Self {
        Self::Db(e.to_string())
    }
}
impl From<redb::CommitError> for StoreError {
    fn from(e: redb::CommitError) -> Self {
        Self::Db(e.to_string())
    }
}
impl From<redb::StorageError> for StoreError {
    fn from(e: redb::StorageError) -> Self {
        Self::Db(e.to_string())
    }
}
impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e.to_string())
    }
}

#[derive(Debug)]
pub struct Store {
    db: Database,
    path: PathBuf,
}

impl Store {
    /// 打开/创建数据库；自动建表与版本号写入。
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<Self>, StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Database::create(&path)?;
        // 触发 schema 表创建。
        let me = Arc::new(Self { db, path });
        me.bootstrap()?;
        info!(target: "store", path = %me.path.display(), "store opened");
        Ok(me)
    }

    fn bootstrap(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let _ = txn.open_table(SMART_NODE_STATS)?;
            let _ = txn.open_table(SMART_DOMAIN_BEST)?;
            let _ = txn.open_table(SMART_NEGATIVE)?;
            let _ = txn.open_table(SMART_PIN)?;
            let _ = txn.open_table(GROUP_MANUAL)?;
            let _ = txn.open_table(FEED_META)?;
            let _ = txn.open_table(DNS_CACHE)?;
            let mut meta = txn.open_table(KV_META)?;
            let v = SCHEMA_VERSION.to_string().into_bytes();
            meta.insert(SCHEMA_KEY, v.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 通用单值读。
    pub fn get_json<T: DeserializeOwned>(
        &self,
        table: redb::TableDefinition<'_, &str, &[u8]>,
        key: &str,
    ) -> Result<Option<T>, StoreError> {
        let txn = self.db.begin_read()?;
        let t = match txn.open_table(table) {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };
        if let Some(v) = t.get(key)? {
            let raw = v.value();
            let value: T = serde_json::from_slice(raw)?;
            return Ok(Some(value));
        }
        Ok(None)
    }

    /// 通用单值写（小事务，谨慎用 —— 高频场景用 [`crate::AsyncWriter`]）。
    pub fn put_json<T: Serialize>(
        &self,
        table: redb::TableDefinition<'_, &str, &[u8]>,
        key: &str,
        value: &T,
    ) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(value)?;
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(table)?;
            t.insert(key, bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn delete(
        &self,
        table: redb::TableDefinition<'_, &str, &[u8]>,
        key: &str,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(table)?;
            t.remove(key)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// 批量 put：把多个写合并到单个事务，**性能关键路径**。
    pub fn write_batch(&self, ops: &[BatchOp]) -> Result<(), StoreError> {
        if ops.is_empty() {
            return Ok(());
        }
        let txn = self.db.begin_write()?;
        {
            // 预先把每张表 open 一次，减少反复打开开销。
            let mut t_stats = txn.open_table(SMART_NODE_STATS)?;
            let mut t_domain = txn.open_table(SMART_DOMAIN_BEST)?;
            let mut t_neg = txn.open_table(SMART_NEGATIVE)?;
            let mut t_pin = txn.open_table(SMART_PIN)?;
            let mut t_manual = txn.open_table(GROUP_MANUAL)?;
            let mut t_feed = txn.open_table(FEED_META)?;
            let mut t_dns = txn.open_table(DNS_CACHE)?;
            for op in ops {
                match op {
                    BatchOp::PutNodeStats(k, v) => {
                        t_stats.insert(k.as_str(), serde_json::to_vec(v)?.as_slice())?;
                    }
                    BatchOp::PutDomainBest(k, v) => {
                        t_domain.insert(k.as_str(), serde_json::to_vec(v)?.as_slice())?;
                    }
                    BatchOp::PutNegative(k, v) => {
                        t_neg.insert(k.as_str(), serde_json::to_vec(v)?.as_slice())?;
                    }
                    BatchOp::PutPin(k, v) => {
                        t_pin.insert(k.as_str(), v.as_bytes())?;
                    }
                    BatchOp::PutGroupManual(k, v) => {
                        t_manual.insert(k.as_str(), v.as_bytes())?;
                    }
                    BatchOp::PutFeedMeta(k, v) => {
                        t_feed.insert(k.as_str(), serde_json::to_vec(v)?.as_slice())?;
                    }
                    BatchOp::PutDnsCache(k, v) => {
                        t_dns.insert(k.as_str(), serde_json::to_vec(v)?.as_slice())?;
                    }
                    BatchOp::Delete(table, key) => match *table {
                        "smart_node_stats" => {
                            t_stats.remove(key.as_str())?;
                        }
                        "smart_domain_best" => {
                            t_domain.remove(key.as_str())?;
                        }
                        "smart_negative" => {
                            t_neg.remove(key.as_str())?;
                        }
                        "smart_pin" => {
                            t_pin.remove(key.as_str())?;
                        }
                        "group_manual" => {
                            t_manual.remove(key.as_str())?;
                        }
                        "feed_meta" => {
                            t_feed.remove(key.as_str())?;
                        }
                        "dns_cache" => {
                            t_dns.remove(key.as_str())?;
                        }
                        _ => {}
                    },
                }
            }
        }
        txn.commit()?;
        debug!(target: "store", ops = ops.len(), "batch committed");
        Ok(())
    }

    /// 列出表所有 (key, JSON) 对，反序列化为 T。
    pub fn iter_json<T: DeserializeOwned>(
        &self,
        table: redb::TableDefinition<'_, &str, &[u8]>,
    ) -> Result<Vec<(String, T)>, StoreError> {
        let txn = self.db.begin_read()?;
        let t = match txn.open_table(table) {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        for entry in t.iter()? {
            let (k, v) = entry?;
            let key = k.value().to_string();
            let val: T = serde_json::from_slice(v.value())?;
            out.push((key, val));
        }
        Ok(out)
    }

    /// 列出表所有 (key, raw bytes -> String)。
    pub fn iter_string(
        &self,
        table: redb::TableDefinition<'_, &str, &[u8]>,
    ) -> Result<Vec<(String, String)>, StoreError> {
        let txn = self.db.begin_read()?;
        let t = match txn.open_table(table) {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        for entry in t.iter()? {
            let (k, v) = entry?;
            out.push((
                k.value().to_string(),
                String::from_utf8_lossy(v.value()).into_owned(),
            ));
        }
        Ok(out)
    }

    pub fn approximate_stats(&self) -> Result<StoreStats, StoreError> {
        let mut s = StoreStats::default();
        s.smart_node_stats = self.iter_json::<NodeStatsBlob>(SMART_NODE_STATS)?.len();
        s.smart_domain_best = self.iter_json::<DomainBestBlob>(SMART_DOMAIN_BEST)?.len();
        s.smart_negative = self.iter_json::<NegativeBlob>(SMART_NEGATIVE)?.len();
        s.smart_pin = self.iter_string(SMART_PIN)?.len();
        s.group_manual = self.iter_string(GROUP_MANUAL)?.len();
        s.feed_meta = self.iter_json::<FeedMetaBlob>(FEED_META)?.len();
        s.dns_cache = self.iter_json::<DnsCacheBlob>(DNS_CACHE)?.len();
        s.path = self.path.display().to_string();
        s.size_bytes = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        Ok(s)
    }

    /// 删除所有学习数据（保留 schema_version）。
    pub fn reset(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut t_stats = txn.open_table(SMART_NODE_STATS)?;
            let mut t_domain = txn.open_table(SMART_DOMAIN_BEST)?;
            let mut t_neg = txn.open_table(SMART_NEGATIVE)?;
            let mut t_pin = txn.open_table(SMART_PIN)?;
            let mut t_manual = txn.open_table(GROUP_MANUAL)?;
            let mut t_feed = txn.open_table(FEED_META)?;
            let mut t_dns = txn.open_table(DNS_CACHE)?;

            // 收集所有 key，然后逐个删除（redb 没有 truncate）。
            let collect = |t: &redb::Table<'_, &str, &[u8]>| -> Result<Vec<String>, StoreError> {
                let mut keys = Vec::new();
                for e in t.iter()? {
                    let (k, _) = e?;
                    keys.push(k.value().to_string());
                }
                Ok(keys)
            };
            for k in collect(&t_stats)? {
                t_stats.remove(k.as_str())?;
            }
            for k in collect(&t_domain)? {
                t_domain.remove(k.as_str())?;
            }
            for k in collect(&t_neg)? {
                t_neg.remove(k.as_str())?;
            }
            for k in collect(&t_pin)? {
                t_pin.remove(k.as_str())?;
            }
            for k in collect(&t_manual)? {
                t_manual.remove(k.as_str())?;
            }
            for k in collect(&t_feed)? {
                t_feed.remove(k.as_str())?;
            }
            for k in collect(&t_dns)? {
                t_dns.remove(k.as_str())?;
            }
        }
        txn.commit()?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct StoreStats {
    pub path: String,
    pub size_bytes: u64,
    pub smart_node_stats: usize,
    pub smart_domain_best: usize,
    pub smart_negative: usize,
    pub smart_pin: usize,
    pub group_manual: usize,
    pub feed_meta: usize,
    pub dns_cache: usize,
}

#[derive(Debug, Clone)]
pub enum BatchOp {
    PutNodeStats(String, NodeStatsBlob),
    PutDomainBest(String, DomainBestBlob),
    PutNegative(String, NegativeBlob),
    PutPin(String, String),
    PutGroupManual(String, String),
    PutFeedMeta(String, FeedMetaBlob),
    PutDnsCache(String, DnsCacheBlob),
    Delete(&'static str, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(label: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "wuthercore-store-{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn open_put_get_persists() {
        let p = tmp_path("rt");
        let s = Store::open(&p).unwrap();
        let blob = NodeStatsBlob {
            samples: 42,
            success_ewma: 0.9,
            p50_latency_ms: 80.0,
            ..Default::default()
        };
        s.put_json(SMART_NODE_STATS, "HK-1", &blob).unwrap();
        drop(s);

        // 重新打开后还能读到
        let s2 = Store::open(&p).unwrap();
        let got: NodeStatsBlob = s2.get_json(SMART_NODE_STATS, "HK-1").unwrap().unwrap();
        assert_eq!(got.samples, 42);
        assert!((got.p50_latency_ms - 80.0).abs() < 1e-6);
    }

    #[test]
    fn batch_write_atomic() {
        let p = tmp_path("batch");
        let s = Store::open(&p).unwrap();
        let ops = vec![
            BatchOp::PutNodeStats(
                "A".into(),
                NodeStatsBlob {
                    samples: 1,
                    ..Default::default()
                },
            ),
            BatchOp::PutNodeStats(
                "B".into(),
                NodeStatsBlob {
                    samples: 2,
                    ..Default::default()
                },
            ),
            BatchOp::PutDomainBest(
                "main|youtube.com".into(),
                DomainBestBlob {
                    node: "A".into(),
                    set_at_secs: 100,
                },
            ),
            BatchOp::PutPin("main|netflix.com".into(), "B".into()),
            BatchOp::PutGroupManual("main".into(), "A".into()),
        ];
        s.write_batch(&ops).unwrap();
        let stats = s.approximate_stats().unwrap();
        assert_eq!(stats.smart_node_stats, 2);
        assert_eq!(stats.smart_domain_best, 1);
        assert_eq!(stats.smart_pin, 1);
        assert_eq!(stats.group_manual, 1);
    }

    #[test]
    fn reset_clears() {
        let p = tmp_path("reset");
        let s = Store::open(&p).unwrap();
        s.write_batch(&[BatchOp::PutNodeStats("A".into(), NodeStatsBlob::default())])
            .unwrap();
        assert_eq!(s.approximate_stats().unwrap().smart_node_stats, 1);
        s.reset().unwrap();
        assert_eq!(s.approximate_stats().unwrap().smart_node_stats, 0);
    }
}
