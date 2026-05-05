//! core-feeds —— 订阅源实际拉取与解析。
//!
//! §5.3 feeds：负责把远程订阅链接转换为可用的 [`ParsedNode`] 列表。
//! 设计要点：
//! * 三种格式：base64-encoded URI 列表（最常见）、Clash/Mihomo YAML proxies、
//!   纯文本 URI（每行一个）；自动嗅探。
//! * 抓取支持：`http(s)://` via reqwest（rustls 后端，无 OpenSSL 依赖）、
//!   `file://` / 本地路径。
//! * 过滤：keep.name_has / drop.name_has；drop 优先级高于 keep。
//! * 重命名：rename.add_prefix + rename.remove。
//! * 缓存：成功一次立刻写入磁盘，失败时回退到磁盘缓存，永远不让一次抓取
//!   失败导致无可用节点。
//! * 周期刷新：每个 feed 独立按 `every` 调度；冷启动立刻拉一次。
//! * 节点热注入：通过 [`FeedSink`] trait 把新节点列表推给 Runtime。

#![forbid(unsafe_code)]

pub mod cache;
pub mod fetcher;
pub mod manager;
pub mod parser;
pub mod userinfo;

pub use cache::{url_digest, FeedDiskCache, FeedMeta};
pub use fetcher::{fetch_feed, FetchError, FetchResult};
pub use manager::{FeedManager, FeedSink, FeedStatus, FeedUpdate};
pub use parser::{apply_filter_rename, parse_feed_payload, FormatHint};
pub use userinfo::SubscriptionUserinfo;
