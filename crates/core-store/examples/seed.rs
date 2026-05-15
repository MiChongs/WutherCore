use std::sync::Arc;

use core_store::{AsyncWriter, NodeStatsBlob, Store, store::BatchOp};

#[tokio::main]
async fn main() {
    let store = Store::open("data/state/wuthercore.redb").unwrap();
    let writer = AsyncWriter::spawn(store.clone());
    for i in 0..5 {
        let mut blob = NodeStatsBlob::default();
        blob.samples = (i + 1) * 10;
        blob.success_ewma = 0.85;
        blob.p50_latency_ms = 60.0 + (i as f64) * 20.0;
        writer.enqueue(BatchOp::PutNodeStats(format!("HK-{i}"), blob));
    }
    writer.enqueue(BatchOp::PutGroupManual("main".into(), "HK-0".into()));
    writer.shutdown().await;
}
