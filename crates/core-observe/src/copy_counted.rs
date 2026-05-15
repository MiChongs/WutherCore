//! 带流量统计 + 取消信号的双向 splice。
//!
//! 与 `tokio::io::copy_bidirectional` 的差异：
//! 1. 每读到一段 N 字节立刻 `up.fetch_add(N)` / `down.fetch_add(N)` —— per-conn
//!    流量计数实时更新（用于 dashboard 的 upload/download 列与速率列）。
//! 2. 同时把 N 透传给可选的全局 [`crate::Metrics`] —— 让 `/traffic` WS 的
//!    总上下行也增长。
//! 3. 接受一个 `cancel: Arc<Notify>`，外部（如 DELETE /connections/:id）触发
//!    时立刻 shutdown 双向 socket，让数据流尽快真正断开。
//!
//! 用法（与现有手写 split + try_join 等价，但少 30 行模板）：
//! ```ignore
//! let (up, down) = guard.counters();
//! let cancel = guard.cancel_token();
//! let metrics = Some(runtime.metrics.clone());
//! let (n_up, n_down) =
//!     copy_bidirectional_counted(&mut inbound, &mut outbound, up, down, cancel, metrics).await?;
//! ```

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Notify,
};

use crate::{ConnectionAccounting, Metrics};

const BUF_SIZE: usize = 32 * 1024;

/// 把 `read` 结果归类为：拿到 N 字节继续 / 干净 EOF 该 break / 真错。
///
/// rustls 在 TLS 对端关 TCP 不发 close_notify 时返回 `UnexpectedEof`，RFC 8446
/// 上是 SHOULD 不是 MUST，实践中海量服务器都不发；mihomo / clash / sing-box
/// 一致把它当 clean EOF 吃掉，这里也对齐——HTTP 等应用层有自己的长度校验，
/// TLS-level 的截断攻击检测对代理场景没意义。
enum ReadOutcome {
    Data(usize),
    Eof,
    Err(io::Error),
}

fn classify_read(r: io::Result<usize>) -> ReadOutcome {
    match r {
        Ok(0) => ReadOutcome::Eof,
        Ok(n) => ReadOutcome::Data(n),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => ReadOutcome::Eof,
        Err(e) => ReadOutcome::Err(e),
    }
}

/// 双向拷贝 a ↔ b，每段透传到 per-conn + 全局 counter。
///
/// 返回 `(up_total, down_total)` —— 即便一方提前出错也会尽量返回到那一刻为止
/// 的流量统计（错误本身通过 `Result` 暴露）。
pub async fn copy_bidirectional_counted<A, B>(
    a: &mut A,
    b: &mut B,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    cancel: Arc<Notify>,
    metrics: Option<Arc<Metrics>>,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let up_metrics = metrics.clone();
    let up_counter = up.clone();
    let cancel_up = cancel.clone();
    let up_task = async move {
        let mut buf = vec![0u8; BUF_SIZE];
        let mut total: u64 = 0;
        loop {
            tokio::select! {
                _ = cancel_up.notified() => {
                    let _ = bw.shutdown().await;
                    break;
                }
                r = ar.read(&mut buf) => {
                    let n = match classify_read(r) {
                        ReadOutcome::Data(n) => n,
                        ReadOutcome::Eof => { let _ = bw.shutdown().await; break; }
                        ReadOutcome::Err(e) => return Err(e),
                    };
                    if let Err(e) = bw.write_all(&buf[..n]).await {
                        return Err(e);
                    }
                    total += n as u64;
                    up_counter.fetch_add(n as u64, Ordering::Relaxed);
                    if let Some(m) = &up_metrics { m.add_up(n as u64); }
                }
            }
        }
        Ok::<u64, io::Error>(total)
    };

    let down_metrics = metrics.clone();
    let down_counter = down.clone();
    let cancel_down = cancel.clone();
    let down_task = async move {
        let mut buf = vec![0u8; BUF_SIZE];
        let mut total: u64 = 0;
        loop {
            tokio::select! {
                _ = cancel_down.notified() => {
                    let _ = aw.shutdown().await;
                    break;
                }
                r = br.read(&mut buf) => {
                    let n = match classify_read(r) {
                        ReadOutcome::Data(n) => n,
                        ReadOutcome::Eof => { let _ = aw.shutdown().await; break; }
                        ReadOutcome::Err(e) => return Err(e),
                    };
                    if let Err(e) = aw.write_all(&buf[..n]).await {
                        return Err(e);
                    }
                    total += n as u64;
                    down_counter.fetch_add(n as u64, Ordering::Relaxed);
                    if let Some(m) = &down_metrics { m.add_down(n as u64); }
                }
            }
        }
        Ok::<u64, io::Error>(total)
    };

    // try_join：任一方向出错立刻短路；正常 EOF 双方各自 break 后 join。
    let (n_up, n_down) = tokio::try_join!(up_task, down_task)?;
    Ok((n_up, n_down))
}

/// 双向拷贝并通过完整连接管理器计数。
///
/// 这个路径对应 mihomo `statistic.NewTCPTracker`/`NewUDPTracker` 的热路径：
/// 每段数据同时更新连接累计值、管理器总流量、连接 max rate 和 `/traffic`
/// 全局指标。
pub async fn copy_bidirectional_tracked<A, B>(
    a: &mut A,
    b: &mut B,
    accounting: ConnectionAccounting,
    metrics: Option<Arc<Metrics>>,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let up_metrics = metrics.clone();
    let up_accounting = accounting.clone();
    let cancel_up = accounting.cancel_token();
    let up_task = async move {
        let mut buf = vec![0u8; BUF_SIZE];
        let mut total: u64 = 0;
        loop {
            tokio::select! {
                _ = cancel_up.notified() => {
                    let _ = bw.shutdown().await;
                    break;
                }
                r = ar.read(&mut buf) => {
                    let n = match classify_read(r) {
                        ReadOutcome::Data(n) => n,
                        ReadOutcome::Eof => { let _ = bw.shutdown().await; break; }
                        ReadOutcome::Err(e) => return Err(e),
                    };
                    if let Err(e) = bw.write_all(&buf[..n]).await {
                        return Err(e);
                    }
                    total += n as u64;
                    up_accounting.record_upload(n as u64);
                    if let Some(m) = &up_metrics { m.add_up(n as u64); }
                }
            }
        }
        Ok::<u64, io::Error>(total)
    };

    let down_metrics = metrics.clone();
    let down_accounting = accounting.clone();
    let cancel_down = accounting.cancel_token();
    let down_task = async move {
        let mut buf = vec![0u8; BUF_SIZE];
        let mut total: u64 = 0;
        loop {
            tokio::select! {
                _ = cancel_down.notified() => {
                    let _ = aw.shutdown().await;
                    break;
                }
                r = br.read(&mut buf) => {
                    let n = match classify_read(r) {
                        ReadOutcome::Data(n) => n,
                        ReadOutcome::Eof => { let _ = aw.shutdown().await; break; }
                        ReadOutcome::Err(e) => return Err(e),
                    };
                    if let Err(e) = aw.write_all(&buf[..n]).await {
                        return Err(e);
                    }
                    total += n as u64;
                    down_accounting.record_download(n as u64);
                    if let Some(m) = &down_metrics { m.add_down(n as u64); }
                }
            }
        }
        Ok::<u64, io::Error>(total)
    };

    let (n_up, n_down) = tokio::try_join!(up_task, down_task)?;
    Ok((n_up, n_down))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// rustls 在 peer 关 TCP 不发 close_notify 时返回 `UnexpectedEof`；
    /// 该错误必须被归类为 clean EOF，否则 relay 层会 `warn!` 一条假错误。
    /// 这是 mihomo / clash / sing-box 的一致行为。
    #[test]
    fn classify_unexpected_eof_is_clean_eof() {
        let err = io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "peer closed without close_notify",
        );
        assert!(matches!(classify_read(Err(err)), ReadOutcome::Eof));
    }

    /// 真正的错误（连接重置等）继续按 Err 透传，不能被吃掉。
    #[test]
    fn classify_other_io_errors_propagate() {
        let err = io::Error::new(io::ErrorKind::ConnectionReset, "RST");
        assert!(matches!(classify_read(Err(err)), ReadOutcome::Err(_)));
    }

    #[test]
    fn classify_normal_data_and_eof() {
        assert!(matches!(classify_read(Ok(0)), ReadOutcome::Eof));
        assert!(matches!(classify_read(Ok(42)), ReadOutcome::Data(42)));
    }

    #[tokio::test]
    async fn round_trip_counts_bytes() {
        let (mut client_a, mut server_a) = tokio::io::duplex(8 * 1024);
        let (mut client_b, mut server_b) = tokio::io::duplex(8 * 1024);

        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let cancel = Arc::new(Notify::new());

        let up_c = up.clone();
        let down_c = down.clone();
        let cancel_c = cancel.clone();
        let bridge = tokio::spawn(async move {
            copy_bidirectional_counted(&mut server_a, &mut server_b, up_c, down_c, cancel_c, None)
                .await
                .unwrap()
        });

        // client_a → bridge → client_b
        let payload = vec![7u8; 4 * 1024];
        client_a.write_all(&payload).await.unwrap();
        client_a.shutdown().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        client_b.read_exact(&mut got).await.unwrap();
        cancel.notify_waiters();
        drop(client_a);
        drop(client_b);

        let (n_up, n_down) = tokio::time::timeout(std::time::Duration::from_millis(500), bridge)
            .await
            .expect("bridge timeout")
            .unwrap();
        assert_eq!(n_up, payload.len() as u64);
        assert!(n_down <= payload.len() as u64); // 可能为 0
        assert_eq!(up.load(Ordering::Relaxed), payload.len() as u64);
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn tracked_round_trip_updates_manager_totals() {
        let table = crate::ConnectionTable::new();
        let guard = table.open(crate::ConnectionMeta::default());
        let accounting = guard.accounting();
        let (mut client_a, mut server_a) = tokio::io::duplex(8 * 1024);
        let (mut client_b, mut server_b) = tokio::io::duplex(8 * 1024);

        let bridge = tokio::spawn(async move {
            copy_bidirectional_tracked(&mut server_a, &mut server_b, accounting, None).await
        });

        client_a.write_all(b"tracked").await.unwrap();
        let mut got = [0u8; 7];
        client_b.read_exact(&mut got).await.unwrap();
        guard.cancel.notify_waiters();
        drop(client_a);
        drop(client_b);

        let result = tokio::time::timeout(std::time::Duration::from_millis(500), bridge)
            .await
            .expect("bridge timeout")
            .expect("bridge join");
        assert!(result.is_ok());
        assert_eq!(&got, b"tracked");
        assert_eq!(table.total(), (7, 0));
        let snap = table.manager_snapshot();
        assert_eq!(snap.upload_total, 7);
        assert_eq!(snap.connections[0].upload, 7);
        assert!(snap.connections[0].max_upload_rate >= 7);
    }

    #[tokio::test]
    async fn cancel_signals_shutdown() {
        let (mut client_a, mut server_a) = tokio::io::duplex(8 * 1024);
        let (mut client_b, mut server_b) = tokio::io::duplex(8 * 1024);

        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let cancel = Arc::new(Notify::new());
        let cancel_c = cancel.clone();
        let bridge = tokio::spawn(async move {
            copy_bidirectional_counted(&mut server_a, &mut server_b, up, down, cancel_c, None).await
        });

        // 写一点数据但不关闭，让 splice 阻塞在下一次 read
        client_a.write_all(b"hello").await.unwrap();
        let _ = client_b.read_exact(&mut [0u8; 5]).await.unwrap();

        // 触发取消
        let start = std::time::Instant::now();
        cancel.notify_waiters();

        // bridge 应在 200ms 内返回
        let r = tokio::time::timeout(std::time::Duration::from_millis(500), bridge)
            .await
            .expect("bridge timeout")
            .expect("bridge join");
        assert!(r.is_ok());
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
    }
}
