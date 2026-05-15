//! 智能 TCP 监听 —— 特权端口降级 + share 模式选地址 + 端口冲突重试。

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::RangeInclusive,
};

use core_config::model::Share;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::privilege::PrivilegeReport;

/// 根据 share 配置选 bind 地址。
///
/// * `share = false` → `127.0.0.1`（仅本机）
/// * `share = home`  → `0.0.0.0`（局域网）
/// * `share = all`   → `0.0.0.0`（要求设置 secret，否则启动应在调用方报错）
pub fn select_bind_addr(share: Share, port: u16) -> SocketAddr {
    let ip: IpAddr = match share {
        Share::False => Ipv4Addr::new(127, 0, 0, 1).into(),
        Share::Home | Share::All => Ipv4Addr::UNSPECIFIED.into(),
    };
    SocketAddr::new(ip, port)
}

/// 尝试绑定；失败时智能降级：
///
/// 1. PermissionDenied 且 `report.can_bind_low_ports == false` → 改为 fallback 高位端口。
/// 2. AddrInUse → 在 fallback 范围内寻找可用端口。
/// 3. 仍失败 → 返回最后错误。
///
/// 默认 fallback 范围：`9001..=9099`。
pub async fn bind_with_fallback(
    desired: SocketAddr,
    report: &PrivilegeReport,
    fallback_range: Option<RangeInclusive<u16>>,
) -> std::io::Result<TcpListener> {
    // 1) 直接尝试期望端口
    match TcpListener::bind(desired).await {
        Ok(l) => return Ok(l),
        Err(e) => {
            let reason = match e.kind() {
                std::io::ErrorKind::PermissionDenied
                    if desired.port() < 1024 && !report.can_bind_low_ports =>
                {
                    "low-port permission denied"
                }
                std::io::ErrorKind::AddrInUse => "address in use",
                _ => return Err(e),
            };
            warn!(
                target: "inbound::listener",
                addr = %desired,
                reason = reason,
                "bind failed; attempting fallback"
            );
        }
    }

    // 2) 在 fallback 范围内顺序尝试
    let range = fallback_range.unwrap_or(9001..=9099);
    for port in range.clone() {
        let alt = SocketAddr::new(desired.ip(), port);
        if let Ok(l) = TcpListener::bind(alt).await {
            info!(
                target: "inbound::listener",
                want = %desired,
                got = %alt,
                "bound to fallback port"
            );
            return Ok(l);
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        format!(
            "bind failed at {} and all fallbacks {}..={}",
            desired,
            range.clone().next().unwrap_or(0),
            range.last().unwrap_or(0)
        ),
    ))
}

#[cfg(test)]
mod tests {
    use core_config::model::Share;

    use super::*;

    #[test]
    fn select_bind_addr_share_modes() {
        let a = select_bind_addr(Share::False, 7890);
        assert_eq!(a.ip().to_string(), "127.0.0.1");
        let a = select_bind_addr(Share::Home, 7890);
        assert_eq!(a.ip().to_string(), "0.0.0.0");
        let a = select_bind_addr(Share::All, 7890);
        assert_eq!(a.ip().to_string(), "0.0.0.0");
    }

    #[tokio::test]
    async fn fallback_when_addr_in_use() {
        // 占用一个端口
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        let report = PrivilegeReport::detect();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        // 应当 fallback 到高位端口段
        let l = bind_with_fallback(addr, &report, Some(20000..=20100))
            .await
            .unwrap();
        let bound_port = l.local_addr().unwrap().port();
        assert_ne!(bound_port, port, "应当 fallback 到不同端口");
        assert!((20000..=20100).contains(&bound_port));
    }
}
