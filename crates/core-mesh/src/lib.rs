//! core-mesh —— 跨后端组网能力、资源仲裁与生命周期监督。
//!
//! 所有具体组网实现都通过 [`NetworkBackend`] 接入，并在修改系统路由、DNS、
//! 防火墙、接口或监听端口前，由 [`MeshSupervisor`] 统一检查资源声明。这样既能
//! 安全附着用户自行管理的系统服务，也能对 WutherCore 创建的子进程做事务启动、
//! 失败回滚和逆序关闭。

#![forbid(unsafe_code)]

use core_config::model::{Mesh, TailscaleMode};
use ipnet::IpNet;
use once_cell::sync::Lazy;
use tracing::info;

pub mod backend;
pub mod conflict;
pub mod model;
pub mod process;
pub mod registry;
pub mod supervisor;

pub use backend::{
    BackendDescriptor, BackendError, BackendResult, ExternalNetworkBackend, NetworkBackend,
    OwnedNetworkBackend,
};
pub use conflict::{
    PublicClaimIncompatibility, PublicResourceConflict, PublicResourceConflictKind,
    PublicRouteManagedResource, PublicSingletonResource, ResourceConflict, detect_conflicts,
};
pub use model::*;
pub use process::*;
pub use registry::{BackendRegistry, RegistryError};
pub use supervisor::{
    BackendCallTimeouts, BackendFailure, MeshError, MeshSupervisor, SupervisorOptions,
};

pub static TAILNET_CIDRS: Lazy<Vec<IpNet>> = Lazy::new(|| {
    ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
});

/// 启动时诊断 Tailscale 集成。
pub fn diagnose(mesh: &Mesh) -> String {
    let Some(ts) = mesh.tailscale.as_ref() else {
        return "tailscale: 未配置".into();
    };
    if !ts.on {
        return "tailscale: 关闭".into();
    }
    let mode = match ts.mode {
        TailscaleMode::Auto => "auto",
        TailscaleMode::Localapi => "localapi",
        TailscaleMode::Userspace => "userspace",
        TailscaleMode::Tsnet => "tsnet",
        TailscaleMode::Off => "off",
    };
    let report = format!(
        "tailscale: on (mode={mode}, keep_tailnet_direct={}, expose_as_node={})",
        ts.keep_tailnet_direct, ts.expose_as_node
    );
    info!(target: "mesh", report = %report, "tailscale diagnose");
    report
}

pub mod tailscale {
    pub use super::TAILNET_CIDRS;
}

mod once_cell_uses {
    #[allow(dead_code)]
    fn _ensure_use() {
        let _ = &*super::TAILNET_CIDRS;
    }
}
