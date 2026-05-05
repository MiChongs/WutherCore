//! Android JNI 入口 —— 暴露给宿主 App（Java/Kotlin）的 native 函数。
//!
//! Java 端约定：
//! ```java
//! package org.wuthercore;
//! public class VpnBridge {
//!     static { System.loadLibrary("wuthercore"); }
//!     // 把 ParcelFileDescriptor.detachFd() 得到的 fd 交给 native。
//!     public static native void setVpnFd(int fd);
//!     // 把 VpnService 实例交给 native；native 出站 socket 会同步调用 service.protect(fd)。
//!     public static native void setVpnService(android.net.VpnService service);
//!     // 读取同一份 YAML，导出 VpnService.Builder 需要的 address/route/dns/app 配置 JSON。
//!     public static native String vpnServiceConfigJson(String configPath);
//!     // （可选）通知 native 可以开始工作 —— 实际 capture supervisor 启动由
//!     // proxy-core::main 控制。
//!     public static native int nativeStart();
//!     public static native void nativeStop();
//! }
//! ```
//!
//! ## 类型对齐
//!
//! JNI extern 函数签名遵循 `Java_<package_underscored>_<Class>_<method>`。
//! 这里定义最小集合；完整 JNI（JNIEnv、jobject 等）由宿主 App 接管复杂参数。

#![cfg(target_os = "android")]
#![allow(unsafe_code)]
#![allow(non_snake_case)]

use std::os::fd::RawFd;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::jstring;
use jni::{JNIEnv, JavaVM};
use parking_lot::Mutex;
use tracing::{debug, warn};

static STARTED: AtomicBool = AtomicBool::new(false);
static VPN_PROTECTOR: Mutex<Option<Arc<AndroidVpnServiceProtector>>> = Mutex::new(None);

struct AndroidVpnServiceProtector {
    vm: JavaVM,
    service: GlobalRef,
}

impl AndroidVpnServiceProtector {
    fn io_error(context: &'static str, err: impl std::fmt::Display) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, format!("{context}: {err}"))
    }
}

impl core_outbound::SocketProtector for AndroidVpnServiceProtector {
    fn protect(&self, socket: core_outbound::ProtectedSocket) -> std::io::Result<()> {
        let fd = i32::try_from(socket.raw()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("android protect fd out of range: {}", socket.raw()),
            )
        })?;
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|e| Self::io_error("attach JVM", e))?;
        let ret = env
            .call_method(self.service.as_obj(), "protect", "(I)Z", &[JValue::Int(fd)])
            .map_err(|e| Self::io_error("VpnService.protect", e))?;
        let ok = ret.z().map_err(|e| Self::io_error("protect return", e))?;
        if ok {
            debug!(target: "capture::android", fd, "protected outbound socket from VPN");
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("VpnService.protect({fd}) returned false"),
            ))
        }
    }
}

/// `void setVpnFd(int fd)` —— 把 ParcelFileDescriptor.detachFd() 的 fd 交给本进程。
#[no_mangle]
pub extern "system" fn Java_org_wuthercore_VpnBridge_setVpnFd(
    _env: *mut core::ffi::c_void,
    _class: *mut core::ffi::c_void,
    fd: i32,
) {
    if fd < 0 {
        return;
    }
    crate::platform::android_tun_io::set_vpn_fd(fd as RawFd);
}

/// `void setVpnService(VpnService service)` —— 注册真实 socket protect 回调。
///
/// Android VpnService 会捕获本进程自己创建的出站 socket；所有 outbound socket
/// 在 connect/send 前必须调用 `VpnService.protect(fd)`，否则代理节点连接会再次
/// 进入 TUN，形成自循环。
#[no_mangle]
pub extern "system" fn Java_org_wuthercore_VpnBridge_setVpnService(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    service: JObject<'_>,
) {
    if service.is_null() {
        *VPN_PROTECTOR.lock() = None;
        core_outbound::set_socket_protector(None);
        return;
    }
    let vm = match env.get_java_vm() {
        Ok(vm) => vm,
        Err(e) => {
            warn!(target: "capture::android", error = %e, "get JavaVM failed");
            return;
        }
    };
    let service = match env.new_global_ref(service) {
        Ok(service) => service,
        Err(e) => {
            warn!(target: "capture::android", error = %e, "create VpnService global ref failed");
            return;
        }
    };
    let protector = Arc::new(AndroidVpnServiceProtector { vm, service });
    *VPN_PROTECTOR.lock() = Some(protector.clone());
    core_outbound::set_socket_protector(Some(protector));
}

/// `String vpnServiceConfigJson(String configPath)` —— 从 YAML 导出 Android
/// `VpnService.Builder` 需要的完整 L3 配置。
///
/// Android VpnService 不是 bridge；宿主 App 必须把这里返回的 `addresses`,
/// `routes`, `dns_servers`, `allowed_applications` / `disallowed_applications`
/// 逐项写入 Builder，随后 `establish()` 并通过 `setVpnFd(fd)` 交给 native。
/// 如果没有这些 Builder 路由，native 侧即使拿到 fd 也不会有真实应用流量进入。
#[no_mangle]
pub extern "system" fn Java_org_wuthercore_VpnBridge_vpnServiceConfigJson(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    config_path: JString<'_>,
) -> jstring {
    let json = match vpn_service_config_json_from_path(&mut env, config_path) {
        Ok(json) => json,
        Err(error) => serde_json::json!({ "error": error }).to_string(),
    };
    new_jstring(&mut env, json)
}

fn vpn_service_config_json_from_path(
    env: &mut JNIEnv<'_>,
    config_path: JString<'_>,
) -> Result<String, String> {
    let path: String = env
        .get_string(&config_path)
        .map_err(|e| format!("read config path from JNI: {e}"))?
        .into();
    let runtime_plan =
        core_config::load_from_path(&path).map_err(|e| format!("load config {path}: {e}"))?;
    let capture_plan = crate::CapturePlan::from_config(&runtime_plan.capture)
        .map_err(|e| format!("build capture plan: {e}"))?;
    crate::android_vpn_config::build_vpn_service_config_json(&capture_plan)
        .map_err(|e| format!("encode vpn service config: {e}"))
}

fn new_jstring(env: &mut JNIEnv<'_>, value: String) -> jstring {
    match env.new_string(value) {
        Ok(value) => value.into_raw(),
        Err(e) => {
            warn!(target: "capture::android", error = %e, "create Java string failed");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_wuthercore_VpnBridge_clearVpnService(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) {
    *VPN_PROTECTOR.lock() = None;
    core_outbound::set_socket_protector(None);
}

/// `int nativeStart()` —— 标记 native 已就绪；返回 0 / 非 0 表示状态。
#[no_mangle]
pub extern "system" fn Java_org_wuthercore_VpnBridge_nativeStart(
    _env: *mut core::ffi::c_void,
    _class: *mut core::ffi::c_void,
) -> i32 {
    STARTED.store(true, Ordering::SeqCst);
    0
}

/// `void nativeStop()` —— 仅做标记；真正停止由上层 supervisor 完成。
#[no_mangle]
pub extern "system" fn Java_org_wuthercore_VpnBridge_nativeStop(
    _env: *mut core::ffi::c_void,
    _class: *mut core::ffi::c_void,
) {
    STARTED.store(false, Ordering::SeqCst);
}

/// `void notifyNetworkChanged(String interfaceName)` —— 物理网卡/连接变更通知。
///
/// 当 Android ConnectivityManager 检测到默认网络变化（WiFi→mobile、重新连接等），
/// 宿主 App 应调用此函数。Native 侧会：
/// 1. 更新 outbound 绑定接口
/// 2. 通知 DNS resolver 重建连接
/// 3. 广播给所有监听者（如 supervisor 可选择 rebind）
///
/// ```java
/// // Java side: in ConnectivityManager.NetworkCallback.onAvailable / onLost
/// VpnBridge.notifyNetworkChanged(activeNetwork.getInterfaceName());
/// ```
#[no_mangle]
pub extern "system" fn Java_org_wuthercore_VpnBridge_notifyNetworkChanged(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    interface_name: JString<'_>,
) {
    let iface: Option<String> = if interface_name.is_null() {
        None
    } else {
        env.get_string(&interface_name).ok().map(|s| s.into())
    };
    crate::net_monitor::notify_network_changed(iface);
}

/// `void setDefaultInterface(String interfaceName)` —— 设置出站绑定的物理接口名。
///
/// 供 Android 在启动时或网络切换时主动设置（如 "wlan0" / "rmnet_data0"）。
/// 设置后，所有新建 outbound 连接会优先 bind 到该接口。
#[no_mangle]
pub extern "system" fn Java_org_wuthercore_VpnBridge_setDefaultInterface(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    interface_name: JString<'_>,
) {
    let iface: Option<String> = if interface_name.is_null() {
        None
    } else {
        env.get_string(&interface_name).ok().map(|s| s.into())
    };
    core_outbound::set_outbound_interface(iface);
}

pub fn is_started() -> bool {
    STARTED.load(Ordering::SeqCst)
}
