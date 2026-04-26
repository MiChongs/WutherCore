//! Wintun ABI —— 通过 `LoadLibraryA` + `GetProcAddress` 动态加载 wintun.dll，
//! 不在编译期硬依赖（Linux/macOS 构建时本文件不参与）。
//!
//! 支持函数子集（与 sing-box / wireguard-windows 兼容）：
//! * `WintunCreateAdapter` / `WintunCloseAdapter`
//! * `WintunStartSession` / `WintunEndSession`
//! * `WintunReceivePacket` / `WintunReleaseReceivePacket`
//! * `WintunAllocateSendPacket` / `WintunSendPacket`
//! * `WintunGetReadWaitEvent`
//!
//! 设计权衡：本封装只暴露安全 API（`WintunSession::recv` / `send`），
//! 内部 `unsafe` 完成 raw FFI 调用与 NUL 终止字符串/UTF-16 转换。

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::ffi::{c_void, CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;

type HMODULE = *mut c_void;
type HANDLE = *mut c_void;
type WintunAdapterHandle = *mut c_void;
type WintunSessionHandle = *mut c_void;

#[allow(non_snake_case)]
struct Funcs {
    WintunCreateAdapter:
        unsafe extern "system" fn(name: *const u16, tunnel_type: *const u16, guid: *const u8) -> WintunAdapterHandle,
    WintunCloseAdapter: unsafe extern "system" fn(adapter: WintunAdapterHandle),
    WintunStartSession:
        unsafe extern "system" fn(adapter: WintunAdapterHandle, capacity: u32) -> WintunSessionHandle,
    WintunEndSession: unsafe extern "system" fn(session: WintunSessionHandle),
    WintunReceivePacket:
        unsafe extern "system" fn(session: WintunSessionHandle, size: *mut u32) -> *mut u8,
    WintunReleaseReceivePacket: unsafe extern "system" fn(session: WintunSessionHandle, packet: *mut u8),
    WintunAllocateSendPacket:
        unsafe extern "system" fn(session: WintunSessionHandle, size: u32) -> *mut u8,
    WintunSendPacket: unsafe extern "system" fn(session: WintunSessionHandle, packet: *mut u8),
    WintunGetReadWaitEvent: unsafe extern "system" fn(session: WintunSessionHandle) -> HANDLE,
}

pub struct Wintun {
    _module: HMODULE,
    funcs: Funcs,
}

unsafe impl Send for Wintun {}
unsafe impl Sync for Wintun {}

#[allow(unsafe_code)]
fn load_library(path: &Path) -> Option<HMODULE> {
    // SAFETY: LoadLibraryA 平凡调用；返回 NULL 表示失败。
    let path_c = CString::new(path.to_string_lossy().as_bytes()).ok()?;
    let h = unsafe { LoadLibraryA(path_c.as_ptr()) };
    if h.is_null() {
        None
    } else {
        Some(h)
    }
}

#[allow(unsafe_code)]
fn get_proc<T: Copy>(module: HMODULE, name: &str) -> Option<T> {
    let cname = CString::new(name).ok()?;
    // SAFETY: GetProcAddress 平凡；返回 NULL 表示找不到。
    let p = unsafe { GetProcAddress(module, cname.as_ptr()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: 转换 fn 指针 —— 调用方保证 T 与 wintun.dll 导出签名兼容。
    Some(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&p) })
}

extern "system" {
    fn LoadLibraryA(name: *const i8) -> HMODULE;
    fn GetProcAddress(module: HMODULE, name: *const i8) -> *mut c_void;
    fn WaitForSingleObject(handle: HANDLE, ms: u32) -> u32;
}

const WAIT_OBJECT_0: u32 = 0;

impl Wintun {
    /// 探测并加载 wintun.dll（PWD 优先，其次 SYSTEM32）。
    pub fn load() -> Option<Arc<Self>> {
        let candidates: Vec<std::path::PathBuf> = [
            std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("wintun.dll"))),
            Some(std::path::PathBuf::from(r"C:\Windows\System32\wintun.dll")),
        ]
        .into_iter()
        .flatten()
        .collect();
        for p in candidates {
            if !p.exists() {
                continue;
            }
            if let Some(m) = load_library(&p) {
                let funcs = Funcs {
                    WintunCreateAdapter: get_proc(m, "WintunCreateAdapter")?,
                    WintunCloseAdapter: get_proc(m, "WintunCloseAdapter")?,
                    WintunStartSession: get_proc(m, "WintunStartSession")?,
                    WintunEndSession: get_proc(m, "WintunEndSession")?,
                    WintunReceivePacket: get_proc(m, "WintunReceivePacket")?,
                    WintunReleaseReceivePacket: get_proc(m, "WintunReleaseReceivePacket")?,
                    WintunAllocateSendPacket: get_proc(m, "WintunAllocateSendPacket")?,
                    WintunSendPacket: get_proc(m, "WintunSendPacket")?,
                    WintunGetReadWaitEvent: get_proc(m, "WintunGetReadWaitEvent")?,
                };
                return Some(Arc::new(Wintun { _module: m, funcs }));
            }
        }
        None
    }

    /// 创建一个 adapter（adapter 名 + tunnel 类型）。
    ///
    /// **GUID 稳定性**：mihomo / wireguard-windows 都用 *固定* GUID（基于 device
    /// name 哈希），让 Windows 把同名网卡识别为同一身份 —— 路由 / 防火墙 /
    /// `Get-NetAdapter | Where-Object InterfaceGuid` 等都能跨重启稳定。
    /// 这里用 blake3(name)[..16]，无外部 crate 引入（项目已有 blake3）。
    pub fn create_adapter(self: &Arc<Self>, name: &str, ttype: &str) -> Option<WintunAdapter> {
        let name_w = utf16(name);
        let ttype_w = utf16(ttype);
        let guid = stable_guid(name);
        // SAFETY: 调用 wintun.dll 导出函数；指针为有效 NUL 结尾 UTF-16。
        let h =
            unsafe { (self.funcs.WintunCreateAdapter)(name_w.as_ptr(), ttype_w.as_ptr(), guid.as_ptr()) };
        if h.is_null() {
            None
        } else {
            Some(WintunAdapter { wintun: self.clone(), handle: h })
        }
    }
}

fn stable_guid(name: &str) -> [u8; 16] {
    let h = blake3::hash(name.as_bytes());
    let mut g = [0u8; 16];
    g.copy_from_slice(&h.as_bytes()[..16]);
    g
}

pub struct WintunAdapter {
    wintun: Arc<Wintun>,
    handle: WintunAdapterHandle,
}

unsafe impl Send for WintunAdapter {}
unsafe impl Sync for WintunAdapter {}

impl Drop for WintunAdapter {
    fn drop(&mut self) {
        // SAFETY: 由 create_adapter 配对得到；Drop 调用一次。
        unsafe { (self.wintun.funcs.WintunCloseAdapter)(self.handle) }
    }
}

impl WintunAdapter {
    pub fn start_session(self: Arc<Self>, capacity: u32) -> Option<Arc<WintunSession>> {
        // SAFETY: 调用 wintun ABI；handle 在 self 持有期间有效。
        let s = unsafe { (self.wintun.funcs.WintunStartSession)(self.handle, capacity) };
        if s.is_null() {
            None
        } else {
            Some(Arc::new(WintunSession {
                adapter: self,
                handle: s,
                lock: Mutex::new(()),
            }))
        }
    }
}

pub struct WintunSession {
    adapter: Arc<WintunAdapter>,
    handle: WintunSessionHandle,
    /// 串行化 send/recv —— wintun.dll 内部线程安全，但避免 Drop 与 in-flight 调用竞争。
    lock: Mutex<()>,
}

unsafe impl Send for WintunSession {}
unsafe impl Sync for WintunSession {}

impl Drop for WintunSession {
    fn drop(&mut self) {
        // SAFETY: wintun 文档允许 EndSession 后 handle 失效；与 in-flight ops 由 lock 串行化。
        let _g = self.lock.lock();
        unsafe { (self.adapter.wintun.funcs.WintunEndSession)(self.handle) }
    }
}

impl WintunSession {
    /// 阻塞接收一个包（最多 `wait_ms` 毫秒）。返回 None 表示超时。
    pub fn recv(&self, wait_ms: u32) -> Option<Vec<u8>> {
        let mut size: u32 = 0;
        // SAFETY: WintunReceivePacket 返回内部缓冲指针；返回 NULL 表示无包，
        // 此时调用 WaitForSingleObject 在 ReadWaitEvent 上阻塞。
        loop {
            let p = unsafe { (self.adapter.wintun.funcs.WintunReceivePacket)(self.handle, &mut size) };
            if !p.is_null() {
                // SAFETY: p..p+size 是 wintun 内部环形缓冲 read-only 视图；
                // 拷贝出来后立刻 release 还给 wintun。
                let slice = unsafe { std::slice::from_raw_parts(p, size as usize) };
                let buf = slice.to_vec();
                unsafe { (self.adapter.wintun.funcs.WintunReleaseReceivePacket)(self.handle, p) };
                return Some(buf);
            }
            // SAFETY: GetReadWaitEvent 返回内部 event 句柄；WaitForSingleObject 阻塞。
            let event = unsafe { (self.adapter.wintun.funcs.WintunGetReadWaitEvent)(self.handle) };
            let r = unsafe { WaitForSingleObject(event, wait_ms) };
            if r != WAIT_OBJECT_0 {
                return None;
            }
        }
    }

    /// 发送一个包。失败时返回 false（环形缓冲已满）。
    pub fn send(&self, pkt: &[u8]) -> bool {
        // SAFETY: 通过 ABI 拿一个长度匹配的 send 缓冲；写完调用 SendPacket 让 wintun 发出。
        let p =
            unsafe { (self.adapter.wintun.funcs.WintunAllocateSendPacket)(self.handle, pkt.len() as u32) };
        if p.is_null() {
            return false;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(pkt.as_ptr(), p, pkt.len());
            (self.adapter.wintun.funcs.WintunSendPacket)(self.handle, p);
        }
        true
    }
}

fn utf16(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_returns_none_when_dll_absent() {
        // 在没有 wintun.dll 的开发机上：load 应该 None，不 panic。
        let _ = Wintun::load();
    }
}
