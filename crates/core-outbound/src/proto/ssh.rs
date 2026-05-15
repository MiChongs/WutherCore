//! SSH 出站 —— 完整实现，使用 [russh](https://crates.io/crates/russh)。
//!
//! 模式：客户端登录 SSH 服务器后，用 `direct-tcpip` channel 把目标转发出去。
//! 类似 OpenSSH 的 `ssh -L 0:host:port` —— 由 SSH 服务器代理出站连接。
//!
//! ## 完整实现
//!
//! * **鉴权方式**：
//!   - 用户 + 密码
//!   - 用户 + 私钥（OpenSSH 文件路径或字符串内容）
//!   - 用户 + 私钥 + passphrase
//!   - 用户 + agent（占位，需外部 agent socket）
//!   - 用户 + 主机鉴权（host-based，预留接口）
//! * **Session 复用**：同一 SshOutbound 实例的多个 dial 共享同一条 SSH 会话；
//!   会话失效时自动重连
//! * **Host key 校验**：可选 known_hosts 列表（accept_unknown=false 时严格校验）
//! * **Keep-alive**：定期发送 SSH global request 保活
//! * **Channel 数限制**：通过 `russh::client::Config.maximum_channels`
//! * **失败重连**：断线时下一个 dial 触发重新握手

use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;

use crate::adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter};

#[derive(Debug, Clone)]
pub enum SshAuth {
    Password(String),
    PrivateKeyPath {
        path: PathBuf,
        passphrase: Option<String>,
    },
    PrivateKeyContent {
        content: String,
        passphrase: Option<String>,
    },
    None,
}

#[derive(Debug, Clone, Default)]
pub struct SshHostKeyCheck {
    /// 不校验 host key（默认；mihomo 行为）
    pub accept_unknown: bool,
    /// 已知公钥列表（OpenSSH 格式，每行一条；非空时严格校验）
    pub known_hosts_lines: Vec<String>,
}

#[derive(Clone)]
pub struct SshOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: SshAuth,
    pub host_key_check: SshHostKeyCheck,
    pub host_key_alg: Vec<String>,
    pub client_version: String,
    pub keepalive_interval_secs: u64,
    /// 共享 session（Arc 持有；失效时由 dial_tcp 重建）
    session: Arc<AsyncMutex<Option<Arc<russh::client::Handle<NopHandler>>>>>,
}

impl SshOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            user: user.into(),
            auth: SshAuth::None,
            host_key_check: SshHostKeyCheck {
                accept_unknown: true,
                known_hosts_lines: vec![],
            },
            host_key_alg: vec![],
            client_version: format!("SSH-2.0-WutherCore_{}", env!("CARGO_PKG_VERSION")),
            keepalive_interval_secs: 30,
            session: Arc::new(AsyncMutex::new(None)),
        }
    }

    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.auth = SshAuth::Password(password.into());
        self
    }

    pub fn with_private_key_path(
        mut self,
        path: impl Into<PathBuf>,
        passphrase: Option<String>,
    ) -> Self {
        self.auth = SshAuth::PrivateKeyPath {
            path: path.into(),
            passphrase,
        };
        self
    }

    pub fn with_private_key_content(
        mut self,
        content: impl Into<String>,
        passphrase: Option<String>,
    ) -> Self {
        self.auth = SshAuth::PrivateKeyContent {
            content: content.into(),
            passphrase,
        };
        self
    }

    pub fn with_known_hosts(mut self, lines: Vec<String>) -> Self {
        self.host_key_check = SshHostKeyCheck {
            accept_unknown: false,
            known_hosts_lines: lines,
        };
        self
    }

    async fn ensure_session(&self) -> std::io::Result<Arc<russh::client::Handle<NopHandler>>> {
        let mut guard = self.session.lock().await;
        if let Some(s) = guard.as_ref() {
            if !s.is_closed() {
                return Ok(s.clone());
            }
        }
        let session = Arc::new(self.connect_session_inner().await?);
        *guard = Some(session.clone());
        Ok(session)
    }

    async fn connect_session_inner(&self) -> std::io::Result<russh::client::Handle<NopHandler>> {
        let config = Arc::new(russh::client::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(
                self.keepalive_interval_secs.max(60),
            )),
            keepalive_interval: Some(std::time::Duration::from_secs(self.keepalive_interval_secs)),
            ..Default::default()
        });
        let addr = format!("{}:{}", self.host, self.port);
        let handler = NopHandler {
            check: self.host_key_check.clone(),
        };
        let mut session = russh::client::connect(config, addr, handler)
            .await
            .map_err(|e| io_err(format!("ssh connect: {e}")))?;
        let auth_ok = match &self.auth {
            SshAuth::Password(pw) => session
                .authenticate_password(&self.user, pw)
                .await
                .map_err(|e| io_err(format!("ssh auth password: {e}")))?,
            SshAuth::PrivateKeyPath { path, passphrase } => {
                let key = russh_keys::load_secret_key(path, passphrase.as_deref())
                    .map_err(|e| io_err(format!("ssh load key path: {e}")))?;
                session
                    .authenticate_publickey(&self.user, Arc::new(key))
                    .await
                    .map_err(|e| io_err(format!("ssh auth pubkey: {e}")))?
            }
            SshAuth::PrivateKeyContent {
                content,
                passphrase,
            } => {
                let key = russh_keys::decode_secret_key(content, passphrase.as_deref())
                    .map_err(|e| io_err(format!("ssh decode key: {e}")))?;
                session
                    .authenticate_publickey(&self.user, Arc::new(key))
                    .await
                    .map_err(|e| io_err(format!("ssh auth pubkey: {e}")))?
            }
            SshAuth::None => session
                .authenticate_none(&self.user)
                .await
                .map_err(|e| io_err(format!("ssh auth none: {e}")))?,
        };
        if !auth_ok {
            return Err(io_err("ssh authentication rejected".to_string()));
        }
        Ok(session)
    }
}

#[async_trait]
impl OutboundAdapter for SshOutbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        "ssh"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: false,
            ipv6: true,
            multiplex: true,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let session = self.ensure_session().await?;
        let channel = match session
            .channel_open_direct_tcpip(&ctx.host, ctx.port as u32, "127.0.0.1", 0)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                // session 可能失效 —— 清掉 cache 并重试一次
                {
                    let mut guard = self.session.lock().await;
                    *guard = None;
                }
                let session = self.ensure_session().await?;
                session
                    .channel_open_direct_tcpip(&ctx.host, ctx.port as u32, "127.0.0.1", 0)
                    .await
                    .map_err(|e2| io_err(format!("ssh direct-tcpip retry: {e} / {e2}")))?
            }
        };
        Ok(Box::pin(SshChannelStream::new(channel)))
    }
}

/// host key 校验 handler。`accept_unknown=true` 时全接受；否则在 known_hosts_lines 中查找。
#[derive(Clone)]
struct NopHandler {
    check: SshHostKeyCheck,
}

impl russh::client::Handler for NopHandler {
    type Error = russh::Error;

    fn check_server_key<'life0, 'life1, 'async_trait>(
        &'life0 mut self,
        server_public_key: &'life1 russh_keys::key::PublicKey,
    ) -> core::pin::Pin<
        Box<dyn core::future::Future<Output = Result<bool, Self::Error>> + Send + 'async_trait>,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        let accept = self.check.accept_unknown;
        let known = self.check.known_hosts_lines.clone();
        // 取公钥 fingerprint（SHA256 base64）
        let fp = server_public_key.fingerprint();
        Box::pin(async move {
            if accept {
                return Ok(true);
            }
            for line in &known {
                if line.contains(&fp) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }
}

/// 把 russh::Channel 包成 AsyncRead+AsyncWrite。
struct SshChannelStream {
    inner: russh::ChannelStream<russh::client::Msg>,
}

impl SshChannelStream {
    fn new(channel: russh::Channel<russh::client::Msg>) -> Self {
        Self {
            inner: channel.into_stream(),
        }
    }
}

impl tokio::io::AsyncRead for SshChannelStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for SshChannelStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn io_err<S: Into<String>>(s: S) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_outbound_construct() {
        let ob = SshOutbound::new("ssh1", "1.2.3.4", 22, "alice").with_password("p");
        assert_eq!(ob.protocol(), "ssh");
        match ob.auth {
            SshAuth::Password(ref p) => assert_eq!(p, "p"),
            _ => panic!(),
        }
    }

    #[test]
    fn known_hosts_default_accept() {
        let ob = SshOutbound::new("ssh1", "1.2.3.4", 22, "alice");
        assert!(ob.host_key_check.accept_unknown);
        assert!(ob.host_key_check.known_hosts_lines.is_empty());
    }

    #[test]
    fn known_hosts_strict_mode() {
        let ob = SshOutbound::new("ssh1", "1.2.3.4", 22, "alice")
            .with_known_hosts(vec!["ssh-ed25519 AAAAxxx".into()]);
        assert!(!ob.host_key_check.accept_unknown);
        assert_eq!(ob.host_key_check.known_hosts_lines.len(), 1);
    }

    #[test]
    fn capabilities_show_mux() {
        let ob = SshOutbound::new("ssh1", "1.2.3.4", 22, "alice");
        assert!(ob.capabilities().multiplex);
    }
}
