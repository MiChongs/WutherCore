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
//!   - 私钥与密码按 mihomo 顺序回退
//! * **Session 复用**：同一 SshOutbound 实例的多个 dial 共享同一条 SSH 会话；
//!   会话失效时自动重连
//! * **Host key 校验**：可选 known_hosts 列表（accept_unknown=false 时严格校验）
//! * **Keep-alive**：定期发送 SSH global request 保活
//! * **Channel 数限制**：通过 `russh::client::Config.maximum_channels`
//! * **失败重连**：断线时下一个 dial 触发重新握手

use std::{borrow::Cow, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;

use crate::adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter};

#[derive(Debug, Clone)]
pub enum SshAuth {
    Password(String),
    PrivateKey(Arc<russh_keys::key::KeyPair>),
}

#[derive(Debug, Clone, Default)]
pub struct SshHostKeyCheck {
    /// 不校验 host key（默认；mihomo 行为）
    pub accept_unknown: bool,
    /// 已知公钥列表（OpenSSH 格式，每行一条；非空时严格校验）
    pub keys: Vec<russh_keys::key::PublicKey>,
}

#[derive(Clone)]
pub struct SshOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Vec<SshAuth>,
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
            auth: Vec::new(),
            host_key_check: SshHostKeyCheck {
                accept_unknown: true,
                keys: vec![],
            },
            host_key_alg: vec![],
            client_version: "SSH-2.0-OpenSSH_8.9".into(),
            keepalive_interval_secs: 30,
            session: Arc::new(AsyncMutex::new(None)),
        }
    }

    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.auth.push(SshAuth::Password(password.into()));
        self
    }

    pub fn with_private_key_path(
        mut self,
        path: impl Into<PathBuf>,
        passphrase: Option<String>,
    ) -> Result<Self, String> {
        let path = path.into();
        let key = russh_keys::load_secret_key(&path, passphrase.as_deref()).map_err(|error| {
            format!(
                "failed to load SSH private key `{}`: {error}",
                path.display()
            )
        })?;
        self.auth.push(SshAuth::PrivateKey(Arc::new(key)));
        Ok(self)
    }

    pub fn with_private_key_content(
        mut self,
        content: impl Into<String>,
        passphrase: Option<String>,
    ) -> Result<Self, String> {
        let content = content.into();
        let key = russh_keys::decode_secret_key(&content, passphrase.as_deref())
            .map_err(|error| format!("failed to decode SSH private key: {error}"))?;
        self.auth.push(SshAuth::PrivateKey(Arc::new(key)));
        Ok(self)
    }

    pub fn with_host_keys(mut self, keys: Vec<russh_keys::key::PublicKey>) -> Self {
        self.host_key_check = SshHostKeyCheck {
            accept_unknown: false,
            keys,
        };
        self
    }

    pub fn with_host_key_algorithms(mut self, algorithms: Vec<String>) -> Result<Self, String> {
        // Validate here so a misspelt security policy never degrades into the
        // library default during the first network connection.
        parse_host_key_algorithms(&algorithms)?;
        self.host_key_alg = algorithms;
        Ok(self)
    }

    pub fn with_client_version(mut self, version: impl Into<String>) -> Result<Self, String> {
        let version = version.into();
        if !version.starts_with("SSH-2.0-") || version.contains(['\r', '\n']) || version.len() > 255
        {
            return Err("SSH client version must be one RFC 4253 `SSH-2.0-*` line".into());
        }
        self.client_version = version;
        Ok(self)
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
        let mut config = russh::client::Config {
            client_id: russh::SshId::Standard(self.client_version.clone()),
            inactivity_timeout: Some(std::time::Duration::from_secs(
                self.keepalive_interval_secs.max(60),
            )),
            keepalive_interval: (self.keepalive_interval_secs > 0)
                .then(|| std::time::Duration::from_secs(self.keepalive_interval_secs)),
            ..Default::default()
        };
        if !self.host_key_alg.is_empty() {
            config.preferred.key =
                Cow::Owned(parse_host_key_algorithms(&self.host_key_alg).map_err(io_err)?);
        }
        let config = Arc::new(config);
        let addr = format!("{}:{}", self.host, self.port);
        let handler = NopHandler {
            check: self.host_key_check.clone(),
        };
        let mut session = russh::client::connect(config, addr, handler)
            .await
            .map_err(|e| io_err(format!("ssh connect: {e}")))?;
        let mut auth_ok = false;
        if self.auth.is_empty() {
            auth_ok = session
                .authenticate_none(&self.user)
                .await
                .map_err(|e| io_err(format!("ssh auth none: {e}")))?;
        } else {
            for auth in &self.auth {
                auth_ok = match auth {
                    SshAuth::Password(password) => session
                        .authenticate_password(&self.user, password)
                        .await
                        .map_err(|e| io_err(format!("ssh auth password: {e}")))?,
                    SshAuth::PrivateKey(key) => session
                        .authenticate_publickey(&self.user, key.clone())
                        .await
                        .map_err(|e| io_err(format!("ssh auth pubkey: {e}")))?,
                };
                if auth_ok {
                    break;
                }
            }
        }
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

/// host key 校验 handler。`accept_unknown=true` 时全接受；否则做公钥字节精确匹配。
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
        let known = self.check.keys.clone();
        let server_public_key = server_public_key.clone();
        Box::pin(async move {
            if accept {
                return Ok(true);
            }
            Ok(known.iter().any(|key| key == &server_public_key))
        })
    }
}

pub fn parse_host_key(value: &str) -> Result<russh_keys::key::PublicKey, String> {
    let mut fields = value.split_whitespace();
    let first = fields
        .next()
        .ok_or_else(|| "SSH host-key must not be empty".to_string())?;
    let encoded = if first.starts_with("ssh-") || first.starts_with("ecdsa-") {
        fields
            .next()
            .ok_or_else(|| "SSH host-key is missing base64 key data".to_string())?
    } else {
        first
    };
    russh_keys::parse_public_key_base64(encoded)
        .map_err(|error| format!("invalid SSH host-key: {error}"))
}

fn parse_host_key_algorithms(algorithms: &[String]) -> Result<Vec<russh_keys::key::Name>, String> {
    let mut parsed = Vec::new();
    for algorithm in algorithms {
        let names: &[russh_keys::key::Name] = match algorithm.trim().to_ascii_lowercase().as_str() {
            "rsa" => &[
                russh_keys::key::RSA_SHA2_512,
                russh_keys::key::RSA_SHA2_256,
                russh_keys::key::SSH_RSA,
            ],
            "ed25519" => &[russh_keys::key::ED25519],
            "ecdsa" => &[
                russh_keys::key::ECDSA_SHA2_NISTP521,
                russh_keys::key::ECDSA_SHA2_NISTP384,
                russh_keys::key::ECDSA_SHA2_NISTP256,
            ],
            exact => {
                let name = russh_keys::key::Name::try_from(exact)
                    .map_err(|_| format!("unsupported SSH host-key algorithm `{algorithm}`"))?;
                parsed.push(name);
                continue;
            }
        };
        for name in names {
            if !parsed.contains(name) {
                parsed.push(*name);
            }
        }
    }
    Ok(parsed)
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
    use russh_keys::PublicKeyBase64;

    use super::*;

    #[test]
    fn ssh_outbound_construct() {
        let ob = SshOutbound::new("ssh1", "1.2.3.4", 22, "alice").with_password("p");
        assert_eq!(ob.protocol(), "ssh");
        match &ob.auth[0] {
            SshAuth::Password(p) => assert_eq!(p, "p"),
            _ => panic!(),
        }
    }

    #[test]
    fn known_hosts_default_accept() {
        let ob = SshOutbound::new("ssh1", "1.2.3.4", 22, "alice");
        assert!(ob.host_key_check.accept_unknown);
        assert!(ob.host_key_check.keys.is_empty());
    }

    #[test]
    fn known_hosts_strict_mode() {
        let key = russh_keys::key::KeyPair::generate_ed25519()
            .clone_public_key()
            .unwrap();
        let ob = SshOutbound::new("ssh1", "1.2.3.4", 22, "alice").with_host_keys(vec![key]);
        assert!(!ob.host_key_check.accept_unknown);
        assert_eq!(ob.host_key_check.keys.len(), 1);
    }

    #[test]
    fn capabilities_show_mux() {
        let ob = SshOutbound::new("ssh1", "1.2.3.4", 22, "alice");
        assert!(ob.capabilities().multiplex);
    }

    #[test]
    fn host_key_parser_accepts_authorized_key_and_raw_base64() {
        let key = russh_keys::key::KeyPair::generate_ed25519()
            .clone_public_key()
            .unwrap();
        let encoded = key.public_key_base64();
        assert_eq!(parse_host_key(&encoded).unwrap(), key);
        assert_eq!(
            parse_host_key(&format!("ssh-ed25519 {encoded} test@example")).unwrap(),
            key
        );
    }

    #[test]
    fn host_key_algorithm_aliases_expand_and_unknown_values_fail() {
        let parsed = parse_host_key_algorithms(&["rsa".into(), "ed25519".into()]).unwrap();
        assert_eq!(
            parsed,
            vec![
                russh_keys::key::RSA_SHA2_512,
                russh_keys::key::RSA_SHA2_256,
                russh_keys::key::SSH_RSA,
                russh_keys::key::ED25519,
            ]
        );
        assert!(parse_host_key_algorithms(&["not-an-algorithm".into()]).is_err());
    }

    #[test]
    fn client_version_is_strictly_validated() {
        assert!(
            SshOutbound::new("ssh1", "1.2.3.4", 22, "alice")
                .with_client_version("SSH-2.0-OpenSSH_9.9")
                .is_ok()
        );
        assert!(
            SshOutbound::new("ssh1", "1.2.3.4", 22, "alice")
                .with_client_version("SSH-2.0-good\r\ninjected")
                .is_err()
        );
    }
}
