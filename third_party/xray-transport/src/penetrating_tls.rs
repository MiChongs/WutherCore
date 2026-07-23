use std::io::{self, Read};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::TransportStream;

const TLS_READ_CHUNK_LIMIT: usize = 8 * 1024;

pub(crate) type ServerReadLog = Arc<Mutex<Option<Vec<u8>>>>;

pub(crate) struct CapturedTcpStream {
    stream: TcpStream,
    server_read_log: Option<ServerReadLog>,
    tls_read_limiter: TlsRecordReadLimiter,
}

impl CapturedTcpStream {
    pub(crate) fn new(stream: TcpStream, server_read_log: Option<ServerReadLog>) -> Self {
        Self {
            stream,
            server_read_log,
            tls_read_limiter: TlsRecordReadLimiter::new(),
        }
    }

    fn into_inner(self) -> TcpStream {
        self.stream
    }
}

struct TlsRecordReadLimiter {
    header: [u8; 5],
    header_len: usize,
    payload_remaining: usize,
}

impl TlsRecordReadLimiter {
    fn new() -> Self {
        Self {
            header: [0; 5],
            header_len: 0,
            payload_remaining: 0,
        }
    }

    fn next_limit(&self, requested: usize) -> usize {
        if self.header_len < self.header.len() {
            requested.min(self.header.len() - self.header_len)
        } else {
            requested.min(self.payload_remaining)
        }
    }

    fn observe(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        if self.header_len < self.header.len() {
            let len = (self.header.len() - self.header_len).min(bytes.len());
            self.header[self.header_len..self.header_len + len].copy_from_slice(&bytes[..len]);
            self.header_len += len;
            if self.header_len == self.header.len() {
                self.payload_remaining =
                    u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                if self.payload_remaining == 0 {
                    self.header_len = 0;
                }
            }
            return;
        }

        self.payload_remaining = self.payload_remaining.saturating_sub(bytes.len());
        if self.payload_remaining == 0 {
            self.header_len = 0;
        }
    }
}

impl AsyncRead for CapturedTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let limit = this
            .tls_read_limiter
            .next_limit(output.remaining())
            .min(TLS_READ_CHUNK_LIMIT);
        let mut scratch = [0; TLS_READ_CHUNK_LIMIT];
        let mut limited = ReadBuf::new(&mut scratch[..limit]);
        match Pin::new(&mut this.stream).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let filled = limited.filled();
                this.tls_read_limiter.observe(filled);
                output.put_slice(filled);
                if let Some(server_read_log) = &this.server_read_log {
                    if !filled.is_empty() {
                        let mut log = server_read_log
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        if let Some(log) = log.as_mut() {
                            log.extend_from_slice(filled);
                        }
                    }
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for CapturedTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

enum PenetratingTlsState {
    Tls(Option<Box<TlsStream<CapturedTcpStream>>>),
    Direct {
        stream: TcpStream,
        pending_plaintext: BytesMut,
    },
}

pub(crate) struct PenetratingTlsStream {
    state: PenetratingTlsState,
}

impl PenetratingTlsStream {
    pub(crate) fn new(stream: TlsStream<CapturedTcpStream>) -> Self {
        Self {
            state: PenetratingTlsState::Tls(Some(Box::new(stream))),
        }
    }

    fn ensure_read_direct(&mut self) -> io::Result<()> {
        let PenetratingTlsState::Tls(tls) = &mut self.state else {
            return Ok(());
        };
        let tls = tls
            .take()
            .ok_or_else(|| io::Error::other("TLS stream was already taken"))?;
        let (stream, mut session) = (*tls).into_inner();
        let stream = stream.into_inner();
        let mut pending_plaintext = BytesMut::new();
        let mut scratch = [0; 8192];

        loop {
            match session.reader().read(&mut scratch) {
                Ok(0) => break,
                Ok(len) => pending_plaintext.extend_from_slice(&scratch[..len]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }

        self.state = PenetratingTlsState::Direct {
            stream,
            pending_plaintext,
        };
        Ok(())
    }

    fn poll_read_direct_mode(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.ensure_read_direct()?;
        let PenetratingTlsState::Direct {
            stream,
            pending_plaintext,
        } = &mut self.state
        else {
            unreachable!("ensure_direct transitions TLS state to direct");
        };

        if !pending_plaintext.is_empty() {
            let len = output.remaining().min(pending_plaintext.len());
            output.put_slice(&pending_plaintext.split_to(len));
            return Poll::Ready(Ok(()));
        }

        Pin::new(stream).poll_read(cx, output)
    }

    fn poll_write_direct_mode(
        &mut self,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.state {
            PenetratingTlsState::Tls(Some(stream)) => {
                let (raw_stream, _) = stream.as_mut().get_mut();
                Pin::new(raw_stream).poll_write(cx, input)
            }
            PenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
            PenetratingTlsState::Direct { stream, .. } => Pin::new(stream).poll_write(cx, input),
        }
    }
}

impl AsyncRead for PenetratingTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            PenetratingTlsState::Tls(Some(stream)) => Pin::new(stream).poll_read(cx, output),
            PenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
            PenetratingTlsState::Direct { .. } => this.poll_read_direct_mode(cx, output),
        }
    }
}

impl AsyncWrite for PenetratingTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match &mut this.state {
            PenetratingTlsState::Tls(Some(stream)) => Pin::new(stream).poll_write(cx, input),
            PenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
            PenetratingTlsState::Direct { .. } => this.poll_write_direct_mode(cx, input),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            PenetratingTlsState::Tls(Some(stream)) => Pin::new(stream).poll_flush(cx),
            PenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
            PenetratingTlsState::Direct { stream, .. } => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            PenetratingTlsState::Tls(Some(stream)) => Pin::new(stream).poll_shutdown(cx),
            PenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
            PenetratingTlsState::Direct { stream, .. } => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl TransportStream for PenetratingTlsStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().poll_read_direct_mode(cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_direct_mode(cx, input)
    }

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            PenetratingTlsState::Tls(Some(stream)) => {
                let (raw_stream, _) = stream.as_mut().get_mut();
                Pin::new(raw_stream).poll_flush(cx)
            }
            PenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
            PenetratingTlsState::Direct { stream, .. } => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            PenetratingTlsState::Tls(Some(stream)) => {
                let (raw_stream, _) = stream.as_mut().get_mut();
                Pin::new(raw_stream).poll_shutdown(cx)
            }
            PenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
            PenetratingTlsState::Direct { stream, .. } => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::sync::Arc;

    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;

    async fn connect_test_stream() -> (
        PenetratingTlsStream,
        tokio_rustls::server::TlsStream<TcpStream>,
    ) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["server.test".to_owned()])
                .expect("generate self-signed certificate");
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).expect("add test root");
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider should support default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider should support default TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server certificate config");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TLS listener");
        let addr = listener.local_addr().expect("listener addr");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept TLS client");
            acceptor.accept(stream).await.expect("accept TLS")
        });

        let client = CapturedTcpStream::new(
            TcpStream::connect(addr).await.expect("connect TLS client"),
            None,
        );
        let server_name = ServerName::try_from("server.test").expect("server name");
        let client = TlsConnector::from(Arc::new(client_config))
            .connect(server_name, client)
            .await
            .expect("client TLS connect");
        let server = server.await.expect("server task");

        (PenetratingTlsStream::new(client), server)
    }

    async fn write_direct(stream: &mut PenetratingTlsStream, bytes: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            let written =
                poll_fn(|cx| Pin::new(&mut *stream).poll_write_direct(cx, &bytes[offset..]))
                    .await?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "direct write returned zero",
                ));
            }
            offset += written;
        }
        poll_fn(|cx| Pin::new(&mut *stream).poll_flush_direct(cx)).await
    }

    async fn read_direct_exact(
        stream: &mut PenetratingTlsStream,
        output: &mut [u8],
    ) -> io::Result<()> {
        let mut offset = 0;
        while offset < output.len() {
            let mut read_buf = ReadBuf::new(&mut output[offset..]);
            poll_fn(|cx| Pin::new(&mut *stream).poll_read_direct(cx, &mut read_buf)).await?;
            let read = read_buf.filled().len();
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "direct read ended early",
                ));
            }
            offset += read;
        }
        Ok(())
    }

    #[tokio::test]
    async fn direct_write_bypasses_tls_after_switch() {
        let (mut client, mut server) = connect_test_stream().await;

        client.write_all(b"tls").await.expect("write TLS plaintext");
        client.flush().await.expect("flush TLS plaintext");
        let mut tls_plaintext = [0; 3];
        server
            .read_exact(&mut tls_plaintext)
            .await
            .expect("read TLS plaintext");
        assert_eq!(&tls_plaintext, b"tls");

        write_direct(&mut client, b"raw")
            .await
            .expect("write direct bytes");
        let (mut raw_server, _) = server.into_inner();
        let mut raw = [0; 3];
        raw_server
            .read_exact(&mut raw)
            .await
            .expect("read raw bytes");

        assert_eq!(&raw, b"raw");
    }

    #[tokio::test]
    async fn direct_write_keeps_tls_read_available_until_direct_read() {
        let (mut client, mut server) = connect_test_stream().await;

        write_direct(&mut client, b"raw")
            .await
            .expect("write direct bytes");

        server
            .write_all(b"tls reply")
            .await
            .expect("write TLS reply");
        server.flush().await.expect("flush TLS reply");

        let mut reply = [0; 9];
        client
            .read_exact(&mut reply)
            .await
            .expect("read TLS reply after direct write");
        assert_eq!(&reply, b"tls reply");

        let (mut raw_server, _) = server.into_inner();
        let mut raw = [0; 3];
        raw_server
            .read_exact(&mut raw)
            .await
            .expect("read raw bytes");
        assert_eq!(&raw, b"raw");
    }

    #[tokio::test]
    async fn direct_read_drains_buffered_tls_plaintext_before_raw_socket() {
        let (mut client, mut server) = connect_test_stream().await;

        server
            .write_all(b"tlsbuffered")
            .await
            .expect("write TLS plaintext");
        server.flush().await.expect("flush TLS plaintext");
        let mut tls_prefix = [0; 3];
        client
            .read_exact(&mut tls_prefix)
            .await
            .expect("read TLS prefix");
        assert_eq!(&tls_prefix, b"tls");

        let (mut raw_server, _) = server.into_inner();
        raw_server
            .write_all(b"raw")
            .await
            .expect("write raw response");
        raw_server.flush().await.expect("flush raw response");

        let mut direct = [0; 11];
        read_direct_exact(&mut client, &mut direct)
            .await
            .expect("read buffered plaintext and raw bytes");

        assert_eq!(&direct, b"bufferedraw");
    }

    #[tokio::test]
    async fn direct_read_preserves_raw_bytes_after_tls_record() {
        let (mut client, mut server) = connect_test_stream().await;

        server
            .write_all(b"tls frame")
            .await
            .expect("write TLS plaintext");
        server.flush().await.expect("flush TLS plaintext");

        let (mut raw_server, _) = server.into_inner();
        raw_server
            .write_all(b"raw")
            .await
            .expect("write raw response");
        raw_server.flush().await.expect("flush raw response");

        let mut tls_frame = [0; 8192];
        let read = client
            .read(&mut tls_frame)
            .await
            .expect("read TLS plaintext before switching direct");
        assert_eq!(&tls_frame[..read], b"tls frame");

        let mut raw = [0; 3];
        read_direct_exact(&mut client, &mut raw)
            .await
            .expect("read raw bytes after TLS record");

        assert_eq!(&raw, b"raw");
    }
}
