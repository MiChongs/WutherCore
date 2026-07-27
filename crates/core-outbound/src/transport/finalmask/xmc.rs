use std::{
    collections::HashMap,
    io::Cursor,
    net::SocketAddr,
    sync::{Arc, LazyLock},
    time::Duration,
};

use aes::{
    Aes128,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use core_config::XmcMaskConfig;
use num_bigint_dig::prime::probably_prime;
use parking_lot::Mutex;
use rand::{Rng, RngCore, rngs::OsRng};
use rsa::{
    BigUint, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePublicKey, spki::Document},
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::adapter::BoxedStream;

struct KeyMaterial {
    private: RsaPrivateKey,
    public: RsaPublicKey,
    der: Vec<u8>,
}

static KEY_CACHE: LazyLock<Mutex<HashMap<String, Arc<KeyMaterial>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) async fn wrap_client(
    mut stream: BoxedStream,
    config: &XmcMaskConfig,
    remote: Option<SocketAddr>,
    remote_host: &str,
    remote_port: u16,
) -> std::io::Result<BoxedStream> {
    let password = config.password.clone();
    let key = key_material(&password).await?;
    let usernames = if config.usernames.is_empty() {
        vec!["Dream".to_string()]
    } else {
        config.usernames.clone()
    };
    let fallback_hostname;
    let hostname = if config.hostname.is_empty() {
        fallback_hostname = remote
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| remote_host.to_string());
        fallback_hostname.as_str()
    } else {
        &config.hostname
    };
    let server_port = remote.map(|addr| addr.port()).unwrap_or(remote_port);
    let secret = tokio::time::timeout(
        Duration::from_secs(30),
        handshake(
            &mut stream,
            hostname,
            server_port,
            &usernames,
            &password,
            &key,
        ),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "xmc handshake timed out"))??;
    Ok(encrypted_bridge(stream, secret))
}

pub(super) async fn wrap_server(
    mut stream: BoxedStream,
    config: &XmcMaskConfig,
) -> std::io::Result<BoxedStream> {
    if config.password.is_empty() {
        return Err(invalid("xmc password must not be empty"));
    }
    let key = key_material(&config.password).await?;
    let secret = tokio::time::timeout(
        Duration::from_secs(30),
        server_handshake(&mut stream, &config.password, &key),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "xmc handshake timed out"))??;
    Ok(encrypted_bridge(stream, secret))
}

async fn key_material(password: &str) -> std::io::Result<Arc<KeyMaterial>> {
    if let Some(key) = KEY_CACHE.lock().get(password).cloned() {
        return Ok(key);
    }
    let password_for_task = password.to_string();
    let key = tokio::task::spawn_blocking(move || derive_key_material(&password_for_task))
        .await
        .map_err(|error| other(format!("xmc key derivation task: {error}")))??;
    let key = Arc::new(key);
    KEY_CACHE.lock().insert(password.to_string(), key.clone());
    Ok(key)
}

async fn handshake(
    stream: &mut BoxedStream,
    hostname: &str,
    remote_port: u16,
    usernames: &[String],
    password: &str,
    key: &KeyMaterial,
) -> std::io::Result<[u8; 16]> {
    let mut fields = Vec::new();
    put_varint(&mut fields, 775);
    put_string(&mut fields, hostname)?;
    fields.extend_from_slice(&remote_port.to_be_bytes());
    put_varint(&mut fields, 2);
    write_packet(stream, 0, &fields).await?;

    let username = usernames
        .get(rand::thread_rng().gen_range(0..usernames.len()))
        .ok_or_else(|| invalid("xmc usernames must not be empty"))?;
    let mut login = Vec::new();
    put_string(&mut login, username)?;
    login.extend_from_slice(&offline_uuid(username));
    write_packet(stream, 0, &login).await?;

    let (packet_id, packet) = read_packet(stream).await?;
    if packet_id != 1 {
        return Err(invalid(format!(
            "xmc expected encryption request packet 1, got {packet_id}"
        )));
    }
    let mut cursor = Cursor::new(packet.as_slice());
    let _server_id = take_string(&mut cursor)?;
    let public_key = take_bytes(&mut cursor)?;
    let mut verify_token = take_bytes(&mut cursor)?;
    if public_key != key.der {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "xmc server public key mismatch",
        ));
    }

    let mut secret = [0u8; 16];
    OsRng.fill_bytes(&mut secret);
    let encrypted_secret = key
        .public
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, &secret)
        .map_err(other)?;
    verify_token.extend_from_slice(password.as_bytes());
    let encrypted_token = key
        .public
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, &verify_token)
        .map_err(other)?;
    let mut response = Vec::new();
    put_bytes(&mut response, &encrypted_secret)?;
    put_bytes(&mut response, &encrypted_token)?;
    write_packet(stream, 1, &response).await?;
    Ok(secret)
}

async fn server_handshake(
    stream: &mut BoxedStream,
    password: &str,
    key: &KeyMaterial,
) -> std::io::Result<[u8; 16]> {
    let (packet_id, packet) = read_packet(stream).await?;
    if packet_id != 0 {
        return Err(invalid("xmc expected handshake packet 0"));
    }
    let mut cursor = Cursor::new(packet.as_slice());
    let _protocol_version = take_varint(&mut cursor)?;
    let _server_address = take_string(&mut cursor)?;
    let mut port = [0u8; 2];
    std::io::Read::read_exact(&mut cursor, &mut port)?;
    let next_state = take_varint(&mut cursor)?;
    match next_state {
        1 => {
            serve_status_ping(stream).await?;
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "xmc status ping completed",
            ))
        }
        2 => server_login(stream, password, key).await,
        other => Err(invalid(format!("xmc invalid next state {other}"))),
    }
}

async fn serve_status_ping(stream: &mut BoxedStream) -> std::io::Result<()> {
    const STATUS: &str = r#"{"description":"A Minecraft Server","players":{"max":20,"online":0},"version":{"name":"26.1.2","protocol":775},"enforcesSecureChat":true}"#;
    for _ in 0..2 {
        let (packet_id, packet) = read_packet(stream).await?;
        match packet_id {
            0 => {
                let mut response = Vec::new();
                put_string(&mut response, STATUS)?;
                write_packet(stream, 0, &response).await?;
            }
            1 => {
                if packet.len() != 8 {
                    return Err(invalid("xmc ping payload must be 8 bytes"));
                }
                write_packet(stream, 1, &packet).await?;
            }
            other => return Err(invalid(format!("xmc invalid status packet {other}"))),
        }
    }
    Ok(())
}

async fn server_login(
    stream: &mut BoxedStream,
    password: &str,
    key: &KeyMaterial,
) -> std::io::Result<[u8; 16]> {
    let (packet_id, packet) = read_packet(stream).await?;
    if packet_id != 0 {
        return Err(invalid("xmc expected login start packet 0"));
    }
    let mut cursor = Cursor::new(packet.as_slice());
    let _username = take_string(&mut cursor)?;
    let mut uuid = [0u8; 16];
    std::io::Read::read_exact(&mut cursor, &mut uuid)?;

    let mut verify_token = [0u8; 4];
    OsRng.fill_bytes(&mut verify_token);
    let mut request = Vec::new();
    put_string(&mut request, "")?;
    put_bytes(&mut request, &key.der)?;
    put_bytes(&mut request, &verify_token)?;
    put_varint(&mut request, 1);
    write_packet(stream, 1, &request).await?;

    let (packet_id, packet) = read_packet(stream).await?;
    if packet_id != 1 {
        return Err(invalid("xmc expected encryption response packet 1"));
    }
    let mut cursor = Cursor::new(packet.as_slice());
    let encrypted_secret = take_bytes(&mut cursor)?;
    let encrypted_token = take_bytes(&mut cursor)?;
    let secret = key
        .private
        .decrypt(Pkcs1v15Encrypt, &encrypted_secret)
        .map_err(other)?;
    let token = key
        .private
        .decrypt(Pkcs1v15Encrypt, &encrypted_token)
        .map_err(other)?;
    if token.len() < verify_token.len()
        || !constant_time_eq(&token[..verify_token.len()], &verify_token)
        || !constant_time_eq(&token[verify_token.len()..], password.as_bytes())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "xmc verify token or password mismatch",
        ));
    }
    secret
        .try_into()
        .map_err(|_| invalid("xmc shared secret must be exactly 16 bytes"))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut different = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        different |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    different == 0
}

fn encrypted_bridge(inner: BoxedStream, secret: [u8; 16]) -> BoxedStream {
    let (client, worker) = tokio::io::duplex(64 * 1024);
    let (mut app_read, mut app_write) = tokio::io::split(worker);
    let (mut raw_read, mut raw_write) = tokio::io::split(inner);
    tokio::spawn(async move {
        let mut cipher = Cfb8::new(secret, false);
        let mut buffer = vec![0; 32 * 1024];
        let result = async {
            loop {
                let count = app_read.read(&mut buffer).await?;
                if count == 0 {
                    raw_write.shutdown().await?;
                    return Ok::<_, std::io::Error>(());
                }
                cipher.apply(&mut buffer[..count]);
                raw_write.write_all(&buffer[..count]).await?;
            }
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "finalmask xmc encryptor stopped");
        }
    });
    tokio::spawn(async move {
        let mut cipher = Cfb8::new(secret, true);
        let mut buffer = vec![0; 32 * 1024];
        let result = async {
            loop {
                let count = raw_read.read(&mut buffer).await?;
                if count == 0 {
                    app_write.shutdown().await?;
                    return Ok::<_, std::io::Error>(());
                }
                cipher.apply(&mut buffer[..count]);
                app_write.write_all(&buffer[..count]).await?;
            }
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "finalmask xmc decryptor stopped");
        }
    });
    Box::pin(client)
}

struct Cfb8 {
    cipher: Aes128,
    iv: [u8; 16],
    decrypt: bool,
}

impl Cfb8 {
    fn new(secret: [u8; 16], decrypt: bool) -> Self {
        Self {
            cipher: Aes128::new(GenericArray::from_slice(&secret)),
            iv: secret,
            decrypt,
        }
    }

    fn apply(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            let ciphertext = *byte;
            let mut block = GenericArray::clone_from_slice(&self.iv);
            self.cipher.encrypt_block(&mut block);
            *byte ^= block[0];
            self.iv.copy_within(1.., 0);
            self.iv[15] = if self.decrypt { ciphertext } else { *byte };
        }
    }
}

fn derive_key_material(password: &str) -> std::io::Result<KeyMaterial> {
    let private = derive_private_key(password)?;
    let public = private.to_public_key();
    let der: Document = public.to_public_key_der().map_err(other)?;
    Ok(KeyMaterial {
        private,
        public,
        der: der.as_bytes().to_vec(),
    })
}

fn derive_private_key(password: &str) -> std::io::Result<RsaPrivateKey> {
    let p = derive_prime(format!("{password}-p-prime").as_bytes());
    let mut q = derive_prime(format!("{password}-q-prime").as_bytes());
    while p == q {
        q += 2u8;
        while !acceptable_prime(&q) {
            q += 2u8;
        }
    }
    RsaPrivateKey::from_primes(vec![p, q], BigUint::from(65537u32)).map_err(other)
}

fn derive_prime(seed: &[u8]) -> BigUint {
    let mut bytes = [0u8; 64];
    let mut offset = 0;
    let mut counter = 0u64;
    while offset < bytes.len() {
        let mut hash = Sha256::new();
        hash.update(seed);
        hash.update(format!("-{counter}").as_bytes());
        counter += 1;
        let block = hash.finalize();
        let count = (bytes.len() - offset).min(block.len());
        bytes[offset..offset + count].copy_from_slice(&block[..count]);
        offset += count;
    }
    bytes[0] |= 0xc0;
    bytes[63] |= 1;
    let mut prime = BigUint::from_bytes_be(&bytes);
    while !acceptable_prime(&prime) {
        prime += 2u8;
    }
    prime
}

fn acceptable_prime(value: &BigUint) -> bool {
    probably_prime(value, 20)
        && ((value - BigUint::from(1u8)) % BigUint::from(65537u32)) != BigUint::from(0u8)
}

fn offline_uuid(username: &str) -> [u8; 16] {
    let hash = Sha256::digest(format!("OfflinePlayer:{username}").as_bytes());
    let mut uuid: [u8; 16] = hash[..16].try_into().expect("sha prefix");
    uuid[6] = (uuid[6] & 0x0f) | 0x30;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}

async fn write_packet(
    stream: &mut BoxedStream,
    packet_id: i32,
    fields: &[u8],
) -> std::io::Result<()> {
    let mut packet = Vec::new();
    put_varint(
        &mut packet,
        varint_size(packet_id) as i32 + fields.len() as i32,
    );
    put_varint(&mut packet, packet_id);
    packet.extend_from_slice(fields);
    stream.write_all(&packet).await
}

async fn read_packet(stream: &mut BoxedStream) -> std::io::Result<(i32, Vec<u8>)> {
    let length = read_varint_async(stream).await?;
    if !(0..=32 * 1024).contains(&length) {
        return Err(invalid(format!("xmc packet has invalid length {length}")));
    }
    let mut packet = vec![0; length as usize];
    stream.read_exact(&mut packet).await?;
    let mut cursor = Cursor::new(packet.as_slice());
    let packet_id = take_varint(&mut cursor)?;
    let consumed = cursor.position() as usize;
    Ok((packet_id, packet[consumed..].to_vec()))
}

async fn read_varint_async(stream: &mut BoxedStream) -> std::io::Result<i32> {
    let mut value = 0i32;
    for position in (0..32).step_by(7) {
        let byte = stream.read_u8().await?;
        value |= i32::from(byte & 0x7f) << position;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid("xmc varint is too large"))
}

fn put_varint(output: &mut Vec<u8>, mut value: i32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn varint_size(mut value: i32) -> usize {
    let mut size = 1;
    while {
        value >>= 7;
        value != 0
    } {
        size += 1;
    }
    size
}

fn put_string(output: &mut Vec<u8>, value: &str) -> std::io::Result<()> {
    if value.len() > 4096 {
        return Err(invalid("xmc string exceeds 4096 bytes"));
    }
    put_varint(output, value.len() as i32);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> std::io::Result<()> {
    if value.len() >= 1024 {
        return Err(invalid("xmc byte string exceeds protocol limit"));
    }
    put_varint(output, value.len() as i32);
    output.extend_from_slice(value);
    Ok(())
}

fn take_varint(cursor: &mut Cursor<&[u8]>) -> std::io::Result<i32> {
    let mut value = 0i32;
    for position in (0..32).step_by(7) {
        let mut byte = [0];
        std::io::Read::read_exact(cursor, &mut byte)?;
        value |= i32::from(byte[0] & 0x7f) << position;
        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid("xmc varint is too large"))
}

fn take_string(cursor: &mut Cursor<&[u8]>) -> std::io::Result<String> {
    let length = take_varint(cursor)?;
    if !(0..=4096).contains(&length) {
        return Err(invalid("xmc string length is invalid"));
    }
    let mut bytes = vec![0; length as usize];
    std::io::Read::read_exact(cursor, &mut bytes)?;
    String::from_utf8(bytes).map_err(invalid)
}

fn take_bytes(cursor: &mut Cursor<&[u8]>) -> std::io::Result<Vec<u8>> {
    let length = take_varint(cursor)?;
    if !(0..1024).contains(&length) {
        return Err(invalid("xmc byte string length is invalid"));
    }
    let mut bytes = vec![0; length as usize];
    std::io::Read::read_exact(cursor, &mut bytes)?;
    Ok(bytes)
}

fn invalid(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
}

fn other(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;

    #[test]
    fn official_private_key_derivation_golden() {
        let key = derive_private_key("deterministic-rsa-key-golden").unwrap();
        let der = key.to_pkcs1_der().unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(der.as_bytes())),
            "3a8c4ad56a6fb42dab73c4d5fc3af754460a2db1441edc0970cbc7f4e0798d2f"
        );
    }

    #[test]
    fn cfb8_roundtrip_across_unequal_chunks() {
        let secret = [7u8; 16];
        let mut encrypted = b"minecraft-compatible-cfb8".to_vec();
        Cfb8::new(secret, false).apply(&mut encrypted);
        let mut decrypt = Cfb8::new(secret, true);
        decrypt.apply(&mut encrypted[..3]);
        decrypt.apply(&mut encrypted[3..]);
        assert_eq!(&encrypted, b"minecraft-compatible-cfb8");
    }

    #[tokio::test]
    async fn client_and_server_handshake_then_proxy_bidirectionally() {
        let config = XmcMaskConfig {
            hostname: "mc.example".into(),
            usernames: vec!["Dream".into()],
            password: "xmc-client-server-test".into(),
        };
        let (left, right) = tokio::io::duplex(64 * 1024);
        let client = wrap_client(Box::pin(left), &config, None, "mc.example", 25565);
        let server = wrap_server(Box::pin(right), &config);
        let (client, server) = tokio::join!(client, server);
        let mut client = client.unwrap();
        let mut server = server.unwrap();

        client.write_all(b"request").await.unwrap();
        let mut request = [0; 7];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");

        server.write_all(b"response").await.unwrap();
        let mut response = [0; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
    }
}
