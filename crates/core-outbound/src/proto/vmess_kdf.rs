//! VMess AEAD KDF —— 嵌套 HMAC-SHA256，与 mihomo / xray / v2ray 兼容。
//!
//! 语义：每一层 path 用 HMAC 包裹前一层（前一层作为底层 hash 函数）。
//! Rust 中通过递归闭包实现：每层 `make_hmac(key, inner_hash_fn)` 返回新的
//! 闭包，闭包接受 msg 返回 32B 输出。
//!
//! 公式：HMAC(K, M) = H( (K' xor opad) || H( (K' xor ipad) || M ) )
//! 其中 H 是底层 hash 函数；嵌套时 H 自己就是上一层的 HMAC。

use sha2::{Digest, Sha256};

const BLOCK_SIZE: usize = 64;
const OUTPUT_SIZE: usize = 32;

type HashFn = Box<dyn Fn(&[u8]) -> [u8; OUTPUT_SIZE] + Send + Sync>;

fn sha256_raw(msg: &[u8]) -> [u8; OUTPUT_SIZE] {
    let mut h = Sha256::new();
    h.update(msg);
    let bytes = h.finalize();
    let mut out = [0u8; OUTPUT_SIZE];
    out.copy_from_slice(&bytes);
    out
}

fn make_hmac(key: Vec<u8>, hash_fn: HashFn) -> HashFn {
    // key 长度处理：> block_size 先 hash 缩短；< block_size 右补零
    let mut key_padded = if key.len() > BLOCK_SIZE {
        hash_fn(&key).to_vec()
    } else {
        key
    };
    key_padded.resize(BLOCK_SIZE, 0);
    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = key_padded[i] ^ 0x36;
        opad[i] = key_padded[i] ^ 0x5c;
    }
    Box::new(move |msg: &[u8]| -> [u8; OUTPUT_SIZE] {
        let mut inner_input = Vec::with_capacity(BLOCK_SIZE + msg.len());
        inner_input.extend_from_slice(&ipad);
        inner_input.extend_from_slice(msg);
        let inner = hash_fn(&inner_input);
        let mut outer_input = Vec::with_capacity(BLOCK_SIZE + OUTPUT_SIZE);
        outer_input.extend_from_slice(&opad);
        outer_input.extend_from_slice(&inner);
        hash_fn(&outer_input)
    })
}

/// 计算 KDF(key, path...)。
///
/// 等价于 mihomo 的 `KDF(key, path...) = HMAC<inner=...>(path[N], key)` 嵌套。
pub fn kdf(key: &[u8], paths: &[&[u8]]) -> [u8; OUTPUT_SIZE] {
    let mut hash_fn: HashFn = Box::new(sha256_raw);
    hash_fn = make_hmac(b"VMess AEAD KDF".to_vec(), hash_fn);
    for path in paths {
        hash_fn = make_hmac(path.to_vec(), hash_fn);
    }
    hash_fn(key)
}

/// 取 KDF 输出的前 N 字节（用于 AES-128 key / nonce）。
pub fn kdf_n(key: &[u8], paths: &[&[u8]], n: usize) -> Vec<u8> {
    let full = kdf(key, paths);
    full[..n].to_vec()
}

// VMess KDF 路径常量（与 mihomo 一致）
pub const KDF_AUTH_ID: &[u8] = b"AES Auth ID Encryption";
pub const KDF_AEAD_KEY_LEN: &[u8] = b"VMess Header AEAD Key_Length";
pub const KDF_AEAD_NONCE_LEN: &[u8] = b"VMess Header AEAD Nonce_Length";
pub const KDF_AEAD_KEY: &[u8] = b"VMess Header AEAD Key";
pub const KDF_AEAD_NONCE: &[u8] = b"VMess Header AEAD Nonce";
pub const KDF_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
pub const KDF_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
pub const KDF_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
pub const KDF_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_single_path_matches_hmac() {
        // 单层时：KDF(key, path) = HMAC(HMAC(KDFSalt, path), key) = nested HMAC
        let out = kdf(b"hello", &[KDF_AUTH_ID]);
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn kdf_3_paths_deterministic() {
        let cmd_key = [0x12u8; 16];
        let auth_id = [0x34u8; 16];
        let nonce = [0x56u8; 8];
        let a = kdf(&cmd_key, &[KDF_AEAD_KEY, &auth_id, &nonce]);
        let b = kdf(&cmd_key, &[KDF_AEAD_KEY, &auth_id, &nonce]);
        assert_eq!(a, b);
    }

    #[test]
    fn kdf_different_paths_differ() {
        let key = [0x99u8; 16];
        let a = kdf(&key, &[KDF_AEAD_KEY]);
        let b = kdf(&key, &[KDF_AEAD_NONCE]);
        assert_ne!(a, b);
    }
}
