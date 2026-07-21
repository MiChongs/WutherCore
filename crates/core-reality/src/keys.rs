use std::io;

use aws_lc_rs::agreement;
use base64::Engine as _;
use rand::RngCore as _;

pub fn x25519_public_key(private_key: &[u8; 32]) -> io::Result<[u8; 32]> {
    let private = agreement::PrivateKey::from_private_key(&agreement::X25519, private_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid X25519 private key"))?;
    private
        .compute_public_key()
        .map_err(|_| io::Error::other("failed to derive X25519 public key"))?
        .as_ref()
        .try_into()
        .map_err(|_| io::Error::other("X25519 public key has unexpected length"))
}

pub fn generate_x25519_keypair() -> io::Result<([u8; 32], [u8; 32])> {
    let mut private = [0u8; 32];
    rand::rng().fill_bytes(&mut private);
    let public = x25519_public_key(&private)?;
    Ok((private, public))
}

pub fn decode_private_key(encoded: &str) -> io::Result<[u8; 32]> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid base64url private key: {error}"),
            )
        })?;
    decoded.as_slice().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "REALITY private key must decode to 32 bytes",
        )
    })
}

pub fn decode_short_id(encoded: &str) -> io::Result<[u8; 8]> {
    if encoded.len() > 16 || encoded.len() % 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "shortId must contain 0 to 16 even hex digits",
        ));
    }
    let mut output = [0u8; 8];
    hex::decode_to_slice(encoded, &mut output[..encoded.len() / 2]).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid shortId: {error}"),
        )
    })?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_is_right_padded_like_xray() {
        assert_eq!(decode_short_id("0102").unwrap(), [1, 2, 0, 0, 0, 0, 0, 0]);
        assert!(decode_short_id("0").is_err());
    }

    #[test]
    fn generated_keypair_roundtrips() {
        let (private, public) = generate_x25519_keypair().unwrap();
        assert_eq!(x25519_public_key(&private).unwrap(), public);
        assert_ne!(public, [0; 32]);
    }
}
