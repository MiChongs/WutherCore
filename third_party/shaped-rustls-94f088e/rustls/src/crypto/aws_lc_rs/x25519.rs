use alloc::boxed::Box;

use crate::crypto::{ActiveKeyExchange, FfdheGroup, SharedSecret};
use crate::msgs::enums::NamedGroup;
use crate::{Error, PeerMisbehaved};

use super::ring_like::agreement;

pub(crate) fn start_fixed_x25519(
    private_key: &[u8; 32],
) -> Result<Box<dyn ActiveKeyExchange>, Error> {
    let private_key = agreement::PrivateKey::from_private_key(&agreement::X25519, private_key)
        .map_err(|_| Error::General("invalid fixed X25519 private key".into()))?;
    let public_key = private_key
        .compute_public_key()
        .map_err(super::unspecified_err)?;

    Ok(Box::new(FixedX25519 {
        private_key,
        public_key: public_key
            .as_ref()
            .try_into()
            .map_err(|_| Error::General("aws-lc X25519 public key was not 32 bytes".into()))?,
    }))
}

struct FixedX25519 {
    private_key: agreement::PrivateKey,
    public_key: [u8; 32],
}

impl ActiveKeyExchange for FixedX25519 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != 32 {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }

        let peer_key = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_pub_key);
        agreement::agree(&self.private_key, &peer_key, (), |secret| {
            Ok(SharedSecret::from(secret))
        })
        .map_err(|_| PeerMisbehaved::InvalidKeyShare.into())
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}
