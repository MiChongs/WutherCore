use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use aws_lc_rs::digest;
use aws_lc_rs::kem;
use shake::Shake256;
use shake::digest::{ExtendableOutput, Update, XofReader};

use crate::crypto::aws_lc_rs::kx_group;
use crate::crypto::aws_lc_rs::pq::mlkem::MlKem;
use crate::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use crate::ffdhe_groups::FfdheGroup;
use crate::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

mod hybrid;
mod mlkem;

/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
static X25519MLKEM768_INNER: hybrid::Hybrid = hybrid::Hybrid {
    classical: kx_group::X25519,
    post_quantum: MLKEM768,
    name: NamedGroup::X25519MLKEM768,
    layout: hybrid::Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: MLKEM768_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM768_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

/// This is the [SECP256R1MLKEM768] key exchange.
///
/// [SECP256R1MLKEM768]: <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
pub static SECP256R1MLKEM768: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: kx_group::SECP256R1,
    post_quantum: MLKEM768,
    name: NamedGroup::secp256r1MLKEM768,
    layout: hybrid::Layout {
        classical_share_len: SECP256R1_LEN,
        post_quantum_client_share_len: MLKEM768_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM768_CIPHERTEXT_LEN,
        post_quantum_first: false,
    },
};

/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
pub static X25519MLKEM768: &dyn SupportedKxGroup = &X25519MLKEM768_INNER;

pub(crate) fn start_x25519mlkem768_with_fixed_x25519(
    private_key: &[u8; 32],
) -> Result<Box<dyn ActiveKeyExchange>, Error> {
    let classical = crate::crypto::aws_lc_rs::x25519::start_fixed_x25519(private_key)?;
    X25519MLKEM768_INNER.start_with_classical(classical)
}

/// This is the draft Chrome X25519Kyber768Draft00 key exchange.
///
/// It uses the same ML-KEM key encoding and ciphertext sizes as X25519MLKEM768,
/// but the draft wire layout and shared-secret order are both classical first.
/// The ML-KEM shared secret is additionally finalized to Kyber-v3 compatibility.
pub static X25519KYBER768DRAFT00: &dyn SupportedKxGroup = &X25519Kyber768Draft00;

const X25519KYBER768DRAFT00_GROUP: NamedGroup = NamedGroup::Unknown(0x6399);

#[derive(Debug)]
struct X25519Kyber768Draft00;

impl X25519Kyber768Draft00 {
    fn start_with_classical(
        &self,
        classical: Box<dyn ActiveKeyExchange>,
    ) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        if classical.group() != NamedGroup::X25519 {
            return Err(Error::General(
                "draft X25519Kyber768 fixed classical component has the wrong group".into(),
            ));
        }

        let post_quantum = MLKEM768.start()?;
        let combined_pub_key = [classical.pub_key(), post_quantum.pub_key()].concat();

        Ok(Box::new(ActiveX25519Kyber768Draft00 {
            classical,
            post_quantum,
            combined_pub_key,
        }))
    }
}

impl SupportedKxGroup for X25519Kyber768Draft00 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        self.start_with_classical(kx_group::X25519.start()?)
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != X25519_LEN + MLKEM768_ENCAP_LEN {
            return Err(INVALID_KEY_SHARE);
        }

        let (classical_share, post_quantum_share) = client_share.split_at(X25519_LEN);
        let classical = kx_group::X25519.start_and_complete(classical_share)?;
        let post_quantum = MLKEM768.start_and_complete(post_quantum_share)?;
        let kyber_shared = kyber_shared_secret(
            post_quantum.pub_key.as_slice(),
            post_quantum.secret.secret_bytes(),
        )?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: [
                classical.pub_key.as_slice(),
                post_quantum.pub_key.as_slice(),
            ]
            .concat(),
            secret: SharedSecret::from(
                [classical.secret.secret_bytes(), kyber_shared.as_slice()].concat(),
            ),
        })
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        X25519KYBER768DRAFT00_GROUP
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

pub(crate) fn start_x25519kyber768draft00_with_fixed_x25519(
    private_key: &[u8; 32],
) -> Result<Box<dyn ActiveKeyExchange>, Error> {
    let classical = crate::crypto::aws_lc_rs::x25519::start_fixed_x25519(private_key)?;
    X25519Kyber768Draft00.start_with_classical(classical)
}

struct ActiveX25519Kyber768Draft00 {
    classical: Box<dyn ActiveKeyExchange>,
    post_quantum: Box<dyn ActiveKeyExchange>,
    combined_pub_key: Vec<u8>,
}

impl ActiveKeyExchange for ActiveX25519Kyber768Draft00 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != X25519_LEN + MLKEM768_CIPHERTEXT_LEN {
            return Err(INVALID_KEY_SHARE);
        }

        let (classical_share, ciphertext) = peer_pub_key.split_at(X25519_LEN);
        let classical = self
            .classical
            .complete(classical_share)?;
        let post_quantum = self.post_quantum.complete(ciphertext)?;
        let kyber_shared = kyber_shared_secret(ciphertext, post_quantum.secret_bytes())?;

        Ok(SharedSecret::from(
            [classical.secret_bytes(), kyber_shared.as_slice()].concat(),
        ))
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.classical.complete(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        X25519KYBER768DRAFT00_GROUP
    }
}

impl fmt::Debug for ActiveX25519Kyber768Draft00 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveX25519Kyber768Draft00")
            .finish_non_exhaustive()
    }
}

/// This is the [MLKEM] key encapsulation mechanism in NIST with security category 3.
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem
pub static MLKEM768: &dyn SupportedKxGroup = &MlKem {
    alg: &kem::ML_KEM_768,
    group: NamedGroup::MLKEM768,
};

/// This is the [MLKEM] key encapsulation mechanism in NIST with security category 5.
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem
pub static MLKEM1024: &dyn SupportedKxGroup = &MlKem {
    alg: &kem::ML_KEM_1024,
    group: NamedGroup::MLKEM1024,
};

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

const X25519_LEN: usize = 32;
const SECP256R1_LEN: usize = 65;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const MLKEM768_ENCAP_LEN: usize = 1184;

fn kyber_shared_secret(ciphertext: &[u8], mlkem_shared: &[u8]) -> Result<[u8; 32], Error> {
    let ciphertext_hash = digest::digest(&digest::SHA3_256, ciphertext);
    let mut shake_input = Vec::with_capacity(mlkem_shared.len() + ciphertext_hash.as_ref().len());
    shake_input.extend_from_slice(mlkem_shared);
    shake_input.extend_from_slice(ciphertext_hash.as_ref());

    let mut output = [0u8; 32];
    shake256(&shake_input, &mut output)?;
    Ok(output)
}

fn shake256(input: &[u8], output: &mut [u8]) -> Result<(), Error> {
    let mut shake = Shake256::default();
    shake.update(input);
    shake.finalize_xof().read(output);
    Ok(())
}
