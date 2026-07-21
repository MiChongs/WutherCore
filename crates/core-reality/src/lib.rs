//! Generic REALITY server transport.
//!
//! The public API terminates an authenticated REALITY TLS 1.3 stream while
//! transparently forwarding unauthenticated probes to a configured camouflage
//! target. It deliberately has no dependency on XHTTP or an inner proxy
//! protocol.

mod buffer;
mod client;
// The attributed Shoes-derived module intentionally retains small standalone
// protocol primitives and test vectors beyond the production server call path.
#[allow(dead_code)]
mod donor;
mod framing;
mod keys;
mod server;

pub use client::{
    RealityClient, RealityClientConfig, RealityClientError, RealityClientStream,
    RealityConnectionLifetime, RealitySpiderPolicy, XRAY_REALITY_WIRE_VERSION, parse_spider_x,
};
pub use donor::{CipherSuite, DEFAULT_CIPHER_SUITES};
pub use framing::{ClientHello, ClientHelloLimits};
pub use keys::{decode_private_key, decode_short_id, generate_x25519_keypair, x25519_public_key};
pub use server::{
    AcceptedRealityStream, FallbackLimit, ProxyProtocolVersion, RealityServer, RealityServerConfig,
    RealityServerError, RealityServerLimits,
};
