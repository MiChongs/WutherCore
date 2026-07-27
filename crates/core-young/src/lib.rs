//! Young v1: an authenticated proxy protocol carried by Mozilla Neqo.
//!
//! The public API deliberately separates the Young wire format from the
//! Firefox HTTP/3/WebTransport carrier.  `codec` can be tested without NSS;
//! `client` and `server` drive Neqo on dedicated current-thread runtimes
//! because Neqo mirrors Firefox's `Rc<RefCell<_>>` integration model.

#![forbid(unsafe_code)]

#[cfg(feature = "firefox-stack")]
mod client;
mod codec;
#[cfg(feature = "firefox-stack")]
mod server;

#[cfg(feature = "firefox-stack")]
pub use client::{YoungClient, YoungClientConfig, YoungUdpChannel};
pub use codec::{
    DEFAULT_CLOCK_SKEW_SECS, FlowKind, FlowOpen, FlowResponse, KeyRing, MAX_PADDING_BYTES,
    ReplayCache, SessionKey, Status, Target, UdpReassembler, VERSION, YoungKey,
    create_authorization, decode_flow_open, decode_flow_response, decode_udp_fragment,
    derive_rotating_path, derive_session_key, encode_flow_open, encode_flow_response,
    encode_udp_fragments, server_accept_proof, verify_authorization, verify_server_accept_proof,
};
#[cfg(feature = "firefox-stack")]
pub use server::{YoungServerConfig, YoungServerHandle};
