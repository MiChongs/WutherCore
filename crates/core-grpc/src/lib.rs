//! Xray gRPC (`gun`) transport implemented with tonic/prost.
//!
//! The crate intentionally owns only the transport framing.  Callers provide
//! an already connected byte stream, so TLS, REALITY, finalmask and socket
//! policy remain composable outside the gRPC implementation.

#![forbid(unsafe_code)]

mod path;
mod proto;
mod stream;

pub mod client;
pub mod server;

pub use path::{GrpcMethodPaths, grpc_method_paths};
pub use stream::{GrpcTunnelStream, TunnelMode};

/// Xray-core compatibility baseline used by the wire oracle tests.
pub const XRAY_GRPC_BASELINE: &str = "6e3322d219140a025285ded1114fe17a5edb74d8";

/// gRPC implementations commonly default to a four MiB message limit.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// Smallest limit that can encode a non-empty protobuf `bytes` field:
/// one tag byte, one length byte and one payload byte.
pub const MIN_MESSAGE_SIZE: usize = 3;

/// Maximum number of protobuf messages queued in either direction.
pub const DEFAULT_QUEUE_CAPACITY: usize = 8;

/// Defensive ceiling for a caller-configured decoded protobuf message.
pub const MAX_MESSAGE_SIZE_LIMIT: usize = 64 * 1024 * 1024;

/// Defensive ceiling for each bounded tunnel channel.
pub const MAX_QUEUE_CAPACITY: usize = 1024;
