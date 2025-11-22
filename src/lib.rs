//! # stackaddr
//!
//! `stackaddr` is a library for self-describing, layered address representation.
//! It enables structured, extensible expression of network addresses and associated metadata,
//! supporting both traditional transport protocols and identity-aware addressing.
//!
//! ## Features
//! - Multi-layered address structure (L2–L7)
//! - Protocol segments: `/ip4/127.0.0.1/tcp/443/tls/http`
//!     - Also, supports L2 MAC addresses like `/mac/aa:bb:cc:dd:ee:ff`.
//! - Identity segments: `/node/<base32>`, `/uuid/<uuid>`
//! - Metadata and path support
//! - `Display` and `FromStr` support
//! - Optional Serde serialization (`serde` feature)
//!
//! ## Example
//! ```rust
//! use stackaddr::{StackAddr, Protocol, Identity, Segment};
//! use bytes::Bytes;
//!
//! let addr = StackAddr::from_parts(&[
//!     Segment::Protocol(Protocol::Ip4("192.168.10.10".parse().unwrap())),
//!     Segment::Protocol(Protocol::Udp(4433)),
//!     Segment::Protocol(Protocol::Quic),
//!     Segment::Identity(Identity::NodeId(Bytes::from_static(&[1; 32]))),
//! ]);
//!
//! println!("{}", addr); // /ip4/192.168.10.10/udp/4433/quic/node/...
//! ```

/// Stack address and protocol representation.
pub mod addr;

/// Segment definitions, including protocol, identity, metadata, and path.
pub mod segment;

/// Error types used in [`StackAddr`] and related parsing operations.
pub mod error;

pub use addr::StackAddr;
pub use error::StackAddrError;
pub use segment::Segment;
pub use segment::identity::Identity;
pub use segment::protocol::Protocol;

pub use mac_addr::MacAddr;
