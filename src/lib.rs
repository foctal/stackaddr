//! StackAddr is a self-describing, layered address format.
//!
//! This crate provides the [`StackAddr`] and [`Protocol`] types for composing and parsing
//! protocol stacks like `/ip4/127.0.0.1/tcp/443/https` or `/identity/some-p2p/<base32>`.
//! Also, supports L2 MAC addresses like `/mac/aa:bb:cc:dd:ee:ff`.
//!
//! # Examples
//! ```
//! use stackaddr::{StackAddr, Protocol};
//! use std::net::Ipv4Addr;
//!
//! let addr = StackAddr::empty()
//!     .with(Protocol::Ip4(Ipv4Addr::new(127, 0, 0, 1)))
//!     .with(Protocol::Tcp(443))
//!     .with(Protocol::Https);
//!
//! assert_eq!(addr.to_string(), "/ip4/127.0.0.1/tcp/443/https");
//! ```

/// Stack address and protocol representation.
pub mod addr;

/// Protocol definitions used in a [`StackAddr`] stack.
pub mod protocol;

/// Error types used in a [`StackAddr`] stack.
pub mod error;

pub use addr::StackAddr;
pub use protocol::Protocol;
pub use error::StackAddrError;
