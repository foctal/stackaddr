//! Identity segment
//!
//! Defines the `Identity` enum, which represents unique cryptographic or system-level identifiers
//! that can be embedded in a layered network address (`StackAddr`).
//!
//! Supported identity types:
//!
//! - `/node/<base32>`: 32-byte NodeId (e.g. Ed25519 public key)
//! - `/peer/<base32>`: 32-byte PeerId
//! - `/uuid/<hex>`: Universally Unique Identifier (v1, v4, etc.)
//! - `/identity/<kind>/<base32>`: Custom identifier with a specified kind
//!
//! All binary identity data is encoded using **base32 (RFC4648 without padding)**,
//! except UUIDs, which are rendered in hyphenless base16 (hex) per convention.
//!
//! Identity segments are useful for describing endpoints in a cryptographically verifiable or
//! globally unique way.

use bytes::Bytes;
use uuid::Uuid;
use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A segment representing a unique identity.
///
/// This can be used to include cryptographic identities (like NodeId, PeerId),
/// UUIDs, or custom identity types in an address stack.
///
/// Binary identity data is encoded as base32 in string form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Identity {
    /// A node ID, such as a public key (e.g. Ed25519)
    NodeId(Bytes),
    /// A peer ID, as used in many P2P protocols
    PeerId(Bytes),
    /// A UUID (supports hyphenless base16 string output)
    Uuid(Uuid),
    /// A custom identity with an explicit kind and ID bytes
    Custom {
        kind: String,
        id: Bytes,
    },
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Identity::*;
        match self {
            NodeId(id) => {
                let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, id);
                write!(f, "/node/{}", encoded)
            },
            PeerId(id) => {
                let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, id);
                write!(f, "/peer/{}", encoded)
            },
            Uuid(uuid) => write!(f, "/uuid/{}", uuid.simple()),
            Custom { kind, id } => {
                let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, id);
                write!(f, "/identity/{}/{}", kind, encoded)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_bytes32() -> Bytes {
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        Bytes::copy_from_slice(&buf)
    }

    #[test]
    fn test_display_nodeid_base32() {
        let id = random_bytes32();
        let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &id);
        let proto = Identity::NodeId(id);
        assert_eq!(proto.to_string(), format!("/node/{}", encoded));
    }

    #[test]
    fn test_display_identity_base32() {
        let id = random_bytes32();
        let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &id);
        let proto = Identity::Custom {
            kind: "some-p2p".to_string(),
            id: id,
        };
        assert_eq!(proto.to_string(), format!("/identity/some-p2p/{}", encoded));
    }

    #[test]
    fn test_display_uuid_simple() {
        let uuid = Uuid::new_v4();
        let proto = Identity::Uuid(uuid);
        assert_eq!(proto.to_string(), format!("/uuid/{}", uuid.simple()));
    }
}
