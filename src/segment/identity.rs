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
use std::fmt;
use uuid::Uuid;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::StackAddrError;

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
    Custom { kind: String, id: Bytes },
}

impl Identity {
    /// Returns the underlying identity bytes for this variant.
    ///
    /// For `Uuid`, this returns the canonical 16-byte representation.
    pub fn id_bytes(&self) -> &[u8] {
        match self {
            Identity::NodeId(b) | Identity::PeerId(b) => b,
            Identity::Custom { id, .. } => id,
            Identity::Uuid(u) => u.as_bytes(),
        }
    }

    /// Encodes the identity bytes as base32 (RFC4648, no padding).
    pub fn to_base32(&self) -> String {
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, self.id_bytes())
    }

    /// Encodes the identity bytes as URL-safe base64 without padding.
    pub fn to_base64url(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.id_bytes())
    }

    pub fn from_base32_node(encoded: &str) -> Result<Self, StackAddrError> {
        let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, encoded)
            .ok_or(StackAddrError::InvalidEncoding("base32 node id"))?;
        Ok(Identity::NodeId(Bytes::from(decoded)))
    }

    pub fn from_base32_peer(encoded: &str) -> Result<Self, StackAddrError> {
        let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, encoded)
            .ok_or(StackAddrError::InvalidEncoding("base32 peer id"))?;
        Ok(Identity::PeerId(Bytes::from(decoded)))
    }

    pub fn from_base32_custom(
        kind: impl Into<String>,
        encoded: &str,
    ) -> Result<Self, StackAddrError> {
        let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, encoded)
            .ok_or(StackAddrError::InvalidEncoding("base32 identity"))?;
        Ok(Identity::Custom {
            kind: kind.into(),
            id: Bytes::from(decoded),
        })
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Identity::*;
        match self {
            NodeId(id) => {
                let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, id);
                write!(f, "/node/{}", encoded)
            }
            PeerId(id) => {
                let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, id);
                write!(f, "/peer/{}", encoded)
            }
            Uuid(uuid) => write!(f, "/uuid/{}", uuid.simple()),
            Custom { kind, id } => {
                let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, id);
                write!(f, "/identity/{}/{}", kind, encoded)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_bytes32() -> Bytes {
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::rng().fill_bytes(&mut buf);
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

    #[test]
    fn test_id_bytes_all_variants() {
        let node_bytes = random_bytes32();
        let peer_bytes = random_bytes32();
        let custom_bytes = random_bytes32();
        let uuid = Uuid::new_v4();

        let node = Identity::NodeId(node_bytes.clone());
        let peer = Identity::PeerId(peer_bytes.clone());
        let custom = Identity::Custom {
            kind: "kind".to_string(),
            id: custom_bytes.clone(),
        };
        let uuid_id = Identity::Uuid(uuid);

        assert_eq!(node.id_bytes(), &node_bytes[..]);
        assert_eq!(peer.id_bytes(), &peer_bytes[..]);
        assert_eq!(custom.id_bytes(), &custom_bytes[..]);
        assert_eq!(uuid_id.id_bytes(), uuid.as_bytes());
    }

    #[test]
    fn test_to_base32_helper() {
        let id = random_bytes32();
        let identity = Identity::NodeId(id.clone());

        let helper = identity.to_base32();
        let manual = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &id);

        assert_eq!(helper, manual);
    }

    #[test]
    fn test_to_base64url_helper() {
        use base64::Engine as _;

        let id = random_bytes32();
        let identity = Identity::PeerId(id.clone());

        let helper = identity.to_base64url();
        let manual = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&id);

        assert_eq!(helper, manual);
    }

    #[test]
    fn test_from_base32_node_roundtrip() {
        let id = random_bytes32();
        let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &id);

        let identity = Identity::from_base32_node(&encoded).expect("decode failed");
        assert!(matches!(identity, Identity::NodeId(_)));
        assert_eq!(identity.id_bytes(), &id[..]);
    }

    #[test]
    fn test_from_base32_peer_roundtrip() {
        let id = random_bytes32();
        let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &id);

        let identity = Identity::from_base32_peer(&encoded).expect("decode failed");
        assert!(matches!(identity, Identity::PeerId(_)));
        assert_eq!(identity.id_bytes(), &id[..]);
    }

    #[test]
    fn test_from_base32_custom_roundtrip() {
        let id = random_bytes32();
        let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &id);

        let identity =
            Identity::from_base32_custom("myproto", &encoded).expect("decode failed");

        match identity {
            Identity::Custom { kind, id: bytes } => {
                assert_eq!(kind, "myproto");
                assert_eq!(bytes, id);
            }
            _ => panic!("expected Identity::Custom"),
        }
    }

    #[test]
    fn test_from_base32_invalid() {
        // Invalid base32 string
        let invalid = "this-is-not-base32-@@@";

        assert!(Identity::from_base32_node(invalid).is_err());
        assert!(Identity::from_base32_peer(invalid).is_err());
        assert!(Identity::from_base32_custom("kind", invalid).is_err());
    }
}
