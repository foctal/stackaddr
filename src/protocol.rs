use bytes::Bytes;
use uuid::Uuid;
use std::{fmt, net::{Ipv4Addr, Ipv6Addr}};
use netdev::mac::MacAddr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A protocol that can be used in a stack address.
/// The protocol can be used to represent a network protocol or a cryptographic identity.
/// - Network protocols are represented by their name and optional parameters.
/// - Cryptographic identities are represented by their kind and ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Protocol {
    Mac(MacAddr),
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
    Dns(String),
    Dns4(String),
    Dns6(String),
    Tcp(u16),
    Udp(u16),
    Quic,
    Http,
    Https,
    Ws(u16),
    Wss(u16),
    WebTransport(u16),
    NodeId(Bytes),
    PeerId(Bytes),
    Identity {
        kind: String,
        id: Bytes,
    },
    Uuid(Uuid),
    Custom(String),
}

impl Protocol {
    /// Create a new identity protocol with the given kind and ID.
    pub fn identity<B: Into<Bytes>>(kind: String, id: B) -> Self {
        Protocol::Identity { kind, id: id.into() }
    }
    /// Create a new NodeId with the given ID.
    pub fn node_id<B: Into<Bytes>>(id: B) -> Self {
        Protocol::NodeId(id.into())
    }
    /// Create a new PeerId with the given ID.
    pub fn peer_id<B: Into<Bytes>>(id: B) -> Self {
        Protocol::PeerId(id.into())
    }
    /// Create a new Uuid with the given ID.
    pub fn uuid<U: Into<Uuid>>(uuid: U) -> Self {
        Protocol::Uuid(uuid.into())
    }
    /// Check if the protocol is a transport protocol.
    pub fn is_transport(&self) -> bool {
        matches!(self, Protocol::Tcp(_) | Protocol::Udp(_) | Protocol::Quic | Protocol::Ws(_) | Protocol::Wss(_) | Protocol::WebTransport(_))
    }
    /// Check if the protocol is an address protocol.
    pub fn is_address(&self) -> bool {
        matches!(self, Protocol::Ip4(_) | Protocol::Ip6(_) | Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_))
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Protocol::*;
        match self {
            Mac(mac) => write!(f, "/mac/{}", mac),
            Ip4(addr) => write!(f, "/ip4/{}", addr),
            Ip6(addr) => write!(f, "/ip6/{}", addr),
            Dns(name) => write!(f, "/dns/{}", name),
            Dns4(name) => write!(f, "/dns4/{}", name),
            Dns6(name) => write!(f, "/dns6/{}", name),
            Tcp(port) => write!(f, "/tcp/{}", port),
            Udp(port) => write!(f, "/udp/{}", port),
            Quic => write!(f, "/quic"),
            Http => write!(f, "/http"),
            Https => write!(f, "/https"),
            Ws(port) => write!(f, "/ws/{}", port),
            Wss(port) => write!(f, "/wss/{}", port),
            WebTransport(port) => write!(f, "/wtr/{}", port),
            NodeId(id) => {
                let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, id);
                write!(f, "/node/{}", encoded)
            },
            PeerId(id) => {
                let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, id);
                write!(f, "/peer/{}", encoded)
            },
            Identity { kind, id } => {
                let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, id);
                write!(f, "/identity/{}/{}", kind, encoded)
            },
            Uuid(uuid) => write!(f, "/uuid/{}", uuid.simple()),
            Custom(name) => write!(f, "/custom/{}", name),
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
    fn test_display_macaddr() {
        use netdev::mac::MacAddr;
        let mac = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        let proto = vec![
            Protocol::Mac(mac),
            Protocol::Ip4("192.168.10.10".parse().unwrap()),
        ];
        let text = proto.iter().map(|p| p.to_string()).collect::<String>();
        assert_eq!(text, "/mac/aa:bb:cc:dd:ee:ff/ip4/192.168.10.10");
    }

    #[test]
    fn test_display_ip4_quic() {
        let proto = vec![
            Protocol::Ip4("127.0.0.1".parse().unwrap()),
            Protocol::Udp(4433),
            Protocol::Quic,
        ];
        let text = proto.iter().map(|p| p.to_string()).collect::<String>();
        assert_eq!(text, "/ip4/127.0.0.1/udp/4433/quic");
    }

    #[test]
    fn test_display_ip6_tcp_https() {
        let proto = vec![
            Protocol::Ip6("::1".parse().unwrap()),
            Protocol::Tcp(443),
            Protocol::Https,
        ];
        let text = proto.iter().map(|p| p.to_string()).collect::<String>();
        assert_eq!(text, "/ip6/::1/tcp/443/https");
    }

    #[test]
    fn test_display_nodeid_base32() {
        let id = random_bytes32();
        let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &id);
        let proto = Protocol::NodeId(id);
        assert_eq!(proto.to_string(), format!("/node/{}", encoded));
    }

    #[test]
    fn test_display_identity_base32() {
        let id = random_bytes32();
        let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &id);
        let proto = Protocol::Identity {
            kind: "some-p2p".to_string(),
            id: id,
        };
        assert_eq!(proto.to_string(), format!("/identity/some-p2p/{}", encoded));
    }

    #[test]
    fn test_display_uuid_simple() {
        let uuid = Uuid::new_v4();
        let proto = Protocol::Uuid(uuid);
        assert_eq!(proto.to_string(), format!("/uuid/{}", uuid.simple()));
    }
}
