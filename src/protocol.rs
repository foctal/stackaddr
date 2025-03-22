use std::{fmt, net::{Ipv4Addr, Ipv6Addr}};
use serde::{Serialize, Deserialize};

/// A protocol that can be used in a stack address.
/// The protocol can be used to represent a network protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Protocol {
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
    Identity {
        kind: String,
        id: Vec<u8>,
    },
    Custom(String),
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Protocol::*;
        match self {
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
            Identity { kind, id } => {
                let encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, id);
                write!(f, "/identity/{}/{}", kind, encoded)
            },
            Custom(name) => write!(f, "/custom/{}", name),
        }
    }
}
