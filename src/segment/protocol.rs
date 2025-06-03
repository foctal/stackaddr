//! Protocol segment
//!
//! Defines the `Protocol` enum, which represents individual protocols
//! used in layered network addressing. These include:
//!
//! - **Link-layer**: e.g. `/mac/aa:bb:cc:dd:ee:ff`
//! - **Network-layer**: e.g. `/ip4/`, `/ip6/`
//! - **Transport-layer**: e.g. `/tcp/`, `/udp/`, `/tls/`, `/quic/`
//! - **Application-layer**: e.g. `/http/`, `/wtr/`, `/webrtc/`, `/onion/...`
//!
//! All variants serialize to a self-describing string form via `Display`, e.g.
//! `/ip4/192.168.0.1/tcp/443/tls/http`.
//!
//! This enum is designed for composability within a [`StackAddr`](crate::StackAddr).

use netdev::mac::MacAddr;
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A protocol segment used to build layered network addresses.
///
/// Each variant represents a well-known protocol at different layers (L2–L7),
/// or a custom protocol. All variants are rendered as `/<name>/<value>` strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Protocol {
    /// MAC address (layer 2)
    Mac(MacAddr),
    /// IPv4 address (layer 3)
    Ip4(Ipv4Addr),
    /// IPv6 address (layer 3)
    Ip6(Ipv6Addr),
    /// DNS (unspecified family)
    Dns(String),
    /// DNS (IPv4)
    Dns4(String),
    /// DNS (IPv6)
    Dns6(String),
    /// TCP port (layer 4)
    Tcp(u16),
    /// UDP port (layer 4)
    Udp(u16),
    /// TLS (over TCP)
    Tls,
    /// QUIC (over UDP)
    Quic,
    /// HTTP protocol
    Http,
    /// HTTPS (alias for `/tls/http`)
    Https,
    /// WebSocket (with port)
    Ws(u16),
    /// Secure WebSocket (with port)
    Wss(u16),
    /// WebTransport (over QUIC or HTTP/3)
    WebTransport(u16),
    /// WebRTC
    WebRTC,
    /// Tor Onion address (v2 or v3)
    Onion(String),
    /// Arbitrary custom protocol
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
            Mac(addr) => write!(f, "/mac/{}", addr),
            Tcp(port) => write!(f, "/tcp/{}", port),
            Udp(port) => write!(f, "/udp/{}", port),
            Tls => write!(f, "/tls"),
            Quic => write!(f, "/quic"),
            Http => write!(f, "/http"),
            Https => write!(f, "/https"),
            Ws(port) => write!(f, "/ws/{}", port),
            Wss(port) => write!(f, "/wss/{}", port),
            WebTransport(port) => write!(f, "/wtr/{}", port),
            WebRTC => write!(f, "/webrtc"),
            Onion(addr) => write!(f, "/onion/{}", addr),
            Custom(name) => write!(f, "/custom/{}", name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TransportProtocol {
    /// TCP port
    Tcp(u16),
    /// UDP port
    Udp(u16),
    /// TLS (over TCP)
    TlsTcp(u16),
    /// QUIC (over UDP)
    Quic(u16),
    /// WebSocket with port
    Ws(u16),
    /// Secure WebSocket with port
    Wss(u16),
    /// WebTransport with port
    WebTransport(u16),
}

impl TransportProtocol {
    /// Get the port number associated with the transport protocol.
    pub fn port(&self) -> u16 {
        match self {
            TransportProtocol::Tcp(p)
            | TransportProtocol::Udp(p)
            | TransportProtocol::TlsTcp(p)
            | TransportProtocol::Quic(p)
            | TransportProtocol::Ws(p)
            | TransportProtocol::Wss(p)
            | TransportProtocol::WebTransport(p) => *p,
        }
    }
    /// Check if the transport protocol is secure. (by TLS)
    pub fn is_secure(&self) -> bool {
        matches!(
            self,
            TransportProtocol::TlsTcp(_)
                | TransportProtocol::Quic(_)
                | TransportProtocol::Wss(_)
                | TransportProtocol::WebTransport(_)
        )
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TransportProtocol::*;
        match self {
            Tcp(port) => write!(f, "tcp/{}", port),
            Udp(port) => write!(f, "udp/{}", port),
            TlsTcp(port) => write!(f, "tls/tcp/{}", port),
            Quic(port) => write!(f, "quic/{}", port),
            Ws(port) => write!(f, "ws/{}", port),
            Wss(port) => write!(f, "wss/{}", port),
            WebTransport(port) => write!(f, "wtr/{}", port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
