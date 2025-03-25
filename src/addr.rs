use bytes::Bytes;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use uuid::Uuid;
use std::{fmt, net::{IpAddr, Ipv4Addr, Ipv6Addr}, str::FromStr};
use crate::{protocol::Protocol, error::StackAddrError};

/// A stack address that contains a stack of protocols.
/// The stack address can be used to represent a network address with multiple protocols.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StackAddr {
    stack: Vec<Protocol>,
}

impl StackAddr {
    /// Create a new stack address with the given protocols.
    pub fn new(protocols: &[Protocol]) -> Self {
        StackAddr {
            stack: protocols.to_vec(),
        }
    }
    /// Create an empty stack address.
    pub fn empty() -> Self {
        StackAddr { stack: Vec::new() }
    }
    /// Create a stack address with the given protocol. 
    /// This is a convenience method for creating a stack address with builder pattern.
    pub fn with(mut self, p: Protocol) -> Self {
        self.stack.push(p);
        self
    }
    /// Create a stack address with the given protocol parts.
    pub fn from_parts<I: IntoIterator<Item = Protocol>>(parts: I) -> Self {
        StackAddr {
            stack: parts.into_iter().collect(),
        }
    }
    /// Create a stack address with the given IP address.
    pub fn with_ip(ip_addr: IpAddr) -> Self {
        match ip_addr {
            IpAddr::V4(addr) => StackAddr::new(&[Protocol::Ip4(addr)]),
            IpAddr::V6(addr) => StackAddr::new(&[Protocol::Ip6(addr)]),
        }
    }
    /// Create a stack address with the given DNS name.
    pub fn with_name(name: &str) -> Self {
        StackAddr::new(&[Protocol::Dns(name.to_string())])
    }
    /// Create a stack address with the given DNS name.
    /// This will resolve to an IPv4 address.
    pub fn with_namev4(name: &str) -> Self {
        StackAddr::new(&[Protocol::Dns4(name.to_string())])
    }
    /// Create a stack address with the given DNS name.
    /// This will resolve to an IPv6 address.
    pub fn with_namev6(name: &str) -> Self {
        StackAddr::new(&[Protocol::Dns6(name.to_string())])
    }

    /// Create a stack address with the UNSPECIFIED IPv4 address.
    pub fn unspecified_ipv4() -> Self {
        StackAddr::new(&[Protocol::Ip4(Ipv4Addr::UNSPECIFIED)])
    }

    /// Create a stack address with the UNSPECIFIED IPv6 address.
    pub fn unspecified_ipv6() -> Self {
        StackAddr::new(&[Protocol::Ip6(Ipv6Addr::UNSPECIFIED)])
    }

    /// Get the protocol stack of the stack address.
    pub fn stack(&self) -> &[Protocol] {
        &self.stack
    }

    /// Get an iterator over the protocols in the stack address.
    pub fn iter(&self) -> impl Iterator<Item = &Protocol> {
        self.stack.iter()
    }

    /// Push a protocol to the stack address.
    pub fn push(&mut self, protocol: Protocol) {
        self.stack.push(protocol);
    }

    /// Pop a protocol from the stack address.
    pub fn pop(&mut self) -> Option<Protocol> {
        self.stack.pop()
    }

    /// Check if the stack address contains the given protocol with inner details.
    pub fn contains(&self, protocol: &Protocol) -> bool {
        self.stack.contains(protocol)
    }

    /// Check if the stack address supports the given protocol without considering the port or inner details.
    pub fn supports(&self, protocol: &Protocol) -> bool {
        self.stack.iter().any(|p| std::mem::discriminant(p) == std::mem::discriminant(protocol))
    }

    /// Replace the first occurrence of the given protocol with a new one.
    /// Returns true if a replacement was made.
    pub fn replace(&mut self, old: &Protocol, new: Protocol) -> bool {
        if let Some(pos) = self.stack.iter().position(|p| p == old) {
            self.stack[pos] = new;
            true
        } else {
            false
        }
    }

    /// Replace all occurrences of the given protocol with the new one.
    /// Returns the number of replacements made.
    pub fn replace_all(&mut self, old: &Protocol, new: Protocol) -> usize {
        let mut count = 0;
        for p in &mut self.stack {
            if p == old {
                *p = new.clone();
                count += 1;
            }
        }
        count
    }

    /// Remove the first occurrence of the given protocol.
    /// Returns true if an element was removed.
    pub fn remove(&mut self, target: &Protocol) -> bool {
        if let Some(pos) = self.stack.iter().position(|p| p == target) {
            self.stack.remove(pos);
            true
        } else {
            false
        }
    }

    /// Remove all occurrences of the given protocol.
    /// Returns the number of elements removed.
    pub fn remove_all(&mut self, target: &Protocol) -> usize {
        let before = self.stack.len();
        self.stack.retain(|p| p != target);
        before - self.stack.len()
    }

    /// Get the IP address of the stack address.
    pub fn ip(&self) -> Option<IpAddr> {
        for p in self.stack.iter() {
            match p {
                Protocol::Ip4(addr) => return Some(IpAddr::V4(*addr)),
                Protocol::Ip6(addr) => return Some(IpAddr::V6(*addr)),
                _ => (),
            }
        }
        None
    }

    /// Get the DNS name of the stack address.
    pub fn name(&self) -> Option<&str> {
        for p in self.stack.iter() {
            match p {
                Protocol::Dns(name) => return Some(name),
                Protocol::Dns4(name) => return Some(name),
                Protocol::Dns6(name) => return Some(name),
                _ => (),
            }
        }
        None
    }

    /// Get the port number of the stack address.
    pub fn port(&self) -> Option<u16> {
        for p in self.stack.iter().rev() {
            match p {
                Protocol::Tcp(port) => return Some(*port),
                Protocol::Udp(port) => return Some(*port),
                Protocol::Quic => return Some(443),
                Protocol::Ws(port) => return Some(*port),
                Protocol::Wss(port) => return Some(*port),
                Protocol::WebTransport(port) => return Some(*port),
                _ => (),
            }
        }
        None
    }

    /// Get the identity of the stack address.
    pub fn identity(&self) -> Option<&[u8]> {
        for p in self.stack.iter() {
            match p {
                Protocol::Identity { id, .. } => return Some(id),
                _ => (),
            }
        }
        None
    }

    /// Check if the stack address is resolved.
    /// This means that the stack address contains an IP address.
    pub fn resolved(&self) -> bool {
        for p in self.stack.iter() {
            match p {
                Protocol::Ip4(_) | Protocol::Ip6(_) => return true,
                _ => (),
            }
        }
        false
    }

    /// Check if the stack address is empty.
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }
    
}

impl fmt::Display for StackAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for p in &self.stack {
            write!(f, "{}", p)?;
        }
        Ok(())
    }
}

impl FromStr for StackAddr {
    type Err = StackAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut protocols = Vec::new();
        let mut parts = s.split('/').filter(|p| !p.is_empty());

        while let Some(proto) = parts.next() {
            let protocol = match proto {
                "mac" => {
                    let val = parts.next().ok_or(StackAddrError::MissingPart("mac address"))?;
                    let mac = val.parse().map_err(|_| StackAddrError::InvalidEncoding("mac address"))?;
                    Protocol::Mac(mac)
                }
                "ip4" => {
                    let addr = parts.next().ok_or(StackAddrError::MissingPart("ip4 address"))?;
                    Protocol::Ip4(addr.parse()?)
                }
                "ip6" => {
                    let addr = parts.next().ok_or(StackAddrError::MissingPart("ip6 address"))?;
                    Protocol::Ip6(addr.parse()?)
                }
                "dns" => {
                    let name = parts.next().ok_or(StackAddrError::MissingPart("dns name"))?;
                    Protocol::Dns(name.to_string())
                }
                "dns4" => {
                    let name = parts.next().ok_or(StackAddrError::MissingPart("dns4 name"))?;
                    Protocol::Dns4(name.to_string())
                }
                "dns6" => {
                    let name = parts.next().ok_or(StackAddrError::MissingPart("dns6 name"))?;
                    Protocol::Dns6(name.to_string())
                }
                "tcp" => {
                    let port = parts.next().ok_or(StackAddrError::MissingPart("tcp port"))?;
                    Protocol::Tcp(port.parse()?)
                }
                "udp" => {
                    let port = parts.next().ok_or(StackAddrError::MissingPart("udp port"))?;
                    Protocol::Udp(port.parse()?)
                }
                "quic" => Protocol::Quic,
                "http" => Protocol::Http,
                "https" => Protocol::Https,
                "ws" => {
                    let port = parts.next().ok_or(StackAddrError::MissingPart("ws port"))?;
                    Protocol::Ws(port.parse()?)
                }
                "wss" => {
                    let port = parts.next().ok_or(StackAddrError::MissingPart("wss port"))?;
                    Protocol::Wss(port.parse()?)
                }
                "webtransport" | "wtr" => {
                    let port = parts.next().ok_or(StackAddrError::MissingPart("webtransport port"))?;
                    Protocol::WebTransport(port.parse()?)
                }
                "node" => {
                    let val = parts.next().ok_or(StackAddrError::MissingPart("node id"))?;
                    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, val)
                        .ok_or(StackAddrError::InvalidEncoding("base32 in node"))?;
                    Protocol::NodeId(Bytes::from(decoded))
                }
                "peer" => {
                    let val = parts.next().ok_or(StackAddrError::MissingPart("peer id"))?;
                    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, val)
                        .ok_or(StackAddrError::InvalidEncoding("base32 in peer"))?;
                    Protocol::PeerId(Bytes::from(decoded))
                }
                "identity" => {
                    let kind = parts.next().ok_or(StackAddrError::MissingPart("identity kind"))?;
                    let val = parts.next().ok_or(StackAddrError::MissingPart("identity value"))?;
                    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, val)
                        .ok_or(StackAddrError::InvalidEncoding("base32 in identity"))?;
                    Protocol::Identity {
                        kind: kind.to_string(),
                        id: Bytes::from(decoded),
                    }
                }
                "uuid" => {
                    let val = parts.next().ok_or(StackAddrError::MissingPart("uuid value"))?;
                    let uuid = Uuid::parse_str(val).map_err(|_| StackAddrError::InvalidEncoding("uuid"))?;
                    Protocol::Uuid(uuid)
                }
                "custom" => {
                    let name = parts.next().ok_or(StackAddrError::MissingPart("custom name"))?;
                    Protocol::Custom(name.to_string())
                }
                unknown => return Err(StackAddrError::UnknownProtocol(unknown.to_string())),
            };
            protocols.push(protocol);
        }

        Ok(StackAddr { stack: protocols })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Protocol;

    fn random_bytes32() -> Bytes {
        use rand::RngCore;
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        Bytes::copy_from_slice(&buf)
    }

    #[test]
    fn test_builder_and_display() {
        let addr = StackAddr::empty()
            .with(Protocol::Ip4("192.168.10.10".parse().unwrap()))
            .with(Protocol::Udp(4433))
            .with(Protocol::Quic);

        assert_eq!(addr.to_string(), "/ip4/192.168.10.10/udp/4433/quic");
    }

    #[test]
    fn test_parse_from_str() {
        let addr: StackAddr = "/ip6/::1/tcp/8080/http".parse().unwrap();
        assert_eq!(addr.ip().unwrap(), Ipv6Addr::LOCALHOST);
        assert_eq!(addr.port(), Some(8080));
    }

    #[test]
    fn test_replace_and_remove() {
        let mut addr = StackAddr::empty()
            .with(Protocol::Dns4("example.com".into()))
            .with(Protocol::Tcp(80));

        assert!(addr.replace(&Protocol::Tcp(80), Protocol::Tcp(443)));
        assert_eq!(addr.port(), Some(443));

        assert!(addr.remove(&Protocol::Dns4("example.com".into())));
        assert!(addr.name().is_none());
    }

    #[test]
    fn test_identity_query() {
        let id = random_bytes32();
        let addr = StackAddr::empty().with(Protocol::Identity {
            kind: "some-p2p".to_string(),
            id: id.clone(),
        });
        assert_eq!(addr.identity(), Some(&id[..]));
    }

    #[test]
    fn test_resolved_check() {
        let name: &str = "example.com";
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();

        let mut a = StackAddr::with_name(name);
        let b = StackAddr::with_ip(IpAddr::V4(ip));
        assert!(!a.resolved());
        assert!(b.resolved());

        a.replace(&Protocol::Dns(name.to_string()), Protocol::Ip4(ip));
        assert!(a.resolved());
    }

    #[test]
    fn test_error_display() {
        let err = StackAddrError::MissingPart("foo");
        assert_eq!(err.to_string(), "Missing foo");
    }

    #[test]
    fn test_l2_to_l4() {
        let s = "/mac/aa:bb:cc:dd:ee:ff/ip4/192.168.1.1/tcp/8080";
        let addr: StackAddr = s.parse().expect("parse failed");

        let expected = StackAddr::new(&[
            Protocol::Mac("aa:bb:cc:dd:ee:ff".parse().unwrap()),
            Protocol::Ip4("192.168.1.1".parse().unwrap()),
            Protocol::Tcp(8080),
        ]);

        assert_eq!(addr, expected);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde() {
        let id = random_bytes32();
        let addr = StackAddr::new(&[
            Protocol::Mac("00:11:22:33:44:55".parse().unwrap()),
            Protocol::Ip4("10.0.0.1".parse().unwrap()),
            Protocol::Udp(4433),
            Protocol::Quic,
            Protocol::NodeId(id),
        ]);

        let json = serde_json::to_string(&addr).unwrap();
        let decoded: StackAddr = serde_json::from_str(&json).unwrap();

        assert_eq!(addr, decoded);
    }
}
