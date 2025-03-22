use std::{fmt, net::{IpAddr, Ipv4Addr, Ipv6Addr}, str::FromStr};
use anyhow::{anyhow, Result};
use serde::{Serialize, Deserialize};
use crate::protocol::Protocol;

/// A stack address that contains a stack of protocols.
/// The stack address can be used to represent a network address with multiple protocols.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut protocols = Vec::new();
        let mut parts = s.split('/').filter(|p| !p.is_empty());

        while let Some(proto) = parts.next() {
            let protocol = match proto {
                "ip4" => {
                    let addr = parts.next().ok_or_else(|| anyhow!("Missing ip4 address"))?;
                    Protocol::Ip4(addr.parse()?)
                }
                "ip6" => {
                    let addr = parts.next().ok_or_else(|| anyhow!("Missing ip6 address"))?;
                    Protocol::Ip6(addr.parse()?)
                }
                "dns" => {
                    let name = parts.next().ok_or_else(|| anyhow!("Missing dns name"))?;
                    Protocol::Dns(name.to_string())
                }
                "dns4" => {
                    let name = parts.next().ok_or_else(|| anyhow!("Missing dns4 name"))?;
                    Protocol::Dns4(name.to_string())
                }
                "dns6" => {
                    let name = parts.next().ok_or_else(|| anyhow!("Missing dns6 name"))?;
                    Protocol::Dns6(name.to_string())
                }
                "tcp" => {
                    let port = parts.next().ok_or_else(|| anyhow!("Missing tcp port"))?;
                    Protocol::Tcp(port.parse()?)
                }
                "udp" => {
                    let port = parts.next().ok_or_else(|| anyhow!("Missing udp port"))?;
                    Protocol::Udp(port.parse()?)
                }
                "quic" => Protocol::Quic,
                "http" => Protocol::Http,
                "https" => Protocol::Https,
                "ws" => {
                    let port = parts.next().ok_or_else(|| anyhow!("Missing ws port"))?;
                    Protocol::Ws(port.parse()?)
                }
                "wss" => {
                    let port = parts.next().ok_or_else(|| anyhow!("Missing wss port"))?;
                    Protocol::Wss(port.parse()?)
                }
                "webtransport" => {
                    let port = parts.next().ok_or_else(|| anyhow!("Missing webtransport port"))?;
                    Protocol::WebTransport(port.parse()?)
                }
                "identity" => {
                    let kind = parts.next().ok_or_else(|| anyhow!("Missing identity kind"))?;
                    let encoded = parts.next().ok_or_else(|| anyhow!("Missing identity value"))?;
                    let id = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, encoded)
                        .ok_or_else(|| anyhow!("Invalid base32 identity"))?;
                    Protocol::Identity {
                        kind: kind.to_string(),
                        id,
                    }
                }
                "custom" => {
                    let name = parts.next().ok_or_else(|| anyhow!("Missing custom name"))?;
                    Protocol::Custom(name.to_string())
                }
                unknown => return Err(anyhow!("Unknown protocol: {}", unknown)),
            };
            protocols.push(protocol);
        }

        Ok(StackAddr { stack: protocols })
    }
}
