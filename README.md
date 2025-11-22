[crates-badge]: https://img.shields.io/crates/v/stackaddr.svg
[crates-url]: https://crates.io/crates/stackaddr
[license-badge]: https://img.shields.io/crates/l/stackaddr.svg
[doc-url]: https://docs.rs/stackaddr/latest/stackaddr
[stackaddr-github-url]: https://github.com/fortnium/stackaddr

# stackaddr [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Self-describing, layered address representation library, designed with flexibility and extensibility.

`stackaddr` provides a type-safe, composable, and future-proof way to represent complex address stacks, including transport protocols, cryptographic identities, metadata, and resource paths.  

## Features
- **Segment-based architecture**: each address consists of typed [`Segment`]s
    - Protocols like `/ip4`, `/tcp`, `/tls`, `/http`
    - Identities like `/node/<base32>`, `/uuid/<uuid>`
    - Metadata like `/meta/env/production`
    - Path-like entries like `/foo/bar`
- **Layered from L2 to L7**: supports MAC, IP, TCP/UDP, TLS, HTTP, and more
    - `/ip4/127.0.0.1/udp/4433/quic`
    - `/mac/aa:bb:cc:dd:ee:ff/ip4/192.168.1.1/tcp/80/http`
- serde support(optional): enable with `features = ["serde"]`
- Easy parsing: implements `FromStr`, `Display`, and error types for easy parsing

## Usage
Add `stackaddr` to your dependencies:  
```toml:Cargo.toml
[dependencies]
stackaddr = "0.7"
```

To enable serde support:
```
[dependencies]
stackaddr = { version = "0.7", features = ["serde"] }
```

## Example
Basic:
```rust
use stackaddr::{StackAddr, Protocol, Segment};

let addr = StackAddr::from_parts(&[
    Segment::Protocol(Protocol::Ip4("192.168.1.1".parse().unwrap())),
    Segment::Protocol(Protocol::Tcp(443)),
    Segment::Protocol(Protocol::Tls),
    Segment::Protocol(Protocol::Http),
]);

println!("{}", addr); 
// Output: /ip4/192.168.1.1/tcp/443/tls/http
```

From L2 to L4:
```rust
let s = "/mac/aa:bb:cc:dd:ee:ff/ip4/192.168.1.1/tcp/8080";
let addr: StackAddr = s.parse().expect("parse failed");
```

With identity:
```rust
let public_key: [u8; 32] = generate_public_key();
let id = Bytes::copy_from_slice(&public_key);
let addr = StackAddr::from_parts(&[
    Segment::Protocol(Protocol::Ip4("192.168.10.10".parse().unwrap())),
    Segment::Protocol(Protocol::Udp(4433)),
    Segment::Protocol(Protocol::Quic),
    Segment::Identity(Identity::NodeId(id)),
]);
```

With path:
```rust
let addr: StackAddr = "/dns/example.com/tcp/443/tls/http/images/logo.png".parse().unwrap();
```

With metadata:
```rust
let addr: StackAddr = "/meta/env/production".parse().unwrap();
```

Resolving to socket addresses:
```rust
use std::net::ToSocketAddrs;

let addr: StackAddr = "/dns/localhost/tcp/443".parse().unwrap();

// Structured host/port extraction
let (host, port) = addr.host_port().unwrap();
assert_eq!((host.as_str(), port), ("localhost", 443));

// System resolution for libraries expecting concrete socket addresses
let addrs = addr.socket_addrs().unwrap();
assert!(!addrs.is_empty());

// Or hand it directly to APIs that accept `ToSocketAddrs`
for sock in addr.to_socket_addrs().unwrap() {
    println!("Resolved: {}", sock);
}
```

## Acknowledgment
Inspired by [Multiaddr](https://github.com/multiformats/multiaddr),
StackAddr inherits its core ideas and provide a more general-purpose and extensible address representation.
