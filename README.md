[crates-badge]: https://img.shields.io/crates/v/stackaddr.svg
[crates-url]: https://crates.io/crates/stackaddr
[license-badge]: https://img.shields.io/crates/l/stackaddr.svg
[doc-url]: https://docs.rs/stackaddr/latest/stackaddr
[stackaddr-github-url]: https://github.com/fortnium/stackaddr

# stackaddr [![Crates.io][crates-badge]][crates-url] ![License][license-badge]
Self-describing, layered address representation library, designed with flexibility and extensibility.

`stackaddr` provides a type-safe, composable, and future-proof way to represent network addresses and protocol stacks.  

## Features
- Layered protocol stack: supports multiple encapsulated protocols (e.g. `/ip4/127.0.0.1/udp/4433/quic`)
    - Supports from L2 (MAC) to application-level protocols (e.g. `/mac/aa:bb:cc:dd:ee:ff/ip4/192.168.1.1/tcp/80/http`)
- Identity aware: supports cryptographic identities like NodeId, PeerId, and UUID
- Strong typing: no ambiguity between TCP/UDP/DNS/etc.
- Serde support(optional): enable with `features = ["serde"]`
- Easy parsing: implements `FromStr`, `Display`, and error types for easy parsing

## Usage
Add `stackaddr` to your dependencies:  
```toml:Cargo.toml
[dependencies]
stackaddr = "0.1"
```

To enable serde support:
```
[dependencies]
stackaddr = { version = "0.1", features = ["serde"] }
```

## Example
Basic:
```rust
use stackaddr::{StackAddr, Protocol};

let addr = StackAddr::new(&[
    Protocol::Ip4("192.168.10.1".parse().unwrap()),
    Protocol::Tcp(443),
    Protocol::Https,
]);

println!("{}", addr); 
// Output: /ip4/192.168.10.1/tcp/443/https
```

From L2 to L4:
```rust
let s = "/mac/aa:bb:cc:dd:ee:ff/ip4/192.168.1.1/tcp/8080";
let addr: StackAddr = s.parse().expect("parse failed");

let expected = StackAddr::new(&[
    Protocol::Mac("aa:bb:cc:dd:ee:ff".parse().unwrap()),
    Protocol::Ip4("192.168.1.1".parse().unwrap()),
    Protocol::Tcp(8080),
]);

assert_eq!(addr, expected);
```

Parsing from string:
```rust
let parsed: StackAddr = "/ip6/::1/tcp/8443".parse().unwrap();
assert_eq!(parsed.port(), Some(8443));
```

With identity:
```rust
let public_key: [u8; 32] = generate_public_key();
let id = Bytes::copy_from_slice(&public_key);
let stack = StackAddr::new(&[
    Protocol::Ip4("192.168.10.10".parse().unwrap()),
    Protocol::Udp(4433),
    Protocol::Quic,
    Protocol::NodeId(id),
]);
```

## Acknowledgment
Inspired by [Multiaddr](https://github.com/multiformats/multiaddr),
StackAddr inherits its core ideas while embracing Rust’s flexibility to provide a more general-purpose and extensible address representation.
