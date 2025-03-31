//! This example demonstrates how to create a `StackAddr` with multiple protocols and an identity.

use bytes::Bytes;
use stackaddr::{Identity, MacAddr, Protocol, StackAddr};

fn random_bytes32() -> Bytes {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    Bytes::copy_from_slice(&buf)
}

fn main() {
    let id = random_bytes32();
    let addr = StackAddr::empty()
        .with_protocol(Protocol::Mac(MacAddr::from_hex_format("aa:bb:cc:dd:ee:ff")))
        .with_protocol(Protocol::Ip4("192.168.10.10".parse().unwrap()))
        .with_protocol(Protocol::Udp(4433))
        .with_protocol(Protocol::Quic)
        .with_identity(Identity::NodeId(id.clone()));

    println!("{}", addr);
}
