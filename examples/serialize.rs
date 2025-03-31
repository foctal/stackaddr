//! Serialize and deserialize a StackAddr using serde_json.

use bytes::Bytes;
use serde_json;
use stackaddr::{Identity, Protocol, StackAddr};

fn main() {
    let id = Bytes::from_static(b"01234567890123456789012345678901");

    let addr = StackAddr::empty()
        .with_protocol(Protocol::Ip4("10.0.0.1".parse().unwrap()))
        .with_protocol(Protocol::Tcp(443))
        .with_protocol(Protocol::Tls)
        .with_protocol(Protocol::Http)
        .with_identity(Identity::NodeId(id.clone()));

    // Serialize
    let json = serde_json::to_string_pretty(&addr).expect("serialize failed");
    println!("Serialized JSON:\n{}\n", json);

    // Deserialize
    let deserialized: StackAddr = serde_json::from_str(&json).expect("deserialize failed");
    println!("✅ Deserialized:\n{}", deserialized);

    assert_eq!(addr, deserialized);
}
