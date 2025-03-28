pub mod identity;
pub mod protocol;

use identity::Identity;
use protocol::Protocol;
use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A single segment in a [`StackAddr`](crate::StackAddr).
///
/// This enum allows protocol stack composition across:
/// - networking layers (L2-L7)
/// - cryptographic identity layers
/// - metadata annotations
/// - resource paths
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Segment {
    /// A transport or application protocol segment.
    Protocol(Protocol),
    /// An identity segment (NodeId, PeerId, UUID, etc.).
    Identity(Identity),
    /// A file or resource path segment.
    Path(String),
    /// A key-value metadata pair, expressed as `/meta/<key>/<value>`.
    Metadata(String, String),
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Segment::Protocol(p) => write!(f, "{}", p),
            Segment::Identity(i) => write!(f, "{}", i),
            Segment::Path(p) => write!(f, "/{}", p),
            Segment::Metadata(k, v) => write!(f, "/meta/{}/{}", k, v),
        }
    }
}
