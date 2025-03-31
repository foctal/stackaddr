use std::fmt;
use std::net::AddrParseError;
use std::num::ParseIntError;

/// An error that can occur when parsing a StackAddr string.
#[derive(Debug)]
pub enum StackAddrError {
    /// A required part of the address was missing.
    MissingPart(&'static str),

    /// Failed to parse an IP address.
    InvalidIp(AddrParseError),

    /// Failed to parse a port number.
    InvalidPort(ParseIntError),

    /// Unknown protocol encountered.
    UnknownProtocol(String),

    /// Invalid encoding encountered.
    InvalidEncoding(&'static str),
}

impl fmt::Display for StackAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StackAddrError::MissingPart(what) => write!(f, "Missing {}", what),
            StackAddrError::InvalidIp(e) => write!(f, "Invalid IP address: {}", e),
            StackAddrError::InvalidPort(e) => write!(f, "Invalid port: {}", e),
            StackAddrError::UnknownProtocol(p) => write!(f, "Unknown protocol: {}", p),
            StackAddrError::InvalidEncoding(e) => write!(f, "Invalid encoding: {}", e),
        }
    }
}

impl std::error::Error for StackAddrError {}

impl From<AddrParseError> for StackAddrError {
    fn from(e: AddrParseError) -> Self {
        StackAddrError::InvalidIp(e)
    }
}

impl From<ParseIntError> for StackAddrError {
    fn from(e: ParseIntError) -> Self {
        StackAddrError::InvalidPort(e)
    }
}
