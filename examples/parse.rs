//! Parse a stack address passed as a command-line argument.
//!
//! Example:
//! $ cargo run --example parse -- "/ip4/127.0.0.1/tcp/443/http"
//! ✅ Parsed: /ip4/127.0.0.1/tcp/443/http

use stackaddr::StackAddr;
use std::env;

fn main() {
    let arg = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("❌ Usage: cargo run --example parse -- \"/ip4/127.0.0.1/tcp/443/http\"");
        std::process::exit(1);
    });

    match arg.parse::<StackAddr>() {
        Ok(addr) => {
            println!("✅ Parsed: {}", addr);
        }
        Err(e) => {
            eprintln!("❌ Parse error: {}", e);
            std::process::exit(1);
        }
    }
}
