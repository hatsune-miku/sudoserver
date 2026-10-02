#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod mcp;
mod mcp_text;
mod peer;
pub mod server;
pub mod shell;

pub const VERSION: &str = env!("LOCALSHELLD_VERSION");
pub const COMMIT: &str = env!("LOCALSHELLD_COMMIT");
