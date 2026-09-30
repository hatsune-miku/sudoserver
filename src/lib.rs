#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod mcp;
mod mcp_text;
pub mod server;
pub mod shell;

pub const VERSION: &str = env!("SUDOSERVER_VERSION");
pub const COMMIT: &str = env!("SUDOSERVER_COMMIT");
