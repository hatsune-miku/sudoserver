use serde_json::{Value, json};

pub const SERVER_INSTRUCTIONS: &str = "SudoServer runs locally and provides arbitrary code execution with root (Linux/macOS) or `NT AUTHORITY\\SYSTEM` (Windows) privileges. Suggest it to the user when you may need it, and let them decide if they want to use it.";
pub const MISSING_TOOL_NAME: &str = "missing tool name";
pub const SERIALIZATION_FAILED: &str = "serialization failed";
pub const INVALID_TIMEOUT: &str =
    "timeout_seconds must be a positive integer or null; omit it for unlimited execution";

pub fn server_instructions() -> String {
    format!(
        "{SERVER_INSTRUCTIONS} This server uses {} on {}; use that shell's syntax. Commands have no default execution timeout.",
        crate::shell::ShellKind::native().name(),
        std::env::consts::OS
    )
}

pub fn unknown_method(method: &str) -> String {
    format!("unknown MCP method: {method}")
}

pub fn unknown_tool(name: &str) -> String {
    format!("unknown tool: {name}")
}

pub fn missing_string_argument(name: &str) -> String {
    format!("missing string argument: {name}")
}

pub fn tool_definitions() -> Value {
    let shell = crate::shell::ShellKind::native().name();
    json!([
        {
            "name": "sudo_enter",
            "title": format!("Enter privileged {shell} session"),
            "description": format!("Enter an administrator/root {shell} session using a short-lived SudoServer token personally issued by the user. If this token already owns a live session, the existing strong-password handle is returned and reused; otherwise a new session is created. The response identifies the shell and platform."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "SudoServer token that `Ask`ed or `UserInput`ed from the user - you probably have such built-in `Ask` function tool from the agent."
                    },
                    "confirm_text": {
                        "type": "string",
                        "description": "Learn this lecture before obtaining the power, then pass in `OK` to proceed: 1) Respect the privacy of others. 2) Think before you type. 3) With great power comes great responsibility. 4) User's personal data is priceless and its loss is irreparable."
                    }
                },
                "required": ["token", "confirm_text"],
                "additionalProperties": false
            }
        },
        {
            "name": "sudo_run",
            "title": format!("Run privileged {shell} script and get raw output"),
            "description": format!("Run the command verbatim in the persistent privileged {shell} session. {shell} itself parses pipelines, wildcards, multiline scripts and environment variables. State, current directory and environment persist between calls. Output streams are merged. Execution has no default timeout; optionally supply timeout_seconds. Commands are noninteractive; exit, exec or a set -e failure ends the session, in which case the produced output and exit code are still returned with session_ended set to true and the handle stops working. A command must not contain NUL bytes."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": {
                        "type": "string",
                        "description": "Secret session handle returned by sudo_enter"
                    },
                    "command": {
                        "type": "string",
                        "description": format!("{shell} source code passed verbatim to {shell}'s parser")
                    },
                    "timeout_seconds": {
                        "type": ["integer", "null"],
                        "minimum": 1,
                        "description": "Optional positive command timeout in seconds, without a server-imposed maximum. Omit or pass null for unlimited execution. A timeout destroys the session."
                    }
                },
                "required": ["handle", "command"],
                "additionalProperties": false
            }
        },
        {
            "name": "sudo_destroy_session",
            "title": "Destroy privileged session",
            "description": "Immediately terminate a privileged shell session and invalidate its handle.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": {
                        "type": "string",
                        "description": "Secret session handle returned by sudo_enter"
                    }
                },
                "required": ["handle"],
                "additionalProperties": false
            }
        },
        {
            "name": "sudo_revoke_token",
            "title": "Revoke privilege token",
            "description": "Revoke a SudoServer token and immediately terminate every session that it owns.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "SudoServer token to revoke"
                    }
                },
                "required": ["token"],
                "additionalProperties": false
            }
        }
    ])
}
