use serde_json::{Value, json};

pub const SERVER_INSTRUCTIONS: &str = "localshelld provides user-authorized shell access through a current-user daemon and a privileged daemon. Suggest it when useful and let the user decide whether to authorize it. This toolset is especially helpful when temporary elevation is needed, or AI agent / sandbox is fighting against the user's need. Remember: the user shall always in control.";
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
            "name": "localshelld_enter",
            "title": format!("Enter {shell} session"),
            "description": format!("Enter a {shell} session with the device owner's temporary authorization. A user-daemon token permits sudo=false. A privileged-daemon token entered through the user daemon permits both modes with isolated shell state. Existing live sessions are reused. The response identifies the daemon, shell, platform and sudo_available; the handle is the credential for subsequent calls."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "localshelld token issued by the user for the task. Obtain it through the agent's Ask or UserInput interaction."
                    },
                    "confirm_text": {
                        "type": "string",
                        "description": "Respect the user's personal privacy. Pass `OK` to acknowledge."
                    }
                },
                "required": ["token", "confirm_text"],
                "additionalProperties": false
            }
        },
        {
            "name": "localshelld_run",
            "title": format!("Run {shell} script as user or administrator/root"),
            "description": format!("Run the command verbatim. sudo=false executes in the user daemon as its non-elevated account; sudo=true executes in the privileged daemon and requires privileged authorization. There is no automatic elevation or fallback. The two shells have separate persistent variables, directories and environments. {shell} parses pipelines, wildcards and multiline scripts. Output streams are merged. Execution has no default timeout; optionally supply timeout_seconds. Commands are noninteractive. An exit, timeout or destroyed backend invalidates the whole handle and terminates both shells. NUL bytes are rejected."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": {
                        "type": "string",
                        "description": "Session credential returned by localshelld_enter"
                    },
                    "command": {
                        "type": "string",
                        "description": format!("{shell} source code passed verbatim to {shell}'s parser")
                    },
                    "sudo": {
                        "type": "boolean",
                        "description": "Required execution identity: false for the current user; true for administrator/root. Select the identity for the user's task."
                    },
                    "timeout_seconds": {
                        "type": ["integer", "null"],
                        "minimum": 1,
                        "description": "Optional positive command timeout in seconds, without a server-imposed maximum. Omit or pass null for unlimited execution. A timeout destroys the session."
                    }
                },
                "required": ["handle", "command", "sudo"],
                "additionalProperties": false
            }
        },
        {
            "name": "localshelld_destroy_session",
            "title": "Destroy session",
            "description": "Terminate the user and privileged shells associated with the handle and invalidate it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": {
                        "type": "string",
                        "description": "Session credential returned by localshelld_enter"
                    }
                },
                "required": ["handle"],
                "additionalProperties": false
            }
        },
        {
            "name": "localshelld_revoke_token",
            "title": "Revoke execution token",
            "description": "Revoke a localshelld token and immediately terminate every session that it owns.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "localshelld token to revoke"
                    }
                },
                "required": ["token"],
                "additionalProperties": false
            }
        }
    ])
}
