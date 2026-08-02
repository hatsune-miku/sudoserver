use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::server::{ApiError, AppState};

#[derive(Deserialize)]
pub struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

pub async fn handle(
    State(state): State<AppState>,
    Json(request): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let Some(id) = request.id.clone() else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let result = dispatch(&state, &request.method, request.params).await;
    let response = match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32602, "message": error.to_string() }
        }),
    };
    Json(response).into_response()
}

async fn dispatch(state: &AppState, method: &str, params: Value) -> Result<Value, ApiError> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": { "name": "SudoServer", "version": env!("CARGO_PKG_VERSION") },
            "instructions": "Every tool can make unrestricted administrator/root changes. Never ask for a Master Password or TOTP. Ask the user for a JWT and ensure they understand the authority they are granting."
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => call_tool(state, params).await,
        _ => Err(ApiError::bad_request(format!(
            "unknown MCP method: {method}"
        ))),
    }
}

async fn call_tool(state: &AppState, params: Value) -> Result<Value, ApiError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("missing tool name"))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    match name {
        "sudo_enter" => {
            let token = string_arg(&arguments, "token")?;
            let result = state.enter(token).await?;
            tool_json(
                serde_json::to_value(result)
                    .map_err(|_| ApiError::internal("serialization failed"))?,
            )
        }
        "sudo_run" => {
            let handle = string_arg(&arguments, "handle")?;
            let command = string_arg(&arguments, "command")?;
            let timeout = arguments.get("timeout_seconds").and_then(Value::as_u64);
            let result = state.run(handle, command, timeout).await?;
            tool_json(
                serde_json::to_value(result)
                    .map_err(|_| ApiError::internal("serialization failed"))?,
            )
        }
        "sudo_destroy_session" => {
            state
                .destroy_session(string_arg(&arguments, "handle")?)
                .await?;
            tool_json(json!({ "destroyed": true }))
        }
        "sudo_revoke_token" => {
            state.revoke_token(string_arg(&arguments, "token")?).await?;
            tool_json(json!({ "revoked": true }))
        }
        _ => Err(ApiError::bad_request(format!("unknown tool: {name}"))),
    }
}

fn string_arg<'a>(arguments: &'a Value, name: &str) -> Result<&'a str, ApiError> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request(format!("missing string argument: {name}")))
}

fn tool_json(value: Value) -> Result<Value, ApiError> {
    Ok(json!({
        "content": [{ "type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_default() }],
        "structuredContent": value,
        "isError": false
    }))
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "sudo_enter",
            "title": "Enter privileged session",
            "description": "Enter an unrestricted administrator/root PowerShell session using a JWT personally issued by the user. Never ask for the Master Password or dynamic Master Password. If this token already owns a live session, the existing strong-password handle is returned and reused; otherwise a new session is created.",
            "inputSchema": {
                "type": "object",
                "properties": { "token": { "type": "string", "description": "JWT supplied by the user via the agent's Ask/user-input tool" } },
                "required": ["token"], "additionalProperties": false
            }
        },
        {
            "name": "sudo_run",
            "title": "Run privileged PowerShell",
            "description": "Run the command verbatim in the persistent privileged PowerShell session. PowerShell itself parses pipelines, wildcards, multiline scripts and environment variables. State, current directory and environment persist between calls. Output streams are merged in PowerShell order.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "handle": { "type": "string", "description": "Secret session handle returned by sudo_enter" },
                    "command": { "type": "string", "description": "PowerShell source code, passed verbatim to PowerShell's parser" },
                    "timeout_seconds": { "type": "integer", "minimum": 1 }
                },
                "required": ["handle", "command"], "additionalProperties": false
            }
        },
        {
            "name": "sudo_destroy_session",
            "title": "Destroy privileged session",
            "description": "Immediately terminate a privileged PowerShell session and invalidate its handle.",
            "inputSchema": {
                "type": "object", "properties": { "handle": { "type": "string" } },
                "required": ["handle"], "additionalProperties": false
            }
        },
        {
            "name": "sudo_revoke_token",
            "title": "Revoke privilege token",
            "description": "Revoke a JWT and immediately terminate every session that it owns.",
            "inputSchema": {
                "type": "object", "properties": { "token": { "type": "string" } },
                "required": ["token"], "additionalProperties": false
            }
        }
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_all_required_tools_and_safety_language() {
        let definitions = tool_definitions();
        let text = definitions.to_string();
        for tool in [
            "sudo_enter",
            "sudo_run",
            "sudo_destroy_session",
            "sudo_revoke_token",
        ] {
            assert!(text.contains(tool));
        }
        assert!(text.contains("Never ask for the Master Password"));
        assert!(text.contains("reused"));
    }
}
