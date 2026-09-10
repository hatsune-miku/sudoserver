use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    mcp_text::{
        MISSING_TOOL_NAME, SERIALIZATION_FAILED, SERVER_INSTRUCTIONS, missing_string_argument,
        tool_definitions, unknown_method, unknown_tool,
    },
    server::{ApiError, AppState},
};

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
            "instructions": SERVER_INSTRUCTIONS
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => call_tool(state, params).await,
        _ => Err(ApiError::bad_request(unknown_method(method))),
    }
}

async fn call_tool(state: &AppState, params: Value) -> Result<Value, ApiError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request(MISSING_TOOL_NAME))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    match name {
        "sudo_enter" => {
            let token = string_arg(&arguments, "token")?;
            let confirm_text = string_arg(&arguments, "confirm_text")?;
            if confirm_text != "OK" {
                return Err(ApiError::bad_request(missing_string_argument(
                    "confirm_text",
                )));
            }

            let result = state.enter(token).await?;
            tool_json(
                serde_json::to_value(result)
                    .map_err(|_| ApiError::internal(SERIALIZATION_FAILED))?,
            )
        }
        "sudo_run" => {
            let handle = string_arg(&arguments, "handle")?;
            let command = string_arg(&arguments, "command")?;
            let timeout = arguments.get("timeout_seconds").and_then(Value::as_u64);
            let result = state.run(handle, command, timeout).await?;
            tool_json(
                serde_json::to_value(result)
                    .map_err(|_| ApiError::internal(SERIALIZATION_FAILED))?,
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
        _ => Err(ApiError::bad_request(unknown_tool(name))),
    }
}

fn string_arg<'a>(arguments: &'a Value, name: &str) -> Result<&'a str, ApiError> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request(missing_string_argument(name)))
}

fn tool_json(value: Value) -> Result<Value, ApiError> {
    Ok(json!({
        "content": [{ "type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_default() }],
        "structuredContent": value,
        "isError": false
    }))
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
        assert!(SERVER_INSTRUCTIONS.contains("arbitrary code execution"));
        assert!(text.contains("With great power comes great responsibility"));
        assert!(text.contains("reused"));
    }
}
