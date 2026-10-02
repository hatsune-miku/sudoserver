use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    mcp_text::{
        INVALID_TIMEOUT, MISSING_TOOL_NAME, SERIALIZATION_FAILED, missing_string_argument,
        server_instructions, tool_definitions, unknown_method, unknown_tool,
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
            "serverInfo": { "name": "localshelld", "version": crate::VERSION },
            "instructions": format!("{} Connected daemon: {:?}.", server_instructions(), state.mode)
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
        "localshelld_enter" => {
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
        "localshelld_run" => {
            let handle = string_arg(&arguments, "handle")?;
            let command = string_arg(&arguments, "command")?;
            let sudo = arguments
                .get("sudo")
                .and_then(Value::as_bool)
                .ok_or_else(|| ApiError::bad_request("sudo must be an explicit boolean"))?;
            let timeout = timeout_arg(&arguments)?;
            let result = state.run(handle, command, sudo, timeout).await?;
            tool_json(
                serde_json::to_value(result)
                    .map_err(|_| ApiError::internal(SERIALIZATION_FAILED))?,
            )
        }
        "localshelld_destroy_session" => {
            state
                .destroy_session(string_arg(&arguments, "handle")?)
                .await?;
            tool_json(json!({ "destroyed": true }))
        }
        "localshelld_revoke_token" => {
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

fn timeout_arg(arguments: &Value) -> Result<Option<u64>, ApiError> {
    match arguments.get("timeout_seconds") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|seconds| *seconds > 0)
            .map(Some)
            .ok_or_else(|| ApiError::bad_request(INVALID_TIMEOUT)),
    }
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
    fn exposes_all_required_tools_and_privacy_guidance() {
        let definitions = tool_definitions();
        let text = definitions.to_string();
        for tool in [
            "localshelld_enter",
            "localshelld_run",
            "localshelld_destroy_session",
            "localshelld_revoke_token",
        ] {
            assert!(text.contains(tool));
        }
        assert!(server_instructions().contains("user-authorized shell access"));
        assert!(server_instructions().contains(crate::shell::ShellKind::native().name()));
        assert!(text.contains("Respect the user's personal privacy."));
        assert!(text.contains("reused"));
    }

    #[test]
    fn validates_optional_unbounded_timeout() {
        for value in [json!({}), json!({"timeout_seconds": null})] {
            assert_eq!(timeout_arg(&value).unwrap(), None);
        }
        assert_eq!(
            timeout_arg(&json!({"timeout_seconds": 3600})).unwrap(),
            Some(3600)
        );
        for value in [json!(0), json!(-1), json!(1.5), json!("10"), json!(true)] {
            assert!(timeout_arg(&json!({"timeout_seconds": value})).is_err());
        }
    }
}
