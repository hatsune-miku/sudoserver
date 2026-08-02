use std::{collections::HashMap, sync::Arc};

use axum::{
    Json, Router,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{
    auth::{AuthError, AuthManager, Credential, DEFAULT_TOKEN_TTL_SECONDS, TokenRecord},
    config::Config,
    mcp,
    shell::{ExecutionResult, PowerShell, ShellError},
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    auth: Arc<Mutex<AuthManager>>,
    sessions: Arc<Mutex<SessionStore>>,
}

struct Session {
    token_jti: String,
    expires_at: Option<i64>,
    shell: Arc<Mutex<PowerShell>>,
}

#[derive(Default)]
struct SessionStore {
    by_handle: HashMap<String, Session>,
    by_token: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct EnterResult {
    pub handle: String,
    pub reused: bool,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> Self {
        let status = match error {
            AuthError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AuthError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        };
        Self {
            status,
            message: error.to_string(),
        }
    }
}

impl From<ShellError> for ApiError {
    fn from(error: ShellError) -> Self {
        let status = match error {
            ShellError::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            status,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

impl AppState {
    pub fn new(config: Config, auth: AuthManager) -> Self {
        Self {
            config: Arc::new(config),
            auth: Arc::new(Mutex::new(auth)),
            sessions: Arc::new(Mutex::new(SessionStore::default())),
        }
    }

    pub async fn enter(&self, token: &str) -> Result<EnterResult, ApiError> {
        let claims = self.auth.lock().await.verify_token(token)?;
        let mut sessions = self.sessions.lock().await;
        if let Some(handle) = sessions.by_token.get(&claims.jti).cloned()
            && sessions.by_handle.contains_key(&handle)
        {
            return Ok(EnterResult {
                handle,
                reused: true,
                message: "Reused the token's existing privileged session.".into(),
            });
        }
        let shell = PowerShell::spawn(&self.config.shell, self.config.max_output_bytes).await?;
        let handle = strong_handle();
        sessions.by_token.insert(claims.jti.clone(), handle.clone());
        sessions.by_handle.insert(
            handle.clone(),
            Session {
                token_jti: claims.jti,
                expires_at: claims.exp,
                shell: Arc::new(Mutex::new(shell)),
            },
        );
        Ok(EnterResult {
            handle,
            reused: false,
            message: "Created a new privileged PowerShell session. Treat the handle as a password."
                .into(),
        })
    }

    pub async fn run(
        &self,
        handle: &str,
        command: &str,
        requested_timeout: Option<u64>,
    ) -> Result<ExecutionResult, ApiError> {
        let timeout = requested_timeout.unwrap_or(self.config.max_command_seconds);
        if timeout == 0 || timeout > self.config.max_command_seconds {
            return Err(ApiError::bad_request(format!(
                "timeout_seconds must be between 1 and {}",
                self.config.max_command_seconds
            )));
        }
        let shell = {
            let mut sessions = self.sessions.lock().await;
            let expired = sessions
                .by_handle
                .get(handle)
                .and_then(|session| session.expires_at)
                .is_some_and(|expiry| Utc::now().timestamp() >= expiry);
            if expired {
                remove_session(&mut sessions, handle);
                return Err(AuthError::Expired.into());
            }
            sessions
                .by_handle
                .get(handle)
                .map(|session| Arc::clone(&session.shell))
                .ok_or_else(|| ApiError::from(AuthError::InvalidCredential))?
        };
        let result = shell.lock().await.execute(command, timeout).await;
        if result.is_err() {
            let mut sessions = self.sessions.lock().await;
            remove_session(&mut sessions, handle);
        }
        result.map_err(Into::into)
    }

    pub async fn destroy_session(&self, handle: &str) -> Result<(), ApiError> {
        let shell = {
            let mut sessions = self.sessions.lock().await;
            remove_session(&mut sessions, handle)
                .ok_or_else(|| ApiError::from(AuthError::InvalidCredential))?
        };
        shell.lock().await.terminate().await;
        Ok(())
    }

    pub async fn revoke_token(&self, token: &str) -> Result<(), ApiError> {
        let jti = {
            let mut auth = self.auth.lock().await;
            let claims = auth.token_identity(token)?;
            auth.revoke(&claims.jti)?;
            claims.jti
        };
        self.destroy_sessions_for_token(&jti).await;
        Ok(())
    }

    async fn destroy_sessions_for_token(&self, jti: &str) {
        let shells = {
            let mut sessions = self.sessions.lock().await;
            let handles: Vec<_> = sessions
                .by_handle
                .iter()
                .filter(|(_, session)| session.token_jti == jti)
                .map(|(handle, _)| handle.clone())
                .collect();
            handles
                .into_iter()
                .filter_map(|handle| remove_session(&mut sessions, &handle))
                .collect::<Vec<_>>()
        };
        for shell in shells {
            shell.lock().await.terminate().await;
        }
    }

    async fn authenticate(&self, credential: &Credential) -> Result<(), ApiError> {
        self.auth.lock().await.verify_credential(credential)?;
        Ok(())
    }
}

fn remove_session(store: &mut SessionStore, handle: &str) -> Option<Arc<Mutex<PowerShell>>> {
    let session = store.by_handle.remove(handle)?;
    store.by_token.remove(&session.token_jti);
    Some(session.shell)
}

fn strong_handle() -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

#[derive(Deserialize)]
struct RunBody {
    handle: String,
    command: String,
    timeout_seconds: Option<u64>,
}

#[derive(Deserialize)]
struct HandleBody {
    handle: String,
}

#[derive(Deserialize)]
struct IssueBody {
    credential: Credential,
    ttl_seconds: Option<u64>,
    #[serde(default)]
    permanent: bool,
}

#[derive(Serialize)]
struct IssueResponse {
    token: String,
    record: TokenRecord,
    warning: &'static str,
}

#[derive(Deserialize)]
struct AdminListBody {
    credential: Credential,
}

#[derive(Deserialize)]
struct AdminRevokeBody {
    credential: Credential,
    jti: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/v1/sessions/enter", post(enter))
        .route("/v1/commands/run", post(run))
        .route("/v1/sessions/destroy", post(destroy))
        .route("/v1/tokens/revoke", post(revoke))
        .route("/v1/admin/tokens/issue", post(issue))
        .route("/v1/admin/tokens/list", post(list_tokens))
        .route("/v1/admin/tokens/revoke", post(admin_revoke))
        .route("/mcp", post(mcp::handle))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("ui.html"))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "SudoServer" }))
}

async fn enter(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<TokenBody>,
) -> Result<Json<EnterResult>, ApiError> {
    Ok(Json(state.enter(&body.token).await?))
}

async fn run(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<RunBody>,
) -> Result<Json<ExecutionResult>, ApiError> {
    Ok(Json(
        state
            .run(&body.handle, &body.command, body.timeout_seconds)
            .await?,
    ))
}

async fn destroy(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<HandleBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.destroy_session(&body.handle).await?;
    Ok(Json(serde_json::json!({ "destroyed": true })))
}

async fn revoke(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<TokenBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.revoke_token(&body.token).await?;
    Ok(Json(serde_json::json!({ "revoked": true })))
}

async fn issue(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<IssueBody>,
) -> Result<Json<IssueResponse>, ApiError> {
    state.authenticate(&body.credential).await?;
    let ttl = if body.permanent {
        None
    } else {
        Some(body.ttl_seconds.unwrap_or(DEFAULT_TOKEN_TTL_SECONDS))
    };
    if ttl == Some(0) {
        return Err(ApiError::bad_request(
            "ttl_seconds must be greater than zero",
        ));
    }
    let (token, record) = state.auth.lock().await.issue_token(ttl)?;
    Ok(Json(IssueResponse {
        token,
        record,
        warning: "This token grants full administrator/root command execution. It naturally becomes invalid when SudoServer restarts.",
    }))
}

async fn list_tokens(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<AdminListBody>,
) -> Result<Json<Vec<TokenRecord>>, ApiError> {
    state.authenticate(&body.credential).await?;
    let records = state.auth.lock().await.list();
    Ok(Json(records))
}

async fn admin_revoke(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<AdminRevokeBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.authenticate(&body.credential).await?;
    state.auth.lock().await.revoke(&body.jti)?;
    state.destroy_sessions_for_token(&body.jti).await;
    Ok(Json(serde_json::json!({ "revoked": true })))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;
    use crate::auth::hash_password;

    async fn request(app: &Router, path: &str, body: Value) -> (StatusCode, Value) {
        let response = app
            .clone()
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, body)
    }

    fn test_app() -> Router {
        let config = Config {
            password_hash: hash_password(b"test master password").unwrap(),
            max_command_seconds: 10,
            ..Config::default()
        };
        let auth = AuthManager::new(config.password_hash.clone(), None);
        router(AppState::new(config, auth))
    }

    #[tokio::test]
    async fn full_http_lifecycle_reuses_session_and_revokes_access() {
        if PowerShell::spawn("pwsh", 1024).await.is_err() {
            return;
        }
        let app = test_app();
        let credential = json!({ "type": "password", "value": "test master password" });
        let (status, issued) = request(
            &app,
            "/v1/admin/tokens/issue",
            json!({ "credential": credential, "ttl_seconds": 120 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = issued["token"].as_str().unwrap();

        let (_, first) = request(&app, "/v1/sessions/enter", json!({ "token": token })).await;
        let (_, second) = request(&app, "/v1/sessions/enter", json!({ "token": token })).await;
        assert_eq!(first["handle"], second["handle"]);
        assert_eq!(first["reused"], false);
        assert_eq!(second["reused"], true);
        assert!(first["handle"].as_str().unwrap().len() >= 40);

        let handle = first["handle"].as_str().unwrap();
        let (status, result) = request(
            &app,
            "/v1/commands/run",
            json!({ "handle": handle, "command": "$global:httpState=40+2; $global:httpState" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(result["output"].as_str().unwrap().contains("42"));

        let (status, _) = request(&app, "/v1/tokens/revoke", json!({ "token": token })).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = request(
            &app,
            "/v1/commands/run",
            json!({ "handle": handle, "command": "'should not run'" }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = request(&app, "/v1/sessions/enter", json!({ "token": token })).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_invalid_timeout_and_credentials() {
        let app = test_app();
        let (status, _) = request(
            &app,
            "/v1/admin/tokens/issue",
            json!({
                "credential": { "type": "password", "value": "wrong password" },
                "ttl_seconds": 0
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
