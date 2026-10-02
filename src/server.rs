use std::{collections::HashMap, sync::Arc, time::Duration};

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
    peer::Peer,
    shell::{ExecutionResult, Shell, ShellError, ShellKind},
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub mode: DaemonMode,
    peer: Option<Peer>,
    auth: Arc<Mutex<AuthManager>>,
    sessions: Arc<Mutex<SessionStore>>,
}

struct Session {
    token_id: String,
    expires_at: Option<i64>,
    shell: Arc<Shell>,
    remote_handle: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DaemonMode {
    User,
    Privileged,
}

#[derive(Default)]
struct SessionStore {
    shutting_down: bool,
    by_handle: HashMap<String, Session>,
    by_token: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct EnterResult {
    pub handle: String,
    pub reused: bool,
    pub shell: ShellKind,
    pub platform: &'static str,
    pub daemon: DaemonMode,
    pub sudo_available: bool,
    pub expires_at: Option<i64>,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    pub(crate) fn peer(status: StatusCode) -> Self {
        Self {
            status,
            message: format!("privileged daemon rejected the request ({status})"),
        }
    }
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
            ShellError::Rejected(_) => StatusCode::BAD_REQUEST,
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
            mode: DaemonMode::Privileged,
            peer: None,
            config: Arc::new(config),
            auth: Arc::new(Mutex::new(auth)),
            sessions: Arc::new(Mutex::new(SessionStore::default())),
        }
    }

    pub fn user(config: Config, auth: AuthManager) -> Result<Self, ApiError> {
        if config.bind == config.privileged_daemon {
            return Err(ApiError::bad_request(
                "user and privileged daemon addresses must differ",
            ));
        }
        let peer = Peer::new(config.privileged_daemon, config.max_output_bytes)?;
        let mut state = Self::new(config, auth);
        state.mode = DaemonMode::User;
        state.peer = Some(peer);
        Ok(state)
    }

    pub async fn enter(&self, token: &str) -> Result<EnterResult, ApiError> {
        // Known local tokens (including expired/revoked ones) never fall back to
        // a different authority. A user token cannot acquire privileged access.
        if self.mode == DaemonMode::User && self.auth.lock().await.token_identity(token).is_err() {
            return self.enter_remote(token).await;
        }
        // Keep authorization and insertion atomic with respect to token revocation.
        let auth = self.auth.lock().await;
        let authorization = auth.verify_token(token)?;
        let mut sessions = self.sessions.lock().await;
        if sessions.shutting_down {
            return Err(ApiError::internal("server is shutting down"));
        }
        if let Some(handle) = sessions.by_token.get(&authorization.id).cloned() {
            if sessions
                .by_handle
                .get(&handle)
                .is_some_and(|session| !session.shell.is_finished())
            {
                return Ok(EnterResult {
                    handle,
                    reused: true,
                    shell: ShellKind::native(),
                    platform: std::env::consts::OS,
                    daemon: self.mode,
                    sudo_available: self.mode == DaemonMode::Privileged,
                    expires_at: authorization.expires_at,
                    message: "Reused the token's existing session.".into(),
                });
            }
            remove_session(&mut sessions, &handle);
        }
        let shell = Shell::spawn(&self.config.shell, self.config.max_output_bytes).await?;
        let handle = strong_handle();
        sessions
            .by_token
            .insert(authorization.id.clone(), handle.clone());
        sessions.by_handle.insert(
            handle.clone(),
            Session {
                token_id: authorization.id,
                expires_at: authorization.expires_at,
                shell: Arc::new(shell),
                remote_handle: None,
            },
        );
        Ok(EnterResult {
            handle,
            reused: false,
            shell: ShellKind::native(),
            platform: std::env::consts::OS,
            daemon: self.mode,
            sudo_available: self.mode == DaemonMode::Privileged,
            expires_at: authorization.expires_at,
            message: format!(
                "Created a new {} session. Use the handle for subsequent calls.",
                ShellKind::native().name()
            ),
        })
    }

    async fn enter_remote(&self, token: &str) -> Result<EnterResult, ApiError> {
        let peer = self.peer.as_ref().expect("user daemon has a peer");
        let entered = peer.enter(token).await?;
        let key = format!("privileged:{}", entered.handle);
        let mut sessions = self.sessions.lock().await;
        if sessions.shutting_down {
            drop(sessions);
            let _ = peer.destroy(&entered.handle).await;
            return Err(ApiError::internal("server is shutting down"));
        }
        let existing = sessions.by_token.get(&key).cloned();
        if existing.as_ref().is_some_and(|handle| {
            sessions
                .by_handle
                .get(handle)
                .is_none_or(|session| session.shell.is_finished())
        }) {
            return Err(ApiError::unavailable(
                "previous session is closing; enter again after it closes",
            ));
        }
        let reused = existing.is_some();
        let handle = if let Some(handle) = existing {
            handle
        } else {
            let shell = match Shell::spawn(&self.config.shell, self.config.max_output_bytes).await {
                Ok(shell) => Arc::new(shell),
                Err(error) => {
                    drop(sessions);
                    let _ = peer.destroy(&entered.handle).await;
                    return Err(error.into());
                }
            };
            let handle = strong_handle();
            sessions.by_token.insert(key.clone(), handle.clone());
            sessions.by_handle.insert(
                handle.clone(),
                Session {
                    token_id: key,
                    expires_at: entered.expires_at,
                    shell: Arc::clone(&shell),
                    remote_handle: Some(entered.handle.clone()),
                },
            );
            // A bounded long poll propagates revocation, shutdown and loss of the
            // privileged authority to the user shell, including running commands.
            let state = self.clone();
            let watched_handle = handle.clone();
            let remote = entered.handle;
            let peer = peer.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = shell.wait_ended() => break,
                        result = peer.validate(&remote, true) => if result.is_err() { break; },
                    }
                }
                remove_session(&mut *state.sessions.lock().await, &watched_handle);
                shell.terminate().await;
                let _ = peer.destroy(&remote).await;
            });
            handle
        };
        Ok(EnterResult {
            handle, reused, shell: ShellKind::native(), platform: std::env::consts::OS,
            daemon: self.mode, sudo_available: true, expires_at: entered.expires_at,
            message: "User and privileged shells have separate state. Set sudo explicitly for every command.".into(),
        })
    }

    pub async fn run(
        &self,
        handle: &str,
        command: &str,
        sudo: bool,
        requested_timeout: Option<u64>,
    ) -> Result<ExecutionResult, ApiError> {
        if requested_timeout == Some(0) {
            return Err(ApiError::bad_request(
                "timeout_seconds must be greater than zero",
            ));
        }
        if self.mode == DaemonMode::Privileged && !sudo {
            return Err(ApiError::forbidden(
                "sudo=false requires the user daemon; connect to its MCP endpoint",
            ));
        }
        let (shell, remote) = {
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
                .map(|session| (Arc::clone(&session.shell), session.remote_handle.clone()))
                .ok_or_else(|| ApiError::from(AuthError::InvalidCredential))?
        };
        if let Some(remote) = &remote {
            let peer = self.peer.as_ref().expect("remote session has a peer");
            if sudo {
                let result = peer.run(remote, command, requested_timeout).await;
                if result.as_ref().map_or_else(
                    |error| error.status != StatusCode::BAD_REQUEST,
                    |result| result.session_ended,
                ) {
                    let _ = self.destroy_session(handle).await;
                }
                return result;
            }
            if let Err(error) = peer.validate(remote, false).await {
                let _ = self.destroy_session(handle).await;
                return Err(error);
            }
        } else if sudo && self.mode == DaemonMode::User {
            return Err(ApiError::forbidden(
                "this user token does not authorize sudo=true; enter with a user-issued privileged daemon token",
            ));
        }
        let result = shell.execute(command, requested_timeout).await;
        // A rejected command leaves the session healthy; any other error, or a
        // command that ended the shell, invalidates the handle.
        let ended = match &result {
            Ok(execution) => execution.session_ended,
            Err(ShellError::Rejected(_)) => false,
            Err(_) => true,
        };
        if ended {
            let mut sessions = self.sessions.lock().await;
            remove_session(&mut sessions, handle);
        }
        result.map_err(Into::into)
    }

    pub async fn destroy_session(&self, handle: &str) -> Result<(), ApiError> {
        let (shell, remote) = {
            let mut sessions = self.sessions.lock().await;
            let remote = sessions
                .by_handle
                .get(handle)
                .and_then(|s| s.remote_handle.clone());
            let shell = remove_session(&mut sessions, handle)
                .ok_or_else(|| ApiError::from(AuthError::InvalidCredential))?;
            (shell, remote)
        };
        shell.terminate().await;
        if let (Some(peer), Some(remote)) = (&self.peer, remote) {
            // Removal is idempotent: the monitor may already have closed it.
            if let Err(error) = peer.destroy(&remote).await
                && error.status != StatusCode::UNAUTHORIZED
            {
                return Err(error);
            }
        }
        Ok(())
    }

    pub async fn revoke_token(&self, token: &str) -> Result<(), ApiError> {
        if let Some(peer) = &self.peer
            && self.auth.lock().await.token_identity(token).is_err()
        {
            return peer.revoke(token).await;
        }
        let token_id = {
            let mut auth = self.auth.lock().await;
            let authorization = auth.token_identity(token)?;
            auth.revoke(&authorization.id)?;
            authorization.id
        };
        self.destroy_sessions_for_token(&token_id).await;
        Ok(())
    }

    async fn destroy_sessions_for_token(&self, token_id: &str) {
        let shells = {
            let mut sessions = self.sessions.lock().await;
            let handles: Vec<_> = sessions
                .by_handle
                .iter()
                .filter(|(_, session)| session.token_id == token_id)
                .map(|(handle, _)| handle.clone())
                .collect();
            handles
                .into_iter()
                .filter_map(|handle| remove_session(&mut sessions, &handle))
                .collect::<Vec<_>>()
        };
        for shell in shells {
            shell.terminate().await;
        }
    }

    pub async fn shutdown(&self) {
        let sessions = {
            let mut sessions = self.sessions.lock().await;
            sessions.shutting_down = true;
            sessions.by_token.clear();
            sessions
                .by_handle
                .drain()
                .map(|(_, session)| {
                    session.shell.cancel();
                    session
                })
                .collect::<Vec<_>>()
        };
        for session in sessions {
            session.shell.terminate().await;
            if let (Some(peer), Some(remote)) = (&self.peer, session.remote_handle) {
                let _ = peer.destroy(&remote).await;
            }
        }
    }

    async fn validate_session(&self, handle: &str, watch: bool) -> Result<(), ApiError> {
        if self.mode != DaemonMode::Privileged {
            return Err(ApiError::forbidden(
                "session validation is only served by the privileged daemon",
            ));
        }
        let (shell, expires) = {
            let sessions = self.sessions.lock().await;
            let session = sessions
                .by_handle
                .get(handle)
                .ok_or(AuthError::InvalidCredential)?;
            (Arc::clone(&session.shell), session.expires_at)
        };
        let remaining = expires.map(|expiry| expiry.saturating_sub(Utc::now().timestamp()));
        if remaining.is_some_and(|seconds| seconds <= 0) || shell.is_finished() {
            let _ = self.destroy_session(handle).await;
            return Err(AuthError::Expired.into());
        }
        if watch {
            let wait = remaining.unwrap_or(15).min(15) as u64;
            tokio::select! {
                _ = shell.wait_ended() => return Err(AuthError::InvalidCredential.into()),
                _ = tokio::time::sleep(Duration::from_secs(wait)) => {},
            }
            if expires.is_some_and(|expiry| expiry <= Utc::now().timestamp()) {
                let _ = self.destroy_session(handle).await;
                return Err(AuthError::Expired.into());
            }
        }
        Ok(())
    }

    async fn authenticate(&self, credential: &Credential) -> Result<(), ApiError> {
        self.auth.lock().await.verify_credential(credential)?;
        Ok(())
    }
}

fn remove_session(store: &mut SessionStore, handle: &str) -> Option<Arc<Shell>> {
    let session = store.by_handle.remove(handle)?;
    if store
        .by_token
        .get(&session.token_id)
        .is_some_and(|mapped| mapped == handle)
    {
        store.by_token.remove(&session.token_id);
    }
    session.shell.cancel();
    Some(session.shell)
}

#[cfg(test)]
mod dual_daemon_tests;

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
    sudo: bool,
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
    id: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/v1/sessions/enter", post(enter))
        .route("/v1/commands/run", post(run))
        .route("/v1/sessions/destroy", post(destroy))
        .route("/v1/sessions/validate", post(validate))
        .route("/v1/sessions/watch", post(watch))
        .route("/v1/tokens/revoke", post(revoke))
        .route("/v1/admin/tokens/issue", post(issue))
        .route("/v1/admin/tokens/list", post(list_tokens))
        .route("/v1/admin/tokens/revoke", post(admin_revoke))
        .route("/mcp", post(mcp::handle))
        .with_state(state)
}

async fn index(axum::extract::State(state): axum::extract::State<AppState>) -> Html<String> {
    let text = include_str!("ui.html");
    let scope = if state.mode == DaemonMode::User {
        "当前用户权限（不含管理员/root）"
    } else {
        "管理员/root 权限"
    };
    Html(text.replace("{{AUTHORIZATION_SCOPE}}", scope))
}

async fn health(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<serde_json::Value> {
    Json(
        serde_json::json!({ "status": "ok", "service": "localshelld", "daemon": state.mode, "version": crate::VERSION, "commit": crate::COMMIT }),
    )
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
            .run(&body.handle, &body.command, body.sudo, body.timeout_seconds)
            .await?,
    ))
}

async fn validate(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<HandleBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.validate_session(&body.handle, false).await?;
    Ok(Json(serde_json::json!({"valid": true})))
}

async fn watch(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<HandleBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.validate_session(&body.handle, true).await?;
    Ok(Json(serde_json::json!({"valid": true})))
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
        warning: if state.mode == DaemonMode::User {
            "User-authorized current-user execution (sudo=false). Valid until expiry, revocation or user daemon restart."
        } else {
            "User-authorized administrator/root execution. Valid until expiry, revocation or privileged daemon restart."
        },
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
    state.auth.lock().await.revoke(&body.id)?;
    state.destroy_sessions_for_token(&body.id).await;
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

    pub(super) async fn request(app: &Router, path: &str, body: Value) -> (StatusCode, Value) {
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
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        (status, body)
    }

    fn test_app() -> Router {
        let config = Config {
            password_hash: hash_password(b"test master password").unwrap(),
            ..Config::default()
        };
        let auth = AuthManager::new(config.password_hash.clone(), None);
        router(AppState::new(config, auth))
    }

    #[tokio::test]
    async fn health_exposes_the_embedded_release_identity() {
        let response = test_app()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["version"], crate::VERSION);
        assert_eq!(body["commit"], crate::COMMIT);
    }

    #[tokio::test]
    async fn full_http_lifecycle_reuses_session_and_revokes_access() {
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
        assert_eq!(token.len(), 22);
        assert!(token.bytes().all(|byte| byte.is_ascii_alphanumeric()));

        let (_, first) = request(&app, "/v1/sessions/enter", json!({ "token": token })).await;
        let (_, second) = request(&app, "/v1/sessions/enter", json!({ "token": token })).await;
        assert_eq!(first["handle"], second["handle"]);
        assert_eq!(first["reused"], false);
        assert_eq!(second["reused"], true);
        assert_eq!(
            first["shell"],
            serde_json::to_value(ShellKind::native()).unwrap()
        );
        assert_eq!(first["platform"], std::env::consts::OS);
        assert!(first["handle"].as_str().unwrap().len() >= 40);

        let handle = first["handle"].as_str().unwrap();
        let (status, result) = request(
            &app,
            "/v1/commands/run",
            json!({ "handle": handle, "sudo": true, "command": if cfg!(windows) { "$global:httpState=40+2; $global:httpState" } else { "httpState=$((40+2)); echo $httpState" } }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(result["output"].as_str().unwrap().contains("42"));

        let (status, _) = request(&app, "/v1/tokens/revoke", json!({ "token": token })).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = request(
            &app,
            "/v1/commands/run",
            json!({ "handle": handle, "sudo": true, "command": "'should not run'" }),
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

    #[tokio::test]
    async fn admin_lists_and_revokes_tokens_by_id() {
        let app = test_app();
        let credential = json!({ "type": "password", "value": "test master password" });
        let (status, issued) = request(
            &app,
            "/v1/admin/tokens/issue",
            json!({ "credential": credential.clone(), "ttl_seconds": 120 }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = issued["token"].as_str().unwrap();
        let id = issued["record"]["id"].as_str().unwrap();

        let (status, records) = request(
            &app,
            "/v1/admin/tokens/list",
            json!({ "credential": credential.clone() }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(records[0]["id"], id);
        assert!(records[0].get("token").is_none());

        let (status, _) = request(
            &app,
            "/v1/admin/tokens/revoke",
            json!({ "credential": credential, "id": id }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = request(&app, "/v1/sessions/enter", json!({ "token": token })).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn destroy_revoke_and_shutdown_interrupt_unlimited_commands() {
        for action in ["destroy", "revoke", "shutdown"] {
            let config = Config::default();
            let mut auth = AuthManager::new("unused".into(), None);
            let (token, _) = auth.issue_token(None).unwrap();
            let state = AppState::new(config, auth);
            let entered = state.enter(&token).await.unwrap();
            state
                .run(&entered.handle, "echo ready", true, Some(3600))
                .await
                .unwrap();
            assert!(
                state
                    .run(&entered.handle, "echo invalid", true, Some(0))
                    .await
                    .is_err()
            );
            let executing = {
                let state = state.clone();
                let handle = entered.handle.clone();
                tokio::spawn(async move {
                    state
                        .run(
                            &handle,
                            if cfg!(windows) {
                                "while ($true) { Start-Sleep -Milliseconds 100 }"
                            } else {
                                "while :; do :; done"
                            },
                            true,
                            None,
                        )
                        .await
                })
            };
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                match action {
                    "destroy" => state.destroy_session(&entered.handle).await.unwrap(),
                    "revoke" => state.revoke_token(&token).await.unwrap(),
                    _ => state.shutdown().await,
                }
            })
            .await
            .expect("cancellation waited for unlimited command");
            assert!(executing.await.unwrap().is_err());
            assert!(
                state
                    .run(&entered.handle, "echo never", true, None)
                    .await
                    .is_err()
            );
            if action == "destroy" {
                let recreated = state.enter(&token).await.unwrap();
                assert!(!recreated.reused);
                assert_ne!(recreated.handle, entered.handle);
                state.shutdown().await;
            } else {
                assert!(state.enter(&token).await.is_err());
            }
        }
    }

    #[tokio::test]
    async fn enter_replaces_session_that_ended_after_caller_disconnected() {
        let mut auth = AuthManager::new("unused".into(), None);
        let (token, _) = auth.issue_token(None).unwrap();
        let state = AppState::new(Config::default(), auth);
        let first = state.enter(&token).await.unwrap();
        // Simulate a worker ending after its HTTP caller was dropped, so the
        // request handler cannot remove the session mapping itself.
        let shell = Arc::clone(&state.sessions.lock().await.by_handle[&first.handle].shell);
        shell.terminate().await;
        let second = state.enter(&token).await.unwrap();
        assert!(!second.reused);
        assert_ne!(first.handle, second.handle);
        state.shutdown().await;
    }
}
