use super::*;
use serde_json::{Value, json};

fn command<'a>(windows: &'a str, bash: &'a str) -> &'a str {
    if cfg!(windows) { windows } else { bash }
}

async fn pair() -> (
    AppState,
    AppState,
    String,
    String,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut root_auth = AuthManager::new("unused".into(), None);
    let (root_token, _) = root_auth.issue_token(None).unwrap();
    let root = AppState::new(
        Config {
            bind: address,
            ..Config::default()
        },
        root_auth,
    );
    let app = router(root.clone());
    let serving = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut user_auth = AuthManager::new("unused".into(), None);
    let (user_token, _) = user_auth.issue_token(None).unwrap();
    let user = AppState::user(
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            privileged_daemon: address,
            ..Config::default()
        },
        user_auth,
    )
    .unwrap();
    (root, user, root_token, user_token, serving)
}

#[tokio::test]
async fn routes_explicit_sudo_and_isolates_persistent_shell_state() {
    let (root, user, root_token, user_token, serving) = pair().await;
    let local = user.enter(&user_token).await.unwrap();
    assert!(!local.sudo_available);
    assert_eq!(local.daemon, DaemonMode::User);
    assert_eq!(user.enter(&user_token).await.unwrap().handle, local.handle);
    assert_eq!(
        user.run(&local.handle, "echo rejected", true, None)
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert!(
        user.run(&local.handle, "echo local-only", false, None)
            .await
            .unwrap()
            .output
            .contains("local-only")
    );
    let entered = user.enter(&root_token).await.unwrap();
    assert!(entered.sudo_available);
    assert_eq!(
        user.enter(&root_token).await.unwrap().handle,
        entered.handle
    );
    let direct = root.enter(&root_token).await.unwrap();
    assert_eq!(
        root.run(&direct.handle, "echo rejected", false, None)
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    for (sudo, marker) in [(false, "user"), (true, "root")] {
        let script = if cfg!(windows) {
            format!("$scopeMarker='{marker}'; $scopeMarker")
        } else {
            format!("scopeMarker='{marker}'; echo $scopeMarker")
        };
        assert_eq!(
            user.run(&entered.handle, &script, sudo, None)
                .await
                .unwrap()
                .output
                .trim(),
            marker
        );
    }
    for (sudo, marker) in [(false, "user"), (true, "root")] {
        assert_eq!(
            user.run(
                &entered.handle,
                command("$scopeMarker", "echo $scopeMarker"),
                sudo,
                None
            )
            .await
            .unwrap()
            .output
            .trim(),
            marker
        );
    }
    // Ordinary work remains available without the privileged daemon.
    root.shutdown().await;
    serving.abort();
    assert!(
        user.run(&local.handle, "echo standalone", false, None)
            .await
            .unwrap()
            .output
            .contains("standalone")
    );
    user.shutdown().await;
}

#[tokio::test]
async fn revocation_and_daemon_shutdown_cancel_both_backends() {
    for action in [
        "revoke-at-root",
        "revoke-at-user",
        "root-shutdown",
        "user-shutdown",
        "destroy",
    ] {
        let (root, user, token, _, serving) = pair().await;
        let entered = user.enter(&token).await.unwrap();
        let handle = entered.handle;
        let mut running = Vec::new();
        for sudo in [false, true] {
            let user = user.clone();
            let handle = handle.clone();
            running.push(tokio::spawn(async move {
                user.run(
                    &handle,
                    command("Start-Sleep -Seconds 120", "sleep 120"),
                    sudo,
                    None,
                )
                .await
            }));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        match action {
            "revoke-at-root" => root.revoke_token(&token).await.unwrap(),
            "revoke-at-user" => user.revoke_token(&token).await.unwrap(),
            "root-shutdown" => root.shutdown().await,
            "user-shutdown" => user.shutdown().await,
            _ => user.destroy_session(&handle).await.unwrap(),
        }
        for task in running {
            assert!(
                tokio::time::timeout(Duration::from_secs(5), task)
                    .await
                    .expect("backend was not cancelled")
                    .unwrap()
                    .is_err(),
                "{action}"
            );
        }
        assert!(user.run(&handle, "echo never", false, None).await.is_err());
        root.shutdown().await;
        user.shutdown().await;
        serving.abort();
    }
}

#[tokio::test]
async fn root_loss_expiry_and_shell_exit_invalidate_linked_user_session() {
    let (root, user, token, _, serving) = pair().await;
    let first = user.enter(&token).await.unwrap();
    let exited = user.run(&first.handle, "exit 7", true, None).await.unwrap();
    assert!(exited.session_ended);
    assert_eq!(exited.exit_code, 7);
    assert!(
        user.run(&first.handle, "echo never", false, None)
            .await
            .is_err()
    );
    let expiring = root.auth.lock().await.issue_token(Some(1)).unwrap().0;
    let second = user.enter(&expiring).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !user
                .sessions
                .lock()
                .await
                .by_handle
                .contains_key(&second.handle)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("expiry did not close the linked session");
    // A backend disappearing must not fall back to executing as another identity.
    let third = user.enter(&token).await.unwrap();
    root.shutdown().await;
    serving.abort();
    assert!(
        user.run(&third.handle, "echo never", true, None)
            .await
            .is_err()
    );
    assert!(
        user.run(&third.handle, "echo never", false, None)
            .await
            .is_err()
    );
    user.shutdown().await;
}

#[tokio::test]
async fn http_and_mcp_require_boolean_sudo_and_only_expose_new_names() {
    let (root, user, _, token, serving) = pair().await;
    let app = router(user.clone());
    let (_, rpc) = super::tests::request(
        &app,
        "/mcp",
        json!({"jsonrpc":"2.0", "id":1, "method":"tools/list"}),
    )
    .await;
    let names: Vec<_> = rpc["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "localshelld_enter",
            "localshelld_run",
            "localshelld_destroy_session",
            "localshelld_revoke_token"
        ]
    );
    let (_, rpc) = super::tests::request(&app, "/mcp", json!({"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{"name":"localshelld_enter", "arguments":{"token":token, "confirm_text":"OK"}}})).await;
    let handle = rpc["result"]["structuredContent"]["handle"]
        .as_str()
        .unwrap();
    for invalid in [
        None,
        Some(Value::Null),
        Some(json!("false")),
        Some(json!(0)),
    ] {
        let mut args = json!({"handle": handle, "command":"echo never"});
        if let Some(value) = invalid {
            args["sudo"] = value;
        }
        let (_, rpc) = super::tests::request(&app, "/mcp", json!({"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{"name":"localshelld_run", "arguments":args}})).await;
        assert!(rpc.get("error").is_some());
        let (status, _) = super::tests::request(&app, "/v1/commands/run", args).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    let (_, rpc) = super::tests::request(&app, "/mcp", json!({"jsonrpc":"2.0", "id":4, "method":"tools/call", "params":{"name":"localshelld_run", "arguments":{"handle":handle, "command":"echo ordinary", "sudo":false}}})).await;
    assert!(
        rpc["result"]["structuredContent"]["output"]
            .as_str()
            .unwrap()
            .contains("ordinary")
    );
    user.shutdown().await;
    root.shutdown().await;
    serving.abort();
}

#[tokio::test]
async fn either_backend_timeout_closes_the_entire_handle() {
    for sudo in [false, true] {
        let (root, user, token, _, serving) = pair().await;
        let entered = user.enter(&token).await.unwrap();
        let error = user
            .run(
                &entered.handle,
                command("Start-Sleep -Seconds 120", "sleep 120"),
                sudo,
                Some(1),
            )
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::REQUEST_TIMEOUT);
        assert!(
            user.run(&entered.handle, "echo never", !sudo, None)
                .await
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if root.sessions.lock().await.by_handle.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("timed-out user shell left the privileged shell alive");
        user.shutdown().await;
        root.shutdown().await;
        serving.abort();
    }
}
