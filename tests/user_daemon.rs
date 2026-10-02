//! Exercise the actual CLI process and its inherited OS identity, not just AppState.
use std::{
    io::Write,
    process::{Child, Command, Stdio},
    time::Duration,
};

use localshelld::config::Config;
use serde_json::{Value, json};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cli() -> Command {
    let command = Command::new(env!("CARGO_BIN_EXE_localshelld"));
    #[cfg(windows)]
    let command = {
        use std::os::windows::process::CommandExt;
        let mut command = command;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        command
    };
    command
}

#[tokio::test]
async fn actual_user_daemon_executes_as_current_user_without_root_backend() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("user/config.toml");
    let mut init = cli()
        .args(["init", "--user", "--password-stdin", "--config"])
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    init.stdin
        .take()
        .unwrap()
        .write_all(b"localshelld integration test password\n")
        .unwrap();
    let initialized = init.wait_with_output().unwrap();
    if !initialized.status.success() {
        // Elevated CI runners must refuse user mode, never silently treat it as
        // an unprivileged server. Unix CI separately tests both real identities.
        let error = String::from_utf8_lossy(&initialized.stderr);
        assert!(error.contains("non-elevated"), "user init failed: {error}");
        let serve = cli()
            .args(["serve", "--user", "--config"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(!serve.status.success());
        assert!(String::from_utf8_lossy(&serve.stderr).contains("non-elevated"));
        return;
    }
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    let mut config = Config::load(&path).unwrap();
    config.bind = address;
    config.privileged_daemon = "127.0.0.1:0".parse().unwrap();
    config.save(&path).unwrap();
    drop(reservation);
    let mut daemon = Daemon(
        cli()
            .args(["serve", "--user", "--config"])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let base = format!("http://{address}");
    let health: Value = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            assert!(daemon.0.try_wait().unwrap().is_none(), "user daemon exited");
            if let Ok(response) = client.get(format!("{base}/health")).send().await {
                break response.json().await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(health["daemon"], "user");
    let page = client
        .get(format!("{base}/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("当前用户权限（不含管理员/root）"));
    let issued: Value = client.post(format!("{base}/v1/admin/tokens/issue")).json(&json!({"credential":{"type":"password", "value":"localshelld integration test password"}}))
        .send().await.unwrap().json().await.unwrap();
    assert!(issued["warning"].as_str().unwrap().contains("sudo=false"));
    let entered: Value = client
        .post(format!("{base}/v1/sessions/enter"))
        .json(&json!({"token":issued["token"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(entered["sudo_available"], false);
    let handle = entered["handle"].as_str().unwrap();
    let result: Value = client
        .post(format!("{base}/v1/commands/run"))
        .json(&json!({"handle":handle,"command":"whoami","sudo":false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let expected = Command::new("whoami").output().unwrap();
    assert!(expected.status.success());
    assert_eq!(
        result["output"].as_str().unwrap().trim(),
        String::from_utf8_lossy(&expected.stdout).trim()
    );
    let denied = client
        .post(format!("{base}/v1/commands/run"))
        .json(&json!({"handle":handle,"command":"whoami","sudo":true}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);
    client
        .post(format!("{base}/v1/sessions/destroy"))
        .json(&json!({"handle":handle}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
}
