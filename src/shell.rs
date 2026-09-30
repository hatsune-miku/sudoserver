use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use std::{fmt::Write as _, process::Stdio, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{mpsc, oneshot, watch},
    time::{Instant, timeout_at},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ShellKind {
    PowerShell,
    Bash,
}
impl ShellKind {
    pub const fn native() -> Self {
        if cfg!(windows) {
            Self::PowerShell
        } else {
            Self::Bash
        }
    }
    pub const fn name(self) -> &'static str {
        match self {
            Self::PowerShell => "PowerShell",
            Self::Bash => "Bash",
        }
    }
    pub const fn executable(self) -> &'static str {
        match self {
            Self::PowerShell => "pwsh",
            Self::Bash => "/bin/bash",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ExecutionResult {
    pub output: String,
    pub exit_code: i32,
    pub success: bool,
    pub truncated: bool,
}

#[derive(Debug, Error)]
pub enum ShellError {
    #[error("failed to start shell: {0}")]
    Start(#[source] std::io::Error),
    #[error("shell session ended unexpectedly or was destroyed")]
    Ended,
    #[error("shell I/O failed: {0}")]
    Io(#[source] std::io::Error),
    #[error("shell returned an invalid response")]
    InvalidResponse,
    #[error("command exceeded the {0}-second timeout; the session was destroyed")]
    Timeout(u64),
}

struct Request {
    command: String,
    timeout_seconds: Option<u64>,
    reply: oneshot::Sender<Result<ExecutionResult, ShellError>>,
}

/// The worker serializes commands; cancellation never needs the execution lock.
/// A disconnected caller does not abandon a half-read protocol response.
pub struct Shell {
    requests: mpsc::Sender<Request>,
    cancel: watch::Sender<bool>,
    finished: watch::Receiver<bool>,
}
impl Shell {
    pub async fn spawn(executable: &str, max_output_bytes: usize) -> Result<Self, ShellError> {
        Self::spawn_kind(ShellKind::native(), executable, max_output_bytes).await
    }
    async fn spawn_kind(
        kind: ShellKind,
        executable: &str,
        max_output_bytes: usize,
    ) -> Result<Self, ShellError> {
        let mut process = Process::spawn(kind, executable, max_output_bytes)?;
        let (requests, mut receiver) = mpsc::channel::<Request>(16);
        let (cancel, mut cancelled) = watch::channel(false);
        let (done, finished) = watch::channel(false);
        tokio::spawn(async move {
            loop {
                let request = tokio::select! {
                    biased;
                    _ = cancelled.changed() => break,
                    _ = process.child.wait() => break,
                    request = receiver.recv() => match request { Some(r) => r, None => break },
                };
                let result = tokio::select! {
                    biased;
                    _ = cancelled.changed() => Err(ShellError::Ended),
                    result = process.execute(&request.command, request.timeout_seconds) => result,
                };
                let failed = result.is_err();
                if failed {
                    process.terminate().await;
                }
                let _ = request.reply.send(result);
                if failed {
                    break;
                }
            }
            process.terminate().await;
            let _ = done.send(true);
        });
        Ok(Self {
            requests,
            cancel,
            finished,
        })
    }
    pub async fn execute(
        &self,
        command: &str,
        timeout_seconds: Option<u64>,
    ) -> Result<ExecutionResult, ShellError> {
        if self.is_finished() {
            return Err(ShellError::Ended);
        }
        let (reply, response) = oneshot::channel();
        self.requests
            .send(Request {
                command: command.to_owned(),
                timeout_seconds,
                reply,
            })
            .await
            .map_err(|_| ShellError::Ended)?;
        response.await.map_err(|_| ShellError::Ended)?
    }
    pub fn cancel(&self) {
        let _ = self.cancel.send(true);
    }
    pub fn is_finished(&self) -> bool {
        *self.cancel.borrow() || *self.finished.borrow()
    }
    pub async fn terminate(&self) {
        self.cancel();
        let mut finished = self.finished.clone();
        let _ = finished.wait_for(|done| *done).await;
    }
}
impl Drop for Shell {
    fn drop(&mut self) {
        self.cancel();
    }
}

struct Process {
    kind: ShellKind,
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    pending: Vec<u8>,
    max_output_bytes: usize,
}
impl Process {
    fn spawn(
        kind: ShellKind,
        executable: &str,
        max_output_bytes: usize,
    ) -> Result<Self, ShellError> {
        let mut command = Command::new(executable);
        match kind {
            ShellKind::PowerShell => {
                let bytes: Vec<u8> = include_str!("shell/powershell.ps1")
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect();
                command.args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-EncodedCommand",
                    &STANDARD.encode(bytes),
                ]);
            }
            ShellKind::Bash => {
                command.args(["--noprofile", "--norc", "-c", include_str!("shell/bash.sh")]);
                // --norc alone does not suppress noninteractive startup via BASH_ENV.
                for name in ["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "CDPATH"] {
                    command.env_remove(name);
                }
            }
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(ShellError::Start)?;
        let stdin = child.stdin.take().ok_or(ShellError::Ended)?;
        let stdout = child.stdout.take().ok_or(ShellError::Ended)?;
        Ok(Self {
            kind,
            child,
            stdin,
            stdout,
            pending: Vec::new(),
            max_output_bytes,
        })
    }
    async fn execute(
        &mut self,
        command: &str,
        seconds: Option<u64>,
    ) -> Result<ExecutionResult, ShellError> {
        // Avoid clock overflow for very large caller-supplied durations.
        match seconds.and_then(|s| Instant::now().checked_add(Duration::from_secs(s))) {
            Some(deadline) => timeout_at(deadline, self.execute_inner(command))
                .await
                .map_err(|_| ShellError::Timeout(seconds.unwrap()))?,
            None => self.execute_inner(command).await,
        }
    }
    async fn execute_inner(&mut self, command: &str) -> Result<ExecutionResult, ShellError> {
        if self.child.try_wait().map_err(ShellError::Io)?.is_some() {
            return Err(ShellError::Ended);
        }
        let mut random = [0_u8; 18];
        OsRng.fill_bytes(&mut random);
        let marker = STANDARD.encode(random);
        let encoded = match self.kind {
            ShellKind::PowerShell => STANDARD.encode(command.as_bytes()),
            ShellKind::Bash => {
                let mut encoded = String::with_capacity(command.len() * 4);
                for byte in command.bytes() {
                    write!(&mut encoded, "\\{byte:03o}").unwrap();
                }
                encoded
            }
        };
        self.stdin
            .write_all(format!("{marker}|{encoded}\n").as_bytes())
            .await
            .map_err(ShellError::Io)?;
        self.stdin.flush().await.map_err(ShellError::Io)?;
        let needle = format!("\u{001e}{marker}|").into_bytes();
        let mut output = Vec::new();
        let mut truncated = false;
        loop {
            if let Some(start) = self.pending.windows(needle.len()).position(|w| w == needle) {
                append_output(
                    &mut output,
                    &self.pending[..start],
                    self.max_output_bytes,
                    &mut truncated,
                );
                self.pending.drain(..start + needle.len());
                loop {
                    if let Some(end) = self.pending.iter().position(|b| *b == 0x1f) {
                        let exit_code: i32 = std::str::from_utf8(&self.pending[..end])
                            .map_err(|_| ShellError::InvalidResponse)?
                            .parse()
                            .map_err(|_| ShellError::InvalidResponse)?;
                        self.pending.drain(..=end);
                        return Ok(ExecutionResult {
                            output: String::from_utf8_lossy(&output).into_owned(),
                            exit_code,
                            success: exit_code == 0,
                            truncated,
                        });
                    }
                    if self.pending.len() > 12 {
                        return Err(ShellError::InvalidResponse);
                    }
                    self.read_more().await?;
                }
            }
            // Retain only a possible partial delimiter. Drain excess output even
            // after truncation so the next command starts at a frame boundary.
            let count = self.pending.len().saturating_sub(needle.len() - 1);
            append_output(
                &mut output,
                &self.pending[..count],
                self.max_output_bytes,
                &mut truncated,
            );
            self.pending.drain(..count);
            self.read_more().await?;
        }
    }
    async fn read_more(&mut self) -> Result<(), ShellError> {
        let mut bytes = [0_u8; 8192];
        let count = self.stdout.read(&mut bytes).await.map_err(ShellError::Io)?;
        if count == 0 {
            return Err(ShellError::Ended);
        }
        self.pending.extend_from_slice(&bytes[..count]);
        Ok(())
    }
    async fn terminate(&mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}
fn append_output(output: &mut Vec<u8>, bytes: &[u8], limit: usize, truncated: &mut bool) {
    let count = bytes.len().min(limit.saturating_sub(output.len()));
    output.extend_from_slice(&bytes[..count]);
    *truncated |= count < bytes.len();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn backends() -> Vec<(ShellKind, String)> {
        let native = ShellKind::native();
        let mut backends = vec![(native, native.executable().into())];
        if cfg!(windows)
            && let Ok(path) = std::env::var("SUDOSERVER_TEST_BASH")
        {
            backends.push((ShellKind::Bash, path));
        }
        backends
    }

    fn source(kind: ShellKind, powershell: &'static str, bash: &'static str) -> &'static str {
        match kind {
            ShellKind::PowerShell => powershell,
            ShellKind::Bash => bash,
        }
    }

    async fn run(shell: &Shell, script: &str) -> ExecutionResult {
        tokio::time::timeout(Duration::from_secs(20), shell.execute(script, None))
            .await
            .expect("shell protocol stalled")
            .unwrap()
    }

    #[tokio::test]
    async fn native_syntax_unicode_pipelines_wildcards_and_state() {
        for (kind, path) in backends() {
            let shell = Shell::spawn_kind(kind, &path, 1024 * 1024).await.unwrap();
            let script = source(
                kind,
                "$values = 1..5\n$values | Where-Object { $_ -gt 3 } | ForEach-Object { \"值=$_\" }; Get-ChildItem -Name Cargo.*",
                "for value in 4 5; do printf '值=%s\\n' \"$value\"; done | cat\nprintf '%s\\n' Cargo.*\ncat <<'EOF'\nheredoc value\nEOF",
            );
            let result = run(&shell, script).await;
            assert!(result.success, "{kind:?}: {}", result.output);
            for expected in ["值=4", "值=5", "Cargo.toml"] {
                assert!(
                    result.output.contains(expected),
                    "{kind:?}: {}",
                    result.output
                );
            }
            run(&shell, source(kind,
                "$ss_test = 'persisted'; $env:SUDOSERVER_TEST = 'yes'; function ss_function { 'function-ok' }; Set-Location src",
                "ss_test='persisted'; export SUDOSERVER_TEST=yes; ss_function() { printf 'function-ok\\n'; }; cd src")).await;
            let result = run(
                &shell,
                source(
                    kind,
                    "\"$ss_test/$env:SUDOSERVER_TEST\"; ss_function; (Get-Location).Path",
                    "printf '%s/%s\\n' \"$ss_test\" \"$SUDOSERVER_TEST\"; ss_function; pwd",
                ),
            )
            .await;
            for expected in ["persisted/yes", "function-ok", "src"] {
                assert!(
                    result.output.contains(expected),
                    "{kind:?}: {}",
                    result.output
                );
            }
            shell.terminate().await;
        }
    }

    #[tokio::test]
    async fn output_framing_truncation_errors_and_next_command() {
        for (kind, path) in backends() {
            let shell = Shell::spawn_kind(kind, &path, 1024).await.unwrap();
            let result = run(
                &shell,
                source(
                    kind,
                    "[Console]::Out.Write('direct-without-newline:'); 'captured'",
                    "printf 'direct-without-newline:captured'",
                ),
            )
            .await;
            assert!(result.output.contains("direct-without-newline:captured"));
            let controls = run(
                &shell,
                source(
                    kind,
                    "[Console]::Out.Write(\"a$([char]0)b$([char]30)other$([char]31)c\")",
                    "printf 'a\\000b\\036other\\037c'",
                ),
            )
            .await;
            assert_eq!(controls.output, "a\0b\u{001e}other\u{001f}c");
            let result = run(
                &shell,
                source(
                    kind,
                    "[Console]::Out.Write(('x' * 40000))",
                    "printf '%40000s' ''",
                ),
            )
            .await;
            assert!(result.success && result.truncated);
            assert_eq!(result.output.len(), 1024);
            assert!(
                run(&shell, "echo next-command")
                    .await
                    .output
                    .contains("next-command")
            );
            let error = run(
                &shell,
                source(
                    kind,
                    "Write-Error 'expected failure'",
                    "printf 'expected failure' >&2; false",
                ),
            )
            .await;
            assert!(!error.success);
            assert!(error.output.contains("expected failure"));
            let native = run(
                &shell,
                source(kind, "pwsh -NoProfile -Command 'exit 7'", "(exit 7)"),
            )
            .await;
            assert_eq!(native.exit_code, 7);
            assert!(run(&shell, "echo recovered").await.success);
            shell.terminate().await;
        }
    }

    #[tokio::test]
    async fn explicit_timeout_destroys_session_but_has_no_server_maximum() {
        for (kind, path) in backends() {
            let shell = Shell::spawn_kind(kind, &path, 1024).await.unwrap();
            assert!(
                shell
                    .execute("echo above-old-limit", Some(3600))
                    .await
                    .unwrap()
                    .success
            );
            let result = shell
                .execute(
                    source(
                        kind,
                        "while ($true) { Start-Sleep -Milliseconds 100 }",
                        "while :; do :; done",
                    ),
                    Some(1),
                )
                .await;
            assert!(matches!(result, Err(ShellError::Timeout(1))));
            assert!(shell.execute("echo invalid", None).await.is_err());
        }
    }

    #[tokio::test]
    async fn cancellation_interrupts_unlimited_and_queued_commands() {
        for (kind, path) in backends() {
            let shell = Arc::new(Shell::spawn_kind(kind, &path, 1024).await.unwrap());
            run(&shell, "echo ready").await;
            let running = {
                let shell = Arc::clone(&shell);
                tokio::spawn(async move {
                    shell
                        .execute(
                            source(
                                kind,
                                "while ($true) { Start-Sleep -Milliseconds 100 }",
                                "while :; do :; done",
                            ),
                            None,
                        )
                        .await
                })
            };
            tokio::time::sleep(Duration::from_millis(200)).await;
            let queued = {
                let shell = Arc::clone(&shell);
                tokio::spawn(async move { shell.execute("echo never", None).await })
            };
            tokio::time::timeout(Duration::from_secs(5), shell.terminate())
                .await
                .unwrap();
            assert!(running.await.unwrap().is_err());
            assert!(queued.await.unwrap().is_err());
        }
    }

    #[tokio::test]
    async fn disconnected_request_does_not_corrupt_next_response() {
        for (kind, path) in backends() {
            let shell = Arc::new(Shell::spawn_kind(kind, &path, 1024).await.unwrap());
            run(&shell, "echo ready").await;
            let request = {
                let shell = Arc::clone(&shell);
                tokio::spawn(async move {
                    shell
                        .execute(
                            source(
                                kind,
                                "Start-Sleep -Seconds 1; 'first'",
                                "sleep 1; echo first",
                            ),
                            None,
                        )
                        .await
                })
            };
            tokio::time::sleep(Duration::from_millis(200)).await;
            request.abort();
            let result = run(&shell, "echo second").await;
            assert!(result.output.contains("second"));
            assert!(!result.output.contains("first"));
            shell.terminate().await;
        }
    }

    #[tokio::test]
    async fn shell_exit_is_reported_without_hanging() {
        for (kind, path) in backends() {
            let shell = Shell::spawn_kind(kind, &path, 1024).await.unwrap();
            let result =
                tokio::time::timeout(Duration::from_secs(10), shell.execute("exit 3", None))
                    .await
                    .unwrap();
            assert!(result.is_err());
        }
    }
}
