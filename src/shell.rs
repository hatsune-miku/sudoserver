use std::{process::Stdio, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    time::timeout,
};

#[derive(Clone, Debug, Serialize)]
pub struct ExecutionResult {
    pub output: String,
    pub exit_code: i32,
    pub success: bool,
    pub truncated: bool,
}

#[derive(Debug, Error)]
pub enum ShellError {
    #[error("failed to start PowerShell: {0}")]
    Start(#[source] std::io::Error),
    #[error("PowerShell session ended unexpectedly")]
    Ended,
    #[error("PowerShell I/O failed: {0}")]
    Io(#[source] std::io::Error),
    #[error("PowerShell returned an invalid response")]
    InvalidResponse,
    #[error("command exceeded the {0}-second timeout; the session was destroyed")]
    Timeout(u64),
}

pub struct PowerShell {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    max_output_bytes: usize,
}

impl PowerShell {
    pub async fn spawn(executable: &str, max_output_bytes: usize) -> Result<Self, ShellError> {
        let mut child = Command::new(executable)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-NoExit",
                "-Command",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(ShellError::Start)?;
        let stdin = child.stdin.take().ok_or(ShellError::Ended)?;
        let stdout = child.stdout.take().ok_or(ShellError::Ended)?;
        let mut shell = Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            max_output_bytes,
        };
        // Force deterministic UTF-8 output without changing the user's PowerShell profile.
        shell
            .stdin
            .write_all(b"[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$OutputEncoding=[Console]::OutputEncoding\n")
            .await
            .map_err(ShellError::Io)?;
        shell.stdin.flush().await.map_err(ShellError::Io)?;
        Ok(shell)
    }

    pub async fn execute(
        &mut self,
        command: &str,
        timeout_seconds: u64,
    ) -> Result<ExecutionResult, ShellError> {
        match timeout(
            Duration::from_secs(timeout_seconds),
            self.execute_inner(command),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                let _ = self.child.kill().await;
                Err(ShellError::Timeout(timeout_seconds))
            }
        }
    }

    async fn execute_inner(&mut self, command: &str) -> Result<ExecutionResult, ShellError> {
        if self.child.try_wait().map_err(ShellError::Io)?.is_some() {
            return Err(ShellError::Ended);
        }
        let mut marker_bytes = [0_u8; 18];
        OsRng.fill_bytes(&mut marker_bytes);
        let marker = format!("__SUDOSERVER_{}__", STANDARD.encode(marker_bytes));
        let encoded = STANDARD.encode(command.as_bytes());
        // The user script is handed to PowerShell's own parser. Capturing *>&1 keeps all
        // PowerShell streams ordered; the random marker frames one request on the persistent process.
        let wrapper = format!(
            "$__ss_s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'));$__ss_ec=0;$__ss_o='';try{{$global:LASTEXITCODE=0;$__ss_errors=$global:Error.Count;$__ss_items=. ([ScriptBlock]::Create($__ss_s)) *>&1;$__ss_ec=if($LASTEXITCODE -ne 0){{[int]$LASTEXITCODE}}elseif($global:Error.Count -gt $__ss_errors){{1}}else{{0}};$__ss_o=$__ss_items|Out-String -Width 32767}}catch{{$__ss_ec=1;$__ss_o=$_|Out-String -Width 32767}};$__ss_b=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$__ss_o));[Console]::Out.WriteLine('{marker}'+$__ss_ec+'|'+$__ss_b)\n"
        );
        self.stdin
            .write_all(wrapper.as_bytes())
            .await
            .map_err(ShellError::Io)?;
        self.stdin.flush().await.map_err(ShellError::Io)?;

        let mut incidental = Vec::new();
        loop {
            let mut line = String::new();
            let read = self
                .stdout
                .read_line(&mut line)
                .await
                .map_err(ShellError::Io)?;
            if read == 0 {
                return Err(ShellError::Ended);
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if let Some(response) = trimmed.strip_prefix(&marker) {
                let (exit_code, payload) = response
                    .split_once('|')
                    .ok_or(ShellError::InvalidResponse)?;
                let exit_code: i32 = exit_code.parse().map_err(|_| ShellError::InvalidResponse)?;
                let mut output = STANDARD
                    .decode(payload)
                    .map_err(|_| ShellError::InvalidResponse)?;
                if !incidental.is_empty() {
                    incidental.append(&mut output);
                    output = incidental;
                }
                let truncated = output.len() > self.max_output_bytes;
                if truncated {
                    output.truncate(self.max_output_bytes);
                }
                return Ok(ExecutionResult {
                    output: String::from_utf8_lossy(&output).into_owned(),
                    exit_code,
                    success: exit_code == 0,
                    truncated,
                });
            }
            if incidental.len() <= self.max_output_bytes {
                incidental.extend_from_slice(line.as_bytes());
            }
        }
    }

    pub async fn terminate(&mut self) {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn shell() -> Option<PowerShell> {
        match PowerShell::spawn("pwsh", 1024 * 1024).await {
            Ok(shell) => Some(shell),
            Err(ShellError::Start(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("{error}"),
        }
    }

    #[tokio::test]
    async fn supports_pipelines_wildcards_multiline_and_unicode() {
        let Some(mut shell) = shell().await else {
            return;
        };
        let result = shell
            .execute("$values = 1..5\n$values | Where-Object { $_ -gt 3 } | ForEach-Object { \"值=$_\" }", 10)
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("值=4"));
        assert!(result.output.contains("值=5"));

        let wildcard = shell
            .execute("Get-ChildItem -Name Cargo.*", 10)
            .await
            .unwrap();
        assert!(wildcard.output.contains("Cargo.toml"));
    }

    #[tokio::test]
    async fn preserves_variables_working_directory_and_environment() {
        let Some(mut shell) = shell().await else {
            return;
        };
        shell
            .execute(
                "$global:SudoServerTest = 'persisted'; $env:SUDOSERVER_TEST = 'yes'",
                10,
            )
            .await
            .unwrap();
        let result = shell
            .execute("\"$global:SudoServerTest/$env:SUDOSERVER_TEST\"", 10)
            .await
            .unwrap();
        assert!(result.output.contains("persisted/yes"));
    }

    #[tokio::test]
    async fn captures_errors_and_native_exit_codes() {
        let Some(mut shell) = shell().await else {
            return;
        };
        let error = shell
            .execute("Write-Error 'expected failure'", 10)
            .await
            .unwrap();
        assert!(!error.success);
        assert!(error.output.contains("expected failure"));

        let native = shell
            .execute("pwsh -NoProfile -Command 'exit 7'", 10)
            .await
            .unwrap();
        assert_eq!(native.exit_code, 7);
    }
}
