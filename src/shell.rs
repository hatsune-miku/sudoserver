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
        let bootstrap = encode_powershell(BOOTSTRAP_SCRIPT);
        let mut child = Command::new(executable)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &bootstrap,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(ShellError::Start)?;
        let stdin = child.stdin.take().ok_or(ShellError::Ended)?;
        let stdout = child.stdout.take().ok_or(ShellError::Ended)?;
        let shell = Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            max_output_bytes,
        };
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
        // The bootstrap reads exactly one line per request. The command itself is Base64,
        // so multiline scripts and every PowerShell metacharacter pass through untouched.
        let request = format!("{marker}|{encoded}\n");
        self.stdin
            .write_all(request.as_bytes())
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
            if let Some(marker_start) = trimmed.find(&marker) {
                // PowerShell's Unix ConsoleHost can emit terminal control bytes before host
                // output even when stdout is redirected. Preserve genuine direct console
                // output and, critically, do not require the protocol marker at column zero.
                incidental.extend_from_slice(&trimmed.as_bytes()[..marker_start]);
                let response = &trimmed[marker_start + marker.len()..];
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

// Run a protocol loop inside one PowerShell script rather than feeding source to
// `pwsh -Command -`. The latter delegates statement framing to ConsoleHost and has
// observably different redirected-stdin/terminal behavior on Unix and Windows.
const BOOTSTRAP_SCRIPT: &str = r#"
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
while (($__ss_line = [Console]::In.ReadLine()) -ne $null) {
    $__ss_separator = $__ss_line.IndexOf('|')
    if ($__ss_separator -le 0) { continue }
    $__ss_marker = $__ss_line.Substring(0, $__ss_separator)
    $__ss_encoded = $__ss_line.Substring($__ss_separator + 1)
    $__ss_ec = 0
    $__ss_o = ''
    try {
        $__ss_s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($__ss_encoded))
        $global:LASTEXITCODE = 0
        $__ss_errors = $global:Error.Count
        $__ss_items = . ([ScriptBlock]::Create($__ss_s)) *>&1
        $__ss_ec = if ($LASTEXITCODE -ne 0) {
            [int]$LASTEXITCODE
        } elseif ($global:Error.Count -gt $__ss_errors) {
            1
        } else {
            0
        }
        $__ss_o = $__ss_items | Out-String -Width 32767
    } catch {
        $__ss_ec = 1
        $__ss_o = $_ | Out-String -Width 32767
    }
    $__ss_b = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$__ss_o))
    [Console]::Out.WriteLine($__ss_marker + $__ss_ec + '|' + $__ss_b)
    [Console]::Out.Flush()
}
"#;

fn encode_powershell(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    STANDARD.encode(bytes)
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

    #[test]
    fn bootstrap_is_encoded_as_utf16le_for_powershell() {
        let encoded = encode_powershell("'ok'");
        assert_eq!(STANDARD.decode(encoded).unwrap(), b"'\0o\0k\0'\0");
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
    async fn accepts_output_before_the_protocol_marker() {
        let Some(mut shell) = shell().await else {
            return;
        };
        let result = shell
            .execute(
                "[Console]::Out.Write('direct-without-newline:'); 'captured'",
                10,
            )
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("direct-without-newline:"));
        assert!(result.output.contains("captured"));
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
