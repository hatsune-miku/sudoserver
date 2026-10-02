#[cfg(unix)]
use std::fs;
use std::{
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
use super::output;
use super::{Lifecycle, checked};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Installed {
    pub executable: std::path::PathBuf,
    pub config: std::path::PathBuf,
    pub was_running: bool,
}

impl Installed {
    fn new(executable: &Path, config: &Path, target: &Path, was_running: bool) -> Result<Self> {
        let executable = executable
            .canonicalize()
            .context("registered service binary is missing")?;
        ensure!(
            executable == target,
            "localshelld is registered at {}; run that binary's update command instead",
            executable.display()
        );
        let config = config.canonicalize()?;
        localshelld::config::Config::load(&config)?;
        Ok(Self {
            executable,
            config,
            was_running,
        })
    }
}

impl Lifecycle for Installed {
    fn stop(&self) -> Result<()> {
        stop()
    }

    fn start_and_verify(&self, expected: Option<&str>) -> Result<()> {
        start()?;
        let config = localshelld::config::Config::load(&self.config)?;
        // The loopback health check must not follow redirects or use an HTTP proxy.
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()?;
        let url = format!("http://{}/health", config.bind);
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut healthy = 0;
        loop {
            let health = client
                .get(&url)
                .send()
                .and_then(|response| response.error_for_status())
                .ok()
                .and_then(|response| super::read_bounded(response, 4096).ok())
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
            let valid = health.is_some_and(|health| {
                health["service"] == "localshelld"
                    && health["status"] == "ok"
                    && expected.is_none_or(|version| health["version"] == version)
            });
            if valid && running()? {
                healthy += 1;
                if healthy >= 3 {
                    return Ok(());
                }
            } else {
                healthy = 0;
            }
            ensure!(
                Instant::now() < deadline,
                "service did not become healthy at the expected version"
            );
            thread::sleep(Duration::from_millis(300));
        }
    }
}

/// Only update binaries in administrator-controlled directories. Otherwise an
/// unprivileged writer could swap the verified image or helper before execution.
pub(super) fn validate_target(target: &Path) -> Result<()> {
    ensure!(
        target.is_absolute() && target.is_file(),
        "update target must be an absolute regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for path in target.ancestors() {
            let metadata = fs::symlink_metadata(path)?;
            ensure!(
                !metadata.file_type().is_symlink()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o022 == 0,
                "{} is not root-owned/protected; install in a root-owned path (not a user-writable checkout) before updating",
                path.display()
            );
            #[cfg(target_os = "macos")]
            {
                // macOS extended ACLs can grant writes not reflected in mode bits.
                let acl = checked(Command::new("/bin/ls").arg("-lde").arg(path))?;
                let extra_write = acl.lines().skip(1).any(|line| {
                    line.contains(" allow ")
                        && line.split([' ', ',']).any(|right| {
                            matches!(
                                right,
                                "write"
                                    | "append"
                                    | "delete"
                                    | "delete_child"
                                    | "add_file"
                                    | "add_subdirectory"
                                    | "writeattr"
                                    | "writeextattr"
                                    | "writesecurity"
                                    | "chown"
                            )
                        })
                });
                ensure!(
                    !extra_write,
                    "writable extended ACL on {}; update manually",
                    path.display()
                );
            }
        }
    }
    #[cfg(windows)]
    {
        // Fixed script; paths are data in the environment, never interpolated code.
        const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$p = $env:LOCALSHELLD_UPDATE_TARGET
$depth = 0
$trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
while ($p) {
  $attributes = [IO.File]::GetAttributes($p)
  if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse point not allowed: $p" }
  $acl = if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
    [IO.Directory]::GetAccessControl($p)
  } else { [IO.File]::GetAccessControl($p) }
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($trusted -notcontains $owner) { throw "Install in an administrator-owned directory first: $p" }
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    $mask = if ($depth -le 1) { 0x000D0156 } else { 0x000D0040 }
    if ($rule.AccessControlType -eq 'Allow' -and $trusted -notcontains $rule.IdentityReference.Value -and
        ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
        ([int]$rule.FileSystemRights -band $mask) -ne 0) {
      throw "Non-administrator write access on $p; use a protected installation directory"
    }
  }
  $p = [IO.Path]::GetDirectoryName($p)
  $depth++
}
"#;
        powershell(SCRIPT, target)?;
    }
    Ok(())
}

pub(super) fn protect_staging(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        // Remove inherited write access and set a trusted owner before placing
        // executable content in this freshly created directory.
        powershell(
            r#"
$ErrorActionPreference = 'Stop'
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$acl.SetOwner($admins)
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
  $id = [Security.Principal.SecurityIdentifier]::new($sid)
  $rule = [Security.AccessControl.FileSystemAccessRule]::new($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
  $acl.AddAccessRule($rule)
}
[IO.Directory]::SetAccessControl($env:LOCALSHELLD_UPDATE_TARGET, $acl)
"#,
            path,
        )?;
    }
    Ok(())
}

#[cfg(windows)]
fn powershell(script: &str, path: &Path) -> Result<()> {
    use base64::Engine;
    let script = format!(
        "$PSModuleAutoLoadingPreference = 'None'; [Console]::OutputEncoding = [Text.Encoding]::UTF8;\n{script}"
    );
    let bytes: Vec<_> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let root = std::env::var_os("SystemRoot").context("missing SystemRoot")?;
    let executable = Path::new(&root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let path = path.to_str().context("non-Unicode installation path")?;
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    ensure!(
        !path.starts_with(r"UNC\") && !path.starts_with(r"\\"),
        "network installations require manual updating"
    );
    checked(
        Command::new(executable)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-OutputFormat",
                "Text",
                "-EncodedCommand",
                &encoded,
            ])
            .env("LOCALSHELLD_UPDATE_TARGET", path),
    )?;
    Ok(())
}

#[cfg(windows)]
fn open_service(
    access: windows_service::service::ServiceAccess,
) -> Result<Option<windows_service::service::Service>> {
    use windows_service::{
        Error,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    match manager.open_service("localshelld", access) {
        Ok(service) => Ok(Some(service)),
        Err(Error::Winapi(error)) if error.raw_os_error() == Some(1060) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(windows)]
pub(super) fn discover(target: &Path) -> Result<Option<Installed>> {
    use windows_service::service::{ServiceAccess, ServiceState};
    let Some(service) = open_service(ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS)?
    else {
        return Ok(None);
    };
    // windows-service returns the complete ImagePath in executable_path.
    let config = service.query_config()?;
    let command = config
        .executable_path
        .to_str()
        .context("service ImagePath is not UTF-8")?;
    let (binary, config) = parse_windows_registration(command)?;
    let state = service.query_status()?.current_state;
    ensure!(
        matches!(state, ServiceState::Running | ServiceState::Stopped),
        "service is transitioning or paused; retry when running/stopped"
    );
    Ok(Some(Installed::new(
        Path::new(binary),
        Path::new(config),
        target,
        state == ServiceState::Running,
    )?))
}

#[cfg(any(windows, test))]
fn parse_windows_registration(command: &str) -> Result<(&str, &str)> {
    let value = command
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .context("unsupported service ImagePath; expected managed installation")?;
    let (binary, config) = value
        .split_once("\" service --config \"")
        .context("unsupported service ImagePath; expected managed installation")?;
    ensure!(
        !binary.contains('"') && !config.contains('"'),
        "unsupported quotes in ImagePath"
    );
    Ok((binary, config))
}

#[cfg(windows)]
fn running() -> Result<bool> {
    use windows_service::service::{ServiceAccess, ServiceState};
    Ok(open_service(ServiceAccess::QUERY_STATUS)?
        .context("service disappeared")?
        .query_status()?
        .current_state
        == ServiceState::Running)
}

#[cfg(windows)]
fn stop() -> Result<()> {
    use windows_service::service::{ServiceAccess, ServiceState};
    let service = open_service(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?
        .context("service disappeared")?;
    let state = service.query_status()?.current_state;
    if state != ServiceState::Stopped && state != ServiceState::StopPending {
        service.stop()?;
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while service.query_status()?.current_state != ServiceState::Stopped {
        ensure!(Instant::now() < deadline, "service stop timed out");
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

#[cfg(windows)]
fn start() -> Result<()> {
    use windows_service::service::{ServiceAccess, ServiceState};
    let service = open_service(ServiceAccess::QUERY_STATUS | ServiceAccess::START)?
        .context("service disappeared")?;
    if service.query_status()?.current_state == ServiceState::Stopped {
        service.start::<&str>(&[])?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
const UNIT: &str = "/etc/systemd/system/localshelld.service";

#[cfg(target_os = "linux")]
pub(super) fn discover(target: &Path) -> Result<Option<Installed>> {
    if !Path::new("/usr/bin/systemctl").try_exists()? && !Path::new(UNIT).try_exists()? {
        return Ok(None);
    }
    let load = systemctl(&[
        "show",
        "localshelld.service",
        "--property=LoadState",
        "--value",
    ])?;
    if load.trim() == "not-found" {
        return Ok(None);
    }
    ensure!(
        load.trim() == "loaded",
        "systemd service is not loaded normally"
    );
    let fragment = systemctl(&[
        "show",
        "localshelld.service",
        "--property=FragmentPath",
        "--value",
    ])?;
    let stale = systemctl(&[
        "show",
        "localshelld.service",
        "--property=NeedDaemonReload",
        "--value",
    ])?;
    ensure!(
        stale.trim() == "no",
        "systemd unit changed on disk; reload/reconcile it before updating"
    );
    let overrides = systemctl(&[
        "show",
        "localshelld.service",
        "--property=DropInPaths",
        "--value",
    ])?;
    ensure!(
        fragment.trim() == UNIT && overrides.trim().is_empty(),
        "custom systemd unit/drop-ins require manual updating"
    );
    let text = fs::read_to_string(UNIT)?;
    let (binary, config) = parse_systemd_registration(&text)?;
    let state = systemctl(&[
        "show",
        "localshelld.service",
        "--property=ActiveState",
        "--value",
    ])?;
    ensure!(
        matches!(state.trim(), "active" | "inactive" | "failed"),
        "service is transitioning; retry update"
    );
    Ok(Some(Installed::new(
        Path::new(&binary),
        Path::new(&config),
        target,
        state.trim() == "active",
    )?))
}

#[cfg(any(target_os = "linux", test))]
fn parse_systemd_registration(text: &str) -> Result<(String, String)> {
    let lines: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("ExecStart="))
        .collect();
    ensure!(lines.len() == 1, "unsupported systemd service command");
    let (binary, config) = lines[0]
        .split_once(" serve --config ")
        .context("unsupported systemd service command")?;
    let decode = |value: &str| -> Result<String> {
        let value = value.replace("\\x20", " ");
        ensure!(
            !value.contains(['\\', '%', '$', '"', '\'']),
            "custom systemd escaping requires manual updating"
        );
        Ok(value)
    };
    Ok((decode(binary)?, decode(config)?))
}

#[cfg(target_os = "linux")]
fn systemctl(args: &[&str]) -> Result<String> {
    checked(Command::new("/usr/bin/systemctl").args(args))
}

#[cfg(target_os = "linux")]
fn running() -> Result<bool> {
    Ok(systemctl(&[
        "show",
        "localshelld.service",
        "--property=ActiveState",
        "--value",
    ])?
    .trim()
        == "active")
}

#[cfg(target_os = "linux")]
fn stop() -> Result<()> {
    systemctl(&["stop", "--no-block", "localshelld.service"])?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let state = systemctl(&[
            "show",
            "localshelld.service",
            "--property=ActiveState",
            "--value",
        ])?;
        if matches!(state.trim(), "inactive" | "failed") {
            return Ok(());
        }
        ensure!(Instant::now() < deadline, "systemd stop timed out");
        thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(target_os = "linux")]
fn start() -> Result<()> {
    systemctl(&["start", "--no-block", "localshelld.service"])?;
    Ok(())
}

#[cfg(target_os = "macos")]
const PLIST: &str = "/Library/LaunchDaemons/dev.localshelld.plist";
#[cfg(target_os = "macos")]
const LABEL: &str = "system/dev.localshelld";

#[cfg(target_os = "macos")]
fn launch_state() -> Result<Option<String>> {
    let result = output(Command::new("/bin/launchctl").args(["print", LABEL]))?;
    if result.status.success() {
        return Ok(Some(String::from_utf8(result.stdout)?));
    }
    ensure!(
        matches!(result.status.code(), Some(3 | 113)),
        "unable to inspect launchd service: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(None)
}

#[cfg(target_os = "macos")]
pub(super) fn discover(target: &Path) -> Result<Option<Installed>> {
    if !Path::new(PLIST).try_exists()? {
        ensure!(
            launch_state()?.is_none(),
            "loaded service has no managed plist; update manually"
        );
        return Ok(None);
    }
    let value = plist::Value::from_file(PLIST)?;
    let dictionary = value.as_dictionary().context("invalid service plist")?;
    let args = dictionary
        .get("ProgramArguments")
        .and_then(plist::Value::as_array)
        .context("missing ProgramArguments")?;
    let args: Vec<_> = args
        .iter()
        .map(|arg| arg.as_string().context("non-string service argument"))
        .collect::<Result<_>>()?;
    ensure!(
        args.len() == 4 && args[1] == "serve" && args[2] == "--config",
        "custom launchd arguments require manual updating"
    );
    let state = launch_state()?;
    // An unloaded service stays unloaded. A loaded but non-running job may auto
    // start during replacement, so fail closed instead of altering its policy.
    let active = state
        .as_ref()
        .is_some_and(|text| text.lines().any(|line| line.trim() == "state = running"));
    ensure!(
        state.is_none() || active,
        "launchd job is loaded but not running; resolve its state before updating"
    );
    Ok(Some(Installed::new(
        Path::new(args[0]),
        Path::new(args[3]),
        target,
        active,
    )?))
}

#[cfg(target_os = "macos")]
fn running() -> Result<bool> {
    Ok(launch_state()?
        .is_some_and(|text| text.lines().any(|line| line.trim() == "state = running")))
}

#[cfg(target_os = "macos")]
fn stop() -> Result<()> {
    if launch_state()?.is_some() {
        checked(Command::new("/bin/launchctl").args(["bootout", LABEL]))?;
    }
    ensure!(launch_state()?.is_none(), "launchd job did not unload");
    Ok(())
}

#[cfg(target_os = "macos")]
fn start() -> Result<()> {
    if launch_state()?.is_none() {
        checked(Command::new("/bin/launchctl").args(["bootstrap", "system", PLIST]))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_managed_service_commands_without_shell_evaluation() {
        assert_eq!(parse_windows_registration(r#""C:\Program Files\localshelld\localshelld.exe" service --config "C:\ProgramData\localshelld\config.toml""#).unwrap(),
            (r"C:\Program Files\localshelld\localshelld.exe", r"C:\ProgramData\localshelld\config.toml"));
        assert!(parse_windows_registration("localshelld service").is_err());
        assert_eq!(parse_systemd_registration("ExecStart=/opt/localshelld\\x20test/localshelld serve --config /etc/localshelld/config.toml").unwrap(),
            ("/opt/localshelld test/localshelld".into(), "/etc/localshelld/config.toml".into()));
        assert!(parse_systemd_registration("ExecStart=/bin/sh -c evil").is_err());
        assert!(
            parse_systemd_registration(
                "ExecStart=/opt/$USER/localshelld serve --config /etc/config"
            )
            .is_err()
        );
    }
}
