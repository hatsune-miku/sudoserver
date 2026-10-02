use std::{
    io::{self, BufRead},
    path::PathBuf,
    process::Command,
};

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(any(target_os = "linux", windows))]
use std::path::Path;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use localshelld::{
    auth::{AuthManager, create_totp, generate_totp_secret, hash_password},
    config::{
        Config, USER_PORT, default_config_path, load_or_create_seal_key, seal, seal_key_path,
        unseal, user_config_path,
    },
    server::{AppState, router},
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(any(target_os = "macos", test))]
mod launchd;
mod update;
mod user_service;
#[cfg(windows)]
mod windows_service_host;

#[derive(Parser)]
#[command(version = localshelld::VERSION, about)]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Subcommand)]
enum CommandKind {
    /// Initialize the Master Password and optional Authenticator support.
    Init {
        /// Initialize an independent current-user daemon configuration.
        #[arg(long)]
        user: bool,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        totp: bool,
        #[arg(long)]
        force: bool,
        /// Read one password line from stdin (intended for automated installation).
        #[arg(long)]
        password_stdin: bool,
    },
    /// Run the system or current-user HTTP/MCP daemon.
    Serve {
        /// Run as the current non-elevated user, routing sudo=true to the system daemon.
        #[arg(long, conflicts_with = "allow_unelevated")]
        user: bool,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Development only: permit starting without administrator/root identity.
        #[arg(long)]
        allow_unelevated: bool,
    },
    /// Register and start the system service or current-user autostart daemon.
    Install {
        /// Install a login-started daemon for the current non-elevated user.
        #[arg(long)]
        user: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Stop and unregister the native system service without deleting configuration.
    Uninstall {
        #[arg(long)]
        user: bool,
    },
    /// Check for or install an update from the official GitHub Releases.
    Update(update::Options),
    /// Internal updater; only a prepared, local update plan is accepted.
    #[cfg(windows)]
    #[command(hide = true)]
    ApplyUpdate { plan: PathBuf },
    /// Internal entry point used by the Windows Service Control Manager.
    #[cfg(windows)]
    #[command(hide = true)]
    Service {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "localshelld=info".into()),
        )
        .init();
    match Cli::parse().command {
        CommandKind::Init {
            user,
            config,
            totp,
            force,
            password_stdin,
        } => initialize(
            mode_config_path(config, user)?,
            totp,
            force,
            password_stdin,
            user,
        ),
        CommandKind::Serve {
            user,
            config,
            allow_unelevated,
        } => {
            serve_mode_until(
                mode_config_path(config, user)?,
                allow_unelevated,
                user,
                shutdown_signal(),
            )
            .await
        }
        CommandKind::Install { config, user } => {
            if user {
                require_user()?;
                user_service::install(&mode_config_path(config, true)?)
            } else {
                install(config_path(config)?)
            }
        }
        CommandKind::Uninstall { user } => {
            if user {
                require_user()?;
                user_service::uninstall()
            } else {
                uninstall()
            }
        }
        CommandKind::Update(options) => {
            tokio::task::spawn_blocking(move || update::run(options)).await?
        }
        #[cfg(windows)]
        CommandKind::ApplyUpdate { plan } => {
            tokio::task::spawn_blocking(move || update::apply_helper(&plan)).await?
        }
        #[cfg(windows)]
        CommandKind::Service { config } => windows_service_host::dispatch(config_path(config)?),
    }
}

fn config_path(path: Option<PathBuf>) -> Result<PathBuf> {
    path.map_or_else(default_config_path, Ok)
}

fn mode_config_path(path: Option<PathBuf>, user: bool) -> Result<PathBuf> {
    if user {
        path.map_or_else(user_config_path, Ok)
    } else {
        config_path(path)
    }
}

fn initialize(
    path: PathBuf,
    enable_totp: bool,
    force: bool,
    password_stdin: bool,
    user: bool,
) -> Result<()> {
    if user {
        require_user()?;
    }
    if path.exists() && !force {
        bail!(
            "{} already exists; use --force to replace it",
            path.display()
        );
    }
    let mut password = if password_stdin {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned())
    } else {
        let first = Zeroizing::new(rpassword::prompt_password("New Master Password: ")?);
        let second = Zeroizing::new(rpassword::prompt_password("Confirm Master Password: ")?);
        if *first != *second {
            bail!("passwords do not match");
        }
        first
    };
    if password.chars().count() < 12 {
        bail!("Master Password must contain at least 12 characters");
    }
    let password_hash = hash_password(password.as_bytes())?;
    password.zeroize();

    let key_path = seal_key_path(&path);
    let key = load_or_create_seal_key(&key_path)?;
    let totp_secret = if enable_totp {
        let secret = generate_totp_secret();
        let mut totp = create_totp(&secret)?;
        if user {
            totp.account_name = "local-user".into();
        }
        println!("\nAdd this account to Proton Authenticator (or another RFC 6238 app):");
        println!("URI: {}", totp.get_url());
        println!("Manual secret: {}", totp.get_secret_base32());
        let mut code = Zeroizing::new(rpassword::prompt_password(
            "Enter the current 6-digit code to confirm: ",
        )?);
        if !totp.check_current(code.trim()).unwrap_or(false) {
            code.zeroize();
            bail!("incorrect TOTP code; configuration was not written");
        }
        code.zeroize();
        Some(seal(&secret, &key)?)
    } else {
        None
    };
    let mut config = Config {
        password_hash,
        totp_secret,
        ..Config::default()
    };
    if user {
        config.bind.set_port(USER_PORT);
    }
    config.save(&path)?;
    println!("Initialized {}", path.display());
    println!("No Master Password was stored; only its Argon2id verifier was written.");
    Ok(())
}

#[cfg(windows)]
async fn serve_until<F>(path: PathBuf, allow_unelevated: bool, shutdown: F) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    serve_mode_until(path, allow_unelevated, false, shutdown).await
}

async fn serve_mode_until<F>(
    path: PathBuf,
    allow_unelevated: bool,
    user: bool,
    shutdown: F,
) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if user {
        require_user()?;
    } else if !allow_unelevated && !is_elevated()? {
        bail!(
            "localshelld must run as Administrator/root (or pass --allow-unelevated for development only)"
        );
    }
    let config = Config::load(&path)?;
    let totp_secret = match &config.totp_secret {
        Some(secret) => {
            let key = load_or_create_seal_key(&seal_key_path(&path))?;
            Some(unseal(secret, &key)?)
        }
        None => None,
    };
    let auth = AuthManager::new(config.password_hash.clone(), totp_secret);
    tracing::info!(bind = %config.bind, "runtime token store initialized");
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    println!("localshelld management UI: http://{}/", config.bind);
    let state = if user {
        AppState::user(config, auth)?
    } else {
        AppState::new(config, auth)
    };
    axum::serve(listener, router(state.clone()))
        .with_graceful_shutdown(async move {
            shutdown.await;
            state.shutdown().await;
        })
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}

fn is_elevated() -> Result<bool> {
    #[cfg(unix)]
    {
        let output = Command::new("/usr/bin/id")
            .arg("-u")
            .output()
            .context("failed to run id -u")?;
        if !output.status.success() {
            bail!("failed to inspect Unix process identity");
        }
        let uid: u32 = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .context("invalid Unix process identity")?;
        Ok(uid == 0)
    }
    #[cfg(windows)]
    {
        // Unlike `net session`, this does not depend on the Server service being
        // enabled. Failure to inspect the access token must never mean "user".
        let output = windows_command("WindowsPowerShell/v1.0/powershell.exe")?
            .args(["-NoProfile", "-NonInteractive", "-Command",
                "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"])
            .output().context("failed to inspect Windows process identity")?;
        if !output.status.success() {
            bail!("failed to inspect Windows process identity");
        }
        match String::from_utf8_lossy(&output.stdout).trim() {
            "True" => Ok(true),
            "False" => Ok(false),
            _ => bail!("unexpected Windows process identity response"),
        }
    }
}

fn require_user() -> Result<()> {
    if is_elevated()? {
        bail!(
            "--user must run from a non-elevated user terminal; refusing root/Administrator identity"
        );
    }
    Ok(())
}

#[cfg(windows)]
fn windows_command(relative: &str) -> Result<Command> {
    let root = std::env::var_os("SystemRoot").context("missing SystemRoot")?;
    Ok(Command::new(
        PathBuf::from(root).join("System32").join(relative),
    ))
}

fn install(config_path: PathBuf) -> Result<()> {
    if !is_elevated()? {
        bail!("service installation requires Administrator/root");
    }
    let config_path = config_path
        .canonicalize()
        .context("failed to resolve configuration path")?;
    Config::load(&config_path)?;
    let executable = std::env::current_exe()?;
    #[cfg(target_os = "linux")]
    install_systemd(&executable, &config_path)?;
    #[cfg(windows)]
    install_windows_service(&executable, &config_path)?;
    #[cfg(target_os = "macos")]
    launchd::install(&executable, &config_path)?;
    println!("localshelld service installed and started.");
    Ok(())
}

fn uninstall() -> Result<()> {
    if !is_elevated()? {
        bail!("service uninstallation requires Administrator/root");
    }
    #[cfg(target_os = "linux")]
    let removed = uninstall_systemd()?;
    #[cfg(windows)]
    let removed = uninstall_windows_service()?;
    #[cfg(target_os = "macos")]
    let removed = launchd::uninstall()?;

    if removed {
        println!("localshelld service stopped and uninstalled.");
    } else {
        println!("localshelld service is not installed.");
    }
    println!("Configuration and seal.key were preserved.");
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_systemd(executable: &Path, config: &Path) -> Result<()> {
    let unit = format!(
        "[Unit]\nDescription=localshelld privileged Bash broker\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={} serve --config {}\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=false\n\n[Install]\nWantedBy=multi-user.target\n",
        systemd_escape(executable),
        systemd_escape(config)
    );
    fs::write(SYSTEMD_UNIT_PATH, unit)?;
    checked(Command::new("systemctl").arg("daemon-reload"))?;
    checked(Command::new("systemctl").args(["enable", "--now", "localshelld.service"]))
}

#[cfg(target_os = "linux")]
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/localshelld.service";

#[cfg(target_os = "linux")]
fn uninstall_systemd() -> Result<bool> {
    let unit_path = Path::new(SYSTEMD_UNIT_PATH);
    if !unit_path.exists() {
        return Ok(false);
    }
    checked(Command::new("systemctl").args(["disable", "--now", "localshelld.service"]))?;
    fs::remove_file(unit_path)?;
    checked(Command::new("systemctl").arg("daemon-reload"))?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn systemd_escape(path: &Path) -> String {
    path.to_string_lossy().replace(' ', "\\x20")
}

#[cfg(windows)]
fn install_windows_service(executable: &Path, config: &Path) -> Result<()> {
    let bin_path = format!(
        "\"{}\" service --config \"{}\"",
        executable.display(),
        config.display()
    );
    checked(Command::new("sc.exe").args([
        "create",
        "localshelld",
        "binPath=",
        &bin_path,
        "start=",
        "auto",
        "DisplayName=",
        "localshelld",
    ]))?;
    checked(Command::new("sc.exe").args([
        "description",
        "localshelld",
        "User-controlled privileged PowerShell broker",
    ]))?;
    checked(Command::new("sc.exe").args([
        "failure",
        "localshelld",
        "reset=",
        "86400",
        "actions=",
        "restart/5000/restart/15000/\"\"/0",
    ]))?;
    checked(Command::new("sc.exe").args(["start", "localshelld"]))
}

#[cfg(windows)]
fn uninstall_windows_service() -> Result<bool> {
    use std::{thread::sleep, time::Duration};

    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
    const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
    const ERROR_SERVICE_MARKED_FOR_DELETE: i32 = 1072;

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("failed to connect to the Windows Service Control Manager")?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = match manager.open_service("localshelld", access) {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error).context("failed to open the localshelld service"),
    };

    match service.delete() {
        Ok(()) => {}
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_SERVICE_MARKED_FOR_DELETE) => {}
        Err(error) => {
            return Err(error).context("failed to mark the localshelld service for deletion");
        }
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut stop_requested = false;
    loop {
        let state = service
            .query_status()
            .context("failed to query the localshelld service status")?
            .current_state;
        match state {
            ServiceState::Stopped => break,
            ServiceState::Running | ServiceState::Paused if !stop_requested => {
                match service.stop() {
                    Ok(_) => stop_requested = true,
                    Err(windows_service::Error::Winapi(error))
                        if error.raw_os_error() == Some(ERROR_SERVICE_NOT_ACTIVE) =>
                    {
                        stop_requested = true;
                    }
                    Err(error) => {
                        return Err(error).context("failed to stop the localshelld service");
                    }
                }
            }
            ServiceState::StopPending => stop_requested = true,
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            bail!("localshelld was marked for deletion but did not stop within 15 seconds");
        }
        sleep(Duration::from_millis(200));
    }
    drop(service);
    Ok(true)
}

fn checked(command: &mut Command) -> Result<()> {
    let description = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("failed to run {description}"))?;
    if !output.status.success() {
        bail!(
            "{description} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_mode_has_separate_configuration_and_no_elevation_bypass() {
        for command in ["init", "serve", "install", "uninstall"] {
            assert!(Cli::try_parse_from(["localshelld", command, "--user"]).is_ok());
        }
        assert!(
            Cli::try_parse_from(["localshelld", "serve", "--user", "--allow-unelevated"]).is_err()
        );
        assert_ne!(
            mode_config_path(None, true).unwrap(),
            mode_config_path(None, false).unwrap()
        );
    }

    #[test]
    fn parses_uninstall_subcommand() {
        let cli = Cli::try_parse_from(["localshelld", "uninstall"]).unwrap();
        assert!(matches!(
            cli.command,
            CommandKind::Uninstall { user: false }
        ));
    }

    #[test]
    fn parses_update_options_and_rejects_ambiguous_downgrades() {
        assert!(Cli::try_parse_from(["localshelld", "update", "--check", "--prerelease"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "localshelld",
                "update",
                "--tag",
                "v0.1.0",
                "--allow-downgrade"
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["localshelld", "update", "--allow-downgrade"]).is_err());
        assert!(
            Cli::try_parse_from(["localshelld", "update", "--tag", "v0.1.0", "--prerelease"])
                .is_err()
        );
    }
}
