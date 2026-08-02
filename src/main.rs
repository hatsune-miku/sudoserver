use std::{
    io::{self, BufRead},
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(target_os = "linux")]
use std::fs;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use sudoserver::{
    auth::{AuthManager, create_totp, generate_totp_secret, hash_password},
    config::{Config, default_config_path, load_or_create_seal_key, seal, seal_key_path, unseal},
    server::{AppState, router},
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(windows)]
mod windows_service_host;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Subcommand)]
enum CommandKind {
    /// Initialize the Master Password and optional Authenticator support.
    Init {
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
    /// Run the privileged HTTP/MCP server.
    Serve {
        #[arg(long)]
        config: Option<PathBuf>,
        /// Development only: permit starting without administrator/root identity.
        #[arg(long)]
        allow_unelevated: bool,
    },
    /// Register and start the native auto-start system service.
    Install {
        #[arg(long)]
        config: Option<PathBuf>,
    },
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
                .unwrap_or_else(|_| "sudoserver=info".into()),
        )
        .init();
    match Cli::parse().command {
        CommandKind::Init {
            config,
            totp,
            force,
            password_stdin,
        } => initialize(config_path(config)?, totp, force, password_stdin),
        CommandKind::Serve {
            config,
            allow_unelevated,
        } => serve(config_path(config)?, allow_unelevated).await,
        CommandKind::Install { config } => install(config_path(config)?),
        #[cfg(windows)]
        CommandKind::Service { config } => windows_service_host::dispatch(config_path(config)?),
    }
}

fn config_path(path: Option<PathBuf>) -> Result<PathBuf> {
    path.map_or_else(default_config_path, Ok)
}

fn initialize(path: PathBuf, enable_totp: bool, force: bool, password_stdin: bool) -> Result<()> {
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
        let totp = create_totp(&secret)?;
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
    Config {
        password_hash,
        totp_secret,
        ..Config::default()
    }
    .save(&path)?;
    println!("Initialized {}", path.display());
    println!("No Master Password was stored; only its Argon2id verifier was written.");
    Ok(())
}

async fn serve(path: PathBuf, allow_unelevated: bool) -> Result<()> {
    serve_until(path, allow_unelevated, shutdown_signal()).await
}

async fn serve_until<F>(path: PathBuf, allow_unelevated: bool, shutdown: F) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if !allow_unelevated && !is_elevated()? {
        bail!(
            "SudoServer must run as Administrator/root (or pass --allow-unelevated for development only)"
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
    tracing::info!(bind = %config.bind, public_key = %auth.public_key_base64(), "runtime Ed25519 key generated");
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    println!("SudoServer management UI: http://{}/", config.bind);
    axum::serve(listener, router(AppState::new(config, auth)))
        .with_graceful_shutdown(shutdown)
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
        let output = Command::new("id")
            .arg("-u")
            .output()
            .context("failed to run id -u")?;
        Ok(output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "0")
    }
    #[cfg(windows)]
    {
        Ok(Command::new("net")
            .arg("session")
            .output()
            .is_ok_and(|output| output.status.success()))
    }
}

fn install(config_path: PathBuf) -> Result<()> {
    if !is_elevated()? {
        bail!("service installation requires Administrator/root");
    }
    Config::load(&config_path)?;
    let executable = std::env::current_exe()?;
    #[cfg(target_os = "linux")]
    install_systemd(&executable, &config_path)?;
    #[cfg(windows)]
    install_windows_service(&executable, &config_path)?;
    #[cfg(not(any(target_os = "linux", windows)))]
    bail!("automatic service installation is currently supported only on Windows and Linux");
    println!("SudoServer service installed and started.");
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_systemd(executable: &Path, config: &Path) -> Result<()> {
    let unit = format!(
        "[Unit]\nDescription=SudoServer privileged PowerShell broker\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={} serve --config {}\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=false\n\n[Install]\nWantedBy=multi-user.target\n",
        systemd_escape(executable),
        systemd_escape(config)
    );
    fs::write("/etc/systemd/system/sudoserver.service", unit)?;
    checked(Command::new("systemctl").arg("daemon-reload"))?;
    checked(Command::new("systemctl").args(["enable", "--now", "sudoserver.service"]))
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
        "SudoServer",
        "binPath=",
        &bin_path,
        "start=",
        "auto",
        "DisplayName=",
        "SudoServer",
    ]))?;
    checked(Command::new("sc.exe").args([
        "description",
        "SudoServer",
        "User-controlled privileged PowerShell broker",
    ]))?;
    checked(Command::new("sc.exe").args([
        "failure",
        "SudoServer",
        "reset=",
        "86400",
        "actions=",
        "restart/5000/restart/15000/\"\"/0",
    ]))?;
    checked(Command::new("sc.exe").args(["start", "SudoServer"]))
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
