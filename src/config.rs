use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const DEFAULT_PORT: u16 = 32119;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub bind: SocketAddr,
    pub password_hash: String,
    pub totp_secret: Option<SealedSecret>,
    pub shell: String,
    pub max_output_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedSecret {
    pub nonce: String,
    pub ciphertext: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), DEFAULT_PORT),
            password_hash: String::new(),
            totp_secret: None,
            shell: crate::shell::ShellKind::native().executable().to_owned(),
            max_output_bytes: 8 * 1024 * 1024,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read configuration {}", path.display()))?;
        let mut config: Self = toml::from_str(&text).context("invalid configuration")?;
        config.migrate_legacy_shell();
        config.validate()?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            set_private_dir(parent)?;
        }
        let text = toml::to_string_pretty(self)?;
        fs::write(path, text)?;
        set_private_file(path)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if !self.bind.ip().is_loopback() {
            bail!(
                "refusing non-loopback bind address {}; put a TLS/authenticating reverse proxy in front instead",
                self.bind
            );
        }
        if self.password_hash.is_empty() {
            bail!("Master Password is not initialized; run `sudoserver init`");
        }
        if self.max_output_bytes < 1024 {
            bail!("max_output_bytes must be at least 1024");
        }
        let executable = Path::new(&self.shell)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let valid = if cfg!(windows) {
            executable.eq_ignore_ascii_case("pwsh") || executable.eq_ignore_ascii_case("pwsh.exe")
        } else {
            executable == "bash"
        };
        if !valid {
            bail!(
                "shell must name {} or its full executable path on this platform",
                crate::shell::ShellKind::native().executable()
            );
        }
        Ok(())
    }

    fn migrate_legacy_shell(&mut self) {
        // Old releases used PowerShell on every platform. Preserve the file and
        // migrate its effective shell in memory; obsolete timeout keys are ignored.
        if !cfg!(windows) && self.shell == "pwsh" {
            self.shell = "/bin/bash".into();
            tracing::warn!(
                "legacy shell=pwsh configuration migrated to /bin/bash; save the configuration to make this explicit"
            );
        }
    }
}

pub fn default_config_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("dev", "SudoServer", "SudoServer")
        .context("unable to determine the platform configuration directory")?;
    Ok(dirs.config_dir().join("config.toml"))
}

pub fn seal_key_path(config_path: &Path) -> PathBuf {
    config_path.with_file_name("seal.key")
}

pub fn load_or_create_seal_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    if path.exists() {
        let encoded = fs::read_to_string(path)?;
        let decoded = STANDARD
            .decode(encoded.trim())
            .context("invalid seal key")?;
        let key: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid seal key length"))?;
        return Ok(Zeroizing::new(key));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_private_dir(parent)?;
    }
    let mut key = [0_u8; 32];
    OsRng.fill_bytes(&mut key);
    fs::write(path, STANDARD.encode(key))?;
    set_private_file(path)?;
    Ok(Zeroizing::new(key))
}

pub fn seal(secret: &[u8], key: &[u8; 32]) -> Result<SealedSecret> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key length is fixed");
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), secret)
        .map_err(|_| anyhow::anyhow!("failed to encrypt TOTP secret"))?;
    Ok(SealedSecret {
        nonce: STANDARD.encode(nonce_bytes),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

pub fn unseal(secret: &SealedSecret, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key length is fixed");
    let nonce = STANDARD
        .decode(&secret.nonce)
        .context("invalid TOTP nonce")?;
    let ciphertext = STANDARD
        .decode(&secret.ciphertext)
        .context("invalid TOTP ciphertext")?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("unable to decrypt TOTP secret"))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
fn set_private_file(path: &Path) -> Result<()> {
    restrict_windows_acl(path, false)
}

#[cfg(windows)]
fn set_private_dir(path: &Path) -> Result<()> {
    restrict_windows_acl(path, true)
}

#[cfg(windows)]
fn restrict_windows_acl(path: &Path, directory: bool) -> Result<()> {
    use std::process::Command;
    let output = Command::new("whoami")
        .output()
        .context("failed to determine the current Windows principal")?;
    if !output.status.success() {
        bail!("whoami could not determine the current Windows principal");
    }
    let principal = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let inheritance = if directory { "(OI)(CI)(F)" } else { "(F)" };
    let system = format!("*S-1-5-18:{inheritance}");
    let administrators = format!("*S-1-5-32-544:{inheritance}");
    let current_user = format!("{principal}:{inheritance}");
    let status = Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .args([system, administrators, current_user])
        .status()
        .context("failed to start icacls")?;
    if !status.success() {
        bail!(
            "icacls could not restrict permissions on {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_timeout_is_ignored_and_shell_is_platform_native() {
        let mut config: Config =
            toml::from_str("password_hash = 'hash'\nshell = 'pwsh'\nmax_command_seconds = 300")
                .unwrap();
        config.migrate_legacy_shell();
        config.validate().unwrap();
        assert_eq!(config.shell, crate::shell::ShellKind::native().executable());
        assert!(
            !toml::to_string(&config)
                .unwrap()
                .contains("max_command_seconds")
        );
    }

    #[test]
    fn rejects_wrong_shell_backend() {
        let config = Config {
            password_hash: "hash".into(),
            shell: if cfg!(windows) { "bash" } else { "powershell" }.into(),
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn sealed_secret_round_trip_and_wrong_key_fails() {
        let key = [7_u8; 32];
        let sealed = seal(b"hello secret", &key).unwrap();
        assert_ne!(sealed.ciphertext, STANDARD.encode(b"hello secret"));
        assert_eq!(&*unseal(&sealed, &key).unwrap(), b"hello secret");
        assert!(unseal(&sealed, &[8_u8; 32]).is_err());
    }

    #[test]
    fn rejects_remote_bind() {
        let config = Config {
            password_hash: "hash".into(),
            bind: "0.0.0.0:1234".parse().unwrap(),
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }
}
