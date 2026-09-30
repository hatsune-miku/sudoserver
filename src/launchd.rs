#[cfg(target_os = "macos")]
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

#[cfg(target_os = "macos")]
use anyhow::{Context, Result, bail};

const LABEL: &str = "dev.sudoserver";
#[cfg(target_os = "macos")]
const PLIST_PATH: &str = "/Library/LaunchDaemons/dev.sudoserver.plist";

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn plist(executable: &str, config: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array><string>{}</string><string>serve</string><string>--config</string><string>{}</string></array>
    <key>UserName</key><string>root</string>
    <key>WorkingDirectory</key><string>/</string>
    <key>EnvironmentVariables</key>
    <dict><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin</string></dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
    <key>ThrottleInterval</key><integer>3</integer>
</dict>
</plist>
"#,
        escape_xml(executable),
        escape_xml(config)
    )
}

#[cfg(target_os = "macos")]
pub fn install(executable: &Path, config: &Path) -> Result<()> {
    if Path::new(PLIST_PATH).exists() {
        bail!("{PLIST_PATH} already exists; run `sudoserver uninstall` before reinstalling");
    }
    let executable = executable
        .to_str()
        .context("executable path is not valid UTF-8")?;
    let config = config
        .to_str()
        .context("configuration path is not valid UTF-8")?;
    // create_new avoids overwriting another installation or following a symlink.
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(PLIST_PATH)?;
    file.write_all(plist(executable, config).as_bytes())?;
    file.set_permissions(fs::Permissions::from_mode(0o644))?;
    super::checked(Command::new("/bin/launchctl").args(["bootstrap", "system", PLIST_PATH]))
        .context("launchd bootstrap failed; plist was preserved for diagnosis")
}

#[cfg(target_os = "macos")]
pub fn uninstall() -> Result<bool> {
    let path = Path::new(PLIST_PATH);
    if !path.exists() {
        return Ok(false);
    }
    let output = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{LABEL}")])
        .output()
        .context("failed to run launchctl bootout")?;
    // ESRCH means the job is already unloaded (e.g. a failed bootstrap).
    if !output.status.success() && output.status.code() != Some(3) {
        bail!(
            "launchctl bootout failed; plist preserved: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fs::remove_file(path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launchd_arguments_are_separate_and_xml_escaped() {
        let xml = plist(
            "/Applications/Sudo Server/bin&tool",
            "/Library/A <B>/\"config\".toml",
        );
        assert!(xml.contains("<string>/Applications/Sudo Server/bin&amp;tool</string>"));
        assert!(xml.contains("<string>/Library/A &lt;B&gt;/&quot;config&quot;.toml</string>"));
        assert!(xml.contains("<key>UserName</key><string>root</string>"));
        assert!(xml.contains("<string>serve</string><string>--config</string>"));
        assert!(!xml.contains("seal.key"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn plist_passes_macos_validation() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(
            plist(
                "/usr/local/bin/sudoserver",
                "/Library/Sudo Server/config.toml",
            )
            .as_bytes(),
        )
        .unwrap();
        let output = Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(file.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}
