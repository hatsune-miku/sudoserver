//! Login-scoped autostart. The caller must be the non-elevated target user.
#[cfg(unix)]
use std::process::Command;
use std::{fs, path::Path};

use anyhow::{Context, Result, bail};

pub fn install(config: &Path) -> Result<()> {
    let config = config
        .canonicalize()
        .context("failed to resolve user configuration")?;
    let loaded = localshelld::config::Config::load(&config)?;
    if loaded.bind == loaded.privileged_daemon {
        bail!("user and privileged daemon addresses must differ");
    }
    let executable = std::env::current_exe()?;
    for path in [&executable, &config] {
        let value = path
            .to_str()
            .context("service paths must be valid Unicode")?;
        if value.chars().any(|ch| ch.is_control()) {
            bail!("service paths must not contain control characters");
        }
    }
    install_native(&executable, &config)?;
    println!("localshelld user daemon installed and started for this user.");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    uninstall_native()?;
    println!("localshelld user daemon uninstalled. Configuration and seal.key were preserved.");
    Ok(())
}

#[cfg(target_os = "macos")]
fn home() -> Result<std::path::PathBuf> {
    directories::BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_owned())
        .context("unable to determine the current user's home directory")
}

#[cfg(target_os = "linux")]
fn unit_path() -> Result<std::path::PathBuf> {
    let dirs =
        directories::BaseDirs::new().context("unable to find user configuration directory")?;
    Ok(dirs
        .config_dir()
        .join("systemd/user/localshelld-user.service"))
}

#[cfg(any(target_os = "linux", test))]
fn systemd_unit(executable: &Path, config: &Path) -> String {
    let quote = |path: &Path| {
        path.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    };
    format!(
        "[Unit]\nDescription=localshelld current-user daemon\n\n[Service]\nExecStart=\"{}\" serve --user --config \"{}\"\nRestart=on-failure\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n",
        quote(executable),
        quote(config)
    )
}

#[cfg(target_os = "linux")]
fn install_native(executable: &Path, config: &Path) -> Result<()> {
    let path = unit_path()?;
    if path.exists() {
        bail!("user unit exists; run localshelld uninstall --user first");
    }
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(path, systemd_unit(executable, config))?;
    super::checked(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
    super::checked(Command::new("systemctl").args([
        "--user",
        "enable",
        "--now",
        "localshelld-user.service",
    ]))
}

#[cfg(target_os = "linux")]
fn uninstall_native() -> Result<()> {
    let path = unit_path()?;
    if path.exists() {
        super::checked(Command::new("systemctl").args([
            "--user",
            "disable",
            "--now",
            "localshelld-user.service",
        ]))?;
        fs::remove_file(path)?;
        super::checked(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
    }
    Ok(())
}

#[cfg(any(target_os = "macos", windows, test))]
fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "macos")]
fn agent_path() -> Result<std::path::PathBuf> {
    Ok(home()?.join("Library/LaunchAgents/dev.localshelld.user.plist"))
}

#[cfg(target_os = "macos")]
fn domain() -> Result<String> {
    let result = Command::new("/usr/bin/id").arg("-u").output()?;
    let uid = String::from_utf8(result.stdout)?.trim().parse::<u32>()?;
    Ok(format!("gui/{uid}"))
}

#[cfg(any(target_os = "macos", test))]
fn launch_agent(executable: &Path, config: &Path, directory: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>dev.localshelld.user</string>
<key>ProgramArguments</key><array><string>{}</string><string>serve</string><string>--user</string><string>--config</string><string>{}</string></array>
<key>WorkingDirectory</key><string>{}</string>
<key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin</string></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>3</integer>
</dict></plist>
"#,
        xml(&executable.to_string_lossy()),
        xml(&config.to_string_lossy()),
        xml(&directory.to_string_lossy())
    )
}

#[cfg(target_os = "macos")]
fn install_native(executable: &Path, config: &Path) -> Result<()> {
    let path = agent_path()?;
    if path.exists() {
        bail!("user LaunchAgent exists; run localshelld uninstall --user first");
    }
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(&path, launch_agent(executable, config, &home()?))?;
    super::checked(
        Command::new("/bin/launchctl")
            .args(["bootstrap", &domain()?])
            .arg(path),
    )
}

#[cfg(target_os = "macos")]
fn uninstall_native() -> Result<()> {
    let path = agent_path()?;
    if path.exists() {
        let output = Command::new("/bin/launchctl")
            .args(["bootout", &format!("{}/dev.localshelld.user", domain()?)])
            .output()?;
        if !output.status.success() && output.status.code() != Some(3) {
            bail!("could not unload user LaunchAgent; plist preserved");
        }
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(windows)]
fn sid() -> Result<String> {
    let output = super::windows_command("WindowsPowerShell/v1.0/powershell.exe")?
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ])
        .output()?;
    let sid = String::from_utf8(output.stdout)?.trim().to_owned();
    if !output.status.success()
        || !sid.starts_with("S-1-")
        || !sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'S' || b == b'-')
    {
        bail!("unable to determine current user SID");
    }
    Ok(sid)
}

#[cfg(any(windows, test))]
fn scheduled_task(executable: &Path, config: &Path, sid: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId></LogonTrigger></Triggers>
<Principals><Principal id="User"><UserId>{sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure></Settings>
<Actions Context="User"><Exec><Command>{}</Command><Arguments>serve --user --config &quot;{}&quot;</Arguments></Exec></Actions>
</Task>
"#,
        xml(&executable.to_string_lossy()),
        xml(&config.to_string_lossy()),
        sid = xml(sid)
    )
}

#[cfg(windows)]
fn install_native(executable: &Path, config: &Path) -> Result<()> {
    let sid = sid()?;
    let task = format!("localshelld-user-{sid}");
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("task.xml");
    let document = scheduled_task(executable, config, &sid);
    let bytes: Vec<u8> = std::iter::once(0xfeff_u16)
        .chain(document.encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect();
    fs::write(&path, bytes)?;
    super::checked(
        super::windows_command("schtasks.exe")?
            .args(["/Create", "/TN", &task, "/XML"])
            .arg(path),
    )?;
    super::checked(super::windows_command("schtasks.exe")?.args(["/Run", "/TN", &task]))
}

#[cfg(windows)]
fn uninstall_native() -> Result<()> {
    let task = format!("localshelld-user-{}", sid()?);
    // An already stopped task need not have a running instance to end.
    let _ = super::windows_command("schtasks.exe")?
        .args(["/End", "/TN", &task])
        .output()?;
    super::checked(super::windows_command("schtasks.exe")?.args(["/Delete", "/TN", &task, "/F"]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autostart_uses_user_identity_and_escaped_paths() {
        let exe = Path::new("/home/A & B/localshelld");
        let config = Path::new("/home/A & B/config.toml");
        let task = scheduled_task(exe, config, "S-1-5-21-123");
        assert!(task.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(task.contains("<LogonType>InteractiveToken</LogonType>"));
        assert!(task.contains("A &amp; B"));
        assert!(task.contains("serve --user --config"));
        let agent = launch_agent(exe, config, Path::new("/home/A & B"));
        assert!(!agent.contains("<key>UserName</key>"));
        assert!(agent.contains("<string>--user</string>"));
        assert!(agent.contains("A &amp; B"));
        let unit = systemd_unit(Path::new("/home/a%u/$bin"), config);
        assert!(unit.contains("a%%u/$$bin"));
        assert!(unit.contains("serve --user --config \"/home/A & B/config.toml\""));
    }

    #[cfg(windows)]
    #[test]
    fn task_scheduler_accepts_user_task_xml_without_registering() {
        use base64::Engine;
        let document = scheduled_task(
            Path::new(r"C:\Program Files\localshelld\localshelld.exe"),
            Path::new(r"C:\Users\A & B\config.toml"),
            &sid().unwrap(),
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(document.as_bytes());
        let script = format!(
            "$ErrorActionPreference='Stop'; $service=New-Object -ComObject Schedule.Service; $service.Connect(); $task=$service.NewTask(0); $task.XmlText=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}')); if ($task.Principal.RunLevel -ne 0) {{ throw 'task requests elevation' }}"
        );
        let output = super::super::windows_command("WindowsPowerShell/v1.0/powershell.exe")
            .unwrap()
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn user_agent_is_a_valid_plist_without_root_identity() {
        let document = launch_agent(
            Path::new("/Applications/A & B/localshelld"),
            Path::new("/Users/test/config.toml"),
            Path::new("/Users/test"),
        );
        let parsed = plist::Value::from_reader(std::io::Cursor::new(document.as_bytes())).unwrap();
        let dictionary = parsed.as_dictionary().unwrap();
        assert_eq!(
            dictionary["Label"].as_string(),
            Some("dev.localshelld.user")
        );
        assert!(!dictionary.contains_key("UserName"));
    }
}
