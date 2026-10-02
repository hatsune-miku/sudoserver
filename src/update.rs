//! Explicit, CLI-only updates. No service exposes an update endpoint.
mod service;

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use fs2::FileExt;
use reqwest::blocking::Client;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::io::Write;

const REPOSITORY: &str = "hatsune-miku/localshelld";
const API: &str = "https://api.github.com/repos/hatsune-miku/localshelld";
const MAX_DOWNLOAD: u64 = 128 * 1024 * 1024;
const MAX_JSON: u64 = 4 * 1024 * 1024;

#[derive(Args, Debug)]
pub struct Options {
    /// Query releases without downloading, changing files, or stopping services.
    #[arg(long)]
    pub check: bool,
    /// Include prereleases (stable versions are eligible too).
    #[arg(long, conflicts_with = "tag")]
    pub prerelease: bool,
    /// Install this exact release tag, including a prerelease tag.
    #[arg(long)]
    pub tag: Option<String>,
    /// Permit an explicitly selected older version.
    #[arg(long, requires = "tag")]
    pub allow_downgrade: bool,
}

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Plan {
    target: PathBuf,
    version: String,
    original_hash: String,
    new_hash: String,
    service: Option<service::Installed>,
}

fn version(tag: &str) -> Result<Version> {
    Version::parse(tag.strip_prefix('v').unwrap_or(tag)).context("invalid semantic release version")
}

fn select_release(releases: Vec<Release>, prerelease: bool) -> Result<Release> {
    releases
        .into_iter()
        .filter_map(|release| {
            let parsed = version(&release.tag_name).ok()?;
            // Some historical RC tags were incorrectly marked as full releases.
            (!release.draft && (prerelease || (!release.prerelease && parsed.pre.is_empty())))
                .then_some((parsed, release))
        })
        .max_by(|a, b| a.0.cmp_precedence(&b.0))
        .map(|(_, release)| release)
        .context("no eligible release found; use --prerelease to include release candidates")
}

fn client() -> Result<Client> {
    Ok(Client::builder()
        .user_agent(concat!("localshelld/", env!("LOCALSHELLD_VERSION")))
        .https_only(true)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let url = attempt.url();
            let permitted = matches!(
                url.host_str(),
                Some(
                    "github.com"
                        | "api.github.com"
                        | "release-assets.githubusercontent.com"
                        | "objects.githubusercontent.com"
                )
            );
            if attempt.previous().len() >= 5 || url.scheme() != "https" || !permitted {
                attempt.error("unexpected release redirect")
            } else {
                attempt.follow()
            }
        }))
        .build()?)
}

fn read_bounded(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "response exceeds size limit");
    Ok(bytes)
}

fn query(client: &Client, url: &str) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .context("unable to query GitHub; check network/proxy settings")?
        .error_for_status()
        .context("GitHub query failed (public API rate limits may apply)")?;
    read_bounded(response, MAX_JSON)
}

fn find_release(client: &Client, options: &Options) -> Result<Release> {
    if let Some(tag) = &options.tag {
        version(tag)?; // Also prevents path/query injection.
        let release: Release =
            serde_json::from_slice(&query(client, &format!("{API}/releases/tags/{tag}"))?)?;
        ensure!(
            !release.draft && release.tag_name == *tag,
            "unexpected or draft release"
        );
        return Ok(release);
    }
    let mut releases = Vec::new();
    for page in 1..=20 {
        let batch: Vec<Release> = serde_json::from_slice(&query(
            client,
            &format!("{API}/releases?per_page=100&page={page}"),
        )?)?;
        let done = batch.len() < 100;
        releases.extend(batch);
        if done {
            return select_release(releases, options.prerelease);
        }
    }
    bail!("release history exceeds query limit; select an exact --tag")
}

fn platform() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Ok("windows-x86_64"),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("macos", "aarch64") => Ok("macos-aarch64"),
        ("macos", "x86_64") => Ok("macos-x86_64"),
        _ => bail!("no official release asset for this build target"),
    }
}

fn asset_for(release: &Release, platform: &str) -> Result<(usize, String)> {
    let extension = if platform.starts_with("windows-") {
        ".zip"
    } else {
        ".tar.gz"
    };
    let archive = format!("localshelld-{platform}{extension}");
    let raw = format!(
        "localshelld-{platform}{}",
        if platform.starts_with("windows-") {
            ".exe"
        } else {
            ""
        }
    );
    for name in [archive, raw] {
        let matches: Vec<_> = release
            .assets
            .iter()
            .enumerate()
            .filter(|(_, asset)| asset.name == name)
            .collect();
        ensure!(matches.len() <= 1, "duplicate release asset {name}");
        if let Some((index, _)) = matches.first() {
            return Ok((*index, name));
        }
    }
    bail!("release {} has no asset for {platform}", release.tag_name)
}

fn asset_response(client: &Client, asset: &Asset) -> Result<reqwest::blocking::Response> {
    let url = reqwest::Url::parse(&asset.browser_download_url)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("github.com")
            && url.port().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && url
                .path()
                .starts_with(&format!("/{REPOSITORY}/releases/download/")),
        "untrusted release asset URL"
    );
    Ok(client.get(url).send()?.error_for_status()?)
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn checksum_from_manifest(text: &str, name: &str) -> Result<String> {
    let mut found = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() == 2 && fields[1].trim_start_matches('*') == name {
            ensure!(
                found.is_none() && valid_hash(fields[0]),
                "invalid or duplicate SHA256SUMS entry"
            );
            found = Some(fields[0].to_ascii_lowercase());
        }
    }
    found.context("asset is missing from SHA256SUMS")
}

fn expected_hash(client: &Client, release: &Release, asset: &Asset) -> Result<String> {
    let digest = asset
        .digest
        .as_deref()
        .map(|value| {
            let hash = value
                .strip_prefix("sha256:")
                .context("unsupported asset digest")?;
            ensure!(valid_hash(hash), "invalid asset digest");
            Ok::<_, anyhow::Error>(hash.to_ascii_lowercase())
        })
        .transpose()?;
    let manifests: Vec<_> = release
        .assets
        .iter()
        .filter(|asset| asset.name == "SHA256SUMS")
        .collect();
    ensure!(manifests.len() <= 1, "duplicate SHA256SUMS asset");
    let manifest = manifests
        .first()
        .map(|asset_checksums| {
            let bytes = read_bounded(asset_response(client, asset_checksums)?, 64 * 1024)?;
            checksum_from_manifest(std::str::from_utf8(&bytes)?, &asset.name)
        })
        .transpose()?;
    if let (Some(digest), Some(manifest)) = (&digest, &manifest) {
        ensure!(digest == manifest, "GitHub digest and SHA256SUMS disagree");
    }
    digest
        .or(manifest)
        .context("release has no SHA-256 verification data; refusing update")
}

fn hash_file(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    io::copy(&mut File::open(path)?, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn copy_bounded(mut reader: impl Read, path: &Path) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let copied = io::copy(&mut reader.by_ref().take(MAX_DOWNLOAD + 1), &mut file)?;
    ensure!(
        copied > 0 && copied <= MAX_DOWNLOAD,
        "empty or oversized release file"
    );
    file.sync_all()?;
    Ok(())
}

fn unpack(archive: &Path, name: &str, platform: &str, destination: &Path) -> Result<()> {
    let binary = if platform.starts_with("windows-") {
        "localshelld.exe"
    } else {
        "localshelld"
    };
    let expected = format!("localshelld-{platform}/{binary}");
    let mut found = false;
    // Never extract arbitrary archive paths, links, permissions, or ancillary files.
    if name.ends_with(".zip") {
        let mut zip = zip::ZipArchive::new(File::open(archive)?)?;
        ensure!(zip.len() <= 100, "too many archive entries");
        for index in 0..zip.len() {
            let mut entry = zip.by_index(index)?;
            if entry.name() != expected {
                continue;
            }
            ensure!(
                !found
                    && entry.is_file()
                    && entry
                        .unix_mode()
                        .is_none_or(|mode| mode & 0o170000 != 0o120000),
                "invalid binary archive entry"
            );
            copy_bounded(&mut entry, destination)?;
            found = true;
        }
    } else if name.ends_with(".tar.gz") {
        let decoder = flate2::read::GzDecoder::new(File::open(archive)?);
        let mut tar = tar::Archive::new(decoder.take(MAX_DOWNLOAD + 1));
        for (index, entry) in tar.entries()?.enumerate() {
            ensure!(index < 100, "too many archive entries");
            let mut entry = entry?;
            if entry.path()?.as_ref() != Path::new(&expected) {
                continue;
            }
            ensure!(
                !found && entry.header().entry_type().is_file(),
                "invalid binary archive entry"
            );
            copy_bounded(&mut entry, destination)?;
            found = true;
        }
    } else {
        copy_bounded(File::open(archive)?, destination)?;
        found = true;
    }
    ensure!(found, "archive does not contain the expected binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

pub(super) fn output(command: &mut Command) -> Result<Output> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start {command:?}"))?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out = thread::spawn(move || read_bounded(stdout, 64 * 1024));
    let err = thread::spawn(move || read_bounded(stderr, 64 * 1024));
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("command timed out: {command:?}");
        }
        thread::sleep(Duration::from_millis(50));
    };
    Ok(Output {
        status,
        stdout: out
            .join()
            .map_err(|_| anyhow::anyhow!("stdout reader failed"))??,
        stderr: err
            .join()
            .map_err(|_| anyhow::anyhow!("stderr reader failed"))??,
    })
}

pub(super) fn checked(command: &mut Command) -> Result<String> {
    let result = output(command)?;
    ensure!(
        result.status.success(),
        "{} failed: {}",
        command.get_program().to_string_lossy(),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}

fn probe(binary: &Path) -> Result<String> {
    let text = checked(Command::new(binary).arg("--version"))?;
    let value = text
        .trim()
        .strip_prefix("localshelld ")
        .context("unexpected binary version response")?;
    version(value)?;
    Ok(value.to_owned())
}

fn lock(target: &Path) -> Result<File> {
    let path = target.with_file_name(format!(
        "{}.update.lock",
        target.file_name().unwrap().to_string_lossy()
    ));
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "unsafe updater lock path"
        );
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.try_lock_exclusive()
        .context("another update is in progress")?;
    Ok(file)
}

pub fn run(options: Options) -> Result<()> {
    ensure!(
        options.check || std::env::var_os("LOCALSHELLD_SESSION").is_none(),
        "updates run from an independent Administrator/root terminal; --check is also available inside a localshelld session"
    );
    let client = client()?;
    let release = find_release(&client, &options)?;
    let wanted = version(&release.tag_name)?;
    let current = version(localshelld::VERSION)?;
    let platform = platform()?;
    let (index, asset_name) = asset_for(&release, platform)?;
    println!(
        "Current: {} ({})\nSelected: {}\nAsset: {}",
        localshelld::VERSION,
        localshelld::COMMIT,
        release.tag_name,
        asset_name
    );
    if wanted.cmp_precedence(&current).is_eq() {
        println!("Already at the selected version.");
        return Ok(());
    }
    if wanted.cmp_precedence(&current).is_lt() && !options.allow_downgrade {
        if options.check {
            println!("No newer eligible release available.");
            return Ok(());
        }
        bail!("refusing downgrade; select --tag with --allow-downgrade explicitly");
    }
    if options.check {
        println!("Update available; no files or services were changed.");
        return Ok(());
    }
    ensure!(
        super::is_elevated()?,
        "updating requires Administrator/root; --check does not"
    );
    let target = std::env::current_exe()?.canonicalize()?;
    service::validate_target(&target)?;
    let _lock = lock(&target)?;
    let installed = service::discover(&target)?;
    let temp = tempfile::Builder::new()
        .prefix(".localshelld-update-")
        .tempdir_in(target.parent().unwrap())?;
    service::protect_staging(temp.path())?;
    let archive = temp.path().join("download");
    let new = temp
        .path()
        .join(if cfg!(windows) { "new.exe" } else { "new" });
    let asset = &release.assets[index];
    let expected = expected_hash(&client, &release, asset)?;
    println!("Downloading and verifying {}...", asset.name);
    copy_bounded(asset_response(&client, asset)?, &archive)?;
    ensure!(
        hash_file(&archive)? == expected,
        "download SHA-256 mismatch; service was not stopped"
    );
    unpack(&archive, &asset_name, platform, &new)?;
    service::validate_target(&new)?;
    ensure!(
        version(&probe(&new)?)? == wanted,
        "downloaded binary does not report the selected release version; old RC builds lack embedded tags and cannot be installed automatically"
    );
    let plan = Plan {
        target,
        version: wanted.to_string(),
        original_hash: hash_file(&std::env::current_exe()?)?,
        new_hash: hash_file(&new)?,
        service: installed,
    };
    fs::remove_file(archive)?;
    println!(
        "Verified. Updating will interrupt sessions and invalidate runtime tokens if the service is running."
    );
    #[cfg(windows)]
    return launch_helper(temp, plan, _lock);
    #[cfg(unix)]
    {
        // Keep both recovery binaries even when restart/rollback fails.
        let stage = temp.keep();
        apply(&plan, &stage)?;
        println!(
            "Updated to {}. Previous binary: {}",
            plan.version,
            stage.join("previous").display()
        );
        Ok(())
    }
}

trait Lifecycle {
    fn stop(&self) -> Result<()>;
    fn start_and_verify(&self, version: Option<&str>) -> Result<()>;
}

fn replace(source: &Path, target: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::rename(source, target)?; // Both are on the target filesystem: atomic name replacement.
    #[cfg(windows)]
    {
        // Windows rename replaces an existing regular file after its image
        // mappings close. Never delete the destination as a fallback.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match fs::rename(source, target) {
                Ok(()) => break,
                Err(error)
                    if matches!(error.raw_os_error(), Some(5 | 32))
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(100))
                }
                Err(error) => return Err(error).context(
                    "binary is in use or replacement failed; stop foreground localshelld processes",
                ),
            }
        }
    }
    sync_directory(target.parent().unwrap())?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(windows)]
    let _ = path;
    Ok(())
}

fn transaction(
    target: &Path,
    stage: &Path,
    lifecycle: Option<&dyn Lifecycle>,
    expected: &str,
) -> Result<()> {
    let new = stage.join(if cfg!(windows) { "new.exe" } else { "new" });
    let backup = stage.join("previous");
    // create_new avoids following a pre-existing link or overwriting a recovery copy.
    copy_bounded(File::open(target)?, &backup)?;
    fs::set_permissions(&backup, fs::metadata(target)?.permissions())?;
    sync_directory(stage)?;
    if let Some(service) = lifecycle
        && let Err(error) = service.stop()
    {
        let restored = service.start_and_verify(None);
        bail!("service stop failed: {error:#}; original-service recovery: {restored:?}");
    }
    let result = replace(&new, target).and_then(|()| {
        if let Some(service) = lifecycle {
            service.start_and_verify(Some(expected))
        } else {
            Ok(())
        }
    });
    if let Err(error) = result {
        // A failed rename can leave the old file completely untouched (e.g. a
        // Windows foreground process still maps it). Do not try to overwrite
        // that intact file again just to roll back a change that never happened.
        if hash_file(target).ok() == Some(hash_file(&backup)?) {
            if let Some(service) = lifecycle {
                service
                    .start_and_verify(None)
                    .context("binary unchanged, but original service did not recover")?;
            }
            bail!("update failed; original binary was preserved: {error:#}");
        }
        // Never replace a still-running failed new service or restart over it.
        if let Some(service) = lifecycle {
            service.stop().context(format!(
                "update failed ({error:#}); unable to stop for rollback; backup: {}",
                backup.display()
            ))?;
        }
        let rollback = stage.join("rollback");
        copy_bounded(File::open(&backup)?, &rollback)?;
        fs::set_permissions(&rollback, fs::metadata(&backup)?.permissions())?;
        replace(&rollback, target).context(format!(
            "update failed ({error:#}); rollback failed; backup: {}",
            backup.display()
        ))?;
        if let Some(service) = lifecycle {
            service
                .start_and_verify(None)
                .context("old binary restored, but original service did not recover")?;
        }
        bail!("update failed and the previous binary was restored: {error:#}");
    }
    Ok(())
}

fn apply(plan: &Plan, stage: &Path) -> Result<()> {
    service::validate_target(&plan.target)?;
    ensure!(
        hash_file(&plan.target)? == plan.original_hash,
        "installed binary changed since preparation"
    );
    ensure!(
        hash_file(&stage.join(if cfg!(windows) { "new.exe" } else { "new" }))? == plan.new_hash,
        "staged binary changed since verification"
    );
    let current_service = service::discover(&plan.target)?;
    ensure!(
        current_service == plan.service,
        "service registration/state changed since preparation; retry update"
    );
    let active = plan.service.as_ref().filter(|service| service.was_running);
    transaction(
        &plan.target,
        stage,
        active.map(|service| service as &dyn Lifecycle),
        &plan.version,
    )
}

#[cfg(windows)]
fn launch_helper(temp: tempfile::TempDir, plan: Plan, update_lock: File) -> Result<()> {
    use std::os::windows::process::CommandExt;
    let helper = temp.path().join("helper.exe");
    fs::copy(std::env::current_exe()?, &helper)?;
    service::validate_target(&helper)?;
    let plan_path = temp.path().join("plan.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&plan_path)?;
    file.write_all(&serde_json::to_vec(&plan)?)?;
    file.sync_all()?;
    let parent = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(temp.path().join("parent.lock"))?;
    parent.lock_exclusive()?;
    let log_path = temp.path().join("update.log");
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&log_path)?;
    Command::new(&helper)
        .arg("apply-update")
        .arg(&plan_path)
        .creation_flags(0x08000000) // CREATE_NO_WINDOW: no visible helper console.
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    let stage = temp.keep();
    println!(
        "Update handed to the local helper. Completion/error log: {}\nRecovery directory: {}",
        log_path.display(),
        stage.display()
    );
    // Keep locks until process termination so the helper never stops the service
    // or replaces the executable while this CLI is still executing.
    std::hint::black_box((&parent, &update_lock));
    std::process::exit(0);
}

#[cfg(windows)]
pub fn apply_helper(plan_path: &Path) -> Result<()> {
    ensure!(
        super::is_elevated()?,
        "update helper requires Administrator"
    );
    let executable = std::env::current_exe()?.canonicalize()?;
    let stage = executable.parent().context("missing helper directory")?;
    ensure!(
        executable
            .file_name()
            .is_some_and(|name| name == "helper.exe")
            && plan_path.canonicalize()? == stage.join("plan.json"),
        "helper must run from its own prepared update directory"
    );
    service::validate_target(&executable)?;
    let parent = OpenOptions::new()
        .read(true)
        .write(true)
        .open(stage.join("parent.lock"))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while parent.try_lock_exclusive().is_err() {
        ensure!(
            Instant::now() < deadline,
            "parent CLI did not exit; no changes made"
        );
        thread::sleep(Duration::from_millis(100));
    }
    let plan: Plan = serde_json::from_slice(&read_bounded(File::open(plan_path)?, 64 * 1024)?)?;
    ensure!(
        plan.target.parent() == stage.parent(),
        "update target is not beside staging directory"
    );
    let _lock = lock(&plan.target)?;
    println!("Applying verified version {}...", plan.version);
    apply(&plan, stage)?;
    println!(
        "SUCCESS: updated to {}. Previous binary: {}",
        plan.version,
        stage.join("previous").display()
    );
    Ok(())
}

#[cfg(test)]
mod tests;
