use super::*;
use std::{cell::RefCell, io::Write};

fn release(tag: &str, prerelease: bool, draft: bool) -> Release {
    Release {
        tag_name: tag.into(),
        prerelease,
        draft,
        assets: vec![],
    }
}

#[test]
fn selects_by_semver_not_api_order_or_mislabelled_rc() {
    let versions = || {
        vec![
            release("v0.1.0-rc.10.1", false, false),
            release("v0.1.0-rc.9.1", true, false),
            release("v0.0.9", false, false),
            release("v9.0.0", false, true),
        ]
    };
    assert_eq!(
        select_release(versions(), false).unwrap().tag_name,
        "v0.0.9"
    );
    assert_eq!(
        select_release(versions(), true).unwrap().tag_name,
        "v0.1.0-rc.10.1"
    );
    assert!(select_release(vec![release("v0.1.0-rc.8.1", false, false)], false).is_err());
    assert!(version("../latest?x=y").is_err());
}

#[test]
fn chooses_only_the_requested_platform_asset() {
    let mut release = release("v1.0.0", false, false);
    for name in [
        "sudoserver-windows-x86_64.exe",
        "sudoserver-windows-x86_64.zip",
        "sudoserver-linux-x86_64.tar.gz",
    ] {
        release.assets.push(Asset {
            name: name.into(),
            browser_download_url: String::new(),
            digest: None,
        });
    }
    assert_eq!(
        asset_for(&release, "windows-x86_64").unwrap().1,
        "sudoserver-windows-x86_64.zip"
    );
    assert!(asset_for(&release, "macos-aarch64").is_err());
}

#[test]
fn checksum_requires_exact_unique_filename_and_valid_digest() {
    let hash = "ab".repeat(32);
    assert_eq!(
        checksum_from_manifest(&format!("{hash}  target.zip\n"), "target.zip").unwrap(),
        hash
    );
    assert_eq!(
        checksum_from_manifest(&format!("{hash} *target.zip\n"), "target.zip").unwrap(),
        hash
    );
    assert!(checksum_from_manifest(&format!("{hash}  evil-target.zip"), "target.zip").is_err());
    assert!(checksum_from_manifest("abc  target.zip", "target.zip").is_err());
    assert!(
        checksum_from_manifest(
            &format!("{hash} target.zip\n{hash} target.zip"),
            "target.zip"
        )
        .is_err()
    );
}

#[test]
fn bounded_reads_reject_oversized_data() {
    assert_eq!(read_bounded(&b"abc"[..], 3).unwrap(), b"abc");
    assert!(read_bounded(&b"abcd"[..], 3).is_err());
}

#[test]
fn rejects_external_asset_url_before_network_access() {
    let asset = Asset {
        name: "evil".into(),
        browser_download_url: "https://example.org/tool.exe".into(),
        digest: None,
    };
    assert!(asset_response(&client().unwrap(), &asset).is_err());
}

#[test]
fn zip_extracts_only_exact_binary_not_path_traversal() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("download");
    let mut archive = zip::ZipWriter::new(File::create(&path).unwrap());
    let options = zip::write::SimpleFileOptions::default();
    archive.start_file("../outside", options).unwrap();
    archive.write_all(b"bad").unwrap();
    archive
        .start_file("SudoServer-windows-x86_64/sudoserver.exe", options)
        .unwrap();
    archive.write_all(b"binary").unwrap();
    archive.finish().unwrap();
    let destination = temp.path().join("new");
    unpack(&path, "asset.zip", "windows-x86_64", &destination).unwrap();
    assert_eq!(fs::read(destination).unwrap(), b"binary");
    assert!(!temp.path().parent().unwrap().join("outside").exists());
}

#[test]
fn tar_rejects_symbolic_link_binary() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("download");
    let gzip =
        flate2::write::GzEncoder::new(File::create(&path).unwrap(), flate2::Compression::default());
    let mut archive = tar::Builder::new(gzip);
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    archive
        .append_link(
            &mut header,
            "SudoServer-linux-x86_64/sudoserver",
            "/etc/passwd",
        )
        .unwrap();
    archive.into_inner().unwrap().finish().unwrap();
    assert!(
        unpack(
            &path,
            "asset.tar.gz",
            "linux-x86_64",
            &temp.path().join("new")
        )
        .is_err()
    );
}

struct MockService {
    calls: RefCell<Vec<String>>,
    fail_new: bool,
    fail_stop: bool,
}

impl Lifecycle for MockService {
    fn stop(&self) -> Result<()> {
        self.calls.borrow_mut().push("stop".into());
        ensure!(!self.fail_stop, "injected stop failure");
        Ok(())
    }
    fn start_and_verify(&self, version: Option<&str>) -> Result<()> {
        self.calls.borrow_mut().push(format!("start:{version:?}"));
        ensure!(
            !self.fail_new || version.is_none(),
            "injected new-version health failure"
        );
        Ok(())
    }
}

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("sudoserver");
    let stage = temp.path().join("stage");
    fs::create_dir(&stage).unwrap();
    fs::write(&target, b"old binary").unwrap();
    fs::write(
        stage.join(if cfg!(windows) { "new.exe" } else { "new" }),
        b"new binary",
    )
    .unwrap();
    (temp, target, stage)
}

#[test]
fn successful_transaction_preserves_backup_and_restarts_once() {
    let (_temp, target, stage) = fixture();
    let service = MockService {
        calls: RefCell::default(),
        fail_new: false,
        fail_stop: false,
    };
    transaction(&target, &stage, Some(&service), "1.0.0").unwrap();
    assert_eq!(fs::read(target).unwrap(), b"new binary");
    assert_eq!(fs::read(stage.join("previous")).unwrap(), b"old binary");
    assert_eq!(*service.calls.borrow(), ["stop", "start:Some(\"1.0.0\")"]);
}

#[test]
fn failed_health_check_restores_original_and_restarts_it() {
    let (_temp, target, stage) = fixture();
    let service = MockService {
        calls: RefCell::default(),
        fail_new: true,
        fail_stop: false,
    };
    assert!(transaction(&target, &stage, Some(&service), "1.0.0").is_err());
    assert_eq!(fs::read(target).unwrap(), b"old binary");
    assert_eq!(
        *service.calls.borrow(),
        ["stop", "start:Some(\"1.0.0\")", "stop", "start:None"]
    );
}

#[test]
fn stop_failure_never_changes_binary() {
    let (_temp, target, stage) = fixture();
    let service = MockService {
        calls: RefCell::default(),
        fail_new: false,
        fail_stop: true,
    };
    assert!(transaction(&target, &stage, Some(&service), "1.0.0").is_err());
    assert_eq!(fs::read(target).unwrap(), b"old binary");
    assert_eq!(*service.calls.borrow(), ["stop", "start:None"]);
}

#[test]
fn inactive_or_uninstalled_service_is_not_started() {
    let (_temp, target, stage) = fixture();
    transaction(&target, &stage, None, "1.0.0").unwrap();
    assert_eq!(fs::read(target).unwrap(), b"new binary");
}

#[cfg(unix)]
#[test]
fn atomic_replacement_keeps_old_open_file_readable() {
    let (_temp, target, stage) = fixture();
    let mut old = File::open(&target).unwrap();
    transaction(&target, &stage, None, "1.0.0").unwrap();
    let mut bytes = Vec::new();
    old.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"old binary");
    assert_eq!(fs::read(target).unwrap(), b"new binary");
}

#[test]
fn update_lock_excludes_concurrent_updates() {
    let (_temp, target, _stage) = fixture();
    let first = lock(&target).unwrap();
    assert!(lock(&target).is_err());
    drop(first);
    assert!(lock(&target).is_ok());
}

#[test]
fn missing_staged_binary_leaves_original_and_recovers_service() {
    let (_temp, target, stage) = fixture();
    fs::remove_file(stage.join(if cfg!(windows) { "new.exe" } else { "new" })).unwrap();
    let service = MockService {
        calls: RefCell::default(),
        fail_new: false,
        fail_stop: false,
    };
    assert!(transaction(&target, &stage, Some(&service), "1.0.0").is_err());
    assert_eq!(fs::read(target).unwrap(), b"old binary");
    assert_eq!(*service.calls.borrow(), ["stop", "start:None"]);
}

#[cfg(windows)]
#[test]
fn windows_acl_check_accepts_protected_system_binary_read_only() {
    let root = std::env::var_os("SystemRoot").unwrap();
    let binary = Path::new(&root)
        .join("System32/cmd.exe")
        .canonicalize()
        .unwrap();
    service::validate_target(&binary).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_acl_check_rejects_user_writable_installation() {
    let (_temp, target, _stage) = fixture();
    assert!(service::validate_target(&target.canonicalize().unwrap()).is_err());
}
