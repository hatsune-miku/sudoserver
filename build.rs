use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-env-changed=LOCALSHELLD_RELEASE_TAG");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    if let Some(reference) = git(&["symbolic-ref", "HEAD"]) {
        println!("cargo:rerun-if-changed=.git/{reference}");
    }
    let commit = git(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let version = std::env::var("LOCALSHELLD_RELEASE_TAG")
        .map(|tag| tag.strip_prefix('v').unwrap_or(&tag).to_owned())
        .unwrap_or_else(|_| format!("{}-dev", std::env::var("CARGO_PKG_VERSION").unwrap()));
    let parsed = semver::Version::parse(&version).expect("invalid semantic release version");
    let package = semver::Version::parse(&std::env::var("CARGO_PKG_VERSION").unwrap()).unwrap();
    assert_eq!(
        (parsed.major, parsed.minor, parsed.patch),
        (package.major, package.minor, package.patch),
        "release tag does not match Cargo package version"
    );
    println!("cargo:rustc-env=LOCALSHELLD_VERSION={version}");
    println!("cargo:rustc-env=LOCALSHELLD_COMMIT={commit}");
}
