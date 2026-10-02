#!/usr/bin/env bash
# Both stable and RC workflows consume the same artifact layout and emit the
# same archive/checksum names. Run from the repository root on the Linux runner.
set -euo pipefail
: "${LOCALSHELLD_RELEASE_TAG:?expected release tag is required}"
mkdir -p assets packages
for platform in windows-x86_64 linux-x86_64 macos-aarch64 macos-x86_64; do
  binary=localshelld
  if [[ "$platform" == windows-* ]]; then binary=localshelld.exe; fi
  source="binaries/localshelld-$platform/$binary"
  test -f "$source" || { echo "$platform artifact is missing" >&2; exit 1; }
  actual="$(tr -d '\r\n' < "binaries/localshelld-$platform/release-version.txt")"
  if [[ "$actual" != "localshelld ${LOCALSHELLD_RELEASE_TAG#v}" ]]; then
    echo "$platform artifact version mismatch; rerun all CI jobs, not only failed jobs" >&2
    exit 1
  fi
  package="localshelld-$platform"
  mkdir -p "packages/$package"
  cp "$source" "packages/$package/"
  cp README.md LICENSE-MIT "packages/$package/"
  if [[ "$platform" == windows-* ]]; then
    (cd packages && zip -qr "../assets/localshelld-$platform.zip" "$package")
  else
    chmod +x "packages/$package/localshelld"
    tar -czf "assets/localshelld-$platform.tar.gz" -C packages "$package"
  fi
done
(cd assets && sha256sum localshelld-* > SHA256SUMS)
