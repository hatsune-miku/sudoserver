#!/usr/bin/env bash
# Both stable and RC workflows consume the same artifact layout and emit the
# same archive/checksum names. Run from the repository root on the Linux runner.
set -euo pipefail
: "${SUDOSERVER_RELEASE_TAG:?expected release tag is required}"
mkdir -p assets packages
for platform in windows-x86_64 linux-x86_64 macos-aarch64 macos-x86_64; do
  binary=sudoserver
  if [[ "$platform" == windows-* ]]; then binary=sudoserver.exe; fi
  source="binaries/sudoserver-$platform/$binary"
  test -f "$source" || { echo "$platform artifact is missing" >&2; exit 1; }
  actual="$(tr -d '\r\n' < "binaries/sudoserver-$platform/release-version.txt")"
  if [[ "$actual" != "sudoserver ${SUDOSERVER_RELEASE_TAG#v}" ]]; then
    echo "$platform artifact version mismatch; rerun all CI jobs, not only failed jobs" >&2
    exit 1
  fi
  package="SudoServer-$platform"
  mkdir -p "packages/$package"
  cp "$source" "packages/$package/"
  cp README.md LICENSE-MIT "packages/$package/"
  if [[ "$platform" == windows-* ]]; then
    (cd packages && zip -qr "../assets/sudoserver-$platform.zip" "$package")
  else
    chmod +x "packages/$package/sudoserver"
    tar -czf "assets/sudoserver-$platform.tar.gz" -C packages "$package"
  fi
done
(cd assets && sha256sum sudoserver-* > SHA256SUMS)
