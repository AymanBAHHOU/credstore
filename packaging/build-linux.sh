#!/usr/bin/env bash
# Build dist/credstore_VERSION_ARCH.deb and dist/credstore-VERSION.ARCH.rpm from release
# binaries. Needs nfpm (go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.41.1).
# Run after `cargo build --release -p credstore -p credstored`.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
case "$(uname -m)" in
x86_64) ARCH=amd64 ;;
aarch64) ARCH=arm64 ;;
*) ARCH="$(uname -m)" ;;
esac
export VERSION ARCH
mkdir -p dist
nfpm package --config packaging/nfpm.yaml --packager deb --target dist/
nfpm package --config packaging/nfpm.yaml --packager rpm --target dist/
# The desktop app (M10), when built (cargo build --release in app/).
if [ -x app/target/release/credstore-app ]; then
    nfpm package --config packaging/nfpm-app.yaml --packager deb --target dist/
    nfpm package --config packaging/nfpm-app.yaml --packager rpm --target dist/
fi
ls -l dist/
