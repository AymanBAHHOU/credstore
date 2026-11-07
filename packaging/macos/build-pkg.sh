#!/usr/bin/env bash
# Build dist/credstore-VERSION.pkg from release binaries (macOS, pkgbuild). Unsigned
# unless SIGN_IDENTITY names a "Developer ID Installer" certificate in the keychain.
# Run after `cargo build --release -p credstore -p credstored`.
#
# The payload is /usr/local/bin/credstore{,d} and /usr/local/share/credstore (install.sh,
# launchd plists, starter policy). The postinstall script runs install.sh --package.
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
install -d "$root/usr/local/bin" "$root/usr/local/share/credstore"
install -m 0755 target/release/credstore target/release/credstored "$root/usr/local/bin/"
install -m 0755 deploy/install.sh "$root/usr/local/share/credstore/"
install -m 0644 deploy/policy.toml deploy/dev.credstore.daemon.plist \
    deploy/dev.credstore.rundir.plist "$root/usr/local/share/credstore/"
# The desktop app (M10), when built (cargo build --release in app/), as a minimal bundle.
if [ -x app/target/release/credstore-app ]; then
    bundle="$root/Applications/credstore.app/Contents"
    install -d "$bundle/MacOS" "$bundle/Resources"
    install -m 0755 app/target/release/credstore-app "$bundle/MacOS/credstore-app"
    install -m 0644 app/icons/icon.png "$bundle/Resources/icon.png"
    sed "s/@VERSION@/$VERSION/g" packaging/macos/Info.plist >"$bundle/Info.plist"
    echo "desktop app included"
fi
chmod 0755 packaging/macos/scripts/postinstall
mkdir -p dist
sign=()
if [ -n "${SIGN_IDENTITY:-}" ]; then sign=(--sign "$SIGN_IDENTITY"); fi
pkgbuild --root "$root" --identifier dev.credstore --version "$VERSION" \
    --scripts packaging/macos/scripts --install-location / ${sign[@]+"${sign[@]}"} \
    "dist/credstore-$VERSION.pkg"
ls -l dist/
