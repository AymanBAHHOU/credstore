#!/bin/sh
# .deb postinst / .rpm %post. deb passes "configure" (and others we ignore); rpm passes
# 1 (install) or 2 (upgrade). The user who ran `sudo apt install` / `sudo dnf install`
# is added to the credstore groups.
set -e
case "$1" in
configure | 1 | 2) ;;
*) exit 0 ;;
esac
user="${SUDO_USER:-}"
if [ -n "$user" ] && [ "$user" != root ]; then
    /usr/lib/credstore/install.sh --package --bin /usr/bin --user "$user"
else
    /usr/lib/credstore/install.sh --package --bin /usr/bin
fi
