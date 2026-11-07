#!/bin/sh
# .deb prerm / .rpm %preun. Stop and remove the service on removal, not on upgrade
# (deb: "remove"; rpm: 0). The vault, policy, audit log, users and groups are kept.
set -e
case "$1" in
remove | 0) /usr/lib/credstore/install.sh --package --bin /usr/bin --uninstall ;;
*) ;;
esac
