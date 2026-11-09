#!/bin/sh
# .deb postrm / .rpm %postun. Only `apt purge` (deb: "purge") deletes the vault, policy,
# audit log, the service account and the credstore groups; a plain remove, an upgrade
# and every rpm case keep them. install.sh is gone by now, so this does it itself
# (the same steps as install.sh --uninstall --delete-data).
set -e
[ "$1" = purge ] || exit 0
rm -rf /var/lib/credstore /var/log/credstore /etc/credstore /run/credstore
rm -f /etc/sysusers.d/credstore.conf
userdel credstore 2>/dev/null || true
for g in credstore-agents credstore-approvers credstore; do
    groupdel "$g" 2>/dev/null || true
done
