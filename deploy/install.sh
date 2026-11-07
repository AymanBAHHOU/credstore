#!/usr/bin/env bash
# Install credstore in installed mode (spec 8 and 8.1) on Linux (systemd) or macOS
# (launchd). Run as root:
#
#   sudo ./deploy/install.sh [--from DIR] [--user NAME]
#   sudo ./deploy/install.sh --uninstall
#
#   --from DIR   directory with the credstore and credstored binaries
#                (default: target/release in the repository)
#   --user NAME  the human who approves requests and runs the agent (default: $SUDO_USER)
#   --bin DIR    where the binaries live (default: /usr/local/bin)
#   --package    called by a .deb/.rpm/.pkg: the binaries are already in --bin, the
#                package manager owns them, and a missing --user is not an error
#
# Safe to re-run: existing users, groups, vault, policy and audit log are kept.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
from="$here/../target/release"
human="${SUDO_USER:-}"
uninstall=0
package=0
bin=/usr/local/bin

die() {
    echo "install.sh: $*" >&2
    exit 1
}
say() { echo "==> $*"; }

while [ $# -gt 0 ]; do
    case "$1" in
    --from)
        from="$2"
        shift 2
        ;;
    --user)
        human="$2"
        shift 2
        ;;
    --bin)
        bin="$2"
        shift 2
        ;;
    --package)
        package=1
        shift
        ;;
    --uninstall)
        uninstall=1
        shift
        ;;
    -h | --help)
        sed -n '2,16p' "$0"
        exit 0
        ;;
    *) die "unknown option: $1" ;;
    esac
done

[ "$(id -u)" = 0 ] || die "run as root (sudo)"
os="$(uname -s)"
case "$os" in
Linux)
    data_dir=/var/lib/credstore
    log_dir=/var/log/credstore
    agent_sock=/run/credstore/agent.sock
    svc_user=credstore
    svc_group=credstore
    ;;
Darwin)
    data_dir=/var/db/credstore
    log_dir=/var/log/credstore
    agent_sock=/var/run/credstore/agent.sock
    svc_user=_credstore
    svc_group=_credstore
    ;;
*) die "unsupported OS $os (Windows: use deploy/install.ps1)" ;;
esac

# Wait for the daemon's agent socket, or show its log and fail.
wait_for_daemon() {
    for _ in $(seq 1 100); do
        [ -S "$agent_sock" ] && return 0
        sleep 0.2
    done
    echo "credstored did not create $agent_sock. Its log:" >&2
    if [ "$os" = Linux ]; then
        journalctl -u credstored.service -n 40 --no-pager >&2 || true
    else
        tail -n 40 "$log_dir/credstored.log" >&2 || true
    fi
    exit 1
}

# ------------------------------- uninstall --------------------------------

if [ "$uninstall" = 1 ]; then
    if [ "$os" = Linux ]; then
        systemctl disable --now credstored.service 2>/dev/null || true
        rm -f /etc/systemd/system/credstored.service
        systemctl daemon-reload
    else
        for label in dev.credstore.daemon dev.credstore.rundir; do
            launchctl bootout "system/$label" 2>/dev/null || true
            rm -f "/Library/LaunchDaemons/$label.plist"
        done
    fi
    if [ "$package" = 0 ]; then
        rm -f "$bin/credstore" "$bin/credstored"
    fi
    if [ "$os" = Darwin ]; then
        # The desktop app, if the .pkg installed it.
        if pkgutil --files dev.credstore 2>/dev/null | grep -qx 'Applications/credstore.app'; then
            rm -rf /Applications/credstore.app
        fi
        pkgutil --forget dev.credstore >/dev/null 2>&1 || true
    fi
    say "removed the service and the binaries"
    echo "Kept (delete by hand if you want them gone): $data_dir (vault), /etc/credstore"
    echo "(policy), $log_dir (audit log), the $svc_user user and the credstore-agents and"
    echo "credstore-approvers groups."
    exit 0
fi

# -------------------------------- install ---------------------------------

if [ "$human" = root ]; then
    human=""
    [ "$package" = 1 ] || die "--user should be your normal account, not root"
fi
if [ -z "$human" ]; then
    [ "$package" = 1 ] || die "--user NAME is required when not run through sudo"
    echo "install.sh: no user to add to the credstore groups; later run:" >&2
    echo "  sudo $here/install.sh --package --bin $bin --user NAME" >&2
else
    id "$human" >/dev/null 2>&1 || die "no user $human"
fi

if [ "$package" = 1 ]; then
    for b in credstore credstored; do
        [ -x "$bin/$b" ] || die "missing $bin/$b"
    done
else
    for b in credstore credstored; do
        [ -x "$from/$b" ] || die "missing $from/$b (build with: cargo build --release)"
    done
    say "binaries -> $bin"
    install -d -m 0755 "$bin"
    install -m 0755 "$from/credstore" "$from/credstored" "$bin/"
fi

if [ "$os" = Linux ]; then
    [ -d /run/systemd/system ] ||
        die "systemd is not running (WSL2: set systemd=true under [boot] in /etc/wsl.conf, then run wsl --shutdown)"

    say "users and groups (systemd-sysusers)"
    install -d -m 0755 /etc/sysusers.d
    install -m 0644 "$here/sysusers.conf" /etc/sysusers.d/credstore.conf
    systemd-sysusers /etc/sysusers.d/credstore.conf
    if [ -n "$human" ]; then
        usermod -aG credstore-agents,credstore-approvers "$human"
    fi
else
    # First id in 300-499 that no user or group uses.
    free_id() {
        local used
        used="$( (dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID) | awk '{print $2}')"
        for i in $(seq 300 499); do
            echo "$used" | grep -qx "$i" || {
                echo "$i"
                return 0
            }
        done
        die "no free system id in 300-499"
    }
    ensure_group() {
        dscl . -read "/Groups/$1" >/dev/null 2>&1 ||
            dseditgroup -o create -i "$(free_id)" -r "$2" "$1"
    }

    say "users and groups (dscl)"
    ensure_group _credstore "credstore daemon"
    ensure_group credstore-agents "credstore agents"
    ensure_group credstore-approvers "credstore approvers"
    if ! dscl . -read /Users/_credstore >/dev/null 2>&1; then
        gid="$(dscl . -read /Groups/_credstore PrimaryGroupID | awk '{print $2}')"
        uid="$(free_id)"
        dscl . -create /Users/_credstore
        dscl . -create /Users/_credstore UniqueID "$uid"
        dscl . -create /Users/_credstore PrimaryGroupID "$gid"
        dscl . -create /Users/_credstore UserShell /usr/bin/false
        dscl . -create /Users/_credstore NFSHomeDirectory /var/empty
        dscl . -create /Users/_credstore RealName "credstore daemon"
        dscl . -create /Users/_credstore Password '*'
        dscl . -create /Users/_credstore IsHidden 1
    fi
    for g in credstore-agents credstore-approvers; do
        # The daemon is a member so it can give its sockets to the group.
        dseditgroup -o edit -a _credstore -t user "$g"
        if [ -n "$human" ]; then
            dseditgroup -o edit -a "$human" -t user "$g"
        fi
    done

    say "directories"
    install -d -o _credstore -g _credstore -m 0700 "$data_dir" "$log_dir"
    install -d -o _credstore -g _credstore -m 0755 /var/run/credstore
fi

say "policy (/etc/credstore/policy.toml)"
install -d -o root -g "$svc_group" -m 0750 /etc/credstore
if [ -e /etc/credstore/policy.toml ]; then
    echo "    keeping the existing policy"
    chown "root:$svc_group" /etc/credstore/policy.toml
    chmod 0640 /etc/credstore/policy.toml
else
    install -o root -g "$svc_group" -m 0640 "$here/policy.toml" /etc/credstore/policy.toml
fi

if [ -n "$human" ]; then
    # The daemon lets accounts listed here in directly, so the user need not log out
    # and back in for the new groups to apply (M9).
    users=/etc/credstore/users
    if [ ! -e "$users" ]; then
        {
            echo "# Accounts allowed on the credstore endpoints without a new login,"
            echo "# one per line. Written by the installer; restart credstored after editing."
        } >"$users"
    fi
    grep -qx "$human" "$users" || echo "$human" >>"$users"
    chown "root:$svc_group" "$users"
    chmod 0640 "$users"
fi

say "service"
if [ "$os" = Linux ]; then
    # The unit names /usr/local/bin; point it at --bin.
    sed "s|/usr/local/bin/credstored|$bin/credstored|" "$here/credstored.service"         >/etc/systemd/system/credstored.service
    chmod 0644 /etc/systemd/system/credstored.service
    systemctl daemon-reload
    systemctl enable credstored.service
    systemctl restart credstored.service
else
    for label in dev.credstore.rundir dev.credstore.daemon; do
        launchctl bootout "system/$label" 2>/dev/null && sleep 1 || true
        install -o root -g wheel -m 0644 "$here/$label.plist" /Library/LaunchDaemons/
        launchctl bootstrap system "/Library/LaunchDaemons/$label.plist"
    done
fi
wait_for_daemon

cat <<EOF

credstore is installed and running as $svc_user.

Next, as ${human:-your normal user}:
  1. credstore setup         create the vault and connect Claude Code (asks first)
  2. credstore set NAME      add a secret (the value is prompted for)
  3. credstore grant DIR     let approved commands run in a project folder
  4. credstore doctor        check the install
EOF
