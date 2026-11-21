#!/bin/sh
# AWAI-465: enroll a serving nginx node as a push target.
#
#   sudo sh install-receiver.sh RENEWER_TAILNET_IP PUBKEY_FILE          # dry run
#   sudo sh install-receiver.sh RENEWER_TAILNET_IP PUBKEY_FILE --apply
#
# Creates the locked user yataverse-acme-recv, root-owned copies of
# receive.sh, acme-lib.sh and nginx-apply.sh in /usr/local/libexec/yataverse-acme,
# /etc/yataverse-acme/receive.conf, a sudoers rule for nginx-apply.sh only
# (checked with visudo), and one authorized_keys line:
#   restrict,from="<ip>",command="receive.sh" <renewer public key>
# It does not edit nginx: the vhost switch to the pushed certificate is a
# separate reviewed step (runbook step 7). Production changes need approval.
set -eu
[ "$#" -ge 2 ] || { echo "usage: $0 RENEWER_IP PUBKEY_FILE [--apply]" >&2; exit 2; }
ip=$1 pub=$2 apply=${3:-}
case "$ip" in 100.*.*.*) ;; *) echo "renewer IP must be a tailnet 100.x address" >&2; exit 2 ;; esac
key=$(cat "$pub")
case "$key" in "ssh-ed25519 "*) ;; *) echo "expected one ssh-ed25519 public key" >&2; exit 2 ;; esac
[ "$(printf '%s\n' "$key" | wc -l)" = 1 ] || exit 2
src=$(cd "$(dirname "$0")" && pwd)
lib=/usr/local/libexec/yataverse-acme
user=yataverse-acme-recv
home=/var/lib/yataverse-acme
line="restrict,from=\"$ip\",command=\"$lib/receive.sh\" $key"

run() { if [ "$apply" = --apply ]; then "$@"; else echo "would run: $*"; fi; }

[ "$(id -u)" = 0 ] || [ "$apply" != --apply ] || { echo "run as root" >&2; exit 2; }
command -v nginx >/dev/null || echo "warning: nginx not found on PATH" >&2

id "$user" >/dev/null 2>&1 || run useradd --system --home-dir "$home" --create-home \
    --shell /bin/sh --user-group "$user"
run passwd -l "$user"
run install -d -o root -g root -m 0755 "$lib" /etc/yataverse-acme
for f in receive.sh acme-lib.sh nginx-apply.sh; do
    run install -o root -g root -m 0755 "$src/$f" "$lib/$f"
done
if [ ! -e /etc/yataverse-acme/receive.conf ]; then
    conf=$(mktemp)
    cat > "$conf" <<EOF
DOMAIN=ipfs.yataverse.com
LIVE_DIR=$home/live
MIN_DAYS=7
APPLY_CMD="/usr/bin/sudo -n $lib/nginx-apply.sh"
LOCAL_TLS=127.0.0.1:443
CHAIN_CA_production=system
CHAIN_CA_staging=none
EOF
    run install -o root -g root -m 0644 "$conf" /etc/yataverse-acme/receive.conf
    rm -f "$conf"
fi
run install -d -o "$user" -g "$user" -m 0700 "$home/live" "$home/.ssh"
sudo_tmp=$(mktemp)
echo "$user ALL=(root) NOPASSWD: $lib/nginx-apply.sh \"\"" > "$sudo_tmp"
visudo -cf "$sudo_tmp" >/dev/null || { echo "sudoers rule failed visudo" >&2; exit 1; }
run install -o root -g root -m 0440 "$sudo_tmp" /etc/sudoers.d/yataverse-acme
rm -f "$sudo_tmp"
ak=$(mktemp)
echo "$line" > "$ak"
run install -o "$user" -g "$user" -m 0600 "$ak" "$home/.ssh/authorized_keys"
rm -f "$ak"
echo "authorized_keys: $line"
echo "for the renewer's known_hosts (prefix it with this node's tailnet FQDN):"
cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub
