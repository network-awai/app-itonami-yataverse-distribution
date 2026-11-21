#!/bin/sh
# AWAI-465 receiver on a serving nginx node. It is the forced command of the
# renewer's key in ~yataverse-acme-recv/.ssh/authorized_keys:
#
#   restrict,from="<renewer tailnet IP>",command="/usr/local/libexec/yataverse-acme/receive.sh" ssh-ed25519 ...
#
# Accepted SSH_ORIGINAL_COMMAND values (nothing else runs):
#   install production|staging   bundle (leaf, chain, one key) on stdin
#   status  production|staging
#
# install: bounded read, SAN/expiry/key/chain checks, no downgrade, then an
# atomic switch of <LIVE_DIR>/<slot>/current.pem (nginx points
# ssl_certificate and ssl_certificate_key at that single file). For the
# production slot it runs APPLY_CMD (nginx -t, then reload), then checks that
# nginx serves the new leaf on LOCAL_TLS. On any failure it switches back.
# The staging slot is never referenced by nginx and is not applied.
# Replies with one line: "ok installed <id>", "ok unchanged <id>",
# "ok status <id|none> <not_after_epoch>" or "error <reason>".
set -eu
umask 077
here=$(dirname "$0")
. "$here/acme-lib.sh"

reply_error() { printf 'error %s\n' "$1"; exit 1; }

conf=${ACME_RECEIVE_CONF:-/etc/yataverse-acme/receive.conf}
acme_trusted_file "$conf" 2>/dev/null || reply_error config
. "$conf"
: "${DOMAIN:?}" "${LIVE_DIR:?}"
MIN_DAYS=${MIN_DAYS:-7}
MAX_BYTES=${MAX_BYTES:-65536}
APPLY_CMD=${APPLY_CMD:-}
LOCAL_TLS=${LOCAL_TLS:-}
[ "$DOMAIN" = ipfs.yataverse.com ] || reply_error domain-not-approved

set -f
set -- ${SSH_ORIGINAL_COMMAND:-}
set +f
[ "$#" = 2 ] || reply_error usage
action=$1 slot=$2
case "$action:$slot" in
install:production|install:staging|status:production|status:staging) ;;
*) reply_error usage ;;
esac
eval "ca=\${CHAIN_CA_$slot:-system}"

dir=$LIVE_DIR/$slot
mkdir -p "$dir/releases"
link=$dir/current.pem

current_id() {
    t=$(readlink "$link" 2>/dev/null) || { echo none; return; }
    t=${t#releases/}; echo "${t%%/*}"
}

if [ "$action" = status ]; then
    id=$(current_id)
    if [ "$id" = none ]; then echo "ok status none 0"; exit 0; fi
    echo "ok status $id $(acme_not_after "$dir/releases/$id/bundle.pem")"
    exit 0
fi

acme_lock "$dir/.lock" 2>/dev/null || reply_error locked
work=$(mktemp -d "$dir/.work.XXXXXX")
trap 'rm -rf "$work"; acme_unlock "$dir/.lock"' EXIT HUP INT TERM

head -c $((MAX_BYTES + 1)) > "$work/in.pem"
[ "$(wc -c < "$work/in.pem")" -le "$MAX_BYTES" ] || reply_error oversize
acme_split "$work/in.pem" "$work" 2>/dev/null || reply_error bundle-shape
acme_verify "$work" "$DOMAIN" "$ca" "$MIN_DAYS" > /dev/null 2>"$work/err" \
    || reply_error "$(acme_clean "$(cat "$work/err")")"
id=$(acme_cert_id "$work")

old=$(current_id)
if [ "$old" = "$id" ]; then echo "ok unchanged $id"; exit 0; fi
if [ "$old" != none ] &&
   [ "$(acme_not_after "$work/leaf.pem")" -lt "$(acme_not_after "$dir/releases/$old/bundle.pem")" ]; then
    reply_error older-than-installed
fi

rel=$dir/releases/$id
rm -rf "$rel"; mkdir "$rel"
cat "$work/leaf.pem" "$work/chain.pem" "$work/key.pem" > "$rel/bundle.pem"
chmod 600 "$rel/bundle.pem"

switch_to() {   # $1: release id or "none"
    if [ "$1" = none ]; then rm -f "$link"; return; fi
    ln -sfn "releases/$1/bundle.pem" "$link.new"
    mv -fT "$link.new" "$link"
}

served_id_matches() {
    want=$(openssl x509 -in "$work/leaf.pem" -noout -fingerprint -sha256)
    i=0
    while [ "$i" -lt 10 ]; do
        got=$(openssl s_client -connect "$LOCAL_TLS" -servername "$DOMAIN" </dev/null 2>/dev/null \
              | openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)
        [ "$got" = "$want" ] && return 0
        i=$((i + 1)); sleep 1
    done
    return 1
}

switch_to "$id"
if [ "$slot" = production ] && [ -n "$APPLY_CMD" ]; then
    if ! $APPLY_CMD > "$work/apply.log" 2>&1; then
        switch_to "$old"; rm -rf "$rel"
        reply_error apply-failed-rolled-back
    fi
    if [ -n "$LOCAL_TLS" ] && ! served_id_matches; then
        switch_to "$old"; rm -rf "$rel"
        $APPLY_CMD > /dev/null 2>&1 || true
        reply_error served-cert-mismatch-rolled-back
    fi
fi

# Keep the current release and the two newest earlier ones for rollback.
ls -1t "$dir/releases" | grep -v -x "$id" | tail -n +3 | while read -r r; do
    rm -rf "${dir:?}/releases/$r"
done
echo "ok installed $id"
