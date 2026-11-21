#!/bin/sh
# AWAI-465 CronJob entrypoint: fetch the pinned lego into the state volume
# (tarball and binary digests both checked), wait for the tailscale sidecar,
# run renew.sh, print its secret-free status, and keep its exit code.
set -eu
umask 077
. /opt/yataverse-acme/acme-lib.sh
conf=/etc/yataverse-acme/renew.conf
acme_trusted_file "$conf" || acme_die config
. "$conf"
: "${PROFILE:?}" "${LEGO_VERSION:?}" "${LEGO_TARBALL_SHA256:?}" "${LEGO_SHA256:?}" "${LEGO_BIN:?}"

if [ ! -f "$LEGO_BIN" ] || [ "$(acme_sha256 "$LEGO_BIN")" != "$LEGO_SHA256" ]; then
    mkdir -p "$(dirname "$LEGO_BIN")"
    t=$(mktemp -d "$STATE_DIR/.lego.XXXXXX")
    curl -fsSL --proto '=https' --tlsv1.2 --max-time 180 -o "$t/lego.tgz" \
        "https://github.com/go-acme/lego/releases/download/v$LEGO_VERSION/lego_v${LEGO_VERSION}_linux_amd64.tar.gz"
    echo "$LEGO_TARBALL_SHA256  $t/lego.tgz" | sha256sum -c - >/dev/null || acme_die lego-tarball-digest
    tar -xzf "$t/lego.tgz" -C "$t" lego
    [ "$(acme_sha256 "$t/lego")" = "$LEGO_SHA256" ] || acme_die lego-digest
    chmod 755 "$t/lego"
    mv -f "$t/lego" "$LEGO_BIN"
    rm -rf "$t"
fi

# The sidecar starts first (native sidecar), but login can take a moment.
i=0
until /ts-bin/tailscale --socket=/ts-run/tailscaled.sock status >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 60 ] || { echo "tailscale not up after 120s; pushes will fail" >&2; break; }
    sleep 2
done

set +e
sh /opt/yataverse-acme/renew.sh "$PROFILE"
rc=$?
set -e
cat "$STATE_DIR/status-$PROFILE.json" 2>/dev/null || true
exit "$rc"
