#!/bin/sh
# AWAI-465 unattended certificate renewer for ipfs.yataverse.com.
#
#   renew.sh production|staging
#
# Runs as the Kubernetes CronJob in deploy/acme/k8s, on a dedicated tainted
# VKE node pool that serves no bytes and shares no node with CI pods. Steps:
#   1. check the config, credentials and the pinned lego binary;
#   2. run lego (DNS-01 via the Cloudflare API with a token scoped to the
#      yataverse.com zone). lego renews only when the certificate is due;
#   3. verify SAN, expiry, key match and chain of the stored certificate;
#   4. push it over the tailnet to every serving target. The target's forced
#      command installs it, runs nginx -t and reload, and reports back;
#   5. write a secret-free status file and exit non-zero (OnFailure alert)
#      when anything is behind.
# Renewal (step 2) never depends on a serving node being online. An offline
# target is retried on the next timer run.
#
# Credentials come only from $CREDENTIALS_DIRECTORY (systemd LoadCredential=,
# or the Secret mount of the Kubernetes CronJob in deploy/acme/k8s):
#   dns.env   CF_DNS_API_TOKEN=... (root-only on disk, never in argv or logs)
#   push_key  SSH key whose authorized_keys entry on each target is forced
#             to receive.sh
# lego gets a minimal environment and no deploy hook, because lego exports
# --env-file values into hook environments.
#
# Exit codes: 0 all in sync, 1 precondition, 2 lego failed, 3 stored cert
# failed verification, 4 cert expires within ALERT_DAYS, 75 a target is behind.
set -eu
umask 077
here=$(dirname "$0")
. "$here/acme-lib.sh"

profile=${1:-}
case "$profile" in production|staging) ;; *) ACME_EXIT=1 acme_die "usage" ;; esac

conf=${ACME_CONF:-/etc/yataverse-acme/renew.conf}
acme_trusted_file "$conf" || acme_die "config"
. "$conf"

: "${DOMAIN:?}" "${LEGO_BIN:?}" "${LEGO_SHA256:?}" "${STATE_DIR:?}"
EMAIL=${EMAIL:-}
ACCOUNT_ID=${ACCOUNT_ID:-yataverse-acme}
DNS_PROVIDER=${DNS_PROVIDER:-cloudflare}
DNS_RESOLVERS=${DNS_RESOLVERS:-1.1.1.1:53,8.8.8.8:53}
RENEW_DAYS=${RENEW_DAYS:-30}
ALERT_DAYS=${ALERT_DAYS:-21}
SSH_BIN=${SSH_BIN:-/usr/bin/ssh}
KNOWN_HOSTS=${KNOWN_HOSTS:-/etc/yataverse-acme/known_hosts}
TARGETS=${TARGETS:-}
SSH_PROXY_COMMAND=${SSH_PROXY_COMMAND:-}
eval "server=\${SERVER_$profile:?}"
eval "chain_ca=\${CHAIN_CA_$profile:-system}"
[ "$DOMAIN" = ipfs.yataverse.com ] || acme_die "domain-not-approved"
case "$DNS_PROVIDER" in cloudflare|exec) ;; *) acme_die "dns-provider" ;; esac
# A staging certificate is never pushed to the production slot and vice versa:
# the receiver gets the profile as its install slot.

cred=${CREDENTIALS_DIRECTORY:?run through systemd LoadCredential}
acme_secret_file "$cred/dns.env" || acme_die "dns-credential"
[ -z "$TARGETS" ] || acme_secret_file "$cred/push_key" || acme_die "push-credential"
acme_exec_file "$LEGO_BIN" || acme_die "lego-binary"
[ "$(acme_sha256 "$LEGO_BIN")" = "$LEGO_SHA256" ] || acme_die "lego-digest"

store=$STATE_DIR/$profile
mkdir -p "$store"
acme_lock "$STATE_DIR/$profile.lock" || acme_die "locked"
work=$(mktemp -d "$STATE_DIR/.work.XXXXXX")
trap 'rm -rf "$work"; acme_unlock "$STATE_DIR/$profile.lock"' EXIT HUP INT TERM

crt=$store/certificates/$DOMAIN.crt
key=$store/certificates/$DOMAIN.key
before=$( [ -f "$crt" ] && acme_sha256 "$crt" || echo none )
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)

set +e
env -i PATH=/usr/bin:/bin HOME="$STATE_DIR" TZ=UTC \
    ${LEGO_CA_CERTIFICATES:+LEGO_CA_CERTIFICATES="$LEGO_CA_CERTIFICATES"} \
    "$LEGO_BIN" run --accept-tos ${EMAIL:+--email "$EMAIL"} --account-id "$ACCOUNT_ID" \
    --server "$server" \
    --domains "$DOMAIN" --key-type EC256 --dns "$DNS_PROVIDER" \
    --dns.resolvers "$DNS_RESOLVERS" ${DNS_DISABLE_ANS:+--dns.propagation.disable-ans} \
    --renew-days "$RENEW_DAYS" --no-random-sleep \
    --path "$store" --env-file "$cred/dns.env" --log.format text \
    > "$work/lego.log" 2>&1
lego_rc=$?
set -e
# lego's own log goes to the journal; it holds no token, but drop any line
# naming the credential variables in case a future version echoes config.
grep -v -E 'CF_|CLOUDFLARE_|TOKEN' "$work/lego.log" | tail -n 40 >&2 || true

after=$( [ -f "$crt" ] && acme_sha256 "$crt" || echo none )
renewed=false; [ "$before" = "$after" ] || renewed=true

status() {
    # $1 result, then target JSON fragments in $targets_json
    cat > "$work/status.json" <<EOF
{"profile":"$profile","domain":"$DOMAIN","started":"$started","finished":"$(date -u +%Y-%m-%dT%H:%M:%SZ)",
 "result":"$1","lego_rc":$lego_rc,"renewed":$renewed,"cert_sha256":"$after",
 "not_after":"${not_after_iso:-unknown}","serial":"${serial:-unknown}","issuer":"${issuer:-unknown}",
 "chain":"${chain:-unknown}","targets":[${targets_json:-}]}
EOF
    mv "$work/status.json" "$STATE_DIR/status-$profile.json"
}

if [ "$lego_rc" != 0 ] && [ "$after" = none ]; then status lego-failed; exit 2; fi

cat "$crt" "$key" > "$work/bundle.pem"
if ! acme_split "$work/bundle.pem" "$work" 2>"$work/err" ||
   ! chain=$(acme_verify "$work" "$DOMAIN" "$chain_ca" 0 2>"$work/err"); then
    chain=$(acme_clean "$(cat "$work/err")"); status stored-cert-invalid; exit 3
fi
after=$(acme_cert_id "$work")
not_after_iso=$(date -u -d "@$(acme_not_after "$work/leaf.pem")" +%Y-%m-%dT%H:%M:%SZ)
serial=$(openssl x509 -in "$work/leaf.pem" -noout -serial | sed 's/^serial=//')
issuer=$(acme_clean "$(openssl x509 -in "$work/leaf.pem" -noout -issuer | sed 's/^issuer=//')")

# cert_sha256 is the digest of the normalised leaf+chain PEM, as the receiver
# computes it, so both ends name the certificate the same way.
# Push even when nothing was renewed: it is idempotent, and it is how a target
# that was offline at renewal time catches up.
behind=0; targets_json=
# On Kubernetes the tailnet is reached through the userspace tailscale
# sidecar: ProxyCommand "tailscale --socket=... nc %h %p".
set --
[ -z "$SSH_PROXY_COMMAND" ] || set -- -o "ProxyCommand=$SSH_PROXY_COMMAND"
for t in $TARGETS; do
    name=${t%%=*} dest=${t#*=}
    set +e
    reply=$("$SSH_BIN" -F /dev/null -T -i "$cred/push_key" -o IdentitiesOnly=yes \
        -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS" \
        -o ConnectTimeout=20 -o ServerAliveInterval=10 -o ServerAliveCountMax=3 "$@" \
        "$dest" "install $profile" < "$work/bundle.pem" 2>"$work/ssh.err")
    rc=$?
    set -e
    reply=$(printf '%s' "$reply" | tail -n 1)
    case "$rc:$reply" in
    "0:ok installed $after"|"0:ok unchanged $after") r=${reply#ok }; r=${r%% *} ;;
    255:*) r=unreachable; behind=1; reply=$(tail -n 1 "$work/ssh.err") ;;
    *) r=rejected; behind=1 ;;
    esac
    printf 'target %s %s\n' "$(acme_clean "$name")" "$r" >&2
    targets_json="${targets_json:+$targets_json,}{\"name\":\"$(acme_clean "$name")\",\"result\":\"$r\",\"rc\":$rc,\"detail\":\"$(acme_clean "$reply")\"}"
done

if [ "$lego_rc" != 0 ]; then status lego-failed-kept-current; exit 2; fi
if ! openssl x509 -in "$work/leaf.pem" -noout -checkend $((ALERT_DAYS * 86400)) >/dev/null; then
    status expiry-alert; exit 4
fi
if [ "$behind" = 1 ]; then status target-behind; exit 75; fi
status ok
