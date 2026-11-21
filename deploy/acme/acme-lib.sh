# Shared certificate checks for the AWAI-465 renewer and receiver.
# POSIX sh, GNU coreutils and OpenSSL >= 1.1.1. Sourced, never executed.
# Functions print one short reason on stderr and return non-zero on failure.
# Nothing here reads or prints credentials.

acme_die() { printf 'error %s\n' "$*" >&2; exit "${ACME_EXIT:-1}"; }

# acme_secret_file PATH: regular file, not a symlink, readable by the caller
# and by nobody else. Accepted: owner-only (400/600) owned by the caller, as
# systemd LoadCredential= provides; or root-owned 440 with the caller's group,
# as a Kubernetes Secret mounted with fsGroup and defaultMode 0440 provides.
acme_secret_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || { echo "missing-secret-file" >&2; return 1; }
    case "$(stat -c '%u %g %a' "$1")" in
    "$(id -u) "*" 400"|"$(id -u) "*" 600"|"0 $(id -g) 440") return 0 ;;
    esac
    echo "secret-file-owner-or-mode" >&2
    return 1
}

# acme_exec_file PATH: an executable whose integrity is pinned by digest. It
# may be owned by the job user (downloaded into its state volume), but must
# not be writable by group or others.
acme_exec_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || { echo "missing-executable" >&2; return 1; }
    case "$(stat -c '%a' "$1")" in *[2367]?|*[2367]) echo "executable-writable" >&2; return 1 ;; esac
}

# acme_trusted_file PATH: configuration that the service sources or executes
# must be owned by root and not writable by group or others.
acme_trusted_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || { echo "missing-trusted-file" >&2; return 1; }
    owner=$(stat -c '%u' "$1"); mode=$(stat -c '%a' "$1")
    if [ "$owner" != 0 ] && [ "${ACME_TEST_ALLOW_NONROOT:-0}" != 1 ]; then
        echo "trusted-file-not-root-owned" >&2; return 1
    fi
    case "$mode" in *[2367]?|*[2367]) echo "trusted-file-writable" >&2; return 1 ;; esac
    return 0
}

acme_sha256() { sha256sum "$1" | cut -d' ' -f1; }

# acme_split BUNDLE DIR: write DIR/leaf.pem, DIR/chain.pem, DIR/key.pem from a
# PEM stream holding certificates (leaf first) and exactly one private key.
acme_split() {
    awk -v d="$2" '
        /^-----BEGIN CERTIFICATE-----$/ { n++; f = (n == 1) ? d "/leaf.pem" : d "/chain.pem"; c = 1 }
        /^-----BEGIN (EC |RSA )?PRIVATE KEY-----$/ { k++; f = d "/key.pem"; c = 1 }
        c { print > f }
        /^-----END / { c = 0 }
        END { if (n < 2 || k != 1) exit 3 }
    ' "$1" || { echo "bundle-shape" >&2; return 1; }
}

# acme_cert_id DIR: identity of the certificate chain both ends agree on.
acme_cert_id() { cat "$1/leaf.pem" "$1/chain.pem" | sha256sum | cut -d' ' -f1; }

acme_epoch() { date -u -d "$1" +%s; }

acme_not_after() {
    acme_epoch "$(openssl x509 -in "$1" -noout -enddate | sed 's/^notAfter=//')"
}

# acme_verify DIR DOMAIN CA MIN_DAYS
# CA: "system" (OpenSSL default trust store), "none" (skip the trust check;
# only for the LE staging profile, recorded as unverified), or a PEM file.
# Prints "chain=verified" or "chain=unverified" on success.
acme_verify() {
    d=$1 domain=$2 ca=$3 min_days=$4
    san=$(openssl x509 -in "$d/leaf.pem" -noout -ext subjectAltName 2>/dev/null \
          | sed -n '2,$p' | tr -d ' ')
    [ "$san" = "DNS:$domain" ] || { echo "san-mismatch" >&2; return 1; }
    openssl x509 -in "$d/leaf.pem" -noout -checkend $((min_days * 86400)) >/dev/null \
        || { echo "expires-within-${min_days}d" >&2; return 1; }
    a=$(openssl x509 -in "$d/leaf.pem" -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum)
    b=$(openssl pkey -in "$d/key.pem" -pubout -outform DER 2>/dev/null | sha256sum)
    [ "$a" = "$b" ] || { echo "key-mismatch" >&2; return 1; }
    case "$ca" in
    none) echo "chain=unverified"; return 0 ;;
    system) set -- ;;
    *) set -- -CAfile "$ca" ;;
    esac
    openssl verify "$@" -purpose sslserver -verify_hostname "$domain" \
        -untrusted "$d/chain.pem" "$d/leaf.pem" >/dev/null 2>&1 \
        || { echo "chain-untrusted" >&2; return 1; }
    echo "chain=verified"
}

# Single-writer lock without flock(1): mkdir is atomic. A lock left by a dead
# process is taken over only when its recorded PID no longer exists.
acme_lock() {
    if mkdir "$1" 2>/dev/null; then echo $$ > "$1/pid"; return 0; fi
    old=$(cat "$1/pid" 2>/dev/null || true)
    if [ -n "$old" ] && ! kill -0 "$old" 2>/dev/null; then
        rm -rf "$1" && mkdir "$1" && echo $$ > "$1/pid" && return 0
    fi
    echo "locked" >&2
    return 1
}
acme_unlock() { rm -rf "$1"; }

# Keep detail strings in status files to a safe, secret-free alphabet.
acme_clean() { printf '%s' "$*" | tr -c 'A-Za-z0-9 ._:=/-' '_' | cut -c1-160; }
