# ipfs.yataverse.com: manual certificate renewal (AWAI-465)

Tracked in [AWAI-465](https://linear.app/kotobalabs/issue/AWAI-465). This is a
**manual** renewal. The owner runs it around **2026-12-20**. It is not automated
renewal. The unattended path (PR #114) stays open and undecided until this is
done.

- Current certificate: SAN `ipfs.yataverse.com`, notAfter **2027-01-29 21:49:17 UTC**,
  SHA-256 of the DER `ea1ad21fefa95707da7132c4ec73e8df29c461041290a4ebcb6bfe9095c85b8d`
  (from `docs/evidence/jun-228-cutover-20261101.json`).
- Hard deadline for this run: **2026-12-30**. The old certificate keeps serving
  until 2027-01-29, so a failed attempt can be retried.
- No API token is created or used. The owner adds the `_acme-challenge` TXT record
  by hand in the Cloudflare dashboard. Cloudflare stays DNS-only: the A record and
  its "DNS only" (grey cloud) setting do not change.
- Nothing in this file is a secret. Do **not** paste the TXT value, the private
  key or any token into Linear, the repo or chat. The TXT value is short-lived, but
  keep it out of the record anyway.

## 0. Preconditions (check on the day)

Run these from the operator Mac:

```sh
# Xavier reachable over the tailnet (it was offline from about 2026-11-07):
ssh -o ConnectTimeout=15 xavier 'hostname; uptime; certbot --version; nginx -v' 2>&1
# The public A record still points at Xavier's WAN address and is not proxied:
dig +short A ipfs.yataverse.com @everton.ns.cloudflare.com   # expect 220.146.177.126
dig +short A ipfs.yataverse.com @1.1.1.1
```

- If the ssh command prints `certbot 0.40.0` and nginx, continue with **path A**.
- If Xavier is still unreachable, use **path B** (§3). Do not move the A record to
  another host as part of this runbook. A route change needs its own approval.

## 1. Path A: renew on Xavier with the existing certbot lineage

All commands run on Xavier (`ssh xavier`).

### 1.1 Record the state before the change

```sh
sudo ls -l /etc/letsencrypt/live/ipfs.yataverse.com/
sudo grep -E '^(authenticator|server|manual_auth_hook|manual_cleanup_hook|pref_challs)' \
  /etc/letsencrypt/renewal/ipfs.yataverse.com.conf
sudo openssl x509 -in /etc/letsencrypt/live/ipfs.yataverse.com/cert.pem -noout \
  -serial -enddate -fingerprint -sha256
```

Write down which `certN.pem` the `live/` symlinks point to. That file is the
rollback target (§1.5).

### 1.2 Issue the certificate (DNS-01, TXT added by hand)

```sh
sudo certbot certonly --manual --preferred-challenges dns \
  --manual-public-ip-logging-ok --force-renewal \
  --cert-name ipfs.yataverse.com -d ipfs.yataverse.com
```

`--force-renewal` is needed because on 12-20 the certificate still has about 40
days left, and certbot otherwise keeps it. `--manual-public-ip-logging-ok` exists
in certbot 0.40 and avoids an extra prompt.

certbot prints a line like
`Please deploy a DNS TXT record under the name _acme-challenge.ipfs.yataverse.com with the following value: <43 characters>`
and waits for Enter. Before pressing Enter:

1. Cloudflare dashboard → `yataverse.com` → DNS → **Add record**: type `TXT`, name
   `_acme-challenge.ipfs`, content = the printed value, TTL `Auto`. Save.
2. In a second terminal, check that **both** authoritative servers and a public
   resolver return it:

   ```sh
   for s in everton.ns.cloudflare.com vivienne.ns.cloudflare.com 1.1.1.1 8.8.8.8; do
     printf '%s: ' "$s"; dig +short TXT _acme-challenge.ipfs.yataverse.com @"$s"
   done
   ```
3. Press Enter in the certbot terminal only when all four return the printed value.

Expected end: `Congratulations! Your certificate and chain have been saved at:
/etc/letsencrypt/live/ipfs.yataverse.com/fullchain.pem`.

If certbot prints nothing and just waits, the stored lineage still uses the
operator hook from JUN-228 (`deploy/dns01_operator_hook.sh`, which waits up to
300 s). In that case the value is in the `value` file inside the state directory
named in `manual_auth_hook` (from §1.1). Publish that value as above, then
`sudo cp <state>/value <state>/ready` within the 300 s.

Then **delete the TXT record** in the Cloudflare dashboard, and check that it is
gone:

```sh
dig +short TXT _acme-challenge.ipfs.yataverse.com @everton.ns.cloudflare.com   # expect empty
```

### 1.3 Check the new files before nginx uses them

```sh
L=/etc/letsencrypt/live/ipfs.yataverse.com
sudo openssl x509 -in $L/cert.pem -noout -subject -issuer -serial -startdate -enddate \
  -ext subjectAltName -fingerprint -sha256
# SAN must be exactly "DNS:ipfs.yataverse.com"; notAfter must be later than 2027-01-29.

# Full chain against the system trust store, with server purpose and hostname:
sudo openssl verify -purpose sslserver -verify_hostname ipfs.yataverse.com \
  -untrusted $L/chain.pem $L/cert.pem          # expect: cert.pem: OK

# The private key matches the certificate:
[ "$(sudo openssl x509 -in $L/cert.pem -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum)" = \
  "$(sudo openssl pkey -in $L/privkey.pem -pubout -outform DER | sha256sum)" ] && echo key-match

# fullchain.pem = cert.pem followed by chain.pem:
sudo sh -c "cat $L/cert.pem $L/chain.pem | cmp - $L/fullchain.pem" && echo fullchain-ok
```

Stop here and roll back (§1.5) if any check fails.

### 1.4 Reload nginx and check what it serves

```sh
sudo nginx -t && sudo systemctl reload nginx
want=$(sudo openssl x509 -in /etc/letsencrypt/live/ipfs.yataverse.com/cert.pem -noout -fingerprint -sha256)
got=$(openssl s_client -connect 127.0.0.1:443 -servername ipfs.yataverse.com </dev/null 2>/dev/null \
      | openssl x509 -noout -fingerprint -sha256)
[ "$want" = "$got" ] && echo served-ok || echo "served-MISMATCH: $got"
```

The vhost already points at `/etc/letsencrypt/live/ipfs.yataverse.com/{fullchain,privkey}.pem`
(`deploy/ipfs-yataverse-canonical.conf.candidate`), so no nginx config changes.

### 1.5 Rollback (only if 1.3 or 1.4 fails)

The old certificate is still valid until 2027-01-29. Point the `live/` symlinks
back to the `certN/chainN/fullchainN/privkeyN` numbers recorded in §1.1, then
reload:

```sh
cd /etc/letsencrypt/live/ipfs.yataverse.com
N=<old number>   # from §1.1
for f in cert chain fullchain privkey; do
  sudo ln -sfn ../../archive/ipfs.yataverse.com/$f$N.pem $f.pem
done
sudo nginx -t && sudo systemctl reload nginx
```

Record the failure on AWAI-465 and retry before 2026-12-30.

## 2. External checks (after path A, or after the install in path B)

Run these from a machine **outside** Xavier's LAN, such as the Mac on a phone
hotspot. A run from inside the LAN goes through the router's hairpin and does not
prove the external path. Write down which vantage you used.

Use OpenSSL 3 or newer. On macOS, `/usr/bin/openssl` is LibreSSL, which lacks
`x509 -ext`. Check with `openssl version`; Homebrew's `/opt/homebrew/bin/openssl`
works.

### 2.1 TLS: SAN, notAfter, full chain

```sh
openssl s_client -connect ipfs.yataverse.com:443 -servername ipfs.yataverse.com \
  -showcerts -verify_return_error -verify_hostname ipfs.yataverse.com </dev/null 2>&1 \
  | grep -E 'Verify return code|^ *[0-9] s:|^ *i:'
# expect "Verify return code: 0 (ok)", depth 0 = CN ipfs.yataverse.com, depth 1 = a Let's Encrypt intermediate

openssl s_client -connect ipfs.yataverse.com:443 -servername ipfs.yataverse.com </dev/null 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName -enddate -serial -fingerprint -sha256
# the fingerprint must equal the one from §1.3

curl -sS -o /dev/null -w 'http=%{http_code} ssl_verify=%{ssl_verify_result}\n' https://ipfs.yataverse.com/
# ssl_verify=0 means the full chain verified against the client's trust store
```

### 2.2 Issuer and revocation (OCSP, CRL)

Let's Encrypt stopped OCSP in 2025. New certificates normally carry **no** OCSP
URL, and revocation is published by CRL. Check what this certificate actually
contains, and use the matching check:

```sh
d=$(mktemp -d); cd "$d"
openssl s_client -connect ipfs.yataverse.com:443 -servername ipfs.yataverse.com -showcerts </dev/null 2>/dev/null \
  | awk '/BEGIN CERT/{n++; p=1} p{print > ("c" n ".pem")} /END CERT/{p=0}'
openssl x509 -in c1.pem -noout -ocsp_uri                      # usually empty for LE in 2026
openssl x509 -in c1.pem -noout -ext authorityInfoAccess,crlDistributionPoints

# Issuer: the CA Issuers URL from authorityInfoAccess must give the same intermediate as c2.pem
ca=$(openssl x509 -in c1.pem -noout -ext authorityInfoAccess | sed -n 's/.*CA Issuers - URI://p')
curl -sS "$ca" -o issuer.der && openssl x509 -inform DER -in issuer.der -noout -fingerprint -sha256
openssl x509 -in c2.pem -noout -fingerprint -sha256           # must be equal

# Revocation by CRL: the CRL is signed by the intermediate and does not list this serial
crl=$(openssl x509 -in c1.pem -noout -ext crlDistributionPoints | sed -n 's/.*URI://p' | head -1)
curl -sS "$crl" -o crl.der
openssl crl -inform DER -in crl.der -CAfile c2.pem -noout && echo crl-signature-ok
serial=$(openssl x509 -in c1.pem -noout -serial | cut -d= -f2)
openssl crl -inform DER -in crl.der -noout -text | grep -qi "$serial" && echo REVOKED || echo not-revoked

# Only if -ocsp_uri printed a URL:
# openssl ocsp -issuer c2.pem -cert c1.pem -url "$(openssl x509 -in c1.pem -noout -ocsp_uri)" -CAfile c2.pem -resp_text | grep -E 'Cert Status|Response verify'
```

If the certificate has neither an OCSP URL nor a CRL distribution point, record
that as it is. Do not count it as a pass.

### 2.3 External CID fetch with SHA-256 match

These are the three JUN-228 CIDs. For a CIDv0 (`Qm…`) the expected SHA-256 is the
multihash digest inside the CID, so the expected values below are derived from
the CIDs, not copied from an earlier fetch.

| CID | bytes | expected SHA-256 |
| --- | --- | --- |
| `QmNLgJDagPKXUg4C1vKtvETQhTxEDScNYwEhYBke5uBan8` | 262158 | `0001cbb2b21e4630f872c22bdd727228a67d3c5908fa461e0f32778ecacae1ed` |
| `QmNLhRArQBktFvoG2vgmoM3oMZC8vgWGhk9sM4Q4KkGUxh` | 262158 | `00030fdbb19d898dce1466b03e5df5d8f362fde2579cfddf5afa4f3a108355f2` |
| `QmNLi4aMV82xKkoUbhQEM3rD4HfPHffu2Ye8SLU6nFKEBE` | 262158 | `0003ca8936bbc706feca68545e79bb40906f290eb4b764a604de6996456393b5` |

With the repo's probe (it verifies size and CID, and refuses redirects):

```sh
cd <checkout of this repo>/deploy
mkdir -p ../.agent-output
for c in QmNLgJDagPKXUg4C1vKtvETQhTxEDScNYwEhYBke5uBan8 \
         QmNLhRArQBktFvoG2vgmoM3oMZC8vgWGhk9sM4Q4KkGUxh \
         QmNLi4aMV82xKkoUbhQEM3rD4HfPHffu2Ye8SLU6nFKEBE; do
  python3 probe_reader.py --provider canonical=https://ipfs.yataverse.com \
    --cid "$c" --expected-bytes 262158 --timeout 30 --output ../.agent-output/awai465-probe-$c.json
  python3 -c 'import json,sys; r=json.load(open(sys.argv[1]))["results"][0]; print(r["cid"], r.get("verified"), r.get("status"), r.get("sha256"), round(r["seconds"],2))' \
    ../.agent-output/awai465-probe-$c.json
done
```

The same check with plain curl, with no repository needed:

```sh
curl -sS --fail --max-time 30 https://ipfs.yataverse.com/ipfs/QmNLgJDagPKXUg4C1vKtvETQhTxEDScNYwEhYBke5uBan8 | shasum -a 256
```

Pass means each CID shows `verified True`, status 200, and the SHA-256 in the
table. In JUN-228 these reads took 2–15 s and some first tries timed out. Retry a
timeout once with `--timeout 60`, and record both attempts.

## 3. Path B: Xavier is still offline

No host serves `ipfs.yataverse.com` while Xavier is down, so renewal cannot be
proven end to end. The goal then is to have a valid replacement ready before
2027-01-29 and to install it when Xavier is back.

1. On the operator Mac, issue the certificate with lego v5.6.0. Use the same
   pinned binary as PR #114, and check its SHA-256 before you run it:

   ```sh
   # darwin/arm64 tarball: 37453b4e1ad7e5d55a969508765db004122b9acbcfe099b95cafb86d0025a383
   # linux/amd64 tarball:  f02fc11b6f56b97e387fa7caa0268f86f5a336953b22458e6430e4651fea439a
   d=$(mktemp -d) && cd "$d" && umask 077
   curl -sSLO https://github.com/go-acme/lego/releases/download/v5.6.0/lego_v5.6.0_darwin_arm64.tar.gz
   shasum -a 256 lego_v5.6.0_darwin_arm64.tar.gz     # must equal the value above
   tar -xzf lego_v5.6.0_darwin_arm64.tar.gz lego
   ./lego run --accept-tos --account-id yataverse-manual --path "$d/store" \
     --dns manual --dns.resolvers 1.1.1.1:53 -d ipfs.yataverse.com
   ```

   lego prints the TXT name and value and waits for Enter. Add, check and delete
   the TXT record exactly as in §1.2. Output:
   `$d/store/certificates/ipfs.yataverse.com.crt` (leaf + intermediate) and
   `.key`.
2. Run the checks from §1.3 on these files. Use `-untrusted` with the second
   certificate in the `.crt` file as the intermediate.
3. Keep `$d` on the Mac only, mode 0700. Do not copy it to the repo or Linear.
4. When Xavier is back, before 2027-01-29: copy both files over the tailnet
   (`scp`), install them as root-only files, point the vhost's
   `ssl_certificate`/`ssl_certificate_key` at them, then run §1.4 and §2. This
   changes the nginx config on the production host and needs approval at that
   time. Then delete `$d` on the Mac.

If Xavier is not back before **2027-01-29 21:49 UTC**, the site is down anyway and
the expiry does not change what clients see. Install the new certificate when
Xavier returns, if it is still valid then.

## 4. Record

Post on AWAI-465 (no TXT value, no key, no token):

- path used (A or B), date and time (UTC), who ran it;
- old and new: serial, notAfter, SHA-256 fingerprint; SAN; issuer intermediate;
- `openssl verify` result; key-match; nginx `-t`/reload result; `served-ok`;
- external vantage, `Verify return code`, `ssl_verify_result`;
- OCSP URL present or not; CRL signature and not-revoked result;
- the three CID rows (verified, status, SHA-256, seconds), including any retries;
- TXT record deleted, and the empty `dig` result.

The new certificate's lifetime sets the next deadline. Read the actual notAfter
and do not assume 90 days, because Let's Encrypt is shortening default lifetimes
from 2027. Schedule the next manual renewal about 30 days before it, unless the
unattended path (PR #114) has been proven by then.
