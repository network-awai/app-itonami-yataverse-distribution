# ipfs.yataverse.com: unattended certificate renewal (AWAI-465)

Tracked in [AWAI-465](https://linear.app/kotobalabs/issue/AWAI-465). Follows
[JUN-228](https://linear.app/kotobalabs/issue/JUN-228) / PR #113. In that
change, the last certificate came from a manual DNS-01 run, where an operator
set the TXT record while `deploy/dns01_operator_hook.sh` waited up to 300 s.
That was not automated renewal, and this change does not call it one.

The certificate expires on **2027-01-29 21:49:17 UTC**. The issue's deadline
is 2026-12-30. If the path below is not proven by then, schedule a manual
renewal and record its evidence.

## State on 2026-11-22 (what is and is not proven)

| Item | State |
| --- | --- |
| Renewer and receiver scripts, local tests (real lego v5.6.0 against Pebble) | Done: 10 tests pass |
| Namespace `yataverse-acme`, PVC, NetworkPolicy, ConfigMap, both CronJobs (suspended) on VKE `awai-tatara-ci` | Applied, no Secrets |
| Pinned base image: tools, uid 65534, restricted PodSecurity, egress to LE and Cloudflare, cloud metadata blocked | Checked with a throwaway pod (no Secrets) |
| Dedicated node pool, Tailscale key and ACL, Cloudflare token | **Owner action** (steps 1–3) |
| LE staging E2E on VKE | **Not run yet**: needs steps 1–3 |
| Production issuance, SAN/expiry/chain readback, nginx reload, external CID SHA-256 fetch | **Not run yet**: Xavier and the other serving nodes have been offline on the tailnet since about 2026-11-07, and `https://ipfs.yataverse.com` does not answer |

## Design

```
VKE pool "yataverse-acme" (tainted, autoscaled 0..1, no CI pods)
  CronJob every 6 h ── lego (DNS-01, Cloudflare API) ──> Let's Encrypt
        │                 token: Secret yataverse-acme-dns, this namespace only
        │ verify SAN / expiry / key / chain
        └─ ssh over tailnet (userspace tailscale sidecar, tag:yataverse-acme)
              └─> each serving node: forced command receive.sh
                     verify again, no downgrade, atomic switch,
                     sudo nginx-apply.sh (nginx -t && reload),
                     check that 127.0.0.1:443 serves the new leaf, else roll back
```

* **Client: lego v5.6.0.** It is a single static binary with a built-in Cloudflare
  DNS provider. Both the release-tarball SHA-256 and the binary SHA-256 are
  pinned in `k8s/renew.conf` and checked on every run. The certbot 0.40.0 on
  Xavier has no DNS plugin. Upgrading it would mean snap or a pip virtualenv on
  each host, and it would tie renewal to that host. acme.sh is a large shell
  program that is harder to pin and review.
* **Why a lego CronJob instead of cert-manager.** cert-manager is a cluster-wide
  controller that can read Secrets in every namespace. Adding it to a cluster that
  runs untrusted CI widens exposure. Its output is a Secret, and we would still
  need our own job to push to nginx nodes outside the cluster. The CronJob reuses
  the tested `renew.sh` as is.
* **Hosts and failover.** Renewal runs on the dedicated VKE pool. No serving node
  is involved: if Xavier is down, the certificate is still renewed and kept on
  the PVC. Every run also re-pushes. Pushing is idempotent: a target answers
  `unchanged` when it already has the certificate. So a node that was offline
  gets the current certificate within 6 h of coming back. While a target is
  behind, the Job fails with exit code 75, and the status file names the target.
  Add more serving nodes by adding them to `TARGETS`. The pool is autoscaled
  from 0, so a pending Job pod should start a node. That has not been verified
  yet (step 5).
* **Separate from CI.** The checks below were run read-only on 2026-11-22:
  - No RoleBinding or ClusterRoleBinding gives the `tatara` service accounts
    Secret access. `tatara-scaler` can only `get/patch statefulsets/scale` on
    `tatara-runner`.
  - The CI `runner` container runs PR code with `CAP_SYS_ADMIN`. The tailscale
    container next to it has `NET_ADMIN` and a hostPath `/dev/net/tun`.
  - So a CI container escape on a shared node could read any Secret mounted on
    that node. **The renewer therefore only runs on its own tainted pool.** The
    Secrets are not created until that pool exists.

  Other restrictions:
  - The namespace enforces PodSecurity `restricted`.
  - The service account has no bindings and no mounted token.
  - Nothing can connect in. Outbound traffic is limited to cluster DNS and
    public addresses; pod, node, CGNAT and link-local metadata ranges are excluded.
* **Credentials.**
  - `yataverse-acme-dns` holds `CF_DNS_API_TOKEN`. Scope it to Zone.DNS:Edit on
    `yataverse.com` only. lego's documentation says it may also need Zone.Zone:Read
    on the same zone; the staging run shows whether it does.
  - `yataverse-acme-tailscale` holds a tagged auth key.
  - `yataverse-acme-push` holds an SSH key. On each target, that key can only
    run `receive.sh`, and only from the renewer's tailnet address.
  - All three are mounted with mode 0440 and the job's group. `renew.sh` refuses
    any other mode.
  - lego reads the token from its env file. It runs with an otherwise empty
    environment and no `--deploy-hook`, because lego v5 exports env-file values
    into hook environments (checked on 2026-11-22).
  - Status files and logs contain only digests, dates, serials and target
    results. The tests check that a sentinel token never appears in them.
* **Staging and production stay separate.** Each profile has its own lego store
  (`/state/<profile>`), CronJob and receiver slot. nginx never reads the
  `staging` slot, and the receiver does not reload nginx for it.
* **Cloudflare stays DNS-only.** Cloudflare only gets the temporary
  `_acme-challenge` TXT record. lego deletes it after validation. The A record
  and the bytes path do not change.

## Owner steps (approval gates)

1. **Node pool.** Create a VKE node pool on cluster `awai-tatara-ci` (nrt):
   - label/name `yataverse-acme`, plan `vc2-1c-2gb`;
   - autoscaler on, min 0, max 1;
   - taint `yataverse.network/acme=renewer:NoSchedule`.

   This needs the Vultr API or console; this repository holds no Vultr credential.
2. **Tailscale.** Add the policy below and create a pre-approved,
   non-ephemeral, single-use auth key tagged `tag:yataverse-acme`. The node
   state lives on the PVC, so the renewer keeps one tailnet address, and
   targets can pin `from=` to it.

   ```json
   {
     "tagOwners": { "tag:yataverse-acme": ["autogroup:admin"] },
     "hosts": { "xavier": "100.87.226.80" },
     "grants": [
       { "src": ["tag:yataverse-acme"], "dst": ["xavier"], "ip": ["tcp:22"] }
     ]
   }
   ```

   Merge this into the existing policy. With the legacy `acls` syntax, the same
   rule is `{"action": "accept", "src": ["tag:yataverse-acme"], "dst": ["xavier:22"]}`.
   If the tailnet still has the default allow-all rule, this grant restricts
   nothing. Then the per-key `restrict,from=,command=` on the target is the only
   boundary.
3. **Secrets.** Run these in your own terminal. Each one prompts without echo,
   and the value goes from stdin straight into the Secret, so it never appears
   in argv, shell history, the repository, Linear or logs:

   ```sh
   K=/Users/junkawasaki/github/workspaces/claude/awai-3542-tatara-runner/kubeconfig
   sh -c 'printf "Cloudflare token: " >&2; stty -echo; read -r t; stty echo; echo >&2
          printf "CF_DNS_API_TOKEN=%s\n" "$t" | kubectl --kubeconfig "$0" -n yataverse-acme \
            create secret generic yataverse-acme-dns --from-file=dns.env=/dev/stdin' "$K"
   sh -c 'printf "Tailscale auth key: " >&2; stty -echo; read -r t; stty echo; echo >&2
          printf "%s" "$t" | kubectl --kubeconfig "$0" -n yataverse-acme \
            create secret generic yataverse-acme-tailscale --from-file=authkey=/dev/stdin' "$K"
   ```

## Operator steps (after 1–3)

4. **Push key.** Generate it on the operator Mac, put the private half only into
   the cluster, and keep the public half for step 7:

   ```sh
   d=$(mktemp -d) && ssh-keygen -q -t ed25519 -N '' -C yataverse-acme-renewer -f "$d/k" &&
   kubectl -n yataverse-acme create secret generic yataverse-acme-push --from-file=push_key="$d/k" &&
   cp "$d/k.pub" .agent-output/yataverse-acme-push.pub && rm -rf "$d"
   ```
5. **Staging E2E.** This is the same CronJob template and code path with the LE
   staging server:

   ```sh
   kubectl -n yataverse-acme create job --from=cronjob/yataverse-acme-staging staging-$(date +%s)
   ```

   Record:
   - that the pod triggered a scale-up of the pool from 0, and how long the node
     took (`kubectl get nodes`, pod events);
   - that the tailscale sidecar logged in as `tag:yataverse-acme`;
   - lego's DNS-01 result (whether Zone:Read was needed);
   - `status-staging.json`: `chain=verified` against `k8s/le-staging-roots.pem`,
     SAN, expiry;
   - that after the Job, the pool scaled back to 0.

   With `TARGETS` still empty, this proves renewal without a target. Run it
   again after step 7 to cover the push to Xavier's staging slot.
6. Unsuspend `yataverse-acme-production`. Do this only after step 7 and a passing
   staging push.
7. **Enroll Xavier** (production host; needs approval). Copy `deploy/acme` to it.
   Run `install-receiver.sh <renewer tailnet IP> yataverse-acme-push.pub` as a dry
   run, then with `--apply`. Put the printed host key into `k8s/known_hosts` as
   `xavier.tail110d8b.ts.net ssh-ed25519 ...`. Set
   `TARGETS="xavier=yataverse-acme-recv@xavier.tail110d8b.ts.net"` in
   `k8s/renew.conf`, then `kubectl apply -k deploy/acme`. Point the
   `ipfs.yataverse.com` vhost at the pushed bundle:

   ```nginx
   ssl_certificate     /var/lib/yataverse-acme/live/production/current.pem;
   ssl_certificate_key /var/lib/yataverse-acme/live/production/current.pem;
   ```

   Do this only after the first production push has installed a certificate. Then
   run `nginx -t` and reload. The certbot lineage in `/etc/letsencrypt` stays
   untouched as the rollback.
8. **Production proof.**
   - Run the production job once.
   - Read back SAN, `notAfter` and chain from `status-production.json`, and from
     `openssl s_client -connect ipfs.yataverse.com:443 -servername ipfs.yataverse.com`.
   - Check the receiver's `served` check result.
   - Fetch the 3 JUN-228 CIDs from outside the LAN with `deploy/probe_reader.py`,
     matching their SHA-256.
   - Post the readback on AWAI-465 without secrets or challenge values.

## Failure handling

| Failure | Behaviour |
| --- | --- |
| lego cannot renew (DNS API, ACME error) | Job exits 2. The current certificate stays on the PVC and is still pushed. The next run is in 6 h. |
| Certificate within 21 days of expiry | Exit 4, even if the pushes succeed. |
| A target is offline or rejects the certificate | Exit 75. The other targets are still updated, and the status file names the one behind. |
| `nginx -t` or reload fails, or 127.0.0.1:443 does not serve the new leaf | The receiver switches back to the previous release and replies `error ...-rolled-back`. |
| Digest mismatch (lego), wrong credential mode, writable config | Exit 1 before any ACME or DNS call. |

**Open: where alerts go.** A failed Job is visible in the cluster and in
`status-<profile>.json`, but nothing forwards it yet. Add a notification channel
before relying on it, for example a webhook that a monitor already watches.

## Local tests

```sh
cd deploy/acme
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_acme_renewal
```

The three renewer cases need `PEBBLE_BIN_DIR` (pebble v2.8.0 and
pebble-challtestsrv), `PEBBLE_MINICA` (Pebble's `test/certs/pebble.minica.pem`)
and `LEGO_TEST_BIN` (a lego v5.6.0 binary for the local OS). Without them they
are skipped. These are local diagnostics. They are not a production renewal,
not an LE staging run, and not a native Amu qualification gate.
