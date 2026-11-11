# Local TLS Callout Verification

## Result and Root Cause

LOCAL DOCKER ONLY, disconnected Flex 1.13.0 with PDK/pdk-test 1.10.0.
**Actual cold policy callout TLS verification remains incomplete.** The matrix
is explicitly ignored in normal `make test`, not treated as passing. Opting in
still fails when the correct-CA policy positive control is blocked.

The failure is not the PEM, certificate chain, SAN, or `trustedCA` config shape:

- OpenSSL verifies the generated CA/leaf chain for `tls-login` and `tls-api`,
  and rejects the unrelated CA and `tls-wrong` hostname.
- The installed `flex-agent` binary contains `TrustedCA` with the
  `json:"trustedCA"` field tag. No standalone TLS schema file is shipped in this
  image's policy-definition directory; the native policy is implemented in the agent.
- The [public TLS Outbound example](https://docs.mulesoft.com/gateway/latest/policies-included-tls-outbound)
  uses `config.trustedCA` directly. `certificate.key/crt` is optional **client
  mTLS identity**, not the CA trust location. Nginx does not request a client certificate.
- A separate plain API upstream in the **same gateway/container**, with the same
  `trustedCA`, server leaf, and hostname, retains an Envoy
  `validation_context.trusted_ca.inline_string` equal to the generated CA and
  successfully reaches the HTTPS mock ping endpoint.
- After the DQ policy initializes, both exact PDK-generated callout clusters
  instead use `validation_context.trusted_ca.filename` =
  `/etc/ssl/certs/ca-certificates.crt`. Their SAN matchers and SNI are correct,
  but the custom CA is absent. Agent debug logs show the explicit services/TLS
  policies being added, then the initializer adding the same services again.
- The actual gated cold request fails the Login handshake; Nginx reports
  `tlsv1 alert unknown ca`, and Login/JWT/detail/gated-backend counts are all zero.

This isolates an effective TLS-context loss on `abi.service_create` policy
callout services in this Flex 1.13.0/PDK 1.10 combination, while the normal
Service TLS binding works. It does not identify the internal SDK/agent code
line responsible, nor establish that other versions have the same limitation.
Reapplying config after initialization was previously tried without success.
No production initializer or SDK code was changed. Do not install the test CA
globally, set `skipValidation: true`, substitute an HTTP callout, or proxy the
policy callout through the plain control and label that a passing matrix.

## Commands

Prerequisites: cached build dependencies, Docker/Compose, OpenSSL with
`req -addext`, and cached images:

- `mulesoft/flex-gateway:1.13.0`
- `httpmock/httpmock:0.8.3`
- `nginx:alpine@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606`

Fixtures refuse pulls. Ensure `tests/config/registration.yaml` already exists:
the existing Makefile pulls an image when it is missing. The TLS test never
mounts that registration; each case generates its own disconnected one with
`--pull=never --network=none`. No Anypoint credentials or live IDMC endpoints
are used. From `dq-gate-policy`:

```sh
# Normal suite: TLS diagnostic is explicitly reported as ignored.
CARGO_NET_OFFLINE=true make test

# Explicit diagnostic, including ignored tests; expected to fail on this combination.
CARGO_NET_OFFLINE=true make test TEST='tls_policy_callout_trust_matrix -- --ignored'
```

The second command uses the existing Makefile's `TEST` forwarding to Cargo;
no Makefile change is required. Build and generator tests still run first.

## Assertions and Bounds

Each case starts a fresh gateway/cache and generates new private CA/key material.
An exempt `tools/list` response with `x-dq-gate-status: skipped` establishes
policy readiness without warming the score cache. The subsequent actual
`tools/call` must return `ok` and exactly one Login, JWT, detail, and gated
backend hit for the trusted positive control. Negative Login cases require
`blocked`, JSON-RPC `-32008`, and zero hits. Negative API cases require one
Login/JWT and zero detail/backend hits; they are NOT RUN when the positive
control fails, and the overall diagnostic fails rather than hiding that gap.
Discovery backend counters are measured and subtracted, not assumed to be one.

All host HTTP operations, including mock creation/counter reads and the Envoy
diagnostic read, use one `no_proxy` reqwest client with a 2-second connect timeout
and 15-second total request timeout (including response bodies). Readiness probes
have 1-second request timeouts and a 30-second deadline plus attempt cap per
readiness phase. Fixture processes have a 60-second timeout; cleanup/log commands
are bounded too. Docker-daemon failure can prevent cleanup despite these bounds.

The control paths are diagnostic only. Nginx root workers access the Envoy admin
Unix socket through a read-only, per-case Docker volume; Flex runs as root only
in this disposable fixture so it can initialize that volume. No host Docker
socket or gateway state is mounted. Admin and plain-control paths are reachable
only via the loopback-published HTTP control port, not the policy ingress port.
The raw admin dump is never printed or persisted. The test extracts only cluster
names, SNI, SAN matchers, CA file paths, and a boolean CA equality check.

## Evidence

On 2026-11-11 the plain HTTPS correct-CA control passed in every executed Login
case. The actual policy results were:

| Case | Policy | Login | JWT | Detail | Gated backend |
| --- | --- | --- | --- | --- | --- |
| Untrusted Login | blocked | 0 | 0 | 0 | 0 |
| Correct CA and SAN | blocked; FAILED positive control | 0 | 0 | 0 | 0 |
| Wrong CA Login | blocked; not independent CA proof | 0 | 0 | 0 | 0 |
| Wrong hostname Login | blocked; not independent SAN proof | 0 | 0 | 0 | 0 |
| API-side negatives | NOT RUN; positive control prerequisite failed | - | - | - | - |

Per-case debug/stdout logs are in `target/pdk-test/tls/dq-tls-<pid>-<case>.log`.
Sanitized effective validation summaries are in the adjacent
`dq-tls-<pid>-<case>-clusters.json`. Look for the contrast between the two
`tls-gate-*-service.default.svc` clusters (OS CA filename) and
`tls-schema-control-upstream.default.svc` (fixture CA equality true).
These are test artifacts, not committed source or full sensitive dumps.

Final bounded opt-in run: prefix `dq-tls-99539-`, 48.66 seconds, one failed
TLS matrix (Cargo failure 101, make nonzero). Its positive-control evidence is
`target/pdk-test/tls/dq-tls-99539-trusted-chain-clusters.json` and the adjacent
`dq-tls-99539-trusted-chain.log`. The subsequent normal offline `make test`
exited 0: 3 generator tests, 82 unit tests, 17 Docker request tests passed;
1 TLS diagnostic explicitly ignored. Request tests took 211.84 seconds.
`docker ps` was empty after verification. Passing the normal suite does not
change the incomplete TLS result above.

## Cleanup and Remaining Work

Normal completion/error/assertion unwinding collects logs then removes the
specific case containers, networks, state volume, certificates, and disconnected
registration. A forcibly killed process cannot run Rust destructors; remove only
its `dq-tls-<pid>-<case>` Compose project and matching OS-temp directory. Do not
use broad Docker prune. Private keys are never created in the repo.

Resolving callout Service TLS-context retention needs separate SDK/runtime
investigation or explicitly approved production/toolchain changes. Only remove
the ignore once the actual policy positive control and **all** API/Login
negatives pass, including specific SAN-mismatch evidence for hostname cases.

Local results do not prove production trust, destination/egress allowlisting,
SSRF/DNS-rebinding defenses, redirects, real IDMC access, or multi-replica
behavior. The production TLS/egress release blocker remains.
