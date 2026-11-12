# IDMC Data Classification Gate

A MuleSoft Flex/Omni Gateway policy (Rust + PDK, `wasm32-wasip1`) that checks the CDGC
classifications of a fixed set of relational columns before forwarding a content-bearing MCP
or A2A invocation. It blocks the **whole call**, not individual fields. It is not authentication,
authorization, response redaction, or a guarantee that caller-selected data matches the configured
columns.

This README describes the current classification implementation, not the sibling DQ or freshness
gates. See [Security Verification](docs/security-verification.md) for the hardening disposition,
verification status, and unresolved production risks. Source remediation is not release sign-off.

## Enforcement Surface

Only POST requests with `application/json` or `application/a2a+json` are inspected; media types
are case-insensitive and may have parameters. Non-POST, other or missing MIME types, SSE GETs,
and gRPC pass through with status `skipped`. Enforce the accepted transport/MIME contract at the
gateway and upstream; an invocation accepted under an excluded MIME type is outside this gate.

Within that surface:

- MCP `tools/call`, `resources/read`, and `prompts/get` are gated. Unrecognized JSON-RPC methods
  are also gated rather than silently exempted.
- A2A JSON-RPC `message/send`, `message/stream`, `SendMessage`, and `SendStreamingMessage` are
  gated. REST paths ending in `message:send`, `message:stream`, or `message:sendStream` are gated
  by path even if their JSON body camouflages an exempt RPC method.
- Explicit MCP discovery/control methods, A2A housekeeping methods, and `notifications/*`
  without an ID are exempt. POST task cancellation/subscription and push-notification creation
  routes are exempt before body validation, including empty bodies.
- Other inspected requests must contain a single valid JSON-RPC invocation. Batches, malformed
  or excessively deep JSON, and gated RPC invocations without a string/number ID are rejected
  with HTTP 400, not forwarded ungated.

Task retrieval/subscriptions can return existing artifacts and are not classification-gated.
This invocation-only boundary does not protect every route that can expose governed data.

| Outcome | MCP | A2A JSON-RPC | A2A REST |
|---|---|---|---|
| Known rank at or below ceiling | Allowed, status `ok` | Allowed | Allowed |
| Known rank above ceiling | HTTP 200, error `-32011` | HTTP 200, error `-32012` | HTTP 403, `google.rpc.Status` error envelope |
| Unknown result | Blocked by default using the same protocol-specific block shape | Same | Same |
| Unknown with `blockOnUnknownClassification: false` | Allowed ungated, status `unknown` | Same | Same |

Blocks report a `PolicyViolation`. With disclosure disabled, clients receive a generic message
and coarse `x-classification-gate-status`. With `discloseClassificationDetails: true`, policy-owned
rank headers and block details may include tiers, ceiling, and offending **column names**, not IDs.
Reserved upstream rank/columns/status headers are stripped, including on skipped requests.
Server-side logs still include governance IDs, tiers, and names; restrict access and retention.

## CDGC Classification Contract

Each refresh performs Login, JWT exchange, and two batched details reads, with at most five IDs
per details request. Hop 1 requests `segments=summary,systemAttributes,dataClassification`.
Every configured ID must resolve exactly once, with a bounded, meaningful `summary['core.name']`
and `systemAttributes['core.classType']` exactly equal to
`com.infa.odin.models.relational.Column`. The discriminator location follows the official
[Informatica batch-details example](https://docs.informatica.com/data-governance-and-quality-cloud/data-governance-and-catalog/current-version/api-reference/search-for-assets/retrieve-details-of-multiple-assets/example-request.html).
It is not inferred from an ID, name, suffix, or `core.type`.

Only such a validated Column with an absent `dataClassification` key or empty list is
unclassified (rank 0). A named table, `ViewColumn`, identity-only response, or missing/wrong class
type is **unknown**, not unclassified. Hop 2 requests `summary,selfAttributes` and requires every
linked classification to resolve to `selfAttributes['core.sensitivity']` of exactly `LOW`,
`MEDIUM`, or `HIGH` (ranks 1, 2, 3). The maximum rank across all configured columns is compared
with `maxAllowedClassification`; equality is allowed.

Missing/unexpected/duplicate identities, unresolved links, malformed responses, unknown or
missing sensitivity, and invalid bounds are integrity failures. They cannot reuse a stale LOW
allow result. Authorization-filtered omissions by the external catalog remain a deployment
assumption; the gate cannot independently establish whether an omitted classification really
means unclassified.

## Configuration

The full schema is [`definition/gcl.yaml`](definition/gcl.yaml).

| Property | Default / constraint |
|---|---|
| `cdgcLoginUrl`, `cdgcBaseApiUrl` | Required, separately configured HTTPS services; no URL userinfo |
| `cdgcOrgUsername`, `cdgcOrgPassword` | Required, sensitive credentials; at most 8192 bytes each |
| `allowInsecureLocalServices` | `false`; explicit HTTP exception for dummy-credential local tests only |
| `governedColumnIds` | Required comma-separated IDs, trimmed and deduplicated; 1-32 distinct columns, at most 256 bytes per ID |
| `maxAllowedClassification` | `MEDIUM`; `LOW`, `MEDIUM`, or `HIGH` |
| `refreshIntervalSeconds` | 86400; at least 30 seconds |
| `timeout` | 5000 ms; 1-10000 ms per CDGC call, clamped to remaining refresh budget |
| `failOpenOnCdgcError` | `true`; permits validated stale results on transient refresh failures/contention only |
| `blockOnUnknownClassification` | `true`; `false` deliberately disables enforcement while result is unknown |
| `discloseClassificationDetails` | `false`; opt-in client governance detail |
| `distributed` | `false`; remote mode requires valid gateway `sharedStorage` coordinates and a registered service |

IDs, names, and identity tokens are validated for meaningful text and control characters; names
are limited to 128 bytes, organization IDs to 256 bytes. Each column can link at most 32
classifications, with at most 256 distinct linked classifications overall. Invalid semantic
configuration is rejected at startup, before CDGC service registration.

HTTPS scheme validation is not proof of certificate/hostname verification or destination trust.
Configure gateway TLS trust and egress restrictions separately. The HTTP opt-in is an operator
promise of local use, not a hostname allowlist. Never enable it with live credentials.

## Cache And Failure Handling

Local storage is PDK policy-isolated. Remote rank and lock namespaces are versioned `v3` and
include a SHA-256 digest of policy namespace/name/filter identity. Opaque cache/lock keys digest
the login URL, catalog URL, account username, and canonical sorted/deduplicated column set.
Credentials are not embedded in plaintext keys; passwords are not part of the digest.
Pre-hardening and name-only namespaces are intentionally not reused.

Strict mode (`failOpenOnCdgcError: false`) refuses stale results on refresh failure, contention,
or storage failure. Transient fallback rereads and validates the current stored winner, rather
than reusing an earlier request snapshot. Cache validation checks rank consistency, column
count, names, and nonnegative/nonfuture observation timestamps. CAS/Absent writes use bounded
retries and observation-start ordering; older/equal observations cannot overwrite a valid newer
winner. Locks expire after 30 seconds and are not explicitly deleted.

Integrity failures mark a bounded **instance-local quarantine before awaiting invalidation**.
Failed or canceled invalidation cannot restore that instance's old allow result. A validated,
committed refresh with acceptable observation ordering and quarantine generation clears it.
Persisted invalidations use CAS, not gossip tombstone deletion. This does not make gossip
linearizable or quarantine durable/shared across replicas, restart, or partitions.

Default transient fail-open has no absolute maximum stale age in local mode. Remote rank
retention is capped by the adapter/backend TTL (up to 30 days), not a guarantee of fresh CDGC
metadata. Select TTL and failure posture for the data's risk, not just availability.

## Resource And Logging Bounds

Inspected request bodies have a 1 MiB limit and a separate 10-second atomic headers/body wait.
Invalid/excessive declared length or excessive actual length returns HTTP 413; body-wait expiry
returns HTTP 408. Keep the gateway connection buffer at 1 MiB as well: policy checks after body
acquisition do not independently bound host buffering. Classification resolution has its own
10-second total deadline including cache reads, locks, CDGC, CAS reads, and persistence. These
are separate phases, not a 10-second complete-request SLA.

CDGC and shared-storage responses are bounded to 1 MiB before policy-side copying. Error
responses are not copied into diagnostics. Configuration and CDGC parse failures use safe
categories/stages/locations, not raw input, response bodies, or Serde error text.

The pinned SDK's generated raw-configuration initializer is replaced through an atomic,
fail-closed generator guard and the hand-authored initializer. Do not generate configuration
directly and compile around that guard. Remote mode uses [`SafeRemoteDataStorage`](src/storage.rs)
instead of the SDK distributed client's raw-response logging path. Its low-level binary/ETag
contract is source-tested; live shared-backend interoperability remains unverified.

## Build And Local Verification

Run from this policy directory. Node.js is required for safe configuration generation; use the
Make targets rather than hand-editing `src/generated/config.rs`.

```bash
make help
make setup
make test-unit test-mocks
make build
make advisory
make test-integration
```

Build/test commands use `--locked`; PDK and cargo-anypoint are pinned to 1.10.0. CI pins Rust
1.90.0, CLI/plugin versions, action SHAs, and Docker image digests, and runs dependency advisories
with warnings denied. The bounded integration runner requires a POSIX host. Publish/release
targets depend on tests and security checks, but repository branch protection and the actually
deployed artifact are not established by that wiring. No publish or live testing is implied by
the commands above. Local verification on 2026-11-11 passed 59 Rust unit tests (including seven
adapter tests), six generator tests, five tooling/runner tests, four mock-contract tests, and nine
Docker integrations. The WASM build, warning-denying dependency audit, formatting, and diff checks
passed. See the [evidence record](docs/security-verification.md#verification-evidence) for limits.

## Local Demo

`make run` uses local mock CDGC services and dummy credentials. After building and generating
the disconnected registration, `playground/demo.sh` shows the local VISIT_REASON transition from
unclassified/allowed to HIGH/blocked after the 30-second fixture TTL. It suppresses response data,
accepts only `http://127.0.0.1:8081/` route URLs, rejects API configuration overrides, validates
the byte-exact reviewed dummy fixture using SHA-256, and disables Compose dotenv loading for
startup and cleanup. Intentional fixture changes require a reviewed hash update in the script.

```bash
make build playground/config/registration.yaml
playground/demo.sh
playground/demo.sh --cleanup
```

Do not insert live credentials into tracked fixtures or `.env` to run the demo. Any separately
approved live configuration belongs in the ignored private file described in
[Local Playground](playground/README.md), mounted **instead of**, never beside, the mock
ApiInstance. The local demo refuses that override. No live credentials, catalog mutation,
deployment, commit, or push are part of this documentation update.
