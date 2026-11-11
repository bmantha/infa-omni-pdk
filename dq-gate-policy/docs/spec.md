# IDMC Data Quality Gate

An inbound Flex/Omni Gateway policy that gates recognized MCP and A2A invocations using one fixed CDGC asset's data-quality rollup. It aggregates validated dimensions, compares the score with warning/block thresholds, and caches observations locally or in gossip-replicated storage. It is a quality gate, not authentication, a scan-freshness guarantee, or a complete protocol access-control boundary.

## Configuration

### allowInsecureLocalServices

Boolean, optional, default `false`. Both service URLs require HTTPS by default, nonempty authorities, and no userinfo. `true` permits HTTP ONLY for local mock testing, for example `http://cdgc-mock:8080`; it does not enforce locality. Never enable in production. External egress destination and TLS trust allowlisting remain mandatory.

### cdgcLoginUrl

Service URL, required, no default. IDMC login base, for example `https://dmp-us.informaticacloud.com`. Verify the pod for the account; do not infer it. Requires approved HTTPS/TLS trust outside local mocks.

### cdgcBaseApiUrl

Service URL, required, no default. Explicit CDGC API base, for example `https://idmc-api.dmp-us.informaticacloud.com`. Login does not reliably supply it. Apply the same egress/TLS restrictions as the login service.

### cdgcOrgUsername

String, required, no default; sensitive service-account credential, for example `local-mock-user` in a mock configuration. Account identity participates in storage keys. Never log credentials.

### cdgcOrgPassword

String, required, no default; sensitive password, for example `local-mock-password` ONLY in a mock configuration. Never include passwords in storage identity, diagnostics, or committed live configurations.

### cdgcAssetId

String, required, no default; nonempty fixed CDGC asset id, for example `mock-asset`. Every governed operation on the route must access that asset. Client-selected tools, arguments, task ids, or tenants must not redirect access to another asset under this score.

### warnThreshold

Number, required with default `90`, finite and in 0..100. Scores below it but at or above `blockThreshold` are allowed with `warn`; for example `90`. Must be >= `blockThreshold`.

### blockThreshold

Number, required with default `80`, finite and in 0..100. Scores below it are blocked; equality is allowed. Example: `80`.

### scoreAggregation

String, optional, default `min`; only `min` and `average` are accepted. Combines validated DQ dimensions; example `min` selects the worst dimension. Fetched and cached scores must be finite and in 0..100; invalid values cannot authorize access.

### refreshIntervalSeconds

Integer, optional, default `86400`, minimum `30`. Observation TTL; example `300` refreshes more frequently. Cache age is NOT scan age: fetching a score does not cause a new CDGC scan or prove source-data freshness.

### failOpenOnCdgcError

Boolean, optional, default `true`. Example `false` treats a refresh failure as unknown rather than using stale data. A stale score on unavailable/failed refresh-lock acquisition is served ONLY when this flag is `true`. A missing score cannot be recovered this way. The outer total deadline returns unknown directly, without guaranteed stale recovery.

### blockOnUnknownScore

Boolean, optional, default `true`. Blocks recognized invocations when no trustworthy score resolves. Example `false` is a deliberate soft-launch bypass with status `unknown` and a one-shot per-worker warning, not a production security guarantee.

### discloseScoreDetails

Boolean, optional, default `false`. Example `true` exposes score/threshold/asset details in applicable errors and the score header. Default clients receive generic errors and coarse status; server-side score/asset diagnostics still require access controls. Never log raw configuration, credentials, tokens, cookies, authorization headers, or CDGC response bodies.

### distributed

Boolean, optional, default `false`. Example `true` selects remote gossip storage for scores and locks. Remote configuration is required. Remote extraction/setup or runtime errors do NOT automatically fall back to local storage; runtime failures follow score-error/unknown posture. Gossip does not provide linearizable coordination.

### timeout

Integer milliseconds, optional, default `5000`, range 1..10000. Per-CDGC-call timeout, clamped to remaining refresh-chain budget; example `2000`. A separate 10s total resolution deadline includes storage. Neither timeout bounds request uploads.

## Behavior

### Request rules

1. Exclude non-POST methods and MIME types other than `application/json` at headers, before body buffering or score lookup. MIME parameters are permitted. These exclusions are ungated, not rejected.
2. For JSON POSTs, reject declared or actual bodies over 1 MiB (1,048,576 bytes) with HTTP 413. Reject malformed or parser-over-depth JSON with HTTP 400, including on otherwise exempt JSON methods. These denials emit PolicyViolations.
3. Recognize final REST path segments `message:send` and `message:stream` before inspecting JSON-RPC method/id. REST path wins even if the valid JSON body resembles an exempt call, notification, or no-id envelope. The policy is not an upstream request-schema validator.
4. Otherwise recognize JSON-RPC calls. Gate MCP `tools/call`, `resources/read`, `prompts/get`, A2A v0.3 `message/send`, `message/stream`, and A2A v1 `SendMessage`, `SendStreamingMessage`. Exempt handshake/discovery and A2A task/config methods, notifications/no-id calls, valid batches, and unrecognized non-send paths pass through ungated.
5. Resolve the score from cache or inline Login -> JWT -> Detail refresh. Fetched dimensions and cached values must be finite and within 0..100. A stale refresh-lock miss/error uses stale data only with `failOpenOnCdgcError=true`; without it, the result is unknown. Normal refresh failures can use last-known-good data under that same flag.
6. Race all score-resolution work against a PDK Timer's 10s deadline with a 10ms tick. Cache reads, locks, HTTP, and storage writes are included. Expiry yields unknown and applies `blockOnUnknownScore`. Dropping pending HTTP/storage futures cannot undo remote writes or already-issued side effects. Body upload/validation precedes this deadline.
7. Block a score below `blockThreshold`; allow with `warn` below `warnThreshold`; otherwise allow with `ok`. Unknown blocks by default; an explicit soft launch may allow it. Emit a PolicyViolation on denial.

### Errors and response flow

| Condition | Response |
|---|---|
| Malformed or over-depth JSON POST | HTTP 400 |
| JSON POST over 1 MiB | HTTP 413 |
| MCP quality/unknown denial | HTTP 200, JSON-RPC `-32008` |
| A2A JSON-RPC quality/unknown denial | HTTP 200, JSON-RPC `-32010` |
| A2A REST quality/unknown denial | HTTP 403, `google.rpc.Status` |

A2A v1 JSON-RPC errors carry a single-element `google.rpc.ErrorInfo` array; REST errors carry `ErrorInfo` in `details`. The reason is `DATA_QUALITY_BELOW_THRESHOLD`, domain `dq-gate.mulesoft.com`. Legacy details and sensitive metadata are disclosure-controlled. Allowed responses replace upstream-supplied DQ diagnostic headers with the policy's own `x-dq-gate-status` and optional `x-dq-gate-score`; response bodies, including SSE, are not buffered by the response filter.

### Deployment boundary and edge cases

- Authentication and authorization MUST run before the gate. Clients MUST NOT reach the direct backend outside the gateway. Fixed-asset binding is an operator/upstream contract, not derived from request data.
- Prohibit alternate transports (including gRPC), non-JSON requests, batches, no-id invocations, and task-read/exempt-method bypasses wherever the upstream can execute or access governed data through them. Recognition exclusions are not a security allowlist.
- MUST configure a gateway 1 MiB connection buffer plus upload, idle, and request timeouts. PDK high-level request buffering waits to EOF; the actual-size check and resolution deadline cannot alone bound memory or slow uploads. Verify effective settings in the deployed topology.
- Each CDGC response has a 1 MiB post-buffer check. High-level HTTP has already buffered the response: this is NOT a network-memory bound. Gateway/egress response buffering and timeouts must be configured independently.
- HTTPS scheme validation does not establish trusted destinations. Require external egress destination allowlisting and TLS trust allowlisting for login and API services.
- Local mode uses the configured services and selected storage backend; it does not implicitly enable HTTP or substitute a local backend when remote extraction/runtime operations fail.
- Dependency advisory scans now pass. Pending release blockers: real-topology buffer/timeout/auth/bypass/direct-backend verification, TLS/egress verification, and multi-replica gossip/concurrency verification. Local buffer/idle controls pass, but the opt-in TLS policy-callout positive control fails on Flex 1.13.0/PDK 1.10.0. See `security-verification.md` for evidence and limitations. No production-readiness claim until these are complete.

## Architecture

The header-stage method/MIME guard precedes combined headers/body holding for candidate JSON requests. Validation and REST-first classification precede the shared score decision. The response filter operates at headers only. Inline refresh avoids a separate background refresh scheduler; the Timer exists to wake the total-resolution deadline.

Score and refresh-lock stores use separate namespaces/lifetimes. Remote namespace identity includes policy metadata `policy_namespace`, `policy_name`, and `filter_name`. Entry identity includes login URL, API URL, account username, asset id, and aggregation mode. Both identities are encoded as SHA-256 digests so raw account/source values do not appear in storage-key logs; no password belongs in an identity. Remote score retention outlives the refresh TTL so a last-known-good value can survive a refresh failure.

Cache writes use CAS/absent operations with bounded retries and reject older or equal observation-start timestamps against the currently observed entry. A losing writer evaluates the validated winning score, not its own older score; persistence errors yield unknown. This protects an observed entry from a delayed older write, NOT global ordering: gossip is not linearizable, replica clocks can skew, and simultaneous refreshes remain unresolved. Timestamps record policy observation start, not CDGC scan completion. Cancellation cannot roll back a write already accepted remotely.

## Examples

Local mock configuration (dummy credentials only; requires the local mock service):

```yaml
allowInsecureLocalServices: true
cdgcLoginUrl: http://cdgc-mock:8080
cdgcBaseApiUrl: http://cdgc-mock:8080
cdgcOrgUsername: local-mock-user
cdgcOrgPassword: local-mock-password
cdgcAssetId: mock-asset
warnThreshold: 90
blockThreshold: 80
scoreAggregation: min
refreshIntervalSeconds: 300
failOpenOnCdgcError: false
blockOnUnknownScore: true
discloseScoreDetails: false
distributed: false
timeout: 2000
```

Recognized MCP request:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup","arguments":{}}}
```

With a valid mock score of 95, the request reaches upstream and its response carries `x-dq-gate-status: ok`, without `x-dq-gate-score`. With a score of 65, it is rejected before upstream execution with HTTP 200 and JSON-RPC error code `-32008`, plus `x-dq-gate-status: blocked`. An over-depth or malformed JSON body instead returns HTTP 400 regardless of the score. For production, disable the HTTP opt-in and use approved HTTPS endpoints, protected credentials, and all deployment controls above; this example is not production authorization.
