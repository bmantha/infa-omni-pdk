# infa-omni-pdk

Monorepo of MuleSoft Flex Gateway PDK policies. Each folder is a self-contained Rust/wasm32-wasip1
crate -- run `make`/`cargo` from inside the folder, not the repo root. This file is only the
orientation layer; `dq-gate-policy/CLAUDE.md` / `AGENTS.md` hold the full engineering detail.

- **`dq-gate-policy`** -- gates MCP tool calls / A2A message-send on a CDGC asset's `dataQuality`
  rollup score (`scoreAggregation: min|average`, warn/block thresholds). The reference
  implementation: fail-closed-by-default posture, A2A v0.3/v1.0 (JSON-RPC + REST), `PolicyViolations`
  telemetry, a Timer-enforced 10s total score-resolution deadline (including storage),
  gossip-distributed caching, and `discloseScoreDetails`. See `dq-gate-policy/docs/spec.md` for
  security boundaries and release blockers; do not assume these changes apply to the other gates.
- **`data-classification-policy`** -- gates the same traffic on the worst-case CDGC
  `core.sensitivity` (LOW=1/MEDIUM=2/HIGH=3) across a list of governed column ids vs.
  `maxAllowedClassification`. Its hardened implementation requires the exact relational Column
  `systemAttributes['core.classType']`, uses two-hop batches of 5, v3 source/account/policy-scoped
  state, CAS ordering, instance-local integrity quarantine, and a safe remote-storage adapter.
  POST JSON/A2A JSON inspection has separate 1 MiB/10s body and 10s total-resolution bounds;
  excluded transports and task-result retrieval remain ungated. See its README and
  `data-classification-policy/docs/security-verification.md` for local evidence and production
  risks; do not assume the sibling gates share these changes.
- **`freshness-gate-policy`** -- gates the same traffic on one CDGC `RuleInstance`'s own
  `selfAttributes.value` (a freshness/SLA score), not an asset rollup: CDGC only populates the
  `dataQuality` rollup for Informatica-automated (`infa-producer.dq`) RuleInstances, so a
  manually asserted / externally computed score has to be read off the RuleInstance directly.
  Cloned from `dq-gate-policy` and back-ported its hardening (Clock injection, latency budget, A2A).
  See `freshness-gate-policy/CLAUDE.md` for the CDGC object model and Publish-API mechanics.

## Block error codes are disjoint on purpose

Each gate owns its own JSON-RPC codes so a client keying off the code alone can tell which gate
fired when several are stacked on one route: dq-gate `-32008` (MCP) / `-32010` (A2A),
data-classification `-32011` (MCP) / `-32012` (A2A), freshness `-32013` (MCP) / `-32014`
(A2A). A2A reserves `-32001..=-32009` for its own errors, so A2A codes stay above that range. The A2A REST binding always uses HTTP 403 +
`google.rpc.Status`, with a per-gate `ErrorInfo.domain`/`reason`.

## Shared CDGC mechanics

1. `POST https://<pod>.informaticacloud.com/identity-service/api/v1/Login` `{"username","password"}`
   -> `sessionId`, `orgId`.
2. `GET .../identity-service/api/v1/jwt/Token?client_id=idmc_api&nonce=<value>` with
   `cookie: USER_SESSION=<sessionId>` + `IDS-SESSION-ID: <sessionId>` -> `jwt_token` (~25-30 min;
   all three gates re-authenticate on every cache-miss refresh, no token reuse).
3. Content calls: `Authorization: Bearer <jwt>`, `X-INFA-ORG-ID: <orgId>` against the CDGC API host
   (configure `cdgcBaseApiUrl` explicitly -- it is not reliably returned by Login).

## Credentials

This repo is public. Never commit CDGC credentials or real org ids: the playground `api.yaml` files
point at the local mock containers with dummy creds. For live testing, put real values in a local,
uncommitted copy or environment variables, and keep `registration.yaml` / `.env` out of git (both
are gitignored per policy). `cdgcOrgUsername` and `cdgcOrgPassword` are `security:sensitive` in
every definition.
