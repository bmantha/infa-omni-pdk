# infa-omni-pdk

Monorepo of MuleSoft Flex Gateway PDK policies. Each folder is a self-contained Rust/wasm32-wasip1
crate -- run `make`/`cargo` from inside the folder, not the repo root. This file is only the
orientation layer; `dq-gate-policy/CLAUDE.md` / `AGENTS.md` hold the full engineering detail.

- **`dq-gate-policy`** -- gates MCP tool calls / A2A message-send on a CDGC asset's `dataQuality`
  rollup score (`scoreAggregation: min|average`, warn/block thresholds). The reference
  implementation: fail-closed-by-default posture, A2A v0.3/v1.0 (JSON-RPC + REST), `PolicyViolations`
  telemetry, a 10s budget on the inline CDGC refresh chain, gossip-distributed caching, and
  `discloseScoreDetails`.
- **`data-classification-policy`** -- gates the same traffic on the worst-case CDGC
  `core.sensitivity` (LOW=1/MEDIUM=2/HIGH=3) across a list of governed column ids vs.
  `maxAllowedClassification`. Structurally mirrors `dq-gate-policy` (same DataStorage cache/lock
  split, CAS writes, latency budget, request classification, rejection shapes); the CDGC side is a
  two-hop batched read (column -> linked classifications -> their sensitivity, chunks of 5).

## Block error codes are disjoint on purpose

Each gate owns its own JSON-RPC codes so a client keying off the code alone can tell which gate
fired when several are stacked on one route: dq-gate `-32008` (MCP) / `-32010` (A2A),
data-classification `-32011` (MCP) / `-32012` (A2A). A2A reserves `-32001..=-32009` for its own
errors, so A2A codes stay above that range. The A2A REST binding always uses HTTP 403 +
`google.rpc.Status`, with a per-gate `ErrorInfo.domain`/`reason`.

## Shared CDGC mechanics

1. `POST https://<pod>.informaticacloud.com/identity-service/api/v1/Login` `{"username","password"}`
   -> `sessionId`, `orgId`.
2. `GET .../identity-service/api/v1/jwt/Token?client_id=idmc_api&nonce=<value>` with
   `cookie: USER_SESSION=<sessionId>` + `IDS-SESSION-ID: <sessionId>` -> `jwt_token` (~25-30 min;
   both policies re-authenticate on every cache-miss refresh, no token reuse).
3. Content calls: `Authorization: Bearer <jwt>`, `X-INFA-ORG-ID: <orgId>` against the CDGC API host
   (configure `cdgcBaseApiUrl` explicitly -- it is not reliably returned by Login).

## Credentials

This repo is public. Never commit CDGC credentials or real org ids: the playground `api.yaml` files
point at the local mock containers with dummy creds. For live testing, put real values in a local,
uncommitted copy or environment variables, and keep `registration.yaml` / `.env` out of git (both
are gitignored per policy). `cdgcOrgUsername` and `cdgcOrgPassword` are `security:sensitive` in
both definitions.
