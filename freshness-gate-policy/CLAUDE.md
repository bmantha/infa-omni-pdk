# Freshness Gate Demo

This project is a MuleSoft PDK policy that gates AI agent / MCP tool calls on a live
**SLA/freshness score** read from Informatica CDGC, structurally cloned from the sibling
`dq-gate-policy` project (same Login->JWT->Detail->gate skeleton, same threshold logic) but
reading a different signal. It's part of the "Omni Gateway Inventory Freshness" demo:

- **Warehouse East** — synced on schedule, freshness score **100** (passes, threshold 80)
- **Warehouse West** — stuck sync job, freshness score **62** (blocked, threshold 80)

When referencing these in responses, use "Warehouse East" / "Warehouse West".

Demo narrative doc (mirrors the DQ gate's canvas): https://salesforce.enterprise.slack.com/docs/T2ULD0UKW/F0C2HMCQY22

## Why this is a separate policy, not a config variant of dq-gate-policy

`dq-gate-policy` reads CDGC's `dataQuality` **rollup segment** on an asset (a connector/dataset),
which aggregates *multiple* DQ dimensions across possibly many columns into one number via
`scoreAggregation` (min/average). That rollup is only populated for RuleInstances produced by
Informatica's own automated ICDQ/CDI pipeline (`core.producer: "infa-producer.dq"`, `isAutomated:
true`) — a flag the public CDGC API cannot set.

`freshness-gate-policy` instead reads **one specific RuleInstance's own `value` attribute**
directly (via `selfAttributes`), tied to exactly one column (`LAST_SYNCED_AT`). This isn't a
downgrade — it's the *correct* granularity for a freshness SLA, which is inherently about one
timestamp column, not a blended asset-wide score. It also happens to be necessary: our
manually-created RuleInstances don't qualify to feed the `dataQuality` rollup, so reading the
RuleInstance directly is the only way to get a real number out of CDGC for this use case.

## Real CDGC objects backing this demo

The live demo-org object ids (RuleTemplate/RuleInstance internal ids, linked tables, current
scores) are kept out of this public repo. If present, see the gitignored `DEMO-ORG.local.md` next
to this file; otherwise ask the policy owner.

## API mechanics discovered this project (undocumented, found by direct experimentation)

Three-step CDGC auth, reused everywhere:
1. `POST https://dmp-us.informaticacloud.com/identity-service/api/v1/Login`
   body `{"username","password"}` -> `sessionId`, `orgId`.
2. `GET https://dmp-us.informaticacloud.com/identity-service/api/v1/jwt/Token?client_id=idmc_api&nonce=1234`
   headers `cookie: USER_SESSION=<sessionId>`, `IDS-SESSION-ID: <sessionId>` -> `jwt_token`
   (expires ~25-30 min).
3. All content calls: `Authorization: Bearer <jwt>`, `X-INFA-ORG-ID: <orgId>`, host
   `cdgc-api.dmp-us.informaticacloud.com`.

**Creating/updating objects** — single endpoint for everything:
`POST {host}/ccgf-contentv2/api/v1/publish`, header `X-INFA-PRODUCT-ID: CDGC` (this determines
`core.producer` on created assets — `CDGC` = user-editable in UI, `MCC` = locked).
- `INSERT` needs `attributes` only.
- `UPDATE` needs **both** `attributes` and a parallel `attributeUpdateOperationTypeMap` (a
  `{attrName: opType}` map) or it 400s with "cannot be null for UPDATE". The only valid opType is
  **`OVERWRITE`** (found by brute force; `SET`/`UPDATE`/`REPLACE`/`MODIFY`/`ADD` all 400).

**The documented score-upload endpoint does not work here**: `dq_manager.py`'s `upload-scores`
command POSTs to `/data360/content/v1/assets/dqscores` — tried on both `idmc-api` and `cdgc-api`
hosts, POST and PUT, always `HTTP 500 "Request method '<X>' is not supported"`. **Workaround
used instead**: a plain `UPDATE` publish call against the RuleInstance's own attributes (`value`,
`totalCount`, `exception`, `scannedTime`), which works and is what's currently live.

**Verified working request body** (confirmed live on 2026-09-17, both items returned
`statusCode: 201, messageCode: "CONTENT_SUCCESS"`):

```json
{
  "items": [
    {
      "elementType": "OBJECT",
      "operation": "UPDATE",
      "type": "com.infa.ccgf.models.governance.RuleInstance",
      "identity": "RTO-LSA-EAST-001",
      "identityType": "EXTERNAL",
      "attributes": {
        "com.infa.ccgf.models.governance.value": 100.0,
        "com.infa.ccgf.models.governance.totalCount": 50,
        "com.infa.ccgf.models.governance.exception": 0,
        "com.infa.ccgf.models.governance.scannedTime": "2026-09-17T15:08:29.000Z"
      },
      "attributeUpdateOperationTypeMap": {
        "com.infa.ccgf.models.governance.value": "OVERWRITE",
        "com.infa.ccgf.models.governance.totalCount": "OVERWRITE",
        "com.infa.ccgf.models.governance.exception": "OVERWRITE",
        "com.infa.ccgf.models.governance.scannedTime": "OVERWRITE"
      }
    }
  ]
}
```

Key fields beyond `attributes`/`attributeUpdateOperationTypeMap` (these were the missing pieces
during earlier blind reconstruction attempts): `elementType: "OBJECT"`, `operation` (not
`operationType`), `type` = fully-qualified class `com.infa.ccgf.models.governance.RuleInstance`,
`identity` = the RuleInstance's **external ID** (e.g. `RTO-LSA-EAST-001`, not the internal UUID),
and `identityType: "EXTERNAL"` telling the API which kind of ID `identity` is.
`scannedTime` takes an ISO-8601 string (`YYYY-MM-DDTHH:MM:SS.000Z`), not epoch millis, on write —
though it reads back as epoch millis via the Detail API's `selfAttributes` segment. Response is
`207` with a `publishJobId`/`publishTaskId` and a per-item `statusCode`/`messageCode`; East/West
were both re-verified via a live GET immediately after and matched exactly (value/totalCount/
exception unchanged, scannedTime updated).

**Reading the score**: `GET {host}/data360/search/v1/assets/{id}?scheme=internal&segments=selfAttributes`,
parse `selfAttributes."com.infa.ccgf.models.governance.value"`. Do **not** use
`segments=dataQuality` on the RuleInstance or on the linked column/table — confirmed via repeated
testing that it stays empty for these manually-created RuleInstances (see "Why this is a separate
policy" above for the producer-flag reason).

## Code state (`src/lib.rs`, `definition/gcl.yaml`, `src/generated/config.rs`)

Already updated to match the above:
- `fetch_cdgc_score` calls Detail API with `segments=selfAttributes`, parses a single
  `RuleInstanceAttributes.value: Option<f64>` (was: `segments=dataQuality`, a `Vec<DqDimensionResult>`).
- `cdgcRuleInstanceId` config property (renamed from `cdgcAssetId` for clarity -- matches
  "RuleInstance" terminology used everywhere else) means **the RuleInstance's own internal id**,
  not the monitored table/column's id -- described as such in `gcl.yaml`, and its description now
  states explicitly that `value` is computed/published externally, never by this policy.
- `scoreAggregation` / `aggregate_score` / `DqDimensionResult` were removed entirely (a single
  RuleInstance's scalar `value` has nothing to aggregate). Removed from `gcl.yaml`,
  `generated/config.rs`, `lib.rs`, `playground/config/api.yaml`, `tests/requests.rs`.
- Unit test mock backend (`cdgc_score_backend` in `lib.rs`) and the integration test mock
  (`mock_cdgc` in `tests/requests.rs`) both updated to return `{"selfAttributes": {"com.infa...value": score}}`.
- `refreshIntervalSeconds` default lowered `3600 -> 900` (2026-09-17, after reviewing an external
  Gemini critique of `gcl.yaml`) in both `gcl.yaml` and `lib.rs`'s `DEFAULT_REFRESH_INTERVAL_SECONDS`
  constant -- a 1h cache meant a stuck sync job could go unenforced for up to an hour after CDGC's
  score already reflected it; 15m was chosen over Gemini's suggested 5m because every refresh is a
  *full* re-login (no JWT reuse/caching), so 5m would meaningfully multiply auth load for a signal
  that doesn't need minute-level resolution. `failOpenOnCdgcError`/`blockOnUnknownScore` descriptions
  in `gcl.yaml` gained guidance (no default change) recommending `false`/`true` respectively for
  endpoints where an agent takes a transactional/write action on the result, vs. the fail-open
  defaults which remain correct for read-only queries.
- `request_filter` now buffers request headers+body atomically via `into_headers_body_state()`
  (PDK's `enable_stop_iteration` feature) instead of releasing headers before deciding, so a
  blocked call can never leak through to the upstream MCP/A2A server while the score lookup is
  in flight.
- Gating now recognizes and classifies **both MCP and A2A (Agent2Agent)** traffic, not just MCP:
  a JSON-RPC 2.0 envelope's `method` name alone classifies both the protocol and, for A2A, the
  version (`message/send`/`message/stream` = A2A v0.3.0, `SendMessage`/`SendStreamingMessage` =
  A2A v1.0, everything else JSON-RPC = MCP), plus the A2A HTTP+JSON (REST) message-send binding
  recognized by its `message:send` path suffix. Only content-bearing "invoke the agent/tool" calls
  are gated; handshake/discovery/housekeeping methods and all `notifications/*` (never given a
  response, per JSON-RPC 2.0) pass through ungated. See `classify_jsonrpc_method`,
  `a2a_rest_send_path`, `GateProtocol`/`A2aBinding`/`A2aVersion` in `lib.rs`.
- Block responses now differ in error code by protocol/binding: MCP stays HTTP 200 +
  `JSONRPC_BLOCK_ERROR_CODE` (`-32008`, moved off `-32000` so as not to collide with the common
  router/proxy "path or method not found" convention); the A2A JSON-RPC binding is HTTP 200 +
  `A2A_BLOCK_ERROR_CODE` (`-32010`, chosen to sit just past A2A's own reserved `-32001..=-32009`
  range so it can never collide with an A2A-defined error like `ExtensionSupportRequiredError`
  at `-32008`); the A2A REST binding answers with a native HTTP `403` + a `google.rpc.Status` body
  (no JSON-RPC envelope at all).
- Added `discloseScoreDetails` config property (default `false`, see `gcl.yaml`): gates whether
  the exact score/`blockThreshold`/`cdgcRuleInstanceId` are revealed in the block message body
  (MCP; A2A's `google.rpc.ErrorInfo.metadata` on v1.0, a free-form string on v0.3.0) and in the
  `x-freshness-gate-score` response header on an *allowed* response. Off by default so a client
  can't probe threshold boundaries or learn asset identifiers; full detail is always still logged
  server-side via `warn!` regardless of this setting.
- Every `Flow::Break` block path now calls the injected `PolicyViolations::generate_policy_violation()`
  (both the below-threshold block and the `blockOnUnknownScore=true` unknown-score block), so
  blocks surface as first-class policy violations in the gateway, not just response headers.
- `cdgcRuleInstanceId` is percent-encoded (`percent_encode` in `lib.rs`) before interpolation into
  the CDGC Detail API path, since PDK's request builder performs no URL encoding itself and the
  id is operator-configured free text.
- `response_filter` completes at header state only (`into_headers_state()`), never transitions to
  body state — it only sets two diagnostic headers and must not buffer/stall a
  Streamable-HTTP (`text/event-stream`) response body.
- **Time is read via the injected PDK `Clock` (`clock.now()`), never `SystemTime::now()`** —
  ported 2026-09-17 from `bmantha/infa-omni-pdk`'s `AGENTS.md` convention (host-sourced, testable
  time). `Clock` is threaded from the `configure` entrypoint (where PDK/`pdk-unit` inject it
  automatically, same mechanism as `HttpClient`/`DataStorageBuilder`) through `request_filter` ->
  `resolve_score` -> `fetch_cdgc_score`/`get_cached_score`/`put_cached_score`/
  `try_acquire_refresh_lock`/`fetch_object_store_token`. No test changes were needed for this by
  itself — the 19 existing tests go through the full `configure`/`UnitTestBuilder` chain, which
  supplies a `Clock` the same way it supplies every other injected param.
- **`CDGC_REFRESH_BUDGET_MS` (10s) caps the whole inline `fetch_cdgc_score` chain** (Login -> JWT
  -> Detail), also ported from the same reference: each call's effective timeout is clamped (via
  `next_call_timeout`) to whatever's left of the budget after `elapsed_ms(start, clock.now())`,
  so the three chained calls can never together block an agent's request longer than 10s,
  regardless of `timeout`/`DEFAULT_TIMEOUT_MS` (still 60_000ms, unchanged — the budget clamp makes
  it irrelevant as a worst-case bound on this path). If the budget is exhausted before a call, the
  refresh aborts with an error and the caller falls back to the configured unknown-score posture.
  This budget does **not** cover the Object Store OAuth/get/put calls in `resolve_score` — only
  the three-call CDGC chain, matching the reference's scope.
- **One-shot per-worker bypass warning** (`UNGATED_BYPASS_LOGGED` thread_local), also ported from
  the same reference: previously the `blockOnUnknownScore=false` pass-through logged a `warn!` on
  *every* bypassed request; now it warns once per worker (still `debug!`-logs every occurrence),
  so a long fail-open window is observable without flooding the logs. Behavior otherwise
  unchanged — every request still passes through with `status: "unknown"`.

**Verified**: `cargo test --lib` — 23/23 pass (19 pre-existing + 4 new: `elapsed_ms`/
`next_call_timeout` budget-helper unit tests, and a two-request test proving the
`UNGATED_BYPASS_LOGGED` guard's second-request arm still passes through ungated).
`cargo build --target wasm32-wasip1 --release` — succeeds, zero warnings. Both re-verified
2026-09-17 after the `Clock`/budget/bypass-warning port above; `make test`'s Docker-based
integration suite was not re-run this session.

**Docker socket gotcha fixed in the `Makefile`**: `pdk-test`'s Rust Docker client (`bollard`)
doesn't consult the active `docker` CLI context and hardcodes `/var/run/docker.sock`, which
doesn't exist on hosts where Docker Desktop's socket lives elsewhere (macOS: typically
`~/.docker/run/docker.sock`) -- `make test`/`make test-coverage` failed with "Socket not found:
/var/run/docker.sock" until `DOCKER_HOST` was exported manually. The `Makefile` now resolves and
exports `DOCKER_HOST` from `docker context inspect` automatically (only if the caller hasn't
already set one), so `make test` works out of the box on any host/context.

## Playground mocks (`playground/mocks/mock_server.py`)

Written this session -- previously missing entirely (see git history / prior revision of this
file for that gap). A single stdlib-only Python `http.server` script, role-selected via the
`ROLE` env var:
- `cdgclogin` / `cdgcapi` / `objectstoreauth` / `objectstore` -- same shape as `dq-gate-policy`'s
  equivalent mocks, except `cdgcapi` returns this project's actual response shape
  (`{"selfAttributes": {"com.infa.ccgf.models.governance.value": <score>}}`, not dq-gate-policy's
  `dataQuality`/`core.score`), keyed off a `SLA_SCORE` env var (not `DQ_SCORE`), still mutable live
  via `PUT /score {"score": <value>}`.
- `warehouseMcp` (new role, doesn't exist in dq-gate-policy) -- the actual gated upstream: an MCP
  JSON-RPC 2.0 endpoint serving `initialize`/`tools/list`/`tools/call` for a single
  `get_inventory_levels` tool, returning **real-looking inventory JSON** (SKUs, descriptions,
  quantities, a `lastSyncedAt` timestamp) for whichever warehouse `WAREHOUSE` (`east`|`west`)
  selects -- unlike dq-gate-policy, whose mock backend is still generic `httpbin` echo (its
  `guests_mcp_schema.json` reference file was never actually wired to anything).

`playground/docker-compose.yaml` (single-stack, used by `make run`) now defaults `backend` to
`warehouseMcp`/`WAREHOUSE=east` and `cdgcapi` to `SLA_SCORE: "100"`, so `make run`'s out-of-the-box
demo is the Warehouse East happy path (`api.yaml`'s `cdgcRuleInstanceId` is `RTO-LSA-EAST-001`,
`blockThreshold: 80`, matching the real CDGC values above).

`playground/demo.sh` (new, adapted from dq-gate-policy's own `demo.sh`) spins up the **two
fully-isolated stacks** pattern -- Stack A (port 8081, Warehouse East, `SLA_SCORE: "100"`) and
Stack B (port 8082, Warehouse West, `SLA_SCORE: "62"`) -- to demo the pass/block contrast, plus a
live score-mutation + cache-TTL-expiry bonus section. Two bugs in the inherited pattern were fixed
while adapting it (both would have broken dq-gate-policy's own `demo.sh` too, on this machine):
`FLEX_IMAGE` was grepped from `docker-compose.yaml`'s literal, unexpanded
`${PDK_TEST_FLEX_IMAGE_NAME:-...}` placeholder instead of being resolved -- now resolved directly
in bash with the same defaults; and the live score-mutation step used
`wget --method=PUT`, which busybox `wget` (the only HTTP client in `python:3.12-alpine`) doesn't
support -- replaced with a `python3 -c "...urllib.request..."` call using the image's own Python.
Also fixed for this project's real behavior (dq-gate-policy's version assumed a wrong HTTP status):
MCP block responses are in-band JSON-RPC errors at **HTTP 200** with `error.code == -32008`, not a
4xx/5xx, so `demo.sh`'s pass/fail checks assert on that instead of an HTTP status code.

**Verified live via Docker this session** (`make build` + manual single-stack `docker compose up`,
then the full `playground/demo.sh`): Warehouse East returns HTTP 200 with real inventory JSON;
Warehouse West (score 62) is blocked HTTP 200 + `{"error":{"code":-32008,...}}`; mutating the
score live via `PUT /score` and waiting out the 30s `refreshIntervalSeconds` cache TTL flips West
to passing. Both the single-stack `docker-compose.yaml` and the two-stack `demo.sh` path were run
and torn down cleanly (`docker compose down`, `demo.sh --cleanup`).

## Known remaining cleanup (deferred, not urgent, inherited from the dq-gate-policy clone)

- `src/generated/config.rs` was hand-edited to match `gcl.yaml`, not regenerated via
  `make build-asset-files` -- should still match, but hasn't been confirmed via the real generator.

## Closing the automation gap (explicitly out of scope for this demo)

Today, nothing recomputes East/West's `value` on a schedule -- every `value`/`scannedTime`/
`TechnicalDescription` update so far has been a manual, one-off publish call made from a terminal
in a Claude Code session. **Decided 2026-09-17: building real automation is out of scope for this
demo.** The demo narrative instead simply *says* an automated DI job populates the score, and the
RuleInstances' `TechnicalDescription` (see above) is worded to match that narrative so a viewer
who opens the RuleInstance in CDGC mid-demo doesn't see text that contradicts what's being said.
Nothing about the actual mechanism changed -- this is a presentation decision, not an engineering
one, and this section's description of what's real vs. narrated should stay accurate even as the
catalog-facing text is written for the story.

In a real deployment this would normally be a CDI (Cloud Data Integration) mapping / Data Quality
"Scorecard" task: Source reads the real `LAST_SYNCED_AT` column, an Expression/Rule step computes
`age vs SLA window`, an Aggregator produces `totalCount`/`exception`, and IDMC's own internal
Data-Quality-to-Catalog integration publishes the result -- which is also the only path that can
stamp `infa-producer.dq`/`isAutomated: true` and populate the `dataQuality` rollup segment we
can't reach. That integration isn't required for this policy to work (it reads the RuleInstance
directly, not the rollup) -- it would only be needed to make the score *actually* live instead of
a manually-asserted current value dressed up as one. A much smaller alternative, if this is ever
revisited: any scheduled script that reads the real timestamp, computes the same formula, and
calls the same UPDATE+OVERWRITE publish call already proven working above.

## Credentials / auth for live testing

CDGC service-account login for org `dmp-us.informaticacloud.com` is read from environment
variables -- not stored in this file or repo:
- `CDGC_USERNAME`
- `CDGC_PASSWORD`

If a new session needs to make a live CDGC call and these aren't set in the shell, ask the user
for them rather than assuming a location; do not commit or display credentials. A JWT obtained
via the 3-step flow above is required for any live CDGC call and expires in ~25-30 min, so expect
to re-authenticate at the start of a new session before making any live API calls.
