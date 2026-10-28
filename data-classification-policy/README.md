# IDMC Data Classification Gate

A MuleSoft Flex/Omni Gateway custom policy (Rust + PDK, `wasm32-wasip1`) that gates inbound **MCP**
tool-invocation and **A2A** message-send traffic on the CDGC **data classifications** of the columns
a route can return. It is the classification counterpart of [`dq-gate-policy`](../dq-gate-policy/)
and shares its runtime design.

## What it does

For every gated call, the policy resolves each column in `governedColumnIds` to its linked CDGC
classification(s), takes the **worst-case** `core.sensitivity` rank across the whole list
(LOW=1, MEDIUM=2, HIGH=3; an unclassified column counts as 0), and compares it to
`maxAllowedClassification`. Above the ceiling the **whole call is blocked** before it reaches the
upstream MCP server or A2A agent; there is no per-column redaction.

Gated: MCP `tools/call`, `resources/read`, `prompts/get`; A2A `message/send`, `message/stream`
(v0.3), `SendMessage`, `SendStreamingMessage` (v1.0), and the REST `...message:send` binding.
Everything else (handshakes, listings, task queries, non-POST) passes through ungated.

| Outcome | MCP | A2A JSON-RPC | A2A REST |
|---|---|---|---|
| Rank <= ceiling | Allowed (`x-classification-gate-status: ok`) | Allowed | Allowed |
| Rank > ceiling | HTTP 200 + JSON-RPC `-32011` | HTTP 200 + JSON-RPC `-32012` | HTTP 403 + `google.rpc.Status` |
| No result (cold start, unresolvable column id) | Blocked when `blockOnUnknownClassification: true` (default), else passed ungated with status `unknown` | same | same |

A PolicyViolation is reported on every block. With `discloseClassificationDetails: true` the block
message and the `x-classification-gate-rank` / `x-classification-gate-columns` headers carry the tier,
ceiling and offending ids; by default the client sees only a generic message and the coarse status.

## Caching and CDGC calls

Results are cached in PDK `DataStorage` (per-replica, or gossip-replicated with `distributed: true`)
for `refreshIntervalSeconds` (default 24h). A stale entry is refreshed inline by one request at a
time (refresh lock, CAS writes). The cache key is the sorted, de-duplicated column list, so
reordering `governedColumnIds` does not create a separate entry. A refresh is Login -> JWT ->
batched column/classification reads (chunks of 5), each call clamped to `timeout` and to a ~10s
overall budget. If a refresh fails and a last-known-good result exists, `failOpenOnCdgcError: true`
keeps serving it.

## Build, test, run

```bash
make build            # definition + wasm
cargo test --lib      # unit tests
make test             # integration tests (Docker)
make run              # playground against the mock CDGC containers (playground/config/api.yaml)
```

The mock `cdgcapi` (see `playground/mocks/mock_server.py`) starts with VISIT_REASON unclassified, so
the default playground config is allowed at the MEDIUM ceiling. Linking it to the HIGH "Clinical
Visit Reason" classification with `PUT /classification` flips the same call to blocked once the 30s
cache lapses. `playground/demo.sh` walks through this transition against a live CDGC org.
