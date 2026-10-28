# infa-omni-pdk

MuleSoft Flex/Omni Gateway custom policies, built with the
[Policy Development Kit (PDK)](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview), that gate
agent traffic (**MCP** tool calls and **A2A** message-send invocations) on governance metadata in
Informatica IDMC **CDGC**. Each policy is a self-contained Rust / `wasm32-wasip1` crate with its own
`Makefile`, definition, playground, and tests.

| Policy | Gates on | MCP block | A2A JSON-RPC block | A2A REST block |
|---|---|---|---|---|
| [`dq-gate-policy`](dq-gate-policy/) | A CDGC asset's data-quality rollup score vs. warn/block thresholds | `-32008` | `-32010` | HTTP 403 |
| [`data-classification-policy`](data-classification-policy/) | Worst-case `core.sensitivity` (LOW/MEDIUM/HIGH) across a list of governed columns vs. a ceiling | `-32011` | `-32012` | HTTP 403 |

Both share the same runtime design: CDGC results are cached in PDK `DataStorage` (local, or
gossip-replicated with `distributed: true`) and refreshed lazily inline under a single-flight
refresh lock, with every CDGC call clamped to a ~10s overall budget. Handshake/housekeeping
methods (`initialize`, `tools/list`, A2A task queries, ...) pass through ungated.

## Working on a policy

```bash
cd dq-gate-policy              # or data-classification-policy
make setup                     # once: cargo-anypoint + llvm-cov
make build                     # definition + wasm implementation
cargo test --lib               # unit tests
make test                      # integration tests (Docker)
make run                       # local Flex Gateway playground against mock CDGC
make publish                   # dev asset to Exchange (needs anypoint-cli-v4 login)
```

See each policy's `README.md` for configuration and behaviour.
