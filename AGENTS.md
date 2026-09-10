<!-- Copyright 2026 Salesforce, Inc. All rights reserved. -->
# AGENTS.md

Context for AI coding agents (Claude Code, Cursor, Codex, Aider, etc.) working in a project scaffolded from this template. Follows the [agents.md](https://agents.md) convention.

## What this repository is

A custom policy for [MuleSoft Flex Gateway](https://docs.mulesoft.com/gateway/) built with the [Policy Development Kit (PDK)](https://docs.mulesoft.com/pdk/latest/). The policy is written in Rust, compiled to WebAssembly (target `wasm32-wasip1`), and runs as a [proxy-wasm](https://github.com/proxy-wasm/spec) filter inside Flex Gateway. PDK abstracts the asynchronous proxy-wasm event model into a simpler `async`/`await` API.

## Project layout

```
.
├── definition/gcl.yaml          # Policy schema — declares configurable properties
├── src/
│   ├── lib.rs                   # Filter logic — edit here
│   └── generated/config.rs      # AUTO-GENERATED from definition/gcl.yaml — do NOT edit by hand
├── tests/
│   ├── requests.rs              # Integration tests (pdk-test, requires Docker)
│   ├── common/mod.rs
│   └── config/
│       └── note.txt             # Drop your registration.yaml here per these instructions
├── playground/                  # `make run` artifacts: local Flex Gateway + sample backend
│   ├── docker-compose.yaml      # Spins up Flex Gateway and a backend container
│   └── config/
│       ├── api.yaml             # Sample API + policy config consumed at runtime — edit to test
│       ├── logging.yaml
│       └── custom-policies/     # Your built .wasm artifacts land here (gitignored)
├── Cargo.toml
└── Makefile
```

Edit `definition/gcl.yaml` to change the configurable properties, `src/lib.rs` for filter logic, and `tests/requests.rs` for integration tests. Everything else is generated or boilerplate.

## proxy-wasm runtime

PDK runs on proxy-wasm — single-threaded inside the policy runtime. Code that compiles fine on a desktop target can still be rejected at runtime if it violates these:

- No multithreading; no `Arc`, `Mutex`, `RwLock`, or other cross-thread synchronization primitives.
- No `block_on`, no synchronous waits, no blocking I/O.
- No full async runtimes (Tokio multi-thread, blocking features, etc.). Use the async model PDK exposes.
- Use `thread_local!` when process-wide state is genuinely required.

## Coding rules

- **Rust toolchain:** stable only. Nightly features, `rustc` flags, or `rustup` overrides selecting nightly are not allowed.
- **`unsafe`:** forbidden in policy code.
- **`.unwrap()`:** avoid in production code.
- **`src/generated/config.rs` is auto-generated** from the policy definition — never edit by hand; regenerate via the project's build tooling.
- **License header:** every source file starts with `// Copyright YYYY Salesforce, Inc. All rights reserved.`

## Common pitfalls

These cause real bugs in production policies. Watch for them before writing code.

- **State machine consumes ownership.** `RequestState` → `RequestHeadersState` → `RequestBodyState` (and the response-side equivalents) each transition consumes the previous state. Read everything you need from headers before transitioning to the body — you cannot go back.
- **Check `contains_body()` before reading or writing the body.** On a bodyless request (GET, HEAD, empty POST) `.body()` returns an empty buffer, and writes to it will not reach upstream — you can't add a body that wasn't there in the first place.
- **Definition defaults arrive pre-filled.** Flex Gateway applies `default` values from the policy definition before the configuration bytes reach the policy, so a `required: true` property with a `default` is never absent at parse time. Do not write code that branches on "missing required field".
- **Always include the raw config bytes in parse-error logs** (via `String::from_utf8_lossy`). Without them the operator cannot debug why the policy refused to load.
- **`Flow::Break(response)` rejects, `Flow::Continue(())` allows.** Inverting these is a security hole: an auth filter that returns `Continue` on failure passes the unauthenticated request to the upstream.
- **Response filter must handle `RequestData::Break`.** If the request was rejected by an earlier filter, the response filter receives `Break(response)`, not `Continue(data)`. `.unwrap()` on a `Break` will crash.
- **Header names are case-insensitive.** Lowercase both sides before comparing (`name.to_ascii_lowercase()`); production policies do this consistently.
- **Decide explicitly how `HttpClient` errors are handled** (timeout, DNS failure, upstream 5xx). Fail-open vs fail-closed is a security decision — surface it in the policy config, do not silently swallow `.await` errors.

## Demo: testing the DQ gate from Claude Desktop

The policy is wired to two MCP connectors in Claude Desktop that share the same mock guest data but are governed by assets at different DQ scores:

| Connector | Asset DQ score | blockThreshold | Expected result |
|---|---|---|---|
| `parks-guests-mcp` | 95 | 80 | ✅ allowed |
| `parks-guests-b-mcp` | 65 | 80 | ❌ blocked by DQ gate |

To run the demo, simply ask Claude to call both connectors (e.g. "look up guests checking out today"). The gate rejects the low-score connector inline and returns a generic block error — by default it does **not** disclose the score, threshold, or asset id to the client — no Docker or local Flex Gateway needed.

### How to surface DQ Gate errors to users

By default the policy does **not** disclose the raw DQ score, `blockThreshold`, or asset id to the MCP client: the block message is generic and only the coarse `x-dq-gate-status` header (`ok`/`warn`/`blocked`/`skipped`/`unknown`) is emitted. The exact score, threshold, and asset id are recorded in the gateway logs only. An operator can opt in to disclosing them to the client — in the block message and via the `x-dq-gate-score` header — by setting `discloseScoreDetails: true`, but that lets clients probe threshold boundaries, so it is off by default.

When a connector call fails with a DQ Gate block, **do not expose raw scores or thresholds** in the response even if disclosure is enabled. Instead, explain the block in plain language, for example:

> "Property B is blocked by the DQ Gate — the data quality for this source didn't meet the required standard, so results from it cannot be shown."

Always tell the user *which* property or connector was blocked and that the DQ Gate was the reason. This gives enough context to follow up with an admin without exposing internal scoring details.

`playground/demo.sh` exists for a self-contained Docker-based demo (two isolated Flex stacks, same contrast), but for a quick Claude Desktop demo the MCP connectors above are sufficient.

## Protocol support: MCP and A2A

The gate is **protocol-aware but score-agnostic**: the DQ-score decision (allow / warn / block) is one
piece of logic; how a request is *recognized* and how a *rejection is shaped* branch by protocol. Two
recognition paths feed the same score gate (both only after the POST + `application/json` guards):

1. **JSON-RPC 2.0 envelope** — shared by MCP and the A2A JSON-RPC transport. The **method name alone**
   classifies both the protocol and, for A2A, the version, because the three method vocabularies are
   mutually disjoint (`classify_jsonrpc_method`):
   - **MCP gated:** `tools/call`, `resources/read`, `prompts/get`.
   - **A2A v0.3.0 gated:** `message/send`, `message/stream`.
   - **A2A v1.0 gated:** `SendMessage`, `SendStreamingMessage`.
   - **Exempt (pass-through, no score fetch):** MCP handshake/discovery (`initialize`, `tools/list`, …)
     and A2A housekeeping — v0.3.0 `tasks/*`, `agent/*`; v1.0 `GetTask`, `ListTasks`, `CancelTask`,
     `*PushNotificationConfig*`, `GetAgentCard`/`GetExtendedAgentCard`, …
2. **A2A HTTP+JSON (REST) send binding** — recognized by request **path** (final segment
   `message:send` / `message:stream`), since the body is a bare `SendMessageRequest`, not a JSON-RPC
   envelope. The version comes from the **`A2A-Version` header** (`1.0` → v1.0; absent → v0.3.0), the
   only place a header is consulted for version — the JSON-RPC path never needs it.

Anything matching neither path (a batch array, a non-send REST path, a notification, unparsable JSON,
`application/grpc`) passes through **ungated** (fail-open recognition).

### Why A2A rejections are shaped differently from MCP

MCP treats a JSON-RPC error as protocol-level, so an MCP block is **HTTP 200 + `-32008`**. A2A blocks
are **HTTP 403 + `-32010`** instead, for two reasons:

- **403 is the A2A-conformant transport signal** for a well-formed but policy-denied call.
- **`-32010` sits *outside* A2A's reserved band** `-32001..=-32009`. That band already assigns
  `-32008 = ExtensionSupportRequiredError` and `-32009 = VersionNotSupportedError` in A2A v1.0, so
  reusing MCP's `-32008` would collide with a real A2A error. `-32010` is the first free slot above the
  band.

On **v1.0** the `error.data` MUST carry a `google.rpc.ErrorInfo` (`reason: DATA_QUALITY_BELOW_THRESHOLD`,
`domain: dq-gate.mulesoft.com`, plus a `metadata` map gated by `discloseScoreDetails`). On **v0.3.0**
`error.data` is free-form and included only when disclosing. `a2a_block_response` builds this; the MCP
`block_response` is unchanged. Both share `block_message` / `block_headers` so the wording, the
`x-dq-gate-status: blocked` header, and the disclosure gate stay identical across protocols. The same
A2A body is returned on both A2A transports — a REST client keys on the `403`.

## Fail-open vs fail-closed posture (a security decision)

How the gate behaves when it *cannot* obtain a trustworthy score is a security decision, surfaced
through two **orthogonal** config knobs — do not conflate them:

| Situation | Knob | Default | Behavior on default |
|---|---|---|---|
| **No score at all** — cold worker start before the first fetch, or a `failOpenOnCdgcError=false` failure with an empty cache | `blockOnUnknownScore` | `true` (fail-**closed**) | Block the request (MCP: HTTP 200 + JSON-RPC `-32008`; A2A: HTTP 403 + JSON-RPC `-32010`) |
| **Transient CDGC error** on an asset whose score is *already* cached | `failOpenOnCdgcError` | `true` (fail-**open** on cache) | Serve the last-known-good cached score |

- **`blockOnUnknownScore` defaults fail-CLOSED.** The gate blocks rather than silently passing
  ungated traffic during exactly the windows an operator is least likely to notice (startup, a CDGC
  outage with a cold cache). Setting it `false` is a deliberate **soft launch**: unknown-score
  traffic passes through ungated with `x-dq-gate-status: unknown`, and a **one-shot per-worker
  warning** (`UNGATED_BYPASS_LOGGED`) marks the window during which the control is disabled — enough
  to be observable in the logs without flooding them.
- **`failOpenOnCdgcError` governs a different case:** a *transient* refresh failure when a
  last-known-good score already exists. `true` keeps serving the cached score; `false` treats the
  failure as an unknown score and defers to `blockOnUnknownScore`. It never applies when there is no
  cached score to fall back to.

### Denials surface as PolicyViolations

Every **block** path calls `violations.generate_policy_violation()` immediately before its
`Flow::Break`, so denials appear in **Anypoint Monitoring** (see `pdk-policy-violations`). Note:

- A `PolicyViolation` does **not** itself reject the request — it is telemetry. The rejection is the
  paired `Flow::Break(block_response(...))`. Both are always emitted together on a block.
- The `PolicyViolation` object carries only the policy name/type (the PDK API exposes no custom
  fields), so the **asset id, score, and threshold live in the correlated `warn!` log** on the same
  path, not on the violation object.
- **Pass-through paths emit no violation** — a soft-launch bypass, a warn-level score, and an
  exempt/non-MCP request are all allowed, so none is a denial. (Empirically verified in the unit
  tests: a `Flow::Break` response carries the request-context violation through to
  `response.violation()`, while a `Flow::Continue` response reports `None`.)

## CDGC fetch latency: inline refresh + bounded budget

The DQ score is refreshed **inline** — the cache-miss request that wins the refresh lock performs the
CDGC Login → JWT → Detail chain itself, on the agent's request hot path. A background `Timer`-based
refresher was considered and **deliberately rejected** for this iteration: it adds a separate
scheduler with its own failure and observability surface. Inline keeps the model simple; the cost is
**bounded, not moved**.

- **Per-call timeout** (`timeout`, default 5000 ms) caps each single CDGC HTTP call.
- **Overall refresh budget** (`CDGC_REFRESH_BUDGET_MS`, ~10s) caps the *whole* three-call chain: each
  call's effective timeout is clamped to the budget still remaining (`next_call_timeout`), so total
  blocking can never exceed the cap. This replaced the previous ~180s worst case (three 60s calls).
- When the budget is exhausted the refresh **aborts** and the request falls back to the configured
  unknown-score posture — serve last-known-good under `failOpenOnCdgcError=true`, otherwise apply
  `blockOnUnknownScore`. The agent's call is never blocked unbounded.

Time is read via the injected PDK `Clock` (`clock.now()`), never `SystemTime::now()`, so it is
host-sourced and testable.

## Resources

- PDK documentation — https://docs.mulesoft.com/pdk/latest/
- Flex Gateway documentation — https://docs.mulesoft.com/gateway/
- Public policy examples — https://github.com/mulesoft/pdk-custom-policy-examples
