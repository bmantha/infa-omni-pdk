# IDMC Data Quality Gate

A MuleSoft Flex/Omni Gateway custom policy that gates inbound **MCP** tool-invocation traffic **and
A2A (Agent2Agent) message-send** traffic on the current **data-quality (DQ) score** of a CDGC-governed
asset in Informatica IDMC. It is written in Rust with the
[Policy Development Kit (PDK)](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview) and compiled
to WebAssembly (`wasm32-wasip1`).

## What it does

The policy compares the monitored asset's DQ score against two configurable thresholds and acts
**before the request reaches the upstream MCP server or A2A agent**. Only the content-bearing
invocations are gated:

- **MCP** JSON-RPC calls — `tools/call`, `resources/read`, `prompts/get`.
- **A2A** message-send invocations — across **both A2A v0.3.0 and v1.0** and both transports:
  - the JSON-RPC send methods: `message/send` / `message/stream` (v0.3.0) and
    `SendMessage` / `SendStreamingMessage` (v1.0);
  - the A2A HTTP+JSON (REST) send binding (a path ending in `message:send`) — a v1.0-only surface.

The score decision is identical for both protocols; only the **rejection shape** differs so each
client sees a protocol-conformant error (see below):

| Score vs. thresholds | MCP outcome | A2A JSON-RPC outcome | A2A REST outcome |
|---|---|---|---|
| ≥ `warnThreshold` | Allowed (`x-dq-gate-status: ok`) | Allowed (`x-dq-gate-status: ok`) | Allowed (`x-dq-gate-status: ok`) |
| ≥ `blockThreshold`, `< warnThreshold` | Allowed + warning (`warn`) | Allowed + warning (`warn`) | Allowed + warning (`warn`) |
| `< blockThreshold` | HTTP 200 + JSON-RPC `-32008` | HTTP 200 + JSON-RPC `-32010` (in-band) | HTTP 403 + `google.rpc.Status` |

A PolicyViolation is reported on every block. Defaults are `warnThreshold: 90` / `blockThreshold: 80`.

### Protocol-conformant A2A rejections

Both MCP and the A2A **JSON-RPC** binding treat a JSON-RPC error as protocol-level, so the block is
carried **in-band on HTTP 200** inside the JSON-RPC envelope (returning an HTTP 4xx for a well-formed
JSON-RPC call is a spec mistake). MCP uses error code `-32008`; A2A uses **`-32010`** — chosen to sit
*outside* A2A's own reserved band (`-32001..=-32009`, which already assigns `-32008` to
`ExtensionSupportRequiredError` and `-32009` to `VersionNotSupportedError` in v1.0), so it never
collides with a real A2A error. On the A2A JSON-RPC binding the `error.data` shape is version-specific:

- **A2A v1.0** — `error.data` is a **single-element array** carrying a
  [`google.rpc.ErrorInfo`](https://cloud.google.com/apis/design/errors) (`reason:
  DATA_QUALITY_BELOW_THRESHOLD`, `domain: dq-gate.mulesoft.com`), the structured form v1.0 expects.
- **A2A v0.3.0 (Legacy)** — `error.data` is free-form and included only when `discloseScoreDetails` is
  on (Legacy predates the structured `ErrorInfo` binding).

The A2A **HTTP+JSON (REST)** send binding is different: it is not a JSON-RPC envelope, so it answers
with a **native HTTP 403** and a [`google.rpc.Status`](https://cloud.google.com/apis/design/errors)
body — `{"error":{"code":403,"message":…,"details":[ErrorInfo]}}` with `error.code` mirroring the HTTP
status and no JSON-RPC envelope. The `ErrorInfo` in `details` is the same one the v1.0 JSON-RPC block
carries in `data`.

A2A **housekeeping** methods — task management, push-notification config, and agent-card discovery
(`tasks/*`, `agent/*` in v0.3.0; `GetTask`, `ListTasks`, `*PushNotificationConfig*`, `GetAgentCard`, …
in v1.0) — touch no asset data and pass through **ungated**, exactly like MCP's handshake/discovery
methods.

> **gRPC transport:** A2A's optional gRPC binding is a documented pass-through — its
> `application/grpc` content type is not `application/json`, so the recognition step skips it ungated.
> Gate A2A agents on their JSON-RPC or REST HTTP surface.

### CDGC / IDMC integration

The DQ score is retrieved from CDGC via a short inline chain — IDMC **Login** → **JWT** → asset
**detail** — using a service-account credential. Multiple DQ dimensions are combined into one score by
`scoreAggregation` (`min`, the conservative default, or `average`). The whole chain is bounded by a
per-call `timeout` and an overall hot-path latency budget, so a slow or failing CDGC never blocks an
agent call unbounded.

### Caching

Scores are cached in **PDK-native `DataStorage`** and refreshed lazily on a TTL (`refreshIntervalSeconds`,
default 24h — CDGC DQ scans run roughly daily), so the vast majority of requests are a fast local read
with no CDGC round-trip. Set `distributed: true` to share the cache and refresh lock across gateway
replicas via gossip-replicated storage; the default keeps per-replica in-memory state.

### Safety posture

- **Fail-open recognition:** only genuine MCP tool calls and A2A message-send invocations are gated.
  Non-POST requests, non-JSON bodies, MCP handshake/discovery methods, A2A housekeeping methods,
  notifications, JSON-RPC batches, and unrecognized paths pass through ungated, so the policy never
  breaks non-gated traffic or connection setup.
- **Fail-closed on the unknown:** when no score is available at all (cold start, or a CDGC outage with
  an empty cache), the gate blocks by default (`blockOnUnknownScore: true`). A deliberate soft launch can
  set it `false`; the bypass window is logged once per worker.
- **No client disclosure by default:** raw scores, thresholds, and the asset id are logged server-side
  only. `discloseScoreDetails: true` opts into surfacing them to the client.

Every configurable property is declared in [`definition/gcl.yaml`](definition/gcl.yaml). See
[`AGENTS.md`](AGENTS.md) for the design rationale and [`playground/`](playground/) for a self-contained
two-stack (pass vs. block) local demo.

## Make command reference
This project has a Makefile that includes different goals that assist the developer during the policy development lifecycle.

*For more information about the Makefile, see [Makefile](https://docs.mulesoft.com/pdk/latest/policies-pdk-create-project#makefile).*

### Setup
The `make setup` goal installs the Policy Development Kit internal dependencies for the rest of the Makefile goals.

*For more information about `make setup`, see [Setup the PDK Build environment](https://docs.mulesoft.com/pdk/latest/policies-pdk-create-project#setup-the-pdk-build-environment).*

### Build asset files
The `make build-asset-files` goal generates all the policy asset files required to build, execute, and publish the policy. This command also updates the `config.rs` source code file with the latest configurations defined in the policy definition.

*For more information about creating a policy definition, see [Defining a Policy Schema Definition](https://docs.mulesoft.com/pdk/latest/policies-pdk-create-schema-definition).*

*For more information about `make build-asset-files`, see [Compiling Custom Policies](https://docs.mulesoft.com/pdk/latest/policies-pdk-compile-policies).*

### Build
The `make build` goal compiles the WebAssembly binary of the policy.
Since the source code must be in sync with the policy definition configurations, this goal runs the `build-asset-files` before compiling.

*For more information about `make build`, see [Compiling Custom Policies](https://docs.mulesoft.com/pdk/latest/policies-pdk-compile-policies).*

### Run
The `make run` goal provides a simple way to execute the current build of the policy in a Docker containerized environment. In order to run this goal, the `playground/config` directory must contain a set of files required for executing the policy in a Flex Gateway instance:
- A `registration.yaml` file generated by performing a Flex Gateway registration in Local Mode. If you already have an instance registered in Local mode, you can reuse the registration file you have and copy it in the `playground/config` folder.
Otherwise, to complete the registration we recommend using the Anypoint Platform:
    1. Go to `Runtime Manager`
    2. Navigate to the `Flex Gateway` tab
    3. Click the `Add Gateway` button
    4. Select `Docker` as your OS and copy the registration command replacing `--connected=true` to `--connected=false`.
    5. Paste the command and run it in the `playground/config` directory.

- An `api.yaml` file updated with the desired policy configuration. This file also supports adding other policies to be applied along the one being developed.

The `playground/config` directory can also contain other resource definitions, such as accessory services used by the policy (Eg. a remote authentication service).

*For more information about `make run`, see [Debugging Custom Policies Locally with PDK](https://docs.mulesoft.com/pdk/latest/policies-pdk-debug-local).*

### Test
The `make test` goal runs unit tests and integration tests. Integration tests are placed in the `tests` directory and are configured with the files placed at the
`tests/<module-name>/<test-name>` directory.

*For more information about writing integration tests, see [Writing Integration Tests](https://docs.mulesoft.com/pdk/latest/policies-pdk-integration-tests).*

### Publish
The `make publish` goal publishes the policy asset in Anypoint Exchange, in your configured Organization.

Since the publish goal is intended to publish a policy asset in development, the _assetId_ and name published will explicitly say `dev`, and the versions published will include a timestamp at the end of the version. Eg.
- groupId: your configured organization id
- visible name: _{Your policy name} Dev_
- assetId: _{your-policy-asset-id}-dev_
- version: _{your-policy-version}-20230618115723_

*For more information about publishing policies, see [Uploading Custom Policies to Exchange](https://docs.mulesoft.com/pdk/latest/policies-pdk-publish-policies).*

### Release
The `make release` goal also publishes the policy to Anypoint Exchange, but as a ready for production asset. In this case, the groupId, visible name, assetId and version will be the ones defined in the project.

*For more information about releasing policies, see [Uploading Custom Policies to Exchange](https://docs.mulesoft.com/pdk/latest/policies-pdk-publish-policies).*

### Skipping unchanged definition publishes
Both `make publish` and `make release` accept the `SKIP_UNCHANGED_DEFINITION` variable (default `true`). When enabled, the definition is not republished if its content matches the version already published in Exchange; instead the implementation asset is published with its dependency pointing at that already-published definition version. Set `SKIP_UNCHANGED_DEFINITION=false` to always republish the definition:

```
make publish SKIP_UNCHANGED_DEFINITION=false
```


### Policy Examples

The PDK provides provides a set of example policy projects to get started creating policies and using the PDK features. To learn more about these examples see [Custom policy Examples](https://docs.mulesoft.com/pdk/latest/policies-pdk-policy-templates).
