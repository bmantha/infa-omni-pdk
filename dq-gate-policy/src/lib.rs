// Copyright 2026 Salesforce, Inc. All rights reserved.
mod generated;

use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use pdk::data_storage::{DataStorage, DataStorageBuilder, DataStorageError, StoreMode};
use pdk::hl::timer::Clock;
use pdk::hl::*;
use pdk::logger;
use pdk::policy_violation::PolicyViolations;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::generated::config::Config;

/// Namespaces for the two PDK-native [`DataStorage`] instances this policy uses. They are kept
/// separate (per the distributed-cache guidance) because the score and the refresh lock have very
/// different lifetimes and, on the remote backend, different namespace TTLs.
const SCORE_CACHE_NAMESPACE: &str = "dq-gate-score";
const REFRESH_LOCK_NAMESPACE: &str = "dq-gate-refresh-lock";

const SCORE_CACHE_KEY_PREFIX: &str = "dq-score-";
const REFRESH_LOCK_KEY_PREFIX: &str = "dq-refresh-lock-";
const REFRESH_LOCK_TTL_SECONDS: i64 = 30;

/// Remote (gossip) namespace TTLs, in milliseconds.
///
/// The lock namespace expires entries automatically shortly after a lock's useful life, so a
/// crashed refresh holder cannot wedge the lock forever. The score namespace, by contrast, is
/// deliberately long-lived: staleness for *refresh* decisions is tracked manually via
/// [`CachedScore::timestamp`], and a stored score must outlive `refreshIntervalSeconds` by a wide
/// margin so a last-known-good value is still present to serve when `failOpenOnCdgcError=true` and
/// CDGC is unreachable. Never rely on TTL eviction to expire the score -- that would destroy the
/// very value fail-open depends on.
const REFRESH_LOCK_TTL_MS: u32 = (REFRESH_LOCK_TTL_SECONDS as u32) * 1000;
const SCORE_STORE_MIN_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000; // 30 days

/// Bounded retries for a CAS-guarded write; a conflict just means another writer won the race, so
/// a small count is enough (see `pdk-distributed-cache-gossip`).
const CAS_MAX_RETRIES: u32 = 3;

/// Per-call timeout (ms) for a single CDGC HTTP request (Login, JWT, or Detail). Deliberately small
/// (5s) because a cache-miss/refresh request performs these three calls *inline* on the agent's
/// request hot path -- see [`CDGC_REFRESH_BUDGET_MS`]. Overridable via the `timeout` config
/// property, but the per-call value is additionally clamped to the remaining overall budget.
const DEFAULT_TIMEOUT_MS: i64 = 5_000;
/// Overall hot-path latency cap (ms) for the *entire* inline CDGC refresh chain (Login -> JWT ->
/// Detail) on a single cache-miss request. The refresh model is deliberately inline (the triggering
/// request pays for the refresh) -- a background `Timer` refresher was considered and rejected for
/// this iteration to avoid a separate scheduler and its own failure/observability surface (#9). The
/// cost is *bounded* rather than moved: each of the three chained calls is capped at the budget
/// still remaining, so total blocking can never exceed this cap. When the budget is exhausted the
/// refresh aborts and the caller falls back to the configured unknown-score posture (serve
/// last-known-good under `failOpenOnCdgcError=true`, else apply `blockOnUnknownScore`), instead of
/// the previous ~180s worst case (three 60s calls).
const CDGC_REFRESH_BUDGET_MS: i64 = 10_000;
const DEFAULT_REFRESH_INTERVAL_SECONDS: i64 = 86_400;
/// JSON-RPC error code returned when a request is blocked. Chosen from the JSON-RPC 2.0
/// server-defined reserved range (`-32000..=-32099`) and deliberately NOT `-32000`, which collides
/// with the common router/proxy "path or method not found" convention; `-32008` is this policy's
/// dedicated "blocked by DQ Gate" code, used consistently on both block paths (below-threshold and
/// unknown-score).
const JSONRPC_BLOCK_ERROR_CODE: i64 = -32008;

/// JSON-RPC error code returned when an **A2A** invocation is blocked on the JSON-RPC binding. It MUST
/// differ from the MCP code above: A2A mints its own errors in the JSON-RPC server-defined reserved
/// range (`-32000..=-32099`) and has so far assigned `-32001..=-32009` (e.g. `-32008` =
/// `ExtensionSupportRequiredError`, `-32009` = `VersionNotSupportedError`, per the A2A spec at tags
/// v0.3.0 / v1.0.0). A2A has no dedicated "blocked by gateway policy" code, and the spec explicitly
/// permits servers to mint their own within that reserved range. `-32010` is the first slot *above*
/// A2A's currently-assigned codes, so it can never collide with an A2A-defined one -- whereas reusing
/// the MCP `-32008` here would collide with A2A's `ExtensionSupportRequiredError`.
const A2A_BLOCK_ERROR_CODE: i64 = -32010;
/// The A2A **HTTP+JSON (REST)** binding block returns this native HTTP status (Forbidden -- the request
/// is well-formed but denied by policy), carrying a `google.rpc.Status` body (pdk-a2a Shape 3). The A2A
/// **JSON-RPC** binding block, by contrast, stays HTTP 200 with the error carried in-band in the
/// JSON-RPC envelope -- the JSON-RPC transport convention shared with MCP; only the code (`-32010`) and,
/// on v1.0, the `google.rpc.ErrorInfo` `data` array distinguish it from an MCP block.
const A2A_REST_BLOCK_HTTP_STATUS: u32 = 403;
/// `google.rpc.ErrorInfo.reason` (UPPER_SNAKE_CASE, no "Error" suffix, per the convention) carried on
/// an A2A v1.0 block.
const A2A_ERROR_REASON: &str = "DATA_QUALITY_BELOW_THRESHOLD";
/// `google.rpc.ErrorInfo.domain` on an A2A v1.0 block. Deliberately NOT `a2a-protocol.org` -- that
/// domain identifies errors defined *by the A2A protocol itself*; this is a policy-owned domain
/// identifying the DQ Gate as the service that produced the error.
const A2A_ERROR_DOMAIN: &str = "dq-gate.mulesoft.com";
const HEADER_DQ_SCORE: &str = "x-dq-gate-score";
const HEADER_DQ_STATUS: &str = "x-dq-gate-status";

/// MCP handshake, discovery, and administrative methods that must always pass through ungated. An
/// MCP client (e.g. `mcp-remote`) issues `initialize` and `tools/list` just to establish the
/// connection and enumerate capabilities, before the agent has chosen to invoke anything --
/// blocking those means the client never even connects, rather than surfacing a per-call block.
/// `logging/setLevel` and `completion/complete` are control/helper calls that touch no governed
/// asset data, so gating them on a data-quality score would be semantically wrong.
///
/// DQ gating is deliberately reserved for the *content-bearing* methods that actually read the
/// governed asset's data: `tools/call`, `resources/read`, and `prompts/get`. Any method that is not
/// in this exempt list (and is not a notification) is gated.
///
/// Note: all `notifications/*` methods are handled earlier by the notification guard in
/// `request_filter` (a notification may never receive a response), so they are intentionally absent
/// from this list.
const EXEMPT_METHODS: &[&str] = &[
    "initialize",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
    "ping",
    "logging/setLevel",
    "completion/complete",
];

// ── A2A (Agent2Agent) method vocabulary ──────────────────────────────────────────────────────────
//
// The A2A JSON-RPC surface is the A2A analogue of MCP: the same gating principle applies -- only the
// *content-bearing* calls that actually invoke the target agent (send a message / task to it) are
// gated on the DQ score; everything else (task lifecycle, push-notification config, agent-card
// discovery) is housekeeping and passes through ungated.
//
// A2A's two protocol versions use DISJOINT method vocabularies, and both are disjoint from MCP's, so
// the method string alone classifies both the protocol AND (for A2A) the version -- no header needed
// for JSON-RPC:
//   * v0.3.0 uses slash-style names (`message/send`, `tasks/get`, `agent/...`);
//   * v1.0    uses PascalCase names (`SendMessage`, `GetTask`, ...);
//   * MCP never uses the `message/`, `tasks/`, or `agent/` prefixes, nor PascalCase.
// (Confirmed against the A2A spec at tags v0.3.0 and v1.0.0.)

/// A2A v0.3.0 message-send (unary) -- gated.
const A2A_V03_SEND: &str = "message/send";
/// A2A v0.3.0 message-send (streaming, SSE) -- gated: it invokes the agent just like the unary send.
const A2A_V03_STREAM: &str = "message/stream";
/// A2A v1.0 message-send (unary) -- gated.
const A2A_V1_SEND: &str = "SendMessage";
/// A2A v1.0 message-send (streaming) -- gated.
const A2A_V1_STREAM: &str = "SendStreamingMessage";

/// A2A housekeeping / discovery methods (both versions), enumerated so they are explicitly exempted
/// rather than falling through to the default MCP-gated arm of [`classify_jsonrpc_method`]. These
/// manage task state and delivery config or fetch the agent card -- none reads the governed asset's
/// data, so gating them on a DQ score would be wrong (and would wrongly *block* them below threshold).
const A2A_HOUSEKEEPING_METHODS: &[&str] = &[
    // v0.3.0 (slash-style)
    "tasks/get",
    "tasks/list",
    "tasks/cancel",
    "tasks/resubscribe",
    "tasks/pushNotificationConfig/set",
    "tasks/pushNotificationConfig/get",
    "tasks/pushNotificationConfig/list",
    "tasks/pushNotificationConfig/delete",
    "agent/getAuthenticatedExtendedCard",
    "agent/card",
    "agent/capabilities",
    // v1.0 (PascalCase)
    "GetTask",
    "ListTasks",
    "CancelTask",
    "SubscribeToTask",
    "CreateTaskPushNotificationConfig",
    "GetTaskPushNotificationConfig",
    "ListTaskPushNotificationConfigs",
    "DeleteTaskPushNotificationConfig",
    "GetExtendedAgentCard",
    "GetAgentCard",
];

/// The cached DQ score for `cdgcAssetId`, and when it was fetched -- compared against
/// `refreshIntervalSeconds` on every request to decide whether a live CDGC fetch is needed.
#[derive(Serialize, Deserialize, Clone)]
struct CachedScore {
    score: f64,
    timestamp: i64,
}

/// The stampede refresh lock's value: the unix second at which the current holder acquired it.
/// Compared against [`REFRESH_LOCK_TTL_SECONDS`] to decide whether a held lock is still fresh.
#[derive(Serialize, Deserialize, Clone)]
struct RefreshLock {
    acquired_at: i64,
}

#[derive(Deserialize)]
struct CdgcLoginResponse {
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "orgId")]
    org_id: String,
}

#[derive(Deserialize)]
struct CdgcJwtResponse {
    jwt_token: String,
}

/// One entry of the CDGC Detail API's `dataQuality` segment -- one per DQ dimension
/// (Completeness, Validity, Accuracy, ...) computed for the asset.
#[derive(Deserialize)]
struct DqDimensionResult {
    #[serde(rename = "core.score")]
    score: f64,
}

#[derive(Deserialize, Default)]
struct AssetDetailResponse {
    #[serde(rename = "dataQuality", default)]
    data_quality: Vec<DqDimensionResult>,
}

/// Data threaded from the request filter to the response filter, used only to annotate the
/// (allowed) response with diagnostic headers -- never consulted for the block decision, which
/// already happened in the request filter.
enum DqGateData {
    Evaluated { score: Option<f64>, status: &'static str },
}

/// Milliseconds elapsed between two [`SystemTime`] readings from the injected [`Clock`], clamped at
/// zero if the clock appears to go backwards. Used to track how much of [`CDGC_REFRESH_BUDGET_MS`]
/// the inline refresh chain has already consumed.
fn elapsed_ms(start: SystemTime, now: SystemTime) -> i64 {
    now.duration_since(start)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

/// Effective timeout for the *next* CDGC call on the inline refresh hot path: the configured
/// per-call timeout (`per_call_ms`) clamped to the overall refresh budget still remaining after
/// `elapsed_ms`. This is what enforces [`CDGC_REFRESH_BUDGET_MS`] across the three chained calls --
/// no single call may block past the remaining budget, so their sum is bounded. Returns `None` once
/// the budget is exhausted, signalling the caller to abort the refresh and fall back to the
/// unknown-score posture.
fn next_call_timeout(per_call_ms: i64, elapsed_ms: i64) -> Option<Duration> {
    let remaining = CDGC_REFRESH_BUDGET_MS - elapsed_ms;
    if remaining <= 0 {
        return None;
    }
    Some(Duration::from_millis(remaining.min(per_call_ms.max(0)) as u64))
}

fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Percent-encodes `value` for safe interpolation into a URL path segment or query value. Everything
/// outside the RFC 3986 "unreserved" set (`A-Z a-z 0-9 - _ . ~`) is escaped as `%XX` on a UTF-8 byte
/// basis. PDK's request builder takes the path/query string verbatim and performs no encoding, and
/// no third-party URL crate is pulled in (prefer-PDK / minimal-deps rules), so this small encoder
/// prevents an asset id or nonce containing `?`, `#`, `/`, `&`, `=`, or whitespace from altering the
/// request target or injecting query parameters (#12).
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Derives a per-request JWT nonce from a [`Clock`] reading: the nanoseconds elapsed since the Unix
/// epoch, as a decimal string. A nonce is a replay-protection primitive that must be unique per
/// request, so this replaces the former hardcoded constant. Uniqueness is guaranteed in practice
/// because the stampede refresh lock serialises refreshes per asset per replica, and each fires at a
/// distinct nanosecond (#12).
fn nonce_from_time(now: SystemTime) -> String {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn score_cache_key(config: &Config) -> String {
    format!("{SCORE_CACHE_KEY_PREFIX}{}", config.cdgc_asset_id)
}

fn refresh_lock_key(config: &Config) -> String {
    format!("{REFRESH_LOCK_KEY_PREFIX}{}", config.cdgc_asset_id)
}

/// TTL (ms) for the remote score namespace. See [`SCORE_STORE_MIN_TTL_MS`]: deliberately long so a
/// last-known-good score outlives `refreshIntervalSeconds` and remains available for fail-open
/// serving. Floored at 30 days, never below 2x the refresh interval, capped at `u32::MAX` ms.
fn score_store_ttl_ms(config: &Config) -> u32 {
    let refresh_secs = config
        .refresh_interval_seconds
        .unwrap_or(DEFAULT_REFRESH_INTERVAL_SECONDS)
        .max(0) as u64;
    let derived_ms = refresh_secs.saturating_mul(2).saturating_mul(1000);
    derived_ms.max(SCORE_STORE_MIN_TTL_MS).min(u32::MAX as u64) as u32
}

/// Combines the per-dimension `DQResult` scores CDGC returns for the asset into the single
/// number the policy compares against thresholds. `min` (the conservative default) gates on the
/// worst dimension; `average` blends them. Returns `None` if CDGC returned no dimensions at all.
fn aggregate_score(results: &[DqDimensionResult], mode: &str) -> Option<f64> {
    if results.is_empty() {
        return None;
    }
    match mode {
        "average" => Some(results.iter().map(|r| r.score).sum::<f64>() / results.len() as f64),
        _ => results.iter().map(|r| r.score).reduce(f64::min),
    }
}

/// Whether a JSON-RPC method name denotes an MCP notification. Per MCP/JSON-RPC 2.0 a notification
/// carries no `id` and MUST NEVER receive a response, so it can never be blocked. All MCP
/// notifications use the `notifications/` prefix.
fn is_notification_method(method: &str) -> bool {
    method.starts_with("notifications/")
}

/// Parses a request body as a single JSON-RPC 2.0 request and returns its `(method, id)`.
///
/// Returns `None` -- meaning "not a gate-able MCP call, pass through (fail-open)" -- for anything
/// that is not a single well-formed JSON-RPC 2.0 object carrying a string `method`: unparsable
/// JSON, a top-level array (a JSON-RPC *batch*, which is out of scope for gating here), a scalar, a
/// response object, a missing or non-`"2.0"` `jsonrpc` tag, or a missing `method`. The `id` is
/// returned verbatim (absent → `None`, which the caller treats as a notification); it is echoed
/// back in a block response so the client can correlate it.
fn parse_jsonrpc_call(body: &[u8]) -> Option<(String, Option<Value>)> {
    let json: Value = serde_json::from_slice(body).ok()?;
    let obj = json.as_object()?;
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return None;
    }
    let method = obj.get("method")?.as_str()?.to_string();
    let id = obj.get("id").cloned();
    Some((method, id))
}

/// The A2A protocol version of a request gated on the **JSON-RPC** binding. Governs only the *shape* of
/// that binding's `error.data`: v1.0 carries a single-element `google.rpc.ErrorInfo` array, v0.3.0
/// (Legacy) a free-form string. Read straight off the (version-disjoint) method name. The REST binding
/// does not use this -- A2A's HTTP+JSON binding is a v1.0 surface with a single (version-independent)
/// `google.rpc.Status` rejection shape.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum A2aVersion {
    V0_3,
    V1_0,
}

/// The A2A transport binding a *gated* A2A request arrived on -- selects the rejection shape, per the
/// `pdk-a2a` convention: the JSON-RPC binding answers in-band at HTTP 200; the HTTP+JSON (REST) binding
/// answers with a native HTTP status and a `google.rpc.Status` body (no JSON-RPC envelope).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum A2aBinding {
    /// JSON-RPC 2.0 over POST (Legacy v0.3.0 and V1). Version selects the `error.data` shape.
    JsonRpc(A2aVersion),
    /// HTTP+JSON (REST) message-send binding (`/message:send`, ...). A2A v1.0 surface; Shape 3.
    Rest,
}

/// The wire protocol a *gated* request arrived on. Selects the block-response shape: MCP → HTTP 200 +
/// JSON-RPC `-32008`; A2A JSON-RPC → HTTP 200 + JSON-RPC `-32010` (a `[google.rpc.ErrorInfo]` `data`
/// array on v1.0); A2A REST → native HTTP 403 + a `google.rpc.Status` body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum GateProtocol {
    Mcp,
    A2a(A2aBinding),
}

/// Classification of a recognized request: gate it on the given protocol's terms, or pass it through
/// ungated (MCP handshake/discovery, A2A housekeeping, anything unrecognized on a non-send path).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RequestClass {
    Gated(GateProtocol),
    Exempt,
}

/// Classifies a JSON-RPC `method` into gate-or-exempt (and, when gated, which protocol/version shapes
/// the block). The A2A send methods are matched first (their vocabulary is disjoint from MCP's and
/// self-describes the version); then A2A housekeeping and the MCP exempt set pass through; anything
/// else -- the MCP content-bearing methods (`tools/call`, `resources/read`, `prompts/get`) and any
/// unrecognized method -- is gated as MCP, preserving the MCP-only design's fail-closed default.
fn classify_jsonrpc_method(method: &str) -> RequestClass {
    match method {
        A2A_V03_SEND | A2A_V03_STREAM => {
            RequestClass::Gated(GateProtocol::A2a(A2aBinding::JsonRpc(A2aVersion::V0_3)))
        }
        A2A_V1_SEND | A2A_V1_STREAM => {
            RequestClass::Gated(GateProtocol::A2a(A2aBinding::JsonRpc(A2aVersion::V1_0)))
        }
        _ if A2A_HOUSEKEEPING_METHODS.contains(&method) => RequestClass::Exempt,
        _ if EXEMPT_METHODS.contains(&method) => RequestClass::Exempt,
        _ => RequestClass::Gated(GateProtocol::Mcp),
    }
}

/// Recognizes the A2A HTTP+JSON (REST) *message-send* binding from the request path, for the transport
/// where the body is a bare `SendMessageRequest`/`MessageSendParams` (no JSON-RPC envelope, so
/// [`parse_jsonrpc_call`] returns `None`). This is A2A's v1.0 REST surface. A2A/AIP action bindings put
/// the verb after a `:` on the final path segment (`message:send`), optionally behind an API-version or
/// tenant prefix (`/v1/message:send`, `/{tenant}/message:send`). Matching on the final segment alone
/// therefore recognizes the send across any routing prefix, while leaving every non-send REST path
/// (task lifecycle, agent-card discovery) unmatched → ungated.
fn a2a_rest_send_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    let last_segment = path.rsplit('/').next().unwrap_or(path);
    matches!(
        last_segment,
        "message:send" | "message:stream" | "message:sendStream"
    )
}

/// The human-readable block message, shared by the MCP and A2A block builders. The wording is
/// protocol-neutral. `discloseScoreDetails` (default false) controls whether internal governance
/// state -- the exact score, `blockThreshold`, and `cdgcAssetId` -- is revealed to the client. Off by
/// default so a client can't probe threshold boundaries or learn asset identifiers; the full detail
/// is always recorded server-side by the `warn!` in `request_filter` regardless (#7).
fn block_message(disclose: bool, score: Option<f64>, config: &Config) -> String {
    if disclose {
        match score {
            Some(score) => format!(
                "Blocked by DQ Gate: asset '{}' DQ score {score:.2} is below blockThreshold {:.2}",
                config.cdgc_asset_id, config.block_threshold
            ),
            None => format!(
                "Blocked by DQ Gate: no DQ score is available yet for asset '{}'",
                config.cdgc_asset_id
            ),
        }
    } else {
        "Blocked by DQ Gate: data quality for the requested source did not meet the required standard"
            .to_string()
    }
}

/// The diagnostic headers shared by every block response, on any protocol: `content-type:
/// application/json` (the body is always a JSON error object), the raw `x-dq-gate-score` only when
/// disclosure is opted in, and the always-safe coarse `x-dq-gate-status: blocked`.
fn block_headers(disclose: bool, score: Option<f64>) -> Vec<(String, String)> {
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    if disclose {
        if let Some(score) = score {
            headers.push((HEADER_DQ_SCORE.to_string(), format!("{score:.2}")));
        }
    }
    headers.push((HEADER_DQ_STATUS.to_string(), "blocked".to_string()));
    headers
}

/// Dispatches to the protocol-appropriate block builder. The score/threshold decision is made by the
/// caller ([`request_filter`]); this only shapes the rejection for the wire protocol/binding the
/// request arrived on -- MCP and the A2A JSON-RPC binding answer in-band at HTTP 200, the A2A REST
/// binding with a native HTTP status.
fn build_block_response(
    protocol: GateProtocol,
    rpc_id: Option<Value>,
    score: Option<f64>,
    config: &Config,
) -> Response {
    match protocol {
        GateProtocol::Mcp => block_response(rpc_id, score, config),
        GateProtocol::A2a(A2aBinding::JsonRpc(version)) => {
            a2a_jsonrpc_block_response(version, rpc_id, score, config)
        }
        GateProtocol::A2a(A2aBinding::Rest) => a2a_rest_block_response(score, config),
    }
}

/// Builds the **MCP** JSON-RPC error response returned to the agent when a request is blocked. Status
/// `200` is intentional: MCP treats JSON-RPC errors as protocol-level, not transport-level, so an MCP
/// client expects `200` + an `error` object carrying [`JSONRPC_BLOCK_ERROR_CODE`], not an HTTP 4xx.
fn block_response(rpc_id: Option<Value>, score: Option<f64>, config: &Config) -> Response {
    let disclose = config.disclose_score_details.unwrap_or(false);
    let message = block_message(disclose, score, config);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": rpc_id.unwrap_or(Value::Null),
        "error": { "code": JSONRPC_BLOCK_ERROR_CODE, "message": message },
    });

    Response::new(200)
        .with_headers(block_headers(disclose, score))
        .with_body(serde_json::to_vec(&body).unwrap_or_default())
}

/// Builds the `google.rpc.ErrorInfo` object carried on an A2A v1.0 block -- as the single element of
/// the JSON-RPC binding's `error.data` array and of the REST binding's `error.details` array. The
/// stable `reason`/`domain` are always present (they disclose no governance state); the `metadata` map
/// is populated only when `discloseScoreDetails` is on, exactly as it gates the MCP message and the
/// score header.
fn a2a_error_info(disclose: bool, score: Option<f64>, config: &Config) -> Value {
    let mut metadata = serde_json::Map::new();
    if disclose {
        if let Some(score) = score {
            metadata.insert("score".to_string(), Value::String(format!("{score:.2}")));
        }
        metadata.insert(
            "blockThreshold".to_string(),
            Value::String(format!("{:.2}", config.block_threshold)),
        );
        metadata.insert(
            "assetId".to_string(),
            Value::String(config.cdgc_asset_id.clone()),
        );
    }
    serde_json::json!({
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": A2A_ERROR_REASON,
        "domain": A2A_ERROR_DOMAIN,
        "metadata": Value::Object(metadata),
    })
}

/// Builds the A2A rejection for the **JSON-RPC** binding (Legacy v0.3.0 and V1). Per the A2A/JSON-RPC
/// transport convention the failure is carried *in-band* at **HTTP 200** -- the transport succeeded,
/// the error lives in the envelope -- exactly as for MCP; only the code ([`A2A_BLOCK_ERROR_CODE`],
/// `-32010`) and the `error.data` shape distinguish it. On **v1.0** `error.data` is a single-element
/// array carrying a `google.rpc.ErrorInfo` (pdk-a2a Shape 2); on **v0.3.0** (Legacy) it is a free-form
/// string (Shape 1), included only when disclosing. `discloseScoreDetails` gates what the `ErrorInfo`
/// metadata reveals.
fn a2a_jsonrpc_block_response(
    version: A2aVersion,
    rpc_id: Option<Value>,
    score: Option<f64>,
    config: &Config,
) -> Response {
    let disclose = config.disclose_score_details.unwrap_or(false);
    let message = block_message(disclose, score, config);

    let mut error = serde_json::Map::new();
    error.insert("code".to_string(), serde_json::json!(A2A_BLOCK_ERROR_CODE));
    error.insert("message".to_string(), Value::String(message));

    let data = match version {
        // v1.0: data is a single-element array carrying a typed google.rpc.ErrorInfo (pdk-a2a Shape 2).
        A2aVersion::V1_0 => Some(serde_json::json!([a2a_error_info(disclose, score, config)])),
        // v0.3.0 (Legacy): data is a free-form plain string, surfaced only when disclosing (Shape 1).
        A2aVersion::V0_3 if disclose => Some(Value::String(A2A_ERROR_REASON.to_string())),
        A2aVersion::V0_3 => None,
    };
    if let Some(data) = data {
        error.insert("data".to_string(), data);
    }

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": rpc_id.unwrap_or(Value::Null),
        "error": Value::Object(error),
    });

    // HTTP 200: JSON-RPC carries the failure in-band, not as an HTTP status (pdk-a2a convention).
    Response::new(200)
        .with_headers(block_headers(disclose, score))
        .with_body(serde_json::to_vec(&body).unwrap_or_default())
}

/// Builds the A2A rejection for the **HTTP+JSON (REST)** binding (A2A v1.0). This is pdk-a2a Shape 3: a
/// native HTTP status ([`A2A_REST_BLOCK_HTTP_STATUS`], `403`) with a `google.rpc.Status` body -- **no**
/// JSON-RPC envelope. `error.code` mirrors the HTTP status and `error.details` is a single-element
/// array carrying the same `google.rpc.ErrorInfo` as the v1.0 JSON-RPC block.
fn a2a_rest_block_response(score: Option<f64>, config: &Config) -> Response {
    let disclose = config.disclose_score_details.unwrap_or(false);
    let message = block_message(disclose, score, config);

    let body = serde_json::json!({
        "error": {
            "code": A2A_REST_BLOCK_HTTP_STATUS,
            "message": message,
            "details": [a2a_error_info(disclose, score, config)],
        }
    });

    Response::new(A2A_REST_BLOCK_HTTP_STATUS)
        .with_headers(block_headers(disclose, score))
        .with_body(serde_json::to_vec(&body).unwrap_or_default())
}

/// Reads the cached DQ score from PDK-native [`DataStorage`]. A storage error degrades to a cache
/// miss (`None`) with a warning, so a transient storage hiccup falls back to a live CDGC fetch
/// rather than failing the request.
async fn read_cached_score<S: DataStorage>(store: &S, key: &str) -> Option<CachedScore> {
    match store.get::<CachedScore>(key).await {
        Ok(Some((cached, _version))) => Some(cached),
        Ok(None) => None,
        Err(err) => {
            logger::warn!("Failed to read cached DQ score from data storage: {err}");
            None
        }
    }
}

/// Persists a refreshed score using a gossip-safe write: `StoreMode::Absent` on a cache miss, or a
/// `StoreMode::Cas` overwrite on an existing entry. Never DELETE-then-insert -- on the remote
/// (gossip) backend a DELETE tombstone can propagate *after* the new write and destroy it. A CAS
/// conflict just means another refresher wrote first, so we re-read and retry a bounded number of
/// times; any hard error is logged and swallowed (the in-flight request already has its score).
async fn write_cached_score<S: DataStorage>(store: &S, key: &str, cached: &CachedScore) {
    for _ in 0..CAS_MAX_RETRIES {
        match store.get::<CachedScore>(key).await {
            Ok(Some((_, version))) => match store.store(key, &StoreMode::Cas(version), cached).await {
                Ok(()) => return,
                // Retriable: a concurrent writer bumped the version. Re-read and try again.
                Err(DataStorageError::CasMismatch) => continue,
                Err(err) => {
                    logger::warn!("Failed to persist refreshed DQ score: {err}");
                    return;
                }
            },
            Ok(None) => match store.store(key, &StoreMode::Absent, cached).await {
                Ok(()) => return,
                // Retriable: another writer created the entry between our read and write.
                Err(DataStorageError::CasMismatch) => continue,
                Err(err) => {
                    logger::warn!("Failed to persist refreshed DQ score: {err}");
                    return;
                }
            },
            Err(err) => {
                logger::warn!("Failed to read DQ score before persisting refresh: {err}");
                return;
            }
        }
    }
    logger::warn!("Exhausted CAS retries persisting refreshed DQ score for key '{key}'");
}

/// Best-effort single-initiator lock so that when the cached score goes stale under concurrent
/// traffic, only one request pays for the (expensive) CDGC Login+JWT+Detail sequence instead of
/// every in-flight request hammering CDGC at once -- which is exactly what produces a CDGC `429`
/// under load. Unlike the previous Object Store V2 implementation (which had no CAS primitive and
/// so was a racy GET-then-PUT), this uses `StoreMode::Absent` for an atomic put-if-absent.
///
/// Returns:
/// - `Ok(true)`  -- this request acquired the lock and must perform the refresh.
/// - `Ok(false)` -- another request holds a still-fresh lock; serve the existing cached value.
/// - `Err(_)`    -- a hard storage error; the caller decides (we favour freshness and refresh).
///
/// On `CasMismatch` (the key already exists) the held lock is classified by age: if older than
/// [`REFRESH_LOCK_TTL_SECONDS`] the holder is presumed dead and the lock is taken over with a
/// CAS-overwrite -- never a DELETE, to avoid a gossip tombstone race.
async fn try_acquire_refresh_lock<S: DataStorage>(
    lock_store: &S,
    key: &str,
    now: i64,
) -> Result<bool, DataStorageError> {
    let entry = RefreshLock { acquired_at: now };
    match lock_store.store(key, &StoreMode::Absent, &entry).await {
        Ok(()) => Ok(true),
        Err(DataStorageError::CasMismatch) => match lock_store.get::<RefreshLock>(key).await? {
            Some((existing, version)) => {
                if now - existing.acquired_at < REFRESH_LOCK_TTL_SECONDS {
                    Ok(false)
                } else {
                    // Stale lock: take it over via CAS-overwrite (never DELETE).
                    match lock_store.store(key, &StoreMode::Cas(version), &entry).await {
                        Ok(()) => Ok(true),
                        Err(DataStorageError::CasMismatch) => Ok(false),
                        Err(err) => Err(err),
                    }
                }
            }
            None => {
                // The lock vanished between our failed put-if-absent and this read; retry the
                // atomic claim once.
                match lock_store.store(key, &StoreMode::Absent, &entry).await {
                    Ok(()) => Ok(true),
                    Err(DataStorageError::CasMismatch) => Ok(false),
                    Err(err) => Err(err),
                }
            }
        },
        Err(err) => Err(err),
    }
}

/// Runs the live CDGC sequence (Login -> JWT -> Detail API `dataQuality` segment) and aggregates
/// the result into a single score. A fresh Login+JWT is performed every call, on purpose -- see
/// the design doc's "Token strategy" decision -- since this only runs on a stale-cache request.
///
/// The three calls run inline on the request hot path, so the whole chain is bounded by
/// [`CDGC_REFRESH_BUDGET_MS`]: `start` is stamped from the injected [`Clock`] and each call's
/// timeout is clamped (via [`next_call_timeout`]) to the budget still remaining. If the budget is
/// exhausted before a call, the refresh aborts with an error and the caller applies the
/// unknown-score fallback -- the request never blocks unbounded (#9).
async fn fetch_cdgc_score(client: &HttpClient, config: &Config, clock: &Clock) -> Result<f64> {
    let start = clock.now();
    let per_call_ms = config.timeout.unwrap_or(DEFAULT_TIMEOUT_MS);

    let login_body = serde_json::to_vec(&serde_json::json!({
        "username": config.cdgc_org_username,
        "password": config.cdgc_org_password,
    }))?;

    let login_timeout = next_call_timeout(per_call_ms, elapsed_ms(start, clock.now())).ok_or_else(|| {
        anyhow!("CDGC refresh exceeded {CDGC_REFRESH_BUDGET_MS}ms latency budget before Login")
    })?;
    let login_response = client
        .request(&config.cdgc_login_url)
        .path("/identity-service/api/v1/Login")
        .headers(vec![("Content-Type", "application/json")])
        .body(&login_body)
        .timeout(login_timeout)
        .post()
        .await
        .map_err(|err| anyhow!("CDGC login failed: {err}"))?;

    if login_response.status_code() >= 300 {
        // Status code only -- NEVER the response body. The Login endpoint echoes a `sessionId`
        // (and other credential detail) in its payload, and errors here propagate verbatim into
        // `logger::warn!`, which is lower-trust than the secret store (see #6 / pdk-policy-logging).
        return Err(anyhow!("CDGC login returned status {}", login_response.status_code()));
    }
    let login: CdgcLoginResponse = serde_json::from_slice(login_response.body())
        .map_err(|err| anyhow!("Failed to parse CDGC login response: {err}"))?;

    // Unique per-request nonce (from the injected Clock), percent-encoded into the query. Encoding a
    // purely numeric nonce is a no-op today but guards the query if the derivation ever changes.
    let nonce = percent_encode(&nonce_from_time(clock.now()));
    let jwt_path = format!("/identity-service/api/v1/jwt/Token?client_id=idmc_api&nonce={nonce}");
    let cookie = format!("USER_SESSION={}", login.session_id);
    let jwt_timeout = next_call_timeout(per_call_ms, elapsed_ms(start, clock.now())).ok_or_else(|| {
        anyhow!("CDGC refresh exceeded {CDGC_REFRESH_BUDGET_MS}ms latency budget before JWT fetch")
    })?;
    let jwt_response = client
        .request(&config.cdgc_login_url)
        .path(&jwt_path)
        .headers(vec![
            ("cookie", cookie.as_str()),
            ("IDS-SESSION-ID", login.session_id.as_str()),
        ])
        .timeout(jwt_timeout)
        .get()
        .await
        .map_err(|err| anyhow!("CDGC JWT fetch failed: {err}"))?;

    if jwt_response.status_code() >= 300 {
        // Status code only -- the Token endpoint returns JWT material in its body; keep it out of logs.
        return Err(anyhow!("CDGC JWT fetch returned status {}", jwt_response.status_code()));
    }
    let jwt: CdgcJwtResponse = serde_json::from_slice(jwt_response.body())
        .map_err(|err| anyhow!("Failed to parse CDGC JWT response: {err}"))?;

    // Percent-encode the asset id: it is interpolated into the path *segment* before the query, so
    // an id containing `?`, `#`, `/`, or whitespace would otherwise alter the request target.
    let detail_path = format!(
        "/data360/search/v1/assets/{}?scheme=internal&segments=dataQuality",
        percent_encode(&config.cdgc_asset_id)
    );
    let authorization = format!("Bearer {}", jwt.jwt_token);
    let detail_timeout = next_call_timeout(per_call_ms, elapsed_ms(start, clock.now())).ok_or_else(|| {
        anyhow!("CDGC refresh exceeded {CDGC_REFRESH_BUDGET_MS}ms latency budget before Detail fetch")
    })?;
    let detail_response = client
        .request(&config.cdgc_base_api_url)
        .path(&detail_path)
        .headers(vec![
            ("Authorization", authorization.as_str()),
            ("X-INFA-ORG-ID", login.org_id.as_str()),
            ("Content-Type", "application/json"),
        ])
        .timeout(detail_timeout)
        .get()
        .await
        .map_err(|err| anyhow!("CDGC DQ score fetch failed: {err}"))?;

    if detail_response.status_code() >= 300 {
        // Status code only -- the Detail response can carry org/asset metadata we don't want in
        // logs. Not a token endpoint, but the same secret-in-logs anti-pattern (#6).
        return Err(anyhow!("CDGC DQ score fetch returned status {}", detail_response.status_code()));
    }
    let detail: AssetDetailResponse = serde_json::from_slice(detail_response.body())
        .map_err(|err| anyhow!("Failed to parse CDGC asset detail response: {err}"))?;

    let mode = config.score_aggregation.as_deref().unwrap_or("min");
    aggregate_score(&detail.data_quality, mode)
        .ok_or_else(|| anyhow!("CDGC returned no dataQuality dimensions for asset '{}'", config.cdgc_asset_id))
}

/// The core lazy/TTL cache-aside logic: read the cached score from PDK-native [`DataStorage`], and
/// if it's missing or older than `refreshIntervalSeconds`, refresh it from CDGC right here, inline,
/// before returning a score to gate on. Returns `None` only when no score is available at all (no
/// cache, and the refresh -- if attempted -- also failed with `failOpenOnCdgcError=false`).
async fn resolve_score<S: DataStorage>(
    client: &HttpClient,
    config: &Config,
    score_store: &S,
    lock_store: &S,
    clock: &Clock,
) -> Option<f64> {
    let key = score_cache_key(config);
    let refresh_interval = config
        .refresh_interval_seconds
        .unwrap_or(DEFAULT_REFRESH_INTERVAL_SECONDS)
        .max(0);
    let fail_open = config.fail_open_on_cdgc_error.unwrap_or(true);

    let cached = read_cached_score(score_store, &key).await;

    // Read wall-clock time through the injected PDK `Clock`, never `SystemTime::now()`: proxy-wasm
    // policies must source time from the host so it is testable and consistent with the runtime's
    // clock (see the `pdk-timer` guidance). No `Timer` is built -- this policy has no periodic task,
    // and `Clock::now()` is the sanctioned way to read the current time without setting a host tick
    // period that would otherwise fire unconsumed wakeups.
    let now = unix_seconds(clock.now());
    let is_stale = match &cached {
        Some(cached) => now - cached.timestamp > refresh_interval,
        None => true,
    };

    if !is_stale {
        logger::info!(
            "Using cached DQ score for asset '{}': {:.2} (age {}s)",
            config.cdgc_asset_id,
            cached.as_ref().map(|c| c.score).unwrap_or_default(),
            cached.as_ref().map(|c| now - c.timestamp).unwrap_or_default()
        );
        return cached.map(|cached| cached.score);
    }

    // Stale or missing: coordinate so only one request refreshes from CDGC.
    let lock_key = refresh_lock_key(config);
    let lock_acquired = match try_acquire_refresh_lock(lock_store, &lock_key, now).await {
        Ok(acquired) => acquired,
        Err(err) => {
            logger::warn!("Failed to acquire DQ score refresh lock: {err}; proceeding with refresh");
            true
        }
    };
    if !lock_acquired {
        logger::info!(
            "DQ score refresh for asset '{}' already in progress elsewhere; serving existing cached value",
            config.cdgc_asset_id
        );
        return cached.map(|cached| cached.score);
    }

    match fetch_cdgc_score(client, config, clock).await {
        Ok(score) => {
            logger::info!(
                "Fetched fresh DQ score from CDGC for asset '{}': {score:.2}",
                config.cdgc_asset_id
            );
            let fresh = CachedScore { score, timestamp: now };
            write_cached_score(score_store, &key, &fresh).await;
            Some(score)
        }
        Err(err) => {
            logger::warn!("CDGC DQ score refresh failed for asset '{}': {err}", config.cdgc_asset_id);
            if fail_open {
                cached.map(|cached| cached.score)
            } else {
                None
            }
        }
    }
}

thread_local! {
    /// One-shot guard so the "gate is passing traffic UNGATED" warning fires only the first time a
    /// bypass happens on this worker -- enough to make the fail-open window observable in the logs
    /// without flooding them on every subsequent request (#10). Per-worker (thread-local) state is
    /// the sanctioned way to hold process-wide flags in the single-threaded proxy-wasm model.
    static UNGATED_BYPASS_LOGGED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

async fn request_filter<S: DataStorage>(
    request_state: RequestState,
    config: &Config,
    client: &HttpClient,
    score_store: &S,
    lock_store: &S,
    clock: &Clock,
    violations: &PolicyViolations,
) -> Flow<DqGateData> {
    // Atomically buffer request headers AND body before deciding. The split
    // into_headers_state() -> into_body_state() path releases headers to Envoy's router, which
    // begins proxying the request upstream in parallel while we compute the score -- so a blocked
    // tools/call could still reach and execute on the upstream MCP server, and the upstream
    // response could race our synthetic Flow::Break. The combined state holds the request in the
    // filter until we decide, so Flow::Break always wins (see #2). The known response-leg hang
    // with this combined state does not apply here -- this is the request leg.
    let state = request_state.into_headers_body_state().await;

    // Fail-open recognition (pdk-mcp / A2A contract): only gate genuine *invocation* traffic on the
    // two protocols this policy governs -- MCP and A2A (Agent2Agent). Anything that is not a POST of
    // application/json -- a GET opening a Streamable-HTTP SSE session, a health probe, a non-JSON
    // content type (including the A2A gRPC transport, which is application/grpc and thus documented
    // pass-through), unparsable JSON, or a batch array -- passes straight through ungated, so the
    // policy never breaks non-MCP/A2A traffic or connection establishment. This is the opposite of
    // failing closed on anything it does not understand.
    let request_method = state.handler().header(":method").unwrap_or_default();
    if !request_method.eq_ignore_ascii_case("POST") {
        logger::debug!("Non-POST request ('{request_method}'); passing through ungated");
        return Flow::Continue(DqGateData::Evaluated { score: None, status: "skipped" });
    }
    let content_type = state.handler().header("content-type").unwrap_or_default();
    if !content_type.to_ascii_lowercase().contains("application/json") {
        logger::debug!("Non-JSON content-type ('{content_type}'); passing through ungated");
        return Flow::Continue(DqGateData::Evaluated { score: None, status: "skipped" });
    }

    let body = if state.contains_body() {
        state.handler().body()
    } else {
        Vec::new()
    };

    // Classify the request into (gated protocol, JSON-RPC id) or pass it through. Two recognition
    // paths feed the same score gate:
    //   1. A JSON-RPC 2.0 envelope -- shared by MCP and the A2A JSON-RPC transport. The method name
    //      alone classifies both the protocol and (for A2A) the version: the MCP, A2A v0.3.0, and A2A
    //      v1.0 method vocabularies are mutually disjoint (see `classify_jsonrpc_method`).
    //   2. Otherwise, the A2A HTTP+JSON (REST) message-send binding, recognized from the request path
    //      (its body is a bare SendMessageRequest, not a JSON-RPC envelope). This is A2A's v1.0 REST
    //      surface, answered with a `google.rpc.Status` body (pdk-a2a Shape 3).
    // Anything matching neither passes through ungated (fail-open).
    let (protocol, rpc_id) = match parse_jsonrpc_call(&body) {
        Some((method, rpc_id)) => {
            // A notification (a `notifications/*` method, or any call without an `id`) may NEVER
            // receive a response per JSON-RPC 2.0, so it can't be answered with a block -- pass it on.
            if is_notification_method(&method) || rpc_id.is_none() {
                logger::debug!(
                    "Notification-style request '{method}' (no response permitted); passing through ungated"
                );
                return Flow::Continue(DqGateData::Evaluated { score: None, status: "skipped" });
            }
            match classify_jsonrpc_method(&method) {
                // MCP handshake/discovery and A2A task/config/discovery housekeeping touch no asset
                // data and are exempt; only the content-bearing invocations (MCP tools/call,
                // resources/read, prompts/get; A2A message-send/stream) are gated on the DQ score.
                RequestClass::Exempt => {
                    logger::info!("Method '{method}' is exempt from DQ gating, passing through");
                    return Flow::Continue(DqGateData::Evaluated { score: None, status: "skipped" });
                }
                RequestClass::Gated(protocol) => (protocol, rpc_id),
            }
        }
        None => {
            // Not a JSON-RPC envelope. Recognize the A2A REST message-send binding by path; anything
            // else (a batch array, a non-send REST path, unparsable JSON) passes through ungated.
            let path = state.handler().header(":path").unwrap_or_default();
            if a2a_rest_send_path(&path) {
                logger::info!("Gating A2A HTTP+JSON (REST) message-send binding (path '{path}')");
                // The REST binding answers with a google.rpc.Status body (Shape 3), not a JSON-RPC
                // envelope, so it carries no rpc id.
                (GateProtocol::A2a(A2aBinding::Rest), None)
            } else {
                logger::debug!(
                    "Request is neither a JSON-RPC 2.0 call nor an A2A REST message-send binding; passing through ungated"
                );
                return Flow::Continue(DqGateData::Evaluated { score: None, status: "skipped" });
            }
        }
    };

    let score = resolve_score(client, config, score_store, lock_store, clock).await;

    // Only surface the raw numeric score to the client (via the x-dq-gate-score header on an
    // allowed response) when explicitly opted in; the coarse status header is always emitted. See
    // `block_response` for the corresponding block-path behavior (#7).
    let disclose = config.disclose_score_details.unwrap_or(false);

    match score {
        None => {
            // Default fail-CLOSED (blockOnUnknownScore defaults true, #10): with no score at all
            // -- cold worker start, or a failOpenOnCdgcError=false failure with an empty cache --
            // the gate blocks rather than silently disabling itself during the windows an operator
            // is least likely to notice. Operators may opt into a soft launch by setting it false.
            if config.block_on_unknown_score.unwrap_or(true) {
                logger::warn!(
                    "Blocking request: no DQ score available yet for asset '{}' (fail-closed; blockOnUnknownScore=true)",
                    config.cdgc_asset_id
                );
                // Surface the denial to Anypoint Monitoring. The PolicyViolation object itself only
                // carries the policy name/type (the API exposes no custom fields), so the asset id
                // and threshold live in the correlated warn log above.
                violations.generate_policy_violation();
                Flow::Break(build_block_response(protocol, rpc_id, None, config))
            } else {
                // Soft-launch bypass: passing traffic UNGATED. Warn ONCE per worker so the window
                // during which the control is disabled is observable without flooding the logs.
                let first_bypass = UNGATED_BYPASS_LOGGED.with(|logged| !logged.replace(true));
                if first_bypass {
                    logger::warn!(
                        "DQ Gate BYPASS: passing traffic UNGATED for asset '{}' -- no DQ score is available and blockOnUnknownScore=false, so the data-quality control is currently disabled for this asset. (Warned once per worker.)",
                        config.cdgc_asset_id
                    );
                }
                logger::debug!(
                    "No DQ score available yet for asset '{}'; passing through per blockOnUnknownScore=false",
                    config.cdgc_asset_id
                );
                Flow::Continue(DqGateData::Evaluated { score: None, status: "unknown" })
            }
        }
        Some(score) if score < config.block_threshold => {
            logger::warn!(
                "Blocking request: asset '{}' DQ score {score:.2} below blockThreshold {:.2}",
                config.cdgc_asset_id,
                config.block_threshold
            );
            // Denial telemetry (see note above): score/threshold/asset id are in the warn log.
            violations.generate_policy_violation();
            Flow::Break(build_block_response(protocol, rpc_id, Some(score), config))
        }
        Some(score) if score < config.warn_threshold => {
            logger::warn!(
                "Warning: asset '{}' DQ score {score:.2} below warnThreshold {:.2}",
                config.cdgc_asset_id,
                config.warn_threshold
            );
            Flow::Continue(DqGateData::Evaluated { score: disclose.then_some(score), status: "warn" })
        }
        Some(score) => Flow::Continue(DqGateData::Evaluated { score: disclose.then_some(score), status: "ok" }),
    }
}

async fn response_filter(response_state: ResponseState, request_data: RequestData<DqGateData>) {
    // Complete at header state and do NOT transition to body state. This filter only annotates two
    // diagnostic response headers; it never needs the body. Forcing into_body_state() would buffer
    // the entire response before releasing it downstream, which stalls MCP Streamable-HTTP
    // (text/event-stream) responses -- a long-lived or never-terminating event stream would never
    // flush to the client (bounded by the Envoy per-connection buffer). Header-only completion is
    // valid in PDK response filters and passes the body through untouched as a stream.
    let headers_state = response_state.into_headers_state().await;

    if let RequestData::Continue(DqGateData::Evaluated { score, status }) = request_data {
        if let Some(score) = score {
            headers_state.handler().set_header(HEADER_DQ_SCORE, &format!("{score:.2}"));
        }
        headers_state.handler().set_header(HEADER_DQ_STATUS, status);
    }
}

/// Wires the request/response filters against a concrete [`DataStorage`] backend. Kept generic over
/// `S` so all cache/lock logic is backend-agnostic; the only place that chooses local vs remote is
/// [`configure`].
async fn launch_policy<S: DataStorage>(
    launcher: Launcher,
    config: &Config,
    client: &HttpClient,
    score_store: &S,
    lock_store: &S,
    clock: &Clock,
    violations: &PolicyViolations,
) -> Result<()> {
    let filter = on_request(|rs| {
        request_filter(rs, config, client, score_store, lock_store, clock, violations)
    })
    .on_response(response_filter);
    launcher.launch(filter).await?;
    Ok(())
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    client: HttpClient,
    storage_builder: DataStorageBuilder,
    clock: Clock,
    violations: PolicyViolations,
) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Failed to parse configuration '{}'. Cause: {}",
            String::from_utf8_lossy(&bytes),
            err
        )
    })?;

    // `distributed=true` shares the score cache and refresh lock across gateway replicas via the
    // gossip-replicated remote backend (requires shared storage configured on the gateway);
    // `false` (default) keeps them per-replica in memory. Downstream logic is identical either
    // way -- see `launch_policy`.
    if config.distributed.unwrap_or(false) {
        let score_store = storage_builder.remote(SCORE_CACHE_NAMESPACE, score_store_ttl_ms(&config));
        let lock_store = storage_builder.remote(REFRESH_LOCK_NAMESPACE, REFRESH_LOCK_TTL_MS);
        launch_policy(launcher, &config, &client, &score_store, &lock_store, &clock, &violations).await
    } else {
        let score_store = storage_builder.local(SCORE_CACHE_NAMESPACE);
        let lock_store = storage_builder.local(REFRESH_LOCK_NAMESPACE);
        launch_policy(launcher, &config, &client, &score_store, &lock_store, &clock, &violations).await
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    use pdk::data_storage::{DataStorage, DataStorageError, StoreMode};
    use pdk_unit::{TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder};
    use serde::{de::DeserializeOwned, Serialize};
    use serde_json::json;

    use super::{CachedScore, REFRESH_LOCK_TTL_SECONDS};

    fn config() -> String {
        json!({
            "cdgcLoginUrl": "http://cdgclogin",
            "cdgcBaseApiUrl": "http://cdgcapi",
            "cdgcOrgUsername": "test-user",
            "cdgcOrgPassword": "test-pass",
            "cdgcAssetId": "asset-1",
            "warnThreshold": 90,
            "blockThreshold": 80,
            "refreshIntervalSeconds": 86400,
        })
        .to_string()
    }

    fn config_with(overrides: serde_json::Value) -> String {
        let mut base: serde_json::Value = serde_json::from_str(&config()).unwrap();
        for (key, value) in overrides.as_object().unwrap() {
            base[key] = value.clone();
        }
        base.to_string()
    }

    fn mcp_request(id: i64) -> UnitHttpRequest {
        UnitHttpRequest::post()
            .with_path("/mcp")
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call" }).to_string())
    }

    fn mcp_request_with_method(id: i64, method: &str) -> UnitHttpRequest {
        UnitHttpRequest::post()
            .with_path("/mcp")
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": id, "method": method }).to_string())
    }

    /// An A2A JSON-RPC request for `method` (e.g. "message/send" for v0.3, "SendMessage" for v1.0),
    /// mirroring `mcp_request_with_method`. The A2A JSON-RPC transport shares MCP's envelope; only the
    /// method vocabulary differs.
    fn a2a_request(id: i64, method: &str) -> UnitHttpRequest {
        UnitHttpRequest::post()
            .with_path("/a2a")
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": id, "method": method }).to_string())
    }

    /// An A2A HTTP+JSON (REST) message-send request: a bare `SendMessageRequest` body (NOT a JSON-RPC
    /// envelope) at the versioned action `path`. `version_header`, when `Some`, sets `A2A-Version`
    /// (only v1.0 clients send it), which is how the REST branch resolves the protocol version.
    fn a2a_rest_send(path: &str, version_header: Option<&str>) -> UnitHttpRequest {
        let mut req = UnitHttpRequest::post()
            .with_path(path)
            .with_header("content-type", "application/json")
            .with_body(json!({ "message": { "role": "user", "parts": [] } }).to_string());
        if let Some(version) = version_header {
            req = req.with_header("a2a-version", version);
        }
        req
    }

    /// Stateful CDGC login mock: always succeeds, tracking call count so tests can assert
    /// whether a cached score avoided re-authenticating.
    fn cdgc_login_backend(calls: Rc<RefCell<u32>>) -> impl Fn(UnitHttpRequest) -> UnitHttpResponse {
        move |req: UnitHttpRequest| {
            let path = req.header(":path").unwrap_or_default();
            if path.starts_with("/identity-service/api/v1/Login") {
                *calls.borrow_mut() += 1;
                UnitHttpResponse::new(200)
                    .with_body(json!({ "sessionId": "session-1", "orgId": "org-1" }).to_string())
            } else if path.starts_with("/identity-service/api/v1/jwt/Token") {
                UnitHttpResponse::new(200).with_body(json!({ "jwt_token": "test-jwt" }).to_string())
            } else {
                UnitHttpResponse::new(404)
            }
        }
    }

    fn cdgc_score_backend(score: f64) -> impl Fn(UnitHttpRequest) -> UnitHttpResponse {
        move |_req: UnitHttpRequest| {
            UnitHttpResponse::new(200).with_body(
                json!({ "dataQuality": [{ "core.score": score }] }).to_string(),
            )
        }
    }

    /// CDGC Detail mock that serves `score` on the first call, then fails (HTTP 500) on every
    /// subsequent call. Lets a test populate the cache once and then force the *refresh* to fail
    /// (exercising the stale-cache fail-open / fail-closed branches of `resolve_score`).
    fn cdgc_score_once_then_error(score: f64, calls: Rc<RefCell<u32>>) -> impl Fn(UnitHttpRequest) -> UnitHttpResponse {
        move |_req: UnitHttpRequest| {
            let n = { let mut c = calls.borrow_mut(); *c += 1; *c };
            if n == 1 {
                UnitHttpResponse::new(200)
                    .with_body(json!({ "dataQuality": [{ "core.score": score }] }).to_string())
            } else {
                UnitHttpResponse::new(500)
            }
        }
    }

    #[test]
    fn healthy_score_passes_through_and_tags_the_response() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(95.0))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("ok"));
        // The raw score is NOT disclosed to the client by default (discloseScoreDetails=false).
        assert_eq!(response.header("x-dq-gate-score"), None);
        assert!(backend.next().is_some());
    }

    #[test]
    fn score_below_block_threshold_rejects_with_jsonrpc_error_and_never_calls_backend() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(50.0))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(42));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("blocked"));
        // The synthetic block body is JSON-RPC, so it must be served as application/json.
        assert_eq!(response.header("content-type"), Some("application/json"));
        // Default (discloseScoreDetails=false): no raw score header, generic message, and no
        // score/threshold/asset id leaked to the client.
        assert_eq!(response.header("x-dq-gate-score"), None);
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 42);
        assert_eq!(body["error"]["code"], -32008);
        let msg = body["error"]["message"].as_str().unwrap();
        assert!(msg.contains("did not meet the required standard"), "got: {}", msg);
        assert!(!msg.contains("blockThreshold"), "must not leak threshold: {}", msg);
        assert!(!msg.contains("asset-1"), "must not leak asset id: {}", msg);
        assert!(!msg.contains("50"), "must not leak score: {}", msg);
        // The MCP server backend must never be invoked for a blocked request.
        assert!(backend.next().is_none());
    }

    #[test]
    fn disclose_true_emits_score_header_on_allowed_response() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "discloseScoreDetails": true })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(95.0))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        assert_eq!(response.header("x-dq-gate-status"), Some("ok"));
        // Opt-in: the raw score IS surfaced to the client when discloseScoreDetails=true.
        assert_eq!(response.header("x-dq-gate-score"), Some("95.00"));
    }

    #[test]
    fn disclose_true_block_message_includes_score_and_threshold() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "discloseScoreDetails": true })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(50.0))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(3));

        assert_eq!(response.header("x-dq-gate-status"), Some("blocked"));
        assert_eq!(response.header("x-dq-gate-score"), Some("50.00"));
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        let msg = body["error"]["message"].as_str().unwrap();
        assert!(msg.contains("blockThreshold"), "got: {}", msg);
        assert!(msg.contains("asset-1"), "got: {}", msg);
        assert!(backend.next().is_none());
    }

    #[test]
    fn exempt_handshake_methods_pass_through_even_below_block_threshold() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        // No CDGC score upstream registered at all: if the exemption ever fell through to
        // resolve_score, fetch_cdgc_score would fail with no score available -- so this test
        // asserts on login_calls staying at zero, proving resolve_score was never even attempted.
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_entrypoint(super::configure);

        for method in ["initialize", "tools/list", "notifications/initialized", "ping"] {
            let response = tester.request(mcp_request_with_method(1, method));
            assert_eq!(response.status_code(), 200, "method {method} should pass through");
            assert_eq!(response.header("x-dq-gate-status"), Some("skipped"));
        }

        assert!(backend.next().is_some());
        assert_eq!(*login_calls.borrow(), 0);
    }

    #[test]
    fn score_below_warn_threshold_passes_through_with_a_warning() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(85.0))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(2));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("warn"));
        assert!(backend.next().is_some());
    }

    #[test]
    fn cached_score_within_ttl_skips_cdgc_entirely() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(95.0))
            .with_entrypoint(super::configure);

        let first = tester.request(mcp_request(1));
        assert_eq!(first.status_code(), 200);
        assert_eq!(*login_calls.borrow(), 1);

        // Second request, well within the 24h refreshIntervalSeconds: must reuse the score cached
        // in native DataStorage rather than re-authenticating to CDGC.
        let second = tester.request(mcp_request(2));
        assert_eq!(second.status_code(), 200);
        assert_eq!(second.header("x-dq-gate-status"), Some("ok"));
        assert_eq!(*login_calls.borrow(), 1);
    }

    #[test]
    fn no_score_and_block_on_unknown_true_rejects() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        // No CDGC score upstream registered, and CDGC login has no upstream either, so
        // fetch_cdgc_score fails: no score is ever available. blockOnUnknownScore=true must reject.
        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "blockOnUnknownScore": true })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(7));

        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"]["code"], -32008);
        assert!(backend.next().is_none());
    }

    #[test]
    fn no_score_defaults_to_fail_closed_and_emits_violation() {
        // #10: with blockOnUnknownScore UNSET, the code default (`unwrap_or(true)`) must fail
        // CLOSED -- distinct from `no_score_and_block_on_unknown_true_rejects`, which sets the flag
        // explicitly. This guards the posture even when the gcl default is not applied (pdk-unit
        // does not pre-fill definition defaults, so the in-code default is what governs here).
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        // No CDGC score upstream at all -> fetch fails -> no score available.
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(11));

        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"]["code"], -32008, "unset flag must fail closed");
        assert!(backend.next().is_none(), "blocked request must never reach the MCP backend");
        // The denial must surface to Anypoint Monitoring as a PolicyViolation.
        let violation = response.violation().expect("fail-closed block must emit a PolicyViolation");
        assert_eq!(violation.get_policy_name(), "test_policy_id");
    }

    #[test]
    fn soft_launch_passes_ungated_when_block_on_unknown_false() {
        // #10: the deliberate soft-launch posture. With no score available and
        // blockOnUnknownScore=false, traffic passes UNGATED (status "unknown") and reaches the
        // upstream MCP server rather than being blocked.
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "blockOnUnknownScore": false })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(12));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("unknown"));
        assert!(response.body().is_empty(), "a soft-launch pass-through must not carry an error body");
        assert!(backend.next().is_some(), "soft-launch traffic must reach the MCP backend");
        // A pass-through is not a denial: no PolicyViolation is reported.
        assert!(response.violation().is_none(), "an ungated pass-through must not emit a violation");
    }

    #[test]
    fn below_block_threshold_emits_policy_violation() {
        // #10: a score below blockThreshold is a denial and must surface a PolicyViolation
        // alongside the Flow::Break, so blocks are visible in platform monitoring.
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(50.0))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(13));

        assert_eq!(response.header("x-dq-gate-status"), Some("blocked"));
        let violation = response.violation().expect("below-threshold block must emit a PolicyViolation");
        assert_eq!(violation.get_policy_name(), "test_policy_id");
    }

    #[test]
    fn aggregate_score_takes_min_by_default_and_averages_when_asked() {
        // `min` is the conservative default: gate on the worst dimension.
        let dims = [
            super::DqDimensionResult { score: 90.0 },
            super::DqDimensionResult { score: 60.0 },
            super::DqDimensionResult { score: 75.0 },
        ];
        assert_eq!(super::aggregate_score(&dims, "min"), Some(60.0));
        // Any non-"average" mode string falls back to min.
        assert_eq!(super::aggregate_score(&dims, "unrecognized"), Some(60.0));
        // "average" blends the dimensions: (90 + 60 + 75) / 3 = 75.
        assert_eq!(super::aggregate_score(&dims, "average"), Some(75.0));
        // No dimensions at all -> no score (drives the unknown-score path upstream).
        assert_eq!(super::aggregate_score(&[], "min"), None);
        assert_eq!(super::aggregate_score(&[], "average"), None);
    }

    #[test]
    fn score_exactly_at_warn_threshold_is_ok() {
        // Boundary: warnThreshold=90. `score < warn_threshold` is false at exactly 90, so 90 is OK,
        // not a warning (the block/warn comparisons are strict `<`).
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(90.0))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("ok"));
        assert!(backend.next().is_some());
    }

    #[test]
    fn score_exactly_at_block_threshold_warns_not_blocks() {
        // Boundary: blockThreshold=80. `score < block_threshold` is false at exactly 80, so 80 is
        // allowed (with a warning, since 80 < warnThreshold 90) rather than blocked.
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(80.0))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("warn"));
        assert!(backend.next().is_some(), "a score at the block threshold must still reach the backend");
    }

    #[test]
    fn jwt_fetch_sends_session_cookie_ids_header_and_nonce_query() {
        // Assert the request-shape of the CDGC JWT exchange: the session cookie, the IDS-SESSION-ID
        // header, and the client_id + per-request nonce query the CDGC identity service expects.
        let jwt_path = Rc::new(RefCell::new(String::new()));
        let jwt_cookie = Rc::new(RefCell::new(String::new()));
        let jwt_ids = Rc::new(RefCell::new(String::new()));

        let (path_c, cookie_c, ids_c) = (Rc::clone(&jwt_path), Rc::clone(&jwt_cookie), Rc::clone(&jwt_ids));
        let capturing_login = move |req: UnitHttpRequest| {
            let path = req.header(":path").unwrap_or_default();
            if path.starts_with("/identity-service/api/v1/Login") {
                UnitHttpResponse::new(200)
                    .with_body(json!({ "sessionId": "session-1", "orgId": "org-1" }).to_string())
            } else if path.starts_with("/identity-service/api/v1/jwt/Token") {
                *path_c.borrow_mut() = path.to_string();
                *cookie_c.borrow_mut() = req.header("cookie").unwrap_or_default().to_string();
                *ids_c.borrow_mut() = req.header("IDS-SESSION-ID").unwrap_or_default().to_string();
                UnitHttpResponse::new(200).with_body(json!({ "jwt_token": "test-jwt" }).to_string())
            } else {
                UnitHttpResponse::new(404)
            }
        };

        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", capturing_login)
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(95.0))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));
        assert_eq!(response.status_code(), 200);

        // Session cookie + IDS header both carry the sessionId returned by Login.
        assert_eq!(*jwt_cookie.borrow(), "USER_SESSION=session-1");
        assert_eq!(*jwt_ids.borrow(), "session-1");
        // The JWT path pins the client_id and carries a nonce query parameter.
        let path = jwt_path.borrow();
        assert!(path.contains("client_id=idmc_api"), "jwt path missing client_id: {path}");
        assert!(path.contains("nonce="), "jwt path missing nonce: {path}");
    }

    #[test]
    fn stale_cache_is_served_when_fail_open_true_and_refresh_fails() {
        // fail-open=true: once a good score is cached, a later CDGC outage on refresh must serve the
        // last-known-good (stale) score rather than failing the request.
        let login_calls = Rc::new(RefCell::new(0));
        let score_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "failOpenOnCdgcError": true })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_once_then_error(95.0, Rc::clone(&score_calls)))
            .with_entrypoint(super::configure);

        // First request populates the cache with a healthy score.
        let first = tester.request(mcp_request(1));
        assert_eq!(first.header("x-dq-gate-status"), Some("ok"));
        assert!(backend.next().is_some());

        // Advance past refreshIntervalSeconds (86400) so the cache is stale, and past the refresh
        // lock TTL (30s) so this request re-attempts the fetch -- which now fails.
        tester.sleep(Duration::from_secs(86_401));

        let second = tester.request(mcp_request(2));
        assert_eq!(second.status_code(), 200);
        assert_eq!(second.header("x-dq-gate-status"), Some("ok"), "stale score must be served on fail-open");
        assert!(second.body().is_empty(), "a served-stale pass-through must not carry an error body");
        assert!(backend.next().is_some(), "fail-open must forward the request to the MCP backend");
        assert!(*score_calls.borrow() >= 2, "the refresh (and its failure) must actually have been attempted");
    }

    #[test]
    fn stale_cache_is_treated_as_unknown_when_fail_open_false() {
        // fail-open=false: a CDGC outage on refresh must NOT serve the stale score. With the score
        // now unknown and blockOnUnknownScore defaulting closed, the request is blocked -- proving
        // the healthy stale score (95.0, which would pass) was discarded rather than reused.
        let login_calls = Rc::new(RefCell::new(0));
        let score_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "failOpenOnCdgcError": false })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_once_then_error(95.0, Rc::clone(&score_calls)))
            .with_entrypoint(super::configure);

        // First request caches the healthy score and passes.
        let first = tester.request(mcp_request(1));
        assert_eq!(first.header("x-dq-gate-status"), Some("ok"));
        assert!(backend.next().is_some());

        tester.sleep(Duration::from_secs(86_401));

        let second = tester.request(mcp_request(2));
        // Refresh failed + fail-open=false -> unknown -> fail closed (blockOnUnknownScore default true).
        let body: serde_json::Value = serde_json::from_slice(second.body()).unwrap();
        assert_eq!(body["error"]["code"], -32008, "fail-open=false must not serve the stale score");
        assert!(backend.next().is_none(), "a blocked request must never reach the MCP backend");
    }

    /// Shared builder for the fail-open recognition tests below: a live-but-low (50.0) CDGC score
    /// is registered so that *if* a request were ever gated, it would be blocked -- letting each
    /// test prove pass-through by asserting the backend was still reached, no error body was
    /// returned, and (via `login_calls == 0`) that `resolve_score` never even ran.
    fn recognition_tester<B: pdk_unit::Backend + 'static>(
        login_calls: Rc<RefCell<u32>>,
        backend: Rc<TraceBackend<B>>,
    ) -> pdk_unit::UnitTest {
        UnitTestBuilder::default()
            .with_config(config())
            .with_backend(backend)
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(login_calls))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(50.0))
            .with_entrypoint(super::configure)
    }

    #[test]
    fn non_post_request_passes_through_ungated() {
        // A GET (e.g. opening a Streamable-HTTP SSE session) must never be gated, even though a
        // low CDGC score is available -- if it reached resolve_score it would be blocked.
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = recognition_tester(Rc::clone(&login_calls), Rc::clone(&backend));

        let response = tester.request(UnitHttpRequest::get().with_path("/mcp"));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("skipped"));
        assert!(response.body().is_empty(), "a passed-through GET must not receive an error body");
        assert!(backend.next().is_some());
        assert_eq!(*login_calls.borrow(), 0, "resolve_score must not run for a non-POST request");
    }

    #[test]
    fn non_json_content_type_passes_through_ungated() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = recognition_tester(Rc::clone(&login_calls), Rc::clone(&backend));

        let request = UnitHttpRequest::post()
            .with_path("/mcp")
            .with_header("content-type", "text/plain")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call" }).to_string());
        let response = tester.request(request);

        assert_eq!(response.header("x-dq-gate-status"), Some("skipped"));
        assert!(backend.next().is_some());
        assert_eq!(*login_calls.borrow(), 0);
    }

    #[test]
    fn non_jsonrpc_body_passes_through_ungated() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = recognition_tester(Rc::clone(&login_calls), Rc::clone(&backend));

        // Valid JSON, but not a JSON-RPC 2.0 call (no jsonrpc/method) -> fail open.
        let request = UnitHttpRequest::post()
            .with_path("/mcp")
            .with_header("content-type", "application/json")
            .with_body(json!({ "hello": "world" }).to_string());
        let response = tester.request(request);

        assert_eq!(response.header("x-dq-gate-status"), Some("skipped"));
        assert!(backend.next().is_some());
        assert_eq!(*login_calls.borrow(), 0);
    }

    #[test]
    fn batch_array_body_fails_open() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = recognition_tester(Rc::clone(&login_calls), Rc::clone(&backend));

        // A JSON-RPC batch (top-level array) is out of scope for gating and must fail open.
        let request = UnitHttpRequest::post()
            .with_path("/mcp")
            .with_header("content-type", "application/json")
            .with_body(json!([{ "jsonrpc": "2.0", "id": 1, "method": "tools/call" }]).to_string());
        let response = tester.request(request);

        assert_eq!(response.header("x-dq-gate-status"), Some("skipped"));
        assert!(response.body().is_empty(), "a batch must not receive a single error object");
        assert!(backend.next().is_some());
        assert_eq!(*login_calls.borrow(), 0);
    }

    #[test]
    fn notifications_pass_through_ungated_and_never_block() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = recognition_tester(Rc::clone(&login_calls), Rc::clone(&backend));

        // A notification carries no id and must never receive a response, even below threshold.
        for method in [
            "notifications/cancelled",
            "notifications/progress",
            "notifications/roots/list_changed",
        ] {
            let request = UnitHttpRequest::post()
                .with_path("/mcp")
                .with_header("content-type", "application/json")
                .with_body(json!({ "jsonrpc": "2.0", "method": method }).to_string());
            let response = tester.request(request);
            assert_eq!(response.status_code(), 200, "{method} must pass through");
            assert_eq!(response.header("x-dq-gate-status"), Some("skipped"), "{method}");
            assert!(response.body().is_empty(), "{} must not receive an error body", method);
            assert!(backend.next().is_some(), "{} must reach the backend", method);
        }
        assert_eq!(*login_calls.borrow(), 0);
    }

    #[test]
    fn call_without_id_is_treated_as_notification_and_passes_through() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = recognition_tester(Rc::clone(&login_calls), Rc::clone(&backend));

        // tools/call with no id -> cannot receive a response -> must pass through, not block.
        let request = UnitHttpRequest::post()
            .with_path("/mcp")
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "method": "tools/call" }).to_string());
        let response = tester.request(request);

        assert_eq!(response.header("x-dq-gate-status"), Some("skipped"));
        assert!(response.body().is_empty());
        assert!(backend.next().is_some());
        assert_eq!(*login_calls.borrow(), 0);
    }

    #[test]
    fn logging_setlevel_is_exempt_from_gating() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = recognition_tester(Rc::clone(&login_calls), Rc::clone(&backend));

        // logging/setLevel touches no asset data; it must be exempt even below block threshold.
        let response = tester.request(mcp_request_with_method(9, "logging/setLevel"));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("skipped"));
        assert!(backend.next().is_some());
        assert_eq!(*login_calls.borrow(), 0);
    }

    // --- A2A (Agent2Agent) gating end-to-end tests ---

    #[test]
    fn a2a_v1_send_below_block_threshold_blocks_in_band_200_with_error_info() {
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::new(RefCell::new(0))))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(50.0))
            .with_entrypoint(super::configure);

        let response = tester.request(a2a_request(7, "SendMessage"));

        // An A2A JSON-RPC block, like MCP, carries the failure in-band at HTTP 200 (the JSON-RPC
        // transport convention). It differs from MCP only in the code (-32010, above A2A's assigned
        // -32001..=-32009) and, on v1.0, a single-element google.rpc.ErrorInfo `data` array carrying
        // the policy-owned reason/domain.
        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("blocked"));
        assert_eq!(response.header("content-type"), Some("application/json"));
        // disclose=false by default: the raw score is not surfaced to the client.
        assert_eq!(response.header("x-dq-gate-score"), None);
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 7);
        assert_eq!(body["error"]["code"], -32010);
        // v1.0 error.data is a single-element [ErrorInfo] array, not a bare object.
        let info = &body["error"]["data"][0];
        assert_eq!(info["@type"], "type.googleapis.com/google.rpc.ErrorInfo");
        assert_eq!(info["reason"], "DATA_QUALITY_BELOW_THRESHOLD");
        assert_eq!(info["domain"], "dq-gate.mulesoft.com");
        // disclose=false: metadata must not leak score/threshold/asset id.
        assert!(
            info["metadata"].as_object().unwrap().is_empty(),
            "metadata must be empty when not disclosing: {info}"
        );
        assert!(backend.next().is_none(), "a blocked A2A send must never reach the agent backend");
    }

    #[test]
    fn a2a_v03_send_below_block_threshold_blocks_in_band_200_free_form() {
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::new(RefCell::new(0))))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(50.0))
            .with_entrypoint(super::configure);

        let response = tester.request(a2a_request(11, "message/send"));

        // v0.3.0 (Legacy) JSON-RPC block: in-band at HTTP 200, code -32010, free-form error.data.
        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("blocked"));
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 11);
        assert_eq!(body["error"]["code"], -32010);
        // v0.3 error.data is free-form and OMITTED entirely when discloseScoreDetails=false.
        assert!(
            body["error"].get("data").is_none(),
            "v0.3 must omit data when not disclosing: {body}"
        );
        let msg = body["error"]["message"].as_str().unwrap();
        assert!(msg.contains("did not meet the required standard"), "got: {msg}");
        assert!(!msg.contains("asset-1"), "must not leak asset id: {msg}");
        assert!(backend.next().is_none());
    }

    #[test]
    fn a2a_send_healthy_score_passes_through_and_tags_response() {
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::new(RefCell::new(0))))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(95.0))
            .with_entrypoint(super::configure);

        let response = tester.request(a2a_request(1, "SendMessage"));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("ok"));
        assert!(backend.next().is_some(), "a healthy A2A send must reach the agent backend");
    }

    #[test]
    fn a2a_housekeeping_methods_pass_through_ungated() {
        // A2A task/config/discovery housekeeping (both vocabularies) touches no asset data, so it
        // must be exempt even below block threshold, and `resolve_score` must never run -- proven by
        // `login_calls == 0` (the recognition_tester registers a low 50.0 score that WOULD block if
        // the method were ever gated).
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = recognition_tester(Rc::clone(&login_calls), Rc::clone(&backend));

        for method in [
            "tasks/get",
            "tasks/pushNotificationConfig/get",
            "agent/getAuthenticatedExtendedCard",
            "GetTask",
            "GetExtendedAgentCard",
            "CancelTask",
        ] {
            let response = tester.request(a2a_request(5, method));
            assert_eq!(response.status_code(), 200, "{method} must pass through");
            assert_eq!(response.header("x-dq-gate-status"), Some("skipped"), "{method}");
            assert!(response.body().is_empty(), "{method} must not receive an error body");
            assert!(backend.next().is_some(), "{method} must reach the backend");
        }
        assert_eq!(*login_calls.borrow(), 0, "A2A housekeeping must not trigger a CDGC fetch");
    }

    #[test]
    fn a2a_rest_send_binding_below_block_threshold_uses_google_rpc_status_403() {
        // The A2A HTTP+JSON (REST) send binding carries a bare SendMessageRequest (no JSON-RPC
        // envelope), so it is recognized by path. It is A2A's v1.0 REST surface: the rejection is
        // pdk-a2a Shape 3 -- a NATIVE HTTP 403 with a google.rpc.Status body (error.code == 403,
        // details[0] a google.rpc.ErrorInfo), NOT a JSON-RPC envelope. The A2A-Version header does not
        // change this shape (both requests below produce the identical Shape 3).
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::new(RefCell::new(0))))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(50.0))
            .with_entrypoint(super::configure);

        // With an API-version prefix and no A2A-Version header.
        let v03 = tester.request(a2a_rest_send("/v1/message:send", None));
        assert_eq!(v03.status_code(), 403);
        assert_eq!(v03.header("x-dq-gate-status"), Some("blocked"));
        let v03_body: serde_json::Value = serde_json::from_slice(v03.body()).unwrap();
        // Shape 3: no JSON-RPC envelope (no `jsonrpc`, no `id`); error.code mirrors the HTTP status.
        assert!(v03_body.get("jsonrpc").is_none(), "REST block must not carry a JSON-RPC envelope");
        assert!(v03_body.get("id").is_none(), "REST block must not carry a JSON-RPC id");
        assert_eq!(v03_body["error"]["code"], 403);
        assert_eq!(
            v03_body["error"]["details"][0]["@type"],
            "type.googleapis.com/google.rpc.ErrorInfo"
        );
        assert_eq!(v03_body["error"]["details"][0]["domain"], "dq-gate.mulesoft.com");

        // Without the prefix and with A2A-Version: 1.0 -> identical Shape 3. The cached 50.0 score
        // (TTL 86400s) is reused, so this still blocks without a second CDGC fetch.
        let v1 = tester.request(a2a_rest_send("/message:send", Some("1.0")));
        assert_eq!(v1.status_code(), 403);
        let v1_body: serde_json::Value = serde_json::from_slice(v1.body()).unwrap();
        assert!(v1_body.get("jsonrpc").is_none());
        assert_eq!(v1_body["error"]["code"], 403);
        assert_eq!(
            v1_body["error"]["details"][0]["@type"],
            "type.googleapis.com/google.rpc.ErrorInfo"
        );
        assert_eq!(v1_body["error"]["details"][0]["domain"], "dq-gate.mulesoft.com");

        assert!(backend.next().is_none(), "blocked REST sends must never reach the agent backend");
    }

    // --- DataStorage-native helper tests (pdk-runtime-model testable-helper pattern) ---

    /// Minimal in-memory [`DataStorage`] test double with version tracking, so `StoreMode::Absent`
    /// and `StoreMode::Cas` behave like the real backends (see `pdk-distributed-cache-gossip`).
    struct MockDataStorage {
        data: Mutex<HashMap<String, (Vec<u8>, u64)>>,
    }

    impl MockDataStorage {
        fn new() -> Self {
            Self { data: Mutex::new(HashMap::new()) }
        }
    }

    impl DataStorage for MockDataStorage {
        async fn get_keys(&self) -> Result<Vec<String>, DataStorageError> {
            Ok(self.data.lock().unwrap().keys().cloned().collect())
        }

        async fn store<T: Serialize>(
            &self,
            key: &str,
            mode: &StoreMode,
            item: &T,
        ) -> Result<(), DataStorageError> {
            let bytes = serde_json::to_vec(item)
                .map_err(|e| DataStorageError::Unexpected(e.to_string()))?;
            let mut map = self.data.lock().unwrap();
            match mode {
                StoreMode::Always => {
                    let version = map.get(key).map(|(_, v)| v + 1).unwrap_or(1);
                    map.insert(key.to_string(), (bytes, version));
                    Ok(())
                }
                StoreMode::Absent => {
                    if map.contains_key(key) {
                        return Err(DataStorageError::CasMismatch);
                    }
                    map.insert(key.to_string(), (bytes, 1));
                    Ok(())
                }
                StoreMode::Cas(version) => {
                    let expected: u64 = version.parse().map_err(|_| DataStorageError::CasMismatch)?;
                    let current = map.get(key).map(|(_, v)| *v);
                    match current {
                        Some(current) if current == expected => {
                            map.insert(key.to_string(), (bytes, current + 1));
                            Ok(())
                        }
                        _ => Err(DataStorageError::CasMismatch),
                    }
                }
            }
        }

        async fn get<T: DeserializeOwned>(
            &self,
            key: &str,
        ) -> Result<Option<(T, String)>, DataStorageError> {
            let map = self.data.lock().unwrap();
            match map.get(key) {
                Some((bytes, version)) => {
                    let item = serde_json::from_slice(bytes)
                        .map_err(|e| DataStorageError::Unexpected(e.to_string()))?;
                    Ok(Some((item, version.to_string())))
                }
                None => Ok(None),
            }
        }

        async fn delete(&self, key: &str) -> Result<(), DataStorageError> {
            self.data.lock().unwrap().remove(key);
            Ok(())
        }

        async fn delete_all(&self) -> Result<(), DataStorageError> {
            self.data.lock().unwrap().clear();
            Ok(())
        }
    }

    /// Minimal, dependency-free executor for the always-ready futures the mock produces. It busy-
    /// loops on `Pending`, which is fine because `MockDataStorage`'s futures never actually pend.
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        use std::pin::pin;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);

        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut future = pin!(future);
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(value) => return value,
                Poll::Pending => continue,
            }
        }
    }

    #[test]
    fn refresh_lock_is_acquired_once_then_denied_while_fresh() {
        let store = MockDataStorage::new();
        let key = "dq-refresh-lock-asset-1";

        // First acquirer wins.
        assert_eq!(block_on(super::try_acquire_refresh_lock(&store, key, 1_000)).unwrap(), true);
        // A second request while the lock is still fresh is denied.
        assert_eq!(block_on(super::try_acquire_refresh_lock(&store, key, 1_005)).unwrap(), false);
    }

    #[test]
    fn refresh_lock_stale_holder_is_taken_over_via_cas() {
        let store = MockDataStorage::new();
        let key = "dq-refresh-lock-asset-1";

        assert_eq!(block_on(super::try_acquire_refresh_lock(&store, key, 1_000)).unwrap(), true);

        // Well past the TTL: the previous holder is presumed dead, so the lock is taken over.
        let later = 1_000 + REFRESH_LOCK_TTL_SECONDS + 1;
        assert_eq!(block_on(super::try_acquire_refresh_lock(&store, key, later)).unwrap(), true);
    }

    #[test]
    fn cached_score_round_trips_and_overwrites_via_cas() {
        let store = MockDataStorage::new();
        let key = "dq-score-asset-1";

        // Miss -> None.
        assert!(block_on(super::read_cached_score(&store, key)).is_none());

        // First write uses Absent; read back the value.
        block_on(super::write_cached_score(&store, key, &CachedScore { score: 95.0, timestamp: 10 }));
        let first = block_on(super::read_cached_score(&store, key)).expect("score present");
        assert_eq!(first.score, 95.0);
        assert_eq!(first.timestamp, 10);

        // Second write overwrites via CAS (no DELETE), and the new value is visible.
        block_on(super::write_cached_score(&store, key, &CachedScore { score: 72.5, timestamp: 20 }));
        let second = block_on(super::read_cached_score(&store, key)).expect("score present");
        assert_eq!(second.score, 72.5);
        assert_eq!(second.timestamp, 20);
    }

    #[test]
    fn refresh_lock_uses_separate_keys_per_asset() {
        let store = MockDataStorage::new();
        // Two different assets must not share a lock.
        assert_eq!(block_on(super::try_acquire_refresh_lock(&store, "dq-refresh-lock-a", 1)).unwrap(), true);
        assert_eq!(block_on(super::try_acquire_refresh_lock(&store, "dq-refresh-lock-b", 1)).unwrap(), true);
    }

    // --- #9 latency-budget helper tests ---

    #[test]
    fn elapsed_ms_is_monotonic_and_floors_at_zero() {
        let start = SystemTime::UNIX_EPOCH;
        let later = start + Duration::from_millis(1_500);
        assert_eq!(super::elapsed_ms(start, later), 1_500);
        // A clock that appears to go backwards must never yield a negative elapsed.
        assert_eq!(super::elapsed_ms(later, start), 0);
        assert_eq!(super::elapsed_ms(start, start), 0);
    }

    #[test]
    fn next_call_timeout_clamps_per_call_to_remaining_budget() {
        let budget = super::CDGC_REFRESH_BUDGET_MS; // 10_000
        let per_call = super::DEFAULT_TIMEOUT_MS; // 5_000

        // Fresh start: the per-call timeout (smaller than the budget) is used as-is.
        assert_eq!(super::next_call_timeout(per_call, 0), Some(Duration::from_millis(5_000)));

        // Late in the chain: only the remaining budget is granted, below the per-call ceiling.
        assert_eq!(super::next_call_timeout(per_call, budget - 500), Some(Duration::from_millis(500)));

        // A per-call value smaller than the remaining budget wins (min of the two).
        assert_eq!(super::next_call_timeout(2_000, 0), Some(Duration::from_millis(2_000)));
    }

    #[test]
    fn next_call_timeout_aborts_when_budget_exhausted() {
        let budget = super::CDGC_REFRESH_BUDGET_MS;
        // Exactly at the budget: nothing left, abort the refresh.
        assert_eq!(super::next_call_timeout(super::DEFAULT_TIMEOUT_MS, budget), None);
        // Past the budget: also abort (no unbounded blocking).
        assert_eq!(super::next_call_timeout(super::DEFAULT_TIMEOUT_MS, budget + 5_000), None);
    }

    // --- #12 CDGC request-construction hardening tests ---

    #[test]
    fn percent_encode_escapes_reserved_and_preserves_unreserved() {
        // Unreserved set passes through untouched.
        assert_eq!(super::percent_encode("abcXYZ0189-_.~"), "abcXYZ0189-_.~");
        // Characters that would alter a URL target or inject query params are escaped.
        assert_eq!(super::percent_encode("a/b?c#d&e=f g"), "a%2Fb%3Fc%23d%26e%3Df%20g");
        // Multi-byte UTF-8 is encoded byte-wise.
        assert_eq!(super::percent_encode("é"), "%C3%A9");
    }

    #[test]
    fn nonce_from_time_is_unique_per_distinct_reading_and_not_constant() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_nanos(1_700_000_000_000_000_123);
        let later = base + Duration::from_nanos(1);
        let a = super::nonce_from_time(base);
        let b = super::nonce_from_time(later);
        // Distinct clock readings must yield distinct nonces (not a fixed constant).
        assert_ne!(a, b);
        assert_ne!(a, "1234");
        // Nonce is a decimal nanosecond count.
        assert!(a.bytes().all(|c| c.is_ascii_digit()), "nonce must be numeric: {}", a);
    }

    // --- pure `&Config` helper coverage (score_store_ttl_ms, block_response) ---

    /// Deserializes a [`Config`] straight from the JSON config bytes (host-native), so pure
    /// `&Config` helpers can be exercised without spinning up the entrypoint. `deserialize_service`
    /// only needs `Metadata::new()`, which defaults when no policy context is set -- so this works
    /// in a plain `#[test]` exactly as the config parse inside `super::configure` does.
    fn parsed_config(overrides: serde_json::Value) -> super::Config {
        serde_json::from_slice(config_with(overrides).as_bytes())
            .expect("config JSON must deserialize into Config")
    }

    #[test]
    fn score_store_ttl_ms_derivation_pins_floor_cap_and_2x_interval() {
        // Default refresh interval (None -> 86400s): 2x*1000 = 172_800_000 ms is below the 30-day
        // floor (30*24*60*60*1000 = 2_592_000_000 ms), so the floor wins. Exercises the
        // `unwrap_or(DEFAULT_REFRESH_INTERVAL_SECONDS)` branch.
        let default_cfg = parsed_config(json!({ "refreshIntervalSeconds": null }));
        assert_eq!(super::score_store_ttl_ms(&default_cfg), 2_592_000_000);

        // Zero interval -> derived 0 -> floored at 30 days.
        let zero_cfg = parsed_config(json!({ "refreshIntervalSeconds": 0 }));
        assert_eq!(super::score_store_ttl_ms(&zero_cfg), 2_592_000_000);

        // Negative interval -> `.max(0)` -> 0 -> floored at 30 days (never underflows).
        let neg_cfg = parsed_config(json!({ "refreshIntervalSeconds": -5 }));
        assert_eq!(super::score_store_ttl_ms(&neg_cfg), 2_592_000_000);

        // 1_500_000s: 2x*1000 = 3_000_000_000 ms, above the 30-day floor and below the u32 cap, so
        // the "2x refresh interval" derivation wins verbatim.
        let mid_cfg = parsed_config(json!({ "refreshIntervalSeconds": 1_500_000 }));
        assert_eq!(super::score_store_ttl_ms(&mid_cfg), 3_000_000_000);

        // 3_000_000s: 2x*1000 = 6_000_000_000 ms exceeds u32::MAX (4_294_967_295), so the result is
        // capped at u32::MAX.
        let cap_cfg = parsed_config(json!({ "refreshIntervalSeconds": 3_000_000 }));
        assert_eq!(super::score_store_ttl_ms(&cap_cfg), u32::MAX);
    }

    #[test]
    fn block_response_discloses_no_score_available_message_when_disclose_true_and_score_none() {
        // discloseScoreDetails=true + score=None: the block message must name the unknown-score
        // case for the asset (lines 276-277), still served on HTTP 200 as application/json with the
        // dedicated -32008 code and the client's rpc id echoed back.
        let config = parsed_config(json!({ "discloseScoreDetails": true }));

        let response = super::block_response(Some(json!(5)), None, &config);

        assert_eq!(response.status_code(), 200);

        let headers = response.headers();
        assert!(
            headers.iter().any(|(k, v)| *k == "content-type" && *v == "application/json"),
            "block body is JSON-RPC and must be application/json: {headers:?}"
        );
        // score=None: even with disclose on, the raw score header push is guarded by `if let
        // Some(score)`, so no x-dq-gate-score is emitted.
        assert!(
            !headers.iter().any(|(k, _)| *k == "x-dq-gate-score"),
            "no score header when score is None: {headers:?}"
        );
        // The coarse status header is always safe to surface.
        assert!(
            headers.iter().any(|(k, v)| *k == "x-dq-gate-status" && *v == "blocked"),
            "status header must be present: {headers:?}"
        );

        let body: serde_json::Value =
            serde_json::from_slice(response.body().expect("block response must carry a body")).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 5);
        assert_eq!(body["error"]["code"], -32008);
        assert_eq!(
            body["error"]["message"].as_str().unwrap(),
            "Blocked by DQ Gate: no DQ score is available yet for asset 'asset-1'"
        );
    }

    // --- A2A pure-function coverage (classify / rest-path / version / block shape) ---

    #[test]
    fn classify_jsonrpc_method_partitions_mcp_a2a_and_housekeeping() {
        use super::{classify_jsonrpc_method, A2aBinding, A2aVersion, GateProtocol, RequestClass};
        // A2A JSON-RPC send methods -> gated; the version (which governs the error.data shape) is
        // inferred from the (version-disjoint) vocabulary, no header needed.
        assert_eq!(
            classify_jsonrpc_method("message/send"),
            RequestClass::Gated(GateProtocol::A2a(A2aBinding::JsonRpc(A2aVersion::V0_3)))
        );
        assert_eq!(
            classify_jsonrpc_method("message/stream"),
            RequestClass::Gated(GateProtocol::A2a(A2aBinding::JsonRpc(A2aVersion::V0_3)))
        );
        assert_eq!(
            classify_jsonrpc_method("SendMessage"),
            RequestClass::Gated(GateProtocol::A2a(A2aBinding::JsonRpc(A2aVersion::V1_0)))
        );
        assert_eq!(
            classify_jsonrpc_method("SendStreamingMessage"),
            RequestClass::Gated(GateProtocol::A2a(A2aBinding::JsonRpc(A2aVersion::V1_0)))
        );
        // A2A housekeeping (both vocabularies) -> exempt.
        for m in [
            "tasks/get",
            "tasks/pushNotificationConfig/set",
            "agent/getAuthenticatedExtendedCard",
            "GetTask",
            "GetExtendedAgentCard",
            "CancelTask",
        ] {
            assert_eq!(classify_jsonrpc_method(m), RequestClass::Exempt, "{m}");
        }
        // MCP handshake/discovery -> exempt.
        for m in ["initialize", "tools/list", "ping"] {
            assert_eq!(classify_jsonrpc_method(m), RequestClass::Exempt, "{m}");
        }
        // MCP content-bearing methods AND any unrecognized method -> gated as MCP (fail-closed
        // default preserved from the MCP-only design).
        for m in ["tools/call", "resources/read", "prompts/get", "some/unknown"] {
            assert_eq!(classify_jsonrpc_method(m), RequestClass::Gated(GateProtocol::Mcp), "{m}");
        }
    }

    #[test]
    fn a2a_rest_send_path_matches_only_send_bindings() {
        use super::a2a_rest_send_path;
        // Send bindings across versions, tenant/routing prefixes, and query strings.
        assert!(a2a_rest_send_path("/v1/message:send")); // v0.3
        assert!(a2a_rest_send_path("/message:send")); // v1.0
        assert!(a2a_rest_send_path("/acme/message:send")); // tenant-scoped v1.0
        assert!(a2a_rest_send_path("/v1/message:stream"));
        assert!(a2a_rest_send_path("/message:sendStream"));
        assert!(a2a_rest_send_path("/message:send?foo=bar")); // query stripped
        // Non-send REST paths (housekeeping/discovery) must NOT be gated.
        assert!(!a2a_rest_send_path("/v1/tasks/abc"));
        assert!(!a2a_rest_send_path("/tasks/abc:cancel"));
        assert!(!a2a_rest_send_path("/.well-known/agent-card.json"));
        assert!(!a2a_rest_send_path("/message"));
    }

    #[test]
    fn a2a_block_error_code_is_outside_a2a_and_mcp_ranges() {
        // The A2A block code must differ from MCP's, and lie outside A2A's own reserved
        // -32001..=-32009 band so it can never collide with an A2A-defined error (e.g. -32008
        // ExtensionSupportRequiredError).
        assert_ne!(super::A2A_BLOCK_ERROR_CODE, super::JSONRPC_BLOCK_ERROR_CODE);
        assert!(
            !(-32009..=-32001).contains(&super::A2A_BLOCK_ERROR_CODE),
            "A2A block code {} must be outside A2A's reserved -32001..=-32009 band",
            super::A2A_BLOCK_ERROR_CODE
        );
        // The REST/HTTP+JSON send binding maps the block onto a native HTTP status.
        assert_eq!(super::A2A_REST_BLOCK_HTTP_STATUS, 403);
    }

    #[test]
    fn a2a_jsonrpc_block_response_v1_carries_error_info_array_gated_by_disclosure() {
        use super::{a2a_jsonrpc_block_response, A2aVersion};
        // The JSON-RPC binding is transport-agnostic of the error: the block rides IN-BAND on
        // HTTP 200 inside the JSON-RPC envelope (returning a 4xx for a well-formed JSON-RPC call
        // is a spec mistake). On v1.0 `error.data` MUST be a single-element [ErrorInfo] array.
        // disclose=false: ErrorInfo present (reason/domain always, they leak nothing), metadata empty.
        let cfg = parsed_config(json!({}));
        let resp = a2a_jsonrpc_block_response(A2aVersion::V1_0, Some(json!(7)), Some(50.0), &cfg);
        assert_eq!(resp.status_code(), 200);
        let body: serde_json::Value =
            serde_json::from_slice(resp.body().expect("block response must carry a body")).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 7);
        assert_eq!(body["error"]["code"], -32010);
        let data = &body["error"]["data"];
        assert!(data.is_array(), "v1.0 error.data must be an array: {body}");
        assert_eq!(data.as_array().unwrap().len(), 1);
        let info = &data[0];
        assert_eq!(info["@type"], "type.googleapis.com/google.rpc.ErrorInfo");
        assert_eq!(info["reason"], "DATA_QUALITY_BELOW_THRESHOLD");
        assert_eq!(info["domain"], "dq-gate.mulesoft.com");
        assert!(info["metadata"].as_object().unwrap().is_empty());

        // disclose=true: metadata carries the exact score / threshold / asset id.
        let cfg = parsed_config(json!({ "discloseScoreDetails": true }));
        let resp = a2a_jsonrpc_block_response(A2aVersion::V1_0, Some(json!(7)), Some(50.0), &cfg);
        assert_eq!(resp.status_code(), 200);
        let body: serde_json::Value =
            serde_json::from_slice(resp.body().unwrap()).unwrap();
        let meta = &body["error"]["data"][0]["metadata"];
        assert_eq!(meta["score"], "50.00");
        assert_eq!(meta["blockThreshold"], "80.00");
        assert_eq!(meta["assetId"], "asset-1");
    }

    #[test]
    fn a2a_jsonrpc_block_response_v03_free_form_data_only_when_disclosing() {
        use super::{a2a_jsonrpc_block_response, A2aVersion};
        // v0.3 rides in-band on HTTP 200 too; `error.data` is free-form (v0.3 predates the
        // structured ErrorInfo binding). disclose=false: no data at all.
        let cfg = parsed_config(json!({}));
        let resp = a2a_jsonrpc_block_response(A2aVersion::V0_3, Some(json!(1)), Some(50.0), &cfg);
        assert_eq!(resp.status_code(), 200);
        let body: serde_json::Value =
            serde_json::from_slice(resp.body().expect("block response must carry a body")).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["error"]["code"], -32010);
        assert!(
            body["error"].get("data").is_none(),
            "v0.3 must omit data when not disclosing: {body}"
        );

        // v0.3 disclose=true: free-form data is just the machine-readable reason string.
        let cfg = parsed_config(json!({ "discloseScoreDetails": true }));
        let resp = a2a_jsonrpc_block_response(A2aVersion::V0_3, Some(json!(1)), Some(50.0), &cfg);
        assert_eq!(resp.status_code(), 200);
        let body: serde_json::Value =
            serde_json::from_slice(resp.body().unwrap()).unwrap();
        assert_eq!(body["error"]["data"], "DATA_QUALITY_BELOW_THRESHOLD");
    }

    // --- DataStorage error-degradation double (pdk-runtime-model testable-helper pattern) ---

    /// What the double's `get` should do on each call.
    #[derive(Clone, Copy)]
    enum FakeGet {
        /// Return a hard storage error (exercises the `Err(err)` degradation arms).
        Fail,
        /// Return `Ok(None)` -- a cache miss (drives `write_cached_score` into its `Absent` arm).
        Miss,
        /// Return `Ok(Some((.., version)))` (drives `write_cached_score` into its `Cas` arm).
        Hit(u64),
    }

    /// What the double's `store` should do on each call.
    #[derive(Clone, Copy)]
    enum FakeStore {
        /// A hard (non-retriable) storage error -- must be logged and swallowed, no retry.
        Fail,
        /// A CAS conflict -- retriable, so the caller loops until `CAS_MAX_RETRIES` is exhausted.
        Cas,
        /// Success.
        Ok,
    }

    /// A [`DataStorage`] test double that returns caller-chosen errors from `get` and/or `store`,
    /// so the error-degradation arms of `read_cached_score`/`write_cached_score` are reachable
    /// without a live backend. `store` calls are counted so tests can assert retry behaviour
    /// (a hard error must NOT retry; a CAS conflict must retry the full bound then give up).
    /// Uses a `Mutex` counter to mirror `MockDataStorage` and keep the future `Send`.
    struct FailingDataStorage {
        on_get: FakeGet,
        on_store: FakeStore,
        store_calls: Mutex<u32>,
    }

    impl FailingDataStorage {
        fn new(on_get: FakeGet, on_store: FakeStore) -> Self {
            Self { on_get, on_store, store_calls: Mutex::new(0) }
        }

        fn store_calls(&self) -> u32 {
            *self.store_calls.lock().unwrap()
        }
    }

    impl DataStorage for FailingDataStorage {
        async fn get_keys(&self) -> Result<Vec<String>, DataStorageError> {
            Ok(Vec::new())
        }

        async fn store<T: Serialize>(
            &self,
            _key: &str,
            _mode: &StoreMode,
            _item: &T,
        ) -> Result<(), DataStorageError> {
            *self.store_calls.lock().unwrap() += 1;
            match self.on_store {
                FakeStore::Fail => Err(DataStorageError::Unexpected("store boom".to_string())),
                FakeStore::Cas => Err(DataStorageError::CasMismatch),
                FakeStore::Ok => Ok(()),
            }
        }

        async fn get<T: DeserializeOwned>(
            &self,
            _key: &str,
        ) -> Result<Option<(T, String)>, DataStorageError> {
            match self.on_get {
                FakeGet::Fail => Err(DataStorageError::Unexpected("get boom".to_string())),
                FakeGet::Miss => Ok(None),
                FakeGet::Hit(version) => {
                    // Materialise a T from a real CachedScore so the helpers (which use
                    // T = CachedScore) deserialize cleanly.
                    let bytes = serde_json::to_vec(&CachedScore { score: 50.0, timestamp: 1 })
                        .map_err(|e| DataStorageError::Unexpected(e.to_string()))?;
                    let item: T = serde_json::from_slice(&bytes)
                        .map_err(|e| DataStorageError::Unexpected(e.to_string()))?;
                    Ok(Some((item, version.to_string())))
                }
            }
        }

        async fn delete(&self, _key: &str) -> Result<(), DataStorageError> {
            Ok(())
        }

        async fn delete_all(&self) -> Result<(), DataStorageError> {
            Ok(())
        }
    }

    #[test]
    fn read_cached_score_degrades_get_error_to_cache_miss() {
        // A hard storage error on read must degrade to a cache miss (None), never propagate or
        // panic -- so a transient storage hiccup falls back to a live CDGC fetch.
        let store = FailingDataStorage::new(FakeGet::Fail, FakeStore::Ok);
        assert!(block_on(super::read_cached_score(&store, "dq-score-asset-err")).is_none());
    }

    #[test]
    fn write_cached_score_swallows_hard_error_on_cas_overwrite() {
        // Existing entry -> CAS overwrite path. A hard (non-CasMismatch) store error must be
        // logged and swallowed WITHOUT retrying: exactly one store attempt, and no panic.
        let store = FailingDataStorage::new(FakeGet::Hit(7), FakeStore::Fail);
        block_on(super::write_cached_score(
            &store,
            "dq-score-asset-cas-hard",
            &CachedScore { score: 88.0, timestamp: 100 },
        ));
        assert_eq!(store.store_calls(), 1, "hard CAS error must not be retried");
    }

    #[test]
    fn write_cached_score_swallows_hard_error_on_absent_insert() {
        // Cache miss -> Absent put-if-absent path. A hard (non-CasMismatch) store error must be
        // logged and swallowed WITHOUT retrying: exactly one store attempt, and no panic.
        let store = FailingDataStorage::new(FakeGet::Miss, FakeStore::Fail);
        block_on(super::write_cached_score(
            &store,
            "dq-score-asset-absent-hard",
            &CachedScore { score: 88.0, timestamp: 100 },
        ));
        assert_eq!(store.store_calls(), 1, "hard Absent-insert error must not be retried");
    }

    #[test]
    fn write_cached_score_swallows_read_before_persist_error() {
        // A hard error on the read-before-write must abort the persist (log + return) BEFORE any
        // store attempt -- so store is never called and nothing panics.
        let store = FailingDataStorage::new(FakeGet::Fail, FakeStore::Ok);
        block_on(super::write_cached_score(
            &store,
            "dq-score-asset-read-err",
            &CachedScore { score: 88.0, timestamp: 100 },
        ));
        assert_eq!(store.store_calls(), 0, "a read error must abort before persisting");
    }

    #[test]
    fn write_cached_score_exhausts_cas_retries_on_existing_entry() {
        // Existing entry + a perpetual CAS conflict: the CAS overwrite is retriable, so the
        // loop must retry exactly CAS_MAX_RETRIES times before giving up (final warn), not spin
        // forever and not bail after one attempt.
        let store = FailingDataStorage::new(FakeGet::Hit(7), FakeStore::Cas);
        block_on(super::write_cached_score(
            &store,
            "dq-score-asset-cas-loop",
            &CachedScore { score: 88.0, timestamp: 100 },
        ));
        assert_eq!(store.store_calls(), super::CAS_MAX_RETRIES, "CAS conflict must retry the full bound");
    }

    #[test]
    fn write_cached_score_exhausts_cas_retries_on_absent_insert() {
        // Cache miss + a perpetual Absent-insert conflict (another writer keeps winning the race):
        // retriable, so the loop must retry exactly CAS_MAX_RETRIES times before giving up.
        let store = FailingDataStorage::new(FakeGet::Miss, FakeStore::Cas);
        block_on(super::write_cached_score(
            &store,
            "dq-score-asset-absent-loop",
            &CachedScore { score: 88.0, timestamp: 100 },
        ));
        assert_eq!(store.store_calls(), super::CAS_MAX_RETRIES, "Absent conflict must retry the full bound");
    }

    // --- Programmable DataStorage double for the racy refresh-lock arms ---

    /// Programmable [`DataStorage`] double whose `store` / `get` outcomes are scripted per call.
    /// `MockDataStorage` executes purely sequentially (its futures never actually pend or race), so
    /// the CAS-race and hard-error arms of `try_acquire_refresh_lock` -- a lost CAS takeover, a
    /// storage error mid-sequence, a lock that vanishes between the failed put-if-absent and the
    /// read -- are unreachable with it. This double lets each arm be driven deterministically by
    /// popping a pre-loaded outcome for every `store`/`get` call in the order the function makes
    /// them.
    struct ScriptedStore {
        store_results: RefCell<std::collections::VecDeque<Result<(), DataStorageError>>>,
        get_results: RefCell<std::collections::VecDeque<Result<Option<Vec<u8>>, DataStorageError>>>,
    }

    impl ScriptedStore {
        /// `store_results` is consumed one entry per `store()` call; `get_results` one per `get()`
        /// call. `Ok(Some(bytes))` for a `get` are the serialized bytes of the stored value.
        fn new(
            store_results: Vec<Result<(), DataStorageError>>,
            get_results: Vec<Result<Option<Vec<u8>>, DataStorageError>>,
        ) -> Self {
            Self {
                store_results: RefCell::new(store_results.into()),
                get_results: RefCell::new(get_results.into()),
            }
        }
    }

    impl DataStorage for ScriptedStore {
        async fn get_keys(&self) -> Result<Vec<String>, DataStorageError> {
            Ok(Vec::new())
        }

        async fn store<T: Serialize>(
            &self,
            _key: &str,
            _mode: &StoreMode,
            _item: &T,
        ) -> Result<(), DataStorageError> {
            self.store_results
                .borrow_mut()
                .pop_front()
                .expect("ScriptedStore: unexpected store() call -- script exhausted")
        }

        async fn get<T: DeserializeOwned>(
            &self,
            _key: &str,
        ) -> Result<Option<(T, String)>, DataStorageError> {
            match self
                .get_results
                .borrow_mut()
                .pop_front()
                .expect("ScriptedStore: unexpected get() call -- script exhausted")
            {
                Ok(Some(bytes)) => {
                    let item = serde_json::from_slice(&bytes)
                        .map_err(|e| DataStorageError::Unexpected(e.to_string()))?;
                    Ok(Some((item, "1".to_string())))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            }
        }

        async fn delete(&self, _key: &str) -> Result<(), DataStorageError> {
            Ok(())
        }

        async fn delete_all(&self) -> Result<(), DataStorageError> {
            Ok(())
        }
    }

    #[test]
    fn refresh_lock_stale_takeover_losing_cas_race_denies() {
        // Put-if-absent fails (key exists), the held lock reads as STALE (acquired_at far in the
        // past), so a CAS-overwrite takeover is attempted -- but another worker wins that CAS first
        // (CasMismatch). The loser must back off and serve the cached value (Ok(false)), never
        // wrongly believe it holds the lock.
        let stale = serde_json::to_vec(&super::RefreshLock { acquired_at: 0 }).unwrap();
        let store = ScriptedStore::new(
            vec![
                Err(DataStorageError::CasMismatch), // initial put-if-absent: key already exists
                Err(DataStorageError::CasMismatch), // CAS takeover of the stale lock: lost the race
            ],
            vec![Ok(Some(stale))], // read-back: a stale holder (acquired_at = 0)
        );

        // `now` well past the 30s TTL so the held lock is classified stale (now - 0 >= TTL).
        let now = REFRESH_LOCK_TTL_SECONDS + 100;
        let acquired = block_on(super::try_acquire_refresh_lock(&store, "k", now)).unwrap();
        assert!(!acquired, "losing the CAS takeover race must deny the lock, not grant it");
    }

    #[test]
    fn refresh_lock_stale_takeover_hard_error_propagates() {
        // As above, but the CAS-overwrite of the stale lock fails with a hard (non-CasMismatch)
        // storage error. `try_acquire_refresh_lock` must propagate the error to the caller rather
        // than silently deny or grant -- resolve_score then decides (it favours freshness).
        let stale = serde_json::to_vec(&super::RefreshLock { acquired_at: 0 }).unwrap();
        let store = ScriptedStore::new(
            vec![
                Err(DataStorageError::CasMismatch),
                Err(DataStorageError::Unexpected("cas takeover write blew up".to_string())),
            ],
            vec![Ok(Some(stale))],
        );

        let now = REFRESH_LOCK_TTL_SECONDS + 100;
        let result = block_on(super::try_acquire_refresh_lock(&store, "k", now));
        assert!(
            matches!(result, Err(DataStorageError::Unexpected(_))),
            "a hard error taking over a stale lock must propagate, got {result:?}"
        );
    }

    #[test]
    fn refresh_lock_vanished_then_reclaimed_on_retry() {
        // Put-if-absent fails (CasMismatch), but the read-back finds nothing: the lock vanished
        // (e.g. TTL-expired) between the failed put and the read. The atomic claim is retried once
        // and succeeds -- this request now legitimately holds the lock (Ok(true)).
        let store = ScriptedStore::new(
            vec![
                Err(DataStorageError::CasMismatch), // initial put-if-absent
                Ok(()),                             // retry put-if-absent: claimed
            ],
            vec![Ok(None)], // read-back: the lock vanished
        );

        let acquired = block_on(super::try_acquire_refresh_lock(&store, "k", 1_000)).unwrap();
        assert!(acquired, "a vanished lock must be re-claimed on the retry");
    }

    #[test]
    fn refresh_lock_vanished_then_lost_to_concurrent_claim() {
        // The lock vanished, but on the retry another worker has already re-created it
        // (CasMismatch). This request must back off and serve cached (Ok(false)).
        let store = ScriptedStore::new(
            vec![
                Err(DataStorageError::CasMismatch), // initial put-if-absent
                Err(DataStorageError::CasMismatch), // retry put-if-absent: someone else got in first
            ],
            vec![Ok(None)], // read-back: the lock vanished
        );

        let acquired = block_on(super::try_acquire_refresh_lock(&store, "k", 1_000)).unwrap();
        assert!(!acquired, "if another request re-claims the vanished lock first, we must back off");
    }

    #[test]
    fn refresh_lock_vanished_retry_hard_error_propagates() {
        // The lock vanished, and the retry put-if-absent fails with a hard (non-CasMismatch)
        // storage error -- it must propagate rather than be swallowed into a false grant/deny.
        let store = ScriptedStore::new(
            vec![
                Err(DataStorageError::CasMismatch),
                Err(DataStorageError::Unexpected("retry claim backend down".to_string())),
            ],
            vec![Ok(None)],
        );

        let result = block_on(super::try_acquire_refresh_lock(&store, "k", 1_000));
        assert!(
            matches!(result, Err(DataStorageError::Unexpected(_))),
            "a hard error on the vanished-lock retry must propagate, got {result:?}"
        );
    }

    #[test]
    fn refresh_lock_initial_put_if_absent_hard_error_propagates() {
        // The very first put-if-absent fails with a hard (non-CasMismatch) storage error. There is
        // no read-back or retry -- the error propagates straight to the caller.
        let store = ScriptedStore::new(
            vec![Err(DataStorageError::Unexpected("store backend down".to_string()))],
            vec![], // get must never be called on this path
        );

        let result = block_on(super::try_acquire_refresh_lock(&store, "k", 1_000));
        assert!(
            matches!(result, Err(DataStorageError::Unexpected(_))),
            "a hard error on the initial put-if-absent must propagate to the caller, got {result:?}"
        );
    }

    // --- entrypoint-driven coverage: resolve_score contention, CDGC HTTP errors, config arms ---

    #[test]
    fn stale_cache_served_without_cdgc_when_refresh_lock_still_fresh() {
        // resolve_score contention arm: when the cached score has gone stale but a *fresh* refresh
        // lock is still held (another request is presumed mid-refresh), this request must serve the
        // existing cached score WITHOUT paying for its own CDGC round-trip. Distinct from the
        // stale-refresh tests, which sleep past the 30s lock TTL so the lock is instead taken over
        // and re-fetched.
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            // refreshIntervalSeconds=1 makes the cache go stale almost immediately, while the
            // refresh lock's fixed 30s TTL keeps the just-acquired lock fresh -- the exact window
            // the stampede guard must serve-cached rather than re-fetch.
            .with_config(config_with(json!({ "refreshIntervalSeconds": 1 })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(95.0))
            .with_entrypoint(super::configure);

        // Request 1 (t=0): cold cache -> acquires the lock, fetches 95.0 from CDGC, caches it.
        let first = tester.request(mcp_request(1));
        assert_eq!(first.header("x-dq-gate-status"), Some("ok"));
        assert_eq!(*login_calls.borrow(), 1, "the first request must perform the CDGC login");
        assert!(backend.next().is_some());

        // Advance 5s: past refreshIntervalSeconds (1) so the cache is stale, but well within the
        // 30s refresh-lock TTL so the lock acquired at t=0 is still fresh and held.
        tester.sleep(Duration::from_secs(5));

        // Request 2 (t=5): cache stale, but the fresh lock denies acquisition -> serve the cached
        // 95.0 and DO NOT re-authenticate against CDGC.
        let second = tester.request(mcp_request(2));
        assert_eq!(second.status_code(), 200);
        assert_eq!(
            second.header("x-dq-gate-status"),
            Some("ok"),
            "the still-cached score must be served during refresh contention"
        );
        assert!(second.body().is_empty(), "a served-cached pass-through carries no error body");
        assert!(backend.next().is_some(), "the contended request must still forward to the MCP backend");
        assert_eq!(
            *login_calls.borrow(),
            1,
            "serving the cached score during contention must NOT trigger a second CDGC fetch"
        );
    }

    #[test]
    fn fetch_login_http_error_blocks_as_unknown_score() {
        // fetch_cdgc_score line ~438: the CDGC Login call returns an HTTP >= 300 status, so the
        // refresh must abort with an error BEFORE parsing the body. With no cached score, that
        // yields no score at all, and blockOnUnknownScore defaults closed -> -32008 block.
        //
        // Non-vacuous by construction: the Login response carries an OTHERWISE-VALID body and a
        // healthy 95.0 score is registered downstream, so if the `status_code() >= 300` guard were
        // removed the login body would parse, the chain would run to a passing score, and the
        // request would come back "ok" instead of "blocked" -- flipping this assertion.
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let login_500 = |req: UnitHttpRequest| {
            let path = req.header(":path").unwrap_or_default();
            if path.starts_with("/identity-service/api/v1/Login") {
                // >= 300 but with a valid CdgcLoginResponse body (proves the status guard, not a
                // parse failure, is what aborts).
                UnitHttpResponse::new(500)
                    .with_body(json!({ "sessionId": "session-1", "orgId": "org-1" }).to_string())
            } else if path.starts_with("/identity-service/api/v1/jwt/Token") {
                UnitHttpResponse::new(200).with_body(json!({ "jwt_token": "test-jwt" }).to_string())
            } else {
                UnitHttpResponse::new(404)
            }
        };

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", login_500)
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(95.0))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(21));

        assert_eq!(response.status_code(), 200);
        assert_eq!(
            response.header("x-dq-gate-status"),
            Some("blocked"),
            "a login HTTP error must abort the refresh and (no cache) fail closed"
        );
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 21);
        assert_eq!(body["error"]["code"], -32008);
        // No secret/body leak: the generic (disclose=false) message must not echo the upstream
        // Login payload's sessionId nor the HTTP status code.
        let msg = body["error"]["message"].as_str().unwrap();
        assert!(msg.contains("did not meet the required standard"), "got: {}", msg);
        let raw = String::from_utf8_lossy(response.body());
        assert!(!raw.contains("session-1"), "must not leak login sessionId: {}", raw);
        assert!(!raw.contains("500"), "must not leak upstream status code: {}", raw);
        // A blocked request must never reach the MCP backend.
        assert!(backend.next().is_none());
    }

    #[test]
    fn fetch_jwt_http_error_blocks_as_unknown_score() {
        // fetch_cdgc_score line ~465: Login succeeds, but the JWT Token call returns HTTP >= 300, so
        // the refresh aborts before parsing the JWT body. No cached score -> fail closed (-32008).
        //
        // Non-vacuous: the JWT response carries a valid CdgcJwtResponse body and a healthy 95.0
        // score is registered downstream, so if the jwt `status_code() >= 300` guard were removed
        // the body would parse, the chain would reach a passing score, and the request would return
        // "ok" instead of "blocked".
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let jwt_500 = |req: UnitHttpRequest| {
            let path = req.header(":path").unwrap_or_default();
            if path.starts_with("/identity-service/api/v1/Login") {
                UnitHttpResponse::new(200)
                    .with_body(json!({ "sessionId": "session-1", "orgId": "org-1" }).to_string())
            } else if path.starts_with("/identity-service/api/v1/jwt/Token") {
                // >= 300 but with a valid jwt body (proves the status guard, not a parse failure).
                UnitHttpResponse::new(500).with_body(json!({ "jwt_token": "test-jwt" }).to_string())
            } else {
                UnitHttpResponse::new(404)
            }
        };

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", jwt_500)
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(95.0))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(22));

        assert_eq!(response.status_code(), 200);
        assert_eq!(
            response.header("x-dq-gate-status"),
            Some("blocked"),
            "a JWT HTTP error must abort the refresh and (no cache) fail closed"
        );
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["id"], 22);
        assert_eq!(body["error"]["code"], -32008);
        // No secret/body leak: the JWT material must never appear in the client response.
        let raw = String::from_utf8_lossy(response.body());
        assert!(!raw.contains("test-jwt"), "must not leak JWT token: {}", raw);
        assert!(!raw.contains("session-1"), "must not leak sessionId: {}", raw);
        assert!(!raw.contains("500"), "must not leak upstream status code: {}", raw);
        assert!(backend.next().is_none());
    }

    #[test]
    fn fetch_detail_http_error_blocks_as_unknown_score() {
        // fetch_cdgc_score line ~496: Login + JWT succeed, but the CDGC Detail (dataQuality) call
        // returns HTTP >= 300, so the refresh aborts before parsing the asset detail body. No
        // cached score -> fail closed (-32008).
        //
        // The 500 here carries a VALID dataQuality body with a healthy 95.0 score, so if the detail
        // `status_code() >= 300` guard were removed the body would parse to a passing score and the
        // request would return "ok" instead of "blocked".
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let detail_500 = |_req: UnitHttpRequest| {
            UnitHttpResponse::new(500)
                .with_body(json!({ "dataQuality": [{ "core.score": 95.0 }] }).to_string())
        };

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", detail_500)
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(23));

        assert_eq!(response.status_code(), 200);
        assert_eq!(
            response.header("x-dq-gate-status"),
            Some("blocked"),
            "a Detail HTTP error must abort the refresh and (no cache) fail closed"
        );
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["id"], 23);
        assert_eq!(body["error"]["code"], -32008);
        // Prove the healthy score in the (rejected) detail body was NOT used and did not leak.
        let raw = String::from_utf8_lossy(response.body());
        assert!(!raw.contains("95"), "the discarded detail score must not leak: {}", raw);
        // Login+JWT were reached before the detail failure.
        assert_eq!(*login_calls.borrow(), 1);
        assert!(backend.next().is_none());
    }

    #[test]
    fn distributed_true_uses_remote_backend_and_still_gates() {
        // distributed=true selects the gossip-replicated REMOTE DataStorage backend for BOTH the
        // score cache and the refresh lock (the `if config.distributed` arm in `configure`).
        // Downstream gating logic is identical to the local path: a healthy CDGC score (95, above
        // warnThreshold 90) must still resolve, pass through, and tag the response "ok" -- proving
        // the remote-backed `launch_policy` monomorphization wires up and runs end to end. If the
        // remote arm failed to launch (or the remote-backed store broke resolution), the status
        // would not be "ok" and the backend would not be reached.
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "distributed": true })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(95.0))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("ok"));
        assert!(backend.next().is_some(), "distributed-mode traffic must still reach the MCP backend");
        assert_eq!(*login_calls.borrow(), 1, "the remote-backed path must still resolve the score via CDGC");
    }

    #[test]
    fn empty_body_post_passes_through_ungated() {
        // A POST with a JSON content-type but NO body: `state.contains_body()` is false, so the
        // filter takes the `Vec::new()` arm rather than reading a body. An empty body is not a
        // JSON-RPC 2.0 call, so `parse_jsonrpc_call` returns None and the request fails open --
        // proving a bodyless POST (e.g. a health probe) is never gated, even though a low CDGC
        // score (50, below blockThreshold 80) is registered that would block a real tools/call.
        // login_calls staying at 0 proves resolve_score was never even attempted.
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = recognition_tester(Rc::clone(&login_calls), Rc::clone(&backend));

        let request = UnitHttpRequest::post()
            .with_path("/mcp")
            .with_header("content-type", "application/json");
        let response = tester.request(request);

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("skipped"));
        assert!(response.body().is_empty(), "a bodyless POST must not receive an error body");
        assert!(backend.next().is_some());
        assert_eq!(*login_calls.borrow(), 0, "resolve_score must not run for an empty-body request");
    }

    #[test]
    fn soft_launch_bypass_warns_once_then_suppresses_on_repeat() {
        // #10 soft-launch: with no score available and blockOnUnknownScore=false, EVERY request
        // passes ungated (status "unknown"), but the BYPASS warning is emitted only ONCE per
        // worker. Two requests on the SAME tester (same worker / same thread-local
        // UNGATED_BYPASS_LOGGED) exercise both arms of the warn-once guard: the second request
        // deterministically finds the flag already set (regardless of what other tests did on this
        // thread), taking the `if first_bypass` false path -- while still passing through to the
        // backend. This guards the "warned once per worker" contract: if the guard regressed and
        // blocked, or failed to pass the second request through, the test fails.
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "blockOnUnknownScore": false })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_entrypoint(super::configure);

        // First request: passes ungated (and, if this is the first bypass on this worker, warns).
        let first = tester.request(mcp_request(1));
        assert_eq!(first.status_code(), 200);
        assert_eq!(first.header("x-dq-gate-status"), Some("unknown"));
        assert!(backend.next().is_some(), "first soft-launch request must reach the backend");

        // Second request on the SAME worker: still passes ungated, but the warn-once guard now
        // suppresses the BYPASS log (the `if first_bypass` false arm).
        let second = tester.request(mcp_request(2));
        assert_eq!(second.status_code(), 200);
        assert_eq!(second.header("x-dq-gate-status"), Some("unknown"));
        assert!(second.body().is_empty(), "a soft-launch pass-through must not carry an error body");
        assert!(backend.next().is_some(), "second soft-launch request must also reach the backend");
        assert!(second.violation().is_none(), "an ungated pass-through must not emit a violation");
    }
}
