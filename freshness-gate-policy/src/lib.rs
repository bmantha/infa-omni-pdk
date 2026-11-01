// Copyright 2026 Salesforce, Inc. All rights reserved.
mod generated;

use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use pdk::data_storage::{DataStorage, DataStorageBuilder, StoreMode};
use pdk::hl::timer::Clock;
use pdk::hl::*;
use pdk::logger;
use pdk::metadata::Metadata;
use pdk::policy_violation::PolicyViolations;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::generated::config::Config;

const OAUTH_TOKEN_CACHE_NAMESPACE: &str = "freshness-gate-object-store-oauth-tokens";
const OAUTH_TOKEN_CACHE_KEY: &str = "object-store-oauth-token";
const SCORE_CACHE_KEY_PREFIX: &str = "freshness-score-";
const REFRESH_LOCK_KEY_PREFIX: &str = "freshness-refresh-lock-";
const REFRESH_LOCK_TTL_SECONDS: i64 = 30;
const DEFAULT_TIMEOUT_MS: i64 = 60_000;
/// Overall latency budget for the *whole* inline CDGC refresh chain in [`fetch_cdgc_score`]
/// (Login -> JWT -> Detail). Each call's effective timeout is clamped to whatever is left of this
/// budget (see [`next_call_timeout`]), so the three chained calls can never together block the
/// request longer than this, regardless of `timeout`/[`DEFAULT_TIMEOUT_MS`]. Without this, a
/// worst case of three `DEFAULT_TIMEOUT_MS` calls could block a single agent request for minutes.
const CDGC_REFRESH_BUDGET_MS: i64 = 10_000;
const DEFAULT_REFRESH_INTERVAL_SECONDS: i64 = 900;
const CDGC_JWT_NONCE: &str = "1234";

/// JSON-RPC error code returned when an MCP request is blocked. Chosen from the JSON-RPC 2.0
/// server-defined reserved range (`-32000..=-32099`) and deliberately NOT `-32000`, which collides
/// with the common router/proxy "path or method not found" convention; `-32008` is this policy's
/// dedicated "blocked by Freshness Gate" code, used consistently on both block paths
/// (below-threshold and unknown-score).
const JSONRPC_BLOCK_ERROR_CODE: i64 = -32008;

/// JSON-RPC error code returned when an **A2A** invocation is blocked on the JSON-RPC binding. It
/// MUST differ from the MCP code above: A2A mints its own errors in the same JSON-RPC reserved
/// range and has so far assigned `-32001..=-32009` (e.g. `-32008` = `ExtensionSupportRequiredError`,
/// `-32009` = `VersionNotSupportedError`, per the A2A spec at tags v0.3.0 / v1.0.0). `-32010` is the
/// first slot *above* A2A's currently-assigned codes, so it can never collide with an A2A-defined
/// one -- whereas reusing the MCP code above here would collide with A2A's
/// `ExtensionSupportRequiredError`.
const A2A_BLOCK_ERROR_CODE: i64 = -32010;
/// The A2A **HTTP+JSON (REST)** binding block returns this native HTTP status (Forbidden -- the
/// request is well-formed but denied by policy), carrying a `google.rpc.Status` body (pdk-a2a Shape
/// 3). The A2A **JSON-RPC** binding block, by contrast, stays HTTP 200 with the error carried
/// in-band in the JSON-RPC envelope -- the JSON-RPC transport convention shared with MCP; only the
/// code (`-32010`) and, on v1.0, the `google.rpc.ErrorInfo` `data` array distinguish it from an MCP
/// block.
const A2A_REST_BLOCK_HTTP_STATUS: u32 = 403;
/// `google.rpc.ErrorInfo.reason` (UPPER_SNAKE_CASE, no "Error" suffix, per the convention) carried
/// on an A2A v1.0 block.
const A2A_ERROR_REASON: &str = "FRESHNESS_SCORE_BELOW_THRESHOLD";
/// `google.rpc.ErrorInfo.domain` on an A2A v1.0 block. Deliberately NOT `a2a-protocol.org` -- that
/// domain identifies errors defined *by the A2A protocol itself*; this is a policy-owned domain
/// identifying the Freshness Gate as the service that produced the error.
const A2A_ERROR_DOMAIN: &str = "freshness-gate.mulesoft.com";
const HEADER_SLA_SCORE: &str = "x-freshness-gate-score";
const HEADER_SLA_STATUS: &str = "x-freshness-gate-status";

/// MCP handshake, discovery, and administrative methods that must always pass through ungated. An
/// MCP client (e.g. `mcp-remote`) issues `initialize` and `tools/list` just to establish the
/// connection and enumerate capabilities, before the agent has chosen to invoke anything --
/// blocking those means the client never even connects, rather than surfacing a per-call block.
/// `logging/setLevel` and `completion/complete` are control/helper calls that touch no governed
/// asset data, so gating them on a freshness score would be semantically wrong.
///
/// Gating is reserved for the *content-bearing* methods that actually read the governed asset's
/// data: `tools/call`, `resources/read`, `prompts/get` (MCP), and the A2A message-send methods
/// below. Any method that is not in this exempt list, not A2A housekeeping, and not a notification
/// is gated.
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
// The A2A JSON-RPC surface is the A2A analogue of MCP: the same gating principle applies -- only
// the *content-bearing* calls that actually invoke the target agent (send a message / task to it)
// are gated on the freshness score; everything else (task lifecycle, push-notification config,
// agent-card discovery) is housekeeping and passes through ungated.
//
// A2A's two protocol versions use DISJOINT method vocabularies, and both are disjoint from MCP's,
// so the method string alone classifies both the protocol AND (for A2A) the version -- no header
// needed for JSON-RPC:
//   * v0.3.0 uses slash-style names (`message/send`, `tasks/get`, `agent/...`);
//   * v1.0    uses PascalCase names (`SendMessage`, `GetTask`, ...);
//   * MCP never uses the `message/`, `tasks/`, or `agent/` prefixes, nor PascalCase.

/// A2A v0.3.0 message-send (unary) -- gated.
const A2A_V03_SEND: &str = "message/send";
/// A2A v0.3.0 message-send (streaming, SSE) -- gated: it invokes the agent just like the unary send.
const A2A_V03_STREAM: &str = "message/stream";
/// A2A v1.0 message-send (unary) -- gated.
const A2A_V1_SEND: &str = "SendMessage";
/// A2A v1.0 message-send (streaming) -- gated.
const A2A_V1_STREAM: &str = "SendStreamingMessage";

/// A2A housekeeping / discovery methods (both versions), enumerated so they are explicitly
/// exempted rather than falling through to the default MCP-gated arm of
/// [`classify_jsonrpc_method`]. These manage task state and delivery config or fetch the agent
/// card -- none reads the governed asset's data, so gating them on a freshness score would be
/// wrong (and would wrongly *block* them below threshold).
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

/// Organization/environment scope used to build Object Store REST paths, sourced from the
/// policy's injected [`Metadata`] (populated from the Flex Gateway registration) rather than a
/// static config property.
struct ObjectStoreScope {
    org_id: String,
    env_id: String,
}

/// Derives the Object Store scope from the policy's platform metadata. Returns `None` -- and logs
/// once -- if the gateway isn't registered against an Anypoint Platform org/environment, which
/// disables score caching entirely (every request then falls back to a live CDGC fetch, subject
/// to `blockOnUnknownScore`/`failOpenOnCdgcError` if that fetch fails).
fn object_store_scope(metadata: &Metadata) -> Option<ObjectStoreScope> {
    let org_id = metadata.platform_metadata.organization_id.clone();
    let env_id = metadata.platform_metadata.environment_id.clone();

    if org_id.is_empty() || env_id.is_empty() {
        logger::warn!("Missing org/env in metadata, SLA score caching disabled");
        return None;
    }

    Some(ObjectStoreScope { org_id, env_id })
}

/// Envelope shape used by the Object Store V2 REST API for a stored key's value.
#[derive(Serialize, Deserialize)]
struct ObjectStoreEnvelope {
    #[serde(rename = "stringValue")]
    string_value: String,
    #[serde(rename = "keyId")]
    key_id: String,
    #[serde(rename = "valueType")]
    value_type: String,
}

/// The cached SLA/freshness score for `cdgcRuleInstanceId`, and when it was fetched -- compared
/// against `refreshIntervalSeconds` on every request to decide whether a live CDGC fetch is needed.
#[derive(Serialize, Deserialize, Clone)]
struct CachedScore {
    score: f64,
    timestamp: i64,
}

#[derive(Serialize, Deserialize)]
struct CachedOauthToken {
    access_token: String,
    valid_until: SystemTime,
}

#[derive(Deserialize)]
struct OauthTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
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

/// The RuleInstance's own scored attributes, read via the CDGC Detail API's `selfAttributes`
/// segment. CDGC has no separate "freshness score" concept: a freshness SLA is expressed as a DQ
/// RuleInstance (e.g. thresholding `LAST_SYNCED_AT` recency against a template), and its `value`
/// attribute -- set directly on the RuleInstance object, the same field the CDGC UI displays as
/// the rule's current result -- is the score this policy gates on. This policy never computes
/// that value itself; it's published externally (an upstream CDI/Data-Quality-Scorecard job in a
/// real deployment, a manual CDGC publish call in this demo) and read here as-is.
///
/// This deliberately does *not* read the asset's `dataQuality` rollup segment: that segment is
/// populated only for RuleInstances produced by Informatica's own automated ICDQ pipeline
/// (`core.producer: "infa-producer.dq"`), a flag the public Publish API cannot set on a
/// user-created RuleInstance. `cdgcRuleInstanceId` must therefore be the RuleInstance's own ID, not the
/// monitored table/column's ID -- its `selfAttributes.value` is real and directly queryable
/// regardless of that rollup gap.
#[derive(Deserialize, Default)]
struct AssetDetailResponse {
    #[serde(rename = "selfAttributes", default)]
    self_attributes: RuleInstanceAttributes,
}

#[derive(Deserialize, Default)]
struct RuleInstanceAttributes {
    #[serde(rename = "com.infa.ccgf.models.governance.value")]
    value: Option<f64>,
}

/// Data threaded from the request filter to the response filter, used only to annotate the
/// (allowed) response with diagnostic headers -- never consulted for the block decision, which
/// already happened in the request filter.
enum FreshnessGateData {
    Evaluated { score: Option<f64>, status: &'static str },
}

/// The A2A protocol version of a request gated on the **JSON-RPC** binding. Governs only the
/// *shape* of that binding's `error.data`: v1.0 carries a single-element `google.rpc.ErrorInfo`
/// array, v0.3.0 (Legacy) a free-form string. Read straight off the (version-disjoint) method
/// name. The REST binding does not use this -- A2A's HTTP+JSON binding is a v1.0 surface with a
/// single (version-independent) `google.rpc.Status` rejection shape.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum A2aVersion {
    V0_3,
    V1_0,
}

/// The A2A transport binding a *gated* A2A request arrived on -- selects the rejection shape, per
/// the `pdk-a2a` convention: the JSON-RPC binding answers in-band at HTTP 200; the HTTP+JSON (REST)
/// binding answers with a native HTTP status and a `google.rpc.Status` body (no JSON-RPC envelope).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum A2aBinding {
    /// JSON-RPC 2.0 over POST (Legacy v0.3.0 and V1). Version selects the `error.data` shape.
    JsonRpc(A2aVersion),
    /// HTTP+JSON (REST) message-send binding (`/message:send`, ...). A2A v1.0 surface; Shape 3.
    Rest,
}

/// The wire protocol a *gated* request arrived on. Selects the block-response shape: MCP -> HTTP
/// 200 + JSON-RPC `-32008`; A2A JSON-RPC -> HTTP 200 + JSON-RPC `-32010` (a `[google.rpc.ErrorInfo]`
/// `data` array on v1.0); A2A REST -> native HTTP 403 + a `google.rpc.Status` body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum GateProtocol {
    Mcp,
    A2a(A2aBinding),
}

/// Classification of a recognized request: gate it on the given protocol's terms, or pass it
/// through ungated (MCP handshake/discovery, A2A housekeeping, anything unrecognized on a
/// non-send path).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RequestClass {
    Gated(GateProtocol),
    Exempt,
}

fn timeout(config: &Config) -> Duration {
    Duration::from_millis(config.timeout.unwrap_or(DEFAULT_TIMEOUT_MS).max(0) as u64)
}

fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
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

fn score_cache_key(config: &Config) -> String {
    format!("{SCORE_CACHE_KEY_PREFIX}{}", config.cdgc_rule_instance_id)
}

/// Percent-encodes `value` for safe interpolation into a URL path segment or query value.
/// Everything outside the RFC 3986 "unreserved" set (`A-Z a-z 0-9 - _ . ~`) is escaped as `%XX` on
/// a UTF-8 byte basis. PDK's request builder takes the path/query string verbatim and performs no
/// encoding, and no third-party URL crate is pulled in (prefer-PDK / minimal-deps rules), so this
/// small encoder prevents `cdgcRuleInstanceId` containing `?`, `#`, `/`, `&`, `=`, or whitespace
/// from altering the request target or injecting query parameters.
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

/// Whether a JSON-RPC method name denotes an MCP notification. Per MCP/JSON-RPC 2.0 a notification
/// carries no `id` and MUST NEVER receive a response, so it can never be blocked. All MCP
/// notifications use the `notifications/` prefix.
fn is_notification_method(method: &str) -> bool {
    method.starts_with("notifications/")
}

/// Parses a request body as a single JSON-RPC 2.0 request and returns its `(method, id)`.
///
/// Returns `None` -- meaning "not a gate-able MCP/A2A call, pass through (fail-open)" -- for
/// anything that is not a single well-formed JSON-RPC 2.0 object carrying a string `method`:
/// unparsable JSON, a top-level array (a JSON-RPC *batch*, out of scope for gating here), a
/// scalar, a response object, a missing or non-`"2.0"` `jsonrpc` tag, or a missing `method`. The
/// `id` is returned verbatim (absent -> `None`, which the caller treats as a notification); it is
/// echoed back in a block response so the client can correlate it.
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

/// Classifies a JSON-RPC `method` into gate-or-exempt (and, when gated, which protocol/version
/// shapes the block). The A2A send methods are matched first (their vocabulary is disjoint from
/// MCP's and self-describes the version); then A2A housekeeping and the MCP exempt set pass
/// through; anything else -- the MCP content-bearing methods (`tools/call`, `resources/read`,
/// `prompts/get`) and any unrecognized method -- is gated as MCP, preserving the MCP-only design's
/// fail-closed default.
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

/// Recognizes the A2A HTTP+JSON (REST) *message-send* binding from the request path, for the
/// transport where the body is a bare `SendMessageRequest`/`MessageSendParams` (no JSON-RPC
/// envelope, so [`parse_jsonrpc_call`] returns `None`). This is A2A's v1.0 REST surface. A2A/AIP
/// action bindings put the verb after a `:` on the final path segment (`message:send`), optionally
/// behind an API-version or tenant prefix (`/v1/message:send`, `/{tenant}/message:send`). Matching
/// on the final segment alone therefore recognizes the send across any routing prefix, while
/// leaving every non-send REST path (task lifecycle, agent-card discovery) unmatched -> ungated.
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
/// state -- the exact score, `blockThreshold`, and `cdgcRuleInstanceId` -- is revealed to the
/// client. Off by default so a client can't probe threshold boundaries or learn asset identifiers;
/// the full detail is always recorded server-side by the `warn!` in `request_filter` regardless.
fn block_message(disclose: bool, score: Option<f64>, config: &Config) -> String {
    if disclose {
        match score {
            Some(score) => format!(
                "Blocked by Freshness Gate: asset '{}' SLA score {score:.2} is below blockThreshold {:.2}",
                config.cdgc_rule_instance_id, config.block_threshold
            ),
            None => format!(
                "Blocked by Freshness Gate: no SLA score is available yet for asset '{}'",
                config.cdgc_rule_instance_id
            ),
        }
    } else {
        "Blocked by Freshness Gate: this data source's freshness/SLA did not meet the required standard"
            .to_string()
    }
}

/// The diagnostic headers shared by every block response, on any protocol: `content-type:
/// application/json` (the body is always a JSON error object), the raw `x-freshness-gate-score`
/// only when disclosure is opted in, and the always-safe coarse `x-freshness-gate-status: blocked`.
fn block_headers(disclose: bool, score: Option<f64>) -> Vec<(String, String)> {
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    if disclose {
        if let Some(score) = score {
            headers.push((HEADER_SLA_SCORE.to_string(), format!("{score:.2}")));
        }
    }
    headers.push((HEADER_SLA_STATUS.to_string(), "blocked".to_string()));
    headers
}

/// Dispatches to the protocol-appropriate block builder. The score/threshold decision is made by
/// the caller ([`request_filter`]); this only shapes the rejection for the wire protocol/binding
/// the request arrived on -- MCP and the A2A JSON-RPC binding answer in-band at HTTP 200, the A2A
/// REST binding with a native HTTP status.
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

/// Builds the **MCP** JSON-RPC error response returned to the agent when a request is blocked.
/// Status `200` is intentional: MCP treats JSON-RPC errors as protocol-level, not transport-level,
/// so an MCP client expects `200` + an `error` object carrying [`JSONRPC_BLOCK_ERROR_CODE`], not an
/// HTTP 4xx.
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

/// Builds the `google.rpc.ErrorInfo` object carried on an A2A v1.0 block -- as the single element
/// of the JSON-RPC binding's `error.data` array and of the REST binding's `error.details` array.
/// The stable `reason`/`domain` are always present (they disclose no governance state); the
/// `metadata` map is populated only when `discloseScoreDetails` is on, exactly as it gates the MCP
/// message and the score header.
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
            "ruleInstanceId".to_string(),
            Value::String(config.cdgc_rule_instance_id.clone()),
        );
    }
    serde_json::json!({
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": A2A_ERROR_REASON,
        "domain": A2A_ERROR_DOMAIN,
        "metadata": Value::Object(metadata),
    })
}

/// Builds the A2A rejection for the **JSON-RPC** binding (Legacy v0.3.0 and V1). Per the
/// A2A/JSON-RPC transport convention the failure is carried *in-band* at **HTTP 200** -- the
/// transport succeeded, the error lives in the envelope -- exactly as for MCP; only the code
/// ([`A2A_BLOCK_ERROR_CODE`], `-32010`) and the `error.data` shape distinguish it. On **v1.0**
/// `error.data` is a single-element array carrying a `google.rpc.ErrorInfo` (pdk-a2a Shape 2); on
/// **v0.3.0** (Legacy) it is a free-form string (Shape 1), included only when disclosing.
/// `discloseScoreDetails` gates what the `ErrorInfo` metadata reveals.
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
        // v1.0: data is a single-element array carrying a typed google.rpc.ErrorInfo (Shape 2).
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

/// Builds the A2A rejection for the **HTTP+JSON (REST)** binding (A2A v1.0). This is pdk-a2a Shape
/// 3: a native HTTP status ([`A2A_REST_BLOCK_HTTP_STATUS`], `403`) with a `google.rpc.Status` body
/// -- **no** JSON-RPC envelope. `error.code` mirrors the HTTP status and `error.details` is a
/// single-element array carrying the same `google.rpc.ErrorInfo` as the v1.0 JSON-RPC block.
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

/// Fetches an Object Store V2 access token via OAuth2 client-credentials, caching it in-memory
/// until shortly before it expires so we don't re-authenticate on every request.
async fn fetch_object_store_token(
    client: &HttpClient,
    config: &Config,
    token_cache: &impl DataStorage,
    clock: &Clock,
) -> Result<String> {
    if let Ok(Some((cached, _))) = token_cache.get::<CachedOauthToken>(OAUTH_TOKEN_CACHE_KEY).await {
        if clock.now() < cached.valid_until {
            return Ok(cached.access_token);
        }
    }

    let request_body = serde_json::to_vec(&serde_json::json!({
        "client_id": config.object_store_client_id,
        "client_secret": config.object_store_client_secret,
        "grant_type": "client_credentials",
    }))?;

    let response = client
        .request(&config.object_store_auth_url)
        .headers(vec![("Content-Type", "application/json")])
        .body(&request_body)
        .timeout(timeout(config))
        .post()
        .await
        .map_err(|err| anyhow!("Object Store OAuth token request failed: {err}"))?;

    if response.status_code() >= 300 {
        return Err(anyhow!(
            "Object Store OAuth returned status {}: {}",
            response.status_code(),
            String::from_utf8_lossy(response.body())
        ));
    }

    let parsed: OauthTokenResponse = serde_json::from_slice(response.body())
        .map_err(|err| anyhow!("Failed to parse OAuth token response: {err}"))?;

    let valid_until =
        clock.now() + Duration::from_secs(parsed.expires_in.unwrap_or(3600).saturating_sub(30));
    let cached = CachedOauthToken {
        access_token: parsed.access_token.clone(),
        valid_until,
    };
    let _ = token_cache.store(OAUTH_TOKEN_CACHE_KEY, &StoreMode::Always, &cached).await;

    Ok(parsed.access_token)
}

/// Builds the Object Store V2 REST path for a cache entry key.
fn object_store_path(scope: &ObjectStoreScope, config: &Config, key: &str) -> String {
    format!(
        "/api/v1/organizations/{}/environments/{}/stores/{}/partitions/default/keys/{}",
        scope.org_id, scope.env_id, config.object_store_name, key
    )
}

async fn object_store_get(
    client: &HttpClient,
    config: &Config,
    scope: &ObjectStoreScope,
    token: &str,
    key: &str,
) -> Result<Option<Vec<u8>>> {
    let path = object_store_path(scope, config, key);
    let authorization = format!("Bearer {token}");

    let response = client
        .request(&config.object_store_url)
        .path(&path)
        .headers(vec![("Authorization", authorization.as_str())])
        .timeout(timeout(config))
        .get()
        .await
        .map_err(|err| anyhow!("Object Store get failed: {err}"))?;

    match response.status_code() {
        200 => Ok(Some(response.body().to_vec())),
        404 => Ok(None),
        status => Err(anyhow!(
            "Object Store get returned {status}: {}",
            String::from_utf8_lossy(response.body())
        )),
    }
}

async fn object_store_put(
    client: &HttpClient,
    config: &Config,
    scope: &ObjectStoreScope,
    token: &str,
    key: &str,
    value: &[u8],
) -> Result<()> {
    let path = object_store_path(scope, config, key);
    let authorization = format!("Bearer {token}");

    let envelope = ObjectStoreEnvelope {
        string_value: String::from_utf8_lossy(value).into_owned(),
        key_id: key.to_string(),
        value_type: "STRING".to_string(),
    };
    let body = serde_json::to_vec(&envelope)?;

    let response = client
        .request(&config.object_store_url)
        .path(&path)
        .headers(vec![
            ("Authorization", authorization.as_str()),
            ("Content-Type", "application/json"),
        ])
        .body(&body)
        .timeout(timeout(config))
        .put()
        .await
        .map_err(|err| anyhow!("Object Store put failed: {err}"))?;

    if response.status_code() >= 300 {
        return Err(anyhow!(
            "Object Store put returned {}: {}",
            response.status_code(),
            String::from_utf8_lossy(response.body())
        ));
    }

    Ok(())
}

async fn get_cached_score(
    client: &HttpClient,
    config: &Config,
    scope: &ObjectStoreScope,
    token_cache: &impl DataStorage,
    key: &str,
    clock: &Clock,
) -> Result<Option<CachedScore>> {
    let token = fetch_object_store_token(client, config, token_cache, clock).await?;
    let Some(bytes) = object_store_get(client, config, scope, &token, key).await? else {
        return Ok(None);
    };

    let envelope: ObjectStoreEnvelope = serde_json::from_slice(&bytes)?;
    let cached: CachedScore = serde_json::from_str(&envelope.string_value)?;
    Ok(Some(cached))
}

async fn put_cached_score(
    client: &HttpClient,
    config: &Config,
    scope: &ObjectStoreScope,
    token_cache: &impl DataStorage,
    key: &str,
    cached: &CachedScore,
    clock: &Clock,
) -> Result<()> {
    let token = fetch_object_store_token(client, config, token_cache, clock).await?;
    let bytes = serde_json::to_vec(cached)?;
    object_store_put(client, config, scope, &token, key, &bytes).await
}

fn refresh_lock_key(config: &Config) -> String {
    format!("{REFRESH_LOCK_KEY_PREFIX}{}", config.cdgc_rule_instance_id)
}

/// Best-effort mutex over the Object Store so that when the cached score goes stale under heavy
/// concurrent traffic, only one request pays for the (expensive) CDGC Login+JWT+Detail sequence
/// instead of every in-flight request independently hammering CDGC at once -- which is exactly
/// what produces a CDGC `429` under load. Object Store V2 has no conditional-put/CAS primitive,
/// so this is GET-then-PUT, not a true atomic lock: a handful of concurrent *first* acquirers can
/// still race through right at the moment the lock expires. That's an acceptable tradeoff here --
/// the goal is collapsing a stampede of hundreds of concurrent refreshes down to roughly one per
/// `REFRESH_LOCK_TTL_SECONDS` window, not perfect mutual exclusion.
async fn try_acquire_refresh_lock(
    client: &HttpClient,
    config: &Config,
    scope: &ObjectStoreScope,
    token_cache: &impl DataStorage,
    now: i64,
    clock: &Clock,
) -> Result<bool> {
    let key = refresh_lock_key(config);
    let token = fetch_object_store_token(client, config, token_cache, clock).await?;

    if let Some(bytes) = object_store_get(client, config, scope, &token, &key).await? {
        let held = serde_json::from_slice::<ObjectStoreEnvelope>(&bytes)
            .ok()
            .and_then(|envelope| envelope.string_value.parse::<i64>().ok())
            .map(|acquired_at| now - acquired_at < REFRESH_LOCK_TTL_SECONDS)
            .unwrap_or(false);
        if held {
            return Ok(false);
        }
    }

    object_store_put(client, config, scope, &token, &key, now.to_string().as_bytes()).await?;
    Ok(true)
}

/// Runs the live CDGC sequence (Login -> JWT -> Detail API `selfAttributes` segment) and returns
/// the RuleInstance's own `value` attribute. A fresh Login+JWT is performed every call, on
/// purpose -- see the design doc's "Token strategy" decision -- since this only runs on a
/// stale-cache request.
///
/// The whole three-call chain is capped by [`CDGC_REFRESH_BUDGET_MS`]: `start` is stamped from the
/// injected [`Clock`] and each call's timeout is clamped (via [`next_call_timeout`]) to the budget
/// still remaining. If the budget is exhausted before a call, the refresh aborts with an error and
/// the caller applies the unknown-score fallback -- the agent's request never blocks unbounded.
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
        return Err(anyhow!(
            "CDGC login returned {}: {}",
            login_response.status_code(),
            String::from_utf8_lossy(login_response.body())
        ));
    }
    let login: CdgcLoginResponse = serde_json::from_slice(login_response.body())
        .map_err(|err| anyhow!("Failed to parse CDGC login response: {err}"))?;

    let jwt_path = format!("/identity-service/api/v1/jwt/Token?client_id=idmc_api&nonce={CDGC_JWT_NONCE}");
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
        return Err(anyhow!(
            "CDGC JWT fetch returned {}: {}",
            jwt_response.status_code(),
            String::from_utf8_lossy(jwt_response.body())
        ));
    }
    let jwt: CdgcJwtResponse = serde_json::from_slice(jwt_response.body())
        .map_err(|err| anyhow!("Failed to parse CDGC JWT response: {err}"))?;

    let detail_path = format!(
        "/data360/search/v1/assets/{}?scheme=internal&segments=selfAttributes",
        percent_encode(&config.cdgc_rule_instance_id)
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
        .map_err(|err| anyhow!("CDGC SLA score fetch failed: {err}"))?;

    if detail_response.status_code() >= 300 {
        return Err(anyhow!(
            "CDGC SLA score fetch returned {}: {}",
            detail_response.status_code(),
            String::from_utf8_lossy(detail_response.body())
        ));
    }
    let detail: AssetDetailResponse = serde_json::from_slice(detail_response.body())
        .map_err(|err| anyhow!("Failed to parse CDGC asset detail response: {err}"))?;

    detail.self_attributes.value.ok_or_else(|| {
        anyhow!(
            "CDGC RuleInstance '{}' has no value attribute set yet",
            config.cdgc_rule_instance_id
        )
    })
}

/// The core lazy/TTL cache-aside logic: read the cached score, and if it's missing or older than
/// `refreshIntervalSeconds`, refresh it from CDGC right here, inline, before returning a score to
/// gate on. Returns `None` only when no score is available at all (no cache, and the refresh --
/// if attempted -- also failed with `failOpenOnCdgcError=false`).
async fn resolve_score(
    client: &HttpClient,
    config: &Config,
    object_store_scope: Option<&ObjectStoreScope>,
    token_cache: &impl DataStorage,
    clock: &Clock,
) -> Option<f64> {
    let key = score_cache_key(config);
    let refresh_interval = config
        .refresh_interval_seconds
        .unwrap_or(DEFAULT_REFRESH_INTERVAL_SECONDS)
        .max(0);
    let fail_open = config.fail_open_on_cdgc_error.unwrap_or(true);

    let cached = match object_store_scope {
        Some(scope) => match get_cached_score(client, config, scope, token_cache, &key, clock).await {
            Ok(cached) => cached,
            Err(err) => {
                logger::warn!("Failed to read cached SLA score from Object Store: {err}");
                None
            }
        },
        None => None,
    };

    // Read wall-clock time through the injected PDK `Clock`, never `SystemTime::now()`, so it is
    // host-sourced and testable.
    let now = unix_seconds(clock.now());
    let is_stale = match &cached {
        Some(cached) => now - cached.timestamp > refresh_interval,
        None => true,
    };

    if !is_stale {
        logger::info!(
            "Using cached SLA score for asset '{}': {:.2} (age {}s)",
            config.cdgc_rule_instance_id,
            cached.as_ref().map(|c| c.score).unwrap_or_default(),
            cached.as_ref().map(|c| now - c.timestamp).unwrap_or_default()
        );
        return cached.map(|cached| cached.score);
    }

    if let Some(scope) = object_store_scope {
        let lock_acquired = match try_acquire_refresh_lock(client, config, scope, token_cache, now, clock).await {
            Ok(acquired) => acquired,
            Err(err) => {
                logger::warn!("Failed to acquire SLA score refresh lock: {err}");
                true
            }
        };
        if !lock_acquired {
            logger::info!(
                "SLA score refresh for asset '{}' already in progress elsewhere; serving existing cached value",
                config.cdgc_rule_instance_id
            );
            return cached.map(|cached| cached.score);
        }
    }

    match fetch_cdgc_score(client, config, clock).await {
        Ok(score) => {
            logger::info!(
                "Fetched fresh SLA score from CDGC for asset '{}': {score:.2}",
                config.cdgc_rule_instance_id
            );
            if let Some(scope) = object_store_scope {
                let fresh = CachedScore { score, timestamp: now };
                if let Err(err) = put_cached_score(client, config, scope, token_cache, &key, &fresh, clock).await {
                    logger::warn!("Failed to persist refreshed SLA score to Object Store: {err}");
                }
            }
            Some(score)
        }
        Err(err) => {
            logger::warn!("CDGC SLA score refresh failed for asset '{}': {err}", config.cdgc_rule_instance_id);
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
    /// without flooding them on every subsequent request. Per-worker (thread-local) state is the
    /// sanctioned way to hold process-wide flags in the single-threaded proxy-wasm model.
    static UNGATED_BYPASS_LOGGED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

async fn request_filter(
    request_state: RequestState,
    config: &Config,
    client: &HttpClient,
    token_cache: &impl DataStorage,
    object_store_scope: Option<&ObjectStoreScope>,
    violations: &PolicyViolations,
    clock: &Clock,
) -> Flow<FreshnessGateData> {
    // Atomically buffer request headers AND body before deciding. Releasing headers to Envoy's
    // router first (the split into_headers_state() -> into_body_state() path) would let it begin
    // proxying the request upstream in parallel while we compute the score -- so a blocked
    // tools/call could still reach and execute on the upstream MCP server. The combined state
    // holds the request in the filter until we decide, so Flow::Break always wins (see #2).
    let state = request_state.into_headers_body_state().await;

    // Fail-open recognition (pdk-mcp / A2A contract): only gate genuine *invocation* traffic on
    // the two protocols this policy governs -- MCP and A2A (Agent2Agent). Anything that is not a
    // POST of application/json -- a GET opening a Streamable-HTTP SSE session, a health probe, a
    // non-JSON content type (including the A2A gRPC transport, which is application/grpc and thus
    // documented pass-through), unparsable JSON, or a batch array -- passes straight through
    // ungated, so the policy never breaks non-MCP/A2A traffic or connection establishment.
    let request_method = state.handler().header(":method").unwrap_or_default();
    if !request_method.eq_ignore_ascii_case("POST") {
        logger::debug!("Non-POST request ('{request_method}'); passing through ungated");
        return Flow::Continue(FreshnessGateData::Evaluated { score: None, status: "skipped" });
    }
    let content_type = state.handler().header("content-type").unwrap_or_default();
    if !content_type.to_ascii_lowercase().contains("application/json") {
        logger::debug!("Non-JSON content-type ('{content_type}'); passing through ungated");
        return Flow::Continue(FreshnessGateData::Evaluated { score: None, status: "skipped" });
    }

    let body = if state.contains_body() { state.handler().body() } else { Vec::new() };

    // Classify the request into (gated protocol, JSON-RPC id) or pass it through. Two recognition
    // paths feed the same score gate:
    //   1. A JSON-RPC 2.0 envelope -- shared by MCP and the A2A JSON-RPC transport. The method
    //      name alone classifies both the protocol and (for A2A) the version (see
    //      `classify_jsonrpc_method`).
    //   2. Otherwise, the A2A HTTP+JSON (REST) message-send binding, recognized from the request
    //      path (its body is a bare SendMessageRequest, not a JSON-RPC envelope).
    // Anything matching neither passes through ungated (fail-open).
    let (protocol, rpc_id) = match parse_jsonrpc_call(&body) {
        Some((method, rpc_id)) => {
            // A notification (a `notifications/*` method, or any call without an `id`) may NEVER
            // receive a response per JSON-RPC 2.0, so it can't be answered with a block.
            if is_notification_method(&method) || rpc_id.is_none() {
                logger::debug!(
                    "Notification-style request '{method}' (no response permitted); passing through ungated"
                );
                return Flow::Continue(FreshnessGateData::Evaluated { score: None, status: "skipped" });
            }
            match classify_jsonrpc_method(&method) {
                RequestClass::Exempt => {
                    logger::info!("Method '{method}' is exempt from freshness gating, passing through");
                    return Flow::Continue(FreshnessGateData::Evaluated { score: None, status: "skipped" });
                }
                RequestClass::Gated(protocol) => (protocol, rpc_id),
            }
        }
        None => {
            let path = state.handler().header(":path").unwrap_or_default();
            if a2a_rest_send_path(&path) {
                logger::info!("Gating A2A HTTP+JSON (REST) message-send binding (path '{path}')");
                (GateProtocol::A2a(A2aBinding::Rest), None)
            } else {
                logger::debug!(
                    "Request is neither a JSON-RPC 2.0 call nor an A2A REST message-send binding; passing through ungated"
                );
                return Flow::Continue(FreshnessGateData::Evaluated { score: None, status: "skipped" });
            }
        }
    };

    let score = resolve_score(client, config, object_store_scope, token_cache, clock).await;

    // Only surface the raw numeric score to the client (via the x-freshness-gate-score header on
    // an allowed response) when explicitly opted in; the coarse status header is always emitted.
    let disclose = config.disclose_score_details.unwrap_or(false);

    match score {
        None => {
            if config.block_on_unknown_score.unwrap_or(false) {
                logger::warn!(
                    "Blocking request: no SLA score available yet for asset '{}'",
                    config.cdgc_rule_instance_id
                );
                violations.generate_policy_violation();
                Flow::Break(build_block_response(protocol, rpc_id, None, config))
            } else {
                // Soft-launch bypass: passing traffic UNGATED. Warn ONCE per worker so the window
                // during which the control is disabled is observable without flooding the logs.
                let first_bypass = UNGATED_BYPASS_LOGGED.with(|logged| !logged.replace(true));
                if first_bypass {
                    logger::warn!(
                        "Freshness Gate BYPASS: passing traffic UNGATED for asset '{}' -- no SLA score is available and blockOnUnknownScore=false, so the freshness control is currently disabled for this asset. (Warned once per worker.)",
                        config.cdgc_rule_instance_id
                    );
                }
                logger::debug!(
                    "No SLA score available yet for asset '{}'; passing through per blockOnUnknownScore=false",
                    config.cdgc_rule_instance_id
                );
                Flow::Continue(FreshnessGateData::Evaluated { score: None, status: "unknown" })
            }
        }
        Some(score) if score < config.block_threshold => {
            logger::warn!(
                "Blocking request: asset '{}' SLA score {score:.2} below blockThreshold {:.2}",
                config.cdgc_rule_instance_id,
                config.block_threshold
            );
            violations.generate_policy_violation();
            Flow::Break(build_block_response(protocol, rpc_id, Some(score), config))
        }
        Some(score) if score < config.warn_threshold => {
            logger::warn!(
                "Warning: asset '{}' SLA score {score:.2} below warnThreshold {:.2}",
                config.cdgc_rule_instance_id,
                config.warn_threshold
            );
            Flow::Continue(FreshnessGateData::Evaluated { score: disclose.then_some(score), status: "warn" })
        }
        Some(score) => Flow::Continue(FreshnessGateData::Evaluated { score: disclose.then_some(score), status: "ok" }),
    }
}

async fn response_filter(response_state: ResponseState, request_data: RequestData<FreshnessGateData>) {
    // Complete at header state and do NOT transition to body state. This filter only annotates
    // two diagnostic response headers; it never needs the body. Forcing into_body_state() would
    // buffer the entire response before releasing it downstream, which stalls MCP Streamable-HTTP
    // (text/event-stream) responses. Header-only completion is valid in PDK response filters and
    // passes the body through untouched as a stream.
    let headers_state = response_state.into_headers_state().await;

    if let RequestData::Continue(FreshnessGateData::Evaluated { score, status }) = request_data {
        if let Some(score) = score {
            headers_state.handler().set_header(HEADER_SLA_SCORE, &format!("{score:.2}"));
        }
        headers_state.handler().set_header(HEADER_SLA_STATUS, status);
    }
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    client: HttpClient,
    storage_builder: DataStorageBuilder,
    metadata: Metadata,
    violations: PolicyViolations,
    clock: Clock,
) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Failed to parse configuration '{}'. Cause: {}",
            String::from_utf8_lossy(&bytes),
            err
        )
    })?;

    let token_cache = storage_builder.local(OAUTH_TOKEN_CACHE_NAMESPACE);
    let object_store_scope = object_store_scope(&metadata);

    let filter = on_request(|rs| {
        request_filter(rs, &config, &client, &token_cache, object_store_scope.as_ref(), &violations, &clock)
    })
    .on_response(response_filter);

    launcher.launch(filter).await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::rc::Rc;

    use pdk_unit::{TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder};
    use serde_json::json;

    fn config() -> String {
        json!({
            "cdgcLoginUrl": "http://cdgclogin",
            "cdgcBaseApiUrl": "http://cdgcapi",
            "cdgcOrgUsername": "test-user",
            "cdgcOrgPassword": "test-pass",
            "cdgcRuleInstanceId": "asset-1",
            "warnThreshold": 90,
            "blockThreshold": 80,
            "refreshIntervalSeconds": 3600,
            "objectStoreAuthUrl": "http://objectstoreauth",
            "objectStoreUrl": "http://objectstore",
            "objectStoreClientId": "test-client-id",
            "objectStoreClientSecret": "test-client-secret",
            "objectStoreName": "test-store",
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

    /// An A2A JSON-RPC request for `method` (e.g. "message/send" for v0.3, "SendMessage" for
    /// v1.0), mirroring `mcp_request_with_method`. The A2A JSON-RPC transport shares MCP's
    /// envelope; only the method vocabulary differs.
    fn a2a_request(id: i64, method: &str) -> UnitHttpRequest {
        UnitHttpRequest::post()
            .with_path("/a2a")
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": id, "method": method }).to_string())
    }

    /// An A2A HTTP+JSON (REST) message-send request: a bare `SendMessageRequest` body (NOT a
    /// JSON-RPC envelope) at the versioned action `path`.
    fn a2a_rest_send(path: &str) -> UnitHttpRequest {
        UnitHttpRequest::post()
            .with_path(path)
            .with_header("content-type", "application/json")
            .with_body(json!({ "message": { "role": "user", "parts": [] } }).to_string())
    }

    /// Builds the raw Object Store envelope bytes for a key, matching what `object_store_put`
    /// would have written, so tests can pre-seed the store's state directly.
    fn envelope_bytes(key: &str, string_value: String) -> Vec<u8> {
        serde_json::to_vec(&super::ObjectStoreEnvelope {
            string_value,
            key_id: key.to_string(),
            value_type: "STRING".to_string(),
        })
        .unwrap()
    }

    fn oauth_backend(_req: UnitHttpRequest) -> UnitHttpResponse {
        UnitHttpResponse::new(200)
            .with_body(json!({ "access_token": "test-token", "expires_in": 3600 }).to_string())
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
                json!({
                    "selfAttributes": {
                        "com.infa.ccgf.models.governance.value": score
                    }
                })
                .to_string(),
            )
        }
    }

    /// Stateful Object Store mock, mirroring the real Object Store V2 REST contract this policy
    /// assumes: `PUT .../keys/{id}` stores the envelope body under `id`, `GET` returns it back
    /// (or 404 if never stored).
    fn object_store_backend(
        store: Rc<RefCell<std::collections::HashMap<String, Vec<u8>>>>,
    ) -> impl Fn(UnitHttpRequest) -> UnitHttpResponse {
        move |req: UnitHttpRequest| {
            let path = req.header(":path").unwrap_or_default();
            let key = path.split('?').next().unwrap_or_default().rsplit('/').next().unwrap_or_default().to_string();

            match req.header(":method") {
                Some("GET") => match store.borrow().get(&key) {
                    Some(value) => UnitHttpResponse::new(200).with_body(value.clone()),
                    None => UnitHttpResponse::new(404),
                },
                Some("PUT") => {
                    store.borrow_mut().insert(key, req.body().to_vec());
                    UnitHttpResponse::new(200)
                }
                _ => UnitHttpResponse::new(404),
            }
        }
    }

    #[test]
    fn healthy_score_passes_through_and_tags_the_response() {
        let store = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(97.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-freshness-gate-status"), Some("ok"));
        // The raw score is NOT disclosed to the client by default (discloseScoreDetails=false).
        assert_eq!(response.header("x-freshness-gate-score"), None);
        assert!(backend.next().is_some());
        assert!(!store.borrow().is_empty());
        assert!(response.violation().is_none(), "an allowed request must not emit a violation");
    }

    #[test]
    fn disclose_true_emits_score_header_on_allowed_response() {
        let store = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "discloseScoreDetails": true })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(97.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        assert_eq!(response.header("x-freshness-gate-status"), Some("ok"));
        assert_eq!(response.header("x-freshness-gate-score"), Some("97.00"));
    }

    #[test]
    fn stale_score_below_block_threshold_rejects_with_jsonrpc_error_and_never_calls_backend() {
        let store = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(60.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(42));

        assert_eq!(response.status_code(), 200);
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 42);
        assert_eq!(body["error"]["code"], -32008);
        let msg = body["error"]["message"].as_str().unwrap();
        // Default (discloseScoreDetails=false): generic message, nothing leaked to the client.
        assert!(msg.contains("did not meet the required standard"), "got: {msg}");
        assert!(!msg.contains("blockThreshold"), "must not leak threshold: {msg}");
        assert!(!msg.contains("asset-1"), "must not leak asset id: {msg}");
        assert_eq!(response.header("x-freshness-gate-score"), None);
        // The MCP server backend must never be invoked for a blocked request.
        assert!(backend.next().is_none());
        assert!(response.violation().is_some(), "a below-threshold block must emit a PolicyViolation");
    }

    #[test]
    fn disclose_true_block_message_includes_score_and_threshold() {
        let store = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "discloseScoreDetails": true })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(60.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(42));

        assert_eq!(response.header("x-freshness-gate-score"), Some("60.00"));
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        let msg = body["error"]["message"].as_str().unwrap();
        assert!(msg.contains("60.00"), "got: {msg}");
        assert!(msg.contains("80.00"), "got: {msg}");
        assert!(msg.contains("asset-1"), "got: {msg}");
    }

    #[test]
    fn exempt_handshake_methods_pass_through_even_below_block_threshold() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        // No CDGC score upstream registered at all: if the exemption ever fell through to
        // resolve_score, fetch_cdgc_score would fail with no score available, and
        // blockOnUnknownScore defaults false so it would (incorrectly) still pass -- so this test
        // asserts on login_calls staying at zero, proving resolve_score was never even attempted.
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_entrypoint(super::configure);

        for method in ["initialize", "tools/list", "notifications/initialized", "ping", "logging/setLevel"] {
            let response = tester.request(mcp_request_with_method(1, method));
            assert_eq!(response.status_code(), 200, "method {method} should pass through");
            assert_eq!(response.header("x-freshness-gate-status"), Some("skipped"));
        }

        assert!(backend.next().is_some());
        assert_eq!(*login_calls.borrow(), 0);
    }

    #[test]
    fn non_post_and_non_json_requests_pass_through_ungated() {
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_entrypoint(super::configure);

        let get_response = tester.request(
            UnitHttpRequest::get().with_path("/mcp").with_header("content-type", "application/json"),
        );
        assert_eq!(get_response.header("x-freshness-gate-status"), Some("skipped"));

        let non_json_response = tester.request(
            UnitHttpRequest::post()
                .with_path("/mcp")
                .with_header("content-type", "application/grpc")
                .with_body(b"binary".to_vec()),
        );
        assert_eq!(non_json_response.header("x-freshness-gate-status"), Some("skipped"));
    }

    #[test]
    fn score_below_warn_threshold_passes_through_with_a_warning() {
        let store = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(85.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(2));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-freshness-gate-status"), Some("warn"));
        assert!(backend.next().is_some());
    }

    #[test]
    fn cached_score_within_ttl_skips_cdgc_entirely() {
        let store = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(97.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let first = tester.request(mcp_request(1));
        assert_eq!(first.status_code(), 200);
        assert_eq!(*login_calls.borrow(), 1);

        // Second request, well within the refreshIntervalSeconds window: must reuse the cached
        // score from Object Store rather than re-authenticating to CDGC.
        let second = tester.request(mcp_request(2));
        assert_eq!(second.status_code(), 200);
        assert_eq!(second.header("x-freshness-gate-status"), Some("ok"));
        assert_eq!(*login_calls.borrow(), 1);
    }

    #[test]
    fn no_score_and_block_on_unknown_true_rejects() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        // No Object Store upstream registered at all -> object_store_scope resolution still
        // works (metadata-derived), but every Object Store call fails, and CDGC login itself
        // also has no registered upstream, so fetch_cdgc_score fails too: no score is ever
        // available. blockOnUnknownScore=true must reject rather than pass through.
        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "blockOnUnknownScore": true })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(7));

        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"]["code"], -32008);
        assert!(backend.next().is_none());
        assert!(response.violation().is_some(), "unknown-score block must emit a PolicyViolation");
    }

    #[test]
    fn no_score_and_block_on_unknown_false_bypasses_ungated_on_every_request() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        // With no score ever available (same setup as the block_on_unknown_score=true test) and
        // blockOnUnknownScore=false, EVERY request passes ungated (status "unknown"), but the
        // UNGATED_BYPASS_LOGGED warn-once guard fires the log only the first time on this worker.
        // Two requests on the same tester exercise both arms of that guard: the second must still
        // pass through even though the flag is already set -- if the guard regressed into gating
        // the second request, or blocking it, this test fails.
        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "blockOnUnknownScore": false })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_entrypoint(super::configure);

        let first = tester.request(mcp_request(1));
        assert_eq!(first.status_code(), 200);
        assert_eq!(first.header("x-freshness-gate-status"), Some("unknown"));

        let second = tester.request(mcp_request(2));
        assert_eq!(second.status_code(), 200);
        assert_eq!(second.header("x-freshness-gate-status"), Some("unknown"));
    }

    #[test]
    fn refresh_lock_held_elsewhere_skips_cdgc_and_serves_stale_cached_score() {
        let store = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        // Simulate a stampede scenario: the cached score is long stale, but another concurrent
        // request already acquired the refresh lock (acquired_at far in the future relative to
        // "now", so it reads as comfortably within REFRESH_LOCK_TTL_SECONDS regardless of wall
        // clock). This request must not itself call CDGC -- it should just serve the stale value.
        let stale = super::CachedScore { score: 97.0, timestamp: 0 };
        store.borrow_mut().insert(
            "freshness-score-asset-1".to_string(),
            envelope_bytes("freshness-score-asset-1", serde_json::to_string(&stale).unwrap()),
        );
        store.borrow_mut().insert(
            "freshness-refresh-lock-asset-1".to_string(),
            envelope_bytes("freshness-refresh-lock-asset-1", "9999999999".to_string()),
        );

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "discloseScoreDetails": true })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(10.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(3));

        assert_eq!(*login_calls.borrow(), 0, "lock held elsewhere must prevent a CDGC refresh");
        assert_eq!(response.header("x-freshness-gate-status"), Some("ok"));
        assert_eq!(response.header("x-freshness-gate-score"), Some("97.00"));
        assert!(backend.next().is_some());
    }

    #[test]
    fn a2a_v1_send_below_block_threshold_blocks_in_band_200_with_error_info() {
        let store = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(60.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let response = tester.request(a2a_request(7, "SendMessage"));

        // In-band at HTTP 200, per the JSON-RPC transport convention shared with MCP.
        assert_eq!(response.status_code(), 200);
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"]["code"], -32010);
        let info = &body["error"]["data"][0];
        assert_eq!(info["reason"], "FRESHNESS_SCORE_BELOW_THRESHOLD");
        assert_eq!(info["domain"], "freshness-gate.mulesoft.com");
        // disclose=false by default: metadata must not leak score/threshold/asset id.
        assert_eq!(info["metadata"], json!({}));
        assert!(backend.next().is_none());
        assert!(response.violation().is_some());
    }

    #[test]
    fn a2a_v03_send_below_block_threshold_blocks_in_band_200_free_form() {
        let store = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(60.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let response = tester.request(a2a_request(11, "message/send"));

        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"]["code"], -32010);
        // v0.3 error.data is free-form and OMITTED entirely when discloseScoreDetails=false.
        assert!(body["error"].get("data").is_none());
    }

    #[test]
    fn a2a_send_healthy_score_passes_through_and_tags_response() {
        let store = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(95.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let response = tester.request(a2a_request(1, "SendMessage"));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-freshness-gate-status"), Some("ok"));
        assert!(backend.next().is_some());
    }

    #[test]
    fn a2a_housekeeping_methods_pass_through_ungated() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_entrypoint(super::configure);

        for method in ["GetTask", "ListTasks", "GetAgentCard", "tasks/get", "agent/card"] {
            let response = tester.request(a2a_request(1, method));
            assert_eq!(response.header("x-freshness-gate-status"), Some("skipped"), "method {method}");
        }
        assert_eq!(*login_calls.borrow(), 0);
    }

    #[test]
    fn a2a_rest_send_binding_below_block_threshold_uses_google_rpc_status_403() {
        let store = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(60.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let response = tester.request(a2a_rest_send("/v1/message:send"));

        // Native HTTP 403, NOT a JSON-RPC envelope (pdk-a2a Shape 3).
        assert_eq!(response.status_code(), 403);
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"]["code"], 403);
        assert_eq!(body["error"]["details"][0]["reason"], "FRESHNESS_SCORE_BELOW_THRESHOLD");
        assert!(backend.next().is_none());
    }

    #[test]
    fn classify_jsonrpc_method_disjoint_vocabularies() {
        use super::{A2aBinding, A2aVersion, GateProtocol, RequestClass};

        assert_eq!(super::classify_jsonrpc_method("tools/call"), RequestClass::Gated(GateProtocol::Mcp));
        assert_eq!(super::classify_jsonrpc_method("initialize"), RequestClass::Exempt);
        assert_eq!(
            super::classify_jsonrpc_method("message/send"),
            RequestClass::Gated(GateProtocol::A2a(A2aBinding::JsonRpc(A2aVersion::V0_3)))
        );
        assert_eq!(
            super::classify_jsonrpc_method("SendMessage"),
            RequestClass::Gated(GateProtocol::A2a(A2aBinding::JsonRpc(A2aVersion::V1_0)))
        );
        assert_eq!(super::classify_jsonrpc_method("GetTask"), RequestClass::Exempt);
    }

    #[test]
    fn a2a_rest_send_path_matches_only_send_bindings() {
        assert!(super::a2a_rest_send_path("/v1/message:send"));
        assert!(super::a2a_rest_send_path("/message:send"));
        assert!(super::a2a_rest_send_path("/acme/message:send"));
        assert!(super::a2a_rest_send_path("/message:sendStream"));
        assert!(super::a2a_rest_send_path("/message:send?foo=bar"));
        assert!(!super::a2a_rest_send_path("/v1/tasks/get"));
        assert!(!super::a2a_rest_send_path("/message:cancel"));
    }

    #[test]
    fn a2a_block_error_code_is_outside_a2a_reserved_range() {
        // A2A currently assigns -32001..=-32009; the block code must sit strictly outside that
        // range, on the more-negative side (the next free slot going further from zero).
        assert!(super::A2A_BLOCK_ERROR_CODE < -32009);
        assert_ne!(super::A2A_BLOCK_ERROR_CODE, super::JSONRPC_BLOCK_ERROR_CODE);
    }

    #[test]
    fn percent_encode_escapes_reserved_url_characters() {
        assert_eq!(super::percent_encode("asset-1"), "asset-1");
        assert_eq!(super::percent_encode("a/b?c=d"), "a%2Fb%3Fc%3Dd");
    }

    #[test]
    fn elapsed_ms_is_monotonic_and_floors_at_zero() {
        use std::time::{Duration, SystemTime};

        let start = SystemTime::UNIX_EPOCH;
        let later = start + Duration::from_millis(1_500);
        assert_eq!(super::elapsed_ms(start, later), 1_500);
        // A clock that appears to go backwards must never yield a negative elapsed.
        assert_eq!(super::elapsed_ms(later, start), 0);
        assert_eq!(super::elapsed_ms(start, start), 0);
    }

    #[test]
    fn next_call_timeout_clamps_per_call_to_remaining_budget() {
        use std::time::Duration;

        let budget = super::CDGC_REFRESH_BUDGET_MS; // 10_000

        // Fresh start: the per-call value is smaller than the remaining budget, so it wins.
        assert_eq!(super::next_call_timeout(2_000, 0), Some(Duration::from_millis(2_000)));

        // Late in the chain: only the remaining budget is granted, below the per-call ceiling
        // (the configured default of 60_000ms is far larger than what's left of the budget).
        assert_eq!(
            super::next_call_timeout(super::DEFAULT_TIMEOUT_MS, budget - 500),
            Some(Duration::from_millis(500))
        );
    }

    #[test]
    fn next_call_timeout_aborts_when_budget_exhausted() {
        let budget = super::CDGC_REFRESH_BUDGET_MS;
        // Exactly at the budget: nothing left, abort the refresh.
        assert_eq!(super::next_call_timeout(super::DEFAULT_TIMEOUT_MS, budget), None);
        // Past the budget: also abort (no unbounded blocking).
        assert_eq!(super::next_call_timeout(super::DEFAULT_TIMEOUT_MS, budget + 5_000), None);
    }
}
