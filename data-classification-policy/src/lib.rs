// Copyright 2026 Salesforce, Inc. All rights reserved.
mod generated;

use std::collections::{HashMap, HashSet};
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

/// Namespaces for the two PDK-native [`DataStorage`] instances this policy uses -- mirrors
/// dq-gate-policy's cache/lock split (different lifetimes, different remote-namespace TTLs).
const RANK_CACHE_NAMESPACE: &str = "classification-gate-rank";
const REFRESH_LOCK_NAMESPACE: &str = "classification-gate-refresh-lock";

const RANK_CACHE_KEY_PREFIX: &str = "classification-rank-";
const REFRESH_LOCK_KEY_PREFIX: &str = "classification-refresh-lock-";
const REFRESH_LOCK_TTL_SECONDS: i64 = 30;
const REFRESH_LOCK_TTL_MS: u32 = (REFRESH_LOCK_TTL_SECONDS as u32) * 1000;
/// See dq-gate-policy's identical constant: deliberately long-lived so a last-known-good rank
/// outlives `refreshIntervalSeconds` and remains available for fail-open serving.
const RANK_STORE_MIN_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000; // 30 days
const CAS_MAX_RETRIES: u32 = 3;

/// Per-call timeout (ms) for a single CDGC HTTP request (Login, JWT, or a details batch). A
/// cache-miss/refresh request performs Login + JWT + N hop-1 batches + M hop-2 batches *inline*
/// on the agent's request hot path -- see [`CDGC_REFRESH_BUDGET_MS`].
const DEFAULT_TIMEOUT_MS: i64 = 5_000;
/// Overall hot-path latency cap (ms) for the entire inline CDGC refresh chain on one cache-miss
/// request, mirroring dq-gate-policy's identical budget and rationale (inline refresh, no
/// background scheduler). Every chained call -- Login, JWT, and each details batch -- is clamped
/// to the budget still remaining via [`next_call_timeout`], so the sum can never exceed this cap.
const CDGC_REFRESH_BUDGET_MS: i64 = 10_000;
const DEFAULT_REFRESH_INTERVAL_SECONDS: i64 = 86_400;

/// CDGC's `data360/search/v1/assets/details` batch endpoint caps at 5 ids per call (confirmed
/// live: a 6th id gets HTTP 400 "the ids list is empty, or exceeds the length limit of 5 ids").
/// A route with N governed columns needs `ceil(N/5)` calls for the column->classification hop,
/// then `ceil(D/5)` for D *distinct* classification ids found across those columns.
const CDGC_BATCH_CHUNK_SIZE: usize = 5;

/// JSON-RPC error code for an **MCP** block. Distinct from dq-gate-policy's `-32008` and
/// freshness-gate-policy's own MCP code, so a client keying off the code alone can still tell
/// which gate fired -- see the monorepo root CLAUDE.md's rationale for why these three policies
/// each own a disjoint code rather than sharing one.
const JSONRPC_BLOCK_ERROR_CODE: i64 = -32011;
/// JSON-RPC error code for an **A2A JSON-RPC** block. Must differ from both this policy's own MCP
/// code above AND dq-gate-policy's A2A code (`-32010`) -- A2A has so far assigned
/// `-32001..=-32009` to its own errors (per the A2A spec at tags v0.3.0/v1.0.0), so `-32012` sits
/// above every code currently in use by any gate in this family and can never collide.
const A2A_BLOCK_ERROR_CODE: i64 = -32012;
/// The A2A HTTP+JSON (REST) binding block returns this native HTTP status, carrying a
/// `google.rpc.Status` body -- mirrors dq-gate-policy's identical convention (Shape 3).
const A2A_REST_BLOCK_HTTP_STATUS: u32 = 403;
const A2A_ERROR_REASON: &str = "CLASSIFICATION_ABOVE_ALLOWED";
/// Deliberately NOT `a2a-protocol.org` -- that domain identifies errors defined by the A2A
/// protocol itself; this is a policy-owned domain identifying which gate produced the error.
const A2A_ERROR_DOMAIN: &str = "data-classification-gate.mulesoft.com";
const HEADER_CLASSIFICATION_RANK: &str = "x-classification-gate-rank";
const HEADER_CLASSIFICATION_STATUS: &str = "x-classification-gate-status";
const HEADER_CLASSIFICATION_COLUMNS: &str = "x-classification-gate-columns";

/// MCP handshake, discovery, and administrative methods that must always pass through ungated --
/// identical trigger surface to dq-gate-policy (see its src/lib.rs for the full rationale): a
/// client establishing/enumerating a connection must never be blocked, and control/helper calls
/// touch no governed asset data so gating them on a classification tier would be semantically
/// wrong. Gating is reserved for the content-bearing methods that actually read governed column
/// data: `tools/call`, `resources/read`, `prompts/get`.
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

// ── A2A (Agent2Agent) method vocabulary -- identical to dq-gate-policy's, see its src/lib.rs ──

const A2A_V03_SEND: &str = "message/send";
const A2A_V03_STREAM: &str = "message/stream";
const A2A_V1_SEND: &str = "SendMessage";
const A2A_V1_STREAM: &str = "SendStreamingMessage";

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

/// A single governed column's resolved name and rank, kept alongside the aggregate [`CachedRank`]
/// so a block message can name the offending column(s) even when served from cache (the common
/// path). `name` is the CDGC `summary.core.name` for the column, falling back to the column id
/// when CDGC omits it. `rank` follows [`rank_of`]: 0 = unclassified.
#[derive(Serialize, Deserialize, Clone)]
struct ColumnRank {
    name: String,
    rank: u8,
}

/// The cached worst-case rank across all of `governedColumnIds`, and when it was fetched --
/// compared against `refreshIntervalSeconds` on every request to decide whether a live CDGC
/// fetch is needed. `rank` follows [`rank_of`]: 0 = unclassified/no governed columns carry a
/// classification, 1 = LOW, 2 = MEDIUM, 3 = HIGH. `columns` is `#[serde(default)]` so a cache
/// entry written before this field existed still deserializes (as an empty list, falling back to
/// the tier-only message).
#[derive(Serialize, Deserialize, Clone)]
struct CachedRank {
    rank: u8,
    timestamp: i64,
    #[serde(default)]
    columns: Vec<ColumnRank>,
}

/// Result of a live CDGC fetch: the aggregate worst-case rank plus each governed column's own
/// resolved name/rank, ready to be wrapped into a [`CachedRank`] for storage.
struct RankOutcome {
    rank: u8,
    columns: Vec<ColumnRank>,
}

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

/// One element of a column's `dataClassification` segment -- a linked classification's identity.
/// Only `core.identity` is needed; the sensitivity itself lives on the classification asset,
/// fetched in the second hop (see [`ClassificationSensitivity`]).
#[derive(Deserialize)]
struct ClassificationRef {
    #[serde(rename = "core.identity")]
    core_identity: String,
}

/// A column asset's own `summary` segment -- just its human-readable `core.name` (e.g.
/// "VISIT_REASON"), fetched in the same hop-1 batch as `dataClassification` via
/// `segments=summary,dataClassification` (verified live: no extra CDGC call needed).
#[derive(Deserialize, Default)]
struct Summary {
    #[serde(rename = "core.name")]
    name: Option<String>,
}

/// A column asset's `dataClassification` segment, as returned by the batched
/// `data360/search/v1/assets/details` read (`segments=summary,dataClassification`). `core_identity`
/// is `None` only when CDGC could not resolve the requested id at all (an empty `{}` body for a
/// single read; simply absent from the batch array) -- that is a config-resolution error, never
/// "unclassified". A column WITH `core_identity` but no `dataClassification` key is genuinely
/// unclassified: the field defaults to empty via `#[serde(default)]`, since CDGC omits the key
/// entirely rather than returning an empty array for an unclassified column (confirmed live).
#[derive(Deserialize, Default)]
struct AssetClassificationSegment {
    #[serde(rename = "core.identity")]
    core_identity: Option<String>,
    #[serde(rename = "summary", default)]
    summary: Summary,
    #[serde(rename = "dataClassification", default)]
    data_classification: Vec<ClassificationRef>,
}

#[derive(Deserialize, Default)]
struct SelfAttributes {
    #[serde(rename = "core.sensitivity")]
    sensitivity: Option<String>,
}

/// A classification asset's sensitivity, as returned by the batched details read
/// (`segments=summary,selfAttributes`). Same config-resolution-error convention as
/// [`AssetClassificationSegment`]: `core_identity: None` means CDGC could not resolve the id.
#[derive(Deserialize, Default)]
struct ClassificationSensitivity {
    #[serde(rename = "core.identity")]
    core_identity: Option<String>,
    #[serde(rename = "selfAttributes", default)]
    self_attributes: SelfAttributes,
}

/// Data threaded from the request filter to the response filter, used only to annotate the
/// (allowed) response with diagnostic headers -- never consulted for the block decision.
enum ClassificationGateData {
    Evaluated { rank: Option<u8>, status: &'static str },
}

// ── Shared timing/encoding helpers -- identical to dq-gate-policy's, protocol/score agnostic ──

fn elapsed_ms(start: SystemTime, now: SystemTime) -> i64 {
    now.duration_since(start)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

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

fn nonce_from_time(now: SystemTime) -> String {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

// ── Classification-specific helpers ─────────────────────────────────────────────────────────

/// Parses `governedColumnIds` (comma-separated) into a deduped, order-preserving list of column
/// asset ids. GCL config schemas in this policy family only support scalar property types (see
/// dq-gate-policy's and freshness-gate-policy's `gcl.yaml`, both scalars-only), so a real list is
/// represented as a delimited string rather than a native array -- parsed here, once, per request.
fn parse_governed_column_ids(config: &Config) -> Vec<String> {
    let mut seen = HashSet::new();
    config
        .governed_column_ids
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .filter(|id| seen.insert(id.to_string()))
        .map(str::to_string)
        .collect()
}

/// Maps a CDGC `core.sensitivity` value to its ordinal rank. The three values below are the only
/// ones this org's CDGC schema currently defines (verified live) -- deliberately no speculative
/// higher tier (e.g. a `RESTRICTED_PHI`), since inventing one would silently misrank a real value
/// this policy has never actually observed. An unrecognized string is `None`, not a default rank:
/// the caller treats it as a data-integrity error (fail-closed), not as "harmless/unclassified".
fn rank_of(sensitivity: &str) -> Option<u8> {
    match sensitivity {
        "LOW" => Some(1),
        "MEDIUM" => Some(2),
        "HIGH" => Some(3),
        _ => None,
    }
}

/// Inverse of [`rank_of`], for disclosure headers and messages. `0` denotes "unclassified" -- a
/// rank that never comes from `rank_of` itself, only from a column carrying no classification.
fn rank_label(rank: u8) -> &'static str {
    match rank {
        1 => "LOW",
        2 => "MEDIUM",
        3 => "HIGH",
        _ => "UNCLASSIFIED",
    }
}

/// Canonical form of `governedColumnIds` for cache/lock keys: the parsed ids, sorted and
/// comma-joined. Keying off the raw string would give `"a,b"`, `"b,a"`, and `"a, b"` -- the same
/// governed set -- separate cache entries and refresh locks, each paying its own CDGC fetch.
fn governed_columns_key(config: &Config) -> String {
    let mut ids = parse_governed_column_ids(config);
    ids.sort();
    ids.join(",")
}

fn rank_cache_key(config: &Config) -> String {
    format!("{RANK_CACHE_KEY_PREFIX}{}", governed_columns_key(config))
}

fn refresh_lock_key(config: &Config) -> String {
    format!("{REFRESH_LOCK_KEY_PREFIX}{}", governed_columns_key(config))
}

fn rank_store_ttl_ms(config: &Config) -> u32 {
    let refresh_secs = config
        .refresh_interval_seconds
        .unwrap_or(DEFAULT_REFRESH_INTERVAL_SECONDS)
        .max(0) as u64;
    let derived_ms = refresh_secs.saturating_mul(2).saturating_mul(1000);
    derived_ms.max(RANK_STORE_MIN_TTL_MS).min(u32::MAX as u64) as u32
}

// ── MCP/A2A recognition -- identical to dq-gate-policy's, see its src/lib.rs for full rationale ──

fn is_notification_method(method: &str) -> bool {
    method.starts_with("notifications/")
}

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum A2aVersion {
    V0_3,
    V1_0,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum A2aBinding {
    JsonRpc(A2aVersion),
    Rest,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum GateProtocol {
    Mcp,
    A2a(A2aBinding),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RequestClass {
    Gated(GateProtocol),
    Exempt,
}

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

fn a2a_rest_send_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    let last_segment = path.rsplit('/').next().unwrap_or(path);
    matches!(
        last_segment,
        "message:send" | "message:stream" | "message:sendStream"
    )
}

// ── Block-response shaping ───────────────────────────────────────────────────────────────────

/// The human-readable block message. `discloseClassificationDetails` (default false) controls
/// whether internal governance state -- the worst-case tier, the configured ceiling, and the
/// offending column name(s) -- is revealed to the client; the full detail is always recorded
/// server-side by the `warn!` in `request_filter` regardless. `offending` (columns whose rank
/// exceeds the ceiling) is only ever non-empty on the disclose path.
fn block_message(disclose: bool, rank: Option<u8>, offending: &[ColumnRank], config: &Config) -> String {
    if disclose {
        match rank {
            Some(rank) => {
                let mut message = format!(
                    "Blocked by Data Classification Gate: worst-case classification tier {} exceeds maxAllowedClassification {}",
                    rank_label(rank), config.max_allowed_classification
                );
                if !offending.is_empty() {
                    let columns = offending
                        .iter()
                        .map(|c| format!("{} [{}]", c.name, rank_label(c.rank)))
                        .collect::<Vec<_>>()
                        .join(", ");
                    message.push_str(&format!(" (columns: {columns})"));
                }
                message
            }
            None => "Blocked by Data Classification Gate: no classification result is available yet for the governed columns".to_string(),
        }
    } else {
        "Blocked by Data Classification Gate: the requested data includes a classification tier that exceeds this route's allowed maximum"
            .to_string()
    }
}

fn block_headers(disclose: bool, rank: Option<u8>, offending: &[ColumnRank]) -> Vec<(String, String)> {
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    if disclose {
        if let Some(rank) = rank {
            headers.push((HEADER_CLASSIFICATION_RANK.to_string(), rank_label(rank).to_string()));
        }
        if !offending.is_empty() {
            let columns = offending.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(",");
            headers.push((HEADER_CLASSIFICATION_COLUMNS.to_string(), columns));
        }
    }
    headers.push((HEADER_CLASSIFICATION_STATUS.to_string(), "blocked".to_string()));
    headers
}

fn build_block_response(
    protocol: GateProtocol,
    rpc_id: Option<Value>,
    rank: Option<u8>,
    offending: &[ColumnRank],
    config: &Config,
) -> Response {
    match protocol {
        GateProtocol::Mcp => block_response(rpc_id, rank, offending, config),
        GateProtocol::A2a(A2aBinding::JsonRpc(version)) => {
            a2a_jsonrpc_block_response(version, rpc_id, rank, offending, config)
        }
        GateProtocol::A2a(A2aBinding::Rest) => a2a_rest_block_response(rank, offending, config),
    }
}

fn block_response(rpc_id: Option<Value>, rank: Option<u8>, offending: &[ColumnRank], config: &Config) -> Response {
    let disclose = config.disclose_classification_details.unwrap_or(false);
    let message = block_message(disclose, rank, offending, config);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": rpc_id.unwrap_or(Value::Null),
        "error": { "code": JSONRPC_BLOCK_ERROR_CODE, "message": message },
    });

    Response::new(200)
        .with_headers(block_headers(disclose, rank, offending))
        .with_body(serde_json::to_vec(&body).unwrap_or_default())
}

fn a2a_error_info(disclose: bool, rank: Option<u8>, offending: &[ColumnRank], config: &Config) -> Value {
    let mut metadata = serde_json::Map::new();
    if disclose {
        if let Some(rank) = rank {
            metadata.insert("tier".to_string(), Value::String(rank_label(rank).to_string()));
        }
        metadata.insert(
            "maxAllowedClassification".to_string(),
            Value::String(config.max_allowed_classification.clone()),
        );
        if !offending.is_empty() {
            let columns: Vec<Value> = offending.iter().map(|c| Value::String(c.name.clone())).collect();
            metadata.insert("columns".to_string(), Value::Array(columns));
        }
    }
    serde_json::json!({
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": A2A_ERROR_REASON,
        "domain": A2A_ERROR_DOMAIN,
        "metadata": Value::Object(metadata),
    })
}

fn a2a_jsonrpc_block_response(
    version: A2aVersion,
    rpc_id: Option<Value>,
    rank: Option<u8>,
    offending: &[ColumnRank],
    config: &Config,
) -> Response {
    let disclose = config.disclose_classification_details.unwrap_or(false);
    let message = block_message(disclose, rank, offending, config);

    let mut error = serde_json::Map::new();
    error.insert("code".to_string(), serde_json::json!(A2A_BLOCK_ERROR_CODE));
    error.insert("message".to_string(), Value::String(message));

    let data = match version {
        A2aVersion::V1_0 => Some(serde_json::json!([a2a_error_info(disclose, rank, offending, config)])),
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

    Response::new(200)
        .with_headers(block_headers(disclose, rank, offending))
        .with_body(serde_json::to_vec(&body).unwrap_or_default())
}

fn a2a_rest_block_response(rank: Option<u8>, offending: &[ColumnRank], config: &Config) -> Response {
    let disclose = config.disclose_classification_details.unwrap_or(false);
    let message = block_message(disclose, rank, offending, config);

    let body = serde_json::json!({
        "error": {
            "code": A2A_REST_BLOCK_HTTP_STATUS,
            "message": message,
            "details": [a2a_error_info(disclose, rank, offending, config)],
        }
    });

    Response::new(A2A_REST_BLOCK_HTTP_STATUS)
        .with_headers(block_headers(disclose, rank, offending))
        .with_body(serde_json::to_vec(&body).unwrap_or_default())
}

// ── Cache/lock plumbing -- identical structure to dq-gate-policy's, see its src/lib.rs ────────

async fn read_cached_rank<S: DataStorage>(store: &S, key: &str) -> Option<CachedRank> {
    match store.get::<CachedRank>(key).await {
        Ok(Some((cached, _version))) => Some(cached),
        Ok(None) => None,
        Err(err) => {
            logger::warn!("Failed to read cached classification rank from data storage: {err}");
            None
        }
    }
}

async fn write_cached_rank<S: DataStorage>(store: &S, key: &str, cached: &CachedRank) {
    for _ in 0..CAS_MAX_RETRIES {
        match store.get::<CachedRank>(key).await {
            Ok(Some((_, version))) => match store.store(key, &StoreMode::Cas(version), cached).await {
                Ok(()) => return,
                Err(DataStorageError::CasMismatch) => continue,
                Err(err) => {
                    logger::warn!("Failed to persist refreshed classification rank: {err}");
                    return;
                }
            },
            Ok(None) => match store.store(key, &StoreMode::Absent, cached).await {
                Ok(()) => return,
                Err(DataStorageError::CasMismatch) => continue,
                Err(err) => {
                    logger::warn!("Failed to persist refreshed classification rank: {err}");
                    return;
                }
            },
            Err(err) => {
                logger::warn!("Failed to read classification rank before persisting refresh: {err}");
                return;
            }
        }
    }
    logger::warn!("Exhausted CAS retries persisting refreshed classification rank for key '{key}'");
}

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
                    match lock_store.store(key, &StoreMode::Cas(version), &entry).await {
                        Ok(()) => Ok(true),
                        Err(DataStorageError::CasMismatch) => Ok(false),
                        Err(err) => Err(err),
                    }
                }
            }
            None => match lock_store.store(key, &StoreMode::Absent, &entry).await {
                Ok(()) => Ok(true),
                Err(DataStorageError::CasMismatch) => Ok(false),
                Err(err) => Err(err),
            },
        },
        Err(err) => Err(err),
    }
}

// ── CDGC client ──────────────────────────────────────────────────────────────────────────────

/// Logs in and exchanges for a JWT -- identical sequence to dq-gate-policy's (see its
/// `fetch_cdgc_score` for the full inline commentary on the budget/timeout clamping and the
/// deliberate no-token-reuse posture). Returns `(login, jwt, elapsed-so-far tracked via `start`)`.
async fn cdgc_login_and_jwt(
    client: &HttpClient,
    config: &Config,
    clock: &Clock,
    start: SystemTime,
    per_call_ms: i64,
) -> Result<(CdgcLoginResponse, CdgcJwtResponse)> {
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
        // Status code only -- never the body, which echoes sessionId/credential detail.
        return Err(anyhow!("CDGC login returned status {}", login_response.status_code()));
    }
    let login: CdgcLoginResponse = serde_json::from_slice(login_response.body())
        .map_err(|err| anyhow!("Failed to parse CDGC login response: {err}"))?;

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
        return Err(anyhow!("CDGC JWT fetch returned status {}", jwt_response.status_code()));
    }
    let jwt: CdgcJwtResponse = serde_json::from_slice(jwt_response.body())
        .map_err(|err| anyhow!("Failed to parse CDGC JWT response: {err}"))?;

    Ok((login, jwt))
}

/// Fetches, for one chunk of ids (at most [`CDGC_BATCH_CHUNK_SIZE`]), the `segments` requested
/// from the batched `data360/search/v1/assets/details` endpoint, and returns the response indexed
/// by `core.identity` so the caller can detect which of the *requested* ids CDGC could not
/// resolve (a config error) vs. simply had an empty segment (e.g. unclassified).
async fn fetch_details_batch(
    client: &HttpClient,
    config: &Config,
    authorization: &str,
    org_id: &str,
    segments: &str,
    ids: &[String],
    timeout: Duration,
) -> Result<Vec<Value>> {
    let path = format!("/data360/search/v1/assets/details?scheme=internal&segments={segments}");
    let body = serde_json::to_vec(ids)?;
    let response = client
        .request(&config.cdgc_base_api_url)
        .path(&path)
        .headers(vec![
            ("Authorization", authorization),
            ("X-INFA-ORG-ID", org_id),
            ("Content-Type", "application/json"),
        ])
        .body(&body)
        .timeout(timeout)
        .post()
        .await
        .map_err(|err| anyhow!("CDGC details batch fetch failed (segments={segments}): {err}"))?;

    if response.status_code() >= 300 {
        return Err(anyhow!(
            "CDGC details batch fetch returned status {} (segments={segments})",
            response.status_code()
        ));
    }
    serde_json::from_slice(response.body())
        .map_err(|err| anyhow!("Failed to parse CDGC details batch response (segments={segments}): {err}"))
}

/// Runs the live CDGC sequence (Login -> JWT -> two batched detail hops) and reduces the result
/// to the single worst-case rank this policy gates on: `MAX(rank)` across every column in
/// `governedColumnIds` (see the monorepo root design note for why MAX rather than per-column
/// redaction). The whole chain is bounded by [`CDGC_REFRESH_BUDGET_MS`], exactly like
/// dq-gate-policy's `fetch_cdgc_score`.
///
/// Hop 1 resolves each governed column to its linked classification id(s) (a column with no
/// `dataClassification` key is unclassified, contributing rank 0). Hop 2 resolves each *distinct*
/// classification id (deduped -- the same classification can be linked to multiple columns) to
/// its `core.sensitivity`. Either hop returning no entry at all for a requested id is a
/// config-resolution error (the asset id in `governedColumnIds` is wrong, or points at something
/// CDGC has since deleted) -- this fails the whole fetch rather than silently treating an
/// unresolvable configured asset as "unclassified, allow" (CDGC's nonexistent-asset response is
/// HTTP 200 + `{}`, not a 404, so this check is the only thing that catches it).
async fn fetch_cdgc_max_rank(client: &HttpClient, config: &Config, clock: &Clock) -> Result<RankOutcome> {
    let start = clock.now();
    let per_call_ms = config.timeout.unwrap_or(DEFAULT_TIMEOUT_MS);

    let column_ids = parse_governed_column_ids(config);
    if column_ids.is_empty() {
        return Err(anyhow!("governedColumnIds resolved to an empty list of column ids"));
    }

    let (login, jwt) = cdgc_login_and_jwt(client, config, clock, start, per_call_ms).await?;
    let authorization = format!("Bearer {}", jwt.jwt_token);

    // Hop 1: column -> linked classification id(s) + name, batched in chunks of
    // CDGC_BATCH_CHUNK_SIZE. `summary` is bundled onto this same call (verified live: no extra
    // CDGC round trip) so the block message can later name the offending column.
    let mut column_to_classifications: HashMap<String, Vec<String>> = HashMap::new();
    let mut column_names: HashMap<String, String> = HashMap::new();
    let mut distinct_classification_ids: HashSet<String> = HashSet::new();

    for chunk in column_ids.chunks(CDGC_BATCH_CHUNK_SIZE) {
        let timeout = next_call_timeout(per_call_ms, elapsed_ms(start, clock.now())).ok_or_else(|| {
            anyhow!("CDGC refresh exceeded {CDGC_REFRESH_BUDGET_MS}ms latency budget before a dataClassification batch fetch")
        })?;
        let raw = fetch_details_batch(
            client,
            config,
            &authorization,
            &login.org_id,
            "summary,dataClassification",
            chunk,
            timeout,
        )
        .await?;
        let segments: Vec<AssetClassificationSegment> = raw
            .into_iter()
            .map(serde_json::from_value)
            .collect::<serde_json::Result<_>>()
            .map_err(|err| anyhow!("Failed to parse dataClassification batch entry: {err}"))?;
        let mut by_id: HashMap<String, AssetClassificationSegment> = segments
            .into_iter()
            .filter_map(|segment| segment.core_identity.clone().map(|id| (id, segment)))
            .collect();

        for column_id in chunk {
            let segment = by_id.remove(column_id).ok_or_else(|| {
                anyhow!(
                    "CDGC could not resolve configured column asset id '{column_id}' from governedColumnIds (misconfigured or deleted asset)"
                )
            })?;
            column_names.insert(
                column_id.clone(),
                segment.summary.name.clone().unwrap_or_else(|| column_id.clone()),
            );
            let refs: Vec<String> = segment
                .data_classification
                .into_iter()
                .map(|r| r.core_identity)
                .collect();
            for classification_id in &refs {
                distinct_classification_ids.insert(classification_id.clone());
            }
            column_to_classifications.insert(column_id.clone(), refs);
        }
    }

    // Hop 2: distinct classification id -> core.sensitivity rank, same batching.
    let mut classification_to_rank: HashMap<String, u8> = HashMap::new();
    let classification_ids: Vec<String> = distinct_classification_ids.into_iter().collect();

    for chunk in classification_ids.chunks(CDGC_BATCH_CHUNK_SIZE) {
        let timeout = next_call_timeout(per_call_ms, elapsed_ms(start, clock.now())).ok_or_else(|| {
            anyhow!("CDGC refresh exceeded {CDGC_REFRESH_BUDGET_MS}ms latency budget before a selfAttributes batch fetch")
        })?;
        let raw = fetch_details_batch(
            client,
            config,
            &authorization,
            &login.org_id,
            "summary,selfAttributes",
            chunk,
            timeout,
        )
        .await?;
        let segments: Vec<ClassificationSensitivity> = raw
            .into_iter()
            .map(serde_json::from_value)
            .collect::<serde_json::Result<_>>()
            .map_err(|err| anyhow!("Failed to parse selfAttributes batch entry: {err}"))?;
        let mut by_id: HashMap<String, ClassificationSensitivity> = segments
            .into_iter()
            .filter_map(|segment| segment.core_identity.clone().map(|id| (id, segment)))
            .collect();

        for classification_id in chunk {
            let entry = by_id.remove(classification_id).ok_or_else(|| {
                anyhow!("CDGC could not resolve linked classification asset id '{classification_id}'")
            })?;
            let sensitivity = entry.self_attributes.sensitivity.ok_or_else(|| {
                anyhow!("CDGC classification asset '{classification_id}' has no core.sensitivity value")
            })?;
            let rank = rank_of(&sensitivity).ok_or_else(|| {
                anyhow!("CDGC classification asset '{classification_id}' has unrecognized core.sensitivity '{sensitivity}'")
            })?;
            classification_to_rank.insert(classification_id.clone(), rank);
        }
    }

    // Reduce: worst-case rank across every governed column. A column with no classification (or
    // whose classifications did not resolve to a rank -- can't happen here since hop 2 above
    // already errored out on that) contributes 0.
    let columns: Vec<ColumnRank> = column_ids
        .iter()
        .map(|column_id| {
            let rank = column_to_classifications
                .get(column_id)
                .into_iter()
                .flatten()
                .filter_map(|classification_id| classification_to_rank.get(classification_id).copied())
                .max()
                .unwrap_or(0);
            let name = column_names.get(column_id).cloned().unwrap_or_else(|| column_id.clone());
            ColumnRank { name, rank }
        })
        .collect();
    let max_rank = columns.iter().map(|c| c.rank).max().unwrap_or(0);

    Ok(RankOutcome { rank: max_rank, columns })
}

/// The core lazy/TTL cache-aside logic -- structurally identical to dq-gate-policy's
/// `resolve_score`, substituting the classification rank fetch/aggregate for the DQ score fetch.
async fn resolve_max_rank<S: DataStorage>(
    client: &HttpClient,
    config: &Config,
    rank_store: &S,
    lock_store: &S,
    clock: &Clock,
) -> Option<CachedRank> {
    let key = rank_cache_key(config);
    let refresh_interval = config
        .refresh_interval_seconds
        .unwrap_or(DEFAULT_REFRESH_INTERVAL_SECONDS)
        .max(0);
    let fail_open = config.fail_open_on_cdgc_error.unwrap_or(true);

    let cached = read_cached_rank(rank_store, &key).await;

    let now = unix_seconds(clock.now());
    let is_stale = match &cached {
        Some(cached) => now - cached.timestamp > refresh_interval,
        None => true,
    };

    if !is_stale {
        logger::info!(
            "Using cached classification rank for governed columns '{}': {} (age {}s)",
            config.governed_column_ids,
            cached.as_ref().map(|c| rank_label(c.rank)).unwrap_or("?"),
            cached.as_ref().map(|c| now - c.timestamp).unwrap_or_default()
        );
        return cached;
    }

    let lock_key = refresh_lock_key(config);
    let lock_acquired = match try_acquire_refresh_lock(lock_store, &lock_key, now).await {
        Ok(acquired) => acquired,
        Err(err) => {
            logger::warn!("Failed to acquire classification refresh lock: {err}; proceeding with refresh");
            true
        }
    };
    if !lock_acquired {
        logger::info!(
            "Classification refresh for governed columns '{}' already in progress elsewhere; serving existing cached value",
            config.governed_column_ids
        );
        return cached;
    }

    match fetch_cdgc_max_rank(client, config, clock).await {
        Ok(outcome) => {
            logger::info!(
                "Fetched fresh classification rank from CDGC for governed columns '{}': {}",
                config.governed_column_ids,
                rank_label(outcome.rank)
            );
            let fresh = CachedRank { rank: outcome.rank, timestamp: now, columns: outcome.columns };
            write_cached_rank(rank_store, &key, &fresh).await;
            Some(fresh)
        }
        Err(err) => {
            logger::warn!(
                "CDGC classification refresh failed for governed columns '{}': {err}",
                config.governed_column_ids
            );
            if fail_open {
                cached
            } else {
                None
            }
        }
    }
}

thread_local! {
    static UNGATED_BYPASS_LOGGED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

async fn request_filter<S: DataStorage>(
    request_state: RequestState,
    config: &Config,
    client: &HttpClient,
    rank_store: &S,
    lock_store: &S,
    clock: &Clock,
    violations: &PolicyViolations,
) -> Flow<ClassificationGateData> {
    let state = request_state.into_headers_body_state().await;

    let request_method = state.handler().header(":method").unwrap_or_default();
    if !request_method.eq_ignore_ascii_case("POST") {
        logger::debug!("Non-POST request ('{request_method}'); passing through ungated");
        return Flow::Continue(ClassificationGateData::Evaluated { rank: None, status: "skipped" });
    }
    let content_type = state.handler().header("content-type").unwrap_or_default();
    if !content_type.to_ascii_lowercase().contains("application/json") {
        logger::debug!("Non-JSON content-type ('{content_type}'); passing through ungated");
        return Flow::Continue(ClassificationGateData::Evaluated { rank: None, status: "skipped" });
    }

    let body = if state.contains_body() {
        state.handler().body()
    } else {
        Vec::new()
    };

    let (protocol, rpc_id) = match parse_jsonrpc_call(&body) {
        Some((method, rpc_id)) => {
            if is_notification_method(&method) || rpc_id.is_none() {
                logger::debug!(
                    "Notification-style request '{method}' (no response permitted); passing through ungated"
                );
                return Flow::Continue(ClassificationGateData::Evaluated { rank: None, status: "skipped" });
            }
            match classify_jsonrpc_method(&method) {
                RequestClass::Exempt => {
                    logger::info!("Method '{method}' is exempt from classification gating, passing through");
                    return Flow::Continue(ClassificationGateData::Evaluated { rank: None, status: "skipped" });
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
                return Flow::Continue(ClassificationGateData::Evaluated { rank: None, status: "skipped" });
            }
        }
    };

    let cached = resolve_max_rank(client, config, rank_store, lock_store, clock).await;
    let rank = cached.as_ref().map(|c| c.rank);
    let disclose = config.disclose_classification_details.unwrap_or(false);
    let ceiling = rank_of(&config.max_allowed_classification).unwrap_or(2);

    match rank {
        None => {
            if config.block_on_unknown_classification.unwrap_or(true) {
                logger::warn!(
                    "Blocking request: no classification result available yet for governed columns '{}' (fail-closed; blockOnUnknownClassification=true)",
                    config.governed_column_ids
                );
                violations.generate_policy_violation();
                Flow::Break(build_block_response(protocol, rpc_id, None, &[], config))
            } else {
                let first_bypass = UNGATED_BYPASS_LOGGED.with(|logged| !logged.replace(true));
                if first_bypass {
                    logger::warn!(
                        "Classification Gate BYPASS: passing traffic UNGATED for governed columns '{}' -- no classification result is available and blockOnUnknownClassification=false, so the control is currently disabled. (Warned once per worker.)",
                        config.governed_column_ids
                    );
                }
                logger::debug!(
                    "No classification result available yet for governed columns '{}'; passing through per blockOnUnknownClassification=false",
                    config.governed_column_ids
                );
                Flow::Continue(ClassificationGateData::Evaluated { rank: None, status: "unknown" })
            }
        }
        Some(rank) if rank > ceiling => {
            let offending: Vec<ColumnRank> = cached
                .map(|c| c.columns.into_iter().filter(|col| col.rank > ceiling).collect())
                .unwrap_or_default();
            logger::warn!(
                "Blocking request: governed columns '{}' worst-case classification {} exceeds maxAllowedClassification {} (offending: {})",
                config.governed_column_ids,
                rank_label(rank),
                config.max_allowed_classification,
                offending.iter().map(|c| format!("{} [{}]", c.name, rank_label(c.rank))).collect::<Vec<_>>().join(", ")
            );
            violations.generate_policy_violation();
            Flow::Break(build_block_response(protocol, rpc_id, Some(rank), &offending, config))
        }
        Some(rank) => Flow::Continue(ClassificationGateData::Evaluated { rank: disclose.then_some(rank), status: "ok" }),
    }
}

async fn response_filter(response_state: ResponseState, request_data: RequestData<ClassificationGateData>) {
    let headers_state = response_state.into_headers_state().await;

    if let RequestData::Continue(ClassificationGateData::Evaluated { rank, status }) = request_data {
        if let Some(rank) = rank {
            headers_state.handler().set_header(HEADER_CLASSIFICATION_RANK, rank_label(rank));
        }
        headers_state.handler().set_header(HEADER_CLASSIFICATION_STATUS, status);
    }
}

async fn launch_policy<S: DataStorage>(
    launcher: Launcher,
    config: &Config,
    client: &HttpClient,
    rank_store: &S,
    lock_store: &S,
    clock: &Clock,
    violations: &PolicyViolations,
) -> Result<()> {
    let filter = on_request(|rs| {
        request_filter(rs, config, client, rank_store, lock_store, clock, violations)
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

    if config.distributed.unwrap_or(false) {
        let rank_store = storage_builder.remote(RANK_CACHE_NAMESPACE, rank_store_ttl_ms(&config));
        let lock_store = storage_builder.remote(REFRESH_LOCK_NAMESPACE, REFRESH_LOCK_TTL_MS);
        launch_policy(launcher, &config, &client, &rank_store, &lock_store, &clock, &violations).await
    } else {
        let rank_store = storage_builder.local(RANK_CACHE_NAMESPACE);
        let lock_store = storage_builder.local(REFRESH_LOCK_NAMESPACE);
        launch_policy(launcher, &config, &client, &rank_store, &lock_store, &clock, &violations).await
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;
    use std::time::Duration;

    use pdk_unit::{TraceBackend, UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitTestBuilder};
    use serde_json::{json, Value};

    use super::REFRESH_LOCK_TTL_SECONDS;

    /// The six real demo columns/classifications this policy was verified against live this
    /// session (`OCCE1B_CLINICNORTH_PATIENTINTAKE_RAW`), used as realistic fixture ids below
    /// rather than opaque placeholders. Not every constant is exercised by every test.
    const VISIT_REASON_COL: &str = "b7e13420-4841-4bbe-86c0-002b1d9af165";
    const VISIT_REASON_CLS: &str = "ceaa1ca4-764d-4458-abc8-146ffee68222";
    #[allow(dead_code)]
    const SSN_COL: &str = "0ffa34a5-a37f-4ce7-be51-7a379a425801";
    #[allow(dead_code)]
    const SSN_CLS: &str = "9eb85680-f8af-45da-ae5c-11aa4808e9cd";
    #[allow(dead_code)]
    const DOB_COL: &str = "46a337b2-4beb-4f36-a8ad-b1ca1e835f56";
    #[allow(dead_code)]
    const DOB_CLS: &str = "fe3a6f92-7dce-42ef-955e-0666cc303330";
    const PATIENT_ID_COL: &str = "9c3d6045-db8a-4bca-897a-1acc686487fa";
    const PATIENT_ID_CLS: &str = "8564078f-e3f3-4c4d-a424-cfc517ccc079";
    const FULL_NAME_COL: &str = "6d26d67b-3ee3-4d23-817b-69fb91fabbb9";
    const FULL_NAME_CLS: &str = "95da15ba-025c-4a7a-85c7-9133fec97bb9";
    const APPOINTMENT_DATE_COL: &str = "86330022-c7c9-4e41-91c7-639f66356dab";

    /// Maps the fixture column ids above to their real technical (`summary.core.name`) names, so
    /// `cdgc_classification_backend`'s hop-1 responses can exercise name resolution without
    /// touching every existing backend/call-site signature.
    fn col_name(id: &str) -> &'static str {
        match id {
            VISIT_REASON_COL => "VISIT_REASON",
            SSN_COL => "SSN",
            DOB_COL => "DATE_OF_BIRTH",
            PATIENT_ID_COL => "PATIENT_ID",
            FULL_NAME_COL => "FULL_NAME",
            APPOINTMENT_DATE_COL => "APPOINTMENT_DATE",
            _ => "UNKNOWN_COLUMN",
        }
    }

    fn config() -> String {
        config_with_columns(&[VISIT_REASON_COL], "MEDIUM")
    }

    fn config_with_columns(columns: &[&str], max_allowed: &str) -> String {
        json!({
            "cdgcLoginUrl": "http://cdgclogin",
            "cdgcBaseApiUrl": "http://cdgcapi",
            "cdgcOrgUsername": "test-user",
            "cdgcOrgPassword": "test-pass",
            "governedColumnIds": columns.join(","),
            "maxAllowedClassification": max_allowed,
            "refreshIntervalSeconds": 86400,
        })
        .to_string()
    }

    fn config_with(overrides: Value) -> String {
        let mut base: Value = serde_json::from_str(&config()).unwrap();
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

    fn a2a_request(id: i64, method: &str) -> UnitHttpRequest {
        UnitHttpRequest::post()
            .with_path("/a2a")
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": id, "method": method }).to_string())
    }

    fn a2a_rest_send() -> UnitHttpRequest {
        UnitHttpRequest::post()
            .with_path("/v1/message:send")
            .with_header("content-type", "application/json")
            .with_body(json!({ "message": { "role": "user", "parts": [] } }).to_string())
    }

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

    fn ids_from_body(req: &UnitHttpRequest) -> Vec<String> {
        serde_json::from_slice::<Vec<String>>(req.body()).unwrap_or_default()
    }

    /// A CDGC classification backend serving `column_map` (column id -> linked classification
    /// ids, empty = unclassified) for the `dataClassification` hop and `sensitivity_map`
    /// (classification id -> LOW/MEDIUM/HIGH) for the `summary,selfAttributes` hop. An id absent
    /// from the relevant map is simply omitted from the returned array -- simulating CDGC's
    /// "could not resolve this id" behavior, which the fetch code must treat as a config error.
    /// Enforces the real 5-id-per-call cap so a chunking bug surfaces as a test failure.
    fn cdgc_classification_backend(
        column_map: Rc<RefCell<HashMap<String, Vec<String>>>>,
        sensitivity_map: Rc<RefCell<HashMap<String, &'static str>>>,
        hop1_calls: Rc<RefCell<u32>>,
        hop2_calls: Rc<RefCell<u32>>,
    ) -> impl Fn(UnitHttpRequest) -> UnitHttpResponse {
        move |req: UnitHttpRequest| {
            let path = req.header(":path").unwrap_or_default();
            if !path.starts_with("/data360/search/v1/assets/details") {
                return UnitHttpResponse::new(404);
            }
            let ids = ids_from_body(&req);
            if ids.is_empty() || ids.len() > 5 {
                return UnitHttpResponse::new(400).with_body(
                    json!({ "message": "Invalid request: the ids list is empty, or exceeds the length limit of 5 ids." })
                        .to_string(),
                );
            }
            if path.contains("segments=summary,dataClassification") {
                *hop1_calls.borrow_mut() += 1;
                let map = column_map.borrow();
                let mut arr = Vec::new();
                for id in &ids {
                    if let Some(classifications) = map.get(id) {
                        let mut obj = serde_json::Map::new();
                        obj.insert("core.identity".to_string(), json!(id));
                        obj.insert("summary".to_string(), json!({ "core.name": col_name(id) }));
                        if !classifications.is_empty() {
                            obj.insert(
                                "dataClassification".to_string(),
                                json!(classifications
                                    .iter()
                                    .map(|c| json!({ "core.identity": c }))
                                    .collect::<Vec<_>>()),
                            );
                        }
                        arr.push(Value::Object(obj));
                    }
                }
                UnitHttpResponse::new(200).with_body(Value::Array(arr).to_string())
            } else if path.contains("segments=summary,selfAttributes") {
                *hop2_calls.borrow_mut() += 1;
                let map = sensitivity_map.borrow();
                let mut arr = Vec::new();
                for id in &ids {
                    if let Some(sensitivity) = map.get(id.as_str()) {
                        arr.push(json!({ "core.identity": id, "selfAttributes": { "core.sensitivity": sensitivity } }));
                    }
                }
                UnitHttpResponse::new(200).with_body(Value::Array(arr).to_string())
            } else {
                UnitHttpResponse::new(404)
            }
        }
    }

    fn single_column_backend(
        column: &str,
        classification: &str,
        sensitivity: &'static str,
        hop1_calls: Rc<RefCell<u32>>,
        hop2_calls: Rc<RefCell<u32>>,
    ) -> impl Fn(UnitHttpRequest) -> UnitHttpResponse {
        let mut columns = HashMap::new();
        columns.insert(column.to_string(), vec![classification.to_string()]);
        let mut sensitivities = HashMap::new();
        sensitivities.insert(classification.to_string(), sensitivity);
        cdgc_classification_backend(
            Rc::new(RefCell::new(columns)),
            Rc::new(RefCell::new(sensitivities)),
            hop1_calls,
            hop2_calls,
        )
    }

    #[test]
    fn low_rank_column_passes_through_and_tags_the_response() {
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with_columns(&[PATIENT_ID_COL], "MEDIUM"))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                single_column_backend(PATIENT_ID_COL, PATIENT_ID_CLS, "MEDIUM", Rc::clone(&hop1_calls), Rc::clone(&hop2_calls)),
            )
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-classification-gate-status"), Some("ok"));
        assert_eq!(response.header("x-classification-gate-rank"), None);
        assert!(backend.next().is_some());
    }

    #[test]
    fn rank_above_ceiling_rejects_with_jsonrpc_error_and_never_calls_backend() {
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with_columns(&[VISIT_REASON_COL], "MEDIUM"))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                single_column_backend(VISIT_REASON_COL, VISIT_REASON_CLS, "HIGH", Rc::clone(&hop1_calls), Rc::clone(&hop2_calls)),
            )
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(42));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-classification-gate-status"), Some("blocked"));
        assert_eq!(response.header("content-type"), Some("application/json"));
        assert_eq!(response.header("x-classification-gate-rank"), None);
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 42);
        assert_eq!(body["error"]["code"], -32011);
        let msg = body["error"]["message"].as_str().unwrap();
        assert!(msg.contains("allowed maximum"), "got: {}", msg);
        assert!(!msg.contains("HIGH"), "must not leak tier: {}", msg);
        assert!(backend.next().is_none());
    }

    #[test]
    fn disclose_true_emits_rank_header_on_allowed_response() {
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "discloseClassificationDetails": true })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                single_column_backend(VISIT_REASON_COL, VISIT_REASON_CLS, "MEDIUM", Rc::clone(&hop1_calls), Rc::clone(&hop2_calls)),
            )
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        assert_eq!(response.header("x-classification-gate-status"), Some("ok"));
        assert_eq!(response.header("x-classification-gate-rank"), Some("MEDIUM"));
    }

    #[test]
    fn disclose_true_block_message_includes_tier_and_ceiling() {
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "discloseClassificationDetails": true })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                single_column_backend(VISIT_REASON_COL, VISIT_REASON_CLS, "HIGH", Rc::clone(&hop1_calls), Rc::clone(&hop2_calls)),
            )
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(3));

        assert_eq!(response.header("x-classification-gate-status"), Some("blocked"));
        assert_eq!(response.header("x-classification-gate-rank"), Some("HIGH"));
        assert_eq!(response.header("x-classification-gate-columns"), Some("VISIT_REASON"));
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        let msg = body["error"]["message"].as_str().unwrap();
        assert!(msg.contains("HIGH"), "got: {}", msg);
        assert!(msg.contains("MEDIUM"), "got: {}", msg);
        assert!(msg.contains("VISIT_REASON"), "got: {}", msg);
        assert!(backend.next().is_none());
    }

    #[test]
    fn disclose_true_block_message_names_column_on_cache_hit_too() {
        // The offending column name must round-trip through the cache: the second request is
        // served entirely from the cached rank (no second CDGC fetch), and must still name
        // VISIT_REASON in the block message -- proving names are stored in CachedRank, not just
        // computed on a fresh fetch.
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "discloseClassificationDetails": true })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                single_column_backend(VISIT_REASON_COL, VISIT_REASON_CLS, "HIGH", Rc::clone(&hop1_calls), Rc::clone(&hop2_calls)),
            )
            .with_entrypoint(super::configure);

        let first = tester.request(mcp_request(1));
        let first_body: Value = serde_json::from_slice(first.body()).unwrap();
        assert!(first_body["error"]["message"].as_str().unwrap().contains("VISIT_REASON"));
        assert_eq!(*login_calls.borrow(), 1);

        let second = tester.request(mcp_request(2));
        assert_eq!(*login_calls.borrow(), 1, "second request must be served from cache, no fresh CDGC fetch");
        assert_eq!(second.header("x-classification-gate-columns"), Some("VISIT_REASON"));
        let second_body: Value = serde_json::from_slice(second.body()).unwrap();
        assert!(second_body["error"]["message"].as_str().unwrap().contains("VISIT_REASON"));
    }

    #[test]
    fn exempt_handshake_methods_pass_through_even_with_high_rank_configured() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_entrypoint(super::configure);

        for method in ["initialize", "tools/list", "notifications/initialized", "ping"] {
            let response = tester.request(mcp_request_with_method(1, method));
            assert_eq!(response.status_code(), 200, "method {method} should pass through");
            assert_eq!(response.header("x-classification-gate-status"), Some("skipped"));
        }

        assert!(backend.next().is_some());
        assert_eq!(*login_calls.borrow(), 0);
    }

    #[test]
    fn cached_rank_within_ttl_skips_cdgc_entirely() {
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                single_column_backend(VISIT_REASON_COL, VISIT_REASON_CLS, "MEDIUM", Rc::clone(&hop1_calls), Rc::clone(&hop2_calls)),
            )
            .with_entrypoint(super::configure);

        let first = tester.request(mcp_request(1));
        assert_eq!(first.status_code(), 200);
        assert_eq!(*login_calls.borrow(), 1);

        let second = tester.request(mcp_request(2));
        assert_eq!(second.status_code(), 200);
        assert_eq!(second.header("x-classification-gate-status"), Some("ok"));
        assert_eq!(*login_calls.borrow(), 1);
    }

    #[test]
    fn no_rank_defaults_to_fail_closed_and_emits_violation() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        // No CDGC upstream registered for "cdgcapi" at all -> the Login/JWT succeed but the
        // details fetch has nowhere to go, so fetch_cdgc_max_rank fails and no rank is ever
        // available. blockOnUnknownClassification is unset, so the code default must fail closed.
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(11));

        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"]["code"], -32011, "unset flag must fail closed");
        assert!(backend.next().is_none(), "blocked request must never reach the MCP backend");
        let violation = response.violation().expect("fail-closed block must emit a PolicyViolation");
        assert_eq!(violation.get_policy_name(), "test_policy_id");
    }

    #[test]
    fn soft_launch_passes_ungated_when_block_on_unknown_false() {
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "blockOnUnknownClassification": false })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(12));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-classification-gate-status"), Some("unknown"));
        assert!(response.body().is_empty());
        assert!(backend.next().is_some());
        assert!(response.violation().is_none());
    }

    #[test]
    fn unresolved_configured_column_id_is_a_config_error_not_unclassified() {
        // A misconfigured/deleted column asset id must NOT silently resolve to "unclassified,
        // allow" -- CDGC returns HTTP 200 for a nonexistent id, so the only signal is the id's
        // absence from the returned batch. That must propagate as an error and, with
        // blockOnUnknownClassification defaulting true, fail closed.
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with_columns(&["00000000-0000-0000-0000-000000000000"], "MEDIUM"))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                // Registers a real column/classification, but NOT the bogus id the config asks
                // for -- so the bogus id is simply absent from the mock's response, exactly as a
                // real nonexistent CDGC asset id would be.
                single_column_backend(VISIT_REASON_COL, VISIT_REASON_CLS, "HIGH", Rc::clone(&hop1_calls), Rc::clone(&hop2_calls)),
            )
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"]["code"], -32011, "an unresolved configured column must fail closed, not pass as unclassified");
        assert!(backend.next().is_none());
    }

    #[test]
    fn unclassified_column_contributes_rank_zero_and_is_allowed() {
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut columns = HashMap::new();
        columns.insert(APPOINTMENT_DATE_COL.to_string(), Vec::new()); // present, no classification key
        let sensitivities: HashMap<String, &'static str> = HashMap::new();

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with_columns(&[APPOINTMENT_DATE_COL], "LOW"))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                cdgc_classification_backend(
                    Rc::new(RefCell::new(columns)),
                    Rc::new(RefCell::new(sensitivities)),
                    Rc::clone(&hop1_calls),
                    Rc::clone(&hop2_calls),
                ),
            )
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-classification-gate-status"), Some("ok"));
        assert!(backend.next().is_some());
        // An unclassified column must never trigger a hop-2 (sensitivity) lookup.
        assert_eq!(*hop2_calls.borrow(), 0);
    }

    #[test]
    fn multi_column_worst_case_rank_blocks_even_when_most_columns_are_low() {
        // Five LOW/MEDIUM columns plus one HIGH column (VISIT_REASON): MAX(rank) must be driven
        // by the single worst column, not diluted by the others.
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut columns = HashMap::new();
        columns.insert(PATIENT_ID_COL.to_string(), vec![PATIENT_ID_CLS.to_string()]);
        columns.insert(FULL_NAME_COL.to_string(), vec![FULL_NAME_CLS.to_string()]);
        columns.insert(VISIT_REASON_COL.to_string(), vec![VISIT_REASON_CLS.to_string()]);
        let mut sensitivities: HashMap<String, &'static str> = HashMap::new();
        sensitivities.insert(PATIENT_ID_CLS.to_string(), "MEDIUM");
        sensitivities.insert(FULL_NAME_CLS.to_string(), "MEDIUM");
        sensitivities.insert(VISIT_REASON_CLS.to_string(), "HIGH");

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with_columns(&[PATIENT_ID_COL, FULL_NAME_COL, VISIT_REASON_COL], "MEDIUM"))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                cdgc_classification_backend(
                    Rc::new(RefCell::new(columns)),
                    Rc::new(RefCell::new(sensitivities)),
                    Rc::clone(&hop1_calls),
                    Rc::clone(&hop2_calls),
                ),
            )
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"]["code"], -32011);
        assert!(backend.next().is_none());
    }

    #[test]
    fn seven_governed_columns_are_batched_in_two_hop1_calls() {
        // 7 columns > CDGC_BATCH_CHUNK_SIZE (5): must take ceil(7/5) = 2 hop-1 calls, not 7
        // separate single-id calls and not one oversized call that the mock would reject.
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let column_ids: Vec<String> = (0..7)
            .map(|i| format!("00000000-0000-0000-0000-00000000000{i}"))
            .collect();
        let mut columns = HashMap::new();
        for id in &column_ids {
            columns.insert(id.clone(), Vec::new()); // all unclassified -> no hop-2 calls needed
        }
        let sensitivities: HashMap<String, &'static str> = HashMap::new();

        let column_refs: Vec<&str> = column_ids.iter().map(String::as_str).collect();
        let mut tester = UnitTestBuilder::default()
            .with_config(config_with_columns(&column_refs, "LOW"))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                cdgc_classification_backend(
                    Rc::new(RefCell::new(columns)),
                    Rc::new(RefCell::new(sensitivities)),
                    Rc::clone(&hop1_calls),
                    Rc::clone(&hop2_calls),
                ),
            )
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-classification-gate-status"), Some("ok"));
        assert_eq!(*hop1_calls.borrow(), 2, "7 columns must be chunked into ceil(7/5) = 2 hop-1 calls");
    }

    #[test]
    fn rank_exactly_at_ceiling_is_allowed_not_blocked() {
        // Boundary: maxAllowedClassification=MEDIUM (rank 2). rank > ceiling is false at exactly
        // 2, so MEDIUM itself must be allowed, not blocked (strict `>`, not `>=`).
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with_columns(&[PATIENT_ID_COL], "MEDIUM"))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                single_column_backend(PATIENT_ID_COL, PATIENT_ID_CLS, "MEDIUM", Rc::clone(&hop1_calls), Rc::clone(&hop2_calls)),
            )
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-classification-gate-status"), Some("ok"));
        assert!(backend.next().is_some());
    }

    #[test]
    fn stale_cache_is_served_when_fail_open_true_and_refresh_fails() {
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        // Attempt 1 (first request, cold cache) must succeed end-to-end; attempt 2 (second
        // request, stale cache) must fail on the details fetch so the fail-open path is
        // exercised. Tracked via a shared attempt counter incremented on each Login call, since a
        // single attempt's Login/JWT/hop1/hop2 calls all share one "/data360/.../details" path
        // prefix and can't be told apart by path alone.
        let attempt = Rc::new(RefCell::new(0u32));
        let attempt_for_login = Rc::clone(&attempt);
        let login_backend = move |req: UnitHttpRequest| {
            let path = req.header(":path").unwrap_or_default();
            if path.starts_with("/identity-service/api/v1/Login") {
                *attempt_for_login.borrow_mut() += 1;
                UnitHttpResponse::new(200)
                    .with_body(json!({ "sessionId": "session-1", "orgId": "org-1" }).to_string())
            } else if path.starts_with("/identity-service/api/v1/jwt/Token") {
                UnitHttpResponse::new(200).with_body(json!({ "jwt_token": "test-jwt" }).to_string())
            } else {
                UnitHttpResponse::new(404)
            }
        };

        let attempt_for_details = Rc::clone(&attempt);
        let inner = single_column_backend(VISIT_REASON_COL, VISIT_REASON_CLS, "MEDIUM", Rc::clone(&hop1_calls), Rc::clone(&hop2_calls));
        let flaky = move |req: UnitHttpRequest| {
            let path = req.header(":path").unwrap_or_default();
            if path.starts_with("/data360/search/v1/assets/details") {
                if *attempt_for_details.borrow() >= 2 {
                    return UnitHttpResponse::new(500);
                }
                return inner(req);
            }
            inner(req)
        };

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with(json!({ "failOpenOnCdgcError": true })))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", login_backend)
            .with_http_upstream_from_authority("cdgcapi", flaky)
            .with_entrypoint(super::configure);

        let first = tester.request(mcp_request(1));
        assert_eq!(first.header("x-classification-gate-status"), Some("ok"));
        assert!(backend.next().is_some());

        tester.sleep(Duration::from_secs(86_401));

        let second = tester.request(mcp_request(2));
        assert_eq!(second.status_code(), 200);
        assert_eq!(second.header("x-classification-gate-status"), Some("ok"), "stale rank must be served on fail-open");
        assert!(backend.next().is_some(), "fail-open must forward the request to the MCP backend");
    }

    #[test]
    fn non_post_request_passes_through_ungated() {
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with_columns(&[VISIT_REASON_COL], "LOW"))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                single_column_backend(VISIT_REASON_COL, VISIT_REASON_CLS, "HIGH", Rc::clone(&hop1_calls), Rc::clone(&hop2_calls)),
            )
            .with_entrypoint(super::configure);

        let response = tester.request(UnitHttpRequest::get().with_path("/mcp"));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-classification-gate-status"), Some("skipped"));
        assert!(backend.next().is_some());
        assert_eq!(*login_calls.borrow(), 0, "resolve_max_rank must not run for a non-POST request");
    }

    #[test]
    fn a2a_v03_send_is_gated_and_blocked_above_ceiling() {
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with_columns(&[VISIT_REASON_COL], "LOW"))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                single_column_backend(VISIT_REASON_COL, VISIT_REASON_CLS, "HIGH", Rc::clone(&hop1_calls), Rc::clone(&hop2_calls)),
            )
            .with_entrypoint(super::configure);

        let response = tester.request(a2a_request(5, "message/send"));

        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"]["code"], -32012);
        assert!(backend.next().is_none());
    }

    #[test]
    fn a2a_rest_send_binding_blocks_with_native_http_403() {
        let login_calls = Rc::new(RefCell::new(0));
        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config_with_columns(&[VISIT_REASON_COL], "LOW"))
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority(
                "cdgcapi",
                single_column_backend(VISIT_REASON_COL, VISIT_REASON_CLS, "HIGH", Rc::clone(&hop1_calls), Rc::clone(&hop2_calls)),
            )
            .with_entrypoint(super::configure);

        let response = tester.request(a2a_rest_send());

        assert_eq!(response.status_code(), 403);
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"]["code"], 403);
        assert!(backend.next().is_none());
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

        let response = tester.request(a2a_request(1, "tasks/get"));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-classification-gate-status"), Some("skipped"));
        assert_eq!(*login_calls.borrow(), 0);
    }

    #[test]
    fn rank_of_maps_known_values_and_rejects_unknown() {
        assert_eq!(super::rank_of("LOW"), Some(1));
        assert_eq!(super::rank_of("MEDIUM"), Some(2));
        assert_eq!(super::rank_of("HIGH"), Some(3));
        // No speculative extra tier -- an unrecognized value is a data-integrity error, not a
        // silently-ranked new tier.
        assert_eq!(super::rank_of("RESTRICTED_PHI"), None);
        assert_eq!(super::rank_of(""), None);
    }

    #[test]
    fn parse_governed_column_ids_trims_dedupes_and_drops_empties() {
        let cfg: super::Config = serde_json::from_str(&config_with_columns(
            &["a", " b ", "a", "", "c"],
            "MEDIUM",
        ))
        .unwrap();
        assert_eq!(super::parse_governed_column_ids(&cfg), vec!["a", "b", "c"]);
    }

    #[test]
    fn cache_and_lock_keys_are_order_and_whitespace_insensitive() {
        let cfg = |cols: &[&str]| -> super::Config {
            serde_json::from_str(&config_with_columns(cols, "MEDIUM")).unwrap()
        };
        let canonical = cfg(&["a", "b"]);
        for variant in [cfg(&["b", "a"]), cfg(&[" a ", "b", "a"])] {
            assert_eq!(super::rank_cache_key(&variant), super::rank_cache_key(&canonical));
            assert_eq!(super::refresh_lock_key(&variant), super::refresh_lock_key(&canonical));
        }
        assert_ne!(super::rank_cache_key(&cfg(&["a", "c"])), super::rank_cache_key(&canonical));
    }

    #[test]
    fn jwt_fetch_sends_session_cookie_ids_header_and_nonce_query() {
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

        let hop1_calls = Rc::new(RefCell::new(0));
        let hop2_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));
        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", capturing_login)
            .with_http_upstream_from_authority(
                "cdgcapi",
                single_column_backend(VISIT_REASON_COL, VISIT_REASON_CLS, "MEDIUM", Rc::clone(&hop1_calls), Rc::clone(&hop2_calls)),
            )
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));
        assert_eq!(response.status_code(), 200);

        assert_eq!(*jwt_cookie.borrow(), "USER_SESSION=session-1");
        assert_eq!(*jwt_ids.borrow(), "session-1");
        let path = jwt_path.borrow();
        assert!(path.contains("client_id=idmc_api"), "jwt path missing client_id: {path}");
        assert!(path.contains("nonce="), "jwt path missing nonce: {path}");
    }

    #[test]
    #[allow(unused)]
    fn silence_unused_lock_ttl_import() {
        let _ = REFRESH_LOCK_TTL_SECONDS;
    }
}
