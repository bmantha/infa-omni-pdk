// Copyright 2026 Salesforce, Inc. All rights reserved.
mod generated;

use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use pdk::data_storage::{DataStorage, DataStorageBuilder, DataStorageError, StoreMode};
use pdk::hl::*;
use pdk::logger;
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

const DEFAULT_TIMEOUT_MS: i64 = 60_000;
const DEFAULT_REFRESH_INTERVAL_SECONDS: i64 = 86_400;
const CDGC_JWT_NONCE: &str = "1234";
const JSONRPC_BLOCK_ERROR_CODE: i64 = -32000;
const HEADER_DQ_SCORE: &str = "x-dq-gate-score";
const HEADER_DQ_STATUS: &str = "x-dq-gate-status";

/// MCP handshake/discovery methods that must always pass through ungated. An MCP client (e.g.
/// `mcp-remote`) issues `initialize` and `tools/list` just to establish the connection and
/// enumerate capabilities, before the agent has chosen to invoke anything -- blocking those means
/// the client never even connects, rather than surfacing a per-call block. Gating is reserved for
/// methods that actually touch upstream data (`tools/call` and anything not explicitly exempted).
const EXEMPT_METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
    "ping",
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

fn timeout(config: &Config) -> Duration {
    Duration::from_millis(config.timeout.unwrap_or(DEFAULT_TIMEOUT_MS).max(0) as u64)
}

fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
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

/// Extracts the JSON-RPC `id` field from an MCP request body, so a block response can echo it
/// back. Per JSON-RPC 2.0, an unparsable/missing id degrades to `null`, not to failing the block.
fn extract_jsonrpc_id(body: &[u8]) -> Option<Value> {
    let json: Value = serde_json::from_slice(body).ok()?;
    json.get("id").cloned()
}

/// Extracts the JSON-RPC `method` field from an MCP request body, used to decide whether this
/// request is a handshake/discovery call exempt from DQ gating (see [`EXEMPT_METHODS`]).
fn extract_jsonrpc_method(body: &[u8]) -> Option<String> {
    let json: Value = serde_json::from_slice(body).ok()?;
    json.get("method")?.as_str().map(str::to_string)
}

/// Builds the JSON-RPC error response returned to the agent when a request is blocked. Status
/// `200` is intentional: JSON-RPC errors are protocol-level, not transport-level, so an MCP
/// client expects `200` + an `error` object here, not an HTTP 4xx.
fn block_response(rpc_id: Option<Value>, score: Option<f64>, config: &Config) -> Response {
    let message = match score {
        Some(score) => format!(
            "Blocked by DQ Gate: asset '{}' DQ score {score:.2} is below blockThreshold {:.2}",
            config.cdgc_asset_id, config.block_threshold
        ),
        None => format!(
            "Blocked by DQ Gate: no DQ score is available yet for asset '{}'",
            config.cdgc_asset_id
        ),
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": rpc_id.unwrap_or(Value::Null),
        "error": { "code": JSONRPC_BLOCK_ERROR_CODE, "message": message },
    });

    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    if let Some(score) = score {
        headers.push((HEADER_DQ_SCORE.to_string(), format!("{score:.2}")));
    }
    headers.push((HEADER_DQ_STATUS.to_string(), "blocked".to_string()));

    Response::new(200)
        .with_headers(headers)
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
async fn fetch_cdgc_score(client: &HttpClient, config: &Config) -> Result<f64> {
    let login_body = serde_json::to_vec(&serde_json::json!({
        "username": config.cdgc_org_username,
        "password": config.cdgc_org_password,
    }))?;

    let login_response = client
        .request(&config.cdgc_login_url)
        .path("/identity-service/api/v1/Login")
        .headers(vec![("Content-Type", "application/json")])
        .body(&login_body)
        .timeout(timeout(config))
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
    let jwt_response = client
        .request(&config.cdgc_login_url)
        .path(&jwt_path)
        .headers(vec![
            ("cookie", cookie.as_str()),
            ("IDS-SESSION-ID", login.session_id.as_str()),
        ])
        .timeout(timeout(config))
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
        "/data360/search/v1/assets/{}?scheme=internal&segments=dataQuality",
        config.cdgc_asset_id
    );
    let authorization = format!("Bearer {}", jwt.jwt_token);
    let detail_response = client
        .request(&config.cdgc_base_api_url)
        .path(&detail_path)
        .headers(vec![
            ("Authorization", authorization.as_str()),
            ("X-INFA-ORG-ID", login.org_id.as_str()),
            ("Content-Type", "application/json"),
        ])
        .timeout(timeout(config))
        .get()
        .await
        .map_err(|err| anyhow!("CDGC DQ score fetch failed: {err}"))?;

    if detail_response.status_code() >= 300 {
        return Err(anyhow!(
            "CDGC DQ score fetch returned {}: {}",
            detail_response.status_code(),
            String::from_utf8_lossy(detail_response.body())
        ));
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
) -> Option<f64> {
    let key = score_cache_key(config);
    let refresh_interval = config
        .refresh_interval_seconds
        .unwrap_or(DEFAULT_REFRESH_INTERVAL_SECONDS)
        .max(0);
    let fail_open = config.fail_open_on_cdgc_error.unwrap_or(true);

    let cached = read_cached_score(score_store, &key).await;

    let now = unix_seconds(SystemTime::now());
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

    match fetch_cdgc_score(client, config).await {
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

async fn request_filter<S: DataStorage>(
    request_state: RequestState,
    config: &Config,
    client: &HttpClient,
    score_store: &S,
    lock_store: &S,
) -> Flow<DqGateData> {
    // Atomically buffer request headers AND body before deciding. The split
    // into_headers_state() -> into_body_state() path releases headers to Envoy's router, which
    // begins proxying the request upstream in parallel while we compute the score -- so a blocked
    // tools/call could still reach and execute on the upstream MCP server, and the upstream
    // response could race our synthetic Flow::Break. The combined state holds the request in the
    // filter until we decide, so Flow::Break always wins (see #2). The known response-leg hang
    // with this combined state does not apply here -- this is the request leg.
    let state = request_state.into_headers_body_state().await;
    let body = if state.contains_body() {
        state.handler().body()
    } else {
        Vec::new()
    };
    let rpc_id = extract_jsonrpc_id(&body);
    let method = extract_jsonrpc_method(&body);

    if let Some(method) = &method {
        if EXEMPT_METHODS.contains(&method.as_str()) {
            logger::info!("Method '{method}' is exempt from DQ gating, passing through");
            return Flow::Continue(DqGateData::Evaluated { score: None, status: "skipped" });
        }
    }

    let score = resolve_score(client, config, score_store, lock_store).await;

    match score {
        None => {
            if config.block_on_unknown_score.unwrap_or(false) {
                logger::warn!(
                    "Blocking request: no DQ score available yet for asset '{}'",
                    config.cdgc_asset_id
                );
                Flow::Break(block_response(rpc_id, None, config))
            } else {
                logger::warn!(
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
            Flow::Break(block_response(rpc_id, Some(score), config))
        }
        Some(score) if score < config.warn_threshold => {
            logger::warn!(
                "Warning: asset '{}' DQ score {score:.2} below warnThreshold {:.2}",
                config.cdgc_asset_id,
                config.warn_threshold
            );
            Flow::Continue(DqGateData::Evaluated { score: Some(score), status: "warn" })
        }
        Some(score) => Flow::Continue(DqGateData::Evaluated { score: Some(score), status: "ok" }),
    }
}

async fn response_filter(response_state: ResponseState, request_data: RequestData<DqGateData>) {
    let headers_state = response_state.into_headers_state().await;

    if let RequestData::Continue(DqGateData::Evaluated { score, status }) = request_data {
        if let Some(score) = score {
            headers_state.handler().set_header(HEADER_DQ_SCORE, &format!("{score:.2}"));
        }
        headers_state.handler().set_header(HEADER_DQ_STATUS, status);
    }

    headers_state.into_body_state().await;
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
) -> Result<()> {
    let filter = on_request(|rs| request_filter(rs, config, client, score_store, lock_store))
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
        launch_policy(launcher, &config, &client, &score_store, &lock_store).await
    } else {
        let score_store = storage_builder.local(SCORE_CACHE_NAMESPACE);
        let lock_store = storage_builder.local(REFRESH_LOCK_NAMESPACE);
        launch_policy(launcher, &config, &client, &score_store, &lock_store).await
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;
    use std::sync::Mutex;

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
            .with_body(json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call" }).to_string())
    }

    fn mcp_request_with_method(id: i64, method: &str) -> UnitHttpRequest {
        UnitHttpRequest::post()
            .with_path("/mcp")
            .with_body(json!({ "jsonrpc": "2.0", "id": id, "method": method }).to_string())
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
        assert_eq!(response.header("x-dq-gate-score"), Some("95.00"));
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
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 42);
        assert_eq!(body["error"]["code"], -32000);
        assert!(body["error"]["message"].as_str().unwrap().contains("blockThreshold"));
        // The MCP server backend must never be invoked for a blocked request.
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
        assert_eq!(body["error"]["code"], -32000);
        assert!(backend.next().is_none());
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
}
