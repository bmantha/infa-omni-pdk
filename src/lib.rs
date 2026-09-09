// Copyright 2026 Salesforce, Inc. All rights reserved.
mod generated;

use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use pdk::data_storage::{DataStorage, DataStorageBuilder, StoreMode};
use pdk::hl::*;
use pdk::logger;
use pdk::metadata::Metadata;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::generated::config::Config;

const OAUTH_TOKEN_CACHE_NAMESPACE: &str = "dq-gate-object-store-oauth-tokens";
const OAUTH_TOKEN_CACHE_KEY: &str = "object-store-oauth-token";
const SCORE_CACHE_KEY_PREFIX: &str = "dq-score-";
const REFRESH_LOCK_KEY_PREFIX: &str = "dq-refresh-lock-";
const REFRESH_LOCK_TTL_SECONDS: i64 = 30;
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
        logger::warn!("Missing org/env in metadata, DQ score caching disabled");
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

/// The cached DQ score for `cdgcAssetId`, and when it was fetched -- compared against
/// `refreshIntervalSeconds` on every request to decide whether a live CDGC fetch is needed.
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

/// Fetches an Object Store V2 access token via OAuth2 client-credentials, caching it in-memory
/// until shortly before it expires so we don't re-authenticate on every request.
async fn fetch_object_store_token(
    client: &HttpClient,
    config: &Config,
    token_cache: &impl DataStorage,
) -> Result<String> {
    if let Ok(Some((cached, _))) = token_cache.get::<CachedOauthToken>(OAUTH_TOKEN_CACHE_KEY).await {
        if SystemTime::now() < cached.valid_until {
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
        SystemTime::now() + Duration::from_secs(parsed.expires_in.unwrap_or(3600).saturating_sub(30));
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
) -> Result<Option<CachedScore>> {
    let token = fetch_object_store_token(client, config, token_cache).await?;
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
) -> Result<()> {
    let token = fetch_object_store_token(client, config, token_cache).await?;
    let bytes = serde_json::to_vec(cached)?;
    object_store_put(client, config, scope, &token, key, &bytes).await
}

fn refresh_lock_key(config: &Config) -> String {
    format!("{REFRESH_LOCK_KEY_PREFIX}{}", config.cdgc_asset_id)
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
) -> Result<bool> {
    let key = refresh_lock_key(config);
    let token = fetch_object_store_token(client, config, token_cache).await?;

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

/// The core lazy/TTL cache-aside logic: read the cached score, and if it's missing or older than
/// `refreshIntervalSeconds`, refresh it from CDGC right here, inline, before returning a score to
/// gate on. Returns `None` only when no score is available at all (no cache, and the refresh --
/// if attempted -- also failed with `failOpenOnCdgcError=false`).
async fn resolve_score(
    client: &HttpClient,
    config: &Config,
    object_store_scope: Option<&ObjectStoreScope>,
    token_cache: &impl DataStorage,
) -> Option<f64> {
    let key = score_cache_key(config);
    let refresh_interval = config
        .refresh_interval_seconds
        .unwrap_or(DEFAULT_REFRESH_INTERVAL_SECONDS)
        .max(0);
    let fail_open = config.fail_open_on_cdgc_error.unwrap_or(true);

    let cached = match object_store_scope {
        Some(scope) => match get_cached_score(client, config, scope, token_cache, &key).await {
            Ok(cached) => cached,
            Err(err) => {
                logger::warn!("Failed to read cached DQ score from Object Store: {err}");
                None
            }
        },
        None => None,
    };

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

    if let Some(scope) = object_store_scope {
        let lock_acquired = match try_acquire_refresh_lock(client, config, scope, token_cache, now).await {
            Ok(acquired) => acquired,
            Err(err) => {
                logger::warn!("Failed to acquire DQ score refresh lock: {err}");
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
    }

    match fetch_cdgc_score(client, config).await {
        Ok(score) => {
            logger::info!(
                "Fetched fresh DQ score from CDGC for asset '{}': {score:.2}",
                config.cdgc_asset_id
            );
            if let Some(scope) = object_store_scope {
                let fresh = CachedScore { score, timestamp: now };
                if let Err(err) = put_cached_score(client, config, scope, token_cache, &key, &fresh).await {
                    logger::warn!("Failed to persist refreshed DQ score to Object Store: {err}");
                }
            }
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

async fn request_filter(
    request_state: RequestState,
    config: &Config,
    client: &HttpClient,
    token_cache: &impl DataStorage,
    object_store_scope: Option<&ObjectStoreScope>,
) -> Flow<DqGateData> {
    let headers_state = request_state.into_headers_state().await;
    let body_state = headers_state.into_body_state().await;
    let body = body_state.handler().body();
    let rpc_id = extract_jsonrpc_id(&body);
    let method = extract_jsonrpc_method(&body);

    if let Some(method) = &method {
        if EXEMPT_METHODS.contains(&method.as_str()) {
            logger::info!("Method '{method}' is exempt from DQ gating, passing through");
            return Flow::Continue(DqGateData::Evaluated { score: None, status: "skipped" });
        }
    }

    let score = resolve_score(client, config, object_store_scope, token_cache).await;

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

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    client: HttpClient,
    storage_builder: DataStorageBuilder,
    metadata: Metadata,
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

    let filter = on_request(|rs| request_filter(rs, &config, &client, &token_cache, object_store_scope.as_ref()))
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
            "cdgcAssetId": "asset-1",
            "warnThreshold": 90,
            "blockThreshold": 70,
            "refreshIntervalSeconds": 86400,
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
            .with_body(json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call" }).to_string())
    }

    fn mcp_request_with_method(id: i64, method: &str) -> UnitHttpRequest {
        UnitHttpRequest::post()
            .with_path("/mcp")
            .with_body(json!({ "jsonrpc": "2.0", "id": id, "method": method }).to_string())
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
                json!({ "dataQuality": [{ "core.score": score }] }).to_string(),
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
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(95.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(1));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("ok"));
        assert_eq!(response.header("x-dq-gate-score"), Some("95.00"));
        assert!(backend.next().is_some());
        assert!(!store.borrow().is_empty());
    }

    #[test]
    fn score_below_block_threshold_rejects_with_jsonrpc_error_and_never_calls_backend() {
        let store = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(50.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
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
        // resolve_score, fetch_cdgc_score would fail with no score available, and
        // blockOnUnknownScore defaults false so it would (incorrectly) still pass -- so this test
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
        let store = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let login_calls = Rc::new(RefCell::new(0));
        let backend = Rc::new(TraceBackend::new(|_req: UnitHttpRequest| UnitHttpResponse::new(200)));

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(80.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(2));

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("x-dq-gate-status"), Some("warn"));
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
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(95.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let first = tester.request(mcp_request(1));
        assert_eq!(first.status_code(), 200);
        assert_eq!(*login_calls.borrow(), 1);

        // Second request, well within the 24h refreshIntervalSeconds: must reuse the cached
        // score from Object Store rather than re-authenticating to CDGC.
        let second = tester.request(mcp_request(2));
        assert_eq!(second.status_code(), 200);
        assert_eq!(second.header("x-dq-gate-status"), Some("ok"));
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
        assert_eq!(body["error"]["code"], -32000);
        assert!(backend.next().is_none());
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
        let stale = super::CachedScore { score: 95.0, timestamp: 0 };
        store.borrow_mut().insert(
            "dq-score-asset-1".to_string(),
            envelope_bytes("dq-score-asset-1", serde_json::to_string(&stale).unwrap()),
        );
        store.borrow_mut().insert(
            "dq-refresh-lock-asset-1".to_string(),
            envelope_bytes("dq-refresh-lock-asset-1", "9999999999".to_string()),
        );

        let mut tester = UnitTestBuilder::default()
            .with_config(config())
            .with_backend(Rc::clone(&backend))
            .with_http_upstream_from_authority("cdgclogin", cdgc_login_backend(Rc::clone(&login_calls)))
            .with_http_upstream_from_authority("cdgcapi", cdgc_score_backend(10.0))
            .with_http_upstream_from_authority("objectstoreauth", oauth_backend)
            .with_http_upstream_from_authority("objectstore", object_store_backend(Rc::clone(&store)))
            .with_entrypoint(super::configure);

        let response = tester.request(mcp_request(3));

        assert_eq!(*login_calls.borrow(), 0, "lock held elsewhere must prevent a CDGC refresh");
        assert_eq!(response.header("x-dq-gate-status"), Some("ok"));
        assert_eq!(response.header("x-dq-gate-score"), Some("95.00"));
        assert!(backend.next().is_some());
    }
}
