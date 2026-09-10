// Copyright 2026 Salesforce, Inc. All rights reserved.

mod common;

use httpmock::MockServer;
use pdk_test::{pdk_test, TestComposite};
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, FlexConfig, Flex, PolicyConfig};
use pdk_test::services::httpmock::{HttpMockConfig, HttpMock};
use serde_json::{json, Value};

use common::*;

// Flex port for the internal test network
const FLEX_PORT: Port = 8081;

fn policy_config(warn_threshold: u32, block_threshold: u32) -> PolicyConfig {
    PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(json!({
            "cdgcLoginUrl": "http://backend",
            "cdgcBaseApiUrl": "http://backend",
            "cdgcOrgUsername": "test-username",
            "cdgcOrgPassword": "test-password",
            "cdgcAssetId": "demo-asset-1",
            "warnThreshold": warn_threshold,
            "blockThreshold": block_threshold,
            "scoreAggregation": "min",
            "refreshIntervalSeconds": 86400,
            "failOpenOnCdgcError": true,
            "blockOnUnknownScore": false,
        }))
        .build()
}

async fn compose(warn_threshold: u32, block_threshold: u32) -> anyhow::Result<(TestComposite, String, MockServer)> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();

    let api_config = ApiConfig::builder()
        .name("myApi")
        .upstream(&httpmock_config)
        .path("/mcp/")
        .port(FLEX_PORT)
        .policies([policy_config(warn_threshold, block_threshold)])
        .build();

    let flex_config = FlexConfig::builder()
        .version("1.13.0")
        .hostname("local-flex")
        .with_api(api_config)
        .config_mounts([(POLICY_DIR, "policy"), (COMMON_CONFIG_DIR, "common")])
        .build();

    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;

    let flex: Flex = composite.service()?;
    let flex_url = flex.external_url(FLEX_PORT).unwrap();

    let httpmock: HttpMock = composite.service()?;
    let mock_server = MockServer::connect_async(httpmock.socket()).await;

    Ok((composite, flex_url, mock_server))
}

/// Same base configuration as [`policy_config`], with `overrides` merged over the top so a test
/// can flip an extra property (e.g. `discloseScoreDetails`) without duplicating the whole config.
fn policy_config_with(warn_threshold: u32, block_threshold: u32, overrides: Value) -> PolicyConfig {
    let mut cfg = json!({
        "cdgcLoginUrl": "http://backend",
        "cdgcBaseApiUrl": "http://backend",
        "cdgcOrgUsername": "test-username",
        "cdgcOrgPassword": "test-password",
        "cdgcAssetId": "demo-asset-1",
        "warnThreshold": warn_threshold,
        "blockThreshold": block_threshold,
        "scoreAggregation": "min",
        "refreshIntervalSeconds": 86400,
        "failOpenOnCdgcError": true,
        "blockOnUnknownScore": false,
    });
    if let (Some(base), Some(extra)) = (cfg.as_object_mut(), overrides.as_object()) {
        for (key, value) in extra {
            base.insert(key.clone(), value.clone());
        }
    }
    PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(cfg)
        .build()
}

/// Like [`compose`], but installs a caller-built [`PolicyConfig`] so a test can vary policy
/// configuration beyond the two thresholds. Kept separate from `compose` so the existing
/// threshold-only callers are untouched.
async fn compose_with_policy(policy: PolicyConfig) -> anyhow::Result<(TestComposite, String, MockServer)> {
    let httpmock_config = HttpMockConfig::builder()
        .port(80)
        .version("latest")
        .hostname("backend")
        .build();

    let api_config = ApiConfig::builder()
        .name("myApi")
        .upstream(&httpmock_config)
        .path("/mcp/")
        .port(FLEX_PORT)
        .policies([policy])
        .build();

    let flex_config = FlexConfig::builder()
        .version("1.13.0")
        .hostname("local-flex")
        .with_api(api_config)
        .config_mounts([(POLICY_DIR, "policy"), (COMMON_CONFIG_DIR, "common")])
        .build();

    let composite = TestComposite::builder()
        .with_service(flex_config)
        .with_service(httpmock_config)
        .build()
        .await?;

    let flex: Flex = composite.service()?;
    let flex_url = flex.external_url(FLEX_PORT).unwrap();

    let httpmock: HttpMock = composite.service()?;
    let mock_server = MockServer::connect_async(httpmock.socket()).await;

    Ok((composite, flex_url, mock_server))
}

// Mocks the CDGC Login -> JWT -> asset-detail sequence, returning the given DQ score for
// the asset. Returns the individual mocks so callers can assert on hit counts.
async fn mock_cdgc<'a>(mock_server: &'a MockServer, score: f64) -> (httpmock::Mock<'a>, httpmock::Mock<'a>, httpmock::Mock<'a>) {
    let login = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST)
                .path_contains("/identity-service/api/v1/Login");
            then.status(200)
                .json_body(json!({"sessionId": "mock-session-1", "orgId": "mock-org-1"}));
        })
        .await;

    let jwt = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::GET)
                .path_contains("/identity-service/api/v1/jwt/Token");
            then.status(200).json_body(json!({"jwt_token": "mock-jwt-token"}));
        })
        .await;

    let detail = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::GET)
                .path_contains("/data360/search/v1/assets/");
            then.status(200)
                .json_body(json!({"dataQuality": [{"core.score": score}]}));
        })
        .await;

    (login, jwt, detail)
}

fn mcp_request(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {}})
}

/// Builds a JSON-RPC 2.0 A2A call. The `method` alone selects the protocol AND version: A2A v0.3.0
/// (`message/send`), A2A v1.0 (`SendMessage`), and A2A housekeeping (`tasks/get`, `GetTask`, ...) are
/// mutually disjoint from each other and from MCP (`tools/call`), so no `A2A-Version` header is needed
/// on the JSON-RPC transport (that header disambiguates only the REST send binding).
fn a2a_request(id: u64, method: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": {"message": {"role": "user"}}})
}

#[pdk_test]
async fn allows_request_when_dq_score_is_healthy() -> anyhow::Result<()> {
    let (_composite, flex_url, mock_server) = compose(90, 80).await?;

    let (_login, _jwt, detail) = mock_cdgc(&mock_server, 95.0).await;
    let mcp = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path_contains("/mcp");
            then.status(200)
                .json_body(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}));
        })
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/mcp"))
        .json(&mcp_request(1))
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    let body: Value = response.json().await?;
    assert_eq!(body["result"]["ok"], true);

    detail.assert_hits_async(1).await;
    mcp.assert_hits_async(1).await;

    Ok(())
}

#[pdk_test]
async fn caches_the_dq_score_so_a_second_request_skips_cdgc() -> anyhow::Result<()> {
    // With refreshIntervalSeconds=86400 (the policy_config default), the score fetched on the
    // first request is served from PDK-native DataStorage on the second. The CDGC chain
    // (Login -> JWT -> asset detail) must therefore be hit exactly once across two requests,
    // while both requests are forwarded upstream.
    let (_composite, flex_url, mock_server) = compose(90, 80).await?;

    let (login, jwt, detail) = mock_cdgc(&mock_server, 95.0).await;
    let mcp = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path_contains("/mcp");
            then.status(200)
                .json_body(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}));
        })
        .await;

    let client = reqwest::Client::new();

    // First request: cold cache -> triggers the CDGC fetch.
    let first = client
        .post(format!("{flex_url}/mcp"))
        .json(&mcp_request(1))
        .send()
        .await?;
    assert_eq!(first.status(), 200);
    assert_eq!(first.json::<Value>().await?["result"]["ok"], true);

    // Second request within the TTL: must be a pure cache read, no CDGC round-trip.
    let second = client
        .post(format!("{flex_url}/mcp"))
        .json(&mcp_request(2))
        .send()
        .await?;
    assert_eq!(second.status(), 200);
    assert_eq!(second.json::<Value>().await?["result"]["ok"], true);

    // CDGC chain hit exactly once despite two gated requests; both reached the upstream.
    login.assert_hits_async(1).await;
    jwt.assert_hits_async(1).await;
    detail.assert_hits_async(1).await;
    mcp.assert_hits_async(2).await;

    Ok(())
}

#[pdk_test]
async fn blocks_request_when_dq_score_is_below_block_threshold() -> anyhow::Result<()> {
    let (_composite, flex_url, mock_server) = compose(90, 80).await?;

    let (_login, _jwt, detail) = mock_cdgc(&mock_server, 50.0).await;
    let mcp = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path_contains("/mcp");
            then.status(200)
                .json_body(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}));
        })
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/mcp"))
        .json(&mcp_request(1))
        .send()
        .await?;

    // JSON-RPC errors are protocol-level: the HTTP status stays 200.
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await?;
    assert_eq!(body["id"], 1);
    assert_eq!(body["error"]["code"], -32008);

    detail.assert_hits_async(1).await;
    mcp.assert_hits_async(0).await;

    Ok(())
}

#[pdk_test]
async fn allows_request_with_a_warning_when_dq_score_is_below_warn_threshold() -> anyhow::Result<()> {
    let (_composite, flex_url, mock_server) = compose(90, 80).await?;

    let (_login, _jwt, detail) = mock_cdgc(&mock_server, 80.0).await;
    let mcp = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path_contains("/mcp");
            then.status(200)
                .json_body(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}));
        })
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/mcp"))
        .json(&mcp_request(1))
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("x-dq-gate-status").unwrap(),
        "warn"
    );
    let body: Value = response.json().await?;
    assert_eq!(body["result"]["ok"], true);

    detail.assert_hits_async(1).await;
    mcp.assert_hits_async(1).await;

    Ok(())
}

#[pdk_test]
async fn discloses_dq_score_header_when_disclose_score_details_enabled() -> anyhow::Result<()> {
    // With discloseScoreDetails=true, an allowed (ok) response must carry the exact numeric score
    // in the x-dq-gate-score header (formatted to 2dp), alongside the coarse x-dq-gate-status.
    // The default (disclose=false) path -- exercised by the other allow tests -- emits status only,
    // so this proves the opt-in disclosure branch end-to-end through the response filter.
    let (_composite, flex_url, mock_server) =
        compose_with_policy(policy_config_with(90, 80, json!({ "discloseScoreDetails": true }))).await?;

    let (_login, _jwt, _detail) = mock_cdgc(&mock_server, 95.0).await;
    let mcp = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path_contains("/mcp");
            then.status(200)
                .json_body(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}));
        })
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/mcp"))
        .json(&mcp_request(1))
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get("x-dq-gate-status").unwrap(), "ok");
    assert_eq!(response.headers().get("x-dq-gate-score").unwrap(), "95.00");
    let body: Value = response.json().await?;
    assert_eq!(body["result"]["ok"], true);

    mcp.assert_hits_async(1).await;

    Ok(())
}

#[pdk_test]
async fn exempt_method_passes_through_without_calling_cdgc() -> anyhow::Result<()> {
    // tools/list is an MCP discovery method in EXEMPT_METHODS: it must pass through ungated and,
    // crucially, must NOT trigger a CDGC score fetch (the gate short-circuits before resolve_score).
    // So the whole CDGC chain (Login/JWT/Detail) stays at zero hits while the request still reaches
    // the upstream and the response is annotated with status "skipped".
    let (_composite, flex_url, mock_server) = compose(90, 80).await?;

    let (login, jwt, detail) = mock_cdgc(&mock_server, 95.0).await;
    let mcp = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path_contains("/mcp");
            then.status(200)
                .json_body(json!({"jsonrpc": "2.0", "id": 7, "result": {"tools": []}}));
        })
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/mcp"))
        .json(&json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}))
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get("x-dq-gate-status").unwrap(), "skipped");
    let body: Value = response.json().await?;
    assert_eq!(body["result"]["tools"], json!([]));

    // Exempt methods never touch CDGC.
    login.assert_hits_async(0).await;
    jwt.assert_hits_async(0).await;
    detail.assert_hits_async(0).await;
    // ...but the request still reaches the upstream.
    mcp.assert_hits_async(1).await;

    Ok(())
}

#[pdk_test]
async fn block_response_declares_json_content_type_over_the_wire() -> anyhow::Result<()> {
    // A below-threshold block is a synthetic Flow::Break response built by block_response, which
    // must set content-type: application/json (JSON-RPC clients parse the error object) and the
    // coarse x-dq-gate-status: blocked header. This asserts those headers survive over the wire,
    // not just the -32008 error code the other block test checks.
    let (_composite, flex_url, mock_server) = compose(90, 80).await?;

    let (_login, _jwt, detail) = mock_cdgc(&mock_server, 50.0).await;
    let mcp = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path_contains("/mcp");
            then.status(200)
                .json_body(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}));
        })
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/mcp"))
        .json(&mcp_request(1))
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    assert!(response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()?
        .contains("application/json"));
    assert_eq!(response.headers().get("x-dq-gate-status").unwrap(), "blocked");
    let body: Value = response.json().await?;
    assert_eq!(body["error"]["code"], -32008);

    // Blocked request must never reach the upstream; CDGC was consulted once for the score.
    detail.assert_hits_async(1).await;
    mcp.assert_hits_async(0).await;

    Ok(())
}

#[pdk_test]
async fn blocks_a2a_v1_send_below_block_threshold_in_band_200_with_error_info() -> anyhow::Result<()>
{
    // A2A v1.0 `SendMessage` on a below-threshold asset. On the JSON-RPC binding an A2A rejection is
    // carried IN-BAND at HTTP 200 (returning an HTTP 4xx for a well-formed JSON-RPC call is a spec
    // mistake) inside the JSON-RPC envelope with code -32010 (outside A2A's own -32001..=-32009 band).
    // On v1.0 `error.data` is a single-element array carrying a google.rpc.ErrorInfo with the
    // policy-owned reason/domain (pdk-a2a Shape 2). The version is inferred from the method name alone
    // -- no A2A-Version header.
    let (_composite, flex_url, mock_server) = compose(90, 80).await?;

    let (_login, _jwt, detail) = mock_cdgc(&mock_server, 50.0).await;
    let upstream = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path_contains("/mcp");
            then.status(200)
                .json_body(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}));
        })
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/mcp"))
        .json(&a2a_request(1, "SendMessage"))
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get("x-dq-gate-status").unwrap(), "blocked");
    let body: Value = response.json().await?;
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1);
    assert_eq!(body["error"]["code"], -32010);
    // v1.0: error.data is a single-element [ErrorInfo] array (Shape 2), not a bare object.
    let data = &body["error"]["data"];
    assert!(data.is_array(), "v1.0 error.data must be an array: {body}");
    let info = &data[0];
    assert_eq!(info["@type"], "type.googleapis.com/google.rpc.ErrorInfo");
    assert_eq!(info["reason"], "DATA_QUALITY_BELOW_THRESHOLD");
    assert_eq!(info["domain"], "dq-gate.mulesoft.com");
    // discloseScoreDetails defaults false -> ErrorInfo is present but its metadata is empty.
    assert_eq!(info["metadata"], json!({}));

    detail.assert_hits_async(1).await;
    upstream.assert_hits_async(0).await;

    Ok(())
}

#[pdk_test]
async fn blocks_a2a_v03_send_below_block_threshold_in_band_200_free_form() -> anyhow::Result<()> {
    // A2A v0.3.0 `message/send`: same in-band HTTP 200 + JSON-RPC -32010 envelope as v1.0, but
    // v0.3.0's error.data is free-form (Shape 1) and (with disclosure off) omitted entirely -- there
    // is no ErrorInfo envelope on Legacy.
    let (_composite, flex_url, mock_server) = compose(90, 80).await?;

    let (_login, _jwt, detail) = mock_cdgc(&mock_server, 50.0).await;
    let upstream = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path_contains("/mcp");
            then.status(200)
                .json_body(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}));
        })
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/mcp"))
        .json(&a2a_request(1, "message/send"))
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    let body: Value = response.json().await?;
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1);
    assert_eq!(body["error"]["code"], -32010);
    // v0.3.0 + disclosure off -> no error.data at all.
    assert!(body["error"]["data"].is_null());

    detail.assert_hits_async(1).await;
    upstream.assert_hits_async(0).await;

    Ok(())
}

#[pdk_test]
async fn allows_a2a_send_when_dq_score_is_healthy() -> anyhow::Result<()> {
    // A healthy score lets an A2A v1.0 `SendMessage` through to the upstream agent, tagged ok -- the
    // score gate is protocol-agnostic on the allow path, exactly as for MCP.
    let (_composite, flex_url, mock_server) = compose(90, 80).await?;

    let (_login, _jwt, detail) = mock_cdgc(&mock_server, 95.0).await;
    let upstream = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path_contains("/mcp");
            then.status(200)
                .json_body(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}));
        })
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/mcp"))
        .json(&a2a_request(1, "SendMessage"))
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get("x-dq-gate-status").unwrap(), "ok");
    let body: Value = response.json().await?;
    assert_eq!(body["result"]["ok"], true);

    detail.assert_hits_async(1).await;
    upstream.assert_hits_async(1).await;

    Ok(())
}

#[pdk_test]
async fn a2a_housekeeping_method_passes_through_without_calling_cdgc() -> anyhow::Result<()> {
    // A2A task/config/discovery housekeeping (here `tasks/get`) touches no asset data and is exempt:
    // even on a below-threshold asset it must pass through ungated WITHOUT fetching a score. This is
    // the fix for the pre-existing latent bug where everything non-exempt was gated as MCP, which
    // would have wrongly blocked A2A housekeeping. The whole CDGC chain stays at zero hits.
    let (_composite, flex_url, mock_server) = compose(90, 80).await?;

    let (login, jwt, detail) = mock_cdgc(&mock_server, 50.0).await;
    let upstream = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path_contains("/mcp");
            then.status(200)
                .json_body(json!({"jsonrpc": "2.0", "id": 9, "result": {"task": {}}}));
        })
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/mcp"))
        .json(&a2a_request(9, "tasks/get"))
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get("x-dq-gate-status").unwrap(), "skipped");

    // Exempt housekeeping never touches CDGC...
    login.assert_hits_async(0).await;
    jwt.assert_hits_async(0).await;
    detail.assert_hits_async(0).await;
    // ...but still reaches the upstream agent.
    upstream.assert_hits_async(1).await;

    Ok(())
}

#[pdk_test]
async fn blocks_a2a_rest_send_binding_below_block_threshold() -> anyhow::Result<()> {
    // The A2A HTTP+JSON (REST) message-send binding carries a bare SendMessageRequest, NOT a JSON-RPC
    // envelope, so it is recognized by the request path (final segment `message:send`) rather than a
    // method string. Unlike the JSON-RPC binding (in-band HTTP 200), the REST binding answers with a
    // NATIVE HTTP 403 and a google.rpc.Status body (pdk-a2a Shape 3): `{error:{code,message,details}}`
    // with `error.code` mirroring the HTTP status and `error.details` a single-element [ErrorInfo]
    // array -- and NO jsonrpc/id fields. This proves the path-based recognition end-to-end through the
    // gateway, complementing the unit-level REST binding coverage.
    let (_composite, flex_url, mock_server) = compose(90, 80).await?;

    let (_login, _jwt, detail) = mock_cdgc(&mock_server, 50.0).await;
    let upstream = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path_contains("/mcp");
            then.status(200)
                .json_body(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}));
        })
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{flex_url}/mcp/message:send"))
        .header("A2A-Version", "1.0")
        // A bare SendMessageRequest body -- deliberately not a JSON-RPC envelope.
        .json(&json!({"message": {"role": "user", "parts": [{"kind": "text", "text": "hi"}]}}))
        .send()
        .await?;

    // Shape 3: native HTTP 403, google.rpc.Status body, no JSON-RPC envelope.
    assert_eq!(response.status(), 403);
    assert_eq!(response.headers().get("x-dq-gate-status").unwrap(), "blocked");
    let body: Value = response.json().await?;
    assert!(body.get("jsonrpc").is_none(), "REST Shape 3 has no jsonrpc field: {body}");
    assert!(body.get("id").is_none(), "REST Shape 3 has no id field: {body}");
    // error.code mirrors the HTTP status (403), not a JSON-RPC code.
    assert_eq!(body["error"]["code"], 403);
    let info = &body["error"]["details"][0];
    assert_eq!(info["@type"], "type.googleapis.com/google.rpc.ErrorInfo");
    assert_eq!(info["reason"], "DATA_QUALITY_BELOW_THRESHOLD");
    assert_eq!(info["domain"], "dq-gate.mulesoft.com");

    detail.assert_hits_async(1).await;
    upstream.assert_hits_async(0).await;

    Ok(())
}
