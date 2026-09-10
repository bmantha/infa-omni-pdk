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
