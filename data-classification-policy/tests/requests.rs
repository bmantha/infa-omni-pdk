// Copyright 2026 Salesforce, Inc. All rights reserved.

mod common;

use httpmock::MockServer;
use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::{HttpMock, HttpMockConfig};
use pdk_test::{pdk_test, TestComposite};
use serde_json::{json, Value};

use common::*;

// Flex port for the internal test network
const FLEX_PORT: Port = 8081;

const COLUMN_ID: &str = "b7e13420-4841-4bbe-86c0-002b1d9af165";
const CLASSIFICATION_ID: &str = "ceaa1ca4-764d-4458-abc8-146ffee68222";

fn policy_config_with(max_allowed: &str, overrides: Value) -> PolicyConfig {
    let mut cfg = json!({
        "cdgcLoginUrl": "http://backend",
        "cdgcBaseApiUrl": "http://backend",
        "cdgcOrgUsername": "test-username",
        "cdgcOrgPassword": "test-password",
        "governedColumnIds": COLUMN_ID,
        "maxAllowedClassification": max_allowed,
        "refreshIntervalSeconds": 86400,
        "failOpenOnCdgcError": true,
        "blockOnUnknownClassification": true,
    });
    if let (Some(base), Some(extra)) = (cfg.as_object_mut(), overrides.as_object()) {
        for (key, value) in extra {
            base.insert(key.clone(), value.clone());
        }
    }
    PolicyConfig::builder().name(POLICY_NAME).configuration(cfg).build()
}

fn policy_config(max_allowed: &str) -> PolicyConfig {
    policy_config_with(max_allowed, json!({}))
}

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

/// Mocks the CDGC Login -> JWT -> two-hop batched details sequence for a single governed column
/// linked to a single classification at the given sensitivity. Returns the individual mocks so
/// callers can assert on hit counts (e.g. to prove caching skips the whole chain).
async fn mock_cdgc<'a>(
    mock_server: &'a MockServer,
    sensitivity: &str,
) -> (httpmock::Mock<'a>, httpmock::Mock<'a>, httpmock::Mock<'a>, httpmock::Mock<'a>) {
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

    let hop1 = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST)
                .path_contains("/data360/search/v1/assets/details")
                .query_param("segments", "summary,dataClassification");
            then.status(200).json_body(json!([
                {
                    "core.identity": COLUMN_ID,
                    "summary": {"core.name": "VISIT_REASON"},
                    "dataClassification": [{"core.identity": CLASSIFICATION_ID}],
                }
            ]));
        })
        .await;

    let hop2 = mock_server
        .mock_async(move |when, then| {
            when.method(httpmock::Method::POST)
                .path_contains("/data360/search/v1/assets/details")
                .query_param("segments", "summary,selfAttributes");
            then.status(200).json_body(json!([
                {
                    "core.identity": CLASSIFICATION_ID,
                    "selfAttributes": {"core.sensitivity": sensitivity},
                }
            ]));
        })
        .await;

    (login, jwt, hop1, hop2)
}

fn mcp_request(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {}})
}

/// Builds a JSON-RPC 2.0 A2A call. The `method` alone selects the protocol AND version -- see
/// dq-gate-policy's identical helper for the full rationale.
fn a2a_request(id: u64, method: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": {"message": {"role": "user"}}})
}

#[pdk_test]
async fn allows_request_when_worst_case_rank_is_at_or_below_ceiling() -> anyhow::Result<()> {
    let (_composite, flex_url, mock_server) = compose_with_policy(policy_config("MEDIUM")).await?;

    let (_login, _jwt, hop1, hop2) = mock_cdgc(&mock_server, "MEDIUM").await;
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
        response.headers().get("x-classification-gate-status").unwrap(),
        "ok"
    );
    let body: Value = response.json().await?;
    assert_eq!(body["result"]["ok"], true);

    hop1.assert_hits_async(1).await;
    hop2.assert_hits_async(1).await;
    mcp.assert_hits_async(1).await;

    Ok(())
}

#[pdk_test]
async fn caches_the_rank_so_a_second_request_skips_cdgc() -> anyhow::Result<()> {
    // With refreshIntervalSeconds=86400 (the default), the rank resolved on the first request is
    // served from PDK-native DataStorage on the second. The CDGC chain (Login -> JWT -> two hops)
    // must therefore be hit exactly once across two requests, while both requests are forwarded
    // upstream.
    let (_composite, flex_url, mock_server) = compose_with_policy(policy_config("MEDIUM")).await?;

    let (login, jwt, hop1, hop2) = mock_cdgc(&mock_server, "MEDIUM").await;
    let mcp = mock_server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST).path_contains("/mcp");
            then.status(200)
                .json_body(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}));
        })
        .await;

    let client = reqwest::Client::new();

    let first = client
        .post(format!("{flex_url}/mcp"))
        .json(&mcp_request(1))
        .send()
        .await?;
    assert_eq!(first.status(), 200);
    assert_eq!(first.json::<Value>().await?["result"]["ok"], true);

    let second = client
        .post(format!("{flex_url}/mcp"))
        .json(&mcp_request(2))
        .send()
        .await?;
    assert_eq!(second.status(), 200);
    assert_eq!(second.json::<Value>().await?["result"]["ok"], true);

    login.assert_hits_async(1).await;
    jwt.assert_hits_async(1).await;
    hop1.assert_hits_async(1).await;
    hop2.assert_hits_async(1).await;
    mcp.assert_hits_async(2).await;

    Ok(())
}

#[pdk_test]
async fn blocks_request_when_worst_case_rank_exceeds_ceiling() -> anyhow::Result<()> {
    let (_composite, flex_url, mock_server) = compose_with_policy(policy_config("MEDIUM")).await?;

    let (_login, _jwt, hop1, _hop2) = mock_cdgc(&mock_server, "HIGH").await;
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
    assert_eq!(body["error"]["code"], -32011);

    hop1.assert_hits_async(1).await;
    mcp.assert_hits_async(0).await;

    Ok(())
}

#[pdk_test]
async fn discloses_rank_header_when_disclose_classification_details_enabled() -> anyhow::Result<()> {
    let (_composite, flex_url, mock_server) =
        compose_with_policy(policy_config_with("MEDIUM", json!({ "discloseClassificationDetails": true }))).await?;

    let (_login, _jwt, _hop1, _hop2) = mock_cdgc(&mock_server, "MEDIUM").await;
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
        response.headers().get("x-classification-gate-status").unwrap(),
        "ok"
    );
    assert_eq!(
        response.headers().get("x-classification-gate-rank").unwrap(),
        "MEDIUM"
    );

    mcp.assert_hits_async(1).await;

    Ok(())
}

#[pdk_test]
async fn exempt_method_passes_through_without_calling_cdgc() -> anyhow::Result<()> {
    // tools/list is an MCP discovery method in EXEMPT_METHODS: it must pass through ungated and,
    // crucially, must NOT trigger a CDGC classification fetch.
    let (_composite, flex_url, mock_server) = compose_with_policy(policy_config("LOW")).await?;

    let (login, jwt, hop1, hop2) = mock_cdgc(&mock_server, "HIGH").await;
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
    assert_eq!(
        response.headers().get("x-classification-gate-status").unwrap(),
        "skipped"
    );
    let body: Value = response.json().await?;
    assert_eq!(body["result"]["tools"], json!([]));

    login.assert_hits_async(0).await;
    jwt.assert_hits_async(0).await;
    hop1.assert_hits_async(0).await;
    hop2.assert_hits_async(0).await;
    mcp.assert_hits_async(1).await;

    Ok(())
}

#[pdk_test]
async fn block_response_declares_json_content_type_over_the_wire() -> anyhow::Result<()> {
    let (_composite, flex_url, mock_server) = compose_with_policy(policy_config("LOW")).await?;

    let (_login, _jwt, hop1, hop2) = mock_cdgc(&mock_server, "HIGH").await;
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
    assert_eq!(
        response.headers().get("x-classification-gate-status").unwrap(),
        "blocked"
    );
    let body: Value = response.json().await?;
    assert_eq!(body["error"]["code"], -32011);

    hop1.assert_hits_async(1).await;
    hop2.assert_hits_async(1).await;
    mcp.assert_hits_async(0).await;

    Ok(())
}

#[pdk_test]
async fn blocks_a2a_v1_send_above_ceiling_in_band_200_with_error_info() -> anyhow::Result<()> {
    // A2A v1.0 `SendMessage` above the ceiling. On the JSON-RPC binding an A2A rejection is
    // carried IN-BAND at HTTP 200 with code -32012 (outside both this policy's own MCP code
    // -32011 and A2A's own -32001..=-32009 band). error.data is a single-element array carrying a
    // google.rpc.ErrorInfo. The version is inferred from the method name alone.
    let (_composite, flex_url, mock_server) = compose_with_policy(policy_config("LOW")).await?;

    let (_login, _jwt, hop1, hop2) = mock_cdgc(&mock_server, "HIGH").await;
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
    assert_eq!(
        response.headers().get("x-classification-gate-status").unwrap(),
        "blocked"
    );
    let body: Value = response.json().await?;
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 1);
    assert_eq!(body["error"]["code"], -32012);
    let data = &body["error"]["data"];
    assert!(data.is_array(), "v1.0 error.data must be an array: {body}");
    let info = &data[0];
    assert_eq!(info["@type"], "type.googleapis.com/google.rpc.ErrorInfo");
    assert_eq!(info["reason"], "CLASSIFICATION_ABOVE_ALLOWED");
    assert_eq!(info["domain"], "data-classification-gate.mulesoft.com");
    // discloseClassificationDetails defaults false -> ErrorInfo is present but metadata is empty.
    assert_eq!(info["metadata"], json!({}));

    hop1.assert_hits_async(1).await;
    hop2.assert_hits_async(1).await;
    upstream.assert_hits_async(0).await;

    Ok(())
}

#[pdk_test]
async fn blocks_a2a_rest_send_binding_above_ceiling_native_403() -> anyhow::Result<()> {
    // The A2A HTTP+JSON (REST) message-send binding carries a bare SendMessageRequest, NOT a
    // JSON-RPC envelope, so it is recognized by the request path (final segment `message:send`)
    // rather than a method string, and answers with a NATIVE HTTP 403 + google.rpc.Status body.
    let (_composite, flex_url, mock_server) = compose_with_policy(policy_config("LOW")).await?;

    let (_login, _jwt, hop1, hop2) = mock_cdgc(&mock_server, "HIGH").await;
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
        .json(&json!({"message": {"role": "user", "parts": [{"kind": "text", "text": "hi"}]}}))
        .send()
        .await?;

    assert_eq!(response.status(), 403);
    assert_eq!(
        response.headers().get("x-classification-gate-status").unwrap(),
        "blocked"
    );
    let body: Value = response.json().await?;
    assert!(body.get("jsonrpc").is_none(), "REST Shape 3 has no jsonrpc field: {body}");
    assert!(body.get("id").is_none(), "REST Shape 3 has no id field: {body}");
    assert_eq!(body["error"]["code"], 403);
    let info = &body["error"]["details"][0];
    assert_eq!(info["@type"], "type.googleapis.com/google.rpc.ErrorInfo");
    assert_eq!(info["reason"], "CLASSIFICATION_ABOVE_ALLOWED");
    assert_eq!(info["domain"], "data-classification-gate.mulesoft.com");

    hop1.assert_hits_async(1).await;
    hop2.assert_hits_async(1).await;
    upstream.assert_hits_async(0).await;

    Ok(())
}

#[pdk_test]
async fn a2a_housekeeping_method_passes_through_without_calling_cdgc() -> anyhow::Result<()> {
    let (_composite, flex_url, mock_server) = compose_with_policy(policy_config("LOW")).await?;

    let (login, jwt, hop1, hop2) = mock_cdgc(&mock_server, "HIGH").await;
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
    assert_eq!(
        response.headers().get("x-classification-gate-status").unwrap(),
        "skipped"
    );

    login.assert_hits_async(0).await;
    jwt.assert_hits_async(0).await;
    hop1.assert_hits_async(0).await;
    hop2.assert_hits_async(0).await;
    upstream.assert_hits_async(1).await;

    Ok(())
}
