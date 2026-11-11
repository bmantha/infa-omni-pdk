// Copyright 2026 Salesforce, Inc. All rights reserved.

use anyhow::{bail, Context, Result};
use pdk_test::pdk_test;
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls");

fn run_bounded(command: &mut Command, dir: &std::path::Path) -> Result<std::process::Output> {
    let stdout = dir.join("command.stdout");
    let stderr = dir.join("command.stderr");
    let mut child = command
        .stdout(fs::File::create(&stdout)?)
        .stderr(fs::File::create(&stderr)?)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("local fixture command exceeded 60 seconds: {command:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Ok(std::process::Output {
        status,
        stdout: fs::read(stdout)?,
        stderr: fs::read(stderr)?,
    })
}

struct Stack {
    dir: PathBuf,
    project: String,
    control_port: u16,
}

impl Stack {
    fn compose(&self, args: &[&str]) -> Result<String> {
        let output = run_bounded(
            Command::new("docker")
                .args([
                    "compose",
                    "-f",
                    &format!("{FIXTURES}/compose.yaml"),
                    "-p",
                    &self.project,
                ])
                .args(args)
                .env("TLS_RUNTIME", &self.dir)
                .env("TLS_FIXTURES", FIXTURES)
                .env("TLS_CONTROL_PORT", self.control_port.to_string())
                .env(
                    "TLS_POLICY_DIR",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/target/wasm32-wasip1/release"),
                ),
            &self.dir,
        )?;
        if !output.status.success() {
            bail!(
                "docker compose {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(String::from_utf8(output.stdout)?)
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        let evidence = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/pdk-test/tls");
        let _ = fs::create_dir_all(&evidence);
        if let Ok(logs) = self.compose(&["logs", "--no-color"]) {
            let _ = fs::write(evidence.join(format!("{}.log", self.project)), logs);
        }
        // Cleanup also runs during assertion panics. Never retain generated private keys.
        let _ = self.compose(&["down", "--volumes", "--remove-orphans"]);
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[pdk_test]
#[ignore = "Flex 1.13.0/PDK 1.10 service_create callout clusters retain OS CA instead of tls-outbound trustedCA; see docs/local-verification.md"]
async fn tls_policy_callout_trust_matrix() -> Result<()> {
    let control_port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let mut trusted_chain_passed = false;
    let mut failures = Vec::new();
    // No inherited Flex env, production registration, credentials, or external Docker network.
    for (case, api_failure, trust, host, allowed) in [
        ("untrusted-login", false, None, "tls-login", false),
        ("trusted-chain", false, Some("ca.crt"), "tls-login", true),
        (
            "wrong-ca-login",
            false,
            Some("wrong-ca.crt"),
            "tls-login",
            false,
        ),
        (
            "wrong-host-login",
            false,
            Some("ca.crt"),
            "tls-wrong",
            false,
        ),
        ("untrusted-api", true, None, "tls-api", false),
        ("wrong-ca-api", true, Some("wrong-ca.crt"), "tls-api", false),
        ("wrong-host-api", true, Some("ca.crt"), "tls-wrong", false),
    ] {
        if api_failure && !trusted_chain_passed {
            println!("TLS {case}: NOT RUN (trusted Login/JWT positive control failed)");
            continue;
        }
        let dir = std::env::temp_dir().join(format!("dq-tls-{}-{case}", std::process::id()));
        fs::create_dir(&dir).context("TLS runtime directory must be new")?;
        let stack = Stack {
            dir: dir.canonicalize()?,
            project: format!("dq-tls-{}-{case}", std::process::id()),
            control_port,
        };
        fs::create_dir(stack.dir.join("certs"))?;
        fs::create_dir(stack.dir.join("flex"))?;
        let certs = run_bounded(
            Command::new("sh")
                .arg(format!("{FIXTURES}/certificates.sh"))
                .arg(stack.dir.join("certs"))
                .arg(FIXTURES),
            &stack.dir,
        )?;
        anyhow::ensure!(
            certs.status.success(),
            "Certificate generation failed: {}",
            String::from_utf8_lossy(&certs.stderr)
        );
        let registration = run_bounded(
            Command::new("docker")
                .args([
                    "run",
                    "--rm",
                    "--pull=never",
                    "--network=none",
                    "--entrypoint",
                    "flexctl",
                    "-v",
                ])
                .arg(format!(
                    "{}:/registration",
                    stack.dir.join("flex").display()
                ))
                .args([
                    "mulesoft/flex-gateway:1.13.0",
                    "registration",
                    "create",
                    "--mode",
                    "disconnected",
                    "--output-directory=/registration",
                    "dq-local-tls",
                ]),
            &stack.dir,
        )?;
        anyhow::ensure!(
            registration.status.success(),
            "Disconnected registration failed: {}",
            String::from_utf8_lossy(&registration.stderr)
        );

        let login_host = if api_failure { "tls-login" } else { host };
        let api_host = if api_failure { host } else { "tls-api" };
        let policy_ref = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/target/policy-ref-name.txt"
        ))?;
        let config = json!({
            "cdgcLoginUrl": format!("https://{login_host}:443"),
            "cdgcBaseApiUrl": format!("https://{api_host}:443"),
            "allowInsecureLocalServices": false,
            "cdgcOrgUsername": "dummy-tls-user", "cdgcOrgPassword": "dummy-tls-password",
            "cdgcAssetId": "dummy-tls-asset", "warnThreshold": 90, "blockThreshold": 80,
            "scoreAggregation": "min", "refreshIntervalSeconds": 30, "timeout": 2000,
            "distributed": false, "failOpenOnCdgcError": false, "blockOnUnknownScore": true,
            "discloseScoreDetails": false
        });
        let mut yaml = "apiVersion: gateway.mulesoft.com/v1alpha1\nkind: ApiInstance\nmetadata:\n  name: tls-ingress\nspec:\n  address: http://0.0.0.0:8081\n  services:\n    upstream:\n      address: http://backend:5000\n".to_string();
        yaml.push_str(&format!("---\napiVersion: gateway.mulesoft.com/v1alpha1\nkind: PolicyBinding\nmetadata:\n  name: tls-gate\nspec:\n  targetRef:\n    kind: ApiInstance\n    name: tls-ingress\n  policyRef:\n    name: {}\n  config: {}\n", policy_ref.trim(), config));
        // Use one explicit binding (not an inline duplicate): its metadata name becomes PDK's policy id.
        for (index, service_host) in [login_host, api_host].into_iter().enumerate() {
            let selected_trust = if (api_failure && index == 0) || (!api_failure && index == 1) {
                Some("ca.crt")
            } else {
                trust
            };
            let name = pdk::serde::service_name("tls-gate", &format!("{service_host}:443"));
            yaml.push_str(&format!("---\napiVersion: gateway.mulesoft.com/v1alpha1\nkind: Service\nmetadata:\n  name: {name}\n  namespace: default\nspec:\n  address: https://{service_host}:443\n"));
            yaml.push_str(&format!("---\napiVersion: gateway.mulesoft.com/v1alpha1\nkind: PolicyBinding\nmetadata:\n  name: tls-outbound-{index}\nspec:\n  targetRef:\n    kind: Service\n    name: {name}\n    namespace: default\n  policyRef:\n    name: tls-outbound\n  config:\n    skipValidation: false\n"));
            if let Some(file) = selected_trust {
                yaml.push_str("    trustedCA: |\n");
                for line in fs::read_to_string(stack.dir.join("certs").join(file))?.lines() {
                    yaml.push_str(&format!("      {line}\n"));
                }
            }
        }
        yaml.push_str("---\napiVersion: gateway.mulesoft.com/v1alpha1\nkind: ApiInstance\nmetadata:\n  name: tls-schema-control\nspec:\n  address: http://0.0.0.0:8082\n  services:\n    upstream:\n      address: https://tls-login:443\n---\napiVersion: gateway.mulesoft.com/v1alpha1\nkind: PolicyBinding\nmetadata:\n  name: tls-schema-control\nspec:\n  targetRef:\n    kind: Service\n    name: tls-schema-control-upstream\n  policyRef:\n    name: tls-outbound\n  config:\n    skipValidation: false\n    trustedCA: |\n");
        for line in fs::read_to_string(stack.dir.join("certs/ca.crt"))?.lines() {
            yaml.push_str(&format!("      {line}\n"));
        }
        fs::write(stack.dir.join("flex/api.yaml"), yaml)?;
        fs::write(stack.dir.join("flex/logging.yaml"), "apiVersion: gateway.mulesoft.com/v1alpha1\nkind: Configuration\nmetadata:\n  name: tls-debug\nspec:\n  logging:\n    runtimeLogs:\n      logLevel: debug\n")?;
        stack.compose(&["up", "-d", "--pull", "never"])?;
        let backend_url = format!("http://{}", stack.compose(&["port", "tls", "5000"])?.trim());
        let flex_url = format!("http://{}", stack.compose(&["port", "tls", "8081"])?.trim());
        let client = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(15))
            .build()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        for attempt in 0..100 {
            if client
                .get(format!("{backend_url}/__httpmock__/ping"))
                .timeout(Duration::from_secs(1))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            anyhow::ensure!(
                attempt < 99 && Instant::now() < deadline,
                "Mock not ready at {backend_url} within 30 seconds"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        // Use the bounded client for mock control too; httpmock's pooled adapter has no timeout.
        let mut mock_ids = Vec::new();
        for (request, body) in [
            (
                json!({"method":"POST", "path":"/identity-service/api/v1/Login", "json_body": {"username":"dummy-tls-user", "password":"dummy-tls-password"}}),
                json!({"sessionId":"dummy-session", "orgId":"dummy-org"}),
            ),
            (
                json!({"method":"GET", "path":"/identity-service/api/v1/jwt/Token"}),
                json!({"jwt_token":"dummy-jwt"}),
            ),
            (
                json!({"method":"GET", "path_includes":["/data360/search/v1/assets/"], "headers":[["authorization","Bearer dummy-jwt"]]}),
                json!({"dataQuality":[{"core.score":95.0}]}),
            ),
            (
                json!({"method":"POST", "path":"/mcp"}),
                json!({"jsonrpc":"2.0", "id":1, "result":{"ok":true}}),
            ),
        ] {
            // httpmock 0.8's wire format is an array of base64 ASCII bytes.
            let bytes = body.to_string().into_bytes();
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut encoded = Vec::new();
            for chunk in bytes.chunks(3) {
                let n = ((chunk[0] as u32) << 16)
                    | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
                    | chunk.get(2).copied().unwrap_or(0) as u32;
                encoded.extend([
                    alphabet[(n >> 18) as usize],
                    alphabet[((n >> 12) & 63) as usize],
                    if chunk.len() > 1 {
                        alphabet[((n >> 6) & 63) as usize]
                    } else {
                        b'='
                    },
                    if chunk.len() > 2 {
                        alphabet[(n & 63) as usize]
                    } else {
                        b'='
                    },
                ]);
            }
            let mock: Value = client.post(format!("{backend_url}/__httpmock__/mocks"))
                .json(&json!({"request":request, "response":{"status":200, "body":encoded, "headers":[["content-type","application/json"]]}}))
                .send().await?.error_for_status()?.json().await?;
            mock_ids.push(mock["id"].as_u64().context("mock id missing")?);
        }
        // An exempt request proves the policy loaded without warming the score cache.
        let mut ready = false;
        let deadline = Instant::now() + Duration::from_secs(30);
        for _ in 0..100 {
            if let Ok(response) = client
                .post(format!("{flex_url}/mcp"))
                .json(&json!({"jsonrpc":"2.0","id":0,"method":"tools/list"}))
                .timeout(Duration::from_secs(1))
                .send()
                .await
            {
                if response
                    .headers()
                    .get("x-dq-gate-status")
                    .is_some_and(|v| v == "skipped")
                {
                    ready = true;
                    break;
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        anyhow::ensure!(
            ready,
            "Flex/policy not ready in case {case}; inspect target/pdk-test/tls logs"
        );
        let baseline: Value = client
            .get(format!("{backend_url}/__httpmock__/mocks/{}", mock_ids[3]))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let discovery_calls = baseline["call_counter"]
            .as_u64()
            .context("baseline counter missing")?;
        // Select only public TLS validation fields; never persist the raw admin dump.
        let envoy: Value = client
            .get(format!("{backend_url}/__tls_clusters"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let mut summaries = Vec::new();
        for config in envoy["configs"].as_array().context("no configs")? {
            if let Some(clusters) = config["dynamic_active_clusters"].as_array() {
                for entry in clusters {
                    let cluster = &entry["cluster"];
                    if cluster["name"].as_str().is_some_and(|name| {
                        name.contains("tls-gate") || name.contains("tls-schema-control")
                    }) {
                        let tls = &cluster["transport_socket"]["typed_config"];
                        let validation = &tls["common_tls_context"]["validation_context"];
                        let ca = &validation["trusted_ca"];
                        summaries.push(json!({"cluster":cluster["name"], "sni":tls["sni"], "san":validation["match_typed_subject_alt_names"], "ca_file":ca["filename"], "inline_ca_matches_fixture":ca["inline_string"].as_str().is_some_and(|pem| fs::read_to_string(stack.dir.join("certs/ca.crt")).is_ok_and(|expected| expected == pem))}));
                    }
                }
            }
        }
        anyhow::ensure!(
            summaries.len() == 3,
            "expected two callout clusters and one schema control"
        );
        let evidence = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/pdk-test/tls");
        fs::create_dir_all(&evidence)?;
        fs::write(
            evidence.join(format!("{}-clusters.json", stack.project)),
            serde_json::to_string_pretty(&summaries)?,
        )?;
        println!(
            "TLS {case} effective validation: {}",
            serde_json::to_string(&summaries)?
        );
        let control = client
            .get(format!(
                "{backend_url}/__tls_schema_control/__httpmock__/ping"
            ))
            .send()
            .await?;
        anyhow::ensure!(
            control.status().is_success(),
            "correct-CA plain upstream control failed: {}",
            control.status()
        );
        println!("TLS {case}: plain HTTPS upstream correct-CA control passed");
        let response = client
            .post(format!("{flex_url}/mcp"))
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}))
            .send()
            .await?;
        assert_eq!(response.status(), 200, "{case}");
        let status = response.headers()["x-dq-gate-status"].to_str()?.to_string();
        assert!(response.headers().get("x-dq-gate-score").is_none());
        let body: Value = response.json().await?;
        let mut counts = Vec::new();
        for id in mock_ids {
            let mock: Value = client
                .get(format!("{backend_url}/__httpmock__/mocks/{id}"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            counts.push(
                mock["call_counter"]
                    .as_u64()
                    .context("mock call_counter missing")?,
            );
        }
        counts[3] = counts[3]
            .checked_sub(discovery_calls)
            .context("backend counter decreased")?;
        if allowed && status != "ok" {
            println!("TLS {case}: FAILED positive control: status={status}, counts={counts:?}");
            failures.push(format!("{case}: expected trustedCA to allow, got {status}"));
            continue;
        }
        assert_eq!(status, if allowed { "ok" } else { "blocked" }, "{case}");
        if allowed {
            assert_eq!(body["result"]["ok"], true, "{case}");
            trusted_chain_passed = true;
        } else {
            assert_eq!(body["error"]["code"], -32008, "{case}");
        }
        assert_eq!(
            counts,
            [
                u64::from(allowed || api_failure),
                u64::from(allowed || api_failure),
                u64::from(allowed),
                u64::from(allowed)
            ],
            "{case}"
        );
        println!(
            "TLS {case}: status={}, Login/JWT={}, detail/backend={}",
            if allowed { "ok" } else { "blocked" },
            usize::from(allowed || api_failure),
            usize::from(allowed)
        );
    }
    anyhow::ensure!(failures.is_empty(), "TLS matrix incomplete: {}. See target/pdk-test/tls logs; API-side negatives require a working positive control.", failures.join("; "));
    Ok(())
}
