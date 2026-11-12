// Copyright 2026 Salesforce, Inc. All rights reserved.

// This module contains common Rust stuff shared between test files.
use std::time::{Duration, Instant};

pub const TEST_TIMEOUT: Duration = Duration::from_secs(240);

pub fn test_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(2))
        .no_proxy()
        .build()?)
}

pub fn httpmock_config() -> anyhow::Result<pdk_test::services::httpmock::HttpMockConfig> {
    static BUILD: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    let build = BUILD.get_or_init(|| {
        for (image, file) in [
            ("classification-httpmock-test:0.8.3", "Dockerfile"),
            ("classification-flex-test:1.13.0", "Dockerfile.flex"),
        ] {
        let mut child = std::process::Command::new("docker")
            .args([
                "build", "--platform", "linux/amd64", "--tag", image, "--file",
                &format!("{}/tests/common/{file}", env!("CARGO_MANIFEST_DIR")),
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/common"),
            ])
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .map_err(|error| format!("Cannot build mock readiness wrapper: {error}"))?;
        let deadline = Instant::now() + Duration::from_secs(120);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                result => {
                    let kill = child.kill();
                    let wait = child.wait();
                    return Err(format!("Mock wrapper timed out after 120s or polling failed: {result:?}; kill: {kill:?}; wait: {wait:?}"));
                }
            }
        };
        if !status.success() { return Err(format!("Pinned test image build failed: {status}")); }
        }
        Ok(())
    });
    build.as_ref().map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(pdk_test::services::httpmock::HttpMockConfig::builder()
        .port(80)
        .version("0.8.3")
        .image_name("classification-httpmock-test")
        .hostname("backend")
        .build())
}

// Directory where the policies implementations are stored.
pub const POLICY_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/wasm32-wasip1/release");

// Directory with the common configurations for tests.
pub const COMMON_CONFIG_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/config");

// In case the project name changes, override this value with the actual policy name.
// To obtain the current name, run the "make show-policy-ref-name" goal, or read it from
// "target/policy-ref-name.txt" after building the project.
pub const POLICY_NAME: &str = "data-classification-policy-flex-v1-0";
