// Copyright 2026 Salesforce, Inc. All rights reserved.

// This module contains common Rust stuff shared between test files.

use std::time::{Duration, Instant};

// Includes fixture startup and httpmock's private remote administration client.
pub const TEST_TIMEOUT: Duration = Duration::from_secs(240);

pub fn test_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(2))
        .no_proxy()
        .build()?)
}

// Directory where the policies implementations are stored.
pub const POLICY_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/wasm32-wasip1/release");

// Directory with the common configurations for tests.
pub const COMMON_CONFIG_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/config");

// In case the project name changes, override this value with the actual policy name.
// To obtain the current name, run the "make show-policy-ref-name" goal, or read it from
// "target/policy-ref-name.txt" after building the project.
pub const POLICY_NAME: &str = "dq-gate-policy-flex-v1-0";

// The remote administration API must match the httpmock client in Cargo.toml.
const HTTPMOCK_VERSION: &str = "0.8.3";
const HTTPMOCK_IMAGE: &str = "dq-gate-httpmock-test";

pub fn httpmock_config() -> anyhow::Result<pdk_test::services::httpmock::HttpMockConfig> {
    static BUILD: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    let build = BUILD.get_or_init(|| {
        let mut child = std::process::Command::new("docker")
            .args([
                "build",
                "--tag",
                &format!("{HTTPMOCK_IMAGE}:{HTTPMOCK_VERSION}"),
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/common"),
            ])
            // Inherit output: waiting with undrained pipes can deadlock a verbose build.
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .map_err(|error| format!("Cannot build mock readiness wrapper: {error}"))?;
        let deadline = Instant::now() + Duration::from_secs(120);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                result => {
                    let kill = child.kill();
                    let wait = child.wait();
                    return Err(format!(
                        "Mock readiness wrapper build timed out after 120s or polling failed: {result:?}; kill: {kill:?}; wait: {wait:?}"
                    ));
                }
            }
        };
        if status.success() {
            Ok(())
        } else {
            Err(format!("Mock readiness wrapper build failed: {status}"))
        }
    });
    build.as_ref().map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(pdk_test::services::httpmock::HttpMockConfig::builder()
        .port(80)
        .version(HTTPMOCK_VERSION)
        .image_name(HTTPMOCK_IMAGE)
        .hostname("backend")
        .build())
}

// Host-side test I/O only. Keep blocking TCP off the async test executor.
pub async fn raw_upload_headers(socket: String, request: Vec<u8>) -> anyhow::Result<String> {
    let (sender, receiver) = futures::channel::oneshot::channel();
    std::thread::spawn(move || {
        let result = (|| -> anyhow::Result<String> {
            use std::io::{BufRead, BufReader, Write};
            use std::time::Duration;

            // The harness uses localhost; resolve it without an unbounded DNS lookup.
            let address: std::net::SocketAddr =
                if let Some(port) = socket.strip_prefix("localhost:") {
                    (std::net::Ipv4Addr::LOCALHOST, port.parse::<u16>()?).into()
                } else {
                    socket.parse()?
                };
            let mut stream =
                std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            stream.set_write_timeout(Some(Duration::from_secs(10)))?;
            stream.write_all(&request)?;
            let mut reader = BufReader::new(stream);
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                anyhow::ensure!(
                    reader.read_line(&mut line)? > 0,
                    "Gateway closed before response headers: {headers}"
                );
                let complete = line == "\r\n";
                headers.push_str(&line);
                if complete {
                    return Ok(headers);
                }
                anyhow::ensure!(headers.len() < 16384, "Response headers exceed test limit");
            }
        })();
        let _ = sender.send(result);
    });
    receiver.await?
}
