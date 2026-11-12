// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Shared storage without the SDK distributed client's raw-response error logging.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use futures::lock::Mutex;
use pdk::data_storage::{DataStorage, DataStorageError, StoreMode};
use pdk::hl::{HttpClient, Service};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

const MAX_RESPONSE_BYTES: usize = 1_048_576;
const MAX_CAS_BYTES: usize = 1024;
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// The caller supplies a validated, registered Service and a policy/config-isolated namespace.
/// TTL is in milliseconds, matching DataStorageBuilder::remote. The runtime must wrap the
/// complete resolution (including these calls) in its total deadline.
pub struct SafeRemoteDataStorage {
    client: HttpClient,
    service: Service,
    namespace: String,
    ttl_seconds: u32,
    ready: Mutex<bool>,
}

impl SafeRemoteDataStorage {
    pub fn new(client: HttpClient, service: Service, namespace: String, ttl: u32) -> Self {
        Self {
            client,
            service,
            namespace: path_segment(&namespace),
            ttl_seconds: (ttl / 1000).min(2_592_000),
            ready: Mutex::new(false),
        }
    }

    async fn ensure_namespace(&self) -> Result<(), DataStorageError> {
        // Holding an async mutex across creation serializes concurrent first operations.
        // Cancellation drops the guard with ready=false, so the next operation retries.
        let mut ready = self.ready.lock().await;
        if *ready {
            return Ok(());
        }
        let path = format!("/api/v1/stores/{}", self.namespace);
        let body = serde_json::to_vec(&serde_json::json!({
            "storeId": self.namespace,
            "defaultTtlSeconds": self.ttl_seconds,
        }))
        .map_err(|_| error("namespace serialization"))?;
        let status = self
            .client
            .request(&self.service)
            .path(&path)
            .timeout(CALL_TIMEOUT)
            .body(&body)
            .extract_with(|event, buffers| status_only(event.body_size, buffers.status_code()))
            .put()
            .await
            .map_err(|_| DataStorageError::HttpClient)??;
        match status {
            201 | 409 => {
                *ready = true;
                Ok(())
            }
            _ => Err(http_error(status)),
        }
    }

    fn key_path(&self, key: &str) -> String {
        format!(
            "/api/v1/stores/{}/partitions/{}/keys/{}",
            self.namespace,
            self.namespace,
            path_segment(key)
        )
    }
}

impl DataStorage for SafeRemoteDataStorage {
    async fn get_keys(&self) -> Result<Vec<String>, DataStorageError> {
        Err(error("unsupported operation"))
    }

    async fn store<T: Serialize>(
        &self,
        key: &str,
        mode: &StoreMode,
        item: &T,
    ) -> Result<(), DataStorageError> {
        let headers = match mode {
            StoreMode::Always => vec![],
            StoreMode::Absent => vec![("if-none-match", "*")],
            StoreMode::Cas(cas) if valid_cas(cas) => vec![("if-match", cas.as_str())],
            StoreMode::Cas(_) => return Err(error("invalid CAS")),
        };
        // Preserve the SDK's fixed-width binary format inside its BINARY JSON envelope.
        let bytes = serde_fixint::to_vec(item).map_err(|_| error("value serialization"))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(error("value exceeds size limit"));
        }
        let body = serde_json::to_vec(&serde_json::json!({
            "valueType": "BINARY", "binaryValue": STANDARD.encode(bytes),
        }))
        .map_err(|_| error("envelope serialization"))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(error("envelope exceeds size limit"));
        }
        let path = self.key_path(key);
        for attempt in 0..2 {
            self.ensure_namespace().await?;
            let status = self
                .client
                .request(&self.service)
                .path(&path)
                .timeout(CALL_TIMEOUT)
                .headers(headers.clone())
                .body(&body)
                .extract_with(|event, buffers| status_only(event.body_size, buffers.status_code()))
                .put()
                .await
                .map_err(|_| DataStorageError::HttpClient)??;
            match status {
                201 => return Ok(()),
                412 => return Err(DataStorageError::CasMismatch),
                404 if attempt == 0 => *self.ready.lock().await = false,
                _ => return Err(http_error(status)),
            }
        }
        Err(error("namespace unavailable"))
    }

    async fn get<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<(T, String)>, DataStorageError> {
        self.ensure_namespace().await?;
        let path = self.key_path(key);
        let response = self
            .client
            .request(&self.service)
            .path(&path)
            .timeout(CALL_TIMEOUT)
            .extract_with(|event, buffers| {
                let status = status_only(event.body_size, buffers.status_code())?;
                if status == 404 {
                    return Ok(None);
                }
                if status != 200 {
                    return Err(http_error(status));
                }
                let body = bounded_body(event.body_size, || buffers.body(0, event.body_size))?;
                let cas = buffers.header("etag").ok_or_else(|| error("missing CAS"))?;
                if !valid_cas(&cas) {
                    return Err(error("invalid CAS"));
                }
                Ok(Some((body, cas)))
            })
            .get()
            .await
            .map_err(|_| DataStorageError::HttpClient)??;
        let Some((body, cas)) = response else {
            return Ok(None);
        };
        let envelope: BinaryObject =
            serde_json::from_slice(&body).map_err(|_| error("invalid envelope"))?;
        if envelope.value_type != "BINARY" {
            return Err(error("invalid value type"));
        }
        let bytes = STANDARD
            .decode(envelope.binary_value)
            .map_err(|_| error("invalid binary encoding"))?;
        let item = serde_fixint::from_slice(&bytes).map_err(|_| error("invalid stored value"))?;
        Ok(Some((item, cas)))
    }

    async fn delete(&self, _key: &str) -> Result<(), DataStorageError> {
        Err(error("unsupported operation"))
    }

    async fn delete_all(&self) -> Result<(), DataStorageError> {
        Err(error("unsupported operation"))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BinaryObject {
    value_type: String,
    binary_value: String,
}

fn error(category: &'static str) -> DataStorageError {
    DataStorageError::Unexpected(format!("shared storage: {category}"))
}

fn http_error(status: u32) -> DataStorageError {
    if status == 504 {
        DataStorageError::Timeout
    } else {
        DataStorageError::Unexpected(format!("shared storage: HTTP status {status}"))
    }
}

fn status_only(size: usize, status: u32) -> Result<u32, DataStorageError> {
    if size > MAX_RESPONSE_BYTES {
        return Err(error("response exceeds size limit"));
    }
    Ok(status)
}

fn bounded_body(
    size: usize,
    read: impl FnOnce() -> Option<Vec<u8>>,
) -> Result<Vec<u8>, DataStorageError> {
    status_only(size, 200)?;
    let body = read().ok_or_else(|| error("response unavailable"))?;
    if body.len() != size {
        return Err(error("response truncated"));
    }
    Ok(body)
}

fn valid_cas(cas: &str) -> bool {
    !cas.is_empty()
        && cas.len() <= MAX_CAS_BYTES
        && cas != "*"
        && !cas.contains(',')
        && cas.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        // Escape dot-only segments as well, preventing path normalization from escaping a key.
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'~')
            || (byte == b'.' && value != "." && value != "..")
        {
            encoded.push(char::from(byte));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use pdk::hl::*;
    use pdk_unit::{
        UnitHttpMessage, UnitHttpRequest, UnitHttpResponse, UnitLogLevel, UnitTestBuilder,
    };
    use std::cell::Cell;
    use std::rc::Rc;

    async fn storage_test(launcher: Launcher, client: HttpClient) -> anyhow::Result<()> {
        let service = Service::new("storage", "http://storage.test".parse()?);
        let storage = SafeRemoteDataStorage::new(client, service, "policy-digest".into(), 30_000);
        launcher
            .launch(on_request(|state: RequestState| async {
                let state = state.into_headers_state().await;
                let operation = state.handler().header("operation").unwrap_or_default();
                let result = match operation.as_str() {
                    "concurrent" => {
                        let (first, second) = futures::join!(
                            storage.store("first", &StoreMode::Absent, &7_u32),
                            storage.store("second", &StoreMode::Absent, &7_u32)
                        );
                        first.and(second)
                    }
                    "absent" => {
                        storage
                            .store("key/with?path", &StoreMode::Absent, &7_u32)
                            .await
                    }
                    "cas" => {
                        storage
                            .store("key/with?path", &StoreMode::Cas("\"v1\"".into()), &7_u32)
                            .await
                    }
                    _ => storage.get::<u32>("key/with?path").await.and_then(|value| {
                        if value == Some((7, "\"v1\"".into())) {
                            Ok(())
                        } else {
                            Err(error("test missing value"))
                        }
                    }),
                };
                let body = match result {
                    Ok(()) => "ok".to_string(),
                    Err(err) => format!("{:#}", anyhow::Error::new(err)),
                };
                Flow::<()>::Break(Response::new(200).with_body(body))
            }))
            .await?;
        Ok(())
    }

    #[test]
    fn wire_contract_conditional_writes_and_one_namespace_creation() {
        let creations = Rc::new(Cell::new(0));
        let seen = creations.clone();
        let mut tester = UnitTestBuilder::default()
            .with_http_upstream("storage", move |req: UnitHttpRequest| {
                assert_eq!(req.header(":method"), Some("PUT"));
                if req.header(":path") == Some("/api/v1/stores/policy-digest") {
                    seen.set(seen.get() + 1);
                    let body: serde_json::Value = serde_json::from_slice(req.body()).unwrap();
                    assert_eq!(body, serde_json::json!({"storeId":"policy-digest", "defaultTtlSeconds":30}));
                    return UnitHttpResponse::new(201).into();
                }
                assert_eq!(req.header(":path"), Some("/api/v1/stores/policy-digest/partitions/policy-digest/keys/key%2Fwith%3Fpath"));
                assert!(req.header("if-none-match") == Some("*") || req.header("if-match") == Some("\"v1\""));
                let body: serde_json::Value = serde_json::from_slice(req.body()).unwrap();
                assert_eq!(body, serde_json::json!({"valueType":"BINARY", "binaryValue":"BwAAAA=="}));
                UnitHttpResponse::new(412).into()
            })
            .with_entrypoint(storage_test);
        for op in ["absent", "cas"] {
            let response = tester.request(UnitHttpRequest::get().with_header("operation", op));
            assert_eq!(response.body(), b"CAS mismatch.");
        }
        assert_eq!(creations.get(), 1);
    }

    #[test]
    fn malformed_responses_never_expose_headers_bodies_or_error_chains() {
        for (status, body) in [
            (
                200,
                "{\"valueType\":\"SECRET-MARKER\",\"binaryValue\":\"AA==\"}",
            ),
            (200, "not json SECRET-MARKER"),
            (
                200,
                "{\"valueType\":\"BINARY\",\"binaryValue\":\"SECRET-MARKER\"}",
            ),
            (503, "SECRET-MARKER"),
        ] {
            let mut tester = UnitTestBuilder::default()
                .set_log_level(UnitLogLevel::Trace)
                .with_http_upstream("storage", move |req: UnitHttpRequest| {
                    if req.header(":method") == Some("PUT") {
                        UnitHttpResponse::new(409).into()
                    } else {
                        UnitHttpResponse::new(status)
                            .with_header("secret-header", "SECRET-MARKER")
                            .with_header("etag", "\"v1\"")
                            .with_body(body)
                            .into()
                    }
                })
                .with_entrypoint(storage_test);
            let response = tester.request(UnitHttpRequest::get());
            assert!(!String::from_utf8_lossy(response.body()).contains("SECRET-MARKER"));
            assert!(tester
                .logs()
                .iter()
                .all(|log| !log.contains("SECRET-MARKER")));
        }
    }

    #[test]
    fn reads_sdk_binary_and_etag() {
        let mut tester = UnitTestBuilder::default()
            .with_http_upstream("storage", |req: UnitHttpRequest| {
                if req.header(":method") == Some("PUT") {
                    UnitHttpResponse::new(201).into()
                } else {
                    UnitHttpResponse::new(200)
                        .with_header("etag", "\"v1\"")
                        .with_body(r#"{"valueType":"BINARY","binaryValue":"BwAAAA=="}"#)
                        .into()
                }
            })
            .with_entrypoint(storage_test);
        assert_eq!(tester.request(UnitHttpRequest::get()).body(), b"ok");
    }

    #[test]
    fn failed_creation_retries_and_lost_namespace_is_recreated_once() {
        let creations = Rc::new(Cell::new(0));
        let writes = Rc::new(Cell::new(0));
        let seen_creations = creations.clone();
        let seen_writes = writes.clone();
        let mut tester = UnitTestBuilder::default()
            .with_http_upstream("storage", move |req: UnitHttpRequest| {
                if req.header(":path") == Some("/api/v1/stores/policy-digest") {
                    seen_creations.set(seen_creations.get() + 1);
                    UnitHttpResponse::new(if seen_creations.get() == 1 { 503 } else { 201 }).into()
                } else {
                    seen_writes.set(seen_writes.get() + 1);
                    UnitHttpResponse::new(if seen_writes.get() == 1 { 404 } else { 201 }).into()
                }
            })
            .with_entrypoint(storage_test);
        let failed = tester.request(UnitHttpRequest::get().with_header("operation", "absent"));
        assert_eq!(
            failed.body(),
            b"Unexpected error: shared storage: HTTP status 503."
        );
        let retried = tester.request(UnitHttpRequest::get().with_header("operation", "absent"));
        assert_eq!(retried.body(), b"ok");
        assert_eq!(creations.get(), 3);
        assert_eq!(writes.get(), 2);
    }

    #[test]
    fn concurrent_first_operations_share_namespace_creation() {
        let creations = Rc::new(Cell::new(0));
        let writes = Rc::new(Cell::new(0));
        let seen_creations = creations.clone();
        let seen_writes = writes.clone();
        let mut tester = UnitTestBuilder::default()
            .with_http_upstream("storage", move |req: UnitHttpRequest| {
                if req.header(":path") == Some("/api/v1/stores/policy-digest") {
                    seen_creations.set(seen_creations.get() + 1);
                } else {
                    seen_writes.set(seen_writes.get() + 1);
                }
                UnitHttpResponse::new(201).into()
            })
            .with_entrypoint(storage_test);
        let response =
            tester.request(UnitHttpRequest::get().with_header("operation", "concurrent"));
        assert_eq!(response.body(), b"ok");
        assert_eq!(creations.get(), 1);
        assert_eq!(writes.get(), 2);
    }

    #[test]
    fn oversize_is_rejected_before_copy_and_truncation_is_rejected() {
        let copied = Cell::new(false);
        let result = bounded_body(MAX_RESPONSE_BYTES + 1, || {
            copied.set(true);
            Some(Vec::new())
        });
        assert!(result.is_err());
        assert!(!copied.get());
        assert!(bounded_body(2, || Some(vec![0])).is_err());
        assert!(bounded_body(1, || None).is_err());
    }

    #[test]
    fn path_and_cas_inputs_cannot_change_request_semantics() {
        assert_eq!(path_segment("../a?b#c%\r\n"), "..%2Fa%3Fb%23c%25%0D%0A");
        assert_eq!(path_segment(".."), "%2E%2E");
        assert_eq!(path_segment("a b+"), "a%20b%2B");
        for cas in ["", "*", "a\r\nx: y", "a b", "v1,v2"] {
            assert!(!valid_cas(cas));
        }
        assert!(valid_cas("\"v1\""));
        assert!(!valid_cas(&"x".repeat(MAX_CAS_BYTES + 1)));
    }
}
