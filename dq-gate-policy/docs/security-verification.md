# Security verification

Verified locally on 2026-11-11 with PDK 1.10.0 and Flex Gateway 1.13.0:

- `make test`: 83 Rust unit tests and 17 Docker integration tests passed; one TLS diagnostic is explicitly ignored.
- `make test-generator`: 3 generated-config sanitization tests passed.
- `make build`: WASM and policy assets built successfully.
- `git diff --check`: passed.
- `make advisory` and `cargo audit --deny warnings`: passed, with no advisory ignores or suppressions.

The test stack now uses reqwest 0.12 and httpmock 0.8.3's remote-only client,
with a version/digest-pinned Docker mock server and readiness wrapper. This
removed vulnerable `h2 0.3.27`, replacing it with patched `h2 0.4.20`, and removed
the unmaintained `async-std` and `pin-utils` dependencies. Unused JWT/XML PDK
features were disabled, removing the reported vulnerable production crypto
dependencies. Container OS/package vulnerabilities were not scanned.

This is not production approval. Required gateway upload/idle limits, trusted
HTTPS egress, authentication ordering, backend isolation, upstream exclusion
semantics, and real multi-replica gossip races remain deployment verification
gates described in `spec.md`. Local buffer and stream-idle checks now pass
with zero dependency/backend calls on denial; see `upload-verification.md`.
The opt-in TLS matrix has a failing correct-CA policy callout control on
Flex 1.13.0/PDK 1.10.0; see `local-verification.md`. A plain HTTPS upstream
retains the CA, but policy-registered callout clusters use the OS trust store.
The diagnostic is ignored in normal tests, not claimed as successful. A
deterministic replica model proves divergence under withheld replication;
see `distributed-verification.md`. No real gossip backend was verified.
The SDK's high-level buffered request API cannot
provide incremental upload limits while retaining the pre-forward gate; the
gateway must enforce those limits. Gossip is not linearizable, and cancellation
does not roll back already-dispatched remote writes. No live CDGC credentials,
production traffic, Exchange publication, or policy deployment was used.
