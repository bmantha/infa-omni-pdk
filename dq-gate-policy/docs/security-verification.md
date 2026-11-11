# Security verification

Verified locally on 2026-11-11 with PDK 1.10.0 and Flex Gateway 1.13.0:

- `make test`: 82 Rust unit tests and 12 Docker integration tests passed.
- `make test-generator`: 3 generated-config sanitization tests passed.
- `make build`: WASM and policy assets built successfully.
- `git diff --check`: passed.
- `make advisory`: FAILED, with no advisory ignores or suppressions.

The remaining vulnerability is `h2 0.3.27`, RUSTSEC-2026-0258 (unbounded empty
DATA frames). It is in the development HTTP test dependency graph through
reqwest 0.11 and httpmock 0.6/hyper 0.14. PDK-test's httpmock-facing types constrain
a direct mock upgrade. A compatible test-stack migration or upstream SDK fix is
required before the full dependency gate can pass. Unmaintained development
dependencies `async-std` and `pin-utils` also remain. Unused JWT/XML PDK features
were disabled, removing the reported vulnerable production crypto dependencies.

This is not production approval. Required gateway upload/idle limits, trusted
HTTPS egress, authentication ordering, backend isolation, upstream exclusion
semantics, and real multi-replica gossip races remain deployment verification
gates described in `spec.md`. The SDK's high-level buffered request API cannot
provide incremental upload limits while retaining the pre-forward gate; the
gateway must enforce those limits. Gossip is not linearizable, and cancellation
does not roll back already-dispatched remote writes. No live CDGC credentials,
production traffic, Exchange publication, or policy deployment was used.
