# Classification Gate Security Verification

## Scope And Status

Date: 2026-11-11. Scope: the current working-branch `data-classification-policy` definition,
Rust implementation, storage adapter, generation/build tooling, CI, mocks, and local demo.
The 23 confirmed review concerns have implementation dispositions below. **Implemented does
not mean independently verified in production or approved for release.** Local compile/unit,
build, advisory, and Docker evidence is recorded below for the uncommitted working tree.

This record supersedes the README's narrow initializer-only evidence statement. It does not
apply the classification changes to `dq-gate-policy` or `freshness-gate-policy`. No live CDGC
credentials, production traffic, shared backend, deployment, catalog changes, commit, or push
were used for this documentation update.

## Finding Disposition

The IDs below are local traceability numbers for the 23 remediation subjects, not reconstructed
severity IDs from a separate review. Regression names identify source evidence, not a claim
that a final execution passed. Paths are relative to this policy directory unless stated otherwise.

| ID | Review concern | Implemented disposition and source/regression mapping |
|---|---|---|
| 01 | Credential-bearing configuration diagnostics | `src/lib.rs` `parse_config` and hand-authored `init` discard raw Serde chains; `configuration_errors_omit_credentials_and_untrusted_values`, `flex_initialization_rejects_invalid_config_before_registering_services`. |
| 02 | Generator recreates unsafe initialization | Atomic `scripts/generate-config.mjs` plus `sanitize-config.mjs` removes the recognized initializer; drift/failure leaves `compile_error!`; six generator regressions include the real pinned generator and missing Node. |
| 03 | Strict-mode stale allows after refresh failure/contention | `resolve_max_rank` checks fail-open posture on contention/error paths; `strict_stale_contention_and_storage_errors_never_serve_allow_cache`. |
| 04 | Semantic failures reuse stale LOW | Typed `IntegrityFailure` separates invalid metadata from transient errors; `integrity_failures_never_reuse_stale_rank_including_the_next_request`, `missing_unknown_and_duplicate_sensitivities_are_integrity_failures`. |
| 05 | Failed invalidation leaves old allow usable | `invalidate_rank` marks bounded local quarantine before storage; `integrity_write_failure_quarantines_old_allow_across_requests`. |
| 06 | Cancellation clears or skips integrity fencing | Quarantine survives canceled invalidation; generation/observation checks constrain clearing after commit; `cancellation_of_invalidation_preserves_local_quarantine`. |
| 07 | Remote source/account/column state collisions | `rank_cache_key` digests source URLs, username, canonical columns; policy-metadata digest scopes remote namespaces; `cache_identity_is_opaque_and_isolates_sources_accounts_and_column_sets`. |
| 08 | Old cache layouts/observations remain trusted | Rank/lock namespace `v3` invalidates older/name-only state; current cache shape is required. See namespace constants and `cache_validation_rejects_inconsistent_ranks_columns_names_and_timestamps`. |
| 09 | REST path overridden by exempt RPC body | REST send path is authoritative before RPC exemptions; `protocol_camouflage_missing_ids_batches_depth_and_media_types`. |
| 10 | Malformed/deep/batched JSON bypass | Inspected JSON parse failures and non-single envelopes reject, not skip; same protocol regression covers these inputs. |
| 11 | Missing/invalid invocation ID bypass | Gated RPC calls require string/number IDs; notification exemption is limited to `notifications/*` without ID; same protocol regression. |
| 12 | Exempt traffic buffered unnecessarily / MIME ambiguity | Headers-first POST/MIME exclusions and explicit REST controls; accepted MIME boundary documented, not claimed universally fail-closed; `explicit_rest_controls_skip_even_empty_or_malformed_bodies`. |
| 13 | Unbounded request bytes/upload wait | 1 MiB declared/actual limit and 10s atomic wait in `request_filter`; `declared_and_actual_request_limits_fail_before_upstream`; gateway buffer still required. |
| 14 | Storage waits exceed resolution budget | Timer races complete resolution, including read/lock/commit/CAS; `total_timer_deadline_cancels_cache_read_lock_write_commit_and_cas_read`. |
| 15 | Older/equal refresh overwrites newer winner | Bounded CAS/Absent writes validate and order observation-start timestamps; `cas_older_equal_observations_return_the_validated_winner_and_errors_are_unknown`. |
| 16 | Fallback uses stale request snapshot | `fallback_rank` rereads current validated storage winner; `fallback_rereads_concurrent_high_and_invalidation_winners`, `cache_read_validates_against_time_after_await_not_request_start`. |
| 17 | Invalid/future cache and unsafe lock time arithmetic | Shape, rank, name/count, timestamp validation and safe lease arithmetic; `invalid_future_cache_is_refreshed_and_replaced`, `refresh_lock_future_overflow_and_contention_are_safe`. |
| 18 | Arbitrary named asset becomes unclassified | Exact `systemAttributes['core.classType']` relational Column discriminator plus meaningful summary; `named_non_column_or_missing_class_type_never_becomes_unclassified_or_stale_allow`. |
| 19 | Incomplete/duplicate/oversized CDGC identities and classifications | Requested identity membership/uniqueness/completeness, exact tiers, and bounded columns/links/names/tokens/responses; `cdgc_auth_integrity_and_response_size_fail_closed_with_stale_cache`, `response_extractor_checks_size_and_status_without_copying`. |
| 20 | Insecure CDGC services / invalid semantic configuration | HTTPS by default, explicit dummy-local HTTP opt-in, no URL userinfo, validated ceiling/timeouts/TTL/IDs/credentials; `semantic_configuration_bounds_and_https_are_enforced`. Destination/trust approval remains external. |
| 21 | SDK distributed logging/startup hazards | `src/storage.rs` `SafeRemoteDataStorage` bypasses SDK raw-response error logging; coordinates checked before construction; `distributed_missing_coordinates_fails_before_remote_storage`, `local_mode_works_without_anypoint`, seven adapter regressions. |
| 22 | Upstream disclosure spoofing / incompatible block details | Reserved headers removed case-insensitively; opt-in policy detail only, ErrorInfo metadata string map; `upstream_reserved_headers_are_removed_even_on_skipped_requests`, `error_info_metadata_is_a_string_map`. |
| 23 | Reproducibility, test deadlines, mock drift, and unsafe demo tooling | Locked Make commands, pinned dependencies/tools/images/actions, advisory gate and CI; bounded process-group runner, mock contract regressions, exact local fixture/dotenv guards, single selected ApiInstance mount. `scripts/*test.mjs`, `playground/mocks/test_mock_server.py`, `tests/common/*`, and root `.github/workflows/classification-gate.yml`. |

## Load-Bearing Contracts

### Classification Integrity

Hop 1 uses `segments=summary,systemAttributes,dataClassification`; the authoritative published
example places the discriminator in `systemAttributes['core.classType']`:
[Informatica: Retrieve Details of Multiple Assets, Example Request](https://docs.informatica.com/data-governance-and-quality-cloud/data-governance-and-catalog/current-version/api-reference/search-for-assets/retrieve-details-of-multiple-assets/example-request.html).
The supported value is exactly `com.infa.odin.models.relational.Column`. Neither `core.type`,
name presence alone, nor a type suffix is evidence of a relational Column. `ViewColumn`, tables,
missing/wrong types, and identity-only responses are unknown. A validated Column with a valid
name and no classification key/empty list is rank 0. Hop 2 requires every referenced identity
and exact LOW/MEDIUM/HIGH sensitivity.

Invalid catalog/auth JSON, identities, tiers, bounds, or cache shape cannot authorize via stale
LOW. Transient transport/non-success status errors can use a validated stale winner only when
`failOpenOnCdgcError` permits it. Unknown still follows `blockOnUnknownClassification`: its
default is block, but setting it false deliberately passes ungated. Thus integrity handling is
not an unconditional block independent of configuration.

### Storage, Ordering, And Cancellation

Remote `v3` namespaces digest policy namespace/name/filter identity; keys digest source URLs,
account username, and canonical columns. The password is not fingerprinted. Digests reduce
plaintext exposure and separate state semantics; they are not access control or encryption.
Old namespaces are not migrated into trust. Local PDK stores retain their policy-isolation path.

CAS/Absent writes compare validated observation-start timestamps with three retries. Returned
winners, not uncommitted fetched values, drive allows. Invalid/future cache can be replaced by a
validated refresh. Transient fallback rereads the stored winner. Locks use 30s leases without
delete/tombstone release. These mechanisms do not establish global mutual exclusion or catalog
revision ordering under gossip partitions or clock skew.

One immutable policy configuration owns one bounded local quarantine slot. Integrity failure
marks it before persistence; cancellation drops awaited work but does not undo that mark.
Only an acceptable validated committed winner with unchanged quarantine generation clears it.
Persisted invalidation is best effort within the total deadline. A different replica, restarted
instance, or lagging backend can still lack that quarantine state.

### Safe Remote Adapter

The custom adapter deliberately bypasses the pinned SDK distributed error path that can expose
raw response material. Its implemented low-level contract is:

- PUT `/api/v1/stores/{namespace}` with `storeId` and `defaultTtlSeconds`; 201/409 establishes
  readiness. An async mutex serializes creation; canceled/failed creation remains retryable.
- Key paths use the namespace as store and partition, and percent-encode keys/path segments.
  Writes carry fixed-width serialized bytes in a base64 `BINARY` JSON envelope.
- `StoreMode::Absent` sends `If-None-Match: *`; CAS sends a bounded validated `If-Match` ETag.
  Write 201 succeeds, 412 maps to CAS mismatch, and a lost namespace allows one recreation retry.
- Read 200 requires a valid ETag and binary envelope; 404 means absent. Responses/writes are
  bounded to 1 MiB; call timeouts are 10s inside the separate total-resolution deadline.
  Error diagnostics retain only categories/status, not remote headers, bodies, or raw chains.
- Enumeration/deletion are unsupported; this policy uses get and conditional writes only.

Adapter tests exercise the assumed SDK-compatible wire shape, concurrent/retried namespace
creation, ETags, encoding, response limits, and dummy-marker nondisclosure. They are not live
shared-storage interoperability, authentication, TLS, or partition tests.

### Transport, Resources, And Secrets

POST JSON/A2A JSON is fail-closed for malformed/deep/batched invocations, not for excluded MIME
types or transports. Explicit control routes bypass body validation. Requests hold headers/body
atomically for at most 10s with 1 MiB policy limits; resolution has a separate 10s total timer
covering storage and persistence. CDGC response size is checked before copying. Configure the
host's connection buffer to 1 MiB; aggregate concurrent streams require separate load controls.

Configuration validates at most 32 columns, 256-byte IDs, 32 links per column, 256 distinct
classifications, 128-byte names, 8192-byte account/password/token values, a 30s minimum TTL,
and 1-10000ms call timeout. HTTPS/no-userinfo rules apply to CDGC services; shared storage uses
validated gateway coordinates and allows HTTP or HTTPS, so its network protection is external.
The local HTTP opt-in does not enforce a loopback hostname whitelist.

Safe config/CDGC diagnostics and the adapter remove identified raw logging paths, not every
possible gateway/SDK log. Governance IDs/names/ranks still appear in policy logs. Inspect host
logs and rotate credentials if earlier unsafe configuration errors may have exposed them.

## Verification Evidence

Executed locally on 2026-11-11 on branch `fix/classification-full-security-hardening`, based on
`7e55dff138e77e1400d10b42468695205e0c26f4`, with the uncommitted remediation diff. No hosted CI
or live CDGC/shared-storage calls were used. The previous initializer-only evidence is superseded.
Two independent source reviews and a follow-up demo review found no remaining confirmed must-fix
issues after remediation; this is not production sign-off.

| Surface | Command from policy directory | Evidence status |
|---|---|---|
| Unit/generation/tooling | `make test-unit` | Exit 0: 59 Rust tests, including seven adapter tests; final run 29.18s |
| Generator | `make test-generator` (included above) | Exit 0: six tests |
| Tooling/runner | `make test-tooling` (included above and in integration) | Exit 0: five tests, including 16 altered-fixture attempts rejected before fake Docker |
| Mock contract | `make test-mocks` | Exit 0: four Python tests |
| WASM/policy assets | `make build` (also integration prerequisite) | Exit 0: release WASM and both policy YAML artifacts generated |
| Dependency advisories | `make advisory` | Exit 0: 322 locked dependencies scanned, warnings denied, no reported vulnerabilities/warnings |
| Docker | `make test-integration` | Exit 0: nine tests in 126.55s against local mock services and pinned Flex 1.13.0 |
| Formatting/diff | `cargo fmt -- --check`; `git diff --check` | Exit 0 |
| Repository CI | Classification Gate Checks | Workflow inspected, not a successful hosted run or required-check configuration |

Locally generated artifact SHA-256 values (not deployed artifact provenance):

| Artifact under `target/wasm32-wasip1/release/` | SHA-256 |
|---|---|
| `data_classification_policy.wasm` | `4835df4ec4d3477f4c8a2b9e815ea1622dc8d7a0ae6403e17fdfbfe99a91868a` |
| `data_classification_policy_definition.yaml` | `1b0573433314c845ea9e2f3a500b4050ed14622ed2d38a5118e7941f876c3b8f` |
| `data_classification_policy_implementation.yaml` | `a40aeb623800aae0786024c5e06f20cec910c2c3dbb07de101da40b166d959fd` |

The Makefile locks dependency resolution and pins cargo-anypoint 1.10.0, llvm-cov 0.9.1, and
cargo-audit 0.23.0. CI pins Rust 1.90.0, Node major 24, CLI 1.6.28, PDK plugin 1.10.0, action
commit SHAs, and image digests. PDK/test/unit dependencies are exact 1.10.0; adapter serialization
uses exact pdk-serde-fixint 1.11.0. Version pins are not proof that every fetched tool dependency
or OS/image component has been audited.

The Docker runner has a 600s POSIX process-group deadline, TERM then KILL after 10s, and
preserves command failure status. Request clients and test/image-build waits are separately
bounded. The demo is local-only: whole-file SHA-256 approved dummy fixture, loopback route, no config overrides,
`--env-file /dev/null` for Compose startup/cleanup, bounded HTTP/readiness, no response-data
printing. Approved private config selection replaces the mock ApiInstance; it does not mount
another credential-bearing instance beside it. Do not rerun demo/live operations to fill this
evidence record without the appropriate approval. Intentional fixture edits require a reviewed
hash update; Python optimization cannot disable the Node fixture check.

## Remaining Production Risks

- Gossip/partitions are not linearizable. CAS tests and local quarantine do not prove replica-wide
  fencing, clock agreement, persisted invalidation success, or restart safety.
- The custom remote adapter is source-tested, not verified against a live backend. Actual wire
  compatibility, service registration, backend authorization/isolation, TLS and network reachability
  remain unknown.
- TLS trust, hostname validation, approved credential destinations, egress restrictions,
  authentication/authorization ordering, rate limits, and prevention of direct backend access
  must be demonstrated for the deployment. Scheme checks alone do not prove these controls.
- Default transient stale serving has no absolute local age ceiling. Fetch observation time is
  not a catalog source revision or proof of metadata recency. Operators must approve the stale
  allowance and ensure the fixed governed columns match every protected invocation.
- gRPC, excluded MIME types, and task/artifact retrieval are outside the whole-call gate. Verify
  real upstream dispatch, route normalization, MIME rejection, and alternate transports separately.
- Suspected A2A asset-type token spelling is unproven, not a confirmed finding. Local load does
  not verify Exchange's accepted vocabulary or the actual deployed protocol binding.
- External CDGC authorization-filtered omissions are unknown. The official response example
  establishes field placement, not completeness for the chosen service account or all catalogs.
- A custom-CA issue is known in the SDK/Flex 1.13 DQ investigation; it is not a proven
  classification-policy defect and is not proven fixed here. Exercise the classification deployment's
  actual TLS trust path before approval.
- Per-request bounds do not prove aggregate HTTP/2 concurrency, CPU/memory, slow-upload or
  outage behavior. OS/container vulnerability audit, production load/partition tests, and source-to-
  deployed-WASM provenance remain unverified.
- CI wiring does not guarantee branch protection, required status checks, protection from
  alternate publication paths, or the contents of the released artifact.

## Release Evidence Required

Before sign-off, retain observed command outcomes and preserved logs for the final source SHA
plus the working-tree diff if applicable. Record WASM and policy
asset digests, actual tool/image versions, advisory output, and CI run URL. Then separately
verify live catalog completeness/least privilege, TLS/egress, actual upstream protocol behavior,
shared-storage interoperability/isolation, replica failure behavior, policy-chain ordering,
concurrency budgets, and deployed artifact provenance. None of those deployment checks is
authorized or completed by this document.
