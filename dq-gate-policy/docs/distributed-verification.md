# Distributed Consistency Verification

## Scope

`gossip_replication_gap_allows_duplicate_locks_and_divergent_local_score_winners`
in `src/lib.rs` is a deterministic helper-level unit test of the documented
non-linearizable gossip limitation. Production logic is unchanged. Two independent
`MockDataStorage` instances represent replica-local views with replication withheld
for the entire test. Each mock enforces local absent/CAS version checks; neither
shares entries with the other. Calls execute sequentially with fixed timestamps,
without threads, sleeps, network calls, or wall-clock reads.

## Exact Modeled Evidence

Both views use the same asset's lock key and score key:
`dq-refresh-lock-asset-1` and `dq-score-asset-1`.

| Step | Replica A | Replica B |
| --- | --- | --- |
| Claim refresh lock | Accepted at 1000 | Accepted at 1001, while A's lock would still be fresh |
| Read local lock | `acquired_at=1000`, version `1` | `acquired_at=1001`, version `1` |
| Write B's observation first | Not visible here | Score 65, observation timestamp 1001, returns `Some(65.0)` |
| Write A's older observation second | Score 95, observation timestamp 1000, returns `Some(95.0)` | A's write is not visible here |
| Attempt score 80 at timestamp 999 on each view | Returns local winner `Some(95.0)` | Returns local winner `Some(65.0)` |
| Read final local winner | Score 95, timestamp 1000, version `1` | Score 65, timestamp 1001, version `1` |

The assertions establish two accepted lock claims and two accepted observations
despite B's newer observation completing before A's write. Older retries use each
view's own winner and do not change its timestamp or version. Local coordination
and observed-entry ordering therefore do not establish a global unique refresh
holder or a globally newest decision score. At a block threshold of 80, the scores
would imply opposite decisions; this test exercises storage helpers, not HTTP
admission or the CDGC refresh chain.

Existing tests for older/equal timestamps and an observed newer winner remain
unchanged, including
`older_or_equal_observations_cannot_overwrite_blocking_winner` and
`cas_conflict_returns_newer_blocking_winner_not_local_passing_score`.

## Supported Consistency Requirements

- Local absent/CAS operations and bounded retries protect entries visible to that
  storage view. A validated observed newer/equal winner supplies the decision
  score instead of the losing observation.
- `distributed=true` requires configured remote storage. It does not strengthen
  gossip into linearizable coordination, guarantee exactly one cross-replica
  refresh, or ensure every replica uses the same score during replication gaps.
- Deployments using gossip must tolerate duplicate refreshes and transient score
  divergence. A requirement for globally exclusive refreshes or globally ordered,
  identical decisions is not supported by this policy's gossip coordination;
  it needs separately designed and verified linearizable coordination or another
  architecture that enforces that requirement.
- Observation timestamps are policy observation-start times, not CDGC scan
  completion times. Clock skew and equal timestamps prevent treating them as a
  globally trustworthy source-data order.

## Verification Boundary And Reproduction

Run from `dq-gate-policy/`:

```sh
CARGO_NET_OFFLINE=true make test-unit TEST=gossip_replication_gap_allows_duplicate_locks_and_divergent_local_score_winners
```

The authorized environment is **local Docker only**, with **no real gossip
service configured**. This unit test runs natively and does not use Docker.
No Docker gossip verification is claimed. It models an interval of withheld
replication, not the real service's conflict resolution, eventual convergence,
TTL behavior, partitions, recovery, or clock skew. Real multi-replica
gossip/concurrency verification remains pending; local mock or Docker results
without a real gossip service do not satisfy that release blocker.
