# Local Docker upload verification

Verified on 2026-11-11 using PDK/pdk-test 1.10.0, Flex Gateway 1.13.0,
and the local httpmock 0.8.3 readiness-wrapper image. No production or live CDGC
calls, Exchange publication, commits, or pushes are involved.

## Configuration

The installed `pdk-test` source exposes `FlexConfig::builder().env(...)` and
forwards its entries to the gateway container. The upload regression explicitly
sets `FLEX_DOWNSTREAM_CONNECTION_BUFFER_LIMIT_BYTES=65536` (64 KiB).

The Gateway 1.13.0 image contains the `stream-idle-timeout-flex` policy and its
definition requires the numeric `timeout` property. The regression installs
`{"timeout":2}` before DQ Gate. This configuration was exercised on the actual
gateway, not inferred from a unit-test mock.

## Regression cases

`make test TEST=gateway_rejects_oversized_and_stalled_uploads_before_cdgc_or_backend`
passed all three cases in one isolated Docker stack:

| Upload | Result | CDGC Login/JWT/Detail and backend |
| --- | --- | --- |
| `Content-Length: 1048577`, headers only, connection left open | HTTP 413 | Zero calls each |
| Chunked 128 KiB body, no terminal chunk, no `Content-Length` | HTTP 413 | Zero calls each |
| `Content-Length: 128`, no body, connection left open | HTTP 408 | Zero calls each |

The declared-length case exercises DQ Gate's 1 MiB header guard without waiting
for the body. The chunked case is below that policy cap but above the explicit
gateway buffer; its 413 occurs before upload completion or JSON parsing. The
stalled case verifies the shipped stream-idle control. A subsequent healthy MCP
call succeeds on the same stack, with exactly one call to each mock, ensuring
that a broken route or unavailable backend cannot explain the denial results.

Raw HTTP/1.1 uploads run on a host-side `std::thread` using `TcpStream`, with a
`futures` oneshot back to the async test. No new Tokio dependency or reqwest
stream feature was added. Socket read/write timeouts of 10 seconds are test
safety bounds, not assertions of a gateway absolute upload deadline.

## Suite results

- The upload regression passed twice: once selected alone, once in the request suite.
- The completed normal suite passes all request integration and generator tests.
  The TLS diagnostic is explicitly ignored; its bounded opt-in run fails the
  correct-CA policy positive control. See `local-verification.md` and the current
  aggregate results in `security-verification.md`.
- `git diff --check` passed.
- Docker mock-image builds have a 120-second process deadline. Each async request
  test has a 240-second deadline covering gateway and remote mock administration
  operations; HTTP clients also have 15-second total and 2-second connect limits.

## Remaining limits

- Stream-idle timeout is not an absolute upload deadline. A peer that keeps
  sending bytes may reset the idle timer; no trickle-upload total-duration bound
  is asserted or verified.
- The DQ Gate timer bounds score resolution after body acquisition, not time
  spent waiting for the buffered request body.
- This verifies HTTP/1.1, one local gateway replica, and the named image/config.
  HTTP/2, production settings, upstream exclusions, and aggregate concurrent
  upload memory remain deployment verification work.
- The 64 KiB buffer is an explicit test/deployment control, not a new policy
  default. The existing full-body oversized JSON test still covers the policy's
  1 MiB rejection separately.
