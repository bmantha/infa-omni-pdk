# Local Playground

`make run` uses only dummy credentials and local mock services. The fixture deliberately sets
`allowInsecureLocalServices: true`; never enable this exception for live CDGC services.
The gateway listens on loopback port 8081. `playground/demo.sh` exercises the local before/after
classification event without printing response data. Set `CLASSIFICATION_DEMO_URL` to the local
route URL if needed; the script rejects non-loopback destinations and config overrides.

## Separate Live Configuration

A live test requires a separately approved operation. Keep the one live ApiInstance file in the
ignored `playground/private/api.yaml`, with HTTPS service URLs, real credentials and
`allowInsecureLocalServices: false`. Protect that file with mode 600. Do not put live values in
the tracked `playground/config/api.yaml`, do not add a second ApiInstance under `config/`, and
do not print the live file or expanded Compose configuration.

The explicit selection is `make run API_CONFIG="$PWD/playground/private/api.yaml"` after approval.
For direct Compose use, set `CLASSIFICATION_API_CONFIG` to the absolute path of that exact file.
The selection is mounted at `conf.d/api.yaml` in place of the mock ApiInstance, not beside it.
Only registration, logging and generated custom policies are otherwise mounted; the private
directory is not mounted. `make run` patches only the selected file's policy reference.
The local demo script refuses this live override.

Generate a disconnected registration with `make playground/config/registration.yaml` and build
with `make build` before starting. Use `make test-mocks` for network-free mock contract regressions.
Unit and Docker tests use local fixtures, not live catalog services. Local verification does not
establish production TLS trust, egress restrictions, or multi-replica correctness.
