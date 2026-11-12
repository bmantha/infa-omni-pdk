#!/usr/bin/env bash
# Copyright 2026 Salesforce, Inc. All rights reserved.
# Local mock demo only; never edit tracked configuration to insert live credentials.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${CLASSIFICATION_API_CONFIG:-}" || -n "${API_CONFIG:-}" ]]; then
  echo "This demo accepts only the tracked local mock fixture." >&2
  exit 1
fi
URL="${CLASSIFICATION_DEMO_URL:-http://127.0.0.1:8081/mcp/}"
case "$URL" in
  http://127.0.0.1:8081/*) ;;
  *) echo "Demo URL must use the local playground at 127.0.0.1:8081." >&2; exit 1 ;;
esac
compose() {
  # Fixture changes, including generated policy-reference changes, require a reviewed hash update.
  node - "$SCRIPT_DIR/config/api.yaml" <<'JS'
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const digest = createHash('sha256').update(readFileSync(process.argv[2])).digest('hex');
if (digest !== 'd58d878c6004e80d100fb52dee6f868c37246870b652da302c8bb2aa9c46bee8') {
  console.error('Demo requires the reviewed, byte-exact local mock fixture');
  process.exit(1);
}
JS
  CLASSIFICATION_API_CONFIG="$SCRIPT_DIR/config/api.yaml" \
    docker compose --env-file /dev/null -f "$SCRIPT_DIR/docker-compose.yaml" "$@"
}
if [[ "${1:-}" == --cleanup ]]; then
  compose down --remove-orphans
  exit 0
fi
if [[ $# -ne 0 ]]; then
  echo "Usage: playground/demo.sh [--cleanup]" >&2
  exit 1
fi
trap 'compose down --remove-orphans' INT TERM
compose up -d --wait --wait-timeout 120
ready=false
for ((i=0; i<30; i++)); do
  if curl --silent --output /dev/null --max-time 2 --connect-timeout 2 --noproxy '*' "$URL"; then
    ready=true
    break
  fi
  sleep 2
done
[[ "$ready" == true ]] || { echo "Local gateway readiness timed out." >&2; exit 1; }
call() {
  curl --silent --show-error --max-time 15 --connect-timeout 2 --noproxy '*' \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{}}' "$URL"
}
call | python3 -c 'import json,sys; r=json.load(sys.stdin); assert "result" in r, "Expected local mock request to pass"'
echo "Before local governance event: allowed (response data not printed)."
compose exec -T cdgcapi python -c '
import json, urllib.request
payload = json.dumps({"columnId":"b7e13420-4841-4bbe-86c0-002b1d9af165","classificationId":"ceaa1ca4-764d-4458-abc8-146ffee68222"}).encode()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(urllib.request.Request("http://127.0.0.1/classification", data=payload, method="PUT", headers={"Content-Type":"application/json"}), timeout=15) as response:
    assert response.status == 200
'
sleep 31
call | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r.get("error",{}).get("code") == -32011, "Expected classification block"; assert "result" not in r'
echo "After local governance event: blocked (-32011)."
echo "Local stack remains running; use playground/demo.sh --cleanup."
