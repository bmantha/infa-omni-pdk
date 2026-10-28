#!/usr/bin/env bash
# demo.sh — Data Classification Gate: before/after governance-event demo, LIVE against the real
# CDGC org (Bhim TSPOD) and the real OCCE1B_CLINICNORTH_PATIENTCHECKIN table.
#
# One MCP tool route, one exact same call, made twice. Nothing is redeployed or restarted between
# the two calls — only CDGC's catalog changes, and this time it's a REAL change made by hand in
# the CDGC UI, not a scripted PUT against a mock.
#
#   1. First call  -> ALLOWED. VISIT_REASON is genuinely unclassified right now in the real org
#      (PATIENT_ID/FULL_NAME are already MEDIUM), so the worst case across governedColumnIds is
#      MEDIUM, at the ceiling. The upstream mock backend's check-in record — including the raw
#      VISIT_REASON free text — is visible in the response.
#   2. THE GOVERNANCE EVENT (you do this live, in the CDGC UI): link VISIT_REASON to the
#      already-cataloged "Clinical Visit Reason" classification (HIGH). This script pauses and
#      waits for you to confirm you've done it.
#   3. Wait for the cache TTL (refreshIntervalSeconds: 30 in config/api.yaml) to lapse.
#   4. Retry the SAME call -> BLOCKED (JSON-RPC -32011). The record — and the sensitive
#      VISIT_REASON text inside it — never reaches the client; only the generic gate error does.
#
# Usage:
#   ./playground/demo.sh
#   ./playground/demo.sh --cleanup
#
# Prerequisites: Docker + docker compose v2 (or docker-compose v1)
# The Flex Gateway WASM must already be built:  make build
# playground/config/api.yaml ships pointed at the local mocks; for this live demo, put real CDGC
# creds/column ids in it locally and do NOT commit them.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── colours ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}▶ $*${NC}"; }
success() { echo -e "${GREEN}✔ $*${NC}"; }
warn()    { echo -e "${YELLOW}⚠ $*${NC}"; }
fail()    { echo -e "${RED}✘ $*${NC}"; }
header()  { echo -e "\n${BOLD}━━━ $* ━━━${NC}"; }

if docker compose version &>/dev/null 2>&1; then
  DC="docker compose"
else
  DC="docker-compose"
fi

cleanup() {
  info "Tearing down..."
  (cd "$SCRIPT_DIR" && $DC down --remove-orphans 2>/dev/null) || true
}

if [[ "${1:-}" == "--cleanup" ]]; then
  cleanup
  success "Done."
  exit 0
fi

trap 'echo ""; warn "Interrupted — cleaning up..."; cleanup; exit 1' INT TERM

WASM_PATH="$PROJECT_ROOT/target/wasm32-wasip1/release/data_classification_policy.wasm"
if [[ ! -f "$WASM_PATH" ]]; then
  fail "WASM not found at $WASM_PATH"
  echo "  Run  make build  first."
  exit 1
fi

REG_FILE="$SCRIPT_DIR/config/registration.yaml"
if [[ ! -f "$REG_FILE" ]]; then
  fail "No registration.yaml found at $REG_FILE"
  echo "  See the README for how to generate one with Anypoint Platform."
  exit 1
fi

header "Starting playground stack"
(cd "$SCRIPT_DIR" && $DC up -d)

info "Waiting for Flex Gateway to be ready..."
for i in $(seq 1 30); do
  if curl -s -o /dev/null "http://localhost:8081/mcp/"; then
    success "Flex Gateway is up (port 8081)"
    break
  fi
  sleep 2
  if [[ "$i" == 30 ]]; then
    fail "Flex Gateway did not become ready after 60s"
    exit 1
  fi
done

call() {
  curl -s -w "\n%{http_code}" -X POST http://localhost:8081/mcp/ \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"tools/call","id":1}'
}

header "Step 1 — BEFORE: VISIT_REASON is unclassified in the real CDGC org right now"
info "Calling the tool → expect HTTP 200 with the check-in record, VISIT_REASON text included"
echo ""

RESP_1=$(call)
BODY_1="${RESP_1%$'\n'*}"
CODE_1="${RESP_1##*$'\n'}"
echo "  HTTP $CODE_1"
echo "  Body: $BODY_1"
echo ""

if [[ "$CODE_1" == "200" && "$BODY_1" == *'visitReason'* ]]; then
  success "Allowed — the record, including VISIT_REASON, reached the client ✔"
else
  warn "Did not see the expected record (HTTP $CODE_1) — cache may need to populate first"
fi

header "Step 2 — THE GOVERNANCE EVENT (do this live, in the CDGC UI)"
echo -e "  Open the ${BOLD}OCCE1B_CLINICNORTH_PATIENTCHECKIN${NC} table in the CDGC UI, select the"
echo -e "  ${BOLD}VISIT_REASON${NC} column, and link it to the existing ${BOLD}'Clinical Visit Reason'${NC}"
echo -e "  classification (HIGH). No code is redeployed, no gateway is restarted — only CDGC's"
echo -e "  catalog changes."
echo ""
read -r -p "  Press ENTER once you've linked it in the UI... "

info "Waiting ${BOLD}31s${NC} for cache TTL (refreshIntervalSeconds: 30) to expire..."
sleep 31

header "Step 3 — AFTER: same exact call, retried"
info "Calling again → expect JSON-RPC error -32011 (BLOCKED), no patient data in the response"
echo ""

RESP_2=$(call)
BODY_2="${RESP_2%$'\n'*}"
CODE_2="${RESP_2##*$'\n'}"
echo "  HTTP $CODE_2"
echo "  Body: $BODY_2"
echo ""

if [[ "$BODY_2" == *'-32011'* && "$BODY_2" != *'visitReason'* ]]; then
  success "Blocked as expected (JSON-RPC -32011) — no patient data reached the client ✔"
else
  warn "Did not see the expected block (HTTP $CODE_2)"
fi

echo ""
header "Summary"
echo -e "  Before classification: HTTP ${GREEN}${CODE_1}${NC} → allowed, record (incl. VISIT_REASON) returned"
echo -e "  After classification:  HTTP ${CODE_2} → ${RED}blocked${NC} (JSON-RPC -32011), no record returned"
echo -e "  Same route, same call, same WASM binary — only CDGC's catalog changed."
echo ""
info "Stack is still running. To tear down:"
echo "  ./playground/demo.sh --cleanup"
echo ""
