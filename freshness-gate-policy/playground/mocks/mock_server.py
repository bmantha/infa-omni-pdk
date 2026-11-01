#!/usr/bin/env python3
"""Minimal stdlib-only stand-ins for the CDGC (Login/JWT/Detail), Object Store V2, and
inventory-MCP HTTP APIs, for local playground testing (`make run` / `demo.sh`). Not meant to
be realistic security-wise -- just enough to exercise the policy's Login -> JWT ->
selfAttributes-fetch and Object Store cache-aside wiring end-to-end in Docker, and to give the
gated MCP backend a real-looking `tools/call` response instead of a generic httpbin echo.

Role is picked with the ROLE env var (cdgclogin|cdgcapi|objectstoreauth|objectstore|warehouseMcp),
port with PORT (default 80).

`cdgcapi`'s SLA/freshness score starts at SLA_SCORE (default 95) and can be changed live,
without a restart, via `PUT /score {"score": <value>}` -- e.g. to demo the warn/block
behavior:

    curl -X PUT http://localhost:<cdgcapi-port>/score -d '{"score": 60}'

(Only reachable from inside the Docker network by default; publish the port or `docker exec
curl` from another playground container if you need to hit it from the host.)

`warehouseMcp` serves the actual upstream behind the gate: an MCP JSON-RPC 2.0 endpoint with a
single `get_inventory_levels` tool. Which warehouse's canned inventory/lastSyncedAt it returns
is picked with the WAREHOUSE env var (east|west, default east) -- see WAREHOUSE_DATA below for
the values, which mirror the real CDGC RuleInstance data described in CLAUDE.md (East ~20min
sync lag, West ~6h sync lag against a 4h SLA window).
"""
import json
import os
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

ROLE = os.environ.get("ROLE", "cdgclogin")
PORT = int(os.environ.get("PORT", "80"))

# cdgcapi mock state: current SLA/freshness score returned for every RuleInstance, mutable via
# PUT /score.
current_score = {"value": float(os.environ.get("SLA_SCORE", "95"))}

# Object Store mock state: raw bytes by cache key.
object_store = {}

# warehouseMcp mock data: canned inventory + sync lag per warehouse, keyed by the WAREHOUSE env
# var. Sync lag numbers match CLAUDE.md's real CDGC data (East well inside the 4h SLA window,
# West ~2h over it).
WAREHOUSE_DATA = {
    "east": {
        "displayName": "Warehouse East",
        "lastSyncedMinutesAgo": 20,
        "items": [
            {"sku": "SKU-1001", "description": "Pallet jack", "quantityOnHand": 342},
            {"sku": "SKU-1042", "description": "Forklift battery, 36V", "quantityOnHand": 58},
            {"sku": "SKU-2077", "description": "Shrink wrap, 1500ft roll", "quantityOnHand": 910},
        ],
    },
    "west": {
        "displayName": "Warehouse West",
        "lastSyncedMinutesAgo": 360,
        "items": [
            {"sku": "SKU-1001", "description": "Pallet jack", "quantityOnHand": 117},
            {"sku": "SKU-1042", "description": "Forklift battery, 36V", "quantityOnHand": 9},
            {"sku": "SKU-2077", "description": "Shrink wrap, 1500ft roll", "quantityOnHand": 402},
        ],
    },
}


def read_json(handler):
    length = int(handler.headers.get("Content-Length", 0))
    raw = handler.rfile.read(length) if length else b"{}"
    return json.loads(raw or b"{}")


def respond(handler, status, payload):
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class CdgcLoginHandler(BaseHTTPRequestHandler):
    """Serves both CDGC identity-service endpoints the policy calls: Login (POST) and the
    JWT exchange (GET, session-cookie authenticated)."""

    def do_POST(self):
        if self.path.startswith("/identity-service/api/v1/Login"):
            read_json(self)
            print("[cdgclogin] issuing session", flush=True)
            respond(self, 200, {"sessionId": "mock-session-1", "orgId": "mock-org-1"})
        else:
            respond(self, 404, {"error": f"no such path: {self.path}"})

    def do_GET(self):
        if self.path.startswith("/identity-service/api/v1/jwt/Token"):
            print("[cdgclogin] issuing jwt", flush=True)
            respond(self, 200, {"jwt_token": "mock-jwt-token"})
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


class CdgcApiHandler(BaseHTTPRequestHandler):
    """Serves the CDGC Detail API's `selfAttributes` segment for the demo RuleInstance."""

    def do_GET(self):
        if self.path.startswith("/data360/search/v1/assets/"):
            print(f"[cdgcapi] GET {self.path} -> value={current_score['value']}", flush=True)
            respond(self, 200, {
                "selfAttributes": {"com.infa.ccgf.models.governance.value": current_score["value"]}
            })
        else:
            self.send_response(404)
            self.end_headers()

    def do_PUT(self):
        if self.path == "/score":
            payload = read_json(self)
            current_score["value"] = float(payload.get("score", current_score["value"]))
            print(f"[cdgcapi] score set to {current_score['value']}", flush=True)
            respond(self, 200, {"score": current_score["value"]})
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


class ObjectStoreAuthHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        print("[objectstoreauth] issuing token", flush=True)
        respond(self, 200, {"access_token": "dummy-object-store-token", "expires_in": 3600})

    def log_message(self, fmt, *args):
        pass


class ObjectStoreHandler(BaseHTTPRequestHandler):
    def _key(self):
        return self.path.rsplit("/", 1)[-1]

    def do_GET(self):
        key = self._key()
        value = object_store.get(key)
        if value is None:
            print(f"[objectstore] GET {key!r} -> 404", flush=True)
            self.send_response(404)
            self.end_headers()
            return
        print(f"[objectstore] GET {key!r} -> hit", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(value)))
        self.end_headers()
        self.wfile.write(value)

    def do_PUT(self):
        key = self._key()
        length = int(self.headers.get("Content-Length", 0))
        value = self.rfile.read(length) if length else b""
        object_store[key] = value
        print(f"[objectstore] PUT {key!r} ({len(value)} bytes)", flush=True)
        self.send_response(200)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


class WarehouseMcpHandler(BaseHTTPRequestHandler):
    """A tiny MCP JSON-RPC 2.0 endpoint standing in for a real inventory connector. Serves
    `initialize`, `tools/list`, and treats every other method (in practice just `tools/call`)
    as a request for this warehouse's current inventory snapshot."""

    warehouse = WAREHOUSE_DATA.get(os.environ.get("WAREHOUSE", "east"), WAREHOUSE_DATA["east"])

    def _inventory_result(self):
        synced_at = datetime.now(timezone.utc) - timedelta(minutes=self.warehouse["lastSyncedMinutesAgo"])
        snapshot = {
            "warehouse": self.warehouse["displayName"],
            "lastSyncedAt": synced_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "items": self.warehouse["items"],
        }
        return {
            "content": [{"type": "text", "text": json.dumps(snapshot, indent=2)}],
            "structuredContent": snapshot,
        }

    def do_GET(self):
        # Readiness probe target (e.g. demo.sh's wait_for_port) -- MCP itself is POST-only.
        respond(self, 200, {"status": "ok", "warehouse": self.warehouse["displayName"]})

    def do_POST(self):
        request = read_json(self)
        method = request.get("method")
        request_id = request.get("id")

        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": f"{self.warehouse['displayName']} Inventory MCP (mock)",
                    "version": "0.0.0-mock",
                },
            }
        elif method == "tools/list":
            result = {
                "tools": [{
                    "name": "get_inventory_levels",
                    "description": f"Get current on-hand inventory levels for {self.warehouse['displayName']}.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"sku": {"type": "string"}},
                    },
                }]
            }
        else:
            result = self._inventory_result()

        print(f"[warehouseMcp:{self.warehouse['displayName']}] {method} (id={request_id})", flush=True)
        respond(self, 200, {"jsonrpc": "2.0", "id": request_id, "result": result})

    def log_message(self, fmt, *args):
        pass


HANDLERS_BY_ROLE = {
    "cdgclogin": CdgcLoginHandler,
    "cdgcapi": CdgcApiHandler,
    "objectstoreauth": ObjectStoreAuthHandler,
    "objectstore": ObjectStoreHandler,
    "warehouseMcp": WarehouseMcpHandler,
}

if __name__ == "__main__":
    handler_cls = HANDLERS_BY_ROLE.get(ROLE, CdgcLoginHandler)
    print(f"Starting {ROLE} mock on :{PORT}", flush=True)
    HTTPServer(("0.0.0.0", PORT), handler_cls).serve_forever()
