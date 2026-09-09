#!/usr/bin/env python3
"""Minimal stdlib-only stand-ins for the CDGC (Login/JWT/Detail) and Object Store V2 HTTP
APIs, for local playground testing (`make run`). Not meant to be realistic -- just enough to
exercise the policy's Login -> JWT -> dataQuality-fetch and Object Store cache-aside wiring
end-to-end in Docker.

Role is picked with the ROLE env var (cdgclogin|cdgcapi|objectstoreauth|objectstore), port
with PORT (default 80).

`cdgcapi`'s DQ score starts at DQ_SCORE (default 95) and can be changed live, without a
restart, via `PUT /score {"score": <value>}` -- e.g. to demo the warn/block behavior:

    curl -X PUT http://localhost:<cdgcapi-port>/score -d '{"score": 60}'

(Only reachable from inside the Docker network by default; publish the port or `docker exec
curl` from another playground container if you need to hit it from the host.)
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

ROLE = os.environ.get("ROLE", "cdgclogin")
PORT = int(os.environ.get("PORT", "80"))

# cdgcapi mock state: current DQ score returned for every asset, mutable via PUT /score.
current_score = {"value": float(os.environ.get("DQ_SCORE", "95"))}

# Object Store mock state: raw bytes by cache key.
object_store = {}


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
    """Serves the CDGC Detail API's `dataQuality` segment for the demo asset."""

    def do_GET(self):
        if self.path.startswith("/data360/search/v1/assets/"):
            print(f"[cdgcapi] GET {self.path} -> score={current_score['value']}", flush=True)
            respond(self, 200, {"dataQuality": [{"core.score": current_score["value"]}]})
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


HANDLERS_BY_ROLE = {
    "cdgclogin": CdgcLoginHandler,
    "cdgcapi": CdgcApiHandler,
    "objectstoreauth": ObjectStoreAuthHandler,
    "objectstore": ObjectStoreHandler,
}

if __name__ == "__main__":
    handler_cls = HANDLERS_BY_ROLE.get(ROLE, CdgcLoginHandler)
    print(f"Starting {ROLE} mock on :{PORT}", flush=True)
    HTTPServer(("0.0.0.0", PORT), handler_cls).serve_forever()
