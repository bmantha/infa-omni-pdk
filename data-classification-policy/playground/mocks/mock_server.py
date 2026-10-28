#!/usr/bin/env python3
"""Minimal stdlib-only stand-ins for the CDGC Login/JWT/batched-details HTTP APIs, for local
playground testing (`make run`). Not meant to be realistic -- just enough to exercise the
policy's Login -> JWT -> (dataClassification hop -> summary,selfAttributes hop) sequence
end-to-end in Docker, seeded with the real demo fixture (OCCE1B_CLINICNORTH_PATIENTINTAKE_RAW).
The rank cache and refresh lock are handled by PDK-native DataStorage, so no Object Store mock
is needed.

Role is picked with the ROLE env var (cdgclogin|cdgcapi|backend), port with PORT (default 80).

`cdgcapi` seeds five classified columns plus VISIT_REASON, which starts deliberately
**unlinked** to any classification -- the demo's "before" state, matching the canvas's actual
thesis (an agent can't protect data it doesn't understand yet). Two live mutations are
supported, without a restart:

    # Link an already-cataloged classification to a column (the governance event: a data
    # steward/automated classifier recognizes VISIT_REASON as clinical free text).
    curl -X PUT http://<cdgcapi-host>/classification \\
      -d '{"columnId": "<column-id>", "classificationId": "<id>"}'

    # Change an existing classification's sensitivity in place.
    curl -X PUT http://<cdgcapi-host>/sensitivity \\
      -d '{"classificationId": "<id>", "sensitivity": "MEDIUM"}'

(Only reachable from inside the Docker network by default; see demo.sh for a container-exec
wrapper that drives this from the host.)

`backend` stands in for the upstream MCP server: it always returns a canned patient-intake
record (the same six columns) so the demo can show the actual record appearing when the call is
allowed and never appearing at all when the gate blocks it upstream of this mock.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

ROLE = os.environ.get("ROLE", "cdgclogin")
PORT = int(os.environ.get("PORT", "80"))

# The six real demo columns from OCCE1B_CLINICNORTH_PATIENTINTAKE_RAW, seeded exactly as verified
# live against the real CDGC org this session, EXCEPT VISIT_REASON: seeded with an empty list
# (never an absent key, to keep this mock simple; the real CDGC API's actual "no dataClassification
# key at all" shape is what src/lib.rs's own unit tests exercise directly) -- demo.sh's governance
# event links it to CLASSIFICATION_VISIT_REASON below via PUT /classification.
COLUMN_ID_VISIT_REASON = "b7e13420-4841-4bbe-86c0-002b1d9af165"
CLASSIFICATION_VISIT_REASON = "ceaa1ca4-764d-4458-abc8-146ffee68222"

COLUMN_TO_CLASSIFICATIONS = {
    COLUMN_ID_VISIT_REASON: [],  # VISIT_REASON -- starts unclassified, the demo's "before" state
    "0ffa34a5-a37f-4ce7-be51-7a379a425801": ["9eb85680-f8af-45da-ae5c-11aa4808e9cd"],  # SSN
    "46a337b2-4beb-4f36-a8ad-b1ca1e835f56": ["fe3a6f92-7dce-42ef-955e-0666cc303330"],  # DATE_OF_BIRTH
    "9c3d6045-db8a-4bca-897a-1acc686487fa": ["8564078f-e3f3-4c4d-a424-cfc517ccc079"],  # PATIENT_ID
    "6d26d67b-3ee3-4d23-817b-69fb91fabbb9": ["95da15ba-025c-4a7a-85c7-9133fec97bb9"],  # FULL_NAME
    "86330022-c7c9-4e41-91c7-639f66356dab": [],  # APPOINTMENT_DATE -- unclassified
}

# CLASSIFICATION_VISIT_REASON already exists as a cataloged classification asset with its own
# sensitivity, exactly like a real CDGC org -- it just isn't LINKED to VISIT_REASON yet. The
# governance event is attaching an existing classification, not inventing a sensitivity on the spot.
CLASSIFICATION_SENSITIVITY = {
    CLASSIFICATION_VISIT_REASON: "HIGH",               # Clinical Visit Reason
    "9eb85680-f8af-45da-ae5c-11aa4808e9cd": "HIGH",    # Social Security Number
    "fe3a6f92-7dce-42ef-955e-0666cc303330": "HIGH",    # Date of Birth
    "8564078f-e3f3-4c4d-a424-cfc517ccc079": "MEDIUM",  # Patient Identifier
    "95da15ba-025c-4a7a-85c7-9133fec97bb9": "MEDIUM",  # Patient Full Name
}

PATIENT_RECORD = {
    "patientId": "P-10293",
    "fullName": "Jordan Alvarez",
    "appointmentDate": "2026-09-18",
    "visitReason": "Routine psychiatric follow-up for anxiety management; patient reports "
                    "improved mood on current sertraline dosage.",
    "checkInStatus": "CHECKED_IN",
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
    """Serves the CDGC batched details API's `dataClassification` and `summary,selfAttributes`
    segments (5-id-per-call cap NOT enforced here -- this mock is for manual smoke testing, not
    correctness proof; the 5-id cap is proven by src/lib.rs's own unit tests)."""

    def do_POST(self):
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/data360/search/v1/assets/details"):
            respond(self, 404, {"error": f"no such path: {self.path}"})
            return

        segments = parse_qs(parsed.query).get("segments", [""])[0]
        ids = read_json(self)
        if not isinstance(ids, list):
            respond(self, 400, {"message": "expected a JSON array of ids"})
            return

        if segments == "dataClassification":
            results = []
            for column_id in ids:
                if column_id not in COLUMN_TO_CLASSIFICATIONS:
                    continue  # unresolved id -> simply absent from the response
                entry = {"core.identity": column_id}
                classifications = COLUMN_TO_CLASSIFICATIONS[column_id]
                if classifications:
                    entry["dataClassification"] = [{"core.identity": c} for c in classifications]
                results.append(entry)
            print(f"[cdgcapi] dataClassification hop for {ids} -> {len(results)} resolved", flush=True)
            respond(self, 200, results)
        elif segments == "summary,selfAttributes":
            results = []
            for classification_id in ids:
                if classification_id not in CLASSIFICATION_SENSITIVITY:
                    continue
                results.append({
                    "core.identity": classification_id,
                    "selfAttributes": {"core.sensitivity": CLASSIFICATION_SENSITIVITY[classification_id]},
                })
            print(f"[cdgcapi] selfAttributes hop for {ids} -> {len(results)} resolved", flush=True)
            respond(self, 200, results)
        else:
            respond(self, 400, {"message": f"unsupported segments '{segments}'"})

    def do_PUT(self):
        if self.path == "/sensitivity":
            payload = read_json(self)
            classification_id = payload.get("classificationId")
            sensitivity = payload.get("sensitivity")
            if classification_id not in CLASSIFICATION_SENSITIVITY or sensitivity not in ("LOW", "MEDIUM", "HIGH"):
                respond(self, 400, {"message": "expected {classificationId, sensitivity: LOW|MEDIUM|HIGH}"})
                return
            CLASSIFICATION_SENSITIVITY[classification_id] = sensitivity
            print(f"[cdgcapi] sensitivity for {classification_id} set to {sensitivity}", flush=True)
            respond(self, 200, {"classificationId": classification_id, "sensitivity": sensitivity})
        elif self.path == "/classification":
            payload = read_json(self)
            column_id = payload.get("columnId")
            classification_id = payload.get("classificationId")
            if column_id not in COLUMN_TO_CLASSIFICATIONS or classification_id not in CLASSIFICATION_SENSITIVITY:
                respond(self, 400, {"message": "expected {columnId, classificationId} for known assets"})
                return
            linked = COLUMN_TO_CLASSIFICATIONS[column_id]
            if classification_id not in linked:
                linked.append(classification_id)
            print(f"[cdgcapi] linked classification {classification_id} to column {column_id}", flush=True)
            respond(self, 200, {"columnId": column_id, "classificationId": classification_id})
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


class BackendHandler(BaseHTTPRequestHandler):
    """Stands in for the upstream MCP server. Always returns the same canned patient-intake
    record, echoing the caller's JSON-RPC id, regardless of path -- the point of this mock is
    only to make it visible when the gate does vs. doesn't let the record reach the client."""

    def do_POST(self):
        payload = read_json(self)
        rpc_id = payload.get("id", 1)
        print("[backend] returning patient-intake record", flush=True)
        respond(self, 200, {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {"records": [PATIENT_RECORD]},
        })

    def log_message(self, fmt, *args):
        pass


HANDLERS_BY_ROLE = {
    "cdgclogin": CdgcLoginHandler,
    "cdgcapi": CdgcApiHandler,
    "backend": BackendHandler,
}

if __name__ == "__main__":
    handler_cls = HANDLERS_BY_ROLE.get(ROLE, CdgcLoginHandler)
    print(f"Starting {ROLE} mock on :{PORT}", flush=True)
    HTTPServer(("0.0.0.0", PORT), handler_cls).serve_forever()
