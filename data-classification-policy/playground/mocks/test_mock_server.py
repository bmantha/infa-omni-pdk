# Copyright 2026 Salesforce, Inc. All rights reserved.
import io
import json
import unittest
from unittest.mock import patch

import mock_server as mock


class Request:
    def __init__(self, path, payload):
        body = json.dumps(payload).encode()
        self.path = path
        self.headers = {"Content-Length": str(len(body))}
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.status = None

    def send_response(self, status):
        self.status = status

    def send_header(self, *args):
        pass

    def end_headers(self):
        pass

    def payload(self):
        return json.loads(self.wfile.getvalue())


class MockContractTests(unittest.TestCase):
    def details(self, segments, ids, suffix=""):
        request = Request("/data360/search/v1/assets/details" + suffix + "?segments=" + segments, ids)
        mock.CdgcApiHandler.do_POST(request)
        return request

    def test_exact_column_segment_supplies_summary_type_and_classification_links(self):
        for identity, links in mock.COLUMN_TO_CLASSIFICATIONS.items():
            response = self.details("summary,systemAttributes,dataClassification", [identity])
            self.assertEqual(response.status, 200)
            asset = response.payload()[0]
            self.assertEqual(asset["core.identity"], identity)
            self.assertEqual(asset["summary"]["core.name"], mock.COLUMN_NAMES[identity])
            self.assertEqual(asset["systemAttributes"]["core.classType"],
                "com.infa.odin.models.relational.Column")
            self.assertEqual(asset.get("dataClassification", []), [{"core.identity": i} for i in links])
            if not links:
                self.assertNotIn("dataClassification", asset)
            self.assertNotIn("core.type", asset)

    def test_classification_segment_supplies_name_and_sensitivity(self):
        for identity, sensitivity in mock.CLASSIFICATION_SENSITIVITY.items():
            response = self.details("summary,selfAttributes", [identity])
            self.assertEqual(response.status, 200)
            asset = response.payload()[0]
            self.assertEqual(asset["summary"]["core.name"], mock.CLASSIFICATION_NAMES[identity])
            self.assertEqual(asset["selfAttributes"]["core.sensitivity"], sensitivity)

    def test_wrong_segments_path_and_invalid_batches_are_rejected(self):
        self.assertEqual(self.details("dataClassification", [mock.COLUMN_ID_VISIT_REASON]).status, 400)
        self.assertEqual(self.details("summary,dataClassification", [mock.COLUMN_ID_VISIT_REASON]).status, 400)
        self.assertEqual(self.details("summary,systemAttributes,dataClassification", [mock.COLUMN_ID_VISIT_REASON], "/extra").status, 404)
        for ids in [[], ["id"] * 6, [None], {}, "id"]:
            self.assertEqual(self.details("summary,systemAttributes,dataClassification", ids).status, 400)

    def test_governance_event_links_existing_classification(self):
        with patch.dict(mock.COLUMN_TO_CLASSIFICATIONS, {mock.COLUMN_ID_VISIT_REASON: []}):
            request = Request("/classification", {"columnId": mock.COLUMN_ID_VISIT_REASON,
                "classificationId": mock.CLASSIFICATION_VISIT_REASON})
            mock.CdgcApiHandler.do_PUT(request)
            self.assertEqual(request.status, 200)
            response = self.details("summary,systemAttributes,dataClassification", [mock.COLUMN_ID_VISIT_REASON])
            self.assertEqual(response.payload()[0]["dataClassification"],
                [{"core.identity": mock.CLASSIFICATION_VISIT_REASON}])


if __name__ == "__main__":
    unittest.main()
