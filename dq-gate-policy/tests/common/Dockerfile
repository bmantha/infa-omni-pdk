# Copyright 2026 Salesforce, Inc. All rights reserved.
FROM httpmock/httpmock:0.8.3@sha256:d32beca8950f5cee8e7f9f777a48da1b4b5ead6410f00b962d75d46f6f597cb1
# pdk-test 1.10's HttpMock readiness probe watches stderr, not stdout.
ENTRYPOINT ["/bin/sh", "-c", "exec httpmock --expose >&2"]
