# Minimum PDK the policy is compatible with. Floor is 1.10: the score cache/refresh lock use the
# DataStorage API and request_filter buffers atomically via enable_stop_iteration (see #1, #2).
export PDK_COMPATIBILITY_VERSION = 1.10.0
TARGET                	:= wasm32-wasip1
TARGET_DIR            	:= target/$(TARGET)/release
CARGO_ANYPOINT        	:= cargo-anypoint
CARGO_ANYPOINT_VERSION := 1.10.0
CARGO_LLVM_COV_VERSION := 0.9.1
CARGO_AUDIT_VERSION    := 0.23.0
FLAGS                  	= 
DEFINITION_NAME        	= $(shell anypoint-cli-v4 pdk policy-project definition get gcl-metadata-name)
DEFINITION_NAMESPACE   	= $(shell anypoint-cli-v4 pdk policy-project definition get gcl-metadata-namespace)
DEFINITION_SRC_GCL_PATH = $(shell anypoint-cli-v4 pdk policy-project locate-gcl definition-src)
DEFINITION_GCL_PATH    	= $(shell anypoint-cli-v4 pdk policy-project locate-gcl definition)
CRATE_NAME             	= $(shell cargo anypoint get-name)
SETUP_ERROR_CMD        	= (echo "ERROR:\n\tMissing custom policy project setup. Please run 'make setup'\n")
FLEX_IMAGE              := mulesoft/flex-gateway:1.13.0@sha256:82d645f34e16554715dbd3b1bb2cbbfc304a3a8ea1264a64b7460fddc97b33fa
API_CONFIG              ?= $(CURDIR)/playground/config/api.yaml
API_CONFIG_ABSOLUTE      := $(abspath $(API_CONFIG))
# Only appended to publish/release when set to a non-empty value. Left empty by default because the
# --skip-unchanged-definition flag is supported only by newer anypoint-cli-v4 releases; the P4A build
# pipeline's CLI rejects it ("Unexpected argument"), so the default MUST omit the flag entirely.
# Opt in on a compatible CLI with e.g. `make publish SKIP_UNCHANGED_DEFINITION=true`.
SKIP_UNCHANGED_DEFINITION ?=
_SKIP_UNCHANGED_DEFINITION_FLAG = $(if $(strip $(SKIP_UNCHANGED_DEFINITION)),--skip-unchanged-definition=$(strip $(SKIP_UNCHANGED_DEFINITION)),)

ifeq ($(OS), Windows_NT)
    SHELL = powershell.exe
    .SHELLFLAGS = -NoProfile -ExecutionPolicy Bypass -Command
	ifneq ($(shell make -v | FIND "GNU Make 4"),)
		ANYPOINT_METADATA_JSON  = $(shell cargo anypoint get-anypoint-metadata | ConvertTo-Json)
	else
		ANYPOINT_METADATA_JSON  = $(shell cargo anypoint get-anypoint-metadata)
	endif
	POLICY_REF_NAME = $(shell $$env:PDK_COMPATIBILITY_VERSION="$(PDK_COMPATIBILITY_VERSION)"; cargo anypoint get-policy-implementation-name)
else
	ANYPOINT_METADATA_JSON  = $(shell cargo anypoint get-anypoint-metadata)
	POLICY_REF_NAME = $(shell export PDK_COMPATIBILITY_VERSION=$(PDK_COMPATIBILITY_VERSION); cargo anypoint get-policy-implementation-name)
endif

.PHONY: setup
setup: install-cargo-anypoint install-llvm-cov ## Setup Cargo Anypoint to build, LLVM-cov for coverage
	cargo fetch --locked

playground/config/registration.yaml tests/config/registration.yaml: ## Generate a disconnected registration.yaml from the local flex gateway
	docker image pull $(FLEX_IMAGE)
ifeq ($(OS), Windows_NT)
	docker run --rm --entrypoint flexctl -v "$(CURDIR)/$(@D)":/registration $(FLEX_IMAGE) registration create --mode disconnected --output-directory=/registration testing-flex
else
	docker run --rm --user "$$(id -u):$$(id -g)" --entrypoint flexctl -v "$(CURDIR)/$(@D)":/registration $(FLEX_IMAGE) registration create --mode disconnected --output-directory=/registration testing-flex
endif

.PHONY: build
build: build-asset-files ## Build the policy definition and implementation
	@$(FLAGS) cargo build --locked --target $(TARGET) --release
	@cp "$(DEFINITION_GCL_PATH)" "$(TARGET_DIR)/$(CRATE_NAME)_definition.yaml"
	@cargo anypoint gcl-gen -d $(DEFINITION_NAME) -n $(DEFINITION_NAMESPACE) -w $(TARGET_DIR)/$(CRATE_NAME).wasm -o $(TARGET_DIR)/$(CRATE_NAME)_implementation.yaml
	@echo $(POLICY_REF_NAME) > target/policy-ref-name.txt

.PHONY: run
run: build playground/config/registration.yaml ## Run the policy in local flex
	@test -f "$(API_CONFIG_ABSOLUTE)" || { echo "API_CONFIG must select an existing file" >&2; exit 1; }
	@cargo anypoint patch-api -o "$(API_CONFIG_ABSOLUTE)" -m $(DEFINITION_GCL_PATH) -n $(POLICY_REF_NAME) -s $(DEFINITION_NAMESPACE)
ifeq ($(OS), Windows_NT)
	rm -Force playground/config/custom-policies/*.yaml
else
	rm -f playground/config/custom-policies/*.yaml
endif
	cp "$(TARGET_DIR)/$(CRATE_NAME)_implementation.yaml" "playground/config/custom-policies/$(CRATE_NAME)_implementation.yaml"
	cp "$(TARGET_DIR)/$(CRATE_NAME)_definition.yaml" "playground/config/custom-policies/$(CRATE_NAME)_definition.yaml"
	-CLASSIFICATION_API_CONFIG="$(API_CONFIG_ABSOLUTE)" docker compose -f ./playground/docker-compose.yaml down
	CLASSIFICATION_API_CONFIG="$(API_CONFIG_ABSOLUTE)" docker compose -f ./playground/docker-compose.yaml up

# Set TEST with a specific test name to run a single test using make test. Example: TEST=my_test
TEST ?=

.PHONY: test
test: ## Run unit and bounded integration tests sequentially
	@$(MAKE) test-unit
	@$(MAKE) test-integration

.PHONY: test-integration
test-integration: build test-tooling tests/config/registration.yaml ## Run Docker requests with a 600s process deadline
	@node scripts/run-tests.mjs -- cargo test --locked --test requests $(TEST) -- --nocapture --test-threads=1

.PHONY: test-unit test-generator test-tooling test-mocks security advisory
test-unit: build-asset-files test-generator test-tooling ## Run unit tests without Docker
	@cargo test --locked --lib $(TEST)

test-generator: ## Check the generated-entrypoint sanitizer
	node --test scripts/sanitize-config.test.mjs

test-tooling: ## Check demo isolation and process deadlines without Docker calls
	node --test scripts/tooling.test.mjs scripts/run-tests.test.mjs

test-mocks: ## Check the local CDGC mock contract without network calls
	python3 -m unittest discover -s playground/mocks -p 'test_*.py'

security: test-unit test-mocks advisory ## Check security regressions and all dependency advisories

advisory: install-cargo-audit ## Audit the checked-in lockfile, including warnings
	cargo audit --file Cargo.lock --deny warnings

FORMAT     ?=
OUTPUT_PATH ?=

_COVERAGE_FORMAT = $(if $(filter json,$(FORMAT)),--json,$(if $(filter html,$(FORMAT)),--html,))
_COVERAGE_OUTPUT = $(if $(OUTPUT_PATH),--output-path $(OUTPUT_PATH),)

.PHONY: test-coverage
test-coverage: build tests/config/registration.yaml ## Run tests with coverage. Opts: FORMAT=json|html, OUTPUT_PATH=/my/path
	node scripts/run-tests.mjs -- cargo llvm-cov test --locked $(_COVERAGE_FORMAT) $(_COVERAGE_OUTPUT) --ignore-filename-regex config.rs -- --nocapture

.PHONY: publish
publish: test security ## Publish a development version after tests and security checks
	anypoint-cli-v4 pdk policy-project publish --binary-path $(TARGET_DIR)/$(CRATE_NAME).wasm --implementation-gcl-path $(TARGET_DIR)/$(CRATE_NAME)_implementation.yaml $(_SKIP_UNCHANGED_DEFINITION_FLAG)

.PHONY: release
release: test security ## Publish a release version after tests and security checks
	anypoint-cli-v4 pdk policy-project release --binary-path $(TARGET_DIR)/$(CRATE_NAME).wasm --implementation-gcl-path $(TARGET_DIR)/$(CRATE_NAME)_implementation.yaml $(_SKIP_UNCHANGED_DEFINITION_FLAG)

.PHONY: build-asset-files
build-asset-files: $(DEFINITION_SRC_GCL_PATH)
	@node --version >/dev/null || { echo "Node is required before configuration generation" >&2; exit 1; }
	@anypoint-cli-v4 pdk policy-project build-asset-files --metadata '$(ANYPOINT_METADATA_JSON)'
	@node scripts/generate-config.mjs "$(DEFINITION_SRC_GCL_PATH)" src/generated/config.rs

.PHONY: install-cargo-anypoint
install-cargo-anypoint:
	cargo install --locked cargo-anypoint@$(CARGO_ANYPOINT_VERSION)

.PHONY: install-llvm-cov
install-llvm-cov:
	rustup component add llvm-tools-preview
	cargo install --locked cargo-llvm-cov@$(CARGO_LLVM_COV_VERSION)

.PHONY: install-cargo-audit
install-cargo-audit:
	cargo install --locked cargo-audit@$(CARGO_AUDIT_VERSION)

.PHONY: show-policy-ref-name
show-policy-ref-name:
	@echo $(POLICY_REF_NAME)

ifneq ($(OS), Windows_NT)
all: help

.PHONY: help
help: ## Shows this help
	@echo 'Usage: make <target>'
	@echo ''
	@echo 'Available targets are:'
	@echo ''
	@grep -Eh '^\w[^:]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-6s\033[0m %s\n", $$1, $$2}' \
		| sort
endif
