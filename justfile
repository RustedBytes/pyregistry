set shell := ["bash", "-euo", "pipefail", "-c"]

config := "pyregistry.toml"
tenant := "acme"

# List available commands.
default:
    @just --list

# Format Rust code.
fmt:
    cargo fmt

# Check Rust formatting without changing files.
fmt-check:
    cargo fmt -- --check

# Type-check the whole workspace.
check:
    cargo check --workspace

# Run the documented workspace test suite with Nextest.
test:
    cargo nextest run --workspace

# Run the CI-style locked Cargo test workflow.
test-locked:
    cargo test --workspace --all-targets --locked

# Run Nextest with the CI profile.
test-ci:
    cargo nextest run --workspace --profile ci

# Run the coverage gate. Extra args are forwarded to scripts/coverage.sh.
coverage *args:
    ./scripts/coverage.sh {{args}}

# Run the coverage gate with the CI Nextest profile.
coverage-ci:
    ./scripts/coverage.sh --profile ci

# Run the local handoff checks documented in README.md and docs/development.md.
qa: fmt check test coverage

# Run read-only handoff checks.
qa-check: fmt-check check test coverage

# Run one cargo-fuzz target. Usage: just fuzz wheel_audit 60
fuzz target seconds="60":
    cargo +nightly fuzz run {{target}} -- -max_total_time={{seconds}} -rss_limit_mb=4096

# Run every maintained cargo-fuzz target briefly.
fuzz-smoke seconds="10":
    cargo +nightly fuzz run domain_inputs -- -max_total_time={{seconds}} -rss_limit_mb=4096
    cargo +nightly fuzz run wheel_archive -- -max_total_time={{seconds}} -rss_limit_mb=4096
    cargo +nightly fuzz run distribution_validation -- -max_total_time={{seconds}} -rss_limit_mb=4096
    cargo +nightly fuzz run wheel_audit -- -max_total_time={{seconds}} -rss_limit_mb=4096

# Build the workspace.
build:
    cargo build --workspace

# Build the release binary.
build-release:
    cargo build --release -p pyregistry

# Generate a local filesystem-backed config.
init-config path=config:
    cargo run -p pyregistry -- init-config --path {{path}} --force

# Generate a local MinIO-backed config.
init-config-minio path=config:
    cargo run -p pyregistry -- init-config --path {{path}} --storage minio --force

# Start Pyregistry through the release wrapper.
serve path=config:
    scripts/pyregistry-release.sh --config {{path}} serve

# Show Pyregistry CLI help through the release wrapper.
cli-help:
    scripts/pyregistry-release.sh --help

# Audit a wheel. Usage: just audit-wheel PROJECT path/to/file.whl
audit-wheel project wheel:
    scripts/pyregistry-release.sh audit-wheel --project {{project}} --wheel {{wheel}}

# Validate one distribution file. Usage: just validate-dist dist/pkg.whl [--sha256 HASH]
validate-dist file *args:
    scripts/pyregistry-release.sh validate-dist --file {{file}} {{args}}

# Validate every stored distribution for a tenant.
validate-dist-all tenant=tenant parallelism="8":
    scripts/pyregistry-release.sh validate-dist-all --tenant {{tenant}} --parallelism {{parallelism}}

# Check stored package versions for known vulnerabilities.
check-registry tenant=tenant:
    scripts/pyregistry-release.sh check-registry --tenant {{tenant}}

# Build and start the full Docker Compose stack.
compose-up:
    docker compose up --build

# Start only the registry and its Compose dependencies.
compose-registry:
    docker compose up --build pyregistry

# Start optional local services without the registry container.
compose-services:
    docker compose up -d postgres sqlserver minio minio-init jwks

# Stop the Docker Compose stack.
compose-down:
    docker compose down

# Serve the MkDocs documentation locally.
docs-serve:
    mkdocs serve

# Build the MkDocs documentation with strict validation.
docs-build:
    mkdocs build --strict

# Refresh vendored YARA signatures.
update-yara:
    scripts/update-yara-signatures.sh
