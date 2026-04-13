# Pyregistry

[![Tests](https://github.com/RustedBytes/pyregistry/actions/workflows/test.yml/badge.svg)](https://github.com/RustedBytes/pyregistry/actions/workflows/test.yml)

Pyregistry is an internal Python package registry written in Rust. It is aimed
at companies that need tenant-scoped package publishing, authenticated installs,
private search, PyPI mirroring, provenance, trusted publishing, and lightweight
package security checks without running a full PyPI clone.

The project is intentionally server-rendered and minimal: Axum for HTTP, Askama
templates compiled into the binary, TOML configuration, and no frontend build
pipeline.

## Table of Contents

- [Current Status](#current-status)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quickstart](#quickstart)
- [Docker Compose](#docker-compose)
- [Local Services](#local-services)
- [Configuration](#configuration)
- [CLI](#cli)
- [Python Tooling](#python-tooling)
- [HTTP Interfaces](#http-interfaces)
- [Security Scanning](#security-scanning)
- [Mirroring](#mirroring)
- [Trusted Publishing](#trusted-publishing)
- [Development Notes](#development-notes)
- [License](#license)

## Current Status

Implemented today:

- Multi-crate Rust workspace with Clean Architecture boundaries.
- Public landing page with aggregate registry statistics.
- Admin login, dashboard, tenant creation, package search, and token issuance.
- Durable audit trail for admin, token upload, and OIDC publishing actions.
- Tenant-scoped Simple Repository API and legacy `twine` upload endpoint.
- Authenticated package downloads using API tokens.
- Read-through mirroring from a configurable PyPI-compatible upstream.
- Background mirror cache downloads from the admin UI.
- PEP 592-style yanking and local package purge flows.
- Provenance storage and trusted-publishing attestation plumbing.
- OIDC trusted publishing token minting for configured issuers.
- SQLite metadata store by default, with in-memory available for throwaway runs.
- OpenDAL artifact storage with filesystem and S3/MinIO configuration.
- Per-client rate limiting for package and OIDC API endpoints.
- Wheel audit CLI and UI modal with RustPython AST checks, FoxGuard source
  checks, heuristics, and YARA virus signatures.
- PySentry-backed known vulnerability checks for package versions.
- Bundled HTML templates and vendored YARA signature material, so the binary can
  run without a repository checkout.

Important limitations:

- SQLite is the default metadata store. PostgreSQL and Microsoft SQL Server are
  available for persistent deployments, and the `in-memory` store is still
  available for throwaway development runs.
- The UI is intentionally small and admin-focused.
- Mirroring targets a PyPI-compatible JSON/files API and defaults to
  `https://pypi.org`.

## Architecture

The workspace keeps dependency direction pointed inward:

- `crates/domain`: pure entities, value objects, invariants, and domain errors.
- `crates/application`: use cases, commands, DTOs, and ports.
- `crates/web`: Axum handlers, Askama templates, presenters, and web auth.
- `crates/infrastructure`: config, logging, SQLite, PostgreSQL, SQL Server, and in-memory stores,
  OpenDAL storage, PyPI mirror client, OIDC verification, hashing, PySentry,
  YARA-X, and wiring.
- `crates/bootstrap`: binary entrypoint and CLI command dispatch.

The domain crate has no dependency on web frameworks, storage backends, SQL
drivers, serialization formats, or config loading.

## Prerequisites

- Rust stable with Edition 2024 support. `yara-x` currently requires Rust 1.89+
  and this repository has been tested with a newer stable toolchain.
- `cargo-nextest` for the workspace test runner:
  `cargo install cargo-nextest --locked`
- `cargo-llvm-cov` for the coverage gate:
  `cargo install cargo-llvm-cov --locked`
- Docker Compose, optional, for local Postgres, SQL Server, MinIO, and the test JWKS server.
- Python tooling such as `pip`, `uv`, and `twine`, optional, for compatibility
  smoke tests.

## Quickstart

Build and test:

```bash
cargo fmt
cargo check --workspace
cargo nextest run --workspace
./scripts/coverage.sh
```

Generate a local config:

```bash
cargo run -p pyregistry -- init-config --path pyregistry.toml --force
```

Start the service:

```bash
scripts/pyregistry-release.sh --config pyregistry.toml serve
```

Then open:

```text
http://127.0.0.1:3000/
http://127.0.0.1:3000/admin/login
```

Default local admin credentials from generated config:

```text
admin@pyregistry.local
change-me-now
```

Change these before using the service for anything beyond local development.

## Docker Compose

Build and start the registry with the local Compose stack:

```bash
docker compose up --build
```

This starts the following published services, reachable from the host through
Docker Compose port mappings:

- Pyregistry at `http://127.0.0.1:3000`, backed by SQLite and filesystem
  artifact storage in the `pyregistry-data` volume.
- Postgres at `127.0.0.1:5432`.
- SQL Server at `127.0.0.1:1433`.
- MinIO S3 API at `127.0.0.1:9000`.
- MinIO console at `127.0.0.1:9001`.
- JWKS test server at `127.0.0.1:8081`.

To start only the registry and the JWKS test server:

```bash
docker compose up --build pyregistry
```

Legacy Compose v1 users can run the same commands with `docker-compose`.

## Local Services

Start the optional local dependencies without the registry container:

```bash
docker compose up -d postgres sqlserver minio minio-init jwks
```

Generate a MinIO-oriented config:

```bash
cargo run -p pyregistry -- init-config \
  --path pyregistry.toml \
  --storage minio \
  --force
```

The generated MinIO template uses bucket `pyregistry` and credentials matching
`docker-compose.yml`.

## Configuration

Pyregistry loads settings in this order:

- Explicit `--config <PATH>` passed to the CLI.
- `pyregistry.toml` in the current directory.
- Environment variables.

Only TOML config files are supported. Config paths must use a `.toml` suffix.

Common settings:

```toml
bind_address = "127.0.0.1:3000"
blob_root = ".pyregistry/blobs"
superadmin_email = "admin@pyregistry.local"
superadmin_password = "change-me-now"
cookie_secret = "replace-me-with-a-long-random-string"
database_store = "sqlite"

[artifact_storage]
backend = "opendal"

[artifact_storage.opendal]
scheme = "fs"

[artifact_storage.opendal.options]
root = ".pyregistry/blobs"

[pypi]
base_url = "https://pypi.org"
mirror_download_concurrency = 4
mirror_eager_download_percent = 10
artifact_download_max_attempts = 3
artifact_download_initial_backoff_millis = 250
mirror_update_enabled = true
mirror_update_interval_seconds = 3600
mirror_update_on_startup = true

[sqlite]
path = ".pyregistry/pyregistry.sqlite3"

[postgres]
connection_url = "postgres://pyregistry:pyregistry@127.0.0.1:5432/pyregistry"
max_connections = 20
min_connections = 2
acquire_timeout_seconds = 10

[sql_server]
connection_url = "sqlserver://sa:Pyregistry123!@127.0.0.1:1433/pyregistry?trust_server_certificate=true"
max_connections = 20
min_connections = 2
acquire_timeout_seconds = 10

[security]
yara_rules_path = "supplied/signature-base/yara"

[security.vulnerability_webhook]
url = "https://discord.com/api/webhooks/..."
username = "Pyregistry"
timeout_seconds = 10

[security.package_publish_webhook]
url = "https://discord.com/api/webhooks/..."
username = "Pyregistry"
timeout_seconds = 10

[rate_limit]
enabled = true
requests_per_minute = 120
burst = 60
max_tracked_clients = 10000
trust_proxy_headers = false

[network_source]
web_ui_allowed_cidrs = []
api_allowed_cidrs = []
trust_proxy_headers = false

[web_ui]
show_index_stats = true

[validation]
distribution_parallelism = 4

[logging]
filter = "info"
module_path = true
target = false
timestamp = "seconds"
```

The current PostgreSQL adapter uses a single `tokio-postgres` connection with
connection pipelining. `max_connections` and `min_connections` are accepted
configuration fields for compatibility with future pooling, but they do not
create a connection pool today.

The SQL Server adapter uses `tiberius` and the same application `RegistryStore`
port. Select it with `database_store = "sqlserver"` and configure `[sql_server]`
or `SQL_SERVER_URL`.

Set `security.yara_rules_path` to a directory containing your own `.yar` or
`.yara` files to replace the default on-disk rule directory. For one-off runs,
pass `--yara-rules-path /path/to/yara-rules`; the CLI override wins over both
`pyregistry.toml` and `YARA_RULES_PATH`.

S3/MinIO storage example:

```toml
[artifact_storage]
backend = "opendal"

[artifact_storage.opendal]
scheme = "s3"

[artifact_storage.opendal.options]
bucket = "pyregistry"
endpoint = "http://127.0.0.1:9000"
region = "us-east-1"
access_key_id = "pyregistry"
secret_access_key = "pyregistry123"
root = "/artifacts"
disable_config_load = "true"
disable_ec2_metadata = "true"
enable_virtual_host_style = "false"
```

Useful environment variables:

- `BIND_ADDRESS`
- `BLOB_ROOT`
- `SUPERADMIN_EMAIL`
- `SUPERADMIN_PASSWORD`
- `COOKIE_SECRET`
- `DATABASE_STORE`
- `SQLITE_PATH` or `SQLITE_DATABASE_PATH`
- `DATABASE_URL` or `POSTGRES_URL`
- `POSTGRES_MAX_CONNECTIONS`
- `POSTGRES_MIN_CONNECTIONS`
- `POSTGRES_ACQUIRE_TIMEOUT_SECONDS`
- `SQL_SERVER_URL` or `MSSQL_URL`
- `SQL_SERVER_MAX_CONNECTIONS`
- `SQL_SERVER_MIN_CONNECTIONS`
- `SQL_SERVER_ACQUIRE_TIMEOUT_SECONDS`
- `ARTIFACT_STORAGE_BACKEND`
- `OPENDAL_SCHEME`
- `OPENDAL_OPTIONS`
- `OPENDAL_ROOT`
- `OPENDAL_BUCKET`
- `OPENDAL_ENDPOINT`
- `OPENDAL_REGION`
- `OPENDAL_ACCESS_KEY_ID`
- `OPENDAL_SECRET_ACCESS_KEY`
- `OPENDAL_SESSION_TOKEN`
- `OPENDAL_DISABLE_CONFIG_LOAD`
- `OPENDAL_DISABLE_EC2_METADATA`
- `OPENDAL_ENABLE_VIRTUAL_HOST_STYLE`
- `OPENDAL_ALLOW_ANONYMOUS`
- `PYPI_BASE_URL` or `PYPI_URL`
- `PYPI_MIRROR_DOWNLOAD_CONCURRENCY`
- `PYPI_ARTIFACT_DOWNLOAD_MAX_ATTEMPTS`
- `PYPI_ARTIFACT_DOWNLOAD_INITIAL_BACKOFF_MILLIS`
- `PYPI_MIRROR_UPDATE_ENABLED`
- `PYPI_MIRROR_UPDATE_INTERVAL_SECONDS`
- `PYPI_MIRROR_UPDATE_ON_STARTUP`
- `YARA_RULES_PATH`
- `VULNERABILITY_WEBHOOK_URL`
- `VULNERABILITY_WEBHOOK_USERNAME`
- `VULNERABILITY_WEBHOOK_TIMEOUT_SECONDS`
- `PACKAGE_PUBLISH_WEBHOOK_URL`
- `PACKAGE_PUBLISH_WEBHOOK_USERNAME`
- `PACKAGE_PUBLISH_WEBHOOK_TIMEOUT_SECONDS`
- `RATE_LIMIT_ENABLED`
- `RATE_LIMIT_REQUESTS_PER_MINUTE`
- `RATE_LIMIT_BURST`
- `RATE_LIMIT_MAX_TRACKED_CLIENTS`
- `RATE_LIMIT_TRUST_PROXY_HEADERS`
- `NETWORK_SOURCE_WEB_UI_ALLOWED_CIDRS`
- `NETWORK_SOURCE_API_ALLOWED_CIDRS`
- `NETWORK_SOURCE_TRUST_PROXY_HEADERS`
- `WEB_UI_SHOW_INDEX_STATS`
- `VALIDATION_DISTRIBUTION_PARALLELISM`
- `LOG_FILTER`
- `LOG_MODULE_PATH`
- `LOG_TARGET`
- `LOG_TIMESTAMP`
- `OIDC_ISSUERS`

Rate limiting applies to package and OIDC API paths (`/t/...` and
`/_/oidc/...`). By default Pyregistry keys limits by the direct TCP peer IP. If
the service runs behind a trusted reverse proxy, set `trust_proxy_headers = true`
so `X-Forwarded-For`, `X-Real-IP`, or `Forwarded` can be used instead.

Network source checks can separately restrict the Web UI (`/` and `/admin...`)
and package/OIDC API routes. Empty CIDR lists allow every source; set
`network_source.trust_proxy_headers = true` only behind a trusted reverse proxy.
Set `web_ui.show_index_stats = false` to hide public index page registry counts.

## CLI

```bash
scripts/pyregistry-release.sh --help
```

Commands:

```bash
scripts/pyregistry-release.sh serve
cargo run -p pyregistry -- init-config --path pyregistry.toml --force
scripts/pyregistry-release.sh audit-wheel --project rsloop --wheel rsloop-0.1.14-cp314-cp314t-win_arm64.whl
scripts/pyregistry-release.sh validate-dist --file dist/demo-0.1.0-py3-none-any.whl --sha256 <expected-sha256>
scripts/pyregistry-release.sh validate-dist --file dist/demo-0.1.0.tar.gz
scripts/pyregistry-release.sh validate-dist-all --tenant acme --parallelism 8
scripts/pyregistry-release.sh check-registry --tenant acme
```

Use release mode for serving, mirroring, vulnerability checks, and wheel scans.
Debug builds work for development, but they are much slower for YARA and
RustPython analysis. The helper above is equivalent to
`cargo run --release -p pyregistry -- ...`.

`audit-wheel` downloads the named wheel from the configured PyPI upstream if the
file is not present locally. The audit checks:

- Unexpected executables or shell scripts.
- Network-related strings inside binaries.
- Post-install behavior clues in package contents.
- Suspicious Python imports and runtime calls using RustPython AST analysis.
- Suspicious dependencies in `METADATA`.
- YARA virus signature matches using the configured rule directory.

`validate-dist` checks downloaded `.whl`, `.tar.gz`, `.tgz`, and `.zip` files
before you trust or import them. It computes SHA-256, optionally compares it
with `--sha256`, and fully reads the zip or tar.gz archive so corrupt payloads
fail fast.

`validate-dist-all` performs the same checksum and archive checks for stored
registry artifact blobs. Use `--tenant` and `--project` to narrow the scope; it
reports missing object-storage blobs, checksum mismatches, corrupt archives, and
source formats this validator does not yet support. Archive inspection supports
wheels plus tar.gz/tgz and zip source distributions, and runs in parallel with
Rayon; tune the default with `[validation].distribution_parallelism` or override
a single run with `--parallelism`.

`check-registry` checks package versions stored in the current metadata store
for known vulnerabilities through the PySentry adapter. Configure
`[security.vulnerability_webhook]` or `VULNERABILITY_WEBHOOK_URL` to send a
Discord-compatible webhook message for each vulnerable package found by that
command.

Configure `[security.package_publish_webhook]` or
`PACKAGE_PUBLISH_WEBHOOK_URL` to send Discord-compatible notifications when a
publish creates a new package or adds a new version.

## Python Tooling

Use an API token with `read` scope for installs:

```bash
export PYREGISTRY_TOKEN="pyr_..."
uv pip install \
  --index-url "http://__token__:${PYREGISTRY_TOKEN}@127.0.0.1:3000/t/acme/simple/" \
  your-package
```

The same index URL shape also works with `pip`:

```bash
python -m pip install \
  --index-url "http://__token__:${PYREGISTRY_TOKEN}@127.0.0.1:3000/t/acme/simple/" \
  your-package
```

Use an API token with `publish` scope for `twine` uploads:

```bash
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="pyr_..."
twine upload \
  --repository-url "http://127.0.0.1:3000/t/acme/legacy/" \
  dist/*
```

## HTTP Interfaces

Public and admin pages:

- `GET /`
- `GET /admin/login`
- `GET /admin/dashboard`
- `GET /admin/search?q=...`
- `GET /admin/t/{tenant}/packages`
- `GET /admin/t/{tenant}/packages/{project}`

Package API:

- `GET /t/{tenant}/simple/`
- `GET /t/{tenant}/simple/{project}/`
- `POST /t/{tenant}/legacy/`
- `GET /t/{tenant}/files/{project}/{version}/{filename}`
- `GET /t/{tenant}/provenance/{project}/{version}/{filename}`

Trusted publishing API:

- `GET /_/oidc/audience`
- `POST /_/oidc/mint-token`

Admin actions include tenant creation, API token issuance, mirror cache
refresh, trusted publisher registration, yanking, unyanking, purge, audit trail,
and wheel scan.

## Security Scanning

Pyregistry has two separate security scan paths:

- Known vulnerability checks use `pysentry` and the PyPA advisory source. Package
  pages show a release-file summary, and `check-registry` exposes a CLI view.
- Wheel content checks use RustPython AST analysis for Python files, FoxGuard
  source and secret checks, built-in heuristics for package layout/binaries,
  and VirusTotal `yara-x` over the configured YARA rule directory. The same
  audit output is available from the `audit-wheel` CLI and the package page
  "Wheel scan" modal.

The repository vendors Neo23x0 `signature-base` YARA rules under
`supplied/signature-base`. The supplied rules are licensed separately under the
Detection Rule License in `supplied/signature-base/LICENSE`.
Those supplied files are embedded into the binary at compile time. If
`security.yara_rules_path` points to a readable directory, Pyregistry uses that
external rule set; otherwise it falls back to the bundled supplied rules.
Use `--yara-rules-path /path/to/yara-rules` to override the configured directory
for a command or service start without editing `pyregistry.toml`.

To refresh the bundled signatures locally, run:

```bash
scripts/update-yara-signatures.sh
```

GitHub Actions also runs `.github/workflows/update-yara-signatures.yml` weekly
and opens a maintenance pull request when upstream YARA files change.

## Mirroring

Tenant admins can enable mirroring and request a mirror cache refresh from the
dashboard. Local projects take precedence over mirrored projects with the same
normalized name, so internal packages are not shadowed by upstream packages.

The upstream base URL is configurable:

```toml
[pypi]
base_url = "https://pypi.org"
mirror_download_concurrency = 4
mirror_eager_download_percent = 10
artifact_download_max_attempts = 3
artifact_download_initial_backoff_millis = 250
mirror_update_enabled = true
mirror_update_interval_seconds = 3600
mirror_update_on_startup = true
```

For an internal PyPI-compatible mirror, set `base_url` to that service instead.
Increase `mirror_download_concurrency` to cache large projects faster, or lower
it if your upstream mirror or object storage needs gentler traffic.
By default, only the newest 10% of release versions are eagerly cached while
older release metadata remains available for on-demand downloads. Set
`mirror_eager_download_percent = 5` for a smaller eager cache.
Set it to `0` to disable eager artifact caching entirely.
Artifact downloads retry transient network failures plus HTTP 408, 429, and
5xx responses using exponential backoff from
`artifact_download_initial_backoff_millis` up to
`artifact_download_max_attempts`.
The background updater periodically refreshes already-mirrored projects in
tenants where mirroring is enabled. It discovers newer upstream releases and
files, then caches them locally using the same bounded download concurrency.
Set `mirror_update_enabled = false` to disable background refreshes, or tune
`mirror_update_interval_seconds` for your upstream traffic budget.

## Trusted Publishing

Trusted publishers are registered per tenant and project. The OIDC mint endpoint
validates an incoming issuer token against configured JWKS settings and returns
a short-lived publish token when claims match a registered publisher.

The local template includes a development JWKS issuer:

```toml
[[oidc_issuers]]
provider = "github"
issuer = "https://issuer.pyregistry.local"
jwks_url = "http://127.0.0.1:8081/jwks.json"
audience = "pyregistry"
```

GitHub Actions and configurable GitLab-style issuers are modeled in the domain
and application layers.

## Development Notes

Run the main checks before handing off changes:

```bash
cargo fmt
cargo check --workspace
cargo nextest run --workspace
./scripts/coverage.sh
```

Use the CI-oriented Nextest profile when you want retries for potentially flaky
integration checks:

```bash
cargo nextest run --workspace --profile ci
./scripts/coverage.sh --profile ci
```

The coverage gate requires at least 95% total line coverage and at least 95%
line coverage for every reported Rust source file. By default the script omits
the binary bootstrap entrypoint and live PostgreSQL adapter from the stable core
surface; set `COVERAGE_IGNORE_FILENAME_REGEX` to replace that default ignore
list. To experiment with a different local threshold, set `COVERAGE_MIN_LINES`
or `COVERAGE_MIN_FILE_LINES`, for example
`COVERAGE_MIN_FILE_LINES=90 ./scripts/coverage.sh`.

The first full build after adding YARA-X can take longer because the dependency
tree includes the YARA-X scanner and Wasmtime components.

Keep new features aligned with the crate boundaries:

- Domain owns business invariants.
- Application owns use cases and ports.
- Web owns HTTP and template presentation.
- Infrastructure owns external systems and third-party crates.
- Bootstrap owns CLI and process wiring.

## License

The Pyregistry code is licensed as `GPL-3.0-or-later`.

Vendored YARA rules in `supplied/signature-base` are supplied material from
Neo23x0 `signature-base` and are licensed under the Detection Rule License. See
`supplied/signature-base/LICENSE` for the rule license text.
