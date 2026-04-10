# Pyregistry

Pyregistry is an internal Python package registry written in Rust. It is aimed
at companies that need tenant-scoped package publishing, authenticated installs,
private search, PyPI mirroring, provenance, trusted publishing, and lightweight
package security checks without running a full PyPI clone.

The project is intentionally server-rendered and minimal: Axum for HTTP, Askama
templates for HTML, TOML/YAML configuration, and no frontend build pipeline.

## Current Status

This is base code for a registry service, not a production release yet.

Implemented today:

- Multi-crate Rust workspace with Clean Architecture boundaries.
- Public landing page with aggregate registry statistics.
- Admin login, dashboard, tenant creation, package search, and token issuance.
- Tenant-scoped Simple Repository API and legacy `twine` upload endpoint.
- Authenticated package downloads using API tokens.
- Read-through mirroring from a configurable PyPI-compatible upstream.
- Background mirror cache downloads from the admin UI.
- PEP 592-style yanking and local package purge flows.
- Provenance storage and trusted-publishing attestation plumbing.
- OIDC trusted publishing token minting for configured issuers.
- OpenDAL artifact storage with filesystem and S3/MinIO configuration.
- Wheel audit CLI and UI modal with heuristic checks plus YARA virus signatures.
- PySentry-backed known vulnerability checks for package versions.

Important limitations:

- The default metadata store is in-memory, so data is lost when the process
  exits and a separate CLI process will not see packages from a running server.
- `database_store = "pgsql"` is accepted in config, but the Postgres metadata
  adapter is not implemented yet.
- The UI is intentionally small and admin-focused.
- Mirroring targets a PyPI-compatible JSON/files API and defaults to
  `https://pypi.org`.

## Architecture

The workspace keeps dependency direction pointed inward:

- `crates/domain`: pure entities, value objects, invariants, and domain errors.
- `crates/application`: use cases, commands, DTOs, and ports.
- `crates/web`: Axum handlers, Askama templates, presenters, and web auth.
- `crates/infrastructure`: config, logging, in-memory store, OpenDAL storage,
  PyPI mirror client, OIDC verification, hashing, PySentry, YARA-X, and wiring.
- `crates/bootstrap`: binary entrypoint and CLI command dispatch.

The domain crate has no dependency on web frameworks, storage backends, SQL
drivers, serialization formats, or config loading.

## Prerequisites

- Rust stable with Edition 2024 support. `yara-x` currently requires Rust 1.89+
  and this repository has been tested with a newer stable toolchain.
- Docker Compose, optional, for local Postgres, MinIO, and the test JWKS server.
- Python tooling such as `pip`, `uv`, and `twine`, optional, for compatibility
  smoke tests.

## Quickstart

Build and test:

```bash
cargo fmt
cargo check
cargo test
```

Generate a local config:

```bash
cargo run -p pyregistry -- init-config --path pyregistry.toml --force
```

Start the service:

```bash
cargo run -p pyregistry -- --config pyregistry.toml serve
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

## Local Services

Start the optional local dependencies:

```bash
docker compose up -d
```

This starts:

- Postgres on `127.0.0.1:5432`.
- MinIO S3 API on `127.0.0.1:9000`.
- MinIO console on `127.0.0.1:9001`.
- JWKS test server on `127.0.0.1:8081`.

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

TOML and YAML are supported. The file format is inferred from the extension.

Common settings:

```toml
bind_address = "127.0.0.1:3000"
blob_root = ".pyregistry/blobs"
superadmin_email = "admin@pyregistry.local"
superadmin_password = "change-me-now"
cookie_secret = "replace-me-with-a-long-random-string"
database_store = "in-memory"

[artifact_storage]
backend = "opendal"

[artifact_storage.opendal]
scheme = "fs"

[artifact_storage.opendal.options]
root = ".pyregistry/blobs"

[pypi]
base_url = "https://pypi.org"

[security]
yara_rules_path = "supplied/signature-base/yara"

[logging]
filter = "info"
module_path = true
target = false
timestamp = "seconds"
```

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
- `DATABASE_STORE`
- `DATABASE_URL` or `POSTGRES_URL`
- `POSTGRES_MAX_CONNECTIONS`
- `POSTGRES_MIN_CONNECTIONS`
- `POSTGRES_ACQUIRE_TIMEOUT_SECONDS`
- `PYPI_BASE_URL` or `PYPI_URL`
- `YARA_RULES_PATH`
- `LOG_FILTER`
- `LOG_MODULE_PATH`
- `LOG_TARGET`
- `LOG_TIMESTAMP`
- `OIDC_ISSUERS`

## CLI

```bash
cargo run -p pyregistry -- --help
```

Commands:

```bash
cargo run -p pyregistry -- serve
cargo run -p pyregistry -- init-config --path pyregistry.toml --force
cargo run -p pyregistry -- audit-wheel --project rsloop --wheel rsloop-0.1.14-cp314-cp314t-win_arm64.whl
cargo run -p pyregistry -- check-registry --tenant acme
```

`audit-wheel` downloads the named wheel from the configured PyPI upstream if the
file is not present locally. The audit checks:

- Unexpected executables or shell scripts.
- Network-related strings inside binaries.
- Post-install behavior clues in package contents.
- Suspicious dependencies in `METADATA`.
- YARA virus signature matches using the configured rule directory.

`check-registry` checks package versions stored in the current metadata store
for known vulnerabilities through the PySentry adapter.

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
refresh, trusted publisher registration, yanking, unyanking, purge, and wheel
scan.

## Security Scanning

Pyregistry has two separate security scan paths:

- Known vulnerability checks use `pysentry` and the PyPA advisory source. Package
  pages show a release-file summary, and `check-registry` exposes a CLI view.
- Wheel content checks use built-in heuristics plus VirusTotal `yara-x` over the
  configured YARA rule directory. The same audit output is available from the
  `audit-wheel` CLI and the package page "Wheel scan" modal.

The repository vendors Neo23x0 `signature-base` YARA rules under
`supplied/signature-base`. The supplied rules are licensed separately under the
Detection Rule License in `supplied/signature-base/LICENSE`.

## Mirroring

Tenant admins can enable mirroring and request a mirror cache refresh from the
dashboard. Local projects take precedence over mirrored projects with the same
normalized name, so internal packages are not shadowed by upstream packages.

The upstream base URL is configurable:

```toml
[pypi]
base_url = "https://pypi.org"
```

For an internal PyPI-compatible mirror, set `base_url` to that service instead.

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
cargo check
cargo test
```

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
