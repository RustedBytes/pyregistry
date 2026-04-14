# Quickstart

This guide gets a local registry running, creates the first usable state, and
shows the commands you should run before changing code.

## Prerequisites

Install:

- Rust stable with Edition 2024 support.
- `cargo-nextest` for the workspace test runner.
- `cargo-llvm-cov` for coverage gates.
- Docker Compose if you want local Postgres, MinIO, and helper services.
- Python tooling such as `pip`, `uv`, and `twine` for client smoke tests.

```bash
cargo install cargo-nextest --locked
cargo install cargo-llvm-cov --locked
```

## Build And Test

From the repository root:

```bash
cargo fmt
cargo check --workspace
cargo nextest run --workspace
./scripts/coverage.sh
```

The coverage script enforces the repository coverage gate. Use it before
handing off changes that affect domain or application behavior.

## Generate Local Configuration

Create a starter TOML config:

```bash
cargo run -p pyregistry -- init-config --path pyregistry.toml --force
```

The generated local template uses:

- SQLite metadata at `.pyregistry/pyregistry.sqlite3`.
- OpenDAL filesystem artifact storage at `.pyregistry/blobs`.
- A local superadmin account.
- A development OIDC issuer entry that points at a local JWKS URL.

Default local admin credentials are:

```text
admin@pyregistry.local
change-me-now
```

Change these before using the service outside local development.

## Start The Service

Use the release wrapper for serving, mirroring, vulnerability checks, and wheel
scans:

```bash
scripts/pyregistry-release.sh --config pyregistry.toml serve
```

Open:

```text
http://127.0.0.1:3000/
http://127.0.0.1:3000/admin/login
```

On first startup, the application seeds a bootstrap tenant named `acme` if the
metadata store is empty.

## Optional Local Services

Start the optional local dependencies without starting the registry container:

```bash
docker compose up -d postgres minio minio-init
```

This starts:

| Service | Address | Purpose |
| --- | --- | --- |
| Postgres | `127.0.0.1:5432` | Persistent metadata store option. |
| MinIO S3 API | `127.0.0.1:9000` | S3-compatible artifact storage option. |
| MinIO console | `127.0.0.1:9001` | Local object storage console. |

The Compose file also defines a `jwks` nginx service for local OIDC
experiments, but this repository does not ship a signing-key fixture. Provide a
`docker/jwks/jwks.json` file or replace the generated issuer settings before
testing trusted publishing end to end.

Generate a MinIO-oriented config:

```bash
cargo run -p pyregistry -- init-config \
  --path pyregistry.toml \
  --storage minio \
  --force
```

The generated MinIO template uses bucket `pyregistry` and credentials from
`docker-compose.yml`.

## Smoke Test The Registry

After logging into the admin UI:

1. Create or use the `acme` tenant.
2. Issue an API token with `read` and `publish` scopes.
3. Configure Python tooling with the tenant URLs shown below.

Install from the tenant index:

```bash
export PYREGISTRY_TOKEN="pyr_..."

python -m pip install \
  --index-url "http://__token__:${PYREGISTRY_TOKEN}@127.0.0.1:3000/t/acme/simple/" \
  your-package
```

Upload with `twine`:

```bash
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="pyr_..."

twine upload \
  --repository-url "http://127.0.0.1:3000/t/acme/legacy/" \
  dist/*
```

## Useful CLI Commands

```bash
scripts/pyregistry-release.sh --help
scripts/pyregistry-release.sh serve
cargo run -p pyregistry -- init-config --path pyregistry.toml --force
scripts/pyregistry-release.sh --config pyregistry.toml create-tenant --slug acme --display-name "Acme Corp" --admin-email tenant-admin@acme.local --admin-password '<change-me>' --enable-mirroring
scripts/pyregistry-release.sh audit-wheel --project rsloop --wheel path/to/file.whl
scripts/pyregistry-release.sh validate-dist --file dist/demo-0.1.0-py3-none-any.whl --sha256 <expected-sha256>
scripts/pyregistry-release.sh validate-dist --file dist/demo-0.1.0.tar.gz
scripts/pyregistry-release.sh validate-dist-all --tenant acme --parallelism 8
scripts/pyregistry-release.sh check-registry --tenant acme
```

Debug builds work for development, but release mode is much faster for YARA and
RustPython analysis.
