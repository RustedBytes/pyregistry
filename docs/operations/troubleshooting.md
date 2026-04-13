# Troubleshooting

Start with the layer where the symptom appears, then move inward. Web errors are
usually adapter issues, application errors usually describe orchestration or
authorization problems, and domain errors usually mean an invariant was
violated.

## Service Will Not Start

Check configuration loading:

```bash
scripts/pyregistry-release.sh --config pyregistry.toml serve
```

Common causes:

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Config file rejected | Path does not end in `.toml`. | Use a `.toml` config path. |
| SQLite config required | `database_store = "sqlite"` without `[sqlite]`. | Add SQLite config or generate a new template. |
| Postgres config required | `database_store = "pgsql"` without `[postgres]`. | Add Postgres config. |
| SQL Server config required | `database_store = "sqlserver"` without `[sql_server]`. | Add SQL Server config or set `SQL_SERVER_URL`. |
| Object storage error | OpenDAL options do not match the backend. | Check `scheme` and backend options. |
| Bind failure | Address already in use or unavailable. | Change `bind_address` or stop the other process. |

## Login Fails

Check:

- You are using the configured `superadmin_email`.
- You are using the configured `superadmin_password`.
- The service was started with the config you edited.
- The metadata store was seeded from the expected config.

For local development, generated credentials are:

```text
admin@pyregistry.local
change-me-now
```

## pip Or uv Cannot Install

Check:

- The token has `read` scope.
- The tenant slug in the URL is correct.
- The URL ends with `/simple/`.
- The package name exists locally or tenant mirroring is enabled.
- The reverse proxy preserves path segments.
- Rate limiting is not rejecting the client.

Example:

```bash
python -m pip install \
  --index-url "http://__token__:pyr_...@127.0.0.1:3000/t/acme/simple/" \
  your-package
```

## twine Cannot Upload

Check:

- `TWINE_USERNAME` is `__token__`.
- `TWINE_PASSWORD` is an API token with `publish` scope.
- The upload URL ends with `/legacy/`.
- The artifact filename is a supported wheel or source distribution.
- The same filename was not already uploaded for the release.

Example:

```bash
twine upload \
  --repository-url "http://127.0.0.1:3000/t/acme/legacy/" \
  dist/*
```

## Mirroring Does Not Fetch A Package

Check:

- Tenant mirroring is enabled.
- `[pypi].base_url` points to a PyPI-compatible upstream.
- The upstream project exists.
- The service can reach the upstream network address.
- Object storage accepts writes.
- Retry settings are not too low for a slow upstream.

Local projects take precedence over mirrored projects with the same normalized
name.

## Trusted Publishing Fails

Check:

- The issuer is configured in `[[oidc_issuers]]`.
- The JWKS URL is reachable from the service.
- For local experiments, a real `jwks.json` fixture exists at the configured
  URL; the generated config points at a placeholder local endpoint.
- The audience in the incoming token matches the configured audience.
- The provider matches the trusted publisher.
- Registered claim rules match the token claims exactly.
- The trusted publisher is registered for the target tenant and project.

## Security Scan Is Slow

Wheel scans use release-mode code much more effectively than debug builds.

Prefer:

```bash
scripts/pyregistry-release.sh audit-wheel --project example --wheel path/to/file.whl
```

The first full build after adding YARA-X can take longer because the dependency
tree includes scanner and Wasmtime components.

## Validate Stored Artifacts

Run:

```bash
scripts/pyregistry-release.sh validate-dist-all --tenant acme --parallelism 8
```

This reports:

- Missing object-storage blobs.
- Checksum mismatches.
- Corrupt archives.
- Unsupported distribution formats.
- Storage errors.

## Debugging Rule Of Thumb

| Error source | Meaning |
| --- | --- |
| Domain error | Business rule or value invariant failed. |
| Application error | Use case could not complete, resource was missing, authorization failed, or an external port failed. |
| Infrastructure error | Config, database, object storage, HTTP, OIDC, scanner, or filesystem problem. |
| Web error | Request parsing, response mapping, session, rate limit, or route issue. |
