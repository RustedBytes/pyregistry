# Deployment

Pyregistry currently gives you the pieces for a company pilot. Treat production
deployment as a hardening exercise around storage, credentials, network
controls, backups, monitoring, and release management.

## Recommended Pilot Topology

For a shared internal pilot:

| Component | Recommendation |
| --- | --- |
| Pyregistry process | Run the release binary behind an internal reverse proxy. |
| Metadata | Use Postgres for shared environments. |
| Artifacts | Use S3-compatible object storage through OpenDAL. |
| TLS | Terminate HTTPS at the reverse proxy or platform ingress. |
| Secrets | Inject config through a secret manager or platform secret store. |
| Logs | Send structured process logs to your central collector. |
| Backups | Back up metadata and artifact storage on the same recovery schedule. |

SQLite and filesystem storage are excellent for local development. They are not
the best first choice for a multi-team company deployment.

## Build A Release Binary

```bash
cargo build --release
```

The binary is:

```text
target/release/pyregistry
```

The helper script runs the same binary through Cargo:

```bash
scripts/pyregistry-release.sh --config pyregistry.toml serve
```

GitHub releases are created by the tag-based workflow in
`.github/workflows/build-and-release.yml`.

## Process Startup

A service manager should run:

```bash
pyregistry --config /etc/pyregistry/pyregistry.toml serve
```

Provide:

- A TOML config or environment variables.
- Network access to Postgres.
- Network access to object storage.
- Network access to the configured PyPI-compatible upstream.
- Network access to OIDC JWKS endpoints if trusted publishing is enabled.

## Reverse Proxy

Put Pyregistry behind a reverse proxy or platform ingress for company use.

Configure:

- HTTPS.
- Request size limits appropriate for Python distributions.
- Access logging.
- Timeouts long enough for package uploads and mirrored artifact downloads.
- Trusted proxy header behavior only when the proxy controls those headers.

If `rate_limit.trust_proxy_headers` is false, Pyregistry keys rate limits by
the direct TCP peer. If the reverse proxy is the only direct peer, enable trusted
headers after confirming untrusted clients cannot spoof them.

## Storage And Backups

Back up both:

- Metadata store: tenants, tokens, projects, releases, artifact records,
  attestations, trusted publishers, audit events.
- Artifact object storage: wheel files, source distributions, and provenance
  payloads.

Backups must be coordinated enough that metadata does not point to missing
object keys after restore.

## Mirroring Operations

Mirroring uses the configured `[pypi]` upstream. For company deployments, decide
whether Pyregistry should point directly to `https://pypi.org` or to an existing
internal upstream mirror.

Tune:

| Setting | Why it matters |
| --- | --- |
| `mirror_download_concurrency` | Controls parallel artifact caching. |
| `artifact_download_max_attempts` | Controls retry attempts for transient failures. |
| `artifact_download_initial_backoff_millis` | Controls retry backoff start. |
| `mirror_update_enabled` | Enables background refresh of already mirrored projects. |
| `mirror_update_interval_seconds` | Controls upstream refresh frequency. |
| `mirror_update_on_startup` | Refreshes mirrored projects when the service starts. |

## Operational Checks

Useful commands:

```bash
scripts/pyregistry-release.sh check-registry --tenant acme
scripts/pyregistry-release.sh validate-dist-all --tenant acme --parallelism 8
scripts/pyregistry-release.sh audit-wheel --project example --wheel path/to/file.whl
```

Use `check-registry` to review known vulnerabilities in stored package versions.
Use `validate-dist-all` to find missing blobs, checksum mismatches, corrupt
archives, and unsupported distribution formats.

## Rollout Checklist

Before a broader rollout:

- Replace generated superadmin credentials.
- Replace generated cookie secrets.
- Use HTTPS.
- Use Postgres or another durable metadata plan.
- Use durable object storage.
- Enable backups and test restore.
- Define tenant ownership.
- Define token issuance and rotation policy.
- Decide PyPI upstream policy.
- Configure rate limiting behind the proxy.
- Configure OIDC issuers if using trusted publishing.
- Review logs for secrets before connecting to central logging.
- Run package install and upload smoke tests from real CI.
