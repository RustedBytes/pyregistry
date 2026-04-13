# Configuration

Pyregistry loads runtime settings from TOML or environment variables. Keep
configuration in the infrastructure layer; domain and application code should
receive already-built ports and values.

## Settings Source

The CLI chooses one settings source:

1. Explicit `--config <PATH>` passed to the CLI.
2. Otherwise, `pyregistry.toml` in the current directory when it exists.
3. Otherwise, environment variables.

Environment variables are a fallback source. They do not override values from a
TOML file that was selected by `--config` or by the default path lookup.

Only TOML config files are supported for file-based configuration. Config paths
must use a `.toml` suffix.

## Generate A Config

Local filesystem storage:

```bash
cargo run -p pyregistry -- init-config --path pyregistry.toml --force
```

MinIO storage:

```bash
cargo run -p pyregistry -- init-config \
  --path pyregistry.toml \
  --storage minio \
  --force
```

## Core Settings

```toml
bind_address = "127.0.0.1:3000"
blob_root = ".pyregistry/blobs"
superadmin_email = "admin@pyregistry.local"
superadmin_password = "change-me-now"
cookie_secret = "replace-me-with-a-long-random-string"
database_store = "sqlite"
```

| Setting | Purpose |
| --- | --- |
| `bind_address` | HTTP listen address. |
| `blob_root` | Legacy filesystem blob root and helper path for local state. |
| `superadmin_email` | Bootstrap superadmin login. |
| `superadmin_password` | Bootstrap superadmin password. |
| `cookie_secret` | Secret used for signed web cookies. |
| `database_store` | Metadata backend: `sqlite`, `pgsql`, `sqlserver`, or `in-memory`. |

Do not use generated credentials or cookie secrets in shared environments.

## Artifact Storage

Pyregistry uses OpenDAL for artifact storage by default.

Local filesystem:

```toml
[artifact_storage]
backend = "opendal"

[artifact_storage.opendal]
scheme = "fs"

[artifact_storage.opendal.options]
root = ".pyregistry/blobs"
```

S3 or MinIO:

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

Use company-managed object storage for shared deployments. Back up artifacts and
metadata together so package records and blobs stay consistent.

## Metadata Store

SQLite is the default and is suitable for local development and small pilots:

```toml
[sqlite]
path = ".pyregistry/pyregistry.sqlite3"
```

Postgres is available for persistent deployments:

```toml
[postgres]
connection_url = "postgres://pyregistry:pyregistry@127.0.0.1:5432/pyregistry"
max_connections = 20
min_connections = 2
acquire_timeout_seconds = 10
```

Set:

```toml
database_store = "pgsql"
```

Microsoft SQL Server is also available for persistent deployments:

```toml
[sql_server]
connection_url = "sqlserver://sa:Pyregistry123!@127.0.0.1:1433/pyregistry?trust_server_certificate=true"
max_connections = 20
min_connections = 2
acquire_timeout_seconds = 10
```

Set:

```toml
database_store = "sqlserver"
```

Use `in-memory` only for throwaway development runs.

## PyPI Upstream And Mirroring

```toml
[pypi]
base_url = "https://pypi.org"
mirror_download_concurrency = 4
artifact_download_max_attempts = 3
artifact_download_initial_backoff_millis = 250
mirror_update_enabled = true
mirror_update_interval_seconds = 3600
mirror_update_on_startup = true
```

For a company upstream mirror, point `base_url` to that PyPI-compatible service.
Increase `mirror_download_concurrency` for faster caching, or lower it to reduce
pressure on upstream services and object storage.

## Rate Limiting

```toml
[rate_limit]
enabled = true
requests_per_minute = 120
burst = 60
max_tracked_clients = 10000
trust_proxy_headers = false
```

Rate limiting applies to package and OIDC API paths:

```text
/t/...
/_/oidc/...
```

By default limits are keyed by the direct TCP peer IP. Set
`trust_proxy_headers = true` only behind a trusted reverse proxy that controls
`X-Forwarded-For`, `X-Real-IP`, or `Forwarded`.

## Security And Validation

```toml
[security]
yara_rules_path = "supplied/signature-base/yara"

[security.scanner_ignores]
pysentry_vulnerability_ids = []
yara_rule_ids = []
foxguard_rule_ids = []

[security.vulnerability_webhook]
url = "https://discord.com/api/webhooks/..."
username = "Pyregistry"
timeout_seconds = 10

[validation]
distribution_parallelism = 4
```

If the configured YARA directory is readable, Pyregistry uses it. Otherwise it
falls back to bundled supplied rules embedded at compile time.

Use `security.scanner_ignores` for known false positives. PySentry entries
match vulnerability IDs such as `GHSA-...` or `CVE-...`; YARA entries match rule
identifiers or `namespace:rule`; FoxGuard entries match rule IDs such as
`secret/aws-access-key-id`.

For one-off runs or container entrypoints that should not edit the TOML file,
pass `--yara-rules-path /path/to/yara-rules`. This CLI override wins over both
`security.yara_rules_path` and `YARA_RULES_PATH`.

Set `security.vulnerability_webhook.url` to enable Discord-compatible webhook
notifications from `check-registry` when vulnerable packages are found and from
mirror updates when cached wheel audits report findings. The webhook URL is
redacted from logs; leave `url` unset to disable notifications.

## Logging

```toml
[logging]
filter = "info"
module_path = true
target = false
timestamp = "seconds"
```

Use module paths while debugging. In production, choose logging settings that
match your collector and retention policy.

## OIDC Issuers

```toml
[[oidc_issuers]]
provider = "github"
issuer = "https://issuer.pyregistry.local"
jwks_url = "http://127.0.0.1:8081/jwks.json"
audience = "pyregistry"
```

The generated local template points at `http://127.0.0.1:8081/jwks.json` as a
development placeholder. This repository does not ship a signing-key fixture, so
provide a JWKS file for local experiments or replace the issuer, JWKS, and
audience values before testing trusted publishing.

Company environments should configure real issuer URLs, JWKS URLs, and audience
values. Register trusted publishers in the admin UI so issuer identities map to
specific tenant projects.

## Environment Variables

Common environment variables:

| Variable | Purpose |
| --- | --- |
| `BIND_ADDRESS` | HTTP bind address. |
| `BLOB_ROOT` | Local blob root. |
| `SUPERADMIN_EMAIL` | Bootstrap superadmin login. |
| `SUPERADMIN_PASSWORD` | Bootstrap superadmin password. |
| `COOKIE_SECRET` | Secret used for signed web cookies. |
| `DATABASE_STORE` | Metadata backend. |
| `SQLITE_PATH` or `SQLITE_DATABASE_PATH` | SQLite database path. |
| `DATABASE_URL` or `POSTGRES_URL` | Postgres connection URL. |
| `POSTGRES_MAX_CONNECTIONS` | Maximum Postgres pool connections. |
| `POSTGRES_MIN_CONNECTIONS` | Minimum Postgres pool connections. |
| `POSTGRES_ACQUIRE_TIMEOUT_SECONDS` | Postgres connection acquire timeout. |
| `SQL_SERVER_URL` or `MSSQL_URL` | SQL Server connection URL. |
| `SQL_SERVER_MAX_CONNECTIONS` | Maximum SQL Server pool connections. |
| `SQL_SERVER_MIN_CONNECTIONS` | Minimum SQL Server pool connections. |
| `SQL_SERVER_ACQUIRE_TIMEOUT_SECONDS` | SQL Server connection acquire timeout. |
| `ARTIFACT_STORAGE_BACKEND` | Artifact backend: `opendal` or `filesystem`. |
| `OPENDAL_SCHEME` | OpenDAL scheme such as `fs` or `s3`. |
| `OPENDAL_OPTIONS` | Comma-separated OpenDAL `key=value` options. |
| `OPENDAL_ROOT` | OpenDAL root option. |
| `OPENDAL_BUCKET` | OpenDAL bucket option for S3-compatible storage. |
| `OPENDAL_ENDPOINT` | OpenDAL endpoint option for S3-compatible storage. |
| `OPENDAL_REGION` | OpenDAL region option. |
| `OPENDAL_ACCESS_KEY_ID` | OpenDAL access key ID option. |
| `OPENDAL_SECRET_ACCESS_KEY` | OpenDAL secret access key option. |
| `OPENDAL_SESSION_TOKEN` | OpenDAL session token option. |
| `OPENDAL_DISABLE_CONFIG_LOAD` | OpenDAL option to skip ambient config loading. |
| `OPENDAL_DISABLE_EC2_METADATA` | OpenDAL option to skip EC2 metadata lookup. |
| `OPENDAL_ENABLE_VIRTUAL_HOST_STYLE` | OpenDAL S3 virtual-host-style option. |
| `OPENDAL_ALLOW_ANONYMOUS` | OpenDAL anonymous access option. |
| `PYPI_BASE_URL` or `PYPI_URL` | Upstream PyPI-compatible base URL. |
| `PYPI_MIRROR_DOWNLOAD_CONCURRENCY` | Parallel artifact downloads during mirroring. |
| `PYPI_ARTIFACT_DOWNLOAD_MAX_ATTEMPTS` | Mirror artifact download retry attempts. |
| `PYPI_ARTIFACT_DOWNLOAD_INITIAL_BACKOFF_MILLIS` | Initial mirror retry backoff. |
| `PYPI_MIRROR_UPDATE_ENABLED` | Enable or disable the background mirror updater. |
| `PYPI_MIRROR_UPDATE_INTERVAL_SECONDS` | Background mirror refresh interval. |
| `PYPI_MIRROR_UPDATE_ON_STARTUP` | Refresh mirrored projects when the service starts. |
| `YARA_RULES_PATH` | External YARA rules directory when no TOML config overrides it. |
| `PYSENTRY_IGNORE_VULNERABILITY_IDS` | Comma-separated PySentry vulnerability IDs to suppress. |
| `YARA_IGNORE_RULE_IDS` | Comma-separated YARA rule identifiers, or `namespace:rule`, to suppress. |
| `FOXGUARD_IGNORE_RULE_IDS` | Comma-separated FoxGuard rule IDs to suppress. |
| `VULNERABILITY_WEBHOOK_URL` | Discord-compatible webhook URL for vulnerable package notifications. |
| `VULNERABILITY_WEBHOOK_USERNAME` | Optional webhook display name. |
| `VULNERABILITY_WEBHOOK_TIMEOUT_SECONDS` | Webhook POST timeout. |
| `RATE_LIMIT_ENABLED` | Enable or disable API rate limiting. |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | Sustained per-client request rate. |
| `RATE_LIMIT_BURST` | Per-client burst capacity. |
| `RATE_LIMIT_MAX_TRACKED_CLIENTS` | Maximum number of rate-limit client buckets. |
| `RATE_LIMIT_TRUST_PROXY_HEADERS` | Use trusted proxy headers for client IPs. |
| `VALIDATION_DISTRIBUTION_PARALLELISM` | Default artifact validation workers. |
| `LOG_FILTER` | Log filter string. |
| `LOG_MODULE_PATH` | Include module paths in logs. |
| `LOG_TARGET` | Include log targets. |
| `LOG_TIMESTAMP` | Log timestamp style: `off`, `seconds`, `millis`, `micros`, or `nanos`. |
| `OIDC_ISSUERS` | Comma-separated issuer entries in `provider|issuer|jwks_url|audience` form. |
