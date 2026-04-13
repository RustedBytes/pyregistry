# Security And Trust

Pyregistry focuses on practical package supply-chain controls: authenticated
access, tenant boundaries, mirroring, provenance, trusted publishing, audit
events, and lightweight package scanning.

## Access Model

Tenant API tokens are the primary client credential. Tokens can carry these
scopes:

| Scope | Grants |
| --- | --- |
| `read` | Read package indexes and download artifacts. |
| `publish` | Upload package artifacts. |
| `admin` | Tenant administration workflows. |

Use separate tokens for separate jobs. Prefer short-lived or CI-bound publish
credentials.

## Admin Credentials

Generated local configs include development credentials. For company use:

- Change the superadmin email and password.
- Store credentials in the company secret system.
- Limit superadmin use.
- Prefer tenant admins for routine tenant operations.
- Rotate credentials after pilots and demos.

## Cookie Secret

`cookie_secret` signs admin session cookies. Use a long random value and keep it
out of source control. Rotating it invalidates existing sessions.

## Rate Limiting

Rate limiting protects package and OIDC API paths:

```text
/t/...
/_/oidc/...
```

When running behind a reverse proxy, only enable trusted proxy headers if the
proxy strips or controls incoming `X-Forwarded-For`, `X-Real-IP`, and
`Forwarded` values.

## Mirroring Trust

Mirroring can reduce direct public-index access from company clients. A tenant
with mirroring enabled can resolve missing packages from the configured
upstream.

Important behavior:

- Local projects take precedence over mirrored projects with the same normalized
  name.
- Mirrored projects are marked as mirrored in the domain model.
- Domain rules prevent purging mirrored projects.
- Background refresh can update already mirrored projects.

For high-control environments, point Pyregistry at an internal upstream mirror
instead of public PyPI.

## Trusted Publishing

Trusted publishing maps an external OIDC identity to a project-specific publish
grant.

Use it to avoid long-lived publish tokens in CI:

1. Configure OIDC issuers with provider, issuer, JWKS URL, and audience.
2. Register a trusted publisher for a tenant project.
3. Match issuer, audience, provider, and claim rules.
4. Mint a short-lived publish token from CI.
5. Upload with that token.

Keep claim rules narrow. Tie them to repository, workflow, branch, environment,
or equivalent CI identity fields when your issuer provides those claims.

## Vulnerability Checks

Known vulnerability checks use the PySentry adapter. Package pages show security
summaries, and the CLI can scan registry state:

```bash
scripts/pyregistry-release.sh check-registry --tenant acme
```

Configure a Discord-compatible webhook to notify when `check-registry` finds a
vulnerable package, and when mirrored wheel updates produce wheel-audit findings:

```toml
[security.vulnerability_webhook]
url = "https://discord.com/api/webhooks/..."
username = "Pyregistry"
timeout_seconds = 10
```

The posted payload includes `content`, `embeds`, and disabled mentions. For
known vulnerabilities it summarizes the tenant, package, scanned files,
vulnerable files, advisory match count, and highest severity. For wheel audit
findings it summarizes the tenant, package, version, wheel filename, scanned
files, and finding details.

Treat results as a signal, not a full risk decision. Combine them with company
policy, dependency ownership, and release criticality.

## Wheel Content Checks

Wheel audit checks include:

- Unexpected executables or shell scripts.
- Network-related strings inside binaries.
- Post-install behavior clues.
- Suspicious Python imports and runtime calls using RustPython AST analysis.
- Suspicious dependencies in `METADATA`.
- YARA virus signature matches.

Run:

```bash
scripts/pyregistry-release.sh audit-wheel --project example --wheel path/to/file.whl
```

The admin UI exposes wheel scans from package pages. Background mirror updates
also scan newly cached wheels and publish webhook notifications when findings
are present.

## YARA Rules

The repository vendors supplied YARA rules under `supplied/signature-base`.
Those files are licensed separately. Pyregistry embeds the supplied rules into
the binary at compile time.

If `security.yara_rules_path` points to a readable directory, Pyregistry uses
that external rule set. Otherwise it falls back to the bundled supplied rules.

Refresh local supplied signatures with:

```bash
scripts/update-yara-signatures.sh
```

## Audit Events

Audit events provide durable records for important operations. Use them to
support incident review and operational accountability.

Review audit trails for:

- Token issuance and revocation.
- Tenant creation.
- Package uploads.
- Yank, unyank, purge, and mirror actions.
- Trusted publishing token minting.
- Admin activity.

## Company Security Checklist

Before using Pyregistry beyond a pilot:

- Enforce HTTPS.
- Replace generated credentials.
- Replace generated cookie secrets.
- Store tokens and config secrets outside source control.
- Define token rotation and expiration policy.
- Configure trusted OIDC issuers deliberately.
- Keep tenant boundaries aligned with ownership boundaries.
- Decide whether public PyPI access is allowed directly or only through
  mirroring.
- Back up metadata and artifacts.
- Send logs and audit records to approved retention systems.
