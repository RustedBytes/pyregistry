# Admin Workflows

The admin UI is intentionally small and focused on registry operations. It is
server-rendered through Axum and Askama templates, with business decisions kept
in the application layer.

## Sign In

Local generated configuration creates a superadmin:

```text
admin@pyregistry.local
change-me-now
```

Open:

```text
http://127.0.0.1:3000/admin/login
```

Change the generated password before using Pyregistry beyond local development.

## Create A Tenant

A tenant is a package namespace and policy boundary. Use tenants for teams,
business units, environments, or customer scopes where package visibility and
token management should be separate.

When creating a tenant, decide:

| Choice | Guidance |
| --- | --- |
| Slug | Use lowercase letters, numbers, and dashes. This appears in package URLs. |
| Display name | Human-readable tenant name for the admin UI. |
| Mirroring | Enable when the tenant should resolve missing packages from the configured upstream. |
| Tenant admin | Create a tenant admin account when operations should be delegated. |

## Issue Tokens

Use tokens to separate read, publish, and admin actions.

| Token type | Scopes | Typical holder |
| --- | --- | --- |
| Developer install token | `read` | Developer machine or team secret. |
| CI install token | `read` | Build pipeline. |
| CI publish token | `publish` | Release pipeline. |
| Bootstrap token | `read`, `publish`, `admin` | Local development only. |

Set expiration when the token is temporary or tied to a rollout.

## Manage Packages

Package pages show project metadata, releases, artifacts, yanked state, trusted
publishers, vulnerability status, and wheel scan actions.

Use yanking when:

- A release or file should stop being selected by new installs.
- Existing consumers may still need the file by exact version.
- You want a reversible administrative action.

Use purge when:

- A local project, release, or artifact must be removed from object storage and
  metadata.
- The project is not mirrored.

Mirrored projects cannot be purged by domain rule. Evict mirror cache instead
when you want Pyregistry to refetch upstream state.

## Mirror Cache

For tenants with mirroring enabled, missing projects can be resolved from the
configured PyPI-compatible upstream. Local projects win over mirrored projects
with the same normalized name.

Use mirror cache refresh when:

- A tenant depends on a public package and you want local artifact bytes cached.
- You want to update mirrored metadata and files.
- You are testing an internal PyPI-compatible upstream.

## Register Trusted Publishers

Trusted publishers are registered per tenant and project. The registered
provider, issuer, audience, and claim rules must match the OIDC identity used by
CI.

Use this for company release pipelines where long-lived publish tokens should be
avoided.

## Review Audit Trail

Audit events record important registry actions. Review them when investigating:

- Tenant creation.
- Token issuance.
- Package upload, yank, unyank, purge, and mirror actions.
- Trusted publishing token minting.
- Admin operations.

Audit events are application-level records. They should not expose raw database
driver errors or transport internals.
