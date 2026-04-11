# Mental Model

Pyregistry is easiest to understand as a small registry core wrapped by several
adapters. The domain model describes package registry concepts. The application
layer turns those concepts into use cases. Web and infrastructure code connect
the use cases to HTTP, storage, mirroring, OIDC, and scanners.

## Core Concepts

| Concept | Meaning |
| --- | --- |
| Tenant | A scoped registry namespace such as a team, company unit, or environment. |
| Admin user | A user that can sign in to the admin UI. A superadmin can manage all tenants. |
| API token | A tenant-scoped secret with `read`, `publish`, or `admin` scope. |
| Project | A Python package name inside one tenant. Project names keep the original spelling and a normalized lookup form. |
| Release | One version of a project. Versions are ordered with PEP 440 parsing when possible. |
| Artifact | A wheel or source distribution file attached to a release. |
| Mirror rule | Tenant setting that allows Pyregistry to resolve missing packages from the configured upstream. |
| Trusted publisher | A registered OIDC identity allowed to mint a short-lived publish token for a project. |
| Attestation | Provenance payload stored beside an artifact. |
| Audit event | Durable record of important admin, token, upload, OIDC, and package actions. |

## Request Flows

### Install A Package

1. A Python client requests `/t/{tenant}/simple/{project}/`.
2. The web adapter authenticates the tenant token for `read` access.
3. The application resolves the tenant and project.
4. If the project is missing and mirroring is enabled, the mirror client fetches
   upstream metadata and artifacts.
5. The application returns a Simple Repository API page with artifact links and
   hashes.
6. The client downloads artifact bytes from object storage through the download
   endpoint.

### Publish A Package

1. `twine` posts to `/t/{tenant}/legacy/`.
2. The web adapter converts multipart form data into an upload command.
3. The application checks the token has `publish` scope.
4. Domain value objects validate tenant slug, project name, version, artifact
   filename, and digests.
5. Artifact bytes are written to object storage.
6. Project, release, artifact, and optional attestation metadata are persisted.

### Mirror A Package

1. A tenant with mirroring enabled asks for a project not stored locally.
2. The application calls the `MirrorClient` port.
3. The infrastructure PyPI mirror client fetches upstream metadata and files.
4. Mirrored projects are stored with `ProjectSource::Mirrored`.
5. Local projects take precedence over mirrored projects with the same normalized
   name.

### Trusted Publishing

1. A CI workflow sends an OIDC token to `/_/oidc/mint-token`.
2. The OIDC verifier validates issuer, JWKS, and audience.
3. The application compares the resulting identity with registered publisher
   claim rules.
4. Pyregistry returns a short-lived publish token when the claims match.
5. Uploads with that token can produce an attestation for the artifact.

## Important Boundaries

Domain code owns invariants. Examples:

- Tenant slugs must be lowercase letters, numbers, and dashes.
- Project names keep original and normalized forms.
- Release versions must use packaging-safe characters.
- Artifact filenames must be wheels or source distributions.
- Mirrored projects cannot be purged.
- Trusted publisher claims must match the registered rules.

Application code owns orchestration. Examples:

- Issuing API tokens.
- Authenticating tenant tokens.
- Uploading artifacts.
- Resolving mirrored packages.
- Yanking, unyanking, and purging releases or artifacts.
- Validating stored distributions.
- Running vulnerability and wheel scans.

Adapters own external details. Examples:

- HTTP routes and Askama templates in `crates/web`.
- SQLite, Postgres, OpenDAL, PyPI HTTP, OIDC JWKS, hashing, and scanners in
  `crates/infrastructure`.
- CLI parsing and process startup in `crates/bootstrap`.

## What To Remember

When adding a feature, ask:

1. What business concept changes in the domain?
2. What use case should orchestrate the behavior?
3. Which ports does the use case need?
4. Which adapters implement those ports?
5. How should errors cross each boundary?

If a design pushes SQL, HTTP, TOML config, Axum extractors, or object storage
details into the domain, move that detail outward.
