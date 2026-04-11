# Architecture

Pyregistry is a Rust workspace organized around Clean Architecture. The domain
model is the center. Application use cases depend on the domain. Web and
infrastructure adapters depend on the application and domain.

## Dependency Rule

Dependencies point inward:

```text
bootstrap -> web -> application -> domain
bootstrap -> infrastructure -> application -> domain
```

The domain crate must not depend on:

- Axum or other web frameworks.
- Askama or templates.
- SQL drivers or database models.
- OpenDAL or object storage details.
- TOML or environment configuration.
- Tokio runtime details.
- Serde for transport convenience unless there is a strong domain reason.

## Workspace Layers

| Crate | Layer | Examples |
| --- | --- | --- |
| `crates/domain` | Domain | `Tenant`, `Project`, `Release`, `Artifact`, `ProjectName`, `ReleaseVersion`, `DomainError`. |
| `crates/application` | Application | `PyregistryApp`, commands, DTOs, ports, upload, mirror, token, audit, scan, and validation use cases. |
| `crates/web` | Interface adapters | Routes, request models, response models, session auth, rate limit middleware, Askama templates. |
| `crates/infrastructure` | Infrastructure | SQLite, Postgres, object storage, PyPI mirror client, OIDC verifier, hashing, scanners, settings, wiring. |
| `crates/bootstrap` | Bootstrap | CLI parsing, command dispatch, HTTP listener, logging setup, background mirror updater. |

## Domain Layer

The domain layer models business meaning and invariants. It uses strong types to
make invalid states harder to represent.

Examples:

| Type or function | Invariant |
| --- | --- |
| `TenantSlug::new` | Slugs are lowercase letters, numbers, and dashes. |
| `ProjectName::new` | Names are non-empty and have a normalized lookup form. |
| `ReleaseVersion::new` | Versions are non-empty and use packaging-safe characters. |
| `ArtifactKind::from_filename` | Artifacts must be wheels or supported source distributions. |
| `DigestSet::new` | SHA-256 and BLAKE2b digests are lowercase 64-character hex values. |
| `ensure_purge_allowed` | Mirrored projects cannot be purged. |
| `TrustedPublisher::matches` | Provider, issuer, audience, and claim rules must match. |

Domain errors represent violated business rules. They should stay independent
from transport, persistence, and framework concerns.

## Application Layer

The application layer owns use cases and ports. `PyregistryApp` orchestrates
domain behavior and delegates I/O through traits.

Important use case areas:

- Tenant and admin operations.
- API token issuance, authentication, and revocation.
- Artifact upload.
- Simple index and artifact download preparation.
- Mirroring and mirror cache refresh.
- Trusted publisher registration and OIDC token minting.
- Yank, unyank, purge, and audit trail workflows.
- Distribution validation.
- Vulnerability and wheel security scanning.

Application commands are plain Rust models such as:

- `CreateTenantCommand`
- `IssueApiTokenCommand`
- `UploadArtifactCommand`
- `RegisterTrustedPublisherCommand`
- `MintOidcPublishTokenCommand`
- `DeletionCommand`
- `ValidateDistributionCommand`
- `ValidateRegistryDistributionsCommand`
- `AuditWheelCommand`

## Ports

Ports are traits in the application layer. Infrastructure implements them.

| Port | Responsibility |
| --- | --- |
| `RegistryStore` | Metadata persistence for tenants, users, tokens, projects, releases, artifacts, attestations, publishers, and audit events. |
| `ObjectStorage` | Artifact and provenance bytes. |
| `MirrorClient` | PyPI-compatible upstream metadata and artifact bytes. |
| `OidcVerifier` | OIDC token validation. |
| `AttestationSigner` | Provenance payload generation. |
| `PasswordHasher` | Admin password hashing and verification. |
| `TokenHasher` | API token hashing. |
| `VulnerabilityScanner` | Known vulnerability reports. |
| `WheelArchiveReader` | Wheel archive reading. |
| `WheelVirusScanner` | YARA virus scanning. |
| `WheelSourceSecurityScanner` | Source-level wheel checks. |
| `DistributionFileInspector` | Local and stored distribution validation. |
| `Clock` | Current time. |
| `IdGenerator` | UUID generation. |
| `CancellationSignal` | Cooperative cancellation for longer workflows. |

This keeps use cases testable with fake ports.

## Web Adapter

`crates/web` maps HTTP to application use cases.

It owns:

- Axum routes.
- Request extraction.
- Form and JSON request models.
- Response mapping.
- Admin sessions.
- Rate limit middleware.
- Askama templates.

Handlers should stay thin. If a handler starts deciding package policy, move
that logic into the application or domain layer.

## Infrastructure Adapter

`crates/infrastructure` implements ports and external wiring.

It owns:

- Settings loading from TOML and environment.
- SQLite and Postgres stores.
- In-memory store for throwaway runs.
- OpenDAL filesystem and S3 object storage.
- PyPI mirror HTTP client.
- OIDC JWKS verification.
- Password and token hashing.
- PySentry vulnerability scanning.
- RustPython and YARA-based wheel checks.
- Supplied asset embedding.

Infrastructure errors should be mapped before they cross inward. Do not leak raw
database or HTTP client types into domain or application APIs.

## Bootstrap Layer

`crates/bootstrap` is the outermost binary layer. It owns process concerns:

- CLI parsing with Clap.
- Logging setup.
- Config path selection.
- Application construction through infrastructure wiring.
- HTTP listener startup.
- Background mirror updater lifecycle.
- CLI command dispatch.

`anyhow` belongs here because this layer is glue code at the process boundary.

## Adding A Feature

Use this sequence:

1. Name the business action.
2. Add or adjust domain value objects and invariants.
3. Add an application command or query model.
4. Implement one focused use case method.
5. Add or adjust ports only when the use case needs an external boundary.
6. Implement infrastructure adapters for those ports.
7. Add web or CLI entry points that translate inputs into use case commands.
8. Test domain behavior first, use cases with fakes second, adapters with
   integration tests third.

Reject designs that push framework, database, object storage, or config details
inward.
