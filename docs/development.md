# Development Workflow

This guide explains how to work in the repository without breaking the
architecture. Keep the business core independent, explicit, and easy to test.

## Local Checks

Run before handing off changes:

```bash
cargo fmt
cargo check --workspace
cargo nextest run --workspace
./scripts/coverage.sh
```

Use the CI-oriented Nextest profile when you want retries:

```bash
cargo nextest run --workspace --profile ci
./scripts/coverage.sh --profile ci
```

The coverage gate defaults to 95 percent line coverage over the stable core
surface. To experiment locally:

```bash
COVERAGE_MIN_LINES=90 ./scripts/coverage.sh
```

## Feature Workflow

1. Start in the domain.
2. Add application commands or query models.
3. Implement a focused use case.
4. Add a port only for a real external boundary.
5. Implement infrastructure adapters.
6. Add web or CLI delivery code.
7. Add tests at the lowest useful layer.
8. Update docs when user behavior or company operations change.

## Where Code Belongs

| Change | Put it here |
| --- | --- |
| Package name invariant | `crates/domain` |
| New registry action | `crates/application` |
| New repository method | Trait in `crates/application`, implementation in `crates/infrastructure` |
| New HTTP form | `crates/web` |
| New SQL table or query | `crates/infrastructure` |
| New CLI command | `crates/bootstrap` with application use case call |
| New runtime setting | `crates/infrastructure/src/settings.rs` |
| New template | `crates/web/templates` |

## Testing Strategy

| Layer | Test style |
| --- | --- |
| Domain | Fast unit tests for constructors, invariants, and business rules. |
| Application | Use case tests with fake ports. |
| Infrastructure | Integration tests for stores, object storage adapters, clients, and scanners. |
| Web | Handler and route tests where request or response mapping is risky. |
| Bootstrap | Minimal tests; keep process glue thin. |

Prefer behavior tests over implementation detail tests.

## Adding A Use Case

Use cases should be named by business intent, not by transport action.

Good names:

- `CreateTenant`
- `IssueApiToken`
- `UploadArtifact`
- `RegisterTrustedPublisher`
- `MintOidcPublishToken`
- `ValidateRegistryDistributions`

A use case should:

- Accept a clear command or query model.
- Validate boundary-level input.
- Invoke domain logic.
- Call required ports.
- Return a clear output model or application result.
- Map errors deliberately.

## Adding A Port

Add a trait only when the use case crosses a real boundary:

- Metadata store.
- Object storage.
- Network client.
- Clock.
- ID generator.
- Password or token hashing.
- External scanner.

Avoid traits created only for speculation. If there is no alternate adapter,
test double, or clear external boundary, keep the code concrete.

## Adding A Web Endpoint

Keep handlers thin:

1. Extract path, query, form, multipart, or JSON data.
2. Authenticate the request.
3. Build an application command or query.
4. Call the use case.
5. Map the result to a response or template.

Do not put package policy, tenant rules, persistence decisions, or scanner logic
in handlers.

## Adding Configuration

Configuration belongs in infrastructure. When adding a setting:

1. Add it to `Settings`.
2. Add TOML parsing and environment loading.
3. Add validation.
4. Add a safe logging summary.
5. Wire it into the adapter or bootstrap code.
6. Document it in [Configuration](operations/configuration.md).

Do not pass raw environment variables into domain or application logic.

## Error Boundaries

| Error type | Meaning |
| --- | --- |
| `DomainError` | A business invariant failed. |
| `ApplicationError` | A use case could not complete. |
| `InfrastructureError` | External configuration or adapter setup failed. |
| `anyhow::Error` | Outermost bootstrap glue failed. |

Map raw SQL, HTTP, object storage, and scanner failures into application or
infrastructure errors before they cross layers.
