# Pyregistry Documentation

Pyregistry is an internal Python package registry written in Rust. It is built
for companies that need tenant-scoped publishing, authenticated installs,
private search, PyPI-compatible mirroring, provenance, trusted publishing, and
lightweight package security checks without running a full PyPI clone.

These docs are written for two readers:

- Newcomers who need to understand the project quickly.
- Company teams evaluating whether Pyregistry fits their internal package
  supply chain.

!!! note "Current status"
    Pyregistry is base code for a registry service, not a production release
    yet. Treat the deployment guidance here as a pilot and hardening path.

## Learn Fast

Follow this path when you are new to the repository:

1. Read the [mental model](mental-model.md) to learn the vocabulary.
2. Run the [quickstart](quickstart.md) to start the service locally.
3. Try [Python client usage](usage/python-clients.md) with `pip`, `uv`, and
   `twine`.
4. Skim the [architecture guide](architecture.md) before changing code.
5. Use the [company adoption guide](company-adoption.md) to plan a pilot.

## What Pyregistry Does

| Capability | What it gives a company |
| --- | --- |
| Tenant-scoped registries | Separate package namespaces for teams, business units, or environments. |
| Authenticated installs | API-token access to private packages through standard Python tooling. |
| Package publishing | `twine` uploads through the legacy PyPI-compatible upload endpoint. |
| Mirroring | Read-through cache from PyPI or another PyPI-compatible upstream. |
| Trusted publishing | OIDC token minting for configured CI issuers and registered publishers. |
| Provenance | Attestation storage for trusted publishing and mirrored artifacts. |
| Security checks | Known vulnerability checks, wheel heuristics, RustPython AST checks, and YARA virus signatures. |
| Admin UI | Server-rendered tenant, package, token, mirror, audit, and scan workflows. |

## Run The Docs

Install MkDocs in your preferred Python environment:

```bash
python -m pip install mkdocs
```

Serve the documentation from the repository root:

```bash
mkdocs serve
```

Then open:

```text
http://127.0.0.1:8000/
```

Build the static site:

```bash
mkdocs build --strict
```

## Repository Map

The workspace follows Clean Architecture boundaries:

| Crate | Layer | Responsibility |
| --- | --- | --- |
| `crates/domain` | Domain | Entities, value objects, invariants, and domain errors. |
| `crates/application` | Application | Use cases, commands, DTOs, and ports. |
| `crates/web` | Interface adapters | Axum handlers, Askama templates, auth extraction, and presenters. |
| `crates/infrastructure` | Infrastructure | Config, persistence, object storage, mirror client, OIDC, hashing, scanning, and wiring. |
| `crates/bootstrap` | Bootstrap | CLI parsing, process startup, HTTP server, and command dispatch. |

Dependency direction points inward. Domain code must not depend on web,
database, serialization, runtime, or configuration details.
