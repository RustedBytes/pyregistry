# Changelog

Notable changes to PyRegistry are documented here. Versions follow Semantic
Versioning. Historical entries summarize published release notes and Git history.

## [0.4.0] - Unreleased

### Added

- Optional `profiling` feature with hotpath timing, allocation and thread metrics,
  a dedicated Cargo profile, an isolated wheel workload and a profiling CI workflow
  ([#54](https://github.com/RustedBytes/pyregistry/pull/54)).
- Artifact concurrency benchmarks and documentation covering executor progress,
  throughput and peak RSS
  ([#55](https://github.com/RustedBytes/pyregistry/pull/55)).
- CI compilation and smoke validation of bundled YARA rules using the production
  compiler ([#53](https://github.com/RustedBytes/pyregistry/pull/53)).

### Changed

- Offload upload distribution inspection and mirrored-wheel extraction/audit to
  a shared single-thread Rayon pool, with admission before submission. Admission
  remains held until CPU work finishes even if the requesting future is cancelled
  ([#55](https://github.com/RustedBytes/pyregistry/pull/55)).
- Reduce wheel-audit allocations with bounded lowercase chunks and reusable byte
  searchers; reserve ZIP entry buffers after archive size checks
  ([#54](https://github.com/RustedBytes/pyregistry/pull/54)).
- Move upload payloads into object storage and reuse inspection's SHA-256 digest,
  avoiding an additional payload copy and hashing pass
  ([#54](https://github.com/RustedBytes/pyregistry/pull/54)).
- Update bundled YARA signatures through the September 2026 upstream snapshot.
- Update dependencies and add Ruff for Python formatting.
- Align Rust workspace and Python project metadata on version `0.4.0`.

CPU admission bounds active work, not memory retained by already-buffered waiting
payloads. See [profiling](docs/profiling.md) and
[artifact concurrency](docs/artifact-concurrency.md) for measurements and limits.

## [0.3.2] - 2026-04-16

### Added

- Release publishing from the administration UI.
- Insecure administration login mode for testing.
- Additional fuzzing coverage.

### Changed

- Limit package management to non-mirrored packages.
- Refactor SQLite storage and clean up code, including performance improvements
  and fixes identified by Qualirs and Clippy.

## [0.3.0] - 2026-04-14

### Added

- Logging to a separate file.
- Security regression tests and fuzzing coverage.

### Changed

- Strengthen security checks and improve the administration UI.

### Fixed

- Dashboard storage statistics.

## [0.2.0] - 2026-04-13

First published GitHub release of the private Python package registry.

### Included

- Tenant-scoped package hosting, PyPI mirroring, trusted publishing and security
  scanning.
- PostgreSQL, SQL Server and Turso-backed SQLite storage; configurable build
  features for storage and security integrations.
- Custom YARA rule directories, per-scanner ignore lists, file-type mismatch
  detection, network access checks and API token revocation.
- Administration UI with dark mode, package removal and a percentage-based limit
  on mirrored releases.
- Redacted logs, webhook events and cross-platform test/build tooling.

[0.4.0]: https://github.com/RustedBytes/pyregistry/compare/v0.3.2...master
[0.3.2]: https://github.com/RustedBytes/pyregistry/releases/tag/v0.3.2
[0.3.0]: https://github.com/RustedBytes/pyregistry/releases/tag/v0.3.0
[0.2.0]: https://github.com/RustedBytes/pyregistry/releases/tag/v0.2.0
