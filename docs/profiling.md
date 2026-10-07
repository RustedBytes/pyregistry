# Optional CPU and memory investigation

`profiling` enables hotpath 0.28.5 timing, allocation tracking, and thread metrics.
It is not a default feature. The dependency is optional and every instrumentation
attribute is gated, so non-profiling builds do not link hotpath or replace their
allocator. Domain code is not instrumented.

```sh
cargo run -p pyregistry --profile profiling --features profiling -- \
  audit-wheel --project demo --wheel /path/to/demo.whl
```

Instrumented paths cover ZIP extraction, distribution validation and hashing,
upload, mirror caching/download, wheel audit heuristics, FoxGuard, YARA compilation
and scanning. Optional security scanners still require their usual features.
`profiling` does not enable them implicitly.

The hotpath entry-point guard writes its report when the command returns or the
server shuts down gracefully. Set `HOTPATH_OUTPUT_FORMAT=json` and
`HOTPATH_OUTPUT_PATH=/tmp/profile.json` to keep the report separate from CLI output.
Set `HOTPATH_METRICS_SERVER_OFF=true` to disable the local metrics HTTP server.
Allocation values are allocated-byte totals, **not peak RSS**. Function timings
are elapsed time, **not per-function sampled CPU time**. Profiling changes timings
and allocator behaviour; use the same configuration when comparing revisions.

## Reproducible isolated wheel workload

```sh
python scripts/profile-wheel-fixture.py /tmp/demo.whl
HOTPATH_METRICS_SERVER_OFF=true \
HOTPATH_OUTPUT_FORMAT=json \
HOTPATH_OUTPUT_PATH=/tmp/profile.json \
cargo run -p pyregistry-infrastructure --example profile_wheel \
  --profile profiling --no-default-features --features profiling -- \
  /tmp/demo.whl 5
```

This example runs real ZIP extraction and the application audit on a deterministic
16 MiB binary entry containing harmless network markers. The above feature set
excludes YARA, FoxGuard and Python AST scanning to isolate the byte heuristics.
Add `virus-yara`, `source-security`, or `pyregistry-application/python-ast-audit`
to investigate those paths. The example does not contact PyPI or use a database.

## Measured changes

Linux x86-64, Rust 1.99.0, optimized `profiling` profile; identical hotpath
instrumentation before and after optimization. Each process audits the same wheel
five times. CPU and process elapsed time below are medians of three runs; CPU is
user + system time from `getrusage(RUSAGE_CHILDREN)`. Per-function allocations are
exclusive hotpath values from one representative run. These results characterize
this synthetic workload, not production throughput or a peak-memory guarantee.

| Metric | Before | After |
| --- | ---: | ---: |
| Process CPU, five audits | 0.264 s | 0.092 s |
| Process elapsed, five audits | 0.264 s | 0.093 s |
| Total allocations, five audits | 560.9 MB | 81.5 MB |
| ZIP extraction allocations per audit | 64.2 MB | 16.2 MB |
| Network heuristic allocations per audit | 32.0 MB | 64.5 KB |
| Post-install heuristic allocations per audit | 16.0 MB | 64.1 KB |

Changes responsible for the savings:

* Byte heuristics lowercase bounded 64 KiB chunks and use reusable SIMD-capable
  memmem finders. Chunk overlap preserves boundary matches; printable-run checks,
  case-insensitivity, deduplication and evidence priority are preserved.
* ZIP extraction reserves the advertised entry size after the existing per-file
  and total-size checks, avoiding repeated growth and copying of entry buffers.
* Upload moves the owned payload into object storage and reuses the SHA-256 digest
  already computed by distribution inspection. This removes one full payload copy
  and a second digest pass. The isolated wheel example does not measure upload.

Differential tests compare the new heuristics with the old implementation on mixed
binary/invalid UTF-8 inputs, short ASCII runs and chunk boundaries. An upload test
checks original buffer ownership at the storage boundary plus stored digest/size.
PR CI tests profiling enabled and disabled and verifies actual JSON report output.

## Remaining investigation limits

Archive snapshots and the storage API still buffer complete payloads. The reader
allows up to 512 MiB of declared uncompressed contents, and concurrent operations
can multiply that footprint. Streaming would require a wider port/API change.
Upload inspection and mirrored-wheel audit also still perform synchronous CPU work
inside async use cases. Moving that work to a bounded CPU pool merits a separate
load/concurrency study; these measurements do not establish a safe production
concurrency setting. Database query performance, PyPI latency, ML classifiers and
large real-world security rule workloads were not represented by this fixture.

Hotpath reference: <https://hotpath.rs/functions> and
<https://hotpath.rs/profiling_modes>.
