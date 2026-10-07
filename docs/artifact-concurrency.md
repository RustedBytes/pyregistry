# Bounded artifact CPU concurrency

Measured 2026-10-07 against master `757227e083660b84ecdda80099b123a519d7ff3b`.

Upload inspection and mirrored-wheel extraction/audit now await a shared,
process-wide admission guard, then execute on a dedicated one-thread Rayon pool.
The owned upload buffer is returned to the caller, preserving storage ownership
and the inspected digest. Mirror auditing consumes the already-owned buffer;
there is no added payload clone. Admission is held by the worker until its work
and result delivery finish, even when the awaiting request is cancelled. Panics
are converted to application errors; ordinary inspection errors still propagate,
and mirrored audit failures retain the existing log-and-continue policy.

The application uses the same Rayon scheduling pattern as its existing CPU
validation paths. `async-lock` supplies runtime-independent admission with
starvation protection; no Tokio runtime dependency is added to the application.
Domain, storage ports and streaming APIs are unchanged. Admission semantics:
<https://docs.rs/async-lock/3.4.2/async_lock/struct.Mutex.html>.

## Method

Linux x86-64, AMD EPYC 9V74, 9 visible CPUs, cgroup CPU quota 8 cores, memory
limit 8 GiB, Rust 1.99.0. Optimized `profiling` profile **without** the `profiling`
feature/allocator instrumentation. Each cell is the median of three fresh
processes, with inline/offload order reversed on alternating repeats. No builds
or tests ran concurrently with the final measurements. Host scheduling and CPU
frequency are uncontrolled; small throughput differences are not significant.

The deterministic wheel has a roughly 16 MiB binary entry and harmless network
markers. We tested identical contents in deflated and stored ZIP forms. A ready
burst contains one owned payload per concurrency slot, allocated before the
heartbeat is armed; RSS still includes input allocation and the transient source fixture buffer. This intentionally
isolates inspection/audit scheduling from input copying and network I/O. Mixed
bursts alternate upload and audit; a single-job mixed burst is omitted because
it cannot exercise both stages.

A separate task sleeps toward a 1 ms heartbeat deadline. Reported delay is
actual wake time minus deadline; after each wake the next deadline is reset.
The table gives the median **worst** heartbeat delay of each process, rather
than pretending that sparse inline heartbeat samples estimate a production p99.
The JSON also includes empirical job/heartbeat p99 and sample counts; with at
most 32 requests, job p99 equals the burst maximum. Throughput covers submission
through completion of the ready burst, including initial CPU worker startup;
input creation and final heartbeat shutdown are excluded. Peak RSS is process
`wait4().ru_maxrss`, not allocated-byte totals. The driver uses Linux KiB units.

Inline upload calls the real FilesystemDistributionInspector. Inline audit uses
the real WheelAuditUseCase and ZipWheelArchiveReader through a memory-backed
reader; offload uses the production async methods and the same algorithms. The
fixture is already in memory in both paths. YARA, FoxGuard, AST and Magika are
excluded, matching the previous isolated byte-heuristic workload. Database,
network, storage writes, mirrored digest validation and HTTP handling are not
measured. These are CPU-stage burst rates, not HTTP production throughput.

## Results

All values below are inline → bounded offload. Latency is in ms, rates in jobs/s,
and RSS in MiB. Full measurements for concurrency 1, 8 and 32 are in the JSON
files next to this document.

### Deflated wheel, one async worker

Input ZIP size: 25,746 bytes. Concurrency 32.

| CPU stage | Worst heartbeat | Throughput | Peak RSS | Request p99 |
| --- | ---: | ---: | ---: | ---: |
| upload | 73.76 → 1.68 | 428.03 → 414.55 | 11.88 → 11.88 | 74.73 → 77.17 |
| audit | 490.55 → 1.88 | 65.10 → 65.51 | 20.09 → 20.12 | 491.51 → 488.43 |
| mixed | 280.56 → 1.73 | 113.65 → 111.78 | 20.11 → 20.05 | 281.52 → 286.25 |

### Stored wheel, one async worker

Input ZIP size: 16,777,675 bytes. Concurrency 32.

| CPU stage | Worst heartbeat | Throughput | Peak RSS | Request p99 |
| --- | ---: | ---: | ---: | ---: |
| upload | 430.18 → 2.54 | 74.22 → 73.28 | 530.15 → 530.15 | 430.40 → 436.68 |
| audit | 533.03 → 1.83 | 59.92 → 56.83 | 531.41 → 531.36 | 533.98 → 563.08 |
| mixed | 479.75 → 2.02 | 66.56 → 66.76 | 530.16 → 530.17 | 480.69 → 479.28 |

### Deflated wheel, two async workers

Input ZIP size: 25,746 bytes. Concurrency 32.

| CPU stage | Worst heartbeat | Throughput | Peak RSS | Request p99 |
| --- | ---: | ---: | ---: | ---: |
| upload | 35.71 → 1.67 | 835.58 → 408.36 | 11.88 → 11.88 | 38.23 → 78.31 |
| audit | 288.79 → 1.85 | 106.39 → 65.79 | 36.24 → 20.02 | 300.69 → 486.32 |
| mixed | 143.07 → 1.91 | 215.27 → 113.32 | 36.18 → 20.13 | 148.59 → 282.32 |

## Decision and limits

Keep **one CPU worker** as the smallest conservative patch. On a single async
worker the CPU stage rate stays broadly similar, while long event-loop stalls
fall to approximately 1–3 ms. On two async workers the limit deliberately trades
parallel CPU throughput for responsiveness and fewer simultaneous snapshots:
deflated audit at concurrency 32 changes from 106.39 to 65.79 jobs/s, worst
heartbeat from 288.79 to 1.85 ms, and RSS from 36.24 to 20.02 MiB. Request queue
latency can increase; this patch does not promise faster individual requests.

This is not a tuned production CPU count. If the measured two-worker throughput
tradeoff is unacceptable for a deployment, a configurable larger CPU budget is a
separate, measurable follow-up that needs its memory budget. We do not silently
scale the pool with CPU count or reuse the unbounded global Rayon queue.

The gate limits **active CPU jobs/expanded snapshots**, not all waiting request
buffers. Stored ZIP bursts grow from about 34–35 MiB RSS at concurrency 1 to
about 530–531 MiB at concurrency 32 in both modes. This is the existing owned
input footprint, not an offload-induced memory regression. The archive reader
still permits up to 512 MiB total declared uncompressed contents. Already-read
uploads, queued mirror payloads and independent registry validation operations
remain outside this gate. CPU admission does not establish safe HTTP concurrency
or a process-wide memory ceiling. A cancelled active CPU job finishes; a queued
cancelled future drops its pending job. Existing HTTP body limits still apply.

These results do not require streaming/full-payload API changes for this patch.
An input-byte admission budget or broader buffering change should be justified
by deployment-level measurements, not inferred from this synthetic fixture.
The separate explicit stored-wheel audit use case and other synchronous CPU
stages are outside this patch's scope.

## Reproduce and regression check

```sh
cargo build -p pyregistry-infrastructure --example artifact_concurrency \
  --profile profiling --no-default-features --locked
python scripts/profile-wheel-fixture.py /tmp/demo-deflated.whl
python scripts/benchmark-artifact-concurrency.py /tmp/demo-deflated.whl \
  --output /tmp/artifact-deflated.json --check
python scripts/benchmark-artifact-concurrency.py /tmp/demo-deflated.whl \
  --workers 2 --concurrency 8,32 \
  --output /tmp/artifact-deflated-workers2.json --check
```

Create the stored version without changing its contents:

```sh
python - <<'PYTHON'
import zipfile
with zipfile.ZipFile('/tmp/demo-deflated.whl') as src, zipfile.ZipFile(
    '/tmp/demo-stored.whl', 'w', compression=zipfile.ZIP_STORED
) as dst:
    for info in src.infolist():
        dst.writestr(info.filename, src.read(info))
PYTHON
python scripts/benchmark-artifact-concurrency.py /tmp/demo-stored.whl \
  --output /tmp/artifact-stored.json --check
```

`--check` is opt-in for a controlled machine. When median inline worst delay is
at least 20 ms, offload must stay below `max(10 ms, inline/4)`. Small baseline
stalls are reported without a ratio assertion because timer noise dominates.
All three final matrices passed. Absolute timings are not enabled as a flaky
per-commit CI gate. The driver writes raw results before reporting a regression.
By default JOBS equals concurrency; a positive `--jobs` preallocates that many
owned inputs and changes the memory interpretation accordingly.

## Validation

* 62 application tests pass with default features, including existing mirror
  findings/notifier behavior and upload buffer ownership, size and digest.
* New single-thread async test checks timer progress, active-request cancellation,
  shared admission, worker panic recovery, and error propagation.
* Infrastructure library/examples check passes with no default features; the
  optimized benchmark builds and all final regression matrices pass.
* Formatting, whitespace checks and Python syntax compilation pass.
* Strict Clippy is affected by existing `async_trait`-generated
  `double_must_use` warnings and `unnecessary_sort_by` in models/ports.rs on Rust
  1.99. It passes with these two existing lints allowed; no unrelated lint
  cleanup is included.
* Existing no-default-feature **test** builds fail on ungated AST helper tests
  in application and ungated storage helper tests in infrastructure. Their
  source is unchanged; no-default-feature production libraries/examples compile.
  Full scanner/backend/platform coverage was not claimed or run for this patch.
