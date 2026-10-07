"""Run isolated CPU stages in fresh processes and record true process peak RSS.
Build artifact_concurrency first. No instrumented allocator is required.
"""

import argparse
import json
import os
import statistics
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("wheel")
parser.add_argument(
    "--binary", default="target/profiling/examples/artifact_concurrency"
)
parser.add_argument("--concurrency", default="1,8,32")
parser.add_argument("--workers", type=int, default=1)
parser.add_argument(
    "--jobs",
    type=int,
    default=0,
    help="0 uses one request per concurrency slot; positive values preallocate that many payloads",
)
parser.add_argument("--repeats", type=int, default=3)
parser.add_argument("--output", required=True)
parser.add_argument(
    "--check",
    action="store_true",
    help="Require at least 4x lower worst heartbeat delay for offload (controlled machine only)",
)
args = parser.parse_args()
rows = []
regressions = []
for workload in ["upload", "audit", "mixed"]:
    for concurrency in map(int, args.concurrency.split(",")):
        if workload == "mixed" and concurrency == 1 and not args.jobs:
            continue  # A single-job burst cannot represent both CPU stages.
        jobs = args.jobs or concurrency
        for repeat in range(args.repeats):
            for mode in (
                ["inline", "offload"] if repeat % 2 == 0 else ["offload", "inline"]
            ):
                proc = subprocess.Popen(
                    [
                        args.binary,
                        args.wheel,
                        mode,
                        workload,
                        str(concurrency),
                        str(jobs),
                        str(args.workers),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                _, status, usage = os.wait4(proc.pid, 0)
                proc.returncode = os.waitstatus_to_exitcode(status)
                stdout, stderr = proc.communicate()
                if proc.returncode:
                    raise RuntimeError(stderr.decode())
                row = json.loads(stdout)
                row.update(
                    repeat=repeat,
                    peak_rss_mib=usage.ru_maxrss / 1024,
                    process_cpu_s=usage.ru_utime + usage.ru_stime,
                )
                rows.append(row)
        pair = {}
        for mode in ["inline", "offload"]:
            group = [
                r
                for r in rows
                if r["workload"] == workload
                and r["concurrency"] == concurrency
                and r["mode"] == mode
            ]
            pair[mode] = {
                k: statistics.median(r[k] for r in group)
                for k in [
                    "jobs_per_second",
                    "heartbeat_max_ms",
                    "peak_rss_mib",
                    "job_p99_ms",
                ]
            }
        print(workload, concurrency, json.dumps(pair), flush=True)
        if (
            args.check
            and pair["inline"]["heartbeat_max_ms"] >= 20
            and pair["offload"]["heartbeat_max_ms"]
            >= max(10, pair["inline"]["heartbeat_max_ms"] / 4)
        ):
            regressions.append(f"{workload}, concurrency={concurrency}")
Path(args.output).write_text(
    json.dumps(
        {
            "platform": "Linux; ru_maxrss in KiB",
            "wheel_bytes": Path(args.wheel).stat().st_size,
            "rows": rows,
        },
        indent=2,
    )
    + "\n"
)

if regressions:
    raise AssertionError("event-loop regressions: " + "; ".join(regressions))
