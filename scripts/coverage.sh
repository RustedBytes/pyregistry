#!/usr/bin/env bash
set -euo pipefail

minimum_lines="${COVERAGE_MIN_LINES:-95}"
minimum_file_lines="${COVERAGE_MIN_FILE_LINES:-95}"
ignore_filename_regex="${COVERAGE_IGNORE_FILENAME_REGEX:-}"
report_path="${COVERAGE_JSON_OUTPUT:-target/llvm-cov/summary.json}"

cargo llvm-cov clean --workspace

coverage_args=(
  nextest
  --workspace
  --summary-only
  --json
  --output-path "${report_path}"
)

if [[ -n "${ignore_filename_regex}" ]]; then
  coverage_args+=(--ignore-filename-regex "${ignore_filename_regex}")
fi

cargo llvm-cov "${coverage_args[@]}" "$@"

python3 - "${report_path}" "${minimum_lines}" "${minimum_file_lines}" <<'PY'
import json
import pathlib
import sys

report_path = pathlib.Path(sys.argv[1])
minimum_lines = float(sys.argv[2])
minimum_file_lines = float(sys.argv[3])

report = json.loads(report_path.read_text())
summary = report["data"][0]
total_lines = summary["totals"]["lines"]["percent"]
failures = []

for file_report in summary["files"]:
    lines = file_report["summary"]["lines"]
    line_count = lines["count"]
    line_percent = lines["percent"]
    if line_count == 0:
        continue
    if line_percent + 1e-9 < minimum_file_lines:
        failures.append((line_percent, lines["covered"], line_count, file_report["filename"]))

if total_lines + 1e-9 < minimum_lines:
    print(
        f"coverage total line coverage {total_lines:.2f}% is below required {minimum_lines:.2f}%",
        file=sys.stderr,
    )

if failures:
    print(
        f"coverage per-file line coverage below required {minimum_file_lines:.2f}%:",
        file=sys.stderr,
    )
    for percent, covered, count, filename in sorted(failures):
        print(f"  {percent:6.2f}%  {covered:>5}/{count:<5} {filename}", file=sys.stderr)

if total_lines + 1e-9 < minimum_lines or failures:
    sys.exit(1)

print(
    f"coverage passed: total line coverage {total_lines:.2f}% and every file >= {minimum_file_lines:.2f}%"
)
PY
