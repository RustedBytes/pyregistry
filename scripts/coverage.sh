#!/usr/bin/env bash
set -euo pipefail

minimum_lines="${COVERAGE_MIN_LINES:-80}"
ignore_filename_regex="${COVERAGE_IGNORE_FILENAME_REGEX:-(^|/)(bootstrap|web)/src/|(^|/)application/src/audit_ops\\.rs|(^|/)infrastructure/src/(crypto|mirror|oidc|postgres_store|settings|sqlite_store|store|wiring)\\.rs}"

cargo llvm-cov clean --workspace

cargo llvm-cov nextest \
  --workspace \
  --summary-only \
  --ignore-filename-regex "${ignore_filename_regex}" \
  --fail-under-lines "${minimum_lines}" \
  "$@"
