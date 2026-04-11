#!/usr/bin/env bash
set -euo pipefail

minimum_lines="${COVERAGE_MIN_LINES:-40}"

cargo llvm-cov clean --workspace

cargo llvm-cov nextest \
  --workspace \
  --summary-only \
  --fail-under-lines "${minimum_lines}" \
  "$@"
