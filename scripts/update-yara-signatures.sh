#!/usr/bin/env bash
set -euo pipefail

SOURCE_REPO="${YARA_SIGNATURE_BASE_REPO:-https://github.com/Neo23x0/signature-base.git}"
SOURCE_REF="${YARA_SIGNATURE_BASE_REF:-master}"
TARGET_DIR="${YARA_SIGNATURE_TARGET_DIR:-supplied/signature-base}"

usage() {
  cat <<'EOF'
Update bundled YARA signatures from Neo23x0/signature-base.

Environment variables:
  YARA_SIGNATURE_BASE_REPO   Git repository to fetch from.
                             Default: https://github.com/Neo23x0/signature-base.git
  YARA_SIGNATURE_BASE_REF    Branch, tag, or commit to fetch.
                             Default: master
  YARA_SIGNATURE_TARGET_DIR  Destination directory in this repository.
                             Default: supplied/signature-base

Examples:
  scripts/update-yara-signatures.sh
  YARA_SIGNATURE_BASE_REF=v2.0 scripts/update-yara-signatures.sh
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

repo_root() {
  git rev-parse --show-toplevel 2>/dev/null || pwd
}

copy_file_if_present() {
  local source_file="$1"
  local target_file="$2"

  if [[ -f "$source_file" ]]; then
    mkdir -p "$(dirname "$target_file")"
    cp "$source_file" "$target_file"
  fi
}

require_command git
require_command cp
require_command find

ROOT="$(repo_root)"
TARGET="$ROOT/$TARGET_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CLONE_DIR="$TMP_DIR/signature-base"

echo "Fetching YARA signatures from $SOURCE_REPO ref $SOURCE_REF"
git clone --depth 1 --filter=blob:none --sparse "$SOURCE_REPO" "$CLONE_DIR"
git -C "$CLONE_DIR" sparse-checkout set --no-cone /yara/ /LICENSE /README.md
git -C "$CLONE_DIR" fetch --depth 1 origin "$SOURCE_REF"
git -C "$CLONE_DIR" checkout --detach FETCH_HEAD
git -C "$CLONE_DIR" sparse-checkout reapply

SOURCE_COMMIT="$(git -C "$CLONE_DIR" rev-parse HEAD)"
SOURCE_YARA_DIR="$CLONE_DIR/yara"

if [[ ! -d "$SOURCE_YARA_DIR" ]]; then
  echo "upstream checkout does not contain a yara/ directory" >&2
  exit 1
fi

mkdir -p "$TARGET"
rm -rf "$TARGET/yara"
mkdir -p "$TARGET/yara"

find "$SOURCE_YARA_DIR" -type f \( -name '*.yar' -o -name '*.yara' \) -print0 |
  while IFS= read -r -d '' source_file; do
    relative_path="${source_file#"$SOURCE_YARA_DIR"/}"
    mkdir -p "$TARGET/yara/$(dirname "$relative_path")"
    cp "$source_file" "$TARGET/yara/$relative_path"
  done

copy_file_if_present "$CLONE_DIR/LICENSE" "$TARGET/LICENSE"
copy_file_if_present "$CLONE_DIR/README.md" "$TARGET/README.md"

cat >"$TARGET/SOURCE.txt" <<EOF
Source repository: $SOURCE_REPO
Source ref: $SOURCE_REF
Source commit: $SOURCE_COMMIT
Bundled path: yara/
EOF

RULE_COUNT="$(find "$TARGET/yara" -type f \( -name '*.yar' -o -name '*.yara' \) | wc -l | tr -d ' ')"
echo "Updated $RULE_COUNT YARA rule files in $TARGET_DIR"
echo "Source commit: $SOURCE_COMMIT"
