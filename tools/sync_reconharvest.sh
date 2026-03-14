#!/usr/bin/env bash
set -euo pipefail

SRC_DEFAULT="/home/ubuntu/.openclaw/workspace/reconHarvest-PythonV"
SRC="${RECONHARVEST_SRC:-$SRC_DEFAULT}"
DST="$(cd "$(dirname "$0")/reconharvest" && pwd)"

if [[ ! -f "$SRC/reconHarvest.py" || ! -f "$SRC/installers.py" ]]; then
  echo "[sync] ERROR: source files not found in $SRC" >&2
  exit 1
fi

if [[ "${SYNC_PULL_LATEST:-0}" == "1" ]]; then
  echo "[sync] pulling latest from source repo..."
  if ! git -C "$SRC" pull --ff-only; then
    CURRENT_URL=$(git -C "$SRC" remote get-url origin 2>/dev/null || true)
    BRANCH=$(git -C "$SRC" rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)
    if [[ "$CURRENT_URL" == git@github.com:* ]]; then
      HTTPS_URL="https://github.com/${CURRENT_URL#git@github.com:}"
      echo "[sync] SSH pull failed, retrying read-only HTTPS: $HTTPS_URL ($BRANCH)"
      if ! git -C "$SRC" pull --ff-only "$HTTPS_URL" "$BRANCH"; then
        echo "[sync] WARN: could not pull latest (SSH/HTTPS failed). Continuing with local source state in $SRC." >&2
      fi
    else
      echo "[sync] WARN: could not pull latest. Continuing with local source state in $SRC." >&2
    fi
  fi
fi

echo "[sync] source: $SRC"
echo "[sync] dest:   $DST"

cp "$SRC/reconHarvest.py" "$DST/reconHarvest.py"
cp "$SRC/installers.py" "$DST/installers.py"

python3 -m py_compile "$DST/reconHarvest.py" "$DST/installers.py"

echo "[sync] Python compile check passed"

go test ./...
go build ./...

echo "[sync] Go test/build passed"

git status --short -- tools/reconharvest || true
git diff --stat -- tools/reconharvest || true

echo "[sync] done"
