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
  # Ensure remote uses SSH to avoid HTTPS 403 auth errors
  CURRENT_URL=$(git -C "$SRC" remote get-url origin 2>/dev/null || true)
  if [[ "$CURRENT_URL" == https://github.com/* ]]; then
    SSH_URL=$(echo "$CURRENT_URL" | sed 's|https://github.com/|git@github.com:|')
    echo "[sync] switching remote from HTTPS to SSH: $SSH_URL"
    git -C "$SRC" remote set-url origin "$SSH_URL"
  fi
  git -C "$SRC" pull --ff-only
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
