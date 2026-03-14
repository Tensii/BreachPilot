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

    # Try authenticated HTTPS via gh token when available.
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
      REPO_PATH=""
      case "$CURRENT_URL" in
        git@github.com:*)
          REPO_PATH="${CURRENT_URL#git@github.com:}"
          ;;
        https://github.com/*)
          REPO_PATH="${CURRENT_URL#https://github.com/}"
          ;;
      esac
      REPO_PATH="${REPO_PATH%.git}"
      if [[ -n "$REPO_PATH" ]]; then
        GH_TOKEN=$(gh auth token 2>/dev/null || true)
        if [[ -n "$GH_TOKEN" ]]; then
          AUTH_URL="https://x-access-token:${GH_TOKEN}@github.com/${REPO_PATH}.git"
          echo "[sync] SSH pull failed, retrying authenticated HTTPS via gh (${REPO_PATH}, ${BRANCH})"
          if git -C "$SRC" pull --ff-only "$AUTH_URL" "$BRANCH"; then
            GH_TOKEN=""
          else
            GH_TOKEN=""
            echo "[sync] WARN: gh-authenticated pull failed." >&2
          fi
        fi
      fi
    fi

    # Final fallback: read-only HTTPS fetch/pull.
    if ! git -C "$SRC" pull --ff-only; then
      if [[ "$CURRENT_URL" == git@github.com:* ]]; then
        HTTPS_URL="https://github.com/${CURRENT_URL#git@github.com:}"
      elif [[ "$CURRENT_URL" == https://github.com/* ]]; then
        HTTPS_URL="$CURRENT_URL"
      else
        HTTPS_URL=""
      fi
      if [[ -n "$HTTPS_URL" ]]; then
        echo "[sync] retrying read-only HTTPS: $HTTPS_URL ($BRANCH)"
        if ! git -C "$SRC" pull --ff-only "$HTTPS_URL" "$BRANCH"; then
          echo "[sync] WARN: could not pull latest (SSH/gh/HTTPS failed). Continuing with local source state in $SRC." >&2
        fi
      else
        echo "[sync] WARN: could not pull latest. Continuing with local source state in $SRC." >&2
      fi
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
