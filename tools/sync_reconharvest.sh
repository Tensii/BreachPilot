#!/usr/bin/env bash
set -euo pipefail

SRC_DEFAULT="/home/ubuntu/.openclaw/workspace/reconHarvest-PythonV"
SRC="${RECONHARVEST_SRC:-$SRC_DEFAULT}"
SRC_EFFECTIVE="$SRC"
DST="$(cd "$(dirname "$0")/reconharvest" && pwd)"
TMP_CLONE=""

if [[ ! -f "$SRC/reconHarvest.py" || ! -f "$SRC/installers.py" ]]; then
  echo "[sync] ERROR: source files not found in $SRC" >&2
  exit 1
fi

if [[ "${SYNC_PULL_LATEST:-0}" == "1" ]]; then
  echo "[sync] pulling latest from source repo..."
  PULLED=0
  CURRENT_URL=$(git -C "$SRC" remote get-url origin 2>/dev/null || true)
  BRANCH=$(git -C "$SRC" rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)
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

  if git -C "$SRC" pull --ff-only; then
    PULLED=1
  else
    echo "[sync] WARN: source repo pull via origin failed" >&2
  fi

  # Try authenticated HTTPS via gh token when available.
  if [[ "$PULLED" == "0" ]] && command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1 && [[ -n "$REPO_PATH" ]]; then
    GH_TOKEN=$(gh auth token 2>/dev/null || true)
    if [[ -n "$GH_TOKEN" ]]; then
      AUTH_URL="https://x-access-token:${GH_TOKEN}@github.com/${REPO_PATH}.git"
      echo "[sync] retrying authenticated HTTPS via gh (${REPO_PATH}, ${BRANCH})"
      if git -C "$SRC" pull --ff-only "$AUTH_URL" "$BRANCH"; then
        PULLED=1
      else
        echo "[sync] WARN: gh-authenticated pull failed." >&2
      fi
      GH_TOKEN=""
    fi
  fi

  # Fallback: temporary gh clone (does not depend on source repo auth/remote state)
  if [[ "$PULLED" == "0" ]] && command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1 && [[ -n "$REPO_PATH" ]]; then
    TMP_CLONE="$(mktemp -d /tmp/reconharvest-sync-XXXXXX)"
    echo "[sync] using temporary gh clone fallback: $REPO_PATH#$BRANCH"
    if gh repo clone "$REPO_PATH" "$TMP_CLONE" -- --depth 1 --branch "$BRANCH" >/dev/null 2>&1; then
      SRC_EFFECTIVE="$TMP_CLONE"
      PULLED=1
    else
      rm -rf "$TMP_CLONE"
      TMP_CLONE=""
      echo "[sync] WARN: gh clone fallback failed." >&2
    fi
  fi

  # Final fallback: read-only HTTPS fetch/pull.
  if [[ "$PULLED" == "0" ]]; then
    if [[ "$CURRENT_URL" == git@github.com:* ]]; then
      HTTPS_URL="https://github.com/${CURRENT_URL#git@github.com:}"
    elif [[ "$CURRENT_URL" == https://github.com/* ]]; then
      HTTPS_URL="$CURRENT_URL"
    else
      HTTPS_URL=""
    fi
    if [[ -n "$HTTPS_URL" ]]; then
      echo "[sync] retrying read-only HTTPS: $HTTPS_URL ($BRANCH)"
      if git -C "$SRC" pull --ff-only "$HTTPS_URL" "$BRANCH"; then
        PULLED=1
      else
        echo "[sync] WARN: could not pull latest (SSH/gh/HTTPS failed). Continuing with local source state in $SRC." >&2
      fi
    else
      echo "[sync] WARN: could not pull latest. Continuing with local source state in $SRC." >&2
    fi
  fi
fi

echo "[sync] source: $SRC"
echo "[sync] dest:   $DST"

cp "$SRC_EFFECTIVE/reconHarvest.py" "$DST/reconHarvest.py"
cp "$SRC_EFFECTIVE/installers.py" "$DST/installers.py"

python3 -m py_compile "$DST/reconHarvest.py" "$DST/installers.py"

echo "[sync] Python compile check passed"

go test ./...
go build ./...

echo "[sync] Go test/build passed"

git status --short -- tools/reconharvest || true
git diff --stat -- tools/reconharvest || true

if [[ -n "$TMP_CLONE" && -d "$TMP_CLONE" ]]; then
  rm -rf "$TMP_CLONE"
fi

echo "[sync] done"
