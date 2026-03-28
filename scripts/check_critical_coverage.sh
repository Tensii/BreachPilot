#!/usr/bin/env bash
set -euo pipefail

threshold="${1:-50}"
packages=(
  "./internal/engine"
  "./internal/exploit"
  "./internal/exploit/httppolicy"
  "./internal/notify"
)

for pkg in "${packages[@]}"; do
  echo "[coverage] checking ${pkg} (threshold=${threshold}%)"
  out="$(go test -count=1 -cover "${pkg}")"
  echo "${out}"
  cov="$(printf '%s\n' "${out}" | sed -n 's/.*coverage: \([0-9.]\+\)% of statements.*/\1/p' | tail -n 1)"
  if [[ -z "${cov}" ]]; then
    echo "[coverage] unable to parse coverage for ${pkg}" >&2
    exit 1
  fi
  awk -v c="${cov}" -v t="${threshold}" -v p="${pkg}" 'BEGIN {
    if ((c + 0) < (t + 0)) {
      printf("[coverage] gate failed for %s: %.1f%% < %.1f%%\n", p, c, t);
      exit 1;
    }
  }'
done

echo "[coverage] all critical package coverage gates passed"
