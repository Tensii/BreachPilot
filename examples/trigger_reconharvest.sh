#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   BREACHPILOT_TRIGGER_SECRET=... ./examples/trigger_reconharvest.sh \
#     --url http://127.0.0.1:8080/v1/trigger/reconharvest \
#     --payload ./examples/trigger_payload.json

URL="http://127.0.0.1:8080/v1/trigger/reconharvest"
PAYLOAD="./examples/trigger_payload.json"
SECRET="${BREACHPILOT_TRIGGER_SECRET:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)
      URL="$2"; shift 2;;
    --payload)
      PAYLOAD="$2"; shift 2;;
    --secret)
      SECRET="$2"; shift 2;;
    -h|--help)
      cat <<'EOF'
Usage:
  BREACHPILOT_TRIGGER_SECRET=... ./examples/trigger_reconharvest.sh \
    --url http://127.0.0.1:8080/v1/trigger/reconharvest \
    --payload ./examples/trigger_payload.json

Options:
  --url       Trigger endpoint URL
  --payload   JSON payload path
  --secret    Override secret directly (optional)
EOF
      exit 0;;
    *)
      echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

if [[ -z "$SECRET" ]]; then
  echo "ERROR: missing trigger secret. Set BREACHPILOT_TRIGGER_SECRET or pass --secret" >&2
  exit 1
fi
if [[ ! -f "$PAYLOAD" ]]; then
  echo "ERROR: payload not found: $PAYLOAD" >&2
  exit 1
fi

SIG=$(python3 - <<'PY' "$PAYLOAD" "$SECRET"
import hmac, hashlib, sys
p, s = sys.argv[1], sys.argv[2]
raw = open(p, 'rb').read()
print(hmac.new(s.encode(), raw, hashlib.sha256).hexdigest())
PY
)

echo "[*] Sending signed trigger to: $URL"
curl -sS -X POST "$URL" \
  -H "Content-Type: application/json" \
  -H "X-BreachPilot-Signature: sha256=$SIG" \
  --data-binary "@$PAYLOAD"
echo
