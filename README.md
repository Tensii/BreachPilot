# BreachPilot

BreachPilot is a Go-based automation control plane for recon-to-exploit workflows.

## Current scope (Phase 2 scaffold)
- HTTP API to submit jobs (`/v1/jobs`) in `ingest` or `full` mode
- Job cancellation endpoint (`POST /v1/jobs/{id}/cancel`)
- Signed trigger endpoint (`POST /v1/trigger/reconharvest`)
- Scope validation + safe-mode gating
- Approval gate for intrusive mode (`approve_intrusive=true` + `approval_ticket` required)
- Template risk classification (safe/verify/intrusive)
- Background worker queue
- ReconHarvest output ingestion (`summary.json`)
- Nuclei execution pipeline (safe verification profile by default)
- Evidence capture under `artifacts/<job-id>/`
- Optional webhook events (`job.started`, `job.completed`, `job.failed`, `job.rejected`)

## Run
### Simple CLI (recommended)
```bash
# Full flow: reconHarvest -> exploit stage
go run ./cmd/breachpilot full example.com

# Use existing ReconHarvest summary
go run ./cmd/breachpilot file /absolute/path/to/summary.json
```

### Build binary shortcut
```bash
make build
./breachpilot full example.com
./breachpilot file /absolute/path/to/summary.json

# machine-readable output
./breachpilot full example.com --json
```

### API server mode (optional)
```bash
go mod tidy
go run ./cmd/breachpilot --listen :8080
```

## Environment
- `BREACHPILOT_TOKEN` (optional API auth token via `X-BreachPilot-Token`)
- `BREACHPILOT_WEBHOOK` (optional webhook URL)
- `BREACHPILOT_WEBHOOK_SECRET` (optional HMAC signing secret)
- `BREACHPILOT_WEBHOOK_RETRIES` (default: `3`)
- `BREACHPILOT_TRIGGER_SECRET` (required for `/v1/trigger/reconharvest` signed requests)
- `BREACHPILOT_NUCLEI_BIN` (default: `nuclei`)
- `BREACHPILOT_RECONHARVEST_CMD` (default points to local reconHarvest.py)
- `BREACHPILOT_RECON_TIMEOUT_SEC` (default: `7200`)
- `BREACHPILOT_RECON_RETRIES` (default: `1`)
- `BREACHPILOT_NUCLEI_TIMEOUT_SEC` (default: `1800`)
- `BREACHPILOT_ARTIFACTS` (default: `./artifacts`)
- `BREACHPILOT_DB` (default: `./breachpilot.db`)
- `BREACHPILOT_WORKERS` (default: `2`)
- `BREACHPILOT_QUEUE_SIZE` (default: `100`)

## Submit job examples
### Ingest mode (use existing ReconHarvest output)
```bash
curl -X POST http://127.0.0.1:8080/v1/jobs \
  -H 'Content-Type: application/json' \
  -d '{
    "mode":"ingest",
    "target":"example.com",
    "recon_summary":"/path/to/recon/summary.json",
    "safe_mode":true,
    "approve_intrusive":false,
    "templates":["http/misconfiguration/"]
  }'
```

### Full mode (run reconHarvest first, then exploit pipeline)
```bash
curl -X POST http://127.0.0.1:8080/v1/jobs \
  -H 'Content-Type: application/json' \
  -d '{
    "mode":"full",
    "target":"example.com",
    "safe_mode":true,
    "approve_intrusive":false
  }'
```

## Signed trigger helper
Use the helper script to sign and send `/v1/trigger/reconharvest` requests:

```bash
BREACHPILOT_TRIGGER_SECRET='your-secret' \
./examples/trigger_reconharvest.sh \
  --url http://127.0.0.1:8080/v1/trigger/reconharvest \
  --payload ./examples/trigger_payload.json
```

The script computes `X-BreachPilot-Signature: sha256=...` over the raw payload body.

## Notes
- CLI mode prints stage progress (`recon.started`, `recon.completed`, `exploit.started`, `exploit.completed`) and streams tool log lines.
- CLI supports `--json` for structured output.
- Recon phase supports retry attempts and resume (skips rerun if summary already exists in the same job artifact path).
- API queue rejects duplicate active jobs on the same target.
- Jobs persist in SQLite (`BREACHPILOT_DB`) and can be fetched after restart.
- Each run writes `job_report.json` inside the evidence directory.
- Safe mode is recommended by default.
- Intrusive execution requires explicit opt-in via `approve_intrusive=true`.
- This project assumes authorized testing scope only.
