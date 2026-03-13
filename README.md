# BreachPilot

BreachPilot is a CLI-first recon-to-exploit orchestrator.

It ships with a vendored ReconHarvest runner under `tools/reconharvest/` for portable full-mode runs.

## Commands
```bash
# preflight checks
./breachpilot setup

# full flow: run reconHarvest then exploit stage
./breachpilot full example.com

# use existing reconHarvest summary
./breachpilot file /absolute/path/to/summary.json

# machine-readable output
./breachpilot full example.com --json
```

## Build
```bash
make build
make test
```

## Sync vendored ReconHarvest
When `reconHarvest-PythonV` is updated, sync into BreachPilot with one command:

```bash
make sync-reconharvest
```

If you also want to `git pull --ff-only` latest changes in source repo first:

```bash
make sync-reconharvest-latest
```

Optional auto-commit helper:

```bash
make sync-reconharvest-commit
```

Source repo path defaults to:
`/home/ubuntu/.openclaw/workspace/reconHarvest-PythonV`

You can override source path per run:

```bash
RECONHARVEST_SRC=/custom/path/to/reconHarvest-PythonV make sync-reconharvest
```

## Config file (recommended)
BreachPilot automatically loads `./breachpilot.env` (or path from `BREACHPILOT_CONFIG`).

A ready config file is included:
- `breachpilot.env`

### Split webhook channels (no conflict)
Use separate webhook URLs:
- `BREACHPILOT_WEBHOOK_RECON` → ReconHarvest progress (recon phase only)
- `BREACHPILOT_WEBHOOK_EXPLOIT` → BreachPilot exploit progress/events

If either one is empty, BreachPilot falls back to `BREACHPILOT_WEBHOOK`.

This gives the exact behavior you asked for:
1. Full run starts recon → ReconHarvest sends to recon webhook channel
2. Recon finishes, exploit starts → BreachPilot sends to exploit webhook channel

## Environment (editable in `breachpilot.env`)
- `BREACHPILOT_WEBHOOK_RECON`
- `BREACHPILOT_WEBHOOK_EXPLOIT`
- `BREACHPILOT_WEBHOOK` (legacy fallback)
- `BREACHPILOT_WEBHOOK_SECRET`
- `BREACHPILOT_WEBHOOK_RETRIES` (default `3`)
- `BREACHPILOT_NUCLEI_BIN` (default `nuclei`)
- `BREACHPILOT_RECONHARVEST_CMD` (optional override; default auto-resolves vendored ReconHarvest)
- `BREACHPILOT_RECON_TIMEOUT_SEC` (default `7200`)
- `BREACHPILOT_RECON_RETRIES` (default `1`)
- `BREACHPILOT_NUCLEI_TIMEOUT_SEC` (default `1800`)
- `BREACHPILOT_ARTIFACTS` (default `./artifacts`)
- `BREACHPILOT_CONFIG` (optional path to env file)

## Notes
- CLI streams stage/log progress.
- Full mode supports resume if recon summary already exists in the same job artifact path.
- Each run writes `job_report.json` in the evidence directory.
