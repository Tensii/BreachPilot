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

# list available exploit modules
./breachpilot list-modules
```

## Build
```bash
make build
make vet
make test
```

## Local config
Tracked secrets and machine-specific config should not live in git.

Use the example file as the template for your local config:
- `breachpilot.env.example`

Keep your real runtime values in:
- `breachpilot.env`

If any webhook or API token was previously committed, rotate it before the next upgrade or release.

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

A ready config template is included:
- `breachpilot.env.example`

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
- `BREACHPILOT_MIN_SEVERITY` (optional findings floor; example: `HIGH` keeps only HIGH/CRITICAL)
- `BREACHPILOT_SKIP_MODULES` (optional comma-separated module skip list; example: `security-headers,cookie-security`)
- `BREACHPILOT_ONLY_MODULES` (optional comma-separated allow-list; example: `cors-poc,js-endpoints`; overrides skip-list when set)
- `BREACHPILOT_VALIDATION_ONLY` (optional bool; when true, only safe read-only modules run)
- `BREACHPILOT_CONFIG` (optional path to env file)
- `BREACHPILOT_PREVIOUS_REPORT` (optional path to previous `exploit_report.json` for diff/delta comparison)
- `BREACHPILOT_REPORT_FORMATS` (comma-separated output formats: `json`, `md`, `html`, `sarif`; default: `json,md,html`)
- `BREACHPILOT_SCAN_PROFILE` (optional preset: `quick`, `standard`, `deep`)
- `BREACHPILOT_RATE_LIMIT_RPS` (max requests/sec across all modules; `0` = unlimited)
- `BREACHPILOT_AGGRESSIVE` (optional bool; enables active verification probes ON and disables SafeMode OFF)

### Active Probing
Pass `aggressive` as a CLI argument to enable active verification probes (default is read-only). CLI arguments override `.env` settings.

```bash
./breachpilot full example.com aggressive
```
- `BREACHPILOT_AUTH_USER_COOKIE` (optional real low-privilege session cookie)
- `BREACHPILOT_AUTH_ADMIN_COOKIE` (optional real admin session cookie)
- `BREACHPILOT_AUTH_ANON_HEADERS` (optional semicolon/newline separated headers for anonymous context)
- `BREACHPILOT_AUTH_USER_HEADERS` (optional semicolon/newline separated headers for user context)
- `BREACHPILOT_AUTH_ADMIN_HEADERS` (optional semicolon/newline separated headers for admin context)

## Notes
- CLI streams stage/log progress.
- Full mode supports resume if recon summary already exists in the same job artifact path.
- Each run writes `job_report.json` in the evidence directory.

## Proof Mode
Use `BREACHPILOT_PROOF_MODE=true` on owned or explicitly approved targets.

**`BREACHPILOT_PROOF_TARGET_ALLOWLIST` is optional.** When left empty, all targets are permitted (the tool trusts the operator to scan their own infrastructure). To restrict to specific domains, set a comma-separated list:

```bash
# Restrict to specific domains
BREACHPILOT_PROOF_TARGET_ALLOWLIST=company.com,*.staging.company.com

# Or leave empty to allow all targets (recommended for internal teams)
BREACHPILOT_PROOF_TARGET_ALLOWLIST=
```

Proof artifacts are written to `artifacts/<job>/proofs/`.

## New Modules (Phase 8)

### `tls-audit`
Validates TLS certificate and handshake security. Detects:
- Expired certificates
- Certificates expiring within 30 days
- Self-signed certificates
- Weak TLS versions (< TLS 1.2)
- Certificate hostname mismatches

### `dns-check`
Validates DNS and email security configuration. Detects:
- Missing SPF records
- Overly permissive SPF (`+all`)
- Missing DMARC records
- DMARC policy set to `none`
- Potentially dangling nameservers

## Diff/Delta Comparison
Set `BREACHPILOT_PREVIOUS_REPORT` to a previous `exploit_report.json` path. The report will include a **Changes Since Last Run** section showing new, resolved, and unchanged finding counts.

## Tag Index
Reports now include a **Tag Index** section with a table of all tags and their counts, sorted by frequency. Available in JSON (`by_tag` field), Markdown, and HTML reports.

## Configurable Report Formats
Set `BREACHPILOT_REPORT_FORMATS` to select which report formats to generate. Default is `json,md,html`. Example: `json,md` to skip HTML generation. Use `sarif` for GitHub Code Scanning integration.

## New Modules (Phase 9)

### `csp-audit`
Validates Content Security Policy headers. Detects:
- Missing CSP header
- `unsafe-inline` in CSP
- `unsafe-eval` in CSP
- Wildcard source directives (`*`)
- Missing `default-src` fallback

### `http-response`
Detects HTTP response anomalies and information leaks:
- Server header version disclosure
- X-Powered-By technology exposure
- Verbose error pages with stack traces
- Directory listing enabled

## Scan Profiles
Set `BREACHPILOT_SCAN_PROFILE` for preset configurations:
- `quick` — Fast surface scan (4 modules, 8 parallel workers)
- `standard` — Balanced scan (all modules, 4 parallel)
- `deep` — Thorough scan (all modules, 2 parallel for less pressure)

Explicit `BREACHPILOT_ONLY_MODULES` / `BREACHPILOT_SKIP_MODULES` override profile settings.

## Rate Limiting
Set `BREACHPILOT_RATE_LIMIT_RPS` to throttle requests per second across all modules. `0` = unlimited.

Findings are automatically enriched with CWE identifiers (e.g. CWE-942 for CORS, CWE-295 for TLS). Displayed in report tables and JSON.

## SARIF Export
Add `sarif` to `BREACHPILOT_REPORT_FORMATS` to generate `exploit_report.sarif` for GitHub Code Scanning and other SARIF-compatible tools.

## Circuit Breaker
Module circuit breaker auto-skips remaining modules after consecutive failures. Controlled via engine configuration.

## Job Resumption (Phase 10)
Interrupting a job with **Ctrl+C** triggers a graceful shutdown that records the current state to a `.breachpilot_state.json` file in the artifact directory. 

You can resume an interrupted scanning job by simply passing the job ID:
```bash
breachpilot resume <job_id>
```
The tool will bypass previously completed steps (e.g., Recon, Nuclei) and skip any individual custom exploit modules that already ran successfully, generating a seamlessly merged continuous report!
