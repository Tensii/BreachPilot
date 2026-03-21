#!/usr/bin/env python3
import atexit
import argparse
import csv
import datetime
import hashlib
import ipaddress
import json
import os
import random
import re
import signal
import shutil
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import zipfile
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from dataclasses import dataclass
from pathlib import Path

from installers import (
    command_exists,
    ensure_dns_wordlist,
    ensure_resolvers_list,
    install_required_tools,
    resolve_tool,
    set_logger,
    verify_tool,
)

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import Progress, BarColumn, SpinnerColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.table import Table
    from rich import box
    from rich.text import Text
    RICH_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    RICH_AVAILABLE = False

RUN_LOG_FILE: Path | None = None
SCHEMA_VERSION = "1.0"
SHARED_CONSOLE: Console | None = None
ACTIVE_DASHBOARD: "HackerDashboard | None" = None
DASHBOARD_ACTIVE = False
SHUTTING_DOWN = False
INTERRUPT_COUNT = 0
INTERRUPT_LOCK = threading.Lock()
RUN_LOG_HANDLE = None
ACTIVE_CHILD_PGIDS: set[int] = set()
ACTIVE_CHILD_LOCK = threading.Lock()
FILE_APPEND_LOCK = threading.Lock()


def _close_log_handle() -> None:
    """Flush and close the global run log handle on program exit."""
    global RUN_LOG_HANDLE
    if RUN_LOG_HANDLE is not None:
        try:
            RUN_LOG_HANDLE.flush()
            RUN_LOG_HANDLE.close()
        except Exception:
            pass
        RUN_LOG_HANDLE = None


atexit.register(_close_log_handle)


# Ensure common user bin paths are always resolvable (go/pipx installs).
os.environ["PATH"] = f"{Path.home() / 'go/bin'}:{Path.home() / '.local/bin'}:{os.environ.get('PATH','')}"

_SCORE_KEYWORDS = frozenset(["admin","login","signin","signup","oauth","sso","callback","redirect","api","graphql","swagger","openapi","actuator","console","upload","download","export","import","backup","debug","test","staging","internal",".git",".env","config","old","dev"])
_SCORE_PARAM_RX = re.compile(r"\b(id|token|redirect|url|next|callback|file|path|key|api_key|auth)\b")
_FP_PATTERNS = [re.compile(p, re.I) for p in [r"404\.html$", r"default\.html$", r"index\.html$", r"/error/?$", r"nginx_status", r"apple-app-site-association"]]
_DIRSEARCH_RX_1 = re.compile(r'(?P<url>https?://\S+).*?\b(?P<status>[1-5][0-9]{2})\b')
_DIRSEARCH_RX_2 = re.compile(r'(?P<status>[1-5][0-9]{2}).*?(?P<url>https?://\S+)')

_GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/query", "/gql", "/graphql/console", "/graphql/playground",
    "/api/v1/graphql", "/api/v2/graphql",
]

_GITHUB_DORK_QUERIES = [
    "{target} password", "{target} secret", "{target} api_key",
    "{target} aws_secret", "{target} private_key", "{target} token",
    "{target} database_url", "{target} connectionstring", "{target} .env", "{target} id_rsa",
]

_RX_AWS_KEY = re.compile(r'(?:AKIA|ASIA)[0-9A-Z]{16}')
_RX_AWS_SECRET = re.compile(r'aws_secret_access_key|aws.{0,20}secret', re.I)
_RX_API_KEY = re.compile(
    r'(?:x-api-key|api[_-]?key|apikey)\s*[=:"\'\s]\s*["\'`]?([A-Za-z0-9_\-.]{16,})',
    re.I
)
_RX_BEARER = re.compile(r'bearer\s+([A-Za-z0-9._-]{20,})', re.I)
_RX_GENERIC_SECRET = re.compile(
    r'(?:secret|password|passwd|private_key)\s*[=:"\'\s]\s*["\']([A-Za-z0-9_\-.+/=]{8,})["\']',
    re.I
)
_RX_JWT = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')
_RX_S3_REF = re.compile(r's3\.amazonaws\.com|[a-z0-9.-]+\.s3\.amazonaws\.com')
_RX_CLOUDFRONT = re.compile(r'[a-z0-9-]+\.cloudfront\.net')
_RX_BUCKET_HOST = re.compile(r'([a-z0-9.-]+)\.s3\.amazonaws\.com')
_RX_BUCKET_URI = re.compile(r's3://([a-z0-9.-]+)')
_RX_JS_PATH = re.compile(
    r'["\'](/(?:api|v\d|graphql|rest|service|internal|admin|auth|oauth)[/A-Za-z0-9_\-./]{2,60})["\']'
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    duration_seconds: float
    stdout_path: str | None = None
    stderr_path: str | None = None
    attempts: int = 1


class GracefulInterrupt(Exception):
    pass


def request_shutdown(reason: str = "") -> None:
    global SHUTTING_DOWN, INTERRUPT_COUNT
    with INTERRUPT_LOCK:
        INTERRUPT_COUNT += 1
        count = INTERRUPT_COUNT
    if count >= 2:
        raise SystemExit(130)
    SHUTTING_DOWN = True
    if reason:
        try:
            log(f"[!] {reason}")
        except Exception as e:
            print(f"[!] request_shutdown logging failed: {e}", file=sys.stderr)


def handle_sigint(signum, frame) -> None:
    request_shutdown("SIGINT received. Stopping child processes…")
    with ACTIVE_CHILD_LOCK:
        pgids = list(ACTIVE_CHILD_PGIDS)
    for pgid in pgids:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except Exception:
            pass


def now_utc_iso() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def utc_now_display() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def esc_md_pipe(value: object) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ").strip()


def append_text_line(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write((line or "").rstrip("\n") + "\n")


def _backoff_sleep(base: float, attempt: int) -> None:
    jitter = random.uniform(0.0, max(0.05, base))
    time.sleep(min(2.5, base * (2 ** max(0, attempt - 1)) + jitter))


def normalize_url_for_output(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    u = re.sub(r"#.*$", "", u)
    return u


def score_endpoint_url(url: str) -> int:
    u = (url or "").lower()
    if not u:
        return 0
    score = 0
    for k in _SCORE_KEYWORDS:
        if k in u:
            score += 8
    if _SCORE_PARAM_RX.search(u):
        score += 12
    if "?" in u:
        score += 4
    return min(score, 100)


def _download_js(url: str, timeout: int = 12) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _JS_USER_AGENTS[0]})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception:
        return ""


_JS_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
]


HACKER_LOGO = """[bold green]╔═[ RECON HARVEST ]══════════════════════════╗
║  █▀█ █▀▀ █▀▀ █▀█ █▄ █   █░█ ▄▀█ █▀█ █░█ ▄▀█ █▀ ▀█▀  ║
║  █▀▄ ██▄ █▄▄ █▄█ █ ▀█   █▀█ █▀█ █▀▄ ▀▄▀ █▀█ ▄█ ░█░  ║
╚════════════════════════════════════════════╝[/bold green]
[bold cyan]ReconHarvest Framework[/bold cyan]"""


class NullDashboard:
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def stage_start(self, stage: str) -> None: ...
    def stage_done(self, stage: str, duration: float) -> None: ...
    def set_stats(self, stats: dict[str, int]) -> None: ...
    def set_context(self, **kwargs) -> None: ...
    def add_event(self, text: str) -> None: ...


class HackerDashboard:
    def __init__(self, target: str, parallel: int, total_stages: int, console: Console | None = None):
        self.target = target
        self.parallel = parallel
        self.total_stages = total_stages
        self.console = console or Console()
        self.live: Live | None = None
        self.stage_order = list(PIPELINE_STAGES)
        self.current_stage = "init"
        self.stage_started_at = time.monotonic()
        self.run_started_at = time.monotonic()

        self.progress = Progress(
            SpinnerColumn(style="yellow"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=20),
            TextColumn("{task.percentage:>3.0f}%"),
            TextColumn("{task.completed}/{task.total}"),
            TimeRemainingColumn(compact=True),
            TimeElapsedColumn(),
            TextColumn("[magenta]{task.fields[phase]}[/magenta]"),
            expand=True,
            console=self.console,
        )
        self.task = self.progress.add_task("pipeline", total=max(1, total_stages), completed=0, phase="init")
        self.subtask = self.progress.add_task("current step", total=100, completed=0, phase="pending")

        self.stats = {
            "subdomains": 0, "live_hosts": 0, "endpoints": 0, "params": 0,
            "nuclei_findings": 0, "hosts_401_403": 0, "legacy_hosts": 0,
            "throttled_hosts": 0, "skipped_hosts": 0,
            "resolved": 0, "subfinder_count": 0, "assetfinder_count": 0,
            "probed_hosts": 0, "nuclei_findings_phase1": 0, "nuclei_findings_phase2": 0, "secrets_findings": 0, "takeover_findings": 0, "cors_findings": 0,
            "xss_findings": 0, "bypass_403_findings": 0, "graphql_findings": 0, "github_dork_hits": 0,
        }
        self.context = {
            "current_host": "-", "queue_depth": 0, "active_jobs": 0, "failed_jobs": 0,
            "httpx_buckets": "-", "nuclei_hosts_scanned": None, "output_dir": "-", "run_mode": "--run",
            "log_file": "run.log", "profile": "balanced/waf-safe", "source_running": "-",
            "ffuf_mode": "-", "dirsearch_mode": "-", "nuclei_severity": "-", "nuclei_tags": "-",
            "subtask_done": 0, "subtask_total": 0,
        }

        self.events: deque[Text] = deque(maxlen=8)
        self._pending_events: deque[Text] = deque(maxlen=64)
        self.last_update = utc_now_display()
        self._dirty = True
        self._last_refresh_monotonic = 0.0
        self._refresh_interval = 0.35

    def _short_ts(self) -> str:
        return datetime.datetime.now(datetime.UTC).strftime("%H:%M:%S")

    def _truncate(self, text: str, width: int = 88) -> str:
        text = re.sub(r"\s+", " ", str(text)).strip()
        return text if len(text) <= width else text[: width - 1] + "…"

    def _fmt_event(self, text: str) -> Text:
        t = self._truncate(text, 82)
        low = t.lower()
        color = "cyan"
        if "done" in low or "completed" in low:
            color = "green"
        elif "warn" in low or "start" in low:
            color = "yellow"
        elif "err" in low or "fail" in low:
            color = "red"
        return Text.assemble((self._short_ts() + " ", "dim"), (t, color))

    def _stage_idx(self, stage: str) -> int:
        base = stage.split(" ")[0]
        return self.stage_order.index(base) if base in self.stage_order else -1

    def _is_reached(self, stage_name: str) -> bool:
        return self._stage_idx(self.current_stage) >= self._stage_idx(stage_name)

    def _metric(self, key: str, stage_gate: str | None = None, color: str = "green") -> Text:
        if stage_gate and not self._is_reached(stage_gate):
            return Text("pending", style="dim")
        v = self.stats.get(key)
        if v is None:
            return Text("—", style="dim")
        return Text(str(v), style=color)

    def add_event(self, text: str) -> None:
        self._pending_events.append(self._fmt_event(text))
        self._dirty = True
        immediate = bool(re.search(r"\b(start|done|warn|err|error|failed)\b", str(text), re.IGNORECASE))
        self._maybe_refresh(force=immediate)

    def _flush_pending_events(self) -> None:
        while self._pending_events:
            self.events.append(self._pending_events.popleft())

    def set_context(self, **kwargs) -> None:
        changed = False
        for k, v in kwargs.items():
            if v is None:
                continue
            if self.context.get(k) != v:
                self.context[k] = v
                changed = True
        if changed:
            self.last_update = utc_now_display()
            self._dirty = True
            self._maybe_refresh()

    def _render_mission(self):
        mission = Table.grid(expand=True)
        mission.add_column(style="cyan")
        mission.add_column(style="white")
        elapsed = int(time.monotonic() - self.stage_started_at)
        mission.add_row("Stage", Text(self.current_stage, style="bold magenta"))
        mission.add_row("Elapsed", Text(f"{elapsed}s"))
        st = self.current_stage
        if st.startswith("subdomains"):
            mission.add_row("Source", Text(str(self.context.get("source_running", "-")), style="yellow"))
            mission.add_row("Subfinder", self._metric("subfinder_count", "subdomains", "cyan"))
            mission.add_row("Assetfinder", self._metric("assetfinder_count", "subdomains", "cyan"))
            mission.add_row("Merged", self._metric("subdomains", "subdomains", "green"))
        elif st.startswith("dnsx"):
            mission.add_row("Inputs", self._metric("subdomains", "subdomains", "cyan"))
            mission.add_row("Resolved", self._metric("resolved", "dnsx", "green"))
        elif st.startswith("httpx"):
            mission.add_row("Probed", self._metric("probed_hosts", "httpx", "cyan"))
            mission.add_row("Live", self._metric("live_hosts", "httpx", "green"))
            mission.add_row("Threads", Text(str(self.parallel)))
            mission.add_row("Buckets", Text(self._truncate(str(self.context.get("httpx_buckets", "-")), 45), style="yellow"))
        elif st.startswith("discovery"):
            mission.add_row("Host", Text(self._truncate(str(self.context.get("current_host", "-")), 45), style="yellow"))
            mission.add_row("Queue", Text(str(self.context.get("queue_depth", 0))))
            mission.add_row("Jobs", Text.assemble((str(self.context.get("active_jobs", 0)), "green"), (" / ", "white"), (str(self.context.get("failed_jobs", 0)), "red")))
            mission.add_row("ffuf", Text(str(self.context.get("ffuf_mode", "-")), style="cyan"))
            mission.add_row("dirsearch", Text(str(self.context.get("dirsearch_mode", "-")), style="cyan"))
        elif st.startswith("nuclei"):
            nscan = self.context.get("nuclei_hosts_scanned", None)
            mission.add_row("Hosts Scanned", Text("pending", style="dim") if nscan is None else Text(str(nscan)))
            mission.add_row("Findings", self._metric("nuclei_findings", "nuclei_phase1", "yellow"))
            mission.add_row("Severity", Text(str(self.context.get("nuclei_severity", "-")), style="cyan"))
            mission.add_row("Tags", Text(self._truncate(str(self.context.get("nuclei_tags", "-")), 40), style="cyan"))
        else:
            mission.add_row("Target", Text(self.target, style="cyan"))
            mission.add_row("Parallel", Text(str(self.parallel)))
        return mission

    def _render_triage(self):
        triage = Table.grid(expand=True)
        triage.add_column(style="cyan")
        triage.add_column(justify="right")
        triage.add_row(Text("Discovery", style="bold"), Text(""))
        triage.add_row("Subdomains", self._metric("subdomains", "subdomains", "green"))
        triage.add_row("Resolved", self._metric("resolved", "dnsx", "green"))
        triage.add_row("Live Hosts", self._metric("live_hosts", "httpx", "green"))
        triage.add_row(Text(""), Text(""))
        triage.add_row(Text("URLs", style="bold"), Text(""))
        triage.add_row("Endpoints", self._metric("endpoints", "urls", "green"))
        triage.add_row("Params", self._metric("params", "urls", "green"))
        triage.add_row(Text(""), Text(""))
        triage.add_row(Text("Findings", style="bold"), Text(""))
        triage.add_row("Nuclei", self._metric("nuclei_findings", "nuclei_phase1", "yellow"))
        triage.add_row("Nuclei P2", self._metric("nuclei_findings_phase2", "nuclei_phase2", "yellow"))
        triage.add_row("Takeover", self._metric("takeover_findings", "takeover", "yellow"))
        triage.add_row("Secrets Hits", self._metric("secrets_findings", "secrets", "yellow"))
        triage.add_row("CORS", self._metric("cors_findings", "cors", "red"))
        triage.add_row("XSS", self._metric("xss_findings", "xss_scan", "red"))
        triage.add_row("403 Bypass", self._metric("bypass_403_findings", "bypass_403", "red"))
        triage.add_row("GraphQL Open", self._metric("graphql_findings", "graphql", "yellow"))
        triage.add_row("GitHub Leaks", self._metric("github_dork_hits", "github_dork", "red"))
        triage.add_row("401/403 Hosts", self._metric("hosts_401_403", "httpx", "yellow"))
        triage.add_row("Legacy Hosts", self._metric("legacy_hosts", "tech_host_mapping", "yellow"))
        triage.add_row("Throttled Hosts", self._metric("throttled_hosts", "discovery", "red"))
        return triage

    def _render(self):
        self._flush_pending_events()
        layout = Layout()

        status_line = Text.assemble(
            (self.target, "cyan"),
            (" • ", "white"),
            (self.current_stage, "magenta"),
            (" • ", "white"),
            (str(self.context.get("profile", "balanced/waf-safe")), "cyan"),
            (" • ", "white"),
            (str(self.context.get("run_mode", "--run")), "yellow"),
            (" • ", "white"),
            (self._truncate(str(self.context.get("output_dir", "-")), 40), "cyan"),
            (" • ", "white"),
            (f"{int(time.monotonic() - self.run_started_at)}s", "green"),
        )

        layout.split_column(
            Layout(Panel(HACKER_LOGO, border_style="green", box=box.SIMPLE), size=7),
            Layout(Panel(status_line, box=box.MINIMAL), size=3),
            Layout(name="middle", ratio=1),
            Layout(name="footer", size=3),
        )

        progress_tbl = Table.grid(expand=True)
        progress_tbl.add_row(self.progress)
        sub_done = int(self.context.get("subtask_done", 0) or 0)
        sub_total = int(self.context.get("subtask_total", 0) or 0)
        self.progress.update(
            self.subtask,
            total=max(1, sub_total or 1),
            completed=min(sub_done, max(1, sub_total or 1)),
            phase=self._truncate(str(self.context.get("source_running", self.current_stage)), 36),
            description="current step",
        )
        step_line = Text.assemble(
            ("Current step: ", "cyan"),
            (f"{sub_done}/{sub_total if sub_total else '—'}", "white"),
            ("  ", "white"),
            (self._truncate(str(self.context.get("source_running", "-")), 44), "magenta"),
        )
        progress_tbl.add_row(step_line)

        events = Table.grid(expand=True)
        recent = list(self.events)[-8:]
        if not recent:
            recent = [Text("-- waiting --", style="cyan")]
        for e in recent:
            events.add_row(e)

        middle = Layout()
        middle.split_column(Layout(name="upper", ratio=2, minimum_size=10), Layout(name="lower", ratio=2, minimum_size=10))
        middle["upper"].split_row(
            Layout(Panel(self._render_mission(), title="Mission", border_style="magenta", box=box.SIMPLE), ratio=1, minimum_size=45),
            Layout(Panel(self._render_triage(), title="Triage / Findings", border_style="green", box=box.SIMPLE), ratio=1, minimum_size=45),
        )
        middle["lower"].split_row(
            Layout(Panel(progress_tbl, title="Progress", border_style="yellow", box=box.SIMPLE), ratio=1, minimum_size=45),
            Layout(Panel(events, title="Recent Events", border_style="cyan", box=box.SIMPLE, height=12), ratio=1, minimum_size=45),
        )
        layout["middle"].update(middle)

        footer = Text.assemble(
            ("Updated: ", "cyan"),
            (self.last_update, "white"),
            (" • ", "white"),
            ("Workers: ", "green"),
            (str(self.context.get("active_jobs", 0)), "white"),
            (" • ", "white"),
            ("Failures: ", "red"),
            (str(self.context.get("failed_jobs", 0)), "white"),
            (" • ", "white"),
            ("Log: ", "cyan"),
            (self._truncate(str(self.context.get("log_file", "run.log")), 36), "white"),
            (" • ", "white"),
            ("Ctrl+C safe stop", "yellow"),
        )
        layout["footer"].update(Panel(footer, border_style="cyan", box=box.MINIMAL))
        return layout

    def _maybe_refresh(self, force: bool = False) -> None:
        if not self.live:
            return
        now = time.monotonic()
        if not force and (not self._dirty or (now - self._last_refresh_monotonic) < self._refresh_interval):
            return
        self.live.update(self._render(), refresh=True)
        self._last_refresh_monotonic = now
        self._dirty = False

    def start(self) -> None:
        global ACTIVE_DASHBOARD, DASHBOARD_ACTIVE, SHARED_CONSOLE
        SHARED_CONSOLE = self.console
        self.live = Live(self._render(), console=self.console, auto_refresh=False, refresh_per_second=2, transient=False)
        self.live.start()
        ACTIVE_DASHBOARD = self
        DASHBOARD_ACTIVE = True
        self._last_refresh_monotonic = 0.0
        self._dirty = True
        self._maybe_refresh(force=True)

    def stop(self) -> None:
        global ACTIVE_DASHBOARD, DASHBOARD_ACTIVE
        if self.live:
            self._flush_pending_events()
            self._dirty = True
            self._maybe_refresh(force=True)
            self.live.stop()
            self.live = None
        ACTIVE_DASHBOARD = None
        DASHBOARD_ACTIVE = False

    def stage_start(self, stage: str) -> None:
        self.current_stage = stage
        self.stage_started_at = time.monotonic()
        self.progress.update(self.task, phase=stage)
        self.add_event(f"START {stage}")
        self._dirty = True
        self._maybe_refresh()

    def stage_done(self, stage: str, duration: float) -> None:
        self.current_stage = f"{stage} ({duration:.1f}s)"
        self.progress.advance(self.task, 1)
        self.progress.update(self.task, phase=f"done:{stage}")
        self.add_event(f"DONE {stage} {duration:.1f}s")
        self._dirty = True
        self._maybe_refresh(force=True)

    def set_stats(self, stats: dict[str, int]) -> None:
        changed = False
        for k, v in stats.items():
            if self.stats.get(k) != v:
                self.stats[k] = v
                changed = True
        if changed:
            self.last_update = utc_now_display()
            self._dirty = True
            self._maybe_refresh()


def should_surface_event(message: str) -> bool:
    s = str(message).lower()
    return bool(re.search(r"\b(start|done|warn|err|error|failed|retry|throttle|throttled|interrupt|shutdown)\b", s))


def log(message: str) -> None:
    global RUN_LOG_HANDLE, ACTIVE_DASHBOARD, DASHBOARD_ACTIVE, SHARED_CONSOLE
    if RUN_LOG_FILE:
        if RUN_LOG_HANDLE is None:
            RUN_LOG_HANDLE = RUN_LOG_FILE.open("a", encoding="utf-8")
        RUN_LOG_HANDLE.write(f"{now_utc_iso()} {message}\n")
        RUN_LOG_HANDLE.flush()

    if DASHBOARD_ACTIVE and ACTIVE_DASHBOARD and ACTIVE_DASHBOARD.live:
        ACTIVE_DASHBOARD.live.console.print(message, markup=False)
        if should_surface_event(message):
            ACTIVE_DASHBOARD.add_event(message)
        return

    if SHARED_CONSOLE is not None:
        SHARED_CONSOLE.print(message, markup=False)
    else:
        print(message)


def is_valid_output_name(name: str) -> bool:
    return True


def normalize_target(value: str) -> str:
    value = (value or '').strip()
    value = re.sub(r'^https?://', '', value, flags=re.I)
    value = value.split('/', 1)[0]
    value = value.split(':', 1)[0]
    return value


def safe_target_dirname(value: str) -> str:
    value = normalize_target(value)
    value = re.sub(r'[^A-Za-z0-9._-]', '_', value)
    return value or 'target'


def next_run_name(target_dir: Path) -> str:
    if not target_dir.exists():
        return "1"
    max_n = 0
    for p in target_dir.iterdir():
        if p.is_dir() and p.name.isdigit():
            max_n = max(max_n, int(p.name))
    return str(max_n + 1)


def find_latest_previous_run(target: str, current_workdir: Path) -> Path | None:
    target_dir = Path("outputs") / safe_target_dirname(target)
    if not target_dir.exists():
        return None
    candidates = []
    for p in target_dir.iterdir():
        if p.is_dir() and p != current_workdir:
            try:
                candidates.append((p.stat().st_mtime, p))
            except OSError:
                continue
    if not candidates:
        return None
    return sorted(candidates, reverse=True)[0][1]


def safe_name_for_host(host: str) -> str:
    digest = hashlib.sha256(host.encode("utf-8", errors="ignore")).hexdigest()[:12]
    host = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", host)
    host = re.sub(r"[^A-Za-z0-9_.-]", "_", host).strip("_")
    if not host:
        host = "host"
    return f"{host}__{digest}"


@dataclass(frozen=True)
class ReconConfig:
    ffuf_threads: int = 40
    ffuf_timeout: int = 5
    ffuf_rate: int = 50
    ffuf_maxtime_job: int = 45
    ffuf_delay: str = "0.03-0.12"
    dirsearch_threads: int = 40
    dirsearch_timeout: int = 5
    dirsearch_delay: float = 0.05
    httpx_threads: int = 200
    httpx_timeout: int = 5
    httpx_retries: int = 1
    subfinder_timeout: int = 180
    assetfinder_timeout: int = 180
    dnsx_timeout: int = 180
    httpx_stage_timeout: int = 300
    host_workers: int = 20
    ffuf_workers: int = 8
    dirsearch_workers: int = 10
    url_workers: int = 10
    katana_timeout: int = 300
    gospider_timeout: int = 300
    hakrawler_timeout: int = 300
    katana_depth: int = 3
    katana_js_crawl: bool = True
    gau_timeout: int = 300
    gau_blacklist: str = "png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3,pdf,zip,tar,gz,rar,7z,dmg,exe,dll,css,map"
    global_request_budget: int = 120
    stop_on_403_ratio: float = 0.95
    stop_on_error: bool = True
    scan_profile: str = "balanced"
    target_profile: str = "waf-safe"
    nuclei_rate_limit: int = 50
    nuclei_concurrency: int = 50
    nuclei_max_host_error: int = 100
    nuclei_timeout: int = 5
    nuclei_retries: int = 1
    secrets_timeout: int = 20
    secrets_js_cap: int = 200
    secrets_sf_cap: int = 50
    secrets_download_delay: float = 0.15
    cors_timeout: int = 8
    skip_secrets: bool = False
    skip_takeover: bool = False
    skip_cors: bool = False
    naabu_ports: str = "80,443,8080,8443,8888,8008,9090,9443,3000,4000,5000,6000,7000,8000,9000,9200,9300,10000,27017,3306,5432,6379"
    naabu_rate: int = 1000
    naabu_timeout: int = 300
    naabu_top_ports: str = ""
    skip_portscan: bool = False
    dns_bruteforce_timeout: int = 600
    skip_dns_bruteforce: bool = False
    arjun_timeout: int = 400
    arjun_host_cap: int = 50
    arjun_threads: int = 10
    skip_param_discovery: bool = False
    dalfox_timeout: int = 600
    dalfox_url_cap: int = 200
    dalfox_workers: int = 20
    skip_xss: bool = False
    bypass_403_timeout: int = 300
    bypass_403_workers: int = 30
    skip_bypass_403: bool = False
    graphql_timeout: int = 8
    skip_graphql: bool = False
    vhost_timeout: int = 300
    vhost_threads: int = 40
    vhost_rate: int = 50
    skip_vhost: bool = False
    github_dork_timeout: int = 120
    skip_github_dork: bool = False
    skip_osint: bool = False
    skip_screenshots: bool = False
    screenshots_threads: int = 8
    screenshots_timeout: int = 10
    output_format: str = "md"
    debug_artifacts: bool = False
    max_report_files: int = 12


@dataclass(frozen=True)
class ToolVersions:
    ffuf: str = "github.com/ffuf/ffuf/v2@v2.1.0"
    httpx: str = "github.com/projectdiscovery/httpx/cmd/httpx@v1.7.1"
    subfinder: str = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.9.0"
    assetfinder: str = "github.com/tomnomnom/assetfinder@latest"
    dnsx: str = "github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.2"
    katana: str = "github.com/projectdiscovery/katana/cmd/katana@v1.1.2"
    gau: str = "github.com/lc/gau/v2/cmd/gau@v2.2.4"
    nuclei: str = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.4.10"


def validate_target(value: str) -> bool:
    value = normalize_target(value).strip().lower()
    if not value:
        return False
    if value == "localhost" or value.endswith(".local"):
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        pass
    if len(value) > 253 or value.startswith(".") or value.endswith(".") or ".." in value:
        return False
    if not re.fullmatch(r"[a-z0-9.-]+", value):
        return False
    labels = value.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


# STAGE_ORDER drives --resume-from-stage state marker resets and includes internal discovery sub-phases.
STAGE_ORDER = [
    "osint", "nuclei_templates", "subdomains", "dns_bruteforce",
    "dnsx", "takeover", "httpx", "vhost_fuzz", "portscan", "screenshots", "cors",
    "discovery_dirsearch", "discovery_ffuf_dirs", "discovery_ffuf_files", "discovery",
    "bypass_403", "graphql", "urls", "param_discovery",
    "tech", "tech_host_mapping", "nuclei_phase1", "xss_scan", "secrets", "github_dork",
    "nuclei_phase2", "endpoint_ranking",
]

# PIPELINE_STAGES is the user-facing dashboard pipeline order (top-level stages only).
PIPELINE_STAGES = [
    "osint", "nuclei_templates", "subdomains", "dns_bruteforce", "dnsx", "takeover",
    "httpx", "vhost_fuzz", "portscan", "screenshots", "cors", "discovery", "bypass_403", "graphql",
    "urls", "param_discovery", "tech", "tech_host_mapping", "nuclei_phase1", "xss_scan",
    "secrets", "github_dork", "nuclei_phase2", "endpoint_ranking",
]

_SUB_STAGES_ONLY = {"discovery_dirsearch", "discovery_ffuf_dirs", "discovery_ffuf_files"}
assert all(
    s in PIPELINE_STAGES
    for s in STAGE_ORDER
    if s not in _SUB_STAGES_ONLY
), "Stage definitions drifted; keep STAGE_ORDER and PIPELINE_STAGES aligned."


class Runner:
    def __init__(self, target: str, workdir: Path, parallel: int, config: ReconConfig | None = None, dashboard: NullDashboard | HackerDashboard | None = None, *, skip_nuclei: bool = False, skip_gau: bool = False, skip_secrets: bool = False, skip_takeover: bool = False, skip_cors: bool = False, force_update_templates: bool = False, nuclei_severity: str = "", nuclei_tags: str = ""):
        self.target = normalize_target(target)
        self.workdir = workdir
        self.parallel = parallel
        self.config = config or ReconConfig()
        self.dashboard = dashboard or NullDashboard()
        self.skip_nuclei = skip_nuclei
        self.skip_gau = skip_gau
        self.skip_secrets = bool(skip_secrets or self.config.skip_secrets)
        self.skip_takeover = bool(skip_takeover or self.config.skip_takeover)
        self.skip_cors = bool(skip_cors or self.config.skip_cors)
        self.force_update_templates = bool(force_update_templates)
        self.nuclei_severity = nuclei_severity
        self.nuclei_tags = nuclei_tags
        self.resume_mode: bool = False
        self._resume_notice_sent: bool = False
        self.state = workdir / ".state"
        self.logs = workdir / "logs"
        self.ffuf = workdir / "ffuf"
        self.dirsearch = workdir / "dirsearch"
        self.urls = workdir / "urls"
        self.intel = workdir / "intel"
        self.reports = workdir / "reports"
        self.cache = workdir / "cache"
        self.raw = workdir / "raw"
        self.commands_md = workdir / "COMMANDS_USED.md"
        self.command_log_jsonl = self.logs / "command_log.jsonl"
        self.status_jsonl = self.logs / "stage_status.jsonl"
        self.errors_jsonl = self.logs / "errors.jsonl"
        self.failure_log = self.logs / "discovery_failures.log"
        self._command_lock = threading.Lock()
        self._httpx_cache: dict[str, dict] = {}
        self.findings: list[dict] = []
        self._last_webhook_at: float = 0.0
        self._last_webhook_fingerprint: str = ""
        self._webhook_failed_sends: int = 0
        self._webhook_consecutive_failures: int = 0
        self._webhook_circuit_open_until: float = 0.0
        self._webhook_sent_ok: int = 0
        self._webhook_events_dropped: int = 0
        self._webhook_queue: deque[dict] = deque()
        self._webhook_lock = threading.Lock()
        self._webhook_signal = threading.Event()
        self._webhook_stop = threading.Event()
        self._webhook_worker: threading.Thread | None = None
        self._last_command_context: dict | None = None
        for d in (self.state, self.logs, self.ffuf, self.dirsearch, self.urls, self.intel, self.reports, self.cache, self.raw):
            d.mkdir(parents=True, exist_ok=True)
        self.commands_md.write_text("", encoding="utf-8")
        self.command_log_jsonl.write_text("", encoding="utf-8")
        self.status_jsonl.write_text("", encoding="utf-8")
        self.errors_jsonl.write_text("", encoding="utf-8")
        self.failure_log.write_text("", encoding="utf-8")

        self.ffuf_bin = resolve_tool("ffuf")
        self.httpx_bin = resolve_tool("httpx")
        self.subfinder_bin = resolve_tool("subfinder")
        self.assetfinder_bin = resolve_tool("assetfinder")
        self.dnsx_bin = resolve_tool("dnsx")
        self.katana_bin = resolve_tool("katana")
        self.gau_bin = resolve_tool("gau")
        self.nuclei_bin = resolve_tool("nuclei")
        self.dirsearch_bin = resolve_tool("dirsearch")
        self.trufflehog_bin = resolve_tool("trufflehog")
        self.gitleaks_bin = resolve_tool("gitleaks")
        self.s3scanner_bin = resolve_tool("s3scanner")
        self.subzy_bin = resolve_tool("subzy")
        self.naabu_bin = resolve_tool("naabu")
        self.puredns_bin = resolve_tool("puredns")
        self.arjun_bin = resolve_tool("arjun")
        self.dalfox_bin = resolve_tool("dalfox")
        self.graphw00f_bin = resolve_tool("graphw00f")
        self.asnmap_bin = resolve_tool("asnmap")
        self.gospider_bin = resolve_tool("gospider")
        self.hakrawler_bin = resolve_tool("hakrawler")
        self.gowitness_bin = resolve_tool("gowitness")
        self.secretfinder_py = str(Path.home() / ".local/share/secretfinder/SecretFinder.py")
        self._hydrate_httpx_cache()

        base = Path("/usr/share/seclists/Discovery/Web-Content")
        self.ffuf_dir_wordlist = base / "raft-medium-directories.txt"
        self.ffuf_file_wordlist = base / "raft-medium-files.txt"
        self.dirsearch_wordlist = base / "directory-list-2.3-medium.txt"
        common = base / "common.txt"
        if not self.ffuf_dir_wordlist.exists():
            self.ffuf_dir_wordlist = common
        if not self.ffuf_file_wordlist.exists():
            self.ffuf_file_wordlist = common
        if not self.dirsearch_wordlist.exists():
            self.dirsearch_wordlist = common
        missing = [p for p in (self.ffuf_dir_wordlist, self.ffuf_file_wordlist, self.dirsearch_wordlist) if not p.exists()]
        if missing:
            fallback = self.workdir / "minimal_wordlist.txt"
            if not fallback.exists():
                fallback.write_text("admin\nlogin\napi\nbackup\nupload\ndownload\nconfig\n", encoding="utf-8")
            self.ffuf_dir_wordlist = fallback
            self.ffuf_file_wordlist = fallback
            self.dirsearch_wordlist = fallback
            self.record_stage_status("wordlists", "fallback", f"missing_seclists={len(missing)} using={fallback}")

    def is_done(self, name: str) -> bool:
        return (self.state / f"{name}.done").exists()

    def mark_done(self, name: str) -> None:
        (self.state / f"{name}.done").write_text("", encoding="utf-8")

    def record_stage_status(self, stage: str, status: str, detail: str = "", metrics: dict | None = None, duration_seconds: float | None = None) -> None:
        if self.resume_mode and status in {"started", "completed", "skipped"}:
            return
        row = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": now_utc_iso(),
            "stage": stage,
            "status": status,
            "detail": detail,
            "duration_seconds": round(duration_seconds, 3) if duration_seconds is not None else None,
            "metrics": metrics or {},
        }
        with self._command_lock:
            with self.status_jsonl.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def record_failure(self, stage: str, host: str, error: Exception, tool: str = "") -> None:
        detail = f"{stage} failed for {host}: {error}"
        row = {
            "schema_version": SCHEMA_VERSION,
            "timestamp": now_utc_iso(),
            "stage": stage,
            "status": "error",
            "detail": detail,
            "duration_seconds": None,
            "metrics": {},
        }
        with self._command_lock:
            with self.failure_log.open("a", encoding="utf-8") as f:
                f.write(f"{now_utc_iso()} {detail}\n")
            with self.errors_jsonl.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"timestamp": now_utc_iso(), "stage": stage, "tool": tool or stage, "host": host, "message": str(error)}) + "\n")
            with self.status_jsonl.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def log_cmd(self, label: str, cmd: str) -> None:
        with self._command_lock:
            with self.commands_md.open("a", encoding="utf-8") as f:
                f.write(f"## {label}\n\n```bash\n{cmd}\n```\n\n")

    def _hydrate_httpx_cache(self) -> None:
        """Load cached httpx metadata from disk to support resume flows."""
        self._httpx_cache = {}
        jpath = self.workdir / "httpx_results.json"
        if not jpath.exists():
            return
        try:
            for line in jpath.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                key = (obj.get("url") or obj.get("input") or "").strip()
                if not key:
                    continue
                self._httpx_cache[key] = {
                    "title": (obj.get("title") or "").lower(),
                    "tech": " ".join(obj.get("tech") or []).lower(),
                    "status": int(obj.get("status_code") or 0),
                }
        except Exception as e:
            log(f"[!] Failed to hydrate httpx cache: {e}")

    def write_json(self, path: Path, payload: dict | list) -> None:
        if isinstance(payload, dict):
            data = {"schema_version": SCHEMA_VERSION, **payload}
        else:
            data = {"schema_version": SCHEMA_VERSION, "items": payload}
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def append_command_log(self, payload: dict) -> None:
        with self._command_lock:
            with self.command_log_jsonl.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"schema_version": SCHEMA_VERSION, **payload}, ensure_ascii=False) + "\n")

    def add_finding(self, stage: str, severity: str, target: str, title: str, evidence: str = "", confidence: int | None = None, tags: list[str] | None = None) -> None:
        row = {
            "timestamp": now_utc_iso(),
            "stage": str(stage or "").strip(),
            "severity": str(severity or "INFO").upper(),
            "target": str(target or "").strip(),
            "title": str(title or "").strip(),
            "evidence": str(evidence or "").strip(),
            "confidence": int(confidence) if confidence is not None else None,
            "tags": list(tags or []),
        }
        self.findings.append(row)

    def dedup_findings(self, items: list[dict]) -> list[dict]:
        seen = set()
        out = []
        for it in items:
            key = (it.get("stage"), it.get("severity"), it.get("target"), it.get("title"))
            if key in seen:
                continue
            seen.add(key)
            out.append(it)
        return out

    def prioritize_findings(self, items: list[dict]) -> list[dict]:
        sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        return sorted(
            items,
            key=lambda x: (
                -sev_rank.get(str(x.get("severity", "INFO")).upper(), 1),
                -(int(x.get("confidence") or 0)),
                str(x.get("stage") or ""),
                str(x.get("target") or ""),
            ),
        )

    def write_md_report(self, path: Path, title: str, sections: list[str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        body = "\n\n".join([s.strip("\n") for s in sections if str(s).strip()])
        text = f"# {title}\n\n" + (body if body else "_No findings._\n")
        path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")

    def cleanup_non_md_artifacts(self, workdir: Path, keep_debug: bool) -> None:
        if keep_debug:
            return

        allowed_reports = {
            "summary.md",
            "findings.md",
            "discovery.md",
            "urls_params.md",
            "tech_summary.md",
            "secrets.md",
            "vuln_surface.md",
            "osint_report.md",
            "takeover.md",
            "nuclei.md",
        }

        for p in workdir.rglob("*"):
            if not p.is_file():
                continue
            sp = str(p)
            if "/logs/" in sp:
                continue
            
            # PROTECT essential files required by BreachPilot for ingestion
            if p.name in {"workspace_meta.json", "summary.json", "live_hosts.txt", "xss_findings.json", "dalfox_targets.txt"}:
                continue
            if p.parent == self.intel and "ranked" in p.name:
                continue
            sp = str(p)
            if "/logs/" in sp:
                continue
            if p.suffix.lower() in {".json", ".jsonl", ".txt"}:
                p.unlink(missing_ok=True)
                continue
            if p.suffix.lower() == ".md":
                # keep only compact reports set under reports/
                if p.parent == self.reports and p.name in allowed_reports:
                    continue
                p.unlink(missing_ok=True)

    def finalize_reports(self) -> None:
        reports = self.reports
        reports.mkdir(parents=True, exist_ok=True)

        def _read(path: Path) -> str:
            return path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""

        def _json_lines(path: Path, title: str) -> str:
            if not path.exists():
                return ""
            try:
                obj = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                return ""
            items = obj.get("items", obj) if isinstance(obj, dict) else obj
            if not isinstance(items, list) or not items:
                return ""
            out = [f"## {title}"]
            for it in items[:100]:
                out.append(f"- {it}")
            return "\n".join(out) + "\n"

        # Core report copies/merges
        self.write_md_report(reports / "osint_report.md", f"OSINT Report — {self.target}", [_read(self.intel / "osint_report.md")])
        self.write_md_report(reports / "discovery.md", f"Discovery — {self.target}", [_read(self.intel / "endpoints_ranked.md"), _json_lines(self.intel / "dirsearch_normalized.json", "Dirsearch Normalized")])
        self.write_md_report(reports / "urls_params.md", f"URLs & Params — {self.target}", [_read(self.intel / "params_ranked.md"), _read(self.urls / "urls_params.txt")])
        self.write_md_report(reports / "tech_summary.md", f"Tech Summary — {self.target}", [_read(self.intel / "tech_summary.md"), _read(self.intel / "tech_to_hosts.md"), _read(self.intel / "webserver_to_hosts.md")])
        self.write_md_report(reports / "secrets.md", f"Secrets — {self.target}", [_read(self.intel / "secrets_findings.md")])
        self.write_md_report(reports / "takeover.md", f"Takeover — {self.target}", [_read(self.workdir / "takeover_readable.md")])
        self.write_md_report(reports / "nuclei.md", f"Nuclei — {self.target}", [_read(self.workdir / "nuclei_readable.md"), _read(self.workdir / "nuclei_phase2_readable.md")])
        self.write_md_report(reports / "vuln_surface.md", f"Vulnerability Surface — {self.target}", [_read(self.intel / "cors_findings.md"), _json_lines(self.intel / "bypass_403_findings.json", "403 Bypass"), _json_lines(self.intel / "xss_findings.json", "XSS"), _json_lines(self.intel / "graphql_findings.json", "GraphQL")])

        ranked_findings = self.prioritize_findings(self.dedup_findings(self.findings))
        findings_lines = []
        for f in ranked_findings[:200]:
            findings_lines.append(
                f"- [{f.get('severity')}] {f.get('stage')} :: {f.get('target')} — {f.get('title')}"
                + (f" | confidence={f.get('confidence')}" if f.get('confidence') is not None else "")
                + (f"\n  - evidence: {f.get('evidence')}" if f.get('evidence') else "")
            )
        self.write_md_report(reports / "findings.md", f"Live Findings — {self.target}", ["\n".join(findings_lines) if findings_lines else "_No findings yet._"])
        self.write_md_report(reports / "summary.md", f"Summary — {self.target}", [_read(self.workdir / "summary.md")])
        try:
            summary_json_src = self.workdir / "summary.json"
            summary_json_dst = reports / "summary.json"
            if summary_json_src.exists():
                summary_json_dst.write_text(summary_json_src.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
            else:
                summary_json_dst.write_text(json.dumps({"error": "summary.json not found", "target": self.target}, indent=2), encoding="utf-8")
        except Exception as e:
            self.record_stage_status("final_reports", "warning", f"summary_json_copy_failed: {e}")

        self.cleanup_non_md_artifacts(self.workdir, keep_debug=self.config.debug_artifacts)

    def validate_outputs(self) -> None:
        required = [
            self.reports / "summary.md",
            self.reports / "findings.md",
            self.reports / "discovery.md",
            self.reports / "urls_params.md",
            self.reports / "tech_summary.md",
            self.reports / "secrets.md",
            self.reports / "vuln_surface.md",
            self.reports / "osint_report.md",
            self.reports / "takeover.md",
            self.reports / "nuclei.md",
        ]
        missing = [str(p) for p in required if not p.exists()]
        if missing:
            self.record_stage_status("final_validation", "error", f"missing_reports={len(missing)}")
            raise RuntimeError("Output validation failed: missing required reports")

        if not self.config.debug_artifacts:
            leftovers = []
            for p in self.workdir.rglob("*"):
                if not p.is_file():
                    continue
                sp = str(p)
                if "/logs/" in sp:
                    continue
                if p.name in {"workspace_meta.json", "summary.json"}:
                    continue
                if p.parent == self.intel and "ranked" in p.name:
                    continue
                if p.suffix.lower() in {".json", ".jsonl"}:
                    leftovers.append(str(p))
                    if len(leftovers) >= 5:
                        break
            if leftovers:
                self.record_stage_status("final_validation", "warning", f"json artifacts remained: {leftovers}")

        md_count = len(list(self.reports.glob("*.md")))
        if md_count > int(self.config.max_report_files):
            self.record_stage_status("final_validation", "error", f"too_many_reports={md_count}")
            raise RuntimeError("Output validation failed: report count exceeds threshold")

        ftxt = (self.reports / "findings.md").read_text(encoding="utf-8", errors="ignore")
        if not ("No findings" in ftxt or "- [" in ftxt):
            self.record_stage_status("final_validation", "error", "findings_rendering_invalid")
            raise RuntimeError("Output validation failed: findings rendering invalid")

        self.record_stage_status("final_validation", "completed", "output contract validated")

    def run_tool(self, label: str, cmd: list[str] | str, *, timeout: int | None = None, retries: int = 0, stdout_path: Path | None = None, stderr_path: Path | None = None, allow_failure: bool = False, stdin_tty: bool = False, env: dict[str, str] | None = None) -> CommandResult:
        global SHUTTING_DOWN
        display = cmd if isinstance(cmd, str) else " ".join(shlex.quote(part) for part in cmd)
        self.log_cmd(label, display)
        attempts = 0
        last_rc = 0
        t0 = time.perf_counter()
        for attempt in range(retries + 1):
            if SHUTTING_DOWN:
                last_rc = 130
                break
            attempts = attempt + 1
            mode = "w" if attempt == 0 else "a"
            out_handle = stdout_path.open(mode, encoding="utf-8") if stdout_path else subprocess.DEVNULL
            if stderr_path and stdout_path and stderr_path == stdout_path:
                err_handle = out_handle
            else:
                err_handle = stderr_path.open(mode, encoding="utf-8") if stderr_path else subprocess.DEVNULL
            proc = None
            try:
                argv = cmd if isinstance(cmd, list) else ["/bin/bash", "-c", cmd]
                proc = subprocess.Popen(
                    argv,
                    stdout=out_handle,
                    stderr=err_handle,
                    stdin=(None if stdin_tty else subprocess.DEVNULL),
                    start_new_session=True,
                    env=env,
                )
                with ACTIVE_CHILD_LOCK:
                    ACTIVE_CHILD_PGIDS.add(proc.pid)
                try:
                    last_rc = proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired as e:
                    last_rc = 124
                    self.record_failure("timeout", label, e, tool="run_tool")
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(proc.pid, signal.SIGKILL)
                            proc.wait(timeout=2)
                    except Exception:
                        pass
            except KeyboardInterrupt:
                request_shutdown("Interrupted by user (Ctrl+C). Graceful shutdown started.")
                self.record_stage_status("shutdown", "interrupted", f"user interrupted while running {label}")
                last_rc = 130
                if proc and proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except Exception:
                        pass
                raise GracefulInterrupt("interrupted")
            finally:
                if proc is not None:
                    with ACTIVE_CHILD_LOCK:
                        ACTIVE_CHILD_PGIDS.discard(proc.pid)
                if hasattr(out_handle, "close"):
                    out_handle.close()
                if err_handle is not out_handle and hasattr(err_handle, "close"):
                    err_handle.close()
            if last_rc == 0:
                break
            if attempt < retries and not SHUTTING_DOWN:
                time.sleep(2 ** attempt)
        result = CommandResult(returncode=last_rc, duration_seconds=round(time.perf_counter() - t0, 3), stdout_path=str(stdout_path) if stdout_path else None, stderr_path=str(stderr_path) if stderr_path else None, attempts=attempts)
        self._last_command_context = {
            "label": label,
            "command": display,
            "returncode": result.returncode,
            "duration_seconds": result.duration_seconds,
            "attempts": result.attempts,
            "stdout_path": result.stdout_path,
            "stderr_path": result.stderr_path,
        }
        self.append_command_log({"timestamp": now_utc_iso(), "label": label, "command": display, "returncode": result.returncode, "duration_seconds": result.duration_seconds, "attempts": result.attempts, "stdout_path": result.stdout_path, "stderr_path": result.stderr_path})
        if (not allow_failure) and result.returncode != 0:
            if self.config.stop_on_error:
                raise RuntimeError(f"{label} failed with return code {result.returncode}")
            self.record_failure("nonfatal", label, RuntimeError(f"return code {result.returncode}"), tool="run_tool")
        return result

    def reuse_previous_artifacts(self) -> int:
        previous = find_latest_previous_run(self.target, self.workdir)
        if not previous:
            return 0
        reusable = [
            ("all_subdomains.txt", self.workdir / "all_subdomains.txt"),
            ("resolved_subdomains.txt", self.workdir / "resolved_subdomains.txt"),
            ("httpx_results.txt", self.workdir / "httpx_results.txt"),
            ("httpx_results.json", self.workdir / "httpx_results.json"),
            ("live_hosts.txt", self.workdir / "live_hosts.txt"),
            ("urls/urls_all.txt", self.urls / "urls_all.txt"),
            ("urls/urls_params.txt", self.urls / "urls_params.txt"),
            ("urls/katana_urls.txt", self.urls / "katana_urls.txt"),
            ("urls/gau_urls.txt", self.urls / "gau_urls.txt"),
        ]
        reused = 0
        for rel, dest in reusable:
            src = previous / rel
            if src.exists() and src.stat().st_size > 0 and not dest.exists():
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                reused += 1
        if reused:
            log(f"[*] Reused {reused} cached artifact(s) from {previous}")
        return reused

    def resume_from_stage(self, stage: str) -> None:
        if stage not in STAGE_ORDER:
            valid = " ".join(STAGE_ORDER)
            raise RuntimeError(f"Unknown stage for --resume-from-stage: {stage}. Valid stages: {valid}")
        start_idx = STAGE_ORDER.index(stage)
        for name in STAGE_ORDER[start_idx:]:
            (self.state / f"{name}.done").unlink(missing_ok=True)
        log(f"[*] Cleared stage markers from: {stage}")

    def touch_files(self, *paths: Path) -> None:
        for p in paths:
            p.touch(exist_ok=True)

    def stage_nuclei_templates(self):
        if self.is_done("nuclei_templates"):
            return
        if self.skip_nuclei:
            self.record_stage_status("nuclei_templates", "skipped", "skip-nuclei enabled")
        elif self.nuclei_bin:
            templates_dir = Path.home() / "nuclei-templates"
            needs_update = True
            if (not self.force_update_templates) and templates_dir.exists():
                age_hours = (time.time() - templates_dir.stat().st_mtime) / 3600
                if age_hours < 24:
                    needs_update = False
                    log(f"[*] nuclei templates up to date (updated {age_hours:.1f}h ago), skipping update")
            if needs_update:
                self.run_tool("nuclei templates update", [self.nuclei_bin, "-update-templates", "-silent"], allow_failure=True)
                self.record_stage_status("nuclei_templates", "completed", "templates update attempted")
            else:
                self.record_stage_status("nuclei_templates", "completed", "templates update skipped (<24h)")
        else:
            self.record_stage_status("nuclei_templates", "skipped", "nuclei missing")
        self.mark_done("nuclei_templates")

    def stage_subdomains(self):
        if self.is_done("subdomains"):
            return
        subfinder_txt = self.workdir / "subfinder.txt"
        assetfinder_txt = self.workdir / "assetfinder.txt"
        all_subdomains = self.workdir / "all_subdomains.txt"
        self.touch_files(subfinder_txt, assetfinder_txt, all_subdomains)
        self.dashboard.set_context(source_running="subfinder", subtask_done=0, subtask_total=2)
        if self.subfinder_bin:
            self.run_tool("subfinder", [self.subfinder_bin, "-d", self.target, "-all", "-silent", "-o", str(subfinder_txt)], timeout=self.config.subfinder_timeout, allow_failure=True)
        self.dashboard.set_context(source_running="assetfinder", subtask_done=1, subtask_total=2)
        if self.assetfinder_bin:
            self.run_tool("assetfinder", [self.assetfinder_bin, "--subs-only", self.target], timeout=self.config.assetfinder_timeout, stdout_path=assetfinder_txt, stderr_path=self.logs / "assetfinder.stderr.log", allow_failure=True)
        lines = sorted({self.target} | {x.strip() for x in (subfinder_txt.read_text(encoding='utf-8', errors='ignore') + "\n" + assetfinder_txt.read_text(encoding='utf-8', errors='ignore')).splitlines() if x.strip()})
        all_subdomains.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        self.dashboard.set_context(source_running="merge complete", subtask_done=2, subtask_total=2)
        self.record_stage_status("subdomains", "completed", "merged passive subdomain sources")
        self.mark_done("subdomains")

    def stage_dnsx(self):
        if self.is_done("dnsx"):
            return
        all_subdomains = self.workdir / "all_subdomains.txt"
        self.dashboard.set_context(source_running="dnsx", subtask_done=0, subtask_total=1)
        resolved = self.workdir / "resolved_subdomains.txt"
        dnsx_raw = self.workdir / "dnsx_raw.txt"
        host_ip_map = self.intel / "dns_host_ip_map.json"
        self.touch_files(resolved, dnsx_raw)
        if self.dnsx_bin:
            # Prefer A-record output for host->IP mapping; keep host-only output as compatibility fallback.
            self.run_tool("dnsx", [self.dnsx_bin, "-l", str(all_subdomains), "-a", "-resp", "-silent", "-o", str(dnsx_raw)], timeout=self.config.dnsx_timeout, allow_failure=True)
            hosts: list[str] = []
            mp: dict[str, set[str]] = {}
            for line in dnsx_raw.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                host = parts[0].strip() if parts else ""
                if host:
                    hosts.append(host)
                raw_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line))
                ips: set[str] = set()
                for ip in raw_ips:
                    try:
                        ipaddress.ip_address(ip)
                        ips.add(ip)
                    except Exception:
                        continue
                if host and ips:
                    mp.setdefault(host, set()).update(ips)

            # Ensure IP addresses from all_subdomains.txt are included in resolved hosts
            if all_subdomains.exists():
                for line in all_subdomains.read_text(encoding="utf-8", errors="ignore").splitlines():
                    val = line.strip()
                    if not val:
                        continue
                    # Strip scheme if present
                    pure = re.sub(r'^https?://', '', val, flags=re.I).split(':')[0]
                    try:
                        ipaddress.ip_address(pure)
                        hosts.append(pure)
                        mp.setdefault(pure, set()).add(pure)
                    except Exception:
                        continue

            # Fallback enrichment from httpx output when dnsx output is hostname-only.
            if not mp:
                httpx_json = self.workdir / "httpx_results.json"
                if httpx_json.exists():
                    for ln in httpx_json.read_text(encoding="utf-8", errors="ignore").splitlines():
                        try:
                            o = json.loads(ln)
                        except Exception:
                            continue
                        host = str(o.get("host") or o.get("input") or "").strip()
                        if not host:
                            continue
                        hosts.append(host)
                        ipset: set[str] = set()
                        hip = str(o.get("host_ip") or "").strip()
                        if hip:
                            try:
                                ipaddress.ip_address(hip)
                                ipset.add(hip)
                            except Exception:
                                pass
                        for ip in (o.get("a") or []):
                            try:
                                ipaddress.ip_address(str(ip))
                                ipset.add(str(ip))
                            except Exception:
                                continue
                        if ipset:
                            mp.setdefault(host, set()).update(ipset)

            uniq_hosts = sorted(set(h for h in hosts if h))
            resolved.write_text("\n".join(uniq_hosts) + ("\n" if uniq_hosts else ""), encoding="utf-8")
            host_ip_map.write_text(json.dumps({k: sorted(v) for k, v in sorted(mp.items())}, indent=2), encoding="utf-8")
            detail = "dnsx resolution attempted (hostnames+ip mapping)"
            if not mp:
                detail = "dnsx resolution attempted (no IPs observed; map empty)"
            self.record_stage_status("dnsx", "completed", detail)
            self.dashboard.set_context(source_running="dnsx complete", subtask_done=1, subtask_total=1)
        else:
            lines_local = [x.strip() for x in all_subdomains.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
            resolved.write_text("\n".join(lines_local) + ("\n" if lines_local else ""), encoding="utf-8")
            host_ip_map.write_text("{}", encoding="utf-8")
            self.record_stage_status("dnsx", "fallback", "dnsx missing; copied subdomains as resolved hosts")
        self.mark_done("dnsx")

    def stage_takeover(self):
        if self.is_done("takeover"):
            return
        if self.skip_takeover:
            self.record_stage_status("takeover", "skipped", "skip-takeover enabled")
            self.mark_done("takeover")
            return
        resolved_subdomains = self.workdir / "resolved_subdomains.txt"
        takeover_summary = self.workdir / "takeover_summary.json"
        nuclei_rows: list[dict] = []
        subzy_rows: list[dict] = []

        if not (resolved_subdomains.exists() and resolved_subdomains.stat().st_size > 0):
            self.write_json(takeover_summary, {
                "schema_version": SCHEMA_VERSION,
                "nuclei_findings": 0,
                "subzy_findings": 0,
                "total": 0,
                "nuclei": [],
                "subzy": [],
            })
            self.record_stage_status("takeover", "completed", "nuclei=0 subzy=0 (no resolved subdomains)")
            self.mark_done("takeover")
            return

        tmp_dir = Path(tempfile.mkdtemp(prefix="rh-takeover-"))
        try:
            nuclei_tmp = tmp_dir / "takeover_nuclei.jsonl"
            subzy_tmp = tmp_dir / "takeover_subzy.json"

            if (not self.skip_nuclei) and self.nuclei_bin and not SHUTTING_DOWN:
                self.run_tool(
                    "takeover nuclei jsonl",
                    [
                        self.nuclei_bin, "-l", str(resolved_subdomains), "-tags", "takeovers",
                        "-severity", "medium,high,critical", "-silent",
                        "-rl", str(self.config.nuclei_rate_limit),
                        "-c", str(self.config.nuclei_concurrency),
                        "-max-host-error", str(self.config.nuclei_max_host_error),
                        "-timeout", str(self.config.nuclei_timeout),
                        "-retries", str(self.config.nuclei_retries),
                        "-jsonl", "-o", str(nuclei_tmp),
                    ],
                    timeout=900,
                    allow_failure=True,
                )
                if nuclei_tmp.exists():
                    for line in nuclei_tmp.read_text(encoding="utf-8", errors="ignore").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except Exception:
                            continue
                        info = obj.get("info") or {}
                        nuclei_rows.append({
                            "severity": str(info.get("severity") or "unknown").upper(),
                            "name": str(info.get("name") or obj.get("template-id") or ""),
                            "matched": str(obj.get("matched-at") or obj.get("host") or ""),
                        })

            if self.subzy_bin and not SHUTTING_DOWN:
                self.run_tool(
                    "takeover subzy",
                    [self.subzy_bin, "run", "--targets", str(resolved_subdomains), "--json"],
                    stdout_path=subzy_tmp,
                    stderr_path=self.logs / "takeover_subzy.log",
                    allow_failure=True,
                )
                subzy_rows = self._parse_subzy_findings(subzy_tmp)

            self.write_json(takeover_summary, {
                "schema_version": SCHEMA_VERSION,
                "nuclei_findings": len(nuclei_rows),
                "subzy_findings": len(subzy_rows),
                "total": len(nuclei_rows) + len(subzy_rows),
                "nuclei": nuclei_rows,
                "subzy": subzy_rows,
            })
            self.record_stage_status("takeover", "completed", f"nuclei={len(nuclei_rows)} subzy={len(subzy_rows)}")
            self.mark_done("takeover")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _fetch_cors_headers(self, url: str, origin: str) -> tuple[str, str] | None:
        req = urllib.request.Request(url, headers={
            "User-Agent": _JS_USER_AGENTS[0],
            "Origin": origin,
        })
        headers = None
        for attempt in range(1, 3):
            try:
                with urllib.request.urlopen(req, timeout=self.config.cors_timeout) as r:
                    headers = r.headers
                break
            except urllib.error.HTTPError as e:
                headers = e.headers
                break
            except Exception:
                if attempt == 2:
                    return None
                _backoff_sleep(0.4, attempt)
        if headers is None:
            return None
        return (headers.get("Access-Control-Allow-Origin", ""), headers.get("Access-Control-Allow-Credentials", ""))

    def _check_cors(self, host: str) -> dict | None:
        url = host.rstrip("/")
        evil_origin = "https://evil-cors-probe.com"
        ctrl_origin = "https://control-cors-probe.com"

        first = self._fetch_cors_headers(url, evil_origin)
        if not first:
            return None
        acao, acac = first
        if evil_origin not in acao:
            return None

        second = self._fetch_cors_headers(url, ctrl_origin)
        ctrl_reflects = bool(second and ctrl_origin in (second[0] or ""))
        if not ctrl_reflects:
            return None

        severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
        confidence = 95 if severity == "HIGH" else 85
        return {"host": host, "acao": acao, "acac": acac, "severity": severity, "confidence": confidence}

    def stage_cors(self):
        if self.is_done("cors"):
            return
        if self.skip_cors:
            self.record_stage_status("cors", "skipped", "skip-cors enabled")
            self.mark_done("cors")
            return
        live_hosts = self.workdir / "live_hosts.txt"
        out_json = self.intel / "cors_findings.json"
        out_md = self.intel / "cors_findings.md"
        hosts = [x.strip() for x in live_hosts.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()] if live_hosts.exists() else []
        findings: list[dict] = []
        if hosts:
            with ThreadPoolExecutor(max_workers=min(20, len(hosts))) as ex:
                futs = {ex.submit(self._check_cors, h): h for h in hosts}
                for fut in as_completed(futs):
                    if SHUTTING_DOWN:
                        break
                    try:
                        row = fut.result()
                    except Exception:
                        row = None
                    if row:
                        findings.append(row)
        findings = sorted(findings, key=lambda r: (0 if r.get("severity") == "HIGH" else 1, r.get("host") or ""))
        self.write_json(out_json, findings)
        md = ["# CORS Misconfiguration Findings\n\n", "| Severity | Host | ACAO | Credentials Allowed |\n", "|---|---|---|---|\n"]
        for r in findings:
            md.append(f"| {esc_md_pipe(r.get('severity',''))} | {esc_md_pipe(r.get('host',''))} | {esc_md_pipe(r.get('acao',''))} | {esc_md_pipe(r.get('acac',''))} |\n")
        out_md.write_text("".join(md), encoding="utf-8")
        self.record_stage_status("cors", "completed", f"findings={len(findings)}")
        for f in findings:
            self.add_finding("cors", f.get("severity", "MEDIUM"), f.get("host", ""), "CORS misconfiguration", evidence=f"ACAO={f.get('acao','')} ACAC={f.get('acac','')}", confidence=int(f.get("confidence") or 80), tags=["cors"])
        if findings:
            self._notify(f"CORS findings={len(findings)}", status="warning", stage="cors", severity="HIGH")
        self.write_live_findings()
        self.mark_done("cors")

    def stage_httpx(self):
        if self.is_done("httpx"):
            return
        resolved = self.workdir / "resolved_subdomains.txt"
        in_count = sum(1 for x in resolved.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()) if resolved.exists() else 0
        self.dashboard.set_context(source_running="httpx probe", subtask_done=0, subtask_total=max(1, in_count))
        httpx_txt = self.workdir / "httpx_results.txt"
        httpx_json = self.workdir / "httpx_results.json"
        live_hosts = self.workdir / "live_hosts.txt"
        self.touch_files(httpx_txt, httpx_json, live_hosts)
        if self.httpx_bin:
            self.run_tool(
                "httpx json",
                [
                    self.httpx_bin,
                    "-l", str(resolved),
                    "-silent", "-json", "-status-code", "-content-length", "-title", "-tech-detect",
                    "-threads", str(self.config.httpx_threads),
                    "-timeout", str(self.config.httpx_timeout),
                    "-retries", str(self.config.httpx_retries),
                    "-o", str(httpx_json),
                ],
                timeout=self.config.httpx_stage_timeout,
                allow_failure=True,
            )
            hosts = set()
            txt_lines = []
            buckets = {"2xx": 0, "3xx": 0, "401": 0, "403": 0, "other": 0}
            for line in httpx_json.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                status = obj.get("status_code")
                url = (obj.get("url") or obj.get("input") or "").strip()
                title = (obj.get("title") or "").strip()
                clen = obj.get("content_length")
                tech = ",".join((obj.get("tech") or [])[:5])
                if url:
                    txt_lines.append(f"[{status}] {url} len={clen} title={title} tech={tech}")
                if isinstance(status, int):
                    if status == 401:
                        buckets["401"] += 1
                    elif status == 403:
                        buckets["403"] += 1
                    elif 200 <= status < 300:
                        buckets["2xx"] += 1
                    elif 300 <= status < 400:
                        buckets["3xx"] += 1
                    else:
                        buckets["other"] += 1
                if url and isinstance(status, int) and ((200 <= status < 400) or status in (401, 403)):
                    hosts.add(url)
            httpx_txt.write_text("\n".join(txt_lines) + ("\n" if txt_lines else ""), encoding="utf-8")
            s_hosts = sorted(hosts)
            live_hosts.write_text("\n".join(s_hosts) + ("\n" if s_hosts else ""), encoding="utf-8")
            # Keep any pre-hydrated entries and update with fresh scan data.
            for line in httpx_json.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                key = (obj.get("url") or obj.get("input") or "").strip()
                if not key:
                    continue
                self._httpx_cache[key] = {
                    "title": (obj.get("title") or "").lower(),
                    "tech": " ".join(obj.get("tech") or []).lower(),
                    "status": int(obj.get("status_code") or 0),
                }
            self.dashboard.set_context(httpx_buckets=f"2xx={buckets['2xx']} 3xx={buckets['3xx']} 401={buckets['401']} 403={buckets['403']} other={buckets['other']}", source_running="httpx complete", subtask_done=sum(buckets.values()), subtask_total=max(1, sum(buckets.values())))
            self.record_stage_status("httpx", "completed", "single-pass httpx json; derived text + strict live hosts")
        else:
            lines = [x.strip() for x in resolved.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
            live_hosts.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            self._httpx_cache = {}
            self.record_stage_status("httpx", "fallback", "httpx missing; reused resolved hosts")
        self.mark_done("httpx")

    def classify_host(self, host: str) -> dict:
        cached = self._httpx_cache.get(host, {})
        title = str(cached.get("title") or "")
        tech = str(cached.get("tech") or "")
        status = int(cached.get("status") or 0)
        host_l = host.lower()
        staticish = bool(re.search(r"(^|[./-])(img|image|static|cdn|assets?|media)([./-]|$)", host_l))
        title_tech = f"{title} {tech}"
        wafish = any(x in title_tech for x in ["akamai", "cloudflare", "imperva", "waf"])
        score = 0
        if status in (200, 204, 301, 302, 307, 401, 403):
            score += 3
        if not staticish:
            score += 2
        if any(x in host_l for x in ["admin", "login", "api", "graphql", "swagger"]):
            score += 3
        if any(x in title_tech for x in ["admin", "login", "api", "graphql", "swagger"]):
            score += 2
        cls = "promising"
        if staticish:
            cls = "static"
        elif wafish and score <= 3:
            cls = "waf_heavy"
        return {"host": host, "score": score, "class": cls, "run_dirs": cls == "promising", "wafish": wafish}

    def _per_host_state(self, host: str, phase: str, state: str) -> None:
        p = self.state / "hosts" / phase
        p.mkdir(parents=True, exist_ok=True)
        (p / f"{safe_name_for_host(host)}.{state}").write_text("", encoding="utf-8")

    def _collect_ffuf_stats(self, csv_path: Path, log_path: Path) -> dict:
        rows, s403, s429, tmo = 0, 0, 0, 0
        req = 0
        if csv_path.exists() and csv_path.stat().st_size > 0:
            try:
                for i, ln in enumerate(csv_path.read_text(encoding="utf-8", errors="ignore").splitlines()):
                    if i == 0:
                        continue
                    rows += 1
                    if ",403," in ln:
                        s403 += 1
                    if ",429," in ln:
                        s429 += 1
            except Exception:
                pass
        if log_path.exists():
            t = log_path.read_text(encoding="utf-8", errors="ignore").lower()
            req_m = re.search(r"requests\s*:\s*(\d+)", t)
            if req_m:
                req = int(req_m.group(1))
            if "timeout" in t or "deadline" in t:
                tmo = 1
        return {
            "requests_sent": req,
            "matches": rows,
            "rate_limited_429": s429,
            "ratio_403": (s403 / max(rows, 1)),
            "ratio_timeout": (tmo / max(req, 1) if req else float(tmo)),
        }

    def _cancel_pending(self, futs: dict) -> None:
        for fut in list(futs.keys()):
            fut.cancel()

    def _flush_discovery_telemetry(self, rows: list[dict]) -> None:
        if not rows:
            return
        out = self.cache / "discovery_telemetry.jsonl"
        with out.open("a", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _run_parallel_queue(
        self,
        hosts: list[str],
        worker_count: int,
        submit_fn,
        on_result_fn,
        *,
        progress_label: str,
        source_running: str,
        ffuf_mode: str,
        dirsearch_mode: str,
    ) -> int:
        global SHUTTING_DOWN
        failures = 0
        ex = ThreadPoolExecutor(max_workers=max(1, worker_count))
        futs: dict = {}
        try:
            for h in hosts:
                if SHUTTING_DOWN:
                    break
                futs[ex.submit(submit_fn, h)] = h
            total = len(hosts)
            for i, fut in enumerate(as_completed(futs), 1):
                if SHUTTING_DOWN:
                    self._cancel_pending(futs)
                    break
                h = futs[fut]
                try:
                    result = fut.result()
                    if on_result_fn(h, result):
                        failures += 1
                except Exception as e:
                    failures += 1
                    self.record_failure(progress_label, h, e)
                self.dashboard.set_context(
                    current_host=h,
                    queue_depth=max(0, total - i),
                    active_jobs=max(0, min(worker_count, total - i)),
                    failed_jobs=failures,
                    dirsearch_mode=dirsearch_mode,
                    ffuf_mode=ffuf_mode,
                    subtask_done=i,
                    subtask_total=max(1, total),
                    source_running=source_running,
                )
                if i % 10 == 0 or i == total:
                    log(f"[*] {source_running} progress {i}/{total} hosts, failures={failures}")
        finally:
            ex.shutdown(wait=not SHUTTING_DOWN, cancel_futures=SHUTTING_DOWN)
        return failures

    def _run_dirsearch_host(self, host: str) -> bool:
        safe = safe_name_for_host(host)
        ds_out = self.dirsearch / f"{safe}.txt"
        ds_log = self.logs / f"{safe}.dirsearch.log"
        if ds_out.exists() and ds_out.stat().st_size > 0:
            return True
        if not self.dirsearch_bin:
            ds_log.write_text("[!] dirsearch missing\n", encoding="utf-8")
            return False
        self._per_host_state(host, "dirsearch", "running")
        r = self.run_tool("dirsearch host", [self.dirsearch_bin, "-u", host, "-w", str(self.dirsearch_wordlist), "-e", "php,html,js,txt,asp,aspx,jsp", "-t", str(max(5, self.config.dirsearch_threads)), "--timeout", str(self.config.dirsearch_timeout), "--delay", str(self.config.dirsearch_delay), "-O", "plain", "-o", str(ds_out)], timeout=600, retries=1, stdout_path=ds_log, stderr_path=ds_log, allow_failure=True)
        ok = (r.returncode == 0)
        self._per_host_state(host, "dirsearch", "completed" if ok else "failed")
        return ok

    def _run_ffuf_host(self, host: str, phase: str, host_meta: dict) -> tuple[bool, dict, str]:
        safe = safe_name_for_host(host)
        host_base = host.rstrip("/")
        is_dirs = phase == "ffuf_dirs"
        out = self.ffuf / (f"{safe}.dirs.csv" if is_dirs else f"{safe}.files.csv")
        logp = self.logs / (f"{safe}.ffuf-dirs.log" if is_dirs else f"{safe}.ffuf-files.log")
        wordlist = self.ffuf_dir_wordlist if is_dirs else self.ffuf_file_wordlist
        if out.exists() and out.stat().st_size > 0:
            return True, self._collect_ffuf_stats(out, logp), "completed"

        req_budget = max(20, self.config.global_request_budget)
        workers = max(1, self.config.ffuf_workers)
        rate = max(5, req_budget // workers)
        threads = max(4, min(20, rate // 2))
        action = "completed"

        if host_meta.get("class") in ("waf_heavy", "static"):
            rate = max(4, rate // 2)
            threads = max(3, threads // 2)
            action = "downgraded"
        if host_meta.get("class") == "static" and not is_dirs:
            return True, {"requests_sent": 0, "matches": 0, "ratio_403": 0.0, "ratio_timeout": 0.0, "rate_limited_429": 0}, "skipped"

        self._per_host_state(host, phase, "running")
        cmd = [self.ffuf_bin, "-noninteractive", "-u", f"{host_base}/FUZZ", "-w", str(wordlist), "-t", str(threads), "-timeout", str(self.config.ffuf_timeout), "-rate", str(rate), "-maxtime-job", str(self.config.ffuf_maxtime_job), "-mc", "200,204,301,302,307,401,403", "-of", "csv", "-o", str(out)]
        if self.config.ffuf_delay:
            cmd.extend(["-p", str(self.config.ffuf_delay)])
        r = self.run_tool(f"{phase} host", cmd, timeout=600, retries=1, stdout_path=logp, stderr_path=logp, allow_failure=True, stdin_tty=False)
        stats = self._collect_ffuf_stats(out, logp)
        if (stats.get("ratio_403", 0.0) >= self.config.stop_on_403_ratio) or (stats.get("ratio_timeout", 0.0) > 0.5):
            action = "downgraded"
        ok = (r.returncode == 0)
        self._per_host_state(host, phase, "completed" if ok else "failed")
        return ok, stats, action

    def normalize_dirsearch_reports(self):
        out = []
        for p in sorted(self.dirsearch.glob("*.txt")):
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                m = _DIRSEARCH_RX_1.search(line) or _DIRSEARCH_RX_2.search(line)
                if not m:
                    continue
                out.append({"source_file": p.name, "url": normalize_url_for_output(m.group("url")), "status": m.group("status"), "raw": line})
        self.write_json(self.intel / "dirsearch_normalized.json", {"items": out})

    def stage_discovery(self):
        global SHUTTING_DOWN
        if self.is_done("discovery"):
            return
        live_hosts = [x.strip() for x in (self.workdir / "live_hosts.txt").read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
        if not live_hosts:
            self.normalize_dirsearch_reports()
            self.record_stage_status("discovery", "skipped", "no live hosts available")
            self.mark_done("discovery")
            return

        t0 = time.perf_counter()
        host_meta = {h: self.classify_host(h) for h in live_hosts}
        telemetry_rows: list[dict] = []

        if SHUTTING_DOWN:
            self.record_stage_status("discovery", "interrupted", "shutdown requested before discovery queues")
            return

        def on_dirsearch_result(h: str, ok: bool) -> bool:
            return not ok

        failed_dir = self._run_parallel_queue(
            live_hosts,
            self.config.dirsearch_workers,
            self._run_dirsearch_host,
            on_dirsearch_result,
            progress_label="discovery_dirsearch",
            source_running="discovery:dirsearch",
            ffuf_mode="pending",
            dirsearch_mode="dirsearch",
        )

        if SHUTTING_DOWN:
            self.record_stage_status("discovery", "interrupted", "shutdown requested before ffuf_dirs")
            self._flush_discovery_telemetry(telemetry_rows)
            return

        dir_hosts = [h for h in live_hosts if host_meta[h].get("run_dirs", True)]
        ffuf_dirs_useful: list[str] = []

        def run_ffuf_dirs(h: str):
            return self._run_ffuf_host(h, "ffuf_dirs", host_meta[h])

        def on_ffuf_dirs_result(h: str, result) -> bool:
            ok, stats, action = result
            if stats.get("matches", 0) > 0 and action != "skipped":
                ffuf_dirs_useful.append(h)
            telemetry_rows.append({"host": h, "phase": "ffuf_dirs", **stats, "final_state": action if ok else "failed"})
            return not ok

        failed_dirs = self._run_parallel_queue(
            dir_hosts,
            self.config.ffuf_workers,
            run_ffuf_dirs,
            on_ffuf_dirs_result,
            progress_label="discovery_ffuf_dirs",
            source_running="discovery:ffuf_dirs",
            ffuf_mode="dirs",
            dirsearch_mode="complete",
        )

        if SHUTTING_DOWN:
            self.record_stage_status("discovery", "interrupted", "shutdown requested before ffuf_files")
            self._flush_discovery_telemetry(telemetry_rows)
            return

        def run_ffuf_files(h: str):
            return self._run_ffuf_host(h, "ffuf_files", host_meta[h])

        def on_ffuf_files_result(h: str, result) -> bool:
            ok, stats, action = result
            telemetry_rows.append({"host": h, "phase": "ffuf_files", **stats, "final_state": action if ok else "failed"})
            return not ok

        failed_files = self._run_parallel_queue(
            ffuf_dirs_useful,
            self.config.ffuf_workers,
            run_ffuf_files,
            on_ffuf_files_result,
            progress_label="discovery_ffuf_files",
            source_running="discovery:ffuf_files",
            ffuf_mode="files",
            dirsearch_mode="complete",
        )

        self._flush_discovery_telemetry(telemetry_rows)
        self.normalize_dirsearch_reports()
        self.record_stage_status("discovery_dirsearch", "partial" if failed_dir else "completed", f"hosts={len(live_hosts)} failures={failed_dir}")
        self.record_stage_status("discovery_ffuf_dirs", "partial" if failed_dirs else "completed", f"hosts={len(dir_hosts)} failures={failed_dirs}")
        self.record_stage_status("discovery_ffuf_files", "partial" if failed_files else "completed", f"hosts={len(ffuf_dirs_useful)} failures={failed_files}")
        total_failed = failed_dir + failed_dirs + failed_files
        overall = "partial" if total_failed else "completed"
        self.record_stage_status("discovery", overall, "central scheduler discovery complete", metrics={"hosts": len(live_hosts), "dir_hosts": len(dir_hosts), "files_hosts": len(ffuf_dirs_useful), "failed": total_failed}, duration_seconds=(time.perf_counter() - t0))
        self.mark_done("discovery_dirsearch")
        self.mark_done("discovery_ffuf_dirs")
        self.mark_done("discovery_ffuf_files")
        self.mark_done("discovery")


    def filter_false_positives(self, urls: list[str]) -> list[str]:
        out = []
        for u in urls:
            if not u:
                continue
            if any(p.search(u) for p in _FP_PATTERNS):
                continue
            out.append(u)
        return sorted(set(out))

    def stage_urls(self):
        if self.is_done("urls"):
            return
        katana_urls = self.urls / "katana_urls.txt"
        gau_urls = self.urls / "gau_urls.txt"
        gospider_urls = self.urls / "gospider_urls.txt"
        hakrawler_urls = self.urls / "hakrawler_urls.txt"
        urls_all = self.urls / "urls_all.txt"
        urls_params = self.urls / "urls_params.txt"
        self.touch_files(katana_urls, gau_urls, gospider_urls, hakrawler_urls, urls_all, urls_params)
        live_hosts = self.workdir / "live_hosts.txt"
        if self.katana_bin and live_hosts.exists() and live_hosts.stat().st_size > 0:
            self.run_tool("katana", [self.katana_bin, "-list", str(live_hosts), "-silent", "-nc", "-kf", "all", "-c", str(max(1, self.config.url_workers)), "-d", str(self.config.katana_depth)] + (["-jc"] if self.config.katana_js_crawl else []) + ["-o", str(katana_urls)], timeout=self.config.katana_timeout, allow_failure=True)
        if self.skip_gau:
            log("[*] gau skipped by config")
        elif self.gau_bin:
            self.run_tool("gau", [self.gau_bin, "--subs", self.target, "--blacklist", self.config.gau_blacklist, "--retries", "2", "--timeout", "15"], timeout=self.config.gau_timeout, stdout_path=gau_urls, stderr_path=self.logs / "gau.stderr.log", allow_failure=True)
        if self.gospider_bin and live_hosts.exists() and live_hosts.stat().st_size > 0:
            self.run_tool("gospider", [self.gospider_bin, "-S", str(live_hosts), "-o", str(self.urls / "gospider_out"), "-t", str(max(1, self.config.url_workers)), "-c", "10", "--no-redirect", "--quiet"], timeout=self.config.gospider_timeout, allow_failure=True, stdout_path=gospider_urls, stderr_path=self.logs / "gospider.stderr.log")
        if self.hakrawler_bin and live_hosts.exists() and live_hosts.stat().st_size > 0:
            hk_input_file = self.urls / "hakrawler_input.txt"
            shutil.copy2(str(live_hosts), str(hk_input_file))
            self.run_tool(
                "hakrawler",
                [
                    self.hakrawler_bin,
                    "-d", "3",
                    "-t", str(self.config.url_workers),
                    "-subs",
                    "-url", str(hk_input_file),
                ],
                timeout=self.config.hakrawler_timeout,
                stdout_path=hakrawler_urls,
                stderr_path=self.logs / "hakrawler.stderr.log",
                allow_failure=True,
            )
            hk_input_file.unlink(missing_ok=True)
        merged_raw = sorted({x.strip() for x in (katana_urls.read_text(encoding="utf-8", errors="ignore") + "\n" + gau_urls.read_text(encoding="utf-8", errors="ignore") + "\n" + gospider_urls.read_text(encoding="utf-8", errors="ignore") + "\n" + hakrawler_urls.read_text(encoding="utf-8", errors="ignore")).splitlines() if x.strip()})
        merged = self.filter_false_positives(merged_raw)
        urls_all.write_text("\n".join(merged) + ("\n" if merged else ""), encoding="utf-8")
        params = sorted({u for u in merged if re.search(r"\?.+=", u)})
        urls_params.write_text("\n".join(params) + ("\n" if params else ""), encoding="utf-8")
        self.build_params_ranked(params)
        self.record_stage_status("urls", "completed", "katana/gau url collection and param ranking generated")
        self.mark_done("urls")

    def build_params_ranked(self, urls_with_params: list[str]):
        juicy = {"id","ids","uid","user","user_id","account","acct","email","phone","token","access_token","refresh_token","auth","jwt","session","sid","key","api_key","redirect","return","returnurl","next","callback","url","dest","destination","continue","file","path","download","doc","document","template","view","q","s","search","query","filter","sort","order","page","limit","offset","cursor","from","to","start","end","lang","locale","debug","test"}
        cnt: dict[str, int] = {}
        examples: dict[str, list[str]] = {}
        for u in urls_with_params:
            try:
                qs = urllib.parse.parse_qsl(urllib.parse.urlsplit(u).query, keep_blank_values=True)
            except Exception:
                continue
            for k, _ in qs:
                k = k.strip()
                if not k:
                    continue
                cnt[k] = cnt.get(k, 0) + 1
                examples.setdefault(k, [])
                if len(examples[k]) < 3:
                    examples[k].append(u)
        out_md = self.intel / "params_ranked.md"
        out_json = self.intel / "params_ranked.json"
        if not cnt:
            out_md.write_text("# Parameter Ranking (Readable)\n\n_No param URLs found._\n", encoding="utf-8")
            self.write_json(out_json, {"total_unique_params": 0, "top": []})
            return
        ranked = sorted(((n + (50 if k.lower() in juicy else 0), k, n, k.lower() in juicy) for k, n in cnt.items()), reverse=True)
        md = []
        md.append("# Parameter Ranking (Readable)\n\n")
        md.append(f"- Total unique params: **{len(cnt)}**\n")
        md.append(f"- Juicy/security-relevant params: **{sum(1 for k in cnt if k.lower() in juicy)}**\n\n")
        md.append("Legend: ✅ = security-relevant keyword match\n\n")
        for idx, (_, k, n, isj) in enumerate(ranked, 1):
            md.append(f"## {idx}. `{esc_md_pipe(k)}` {'✅' if isj else ''}\n")
            md.append(f"- Count: **{n}**\n")
            exs = examples.get(k, [])
            if exs:
                md.append("- Examples:\n")
                for ex in exs:
                    ex = ex if len(ex) <= 180 else (ex[:177] + "...")
                    md.append(f"  - `{esc_md_pipe(ex)}`\n")
            md.append("\n")
        out_md.write_text("".join(md), encoding="utf-8")
        self.write_json(out_json, {"total_unique_params": len(cnt), "top": [{"param": k, "count": n, "juicy": isj} for _, k, n, isj in ranked]})

    def stage_tech(self):
        if self.is_done("tech"):
            return
        jpath = self.workdir / "httpx_results.json"
        out_md = self.intel / "tech_summary.md"
        out_json = self.intel / "tech_summary.json"
        if not jpath.exists() or jpath.stat().st_size == 0:
            out_md.write_text("# Tech Summary\n\n_No httpx_results.json found._\n", encoding="utf-8")
            self.write_json(out_json, {"error": "no httpx json"})
            self.record_stage_status("tech", "completed", "tech correlation generated from httpx json")
            self.mark_done("tech")
            return
        tech_cnt, ws_cnt, st_cnt = {}, {}, {}
        for line in jpath.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            for t in o.get("tech") or []:
                tech_cnt[str(t)] = tech_cnt.get(str(t), 0) + 1
            ws = o.get("webserver")
            if ws:
                ws_cnt[str(ws)] = ws_cnt.get(str(ws), 0) + 1
            sc = o.get("status_code")
            if sc is not None:
                st_cnt[str(sc)] = st_cnt.get(str(sc), 0) + 1
        def top(d: dict[str, int], n: int):
            return sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]
        md = ["# Tech Summary (from httpx)\n\n", "## Top Technologies\n\n| Tech | Count |\n|---|---:|\n"]
        md += [f"| {k} | {v} |\n" for k, v in top(tech_cnt, 30)]
        md += ["\n## Webservers\n\n| Webserver | Count |\n|---|---:|\n"]
        md += [f"| {k} | {v} |\n" for k, v in top(ws_cnt, 20)]
        md += ["\n## Status Codes\n\n| Status | Count |\n|---|---:|\n"]
        md += [f"| {k} | {v} |\n" for k, v in top(st_cnt, 20)]
        out_md.write_text("".join(md), encoding="utf-8")
        self.write_json(out_json, {"tech_top": top(tech_cnt, 100), "webserver_top": top(ws_cnt, 100), "status_top": top(st_cnt, 100)})
        self.record_stage_status("tech", "completed", "tech correlation generated from httpx json")
        self.mark_done("tech")

    def stage_tech_host_mapping(self):
        if self.is_done("tech_host_mapping"):
            return
        httpx_json = self.workdir / "httpx_results.json"
        tech_to_hosts: dict[str, set[str]] = {}
        ws_to_hosts: dict[str, set[str]] = {}
        host_rows: list[dict] = []
        if httpx_json.exists():
            for line in httpx_json.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                host = (o.get("url") or o.get("input") or "").strip()
                if not host:
                    continue
                techs = sorted(set(str(t) for t in (o.get("tech") or []) if str(t).strip()))
                ws = str(o.get("webserver") or "").strip()
                sc = o.get("status_code")
                for t in techs:
                    tech_to_hosts.setdefault(t, set()).add(host)
                if ws:
                    ws_to_hosts.setdefault(ws, set()).add(host)
                host_rows.append({"host": host, "status_code": sc, "webserver": ws, "tech": techs})
        (self.intel / "tech_to_hosts.json").write_text(json.dumps({k: sorted(v) for k, v in sorted(tech_to_hosts.items(), key=lambda x: (-len(x[1]), x[0].lower()))}, indent=2), encoding="utf-8")
        (self.intel / "webserver_to_hosts.json").write_text(json.dumps({k: sorted(v) for k, v in sorted(ws_to_hosts.items(), key=lambda x: (-len(x[1]), x[0].lower()))}, indent=2), encoding="utf-8")
        tech_md = ["# Technology → Hosts\n\n"]
        for tech, hosts in sorted(tech_to_hosts.items(), key=lambda x: (-len(x[1]), x[0].lower())):
            tech_md.append(f"## {tech} ({len(hosts)})\n")
            for h in sorted(hosts):
                tech_md.append(f"- {h}\n")
            tech_md.append("\n")
        (self.intel / "tech_to_hosts.md").write_text("".join(tech_md), encoding="utf-8")
        ws_md = ["# Webserver → Hosts\n\n"]
        for ws, hosts in sorted(ws_to_hosts.items(), key=lambda x: (-len(x[1]), x[0].lower())):
            ws_md.append(f"## {ws} ({len(hosts)})\n")
            for h in sorted(hosts):
                ws_md.append(f"- {h}\n")
            ws_md.append("\n")
        (self.intel / "webserver_to_hosts.md").write_text("".join(ws_md), encoding="utf-8")
        legacy_markers = ("nginx/", "apache/", "iis/", "microsoft-iis/", "php/", "jquery:", "prototype")
        legacy = []
        for row in host_rows:
            blob = " ".join([(row.get("webserver") or "").lower()] + [t.lower() for t in row.get("tech") or []])
            if any(m in blob for m in legacy_markers):
                legacy.append(row)
        legacy_md = ["# Hosts with Versioned/Legacy-Looking Tech\n\n"]
        if not legacy:
            legacy_md.append("_No obvious versioned/legacy signatures found._\n")
        else:
            for row in sorted(legacy, key=lambda x: x["host"]):
                legacy_md.append(f"- {row['host']} | webserver={row.get('webserver') or "-"} | tech={', '.join(row.get('tech') or [])}\n")
        (self.intel / "hosts_with_legacy_versions.md").write_text("".join(legacy_md), encoding="utf-8")
        self.write_json(self.intel / "hosts_with_legacy_versions.json", {"count": len(legacy), "hosts": sorted([r["host"] for r in legacy])})
        self.record_stage_status("tech_host_mapping", "completed", "generated tech/webserver to host mapping")
        self.mark_done("tech_host_mapping")

    def render_nuclei_jsonl_text(self, src: Path, dst: Path) -> int:
        lines = []
        for line in src.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            info = obj.get("info") or {}
            sev = str(info.get("severity") or "unknown").upper()
            name = str(info.get("name") or obj.get("template-id") or "finding")
            matched = str(obj.get("matched-at") or obj.get("host") or obj.get("url") or "")
            lines.append(f"[{sev}] {name} :: {matched}")
        dst.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return len(lines)

    def stage_nuclei_phase1(self):
        if self.is_done("nuclei_phase1"):
            return
        txt = self.workdir / "nuclei_phase1.txt"
        js = self.workdir / "nuclei_phase1.jsonl"
        self.touch_files(txt, js)
        live_hosts = self.workdir / "live_hosts.txt"
        scanned = sum(1 for x in live_hosts.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()) if live_hosts.exists() else 0
        self.dashboard.set_context(nuclei_hosts_scanned=scanned)
        sev = self.nuclei_severity or "high,critical"
        tags = self.nuclei_tags or "cves,misconfig,login,token-spray"
        self.dashboard.set_context(nuclei_severity=sev, nuclei_tags=tags, source_running="nuclei phase1")
        if self.skip_nuclei:
            self.record_stage_status("nuclei_phase1", "skipped", "skip-nuclei enabled")
        elif self.nuclei_bin and live_hosts.exists() and live_hosts.stat().st_size > 0:
            self.run_tool("nuclei phase1 jsonl", [self.nuclei_bin, "-l", str(live_hosts), "-severity", sev, "-tags", tags, "-silent", "-rl", str(self.config.nuclei_rate_limit), "-c", str(self.config.nuclei_concurrency), "-max-host-error", str(self.config.nuclei_max_host_error), "-timeout", str(self.config.nuclei_timeout), "-retries", str(self.config.nuclei_retries), "-jsonl", "-o", str(js)], timeout=900, allow_failure=True)
            self.render_nuclei_jsonl_text(js, txt)
            self.record_stage_status("nuclei_phase1", "completed", "phase1 nuclei scan attempted")
            self.add_finding("nuclei_phase1", "INFO", self.target, "Nuclei phase1 completed", evidence="See nuclei_readable.md for details", confidence=50, tags=["nuclei"])
        else:
            self.record_stage_status("nuclei_phase1", "skipped", "nuclei missing or no live hosts")
        self.mark_done("nuclei_phase1")


    def stage_nuclei_phase2(self):
        if self.is_done("nuclei_phase2"):
            return
        txt = self.workdir / "nuclei_phase2.txt"
        js = self.workdir / "nuclei_phase2.jsonl"
        targets_file = self.workdir / "nuclei_phase2_targets.txt"
        self.touch_files(txt, js, targets_file)
        if self.skip_nuclei:
            self.record_stage_status("nuclei_phase2", "skipped", "skip-nuclei enabled")
            self.mark_done("nuclei_phase2")
            return
        ranked_json = self.intel / "endpoints_ranked.json"
        if not ranked_json.exists():
            self.record_stage_status("nuclei_phase2", "skipped", "endpoints_ranked.json missing")
            self.mark_done("nuclei_phase2")
            return
        try:
            ranked = json.loads(ranked_json.read_text(encoding="utf-8", errors="ignore"))
        except Exception as e:
            self.record_failure("nuclei_phase2", "ranked_read", e)
            self.record_stage_status("nuclei_phase2", "skipped", "failed to parse endpoints_ranked.json")
            self.mark_done("nuclei_phase2")
            return
        tops = []
        for item in (ranked or []):
            if not isinstance(item, dict):
                continue
            u = str(item.get("url") or "").strip()
            if u:
                tops.append(u)
            if len(tops) >= 50:
                break
        targets_file.write_text("\n".join(tops) + ("\n" if tops else ""), encoding="utf-8")
        self.dashboard.set_context(nuclei_hosts_scanned=len(tops))
        sev = "medium,high,critical"
        tags = "sqli,xss,ssrf,lfi,idor,redirect,exposure"
        self.dashboard.set_context(nuclei_severity=sev, nuclei_tags=tags, source_running="nuclei phase2")
        if not tops:
            self.record_stage_status("nuclei_phase2", "skipped", "no ranked endpoints for phase2")
            self.mark_done("nuclei_phase2")
            return
        if self.nuclei_bin and targets_file.exists() and targets_file.stat().st_size > 0:
            self.run_tool("nuclei phase2 jsonl", [self.nuclei_bin, "-l", str(targets_file), "-severity", sev, "-tags", tags, "-silent", "-rl", str(self.config.nuclei_rate_limit), "-c", str(self.config.nuclei_concurrency), "-max-host-error", str(self.config.nuclei_max_host_error), "-timeout", str(self.config.nuclei_timeout), "-retries", str(self.config.nuclei_retries), "-jsonl", "-o", str(js)], timeout=900, allow_failure=True)
            self.render_nuclei_jsonl_text(js, txt)
            self.record_stage_status("nuclei_phase2", "completed", f"phase2 nuclei scan attempted on {len(tops)} endpoints")
            self.add_finding("nuclei_phase2", "INFO", self.target, "Nuclei phase2 completed", evidence=f"endpoints_tested={len(tops)}", confidence=50, tags=["nuclei"])
        else:
            self.record_stage_status("nuclei_phase2", "skipped", "nuclei missing or no phase2 targets")
        self.mark_done("nuclei_phase2")



    def _build_secrets_report(self, downloaded: int, attempted: int, quick_hits_count: int, buckets_count: int) -> tuple[Path, Path]:
        intel = self.intel
        quick_hits_file = intel / "secrets_quick_hits.txt"
        buckets_file = intel / "secrets_s3_buckets.txt"
        truffle_out = intel / "secrets_trufflehog.jsonl"
        gitleaks_out = intel / "secrets_gitleaks.json"
        sf_out = intel / "secrets_secretfinder.txt"
        md_out = intel / "secrets_findings.md"
        json_out = intel / "secrets_findings.json"

        aws_keys: list[dict] = []
        jwt_tokens: list[dict] = []
        api_tokens: list[dict] = []
        generic_secrets: list[dict] = []
        truffle_rows: list[dict] = []
        gitleaks_rows: list[dict] = []
        sf_rows: list[dict] = []
        buckets_rows: list[dict] = []

        seen = {
            "aws": set(),
            "jwt": set(),
            "api": set(),
            "gen": set(),
            "truf": set(),
            "gl": set(),
            "sf": set(),
            "bucket": set(),
        }

        if quick_hits_file.exists():
            for ln in quick_hits_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                m = re.match(r"^(.*?):(\d+):\s*(.*)$", ln)
                if not m:
                    continue
                src = f"{m.group(1)}:{m.group(2)}"
                content = m.group(3)
                for x in _RX_AWS_KEY.findall(content):
                    if x not in seen["aws"]:
                        seen["aws"].add(x)
                        aws_keys.append({"value": x, "source": src})
                for x in _RX_JWT.findall(content):
                    if x not in seen["jwt"]:
                        seen["jwt"].add(x)
                        jwt_tokens.append({"value": x[:80] + ("…" if len(x) > 80 else ""), "source": src})
                for rx in (_RX_API_KEY, _RX_BEARER):
                    for mm in rx.finditer(content):
                        val = (mm.group(1) if mm.lastindex else mm.group(0))
                        if val not in seen["api"]:
                            seen["api"].add(val)
                            api_tokens.append({"value": val[:80] + ("…" if len(val) > 80 else ""), "source": src})
                for mm in _RX_GENERIC_SECRET.finditer(content):
                    val = (mm.group(1) if mm.lastindex else mm.group(0))
                    if val not in seen["gen"]:
                        seen["gen"].add(val)
                        generic_secrets.append({"value": val[:80] + ("…" if len(val) > 80 else ""), "source": src})

        if truffle_out.exists():
            for ln in truffle_out.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    o = json.loads(ln)
                except Exception:
                    continue
                det = str(o.get("DetectorName") or "unknown")
                raw = str(o.get("Raw") or "")
                filep = str((((o.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}).get("file") or "")
                key = (det, raw, filep)
                if key in seen["truf"]:
                    continue
                seen["truf"].add(key)
                truffle_rows.append({"detector": det, "value": raw[:80] + ("…" if len(raw) > 80 else ""), "file": filep})

        if gitleaks_out.exists():
            try:
                arr = json.loads(gitleaks_out.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(arr, dict):
                    arr = arr.get("findings") or []
            except Exception:
                arr = []
            for o in (arr or []):
                rule = str(o.get("RuleID") or "unknown")
                sec = str(o.get("Secret") or "")
                filep = str(o.get("File") or "")
                line = o.get("Line")
                key = (rule, sec, filep, line)
                if key in seen["gl"]:
                    continue
                seen["gl"].add(key)
                gitleaks_rows.append({"rule": rule, "secret": sec[:80] + ("…" if len(sec) > 80 else ""), "file_line": f"{filep}:{line}" if line else filep})

        sf_raw = ""
        if sf_out.exists():
            sf_raw = sf_out.read_text(encoding="utf-8", errors="ignore")
            if len(sf_raw) > 5000:
                sf_raw = sf_raw[:5000]
            sf_rows = [{"text": sf_raw}] if sf_raw.strip() else []

        if buckets_file.exists():
            for b in [x.strip() for x in buckets_file.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]:
                if b not in seen["bucket"]:
                    seen["bucket"].add(b)
                    buckets_rows.append({"name": b})

        report = {
            "generated": now_utc_iso(),
            "downloaded": downloaded,
            "attempted": attempted,
            "quick_hits": quick_hits_count,
            "buckets": buckets_count,
            "aws_keys": aws_keys,
            "jwts": jwt_tokens,
            "api_keys": api_tokens,
            "generic_secrets": generic_secrets,
            "trufflehog": truffle_rows,
            "gitleaks": gitleaks_rows,
            "secretfinder": sf_rows,
            "s3_buckets": [b.get("name","") for b in buckets_rows],
        }
        self.write_json(json_out, report)

        md = []
        md.append(f"# Secrets Findings — {self.target}\n\n")
        md.append(f"Generated: {now_utc_iso()} | JS files: {downloaded}/{attempted} | Quick hits: {quick_hits_count} | Buckets: {buckets_count}\n\n")

        def table_section(title: str, rows: list[dict], cols: list[tuple[str, str]]):
            md.append(f"## {title} ({len(rows)})\n")
            if not rows:
                md.append("_None_\n\n")
                return
            md.append("| " + " | ".join(h for h, _ in cols) + " |\n")
            md.append("|" + "|".join(["---"] * len(cols)) + "|\n")
            for r in rows:
                md.append("| " + " | ".join(esc_md_pipe(str(r.get(k, ""))) for _, k in cols) + " |\n")
            md.append("\n")

        table_section("AWS Keys", aws_keys, [("Value", "value"), ("Source", "source")])
        table_section("JWT Tokens", jwt_tokens, [("Value", "value"), ("Source", "source")])
        table_section("API Keys / Tokens", api_tokens, [("Value", "value"), ("Source", "source")])
        table_section("Generic Secrets", generic_secrets, [("Value", "value"), ("Source", "source")])
        table_section("TruffleHog Findings", truffle_rows, [("Detector", "detector"), ("Value (truncated)", "value"), ("File", "file")])
        table_section("Gitleaks Findings", gitleaks_rows, [("Rule", "rule"), ("Secret (truncated)", "secret"), ("File:Line", "file_line")])

        md.append(f"## SecretFinder Findings ({len(sf_rows)})\n")
        if sf_rows:
            for r in sf_rows[:500]:
                md.append(f"- {esc_md_pipe(r['text'])}\n")
        else:
            md.append("_None_\n")
        md.append("\n")

        md.append(f"## S3 Buckets ({len(buckets_rows)})\n")
        if buckets_rows:
            for b in buckets_rows:
                md.append(f"- {esc_md_pipe(b['name'])}\n")
        else:
            md.append("_None_\n")
        md.append("\n")
        md_out.write_text("".join(md), encoding="utf-8")
        return md_out, json_out

    def stage_secrets(self):
        if self.is_done("secrets"):
            return
        if self.skip_secrets:
            self.record_stage_status("secrets", "skipped", "skip-secrets enabled")
            self.mark_done("secrets")
            return

        intel = self.intel
        logs = self.logs
        js_urls_file = intel / "secrets_js_urls.txt"
        quick_hits_file = intel / "secrets_quick_hits.txt"
        buckets_file = intel / "secrets_s3_buckets.txt"
        truffle_out = intel / "secrets_trufflehog.jsonl"
        gitleaks_out = intel / "secrets_gitleaks.json"
        sf_out = intel / "secrets_secretfinder.txt"
        s3_out = intel / "secrets_s3scanner.txt"
        summary_out = intel / "secrets_summary.json"

        urls_all = self.urls / "urls_all.txt"
        live_hosts = self.workdir / "live_hosts.txt"
        js_urls: list[str] = []
        if urls_all.exists():
            for u in urls_all.read_text(encoding="utf-8", errors="ignore").splitlines():
                u = u.strip()
                if u and re.search(r"\.js(\?|#|$)", u, re.I):
                    js_urls.append(u)
        if live_hosts.exists():
            for h in live_hosts.read_text(encoding="utf-8", errors="ignore").splitlines():
                h = h.strip()
                if h and re.search(r"\.js(\?|#|$)", h, re.I):
                    js_urls.append(h)
        seen_paths: set[tuple[str, str, str]] = set()
        deduped: list[str] = []
        for u in js_urls:
            try:
                parsed = urllib.parse.urlsplit(u)
                key = (parsed.scheme, parsed.netloc, parsed.path)
            except Exception:
                key = (u, "", "")
            if key not in seen_paths:
                seen_paths.add(key)
                deduped.append(u)
        js_urls = deduped
        js_urls_file.write_text("\n".join(js_urls) + ("\n" if js_urls else ""), encoding="utf-8")

        findings: list[str] = []
        buckets: set[str] = set()
        tools_ran: list[str] = []
        missing_tools: list[str] = []

        tmp_dir = Path(tempfile.mkdtemp(prefix="rh-secrets-"))
        downloaded = 0
        js_endpoints: set[str] = set()
        try:
            capped_urls = js_urls[: self.config.secrets_js_cap]

            def _dl_one(u: str) -> tuple[str, bool, str]:
                outp = tmp_dir / f"{safe_name_for_host(u)}.js"
                try:
                    ok = _download_js(u, outp, self.config.secrets_timeout)
                    if ok:
                        return (u, True, "")
                    return (u, False, "download failed after UA rotation")
                except Exception as e:
                    return (u, False, str(e))

            if capped_urls:
                with ThreadPoolExecutor(max_workers=min(10, len(capped_urls))) as ex:
                    futs = {ex.submit(_dl_one, u): u for u in capped_urls}
                    for fut in as_completed(futs):
                        if SHUTTING_DOWN:
                            break
                        u = futs[fut]
                        try:
                            _u, ok, err = fut.result()
                            if ok:
                                downloaded += 1
                                time.sleep(self.config.secrets_download_delay)
                            else:
                                append_text_line(self.logs / "secrets_download_failures.log", f"{now_utc_iso()} {u}: {err}")
                        except Exception as e:
                            append_text_line(self.logs / "secrets_download_failures.log", f"{now_utc_iso()} {u}: {e}")

            log(f"[*] secrets: downloaded {downloaded}/{len(js_urls[:self.config.secrets_js_cap])} JS files ({len(js_urls[:self.config.secrets_js_cap]) - downloaded} skipped)")

            seen_values: set[str] = set()
            for fp in sorted(tmp_dir.glob("*.js")):
                try:
                    with fp.open("r", encoding="utf-8", errors="ignore") as f:
                        for i, line in enumerate(f, 1):
                            line_s = line.rstrip("\n")
                            for rx in (_RX_AWS_KEY, _RX_AWS_SECRET, _RX_API_KEY, _RX_BEARER, _RX_GENERIC_SECRET, _RX_JWT):
                                for m in rx.finditer(line_s):
                                    val = m.group(0)[:120]
                                    if val not in seen_values:
                                        seen_values.add(val)
                                        display = line_s[:300] + ("…" if len(line_s) > 300 else "")
                                        findings.append(f"{fp.name}:{i}: {display}")
                                    break
                            for m in _RX_JS_PATH.finditer(line_s):
                                js_endpoints.add(m.group(1))
                            for m in _RX_BUCKET_HOST.finditer(line_s):
                                buckets.add(m.group(1))
                            for m in _RX_BUCKET_URI.finditer(line_s):
                                buckets.add(m.group(1))
                except Exception:
                    continue

            quick_hits_file.write_text("\n".join(findings) + ("\n" if findings else ""), encoding="utf-8")
            buckets_file.write_text("\n".join(sorted(buckets)) + ("\n" if buckets else ""), encoding="utf-8")
            if js_endpoints:
                ep_file = intel / "secrets_js_endpoints.txt"
                ep_file.write_text("\n".join(sorted(js_endpoints)) + "\n", encoding="utf-8")
                log(f"[*] secrets: extracted {len(js_endpoints)} JS endpoint paths → {ep_file}")

            if not js_urls:
                report_md, report_json = self._build_secrets_report(downloaded=0, attempted=0, quick_hits_count=len(findings), buckets_count=len(buckets))
                self.write_json(summary_out, {
                    "js_urls": 0,
                    "downloaded": 0,
                    "quick_hits": len(findings),
                    "buckets": len(buckets),
                    "tools_ran": tools_ran,
                    "missing_tools": [n for n, ok in {
                        "trufflehog": bool(self.trufflehog_bin),
                        "gitleaks": bool(self.gitleaks_bin),
                        "secretfinder": Path(self.secretfinder_py).exists(),
                        "s3scanner": bool(self.s3scanner_bin),
                    }.items() if not ok],
                    "outputs": {"secrets_findings_md": str(report_md), "secrets_findings_json": str(report_json)},
                })
                for pth in (quick_hits_file, truffle_out, gitleaks_out, sf_out, buckets_file):
                    pth.unlink(missing_ok=True)
                self.record_stage_status("secrets", "completed", "no js urls in urls_all")
                self.mark_done("secrets")
                return

            if not SHUTTING_DOWN and self.trufflehog_bin:
                self.run_tool("secrets trufflehog", [self.trufflehog_bin, "filesystem", str(tmp_dir), "--json"], stdout_path=truffle_out, stderr_path=logs / "secrets_trufflehog.log", allow_failure=True)
                tools_ran.append("trufflehog")
            else:
                missing_tools.append("trufflehog")

            if not SHUTTING_DOWN and self.gitleaks_bin:
                self.run_tool("secrets gitleaks", [self.gitleaks_bin, "detect", "--source", str(tmp_dir), "--report-format", "json", "--report-path", str(gitleaks_out)], stdout_path=logs / "secrets_gitleaks.log", stderr_path=logs / "secrets_gitleaks.log", allow_failure=True)
                tools_ran.append("gitleaks")
            else:
                missing_tools.append("gitleaks")

            sf_path = Path(self.secretfinder_py)
            if not SHUTTING_DOWN and sf_path.exists():
                sf_tmp = []
                sf_env = dict(os.environ)
                sf_venv_bin = str(Path.home() / ".local/share/secretfinder/.venv/bin")
                sf_env["PATH"] = f"{sf_venv_bin}:{sf_env.get('PATH','')}"
                py_exec = str(Path.home() / ".local/share/secretfinder/.venv/bin/python")
                if not Path(py_exec).exists():
                    py_exec = "python3"
                for idx, u in enumerate(js_urls[: self.config.secrets_sf_cap], 1):
                    if SHUTTING_DOWN:
                        break
                    tmpo = tmp_dir / f"secretfinder_{idx}.txt"
                    self.run_tool("secrets secretfinder", [py_exec, str(sf_path), "-i", u, "-o", "cli"], stdout_path=tmpo, stderr_path=logs / "secrets_secretfinder.log", allow_failure=True, env=sf_env)
                    if tmpo.exists():
                        txt = tmpo.read_text(encoding="utf-8", errors="ignore")
                        if txt.strip():
                            sf_tmp.append(txt)
                if sf_tmp:
                    sf_out.write_text("\n".join(sf_tmp), encoding="utf-8")
                tools_ran.append("secretfinder")
            else:
                missing_tools.append("secretfinder")

            if buckets and (not SHUTTING_DOWN) and self.s3scanner_bin:
                help_log = logs / "secrets_s3scanner_help.log"
                self.run_tool("secrets s3scanner help", [self.s3scanner_bin, "--help"], stdout_path=help_log, stderr_path=help_log, allow_failure=True)
                help_txt = help_log.read_text(encoding="utf-8", errors="ignore").lower() if help_log.exists() else ""
                if "--bucket-file" in help_txt:
                    self.run_tool("secrets s3scanner", [self.s3scanner_bin, "--bucket-file", str(buckets_file)], stdout_path=s3_out, stderr_path=logs / "secrets_s3scanner.log", allow_failure=True)
                elif "--buckets" in help_txt:
                    self.run_tool("secrets s3scanner", [self.s3scanner_bin, "--buckets", str(buckets_file)], stdout_path=s3_out, stderr_path=logs / "secrets_s3scanner.log", allow_failure=True)
                else:
                    accum = []
                    for b in sorted(buckets):
                        tmpb = tmp_dir / f"s3_{safe_name_for_host(b)}.txt"
                        self.run_tool("secrets s3scanner bucket", [self.s3scanner_bin, b], stdout_path=tmpb, stderr_path=logs / "secrets_s3scanner.log", allow_failure=True)
                        if tmpb.exists():
                            txt = tmpb.read_text(encoding="utf-8", errors="ignore")
                            if txt.strip():
                                accum.append(txt)
                    if accum:
                        s3_out.write_text("\n".join(accum), encoding="utf-8")
                tools_ran.append("s3scanner")
            elif not self.s3scanner_bin:
                missing_tools.append("s3scanner")

            report_md, report_json = self._build_secrets_report(downloaded=downloaded, attempted=len(capped_urls), quick_hits_count=len(findings), buckets_count=len(buckets))
            self.write_json(summary_out, {
                "js_urls": len(js_urls),
                "downloaded": downloaded,
                "quick_hits": len(findings),
                "buckets": len(buckets),
                "tools_ran": tools_ran,
                "missing_tools": sorted(set(missing_tools)),
                "outputs": {
                    "js_urls": str(js_urls_file),
                    "s3scanner": str(s3_out) if s3_out.exists() else "",
                    "secrets_findings_md": str(report_md),
                    "secrets_findings_json": str(report_json),
                },
            })
            for pth in (quick_hits_file, truffle_out, gitleaks_out, sf_out, buckets_file):
                pth.unlink(missing_ok=True)
            status = "completed" if len(missing_tools) == 0 else "partial"
            self.record_stage_status("secrets", status, f"quick_hits={len(findings)} buckets={len(buckets)} missing_tools={len(set(missing_tools))}")
            for f in findings[:200]:
                self.add_finding("secrets", "HIGH", str(f.get("url") or f.get("file") or ""), "Potential secret exposure", evidence=str(f)[:300], confidence=70, tags=["secrets"])
            self.mark_done("secrets")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def stage_endpoint_ranking(self):
        if self.is_done("endpoint_ranking"):
            return
        urls_all = self.urls / "urls_all.txt"
        dirsearch_json = self.intel / "dirsearch_normalized.json"
        out_md = self.intel / "endpoints_ranked.md"
        out_json = self.intel / "endpoints_ranked.json"
        candidates: dict[str, dict] = {}
        def bump(u: str, add: int, src: str):
            c = candidates.setdefault(u, {"score": 0, "sources": set()})
            c["score"] += add + score_endpoint_url(u)
            c["sources"].add(src)
        if urls_all.exists():
            for u in [x.strip() for x in urls_all.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]:
                c = candidates.setdefault(u, {"score": 0, "sources": set()})
                c["score"] += score_endpoint_url(u)
                c["sources"].add("urls")
        for p in self.ffuf.glob("*.csv"):
            try:
                with p.open("r", encoding="utf-8", errors="ignore", newline="") as f:
                    r = csv.reader(f)
                    next(r, None)
                    for row in r:
                        if len(row) < 3:
                            continue
                        url, sc = row[0], row[2]
                        if not url:
                            continue
                        add = 10 + (20 if sc.startswith("2") else 10 if sc.startswith("3") else 8 if sc in ("401", "403") else 0)
                        bump(url, add, "ffuf")
            except Exception:
                pass
        if dirsearch_json.exists():
            try:
                data = json.loads(dirsearch_json.read_text(encoding="utf-8", errors="ignore"))
                rows = data.get("items", []) if isinstance(data, dict) else data
                for row in rows:
                    u = str(row.get("url") or "").strip()
                    sc = str(row.get("status") or "").strip()
                    if not u or not sc:
                        continue
                    add = 8 + (18 if sc.startswith("2") else 10 if sc.startswith("3") else 0)
                    bump(u, add, "dirsearch")
            except Exception as e:
                self.record_failure("endpoint_ranking", "dirsearch_json", e)
        js_endpoints_file = self.intel / "secrets_js_endpoints.txt"
        if js_endpoints_file.exists():
            base = f"https://{self.target}"
            for raw in js_endpoints_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                path = raw.strip()
                if not path:
                    continue
                if path.startswith("http://") or path.startswith("https://"):
                    u = path
                else:
                    u = urllib.parse.urljoin(base + "/", path)
                bump(u, 15, "js_extract")
        ranked = sorted(((v["score"], u, sorted(v["sources"])) for u, v in candidates.items()), reverse=True)
        md = ["# Endpoint Ranking (triage)\n\n", "| Score | URL | Sources |\n|---:|---|---|\n"]
        for score, u, sources in ranked[:200]:
            md.append(f"| {score} | {esc_md_pipe(u)} | {esc_md_pipe(', '.join(sources))} |\n")
        out_md.write_text("".join(md), encoding="utf-8")
        self.write_json(out_json, [{"score": s, "url": u, "sources": src} for s, u, src in ranked[:2000]])
        self.record_stage_status("endpoint_ranking", "completed", "endpoint ranking generated")
        self.mark_done("endpoint_ranking")

    def _count_lines(self, path: Path) -> int:
        if not path.exists():
            return 0
        return sum(1 for x in path.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip())

    def _parse_subzy_findings(self, path: Path) -> list[dict]:
        if not path.exists() or path.stat().st_size == 0:
            return []
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore").strip()
            idx = raw.find("[")
            if idx == -1:
                return []
            data = json.loads(raw[idx:])
        except Exception:
            return []
        findings = []
        for item in (data if isinstance(data, list) else []):
            if not isinstance(item, dict):
                continue
            if not item.get("vulnerable"):
                continue
            findings.append({
                "host": str(item.get("subdomain") or "").strip(),
                "service": str(item.get("service") or "").strip(),
                "cname": str(item.get("cname") or "").strip(),
                "severity": "HIGH",
            })
        return findings



    def build_summaries(self):
        summary_md = self.workdir / "summary.md"
        summary_json = self.workdir / "summary.json"
        paths = {
            "all_subdomains": self.workdir / "all_subdomains.txt",
            "resolved_subdomains": self.workdir / "resolved_subdomains.txt",
            "live_hosts": self.workdir / "live_hosts.txt",
            "urls_all": self.urls / "urls_all.txt",
            "urls_params": self.urls / "urls_params.txt",
            "nuclei_phase1": self.workdir / "nuclei_phase1.txt",
            "takeover_summary": self.workdir / "takeover_summary.json",
        }
        cors_count = 0
        cors_json = self.intel / "cors_findings.json"
        if cors_json.exists():
            try:
                c = json.loads(cors_json.read_text(encoding="utf-8", errors="ignore"))
                cors_count = len(c) if isinstance(c, list) else 0
            except Exception:
                cors_count = 0
        takeover_count = 0
        if paths["takeover_summary"].exists():
            try:
                t = json.loads(paths["takeover_summary"].read_text(encoding="utf-8", errors="ignore"))
                takeover_count = int(t.get("total") or 0)
            except Exception:
                takeover_count = 0
        md = [
            f"# Recon Summary for {self.target}\n\n",
            f"- Generated: {utc_now_display()}\n",
            f"- Workspace: `{self.workdir}`\n\n",
            "## Counts\n\n",
            f"- Subdomains: **{self._count_lines(paths['all_subdomains'])}**\n",
            f"- Resolved: **{self._count_lines(paths['resolved_subdomains'])}**\n",
            f"- Live hosts: **{self._count_lines(paths['live_hosts'])}**\n",
            f"- URLs (all): **{self._count_lines(paths['urls_all'])}**\n",
            f"- URLs (with params): **{self._count_lines(paths['urls_params'])}**\n",
            f"- Nuclei findings (phase1): **{self._count_lines(paths['nuclei_phase1'])}**\n",
            f"- Takeover findings: **{takeover_count}**\n",
            f"- CORS findings: **{cors_count}**\n",
            f"- XSS findings: **{self._count_json_list(self.cache / 'xss_findings.json')}**\n",
            f"- 403 bypass findings: **{self._count_json_list(self.cache / 'bypass_403_findings.json')}**\n",
            f"- GraphQL introspection open: **{self._count_json_list(self.cache / 'graphql_findings.json')}**\n",
            f"- GitHub dork hits: **{self._count_json_list(self.cache / 'github_dork_findings.json')}**\n",
            f"- Webhook sent ok: **{self._webhook_sent_ok}**\n",
            f"- Webhook failed sends: **{self._webhook_failed_sends}**\n",
            f"- Webhook consecutive failures: **{self._webhook_consecutive_failures}**\n",
            f"- Webhook events dropped: **{self._webhook_events_dropped}**\n\n",
            "## Intelligence Views\n\n",
            f"- Param juice ranking: `{self.intel / 'params_ranked.md'}`\n",
            f"- Tech summary: `{self.intel / 'tech_summary.md'}`\n",
            f"- Tech to hosts: `{self.intel / 'tech_to_hosts.md'}`\n",
            f"- Webserver to hosts: `{self.intel / 'webserver_to_hosts.md'}`\n",
            f"- Legacy/version shortlist: `{self.intel / 'hosts_with_legacy_versions.md'}`\n",
            f"- DNS host→IP map: `{self.intel / 'dns_host_ip_map.json'}`\n",
            f"- Normalized dirsearch data: `{self.intel / 'dirsearch_normalized.json'}`\n",
            f"- Endpoint ranking: `{self.intel / 'endpoints_ranked.md'}`\n",
            f"- Secrets summary: `{self.intel / 'secrets_summary.json'}`\n",
            f"- Secrets findings md: `{self.intel / 'secrets_findings.md'}`\n",
            f"- Secrets findings json: `{self.intel / 'secrets_findings.json'}`\n",
            f"- Stage status log: `{self.workdir / 'stage_status.jsonl'}`\n\n",
            "## Notes\n\n",
            "- Empty nuclei output can be normal if filters are tight (high/critical + limited tags) and there are no matching known issues.\n",
            "- Use endpoint/param rankings to prioritize manual testing.\n",
        ]
        if self._webhook_consecutive_failures >= 3 or self._webhook_failed_sends >= 3:
            md.append("- ⚠️ Webhook health warning: repeated webhook delivery failures detected during this run.\n")
        summary_md.write_text("".join(md), encoding="utf-8")
        out = {
            "workdir": str(self.workdir),
            "subdomains": str(self.workdir / "all_subdomains.txt"),
            "resolved": str(self.workdir / "resolved_subdomains.txt"),
            "live_hosts": str(self.workdir / "live_hosts.txt"),
            "httpx": {"text": str(self.workdir / "httpx_results.txt"), "jsonl": str(self.workdir / "httpx_results.json")},
            "urls": {"katana": str(self.urls / "katana_urls.txt"), "gau": str(self.urls / "gau_urls.txt"), "all": str(self.urls / "urls_all.txt"), "params": str(self.urls / "urls_params.txt")},
            "nuclei": {"phase1_text": str(self.workdir / "nuclei_phase1.txt"), "phase1_jsonl": str(self.workdir / "nuclei_phase1.jsonl"), "phase2_text": str(self.workdir / "nuclei_phase2.txt"), "phase2_jsonl": str(self.workdir / "nuclei_phase2.jsonl")},
            "takeover": {"summary": str(self.workdir / "takeover_summary.json")},
            "intel": {
                "params_ranked_md": str(self.intel / "params_ranked.md"),
                "params_ranked_json": str(self.intel / "params_ranked.json"),
                "tech_summary_md": str(self.intel / "tech_summary.md"),
                "tech_summary_json": str(self.intel / "tech_summary.json"),
                "tech_to_hosts_md": str(self.intel / "tech_to_hosts.md"),
                "tech_to_hosts_json": str(self.intel / "tech_to_hosts.json"),
                "webserver_to_hosts_md": str(self.intel / "webserver_to_hosts.md"),
                "webserver_to_hosts_json": str(self.intel / "webserver_to_hosts.json"),
                "hosts_with_legacy_versions_md": str(self.intel / "hosts_with_legacy_versions.md"),
                "dirsearch_normalized_json": str(self.intel / "dirsearch_normalized.json"),
                "dns_host_ip_map_json": str(self.intel / "dns_host_ip_map.json"),
                "endpoints_ranked_md": str(self.intel / "endpoints_ranked.md"),
                "endpoints_ranked_json": str(self.intel / "endpoints_ranked.json"),
                "secrets_summary": str(self.intel / "secrets_summary.json"),
                "cors_findings_md": str(self.intel / "cors_findings.md"),
                "cors_findings_json": str(self.intel / "cors_findings.json"),
                "secrets_findings_md": str(self.intel / "secrets_findings.md"),
                "secrets_findings_json": str(self.intel / "secrets_findings.json"),
                "portscan_results_json": str(self.workdir / "portscan_results.json"),
                "portscan_hosts_txt": str(self.workdir / "portscan_hosts.txt"),
            },
            "status": {
                "stage_status_jsonl": str(self.workdir / "stage_status.jsonl"),
                "errors_jsonl": str(self.errors_jsonl),
                "webhook_sent_ok": self._webhook_sent_ok,
                "webhook_failed_sends": self._webhook_failed_sends,
                "webhook_consecutive_failures": self._webhook_consecutive_failures,
                "webhook_events_dropped": self._webhook_events_dropped,
                "webhook_circuit_open_until": self._webhook_circuit_open_until,
            },
        }
        summary_json.write_text(json.dumps(out, indent=2), encoding="utf-8")

    def write_run_commands_script(self, original_args: list[str], script_name: str) -> None:
        runfile = self.workdir / "run_commands.sh"
        cmd = shlex.join(original_args)
        content = f"#!/usr/bin/env bash\nset -euo pipefail\n\n# Generated by {script_name}\n# Original invocation:\n# {cmd}\n\npython3 {shlex.quote(script_name)} --resume {shlex.quote(str(self.workdir))} --run\n"
        runfile.write_text(content, encoding="utf-8")
        runfile.chmod(0o755)

    def _count_json_list(self, path: Path) -> int:
        """Return len of JSON list at path, or 0 on any failure."""
        if not path.exists():
            return 0
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            items = data.get("items", data) if isinstance(data, dict) else data
            return len(items) if isinstance(items, list) else 0
        except Exception:
            return 0

    def collect_stats(self) -> dict[str, int]:
        nuclei_findings = self._count_lines(self.workdir / "nuclei_phase1.txt")
        nuclei_findings_phase2 = self._count_lines(self.workdir / "nuclei_phase2.txt")
        takeover_findings = 0
        takeover_summary = self.workdir / "takeover_summary.json"
        if takeover_summary.exists():
            try:
                to = json.loads(takeover_summary.read_text(encoding="utf-8", errors="ignore"))
                takeover_findings = int(to.get("nuclei_findings") or 0) + int(to.get("subzy_findings") or 0)
            except Exception:
                takeover_findings = 0
        cors_findings = 0
        cors_json = self.intel / "cors_findings.json"
        if cors_json.exists():
            try:
                data = json.loads(cors_json.read_text(encoding="utf-8", errors="ignore"))
                cors_findings = len(data) if isinstance(data, list) else 0
            except Exception:
                cors_findings = 0
        subfinder_count = self._count_lines(self.workdir / "subfinder.txt")
        assetfinder_count = self._count_lines(self.workdir / "assetfinder.txt")
        resolved_count = self._count_lines(self.workdir / "resolved_subdomains.txt")
        hosts_401_403 = 0
        buckets = {"2xx": 0, "3xx": 0, "401": 0, "403": 0, "other": 0}

        if self._httpx_cache:
            for o in self._httpx_cache.values():
                sc = int(o.get("status") or 0)
                if sc == 401:
                    buckets["401"] += 1
                    hosts_401_403 += 1
                elif sc == 403:
                    buckets["403"] += 1
                    hosts_401_403 += 1
                elif 200 <= sc < 300:
                    buckets["2xx"] += 1
                elif 300 <= sc < 400:
                    buckets["3xx"] += 1
                else:
                    buckets["other"] += 1
        else:
            jpath = self.workdir / "httpx_results.json"
            if jpath.exists():
                for ln in jpath.read_text(encoding="utf-8", errors="ignore").splitlines():
                    try:
                        o = json.loads(ln)
                    except Exception:
                        continue
                    sc = int(o.get("status_code") or 0)
                    if sc == 401:
                        buckets["401"] += 1
                        hosts_401_403 += 1
                    elif sc == 403:
                        buckets["403"] += 1
                        hosts_401_403 += 1
                    elif 200 <= sc < 300:
                        buckets["2xx"] += 1
                    elif 300 <= sc < 400:
                        buckets["3xx"] += 1
                    else:
                        buckets["other"] += 1

        legacy_hosts = 0
        legacy_json = self.intel / "hosts_with_legacy_versions.json"
        if legacy_json.exists():
            try:
                legacy_hosts = int(json.loads(legacy_json.read_text(encoding="utf-8", errors="ignore")).get("count") or 0)
            except Exception as e:
                log(f"[!] Failed to parse legacy host count: {e}")

        throttled_hosts = 0
        skipped_hosts = 0
        telemetry = self.cache / "discovery_telemetry.jsonl"
        if telemetry.exists():
            for ln in telemetry.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    o = json.loads(ln)
                except Exception:
                    continue
                st = (o.get("final_state") or "").lower()
                if st == "downgraded":
                    throttled_hosts += 1
                if st == "skipped":
                    skipped_hosts += 1

        _sf_count = 0
        _sf_path = self.intel / "secrets_summary.json"
        if _sf_path.exists():
            try:
                _sf_count = int(
                    json.loads(_sf_path.read_text(encoding="utf-8", errors="ignore")).get("quick_hits") or 0
                )
            except Exception as e:
                log(f"[!] Failed to read secrets_summary.json for stats: {e}")

        return {
            "subdomains": self._count_lines(self.workdir / "all_subdomains.txt"),
            "subfinder_count": subfinder_count,
            "assetfinder_count": assetfinder_count,
            "resolved": resolved_count,
            "probed_hosts": sum(buckets.values()),
            "live_hosts": self._count_lines(self.workdir / "live_hosts.txt"),
            "endpoints": self._count_lines(self.urls / "urls_all.txt"),
            "params": self._count_lines(self.urls / "urls_params.txt"),
            "nuclei_findings": nuclei_findings,
            "nuclei_findings_phase1": nuclei_findings,
            "nuclei_findings_phase2": nuclei_findings_phase2,
            "takeover_findings": takeover_findings,
            "cors_findings": cors_findings,
            "hosts_401_403": hosts_401_403,
            "legacy_hosts": legacy_hosts,
            "throttled_hosts": throttled_hosts,
            "skipped_hosts": skipped_hosts,
            "httpx_2xx": buckets["2xx"],
            "httpx_3xx": buckets["3xx"],
            "httpx_401": buckets["401"],
            "httpx_403": buckets["403"],
            "httpx_other": buckets["other"],
            "secrets_findings": _sf_count,
            "xss_findings": self._count_json_list(self.intel / "xss_findings.json"),
            "bypass_403_findings": self._count_json_list(self.intel / "bypass_403_findings.json"),
            "graphql_findings": self._count_json_list(self.intel / "graphql_findings.json"),
            "github_dork_hits": self._count_json_list(self.intel / "github_dork_findings.json"),
        }


    def stage_dns_bruteforce(self) -> None:
        if self.is_done("dns_bruteforce"):
            return
        if self.config.skip_dns_bruteforce or not self.puredns_bin:
            self.record_stage_status("dns_bruteforce", "skipped", "skip-dns-bruteforce or puredns missing")
            self.mark_done("dns_bruteforce")
            return
        wordlist = ensure_dns_wordlist()
        resolvers = ensure_resolvers_list()
        brute_out = self.workdir / "bruteforce_subdomains.txt"
        all_subs = self.workdir / "all_subdomains.txt"
        self.touch_files(brute_out)
        self.run_tool("puredns bruteforce", [self.puredns_bin, "bruteforce", str(wordlist), self.target, "--resolvers", str(resolvers), "--write", str(brute_out), "--quiet"], timeout=self.config.dns_bruteforce_timeout, allow_failure=True)
        existing = set(
            x.strip() for x in all_subs.read_text(encoding="utf-8", errors="ignore").splitlines()
            if x.strip() and not x.strip().startswith("#")
        ) if all_subs.exists() else set()
        new_subs = set(
            x.strip() for x in brute_out.read_text(encoding="utf-8", errors="ignore").splitlines()
            if x.strip() and not x.strip().startswith("#")
        ) if brute_out.exists() else set()
        merged = sorted(existing | new_subs)
        all_subs.write_text("\n".join(merged) + "\n", encoding="utf-8")
        gained = len(new_subs - existing)
        self.record_stage_status("dns_bruteforce", "completed", f"found={len(new_subs)} new={gained} total={len(merged)}")
        self.mark_done("dns_bruteforce")

    def stage_portscan(self) -> None:
        if self.is_done("portscan"):
            return
        if self.config.skip_portscan or not self.naabu_bin:
            self.record_stage_status("portscan", "skipped", "skip-portscan enabled or naabu missing")
            self.mark_done("portscan")
            return
        resolved = self.workdir / "resolved_subdomains.txt"
        out_json = self.workdir / "portscan_results.json"
        out_txt = self.workdir / "portscan_hosts.txt"
        self.touch_files(out_json, out_txt)
        cmd = [self.naabu_bin, "-l", str(resolved), "-rate", str(self.config.naabu_rate), "-json", "-o", str(out_json), "-silent"]
        if self.config.naabu_top_ports:
            cmd += ["-top-ports", self.config.naabu_top_ports]
        else:
            cmd += ["-p", self.config.naabu_ports]
        self.run_tool("naabu portscan", cmd, timeout=self.config.naabu_timeout, allow_failure=True)
        extra_hosts = set()
        if out_json.exists():
            for ln in out_json.read_text(encoding="utf-8", errors="ignore").splitlines():
                try:
                    obj = json.loads(ln.strip())
                except Exception:
                    continue
                ip = str(obj.get("ip") or "").strip()
                port = obj.get("port")
                host = str(obj.get("host") or ip).strip()
                if host and port:
                    scheme = "https" if int(port) in (443, 8443, 9443) else "http"
                    extra_hosts.add(f"{scheme}://{host}:{port}")
        live_hosts = self.workdir / "live_hosts.txt"
        existing = set(
            x.strip() for x in live_hosts.read_text(encoding="utf-8", errors="ignore").splitlines()
            if x.strip()
        ) if live_hosts.exists() else set()
        merged = sorted(existing | extra_hosts)
        live_hosts.write_text("\n".join(merged) + "\n", encoding="utf-8")
        out_txt.write_text("\n".join(sorted(extra_hosts)) + "\n", encoding="utf-8")
        self.record_stage_status("portscan", "completed", f"new_hosts={len(extra_hosts)} merged_total={len(merged)}")
        self.mark_done("portscan")

    def stage_screenshots(self) -> None:
        if self.is_done("screenshots"):
            return
        if self.config.skip_screenshots or not self.gowitness_bin:
            self.record_stage_status("screenshots", "skipped", "skip-screenshots or gowitness missing")
            self.mark_done("screenshots")
            return
        live_hosts = self.workdir / "live_hosts.txt"
        if not (live_hosts.exists() and live_hosts.stat().st_size > 0):
            self.record_stage_status("screenshots", "skipped", "no live hosts")
            self.mark_done("screenshots")
            return
        out_dir = self.intel / "screenshots"
        out_dir.mkdir(parents=True, exist_ok=True)
        # Keep this stage deterministic: clean old artifacts before fresh capture.
        shutil.rmtree(out_dir, ignore_errors=True)
        out_dir.mkdir(parents=True, exist_ok=True)
        db_path = self.cache / "gowitness.sqlite3"
        db_path.unlink(missing_ok=True)
        gw_log = self.logs / "gowitness_screenshots.log"
        self.run_tool(
            "gowitness screenshots",
            [
                self.gowitness_bin,
                "scan", "file",
                "--file", str(live_hosts),
                "--screenshot-path", str(out_dir),
                "--db-uri", f"sqlite://{db_path}",
                "--threads", str(self.config.screenshots_threads),
                "--timeout", str(self.config.screenshots_timeout),
            ],
            timeout=self.config.screenshots_timeout + 60,
            stdout_path=gw_log,
            stderr_path=gw_log,
            allow_failure=True,
        )
        count = (
            len(list(out_dir.rglob("*.png")))
            + len(list(out_dir.rglob("*.jpg")))
            + len(list(out_dir.rglob("*.jpeg")))
        )
        self.record_stage_status("screenshots", "completed", f"screenshots={count} db={db_path}")
        self.mark_done("screenshots")

    def stage_param_discovery(self) -> None:
        if self.is_done("param_discovery"):
            return
        if self.config.skip_param_discovery or not self.arjun_bin:
            self.record_stage_status("param_discovery", "skipped", "skip-param-discovery or arjun missing")
            self.mark_done("param_discovery")
            return
        live_hosts_path = self.workdir / "live_hosts.txt"
        hosts = [x.strip() for x in live_hosts_path.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()] if live_hosts_path.exists() else []
        scored = sorted(hosts, key=lambda h: self.classify_host(h).get("score", 0), reverse=True)
        capped = scored[:self.config.arjun_host_cap]
        out_json = self.cache / "arjun_params.json"
        all_found = {}
        scan_errors = 0
        for host in capped:
            if SHUTTING_DOWN:
                break
            tmp = self.intel / f"arjun_{safe_name_for_host(host)}.json"
            self.run_tool(
                f"arjun {host}",
                [self.arjun_bin, "-u", host, "--output-file", str(tmp), "-t", str(self.config.arjun_threads), "--stable", "-q"],
                timeout=self.config.arjun_timeout,
                allow_failure=True,
            )
            if tmp.exists():
                try:
                    data = json.loads(tmp.read_text(encoding="utf-8", errors="ignore"))
                    params = data.get(host, {}).get("params", [])
                    if params:
                        all_found[host] = params
                except Exception:
                    scan_errors += 1
                tmp.unlink(missing_ok=True)
            else:
                scan_errors += 1
        out_json.write_text(json.dumps(all_found, indent=2), encoding="utf-8")
        total_params = sum(len(v) for v in all_found.values())
        if capped and total_params == 0:
            self.record_stage_status("param_discovery", "warning", f"hosts={len(capped)} params_found=0 errors={scan_errors}")
        else:
            self.record_stage_status("param_discovery", "completed", f"hosts={len(capped)} params_found={total_params} errors={scan_errors}")
        self.mark_done("param_discovery")

    def stage_xss_scan(self) -> None:
        if self.is_done("xss_scan"):
            return
        if self.config.skip_xss or not self.dalfox_bin:
            self.record_stage_status("xss_scan", "skipped", "skip-xss or dalfox missing")
            self.mark_done("xss_scan")
            return
        params_file = self.urls / "urls_params.txt"
        if not (params_file.exists() and params_file.stat().st_size > 0):
            self.record_stage_status("xss_scan", "skipped", "no param URLs available")
            self.mark_done("xss_scan")
            return
        urls = [x.strip() for x in params_file.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()][:self.config.dalfox_url_cap]
        targets_file = self.intel / "dalfox_targets.txt"
        targets_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
        out_json = self.intel / "xss_findings.json"
        result = self.run_tool("dalfox xss scan", [self.dalfox_bin, "file", str(targets_file), "--silence", "--skip-bav", "--worker", str(self.config.dalfox_workers), "--format", "json", "--output", str(out_json)], timeout=self.config.dalfox_timeout, allow_failure=True)
        raw_data: list = []
        if out_json.exists():
            try:
                loaded = json.loads(out_json.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(loaded, list):
                    # Filter out empty objects [{}] which Dalfox v2.12.0 outputs for failed/unreachable targets
                    raw_data = [x for x in loaded if isinstance(x, dict) and x]
            except Exception:
                pass
        data = [x for x in raw_data if self._is_strong_xss_finding(x)]
        discarded = max(0, len(raw_data) - len(data))
        count = len(data)
        if count > 0:
            self.write_json(out_json, data)
        else:
            out_json.unlink(missing_ok=True)

        if result.returncode != 0:
            detail = f"urls_tested={len(urls)} findings={count} discarded={discarded} rc={result.returncode}"
            if count > 0:
                self.record_stage_status("xss_scan", "warning", f"dalfox incomplete; retained stronger findings only ({detail})")
            else:
                self.record_stage_status("xss_scan", "warning", f"dalfox incomplete; discarded partial or reflection-only results ({detail})")
        else:
            self.record_stage_status("xss_scan", "completed", f"urls_tested={len(urls)} findings={count} discarded={discarded}")
        for x in data[:100]:
            tgt = str(x.get("url") or x.get("target") or "") if isinstance(x, dict) else ""
            self.add_finding("xss_scan", "HIGH", tgt, "Potential XSS finding", evidence=str(x)[:300], confidence=75, tags=["xss"])
        if count > 0:
            self._notify(f"XSS findings={count}", status="warning", stage="xss_scan", severity="HIGH")
        self.write_live_findings()
        self.mark_done("xss_scan")

    def _is_strong_xss_finding(self, finding: dict) -> bool:
        if not isinstance(finding, dict) or not finding:
            return False
        finding_type = str(finding.get("type") or "").strip().lower()
        inject_type = str(finding.get("inject_type") or "").strip().lower()
        poc_type = str(finding.get("poc_type") or "").strip().lower()
        msg = " ".join(
            str(finding.get(k) or "").strip().lower()
            for k in ("message_str", "evidence", "message", "detail")
        )

        if "reflected payload" in msg:
            return False
        if finding_type == "r":
            return False
        if inject_type.startswith("injs-none") and poc_type in {"", "plain"}:
            return False

        strong_terms = (
            "triggered",
            "verified",
            "executed",
            "headless",
            "blind",
            "stored",
            "dom",
            "callback",
            "interactsh",
        )
        if any(term in msg for term in strong_terms):
            return True

        if poc_type in {"headless", "gheadless"}:
            return True

        return False

    def stage_bypass_403(self) -> None:
        if self.is_done("bypass_403"):
            return
        if self.config.skip_bypass_403:
            self.record_stage_status("bypass_403", "skipped", "skip-bypass-403 enabled")
            self.mark_done("bypass_403")
            return
        hosts_403 = [h for h, meta in self._httpx_cache.items() if meta.get("status") == 403]
        if not hosts_403:
            self.record_stage_status("bypass_403", "skipped", "no 403 hosts found")
            self.mark_done("bypass_403")
            return
        bypass_headers=[{"X-Original-URL":"/"},{"X-Rewrite-URL":"/"},{"X-Forwarded-For":"127.0.0.1"},{"X-Forwarded-For":"localhost"},{"X-Client-IP":"127.0.0.1"},{"X-Real-IP":"127.0.0.1"},{"X-Custom-IP-Authorization":"127.0.0.1"},{"X-Host":"localhost"},{"Referer":"/admin"}]
        bypass_paths=["/","/%2F","//","/./","/..","/%20","/?anything"]
        findings=[]
        errors = 0
        lock=threading.Lock()
        def _probe(host: str):
            nonlocal errors
            url=host.rstrip("/")
            for hdrs in bypass_headers:
                try:
                    req=urllib.request.Request(url, headers={"User-Agent": _JS_USER_AGENTS[0], **hdrs})
                    with urllib.request.urlopen(req, timeout=max(5, int(self.config.bypass_403_timeout))) as resp:
                        if resp.status < 400:
                            with lock: findings.append({"host":host,"bypass":"header","header":str(hdrs),"status":resp.status})
                            return
                except Exception:
                    errors += 1
            for path in bypass_paths:
                try:
                    parsed=urllib.parse.urlsplit(url)
                    probe_url=urllib.parse.urlunsplit(parsed._replace(path=path))
                    req=urllib.request.Request(probe_url, headers={"User-Agent": _JS_USER_AGENTS[0]})
                    with urllib.request.urlopen(req, timeout=max(5, int(self.config.bypass_403_timeout))) as resp:
                        if resp.status < 400:
                            with lock: findings.append({"host":host,"bypass":"path","path":path,"status":resp.status})
                            return
                except Exception:
                    errors += 1
        with ThreadPoolExecutor(max_workers=min(self.config.bypass_403_workers, len(hosts_403))) as ex:
            futs=[ex.submit(_probe,h) for h in hosts_403]
            stage_deadline_s = max(15, int(self.config.bypass_403_timeout))
            try:
                for fut in as_completed(futs, timeout=stage_deadline_s):
                    if SHUTTING_DOWN: break
                    try: fut.result()
                    except Exception: pass
            except TimeoutError:
                errors += 1
                self.record_stage_status("bypass_403", "warning", f"stage deadline exceeded after {stage_deadline_s}s")
                for f in futs:
                    f.cancel()
        out_json=self.intel / "bypass_403_findings.json"
        self.write_json(out_json, findings)
        if hosts_403 and len(findings) == 0:
            self.record_stage_status("bypass_403", "warning", f"probed={len(hosts_403)} bypassed=0 errors={errors}")
        else:
            self.record_stage_status("bypass_403", "completed", f"probed={len(hosts_403)} bypassed={len(findings)} errors={errors}")
        for f in findings:
            self.add_finding("bypass_403", "HIGH", f.get("host", ""), "403 bypass successful", evidence=str(f), confidence=85, tags=["authz","bypass403"])
        if findings:
            self._notify(f"403 bypass findings={len(findings)}", status="warning", stage="bypass_403", severity="HIGH")
        self.write_live_findings()
        self.mark_done("bypass_403")

    def stage_graphql(self) -> None:
        if self.is_done("graphql"):
            return
        if self.config.skip_graphql:
            self.record_stage_status("graphql", "skipped", "skip-graphql enabled")
            self.mark_done("graphql")
            return
        live_hosts = self.workdir / "live_hosts.txt"
        hosts = [x.strip() for x in live_hosts.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()] if live_hosts.exists() else []
        schema_dir = self.intel / "graphql_schemas"
        schema_dir.mkdir(parents=True, exist_ok=True)
        findings=[]
        attempts = 0
        errors = 0
        q = json.dumps({"query": "{__schema{types{name}}}", "operationName": None, "variables": {}})

        def _scan_host(host: str) -> tuple[dict | None, int, int]:
            local_attempts = 0
            local_errors = 0
            for path in _GRAPHQL_PATHS:
                if SHUTTING_DOWN:
                    break
                url = host.rstrip("/") + path
                for attempt in range(1, 3):
                    local_attempts += 1
                    try:
                        req = urllib.request.Request(url, data=q.encode("utf-8"), headers={"Content-Type":"application/json","User-Agent":_JS_USER_AGENTS[0]})
                        with urllib.request.urlopen(req, timeout=max(5, int(self.config.graphql_timeout))) as resp:
                            body = resp.read().decode("utf-8", errors="ignore")
                            if "__schema" in body or "types" in body:
                                sf = schema_dir / (safe_name_for_host(url)+".json")
                                sf.write_text(body, encoding="utf-8")
                                return ({"url":url,"introspection":True,"schema_file":str(sf)}, local_attempts, local_errors)
                    except Exception:
                        local_errors += 1
                        if attempt == 1:
                            _backoff_sleep(0.35, attempt)
            return (None, local_attempts, local_errors)

        if hosts:
            workers = min(20, len(hosts))
            stage_deadline_s = max(30, int(self.config.graphql_timeout) * min(len(hosts), 10))
            with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
                futs = [ex.submit(_scan_host, h) for h in hosts]
                try:
                    for fut in as_completed(futs, timeout=stage_deadline_s):
                        if SHUTTING_DOWN:
                            break
                        try:
                            item, a, e = fut.result()
                            attempts += a
                            errors += e
                            if item:
                                findings.append(item)
                        except Exception:
                            errors += 1
                except TimeoutError:
                    errors += 1
                    self.record_stage_status("graphql", "warning", f"stage deadline exceeded after {stage_deadline_s}s")
                    for f in futs:
                        f.cancel()
        self.write_json(self.intel / "graphql_findings.json", findings)
        if hosts and attempts > 0 and len(findings) == 0:
            self.record_stage_status("graphql", "warning", f"hosts_checked={len(hosts)} introspection_open=0 attempts={attempts} errors={errors}")
        else:
            self.record_stage_status("graphql", "completed", f"hosts_checked={len(hosts)} introspection_open={len(findings)} attempts={attempts} errors={errors}")
        for g in findings:
            self.add_finding("graphql", "HIGH", g.get("url", ""), "GraphQL introspection enabled", evidence=str(g.get("schema_file") or ""), confidence=90, tags=["graphql"])
        if findings:
            self._notify(f"GraphQL introspection open={len(findings)}", status="warning", stage="graphql", severity="HIGH")
        self.write_live_findings()
        self.mark_done("graphql")

    def stage_vhost_fuzz(self) -> None:
        if self.is_done("vhost_fuzz"):
            return
        if self.config.skip_vhost or not self.ffuf_bin:
            self.record_stage_status("vhost_fuzz", "skipped", "skip-vhost or ffuf missing")
            self.mark_done("vhost_fuzz")
            return
        try:
            main_ip = socket.gethostbyname(self.target)
        except Exception:
            self.record_stage_status("vhost_fuzz", "skipped", "could not resolve target IP")
            self.mark_done("vhost_fuzz")
            return
        wordlist = Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        if not wordlist.exists():
            wordlist = ensure_dns_wordlist()
        out_json = self.cache / "vhost_findings.json"
        out_log = self.logs / "vhost_ffuf.log"

        baseline_size: int | None = None
        try:
            _bogus_req = urllib.request.Request(
                f"http://{main_ip}",
                headers={
                    "Host": f"rh-probe-{random.randint(10000, 99999)}.{self.target}",
                    "User-Agent": _JS_USER_AGENTS[0],
                },
            )
            with urllib.request.urlopen(_bogus_req, timeout=8) as _r:
                baseline_size = len(_r.read())
        except Exception:
            pass

        cmd = [self.ffuf_bin, "-u", f"http://{main_ip}", "-H", f"Host: FUZZ.{self.target}", "-w", str(wordlist), "-t", str(self.config.vhost_threads), "-rate", str(self.config.vhost_rate), "-mc", "200,301,302,401,403", "-of", "json", "-o", str(out_json), "-noninteractive", "-s"]
        if baseline_size is not None:
            cmd += ["-fs", str(baseline_size)]
            log(f"[*] vhost_fuzz: baseline_size={baseline_size}, using -fs filter")

        self.run_tool("ffuf vhost fuzz", cmd, timeout=self.config.vhost_timeout, stdout_path=out_log, stderr_path=out_log, allow_failure=True)
        count = 0
        if out_json.exists():
            try:
                data = json.loads(out_json.read_text(encoding="utf-8", errors="ignore"))
                count = len(data.get("results", []))
            except Exception:
                pass
        self.record_stage_status("vhost_fuzz", "completed", f"vhosts_found={count} target_ip={main_ip}")
        self.mark_done("vhost_fuzz")

    def stage_github_dork(self) -> None:
        if self.is_done("github_dork"):
            return
        if self.config.skip_github_dork:
            self.record_stage_status("github_dork", "skipped", "skip-github-dork enabled")
            self.mark_done("github_dork")
            return
        token = os.environ.get("GITHUB_TOKEN", "").strip()
        if not token:
            self.record_stage_status("github_dork", "skipped", "GITHUB_TOKEN not set")
            self.mark_done("github_dork")
            return
        headers={"Authorization": f"token {token}", "Accept":"application/vnd.github+json", "User-Agent":"reconharvest"}
        findings=[]
        for qt in _GITHUB_DORK_QUERIES:
            if SHUTTING_DOWN:
                break
            q = urllib.parse.quote(qt.format(target=self.target))
            api = f"https://api.github.com/search/code?q={q}&per_page=10"
            try:
                req = urllib.request.Request(api, headers=headers)
                with urllib.request.urlopen(req, timeout=self.config.github_dork_timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    for item in (data.get("items") or []):
                        findings.append({
                            "query": qt.format(target=self.target),
                            "repo": (item.get("repository") or {}).get("full_name"),
                            "file": item.get("name"),
                            "url": item.get("html_url"),
                        })
                time.sleep(1.5)
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    log(f"[!] github_dork: rate-limited (403) on query '{qt}'. Stopping early.")
                    break
                log(f"[!] github_dork: HTTP {e.code} on '{qt}'")
            except Exception as e:
                log(f"[!] github_dork: error on '{qt}': {e}")
        self.write_json(self.intel / "github_dork_findings.json", findings)
        self.record_stage_status("github_dork", "completed", f"queries={len(_GITHUB_DORK_QUERIES)} hits={len(findings)}")
        for f in findings[:200]:
            self.add_finding("github_dork", "MEDIUM", f.get("repo", ""), "GitHub dork hit", evidence=f"{f.get('query','')} -> {f.get('url','')}", confidence=65, tags=["osint","secrets"])
        if findings:
            self._notify(f"GitHub dork hits={len(findings)}", status="warning", stage="github_dork", severity="MEDIUM")
        self.mark_done("github_dork")

    def stage_osint(self) -> None:
        if self.is_done("osint"):
            return
        if not command_exists("dig"):
            log("[!] osint: 'dig' not found — install dnsutils. Skipping OSINT stage.")
            (self.intel / "osint_report.md").write_text(
                f"# OSINT Report — {self.target}\n\n_Skipped: dig not installed._\n",
                encoding="utf-8",
            )
            self.record_stage_status("osint", "skipped", "dig missing — install dnsutils")
            self.mark_done("osint")
            return
        if self.config.skip_osint:
            self.record_stage_status("osint", "skipped", "skip-osint enabled")
            self.mark_done("osint")
            return
        report={"dmarc":None,"spf":None,"dkim_probed":[],"emails":[]}
        try:
            dmarc_cp=subprocess.run(["dig", "+short", "TXT", f"_dmarc.{self.target}"], capture_output=True, text=True, timeout=10)
            report["dmarc"]=dmarc_cp.stdout.strip()
        except Exception:
            report["dmarc"]=""
        try:
            spf_cp=subprocess.run(["dig", "+short", "TXT", self.target], capture_output=True, text=True, timeout=10)
            spf_lines=[l for l in spf_cp.stdout.splitlines() if "v=spf1" in l.lower()]
            report["spf"]=spf_lines[0] if spf_lines else "not found"
        except Exception:
            report["spf"]="not found"
        for sel in ["default","google","mail","k1","selector1","selector2"]:
            try:
                cp=subprocess.run(["dig", "+short", "TXT", f"{sel}._domainkey.{self.target}"], capture_output=True, text=True, timeout=8)
                if cp.stdout.strip(): report["dkim_probed"].append({"selector":sel,"record":cp.stdout.strip()})
            except Exception:
                pass
        dmarc_val = report.get("dmarc") or ""
        dmarc_warn = ("⚠️  MISSING — domain is phishable" if not dmarc_val else ("⚠️  p=none — reporting only, not enforced" if "p=none" in dmarc_val.lower() else "✅ enforced"))
        md=[f"# OSINT Report — {self.target}\n\n", f"## DMARC\n- Record: {dmarc_val or 'NOT FOUND'}\n", f"- Assessment: {dmarc_warn}\n\n", f"## SPF\n- Record: {report.get('spf')}\n\n", f"## DKIM Selectors Found ({len(report['dkim_probed'])})\n"]
        for d in report["dkim_probed"]:
            md.append(f"- `{d['selector']}`: {d['record'][:120]}\n")
        (self.intel / "osint_report.md").write_text("".join(md), encoding="utf-8")
        self.write_json(self.cache / "osint_report.json", report)
        self.record_stage_status("osint", "completed", f"dmarc={'found' if dmarc_val else 'MISSING'} dkim_selectors={len(report['dkim_probed'])}")
        self.mark_done("osint")

    def write_live_findings(self) -> None:
        out = self.workdir / "findings.md"
        sections=[]
        for title, fn in [("## CORS Findings\n", self.intel / "cors_findings.json"), ("## 403 Bypasses\n", self.intel / "bypass_403_findings.json"), ("## XSS Findings\n", self.intel / "xss_findings.json"), ("## GraphQL Introspection Open\n", self.intel / "graphql_findings.json")]:
            if not fn.exists():
                continue
            try:
                data=json.loads(fn.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            items = data.get("items", data) if isinstance(data, dict) else data
            if not items:
                continue
            sections.append(title)
            if isinstance(items, list):
                for it in items[:30]:
                    sections.append(f"- {it}\n")
        header=[f"# Live Findings — {self.target}\n", f"Updated: {utc_now_display()}\n\n"]
        content="".join(header+sections).strip()
        out.write_text(content if content else "# Live Findings\n_No findings yet._\n", encoding="utf-8")

    def _top_findings_snippet(self, limit: int = 3) -> str:
        ranked = self.prioritize_findings(self.dedup_findings(self.findings))
        if not ranked:
            return ""
        lines = []
        for f in ranked[:max(1, limit)]:
            lines.append(f"- [{f.get('severity','INFO')}] {f.get('stage','')} :: {f.get('target','')} — {f.get('title','')}")
        return "\n".join(lines)

    def _stage_metrics_fields(self) -> list[dict]:
        stats = self.collect_stats()
        findings_total = (
            stats.get("nuclei_findings", 0)
            + stats.get("nuclei_findings_phase2", 0)
            + stats.get("secrets_findings", 0)
            + stats.get("cors_findings", 0)
            + stats.get("xss_findings", 0)
            + stats.get("bypass_403_findings", 0)
            + stats.get("graphql_findings", 0)
            + stats.get("github_dork_hits", 0)
            + stats.get("takeover_findings", 0)
        )
        return [
            {"name": "Subdomains", "value": str(stats.get("all_subdomains", 0)), "inline": True},
            {"name": "Live Hosts", "value": str(stats.get("live_hosts", 0)), "inline": True},
            {"name": "Endpoints", "value": str(stats.get("endpoints", 0)), "inline": True},
            {"name": "Findings", "value": str(findings_total), "inline": True},
        ]

    def _recent_log_excerpt(self, *, stage: str = "", log_file: str = "", lines: int = 3) -> str:
        candidates: list[Path] = []
        if log_file:
            candidates.append(Path(log_file))
        candidates.extend([self.errors_jsonl, self.status_jsonl])
        for path in candidates:
            if not path.exists():
                continue
            raw = [ln.strip() for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
            if not raw:
                continue
            if stage:
                filtered = [ln for ln in raw if stage in ln]
                raw = filtered or raw
            excerpt = "\n".join(raw[-max(1, lines):])
            if excerpt:
                return excerpt
        return ""

    def _error_fingerprint(self, stage: str, message: str) -> str:
        blob = f"{stage}|{message}".encode("utf-8", errors="ignore")
        return hashlib.sha1(blob).hexdigest()[:10]

    def _truncate(self, text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[: max(0, limit - 1)] + "…"

    def _sanitize_embed(self, body: dict) -> dict:
        # Discord-safe size guards.
        max_title, max_desc, max_field_name, max_field_value, max_footer = 256, 4096, 256, 1024, 2048
        b = dict(body)
        embeds = list(b.get("embeds") or [])
        if not embeds:
            return b
        em = dict(embeds[0])
        em["title"] = self._truncate(str(em.get("title") or ""), max_title)
        em["description"] = self._truncate(str(em.get("description") or ""), max_desc)
        cleaned_fields = []
        for f in list(em.get("fields") or [])[:25]:
            cleaned_fields.append({
                "name": self._truncate(str(f.get("name") or "-"), max_field_name),
                "value": self._truncate(str(f.get("value") or "-"), max_field_value),
                "inline": bool(f.get("inline", False)),
            })
        em["fields"] = cleaned_fields
        footer = dict(em.get("footer") or {})
        if footer:
            footer["text"] = self._truncate(str(footer.get("text") or ""), max_footer)
            em["footer"] = footer
        embeds[0] = em
        b["embeds"] = embeds
        b["content"] = self._truncate(str(b.get("content") or ""), 2000)
        b["text"] = self._truncate(str(b.get("text") or ""), 2000)
        return b

    def _notify_urls(self, st: str, sev: str) -> list[str]:
        base = os.environ.get("RECONHARVEST_WEBHOOK", "").strip()
        if not base:
            return []
        return [base]

    def _ensure_webhook_worker(self) -> None:
        if self._webhook_worker and self._webhook_worker.is_alive():
            return
        self._webhook_stop.clear()

        def _worker() -> None:
            while not self._webhook_stop.is_set() or self._webhook_queue:
                item = None
                with self._webhook_lock:
                    if self._webhook_queue:
                        item = self._webhook_queue.popleft()
                if item is None:
                    self._webhook_signal.wait(0.3)
                    self._webhook_signal.clear()
                    continue
                self._deliver_webhook_event(item)

        self._webhook_worker = threading.Thread(target=_worker, name="recon-webhook", daemon=False)
        self._webhook_worker.start()

    def _next_retry_delay(self, attempt: int, headers: dict | None = None) -> float:
        # Exponential backoff with jitter + honor Retry-After / rate limit headers.
        hdr = headers or {}
        retry_after = hdr.get("Retry-After") or hdr.get("retry-after") or hdr.get("X-RateLimit-Reset-After") or hdr.get("x-ratelimit-reset-after")
        if retry_after:
            try:
                return max(0.2, float(str(retry_after).strip()))
            except Exception:
                pass
        base = min(20.0, 0.6 * (2 ** max(0, attempt - 1)))
        return base + random.uniform(0.0, 0.35)

    def _deliver_webhook_event(self, event: dict) -> None:
        now_m = time.monotonic()
        if now_m < self._webhook_circuit_open_until:
            self._webhook_events_dropped += 1
            return

        urls = event.get("urls") or []
        body = self._sanitize_embed(dict(event.get("body") or {}))
        payload = json.dumps(body).encode("utf-8")
        delivered = False

        for url in urls:
            ok = False
            for attempt in range(1, 5):
                try:
                    req = urllib.request.Request(
                        str(url),
                        data=payload,
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": "ReconHarvest-Notifier/1.0",
                            "Accept": "application/json",
                        },
                    )
                    with urllib.request.urlopen(req, timeout=8):
                        pass
                    ok = True
                    break
                except urllib.error.HTTPError as e:
                    retriable = e.code in (429, 500, 502, 503, 504)
                    if retriable and attempt < 4:
                        time.sleep(self._next_retry_delay(attempt, dict(e.headers or {})))
                        continue
                    break
                except Exception:
                    if attempt < 4:
                        time.sleep(self._next_retry_delay(attempt, {}))
                        continue
                    break
            if ok:
                delivered = True

        if delivered:
            self._webhook_sent_ok += 1
            self._webhook_consecutive_failures = 0
            self._last_webhook_fingerprint = str(event.get("fingerprint") or "")
            self._last_webhook_at = time.monotonic()
            return

        self._webhook_failed_sends += 1
        self._webhook_consecutive_failures += 1
        if self._webhook_consecutive_failures >= 5:
            self._webhook_circuit_open_until = time.monotonic() + 120.0

    def _queue_webhook_event(self, event: dict) -> None:
        self._ensure_webhook_worker()
        with self._webhook_lock:
            if len(self._webhook_queue) > 400:
                self._webhook_queue.popleft()
                self._webhook_events_dropped += 1
            self._webhook_queue.append(event)
        self._webhook_signal.set()

    def _flush_webhooks(self, timeout_seconds: float = 8.0) -> None:
        self._webhook_signal.set()
        deadline = time.monotonic() + max(0.2, timeout_seconds)
        while time.monotonic() < deadline:
            with self._webhook_lock:
                pending = len(self._webhook_queue)
            if pending == 0:
                break
            time.sleep(0.1)
        self._webhook_stop.set()
        self._webhook_signal.set()
        if self._webhook_worker and self._webhook_worker.is_alive():
            self._webhook_worker.join(timeout=12.0)

    def _notify(self, message: str, *, status: str = "info", stage: str = "", severity: str = "INFO", log_file: str = "") -> None:
        st = (status or "info").lower()
        sev = (severity or "INFO").upper()
        urls = self._notify_urls(st, sev)
        if not urls:
            return

        color_map = {"completed": 0x2ECC71, "info": 0x3498DB, "warning": 0xF1C40F, "error": 0xE74C3C, "interrupted": 0xE67E22}
        emoji_map = {"completed": "✅", "info": "ℹ️", "warning": "⚠️", "error": "❌", "interrupted": "🟠"}
        color = color_map.get(st, 0x3498DB)
        emoji = emoji_map.get(st, "ℹ️")

        fingerprint = f"{st}|{stage}|{message}"
        now_m = time.monotonic()
        if sev not in {"HIGH", "CRITICAL"}:
            if fingerprint == self._last_webhook_fingerprint and (now_m - self._last_webhook_at) < 30:
                return
            if st == "completed" and (now_m - self._last_webhook_at) < 2:
                return

        mention = "@here " if (sev in {"HIGH", "CRITICAL"} or st in {"warning", "error"}) else ""
        text = f"{mention}[ReconHarvest] {self.target}: {message}"

        fields = [
            {"name": "Target", "value": self.target, "inline": True},
            {"name": "Status", "value": st.upper(), "inline": True},
            {"name": "Severity", "value": sev, "inline": True},
        ]
        if stage:
            fields.append({"name": "Stage", "value": stage, "inline": True})
        fields.extend(self._stage_metrics_fields())
        if log_file:
            fields.append({"name": "Log", "value": log_file, "inline": False})

        event_type = "stage_completed" if st == "completed" and stage and stage != "pipeline" else "run_completed"
        if st in {"warning", "error", "interrupted"}:
            event_type = "run_error"
        elif st == "info" and stage == "startup":
            event_type = "run_started"
        elif st == "warning" and stage in {"cors", "xss_scan", "bypass_403", "graphql", "github_dork"}:
            event_type = "finding_detected"

        description = message
        if stage == "pipeline" and st == "completed":
            top3 = self._top_findings_snippet(3)
            if top3:
                description = f"{message}\n\nTop findings:\n{top3}"
                fields.append({"name": "Top Findings", "value": f"```\n{top3}\n```", "inline": False})

        if st in {"warning", "error", "interrupted"}:
            excerpt = self._recent_log_excerpt(stage=stage, log_file=log_file, lines=3)
            if excerpt:
                fields.append({"name": "Recent Log Excerpt", "value": f"```\n{excerpt}\n```", "inline": False})
            err_fp = self._error_fingerprint(stage or "n/a", message)
            fields.append({"name": "Error Fingerprint", "value": err_fp, "inline": True})
            if self._last_command_context:
                cmd = self._last_command_context
                fields.append({
                    "name": "Command Context",
                    "value": f"tool={cmd.get('label','')} rc={cmd.get('returncode','?')} dur={cmd.get('duration_seconds','?')}s",
                    "inline": False,
                })

        fields.append({"name": "Workspace", "value": str(self.workdir), "inline": False})

        body = {
            "text": text,
            "content": text,
            "embeds": [{
                "title": f"{emoji} ReconHarvest Update",
                "description": description,
                "color": color,
                "fields": fields,
                "footer": {"text": now_utc_iso()},
            }],
            "event": {
                "type": event_type,
                "target": self.target,
                "stage": stage,
                "status": st,
                "severity": sev,
                "timestamp": now_utc_iso(),
            },
            "target": self.target,
            "workdir": str(self.workdir),
            "timestamp": now_utc_iso(),
        }
        self._queue_webhook_event({"urls": urls, "body": body, "fingerprint": fingerprint})

    def execute(self) -> None:
        global SHUTTING_DOWN
        reused = self.reuse_previous_artifacts()
        if reused:
            self.record_stage_status("cache", "completed", "reused previous artifacts", metrics={"reused_files": reused})
        pipeline = [
            ("osint", self.stage_osint),
            ("nuclei_templates", self.stage_nuclei_templates),
            ("subdomains", self.stage_subdomains),
            ("dns_bruteforce", self.stage_dns_bruteforce),
            ("dnsx", self.stage_dnsx),
            ("takeover", self.stage_takeover),
            ("httpx", self.stage_httpx),
            ("vhost_fuzz", self.stage_vhost_fuzz),
            ("portscan", self.stage_portscan),
            ("screenshots", self.stage_screenshots),
            ("cors", self.stage_cors),
            ("discovery", self.stage_discovery),
            ("bypass_403", self.stage_bypass_403),
            ("graphql", self.stage_graphql),
            ("urls", self.stage_urls),
            ("param_discovery", self.stage_param_discovery),
            ("tech", self.stage_tech),
            ("tech_host_mapping", self.stage_tech_host_mapping),
            ("nuclei_phase1", self.stage_nuclei_phase1),
            ("xss_scan", self.stage_xss_scan),
            ("secrets", self.stage_secrets),
            ("github_dork", self.stage_github_dork),
            ("nuclei_phase2", self.stage_nuclei_phase2),
            ("endpoint_ranking", self.stage_endpoint_ranking),
        ]
        self.dashboard.start()
        interrupted = False
        try:
            prof = f"scan:{self.config.ffuf_rate}/thr:{self.config.ffuf_threads}"
            self.dashboard.set_context(output_dir=str(self.workdir), run_mode="--run", log_file=str(RUN_LOG_FILE) if RUN_LOG_FILE else "run.log", profile=prof)
            self.dashboard.set_stats(self.collect_stats())
            if not self.resume_mode:
                self._notify(f"Run started | profile={prof}", status="info", stage="startup", severity="INFO", log_file=str(self.logs / "stage_status.jsonl"))
            for stage_name, fn in pipeline:
                if SHUTTING_DOWN:
                    interrupted = True
                    break
                # Record whether this stage was already done BEFORE running it.
                # On resume, stages that were previously completed return immediately
                # via is_done(); we suppress their "done" webhook to avoid spam.
                already_done = self.resume_mode and self.is_done(stage_name)
                self.dashboard.stage_start(stage_name)
                self.dashboard.set_context(current_host="-", queue_depth=0, active_jobs=0, failed_jobs=0)
                t0 = time.perf_counter()
                fn()
                dt = time.perf_counter() - t0
                self.record_stage_status("pipeline", "completed", f"{stage_name} complete", duration_seconds=dt)
                if not already_done:
                    self._notify(
                        f"Stage done | duration={dt:.1f}s",
                        status="completed",
                        stage=stage_name,
                        severity="INFO",
                        log_file=str(self.logs / "stage_status.jsonl"),
                    )
                stats = self.collect_stats()
                self.dashboard.set_stats(stats)
                self.dashboard.set_context(httpx_buckets=f"2xx={stats.get('httpx_2xx',0)} 3xx={stats.get('httpx_3xx',0)} 401={stats.get('httpx_401',0)} 403={stats.get('httpx_403',0)}")
                self.dashboard.stage_done(stage_name, dt)
        except (GracefulInterrupt, KeyboardInterrupt):
            request_shutdown("Interrupted by user (Ctrl+C). Graceful shutdown started.")
            self.record_stage_status("shutdown", "interrupted", "user pressed Ctrl+C")
            interrupted = True
        finally:
            self.dashboard.stop()
        if interrupted or SHUTTING_DOWN:
            self.build_summaries()
            self.finalize_reports()
            # Ensure interrupted marker exists in summary report
            s = self.reports / "summary.md"
            if s.exists():
                s.write_text(s.read_text(encoding="utf-8", errors="ignore") + "\n\n> Run interrupted: partial results shown.\n", encoding="utf-8")
            else:
                self.write_md_report(s, f"Summary — {self.target}", ["> Run interrupted: partial results shown."])
            f = self.reports / "findings.md"
            if not f.exists():
                self.write_md_report(f, f"Live Findings — {self.target}", ["_No findings yet._"])
            self.record_stage_status("final_validation", "skipped", "run interrupted")
            stats = self.collect_stats()
            self._notify(
                f"Run interrupted | live_hosts={stats.get('live_hosts',0)} "
                f"endpoints={stats.get('endpoints',0)} findings={stats.get('nuclei_findings',0)+stats.get('nuclei_findings_phase2',0)+stats.get('secrets_findings',0)+stats.get('cors_findings',0)+stats.get('xss_findings',0)+stats.get('bypass_403_findings',0)+stats.get('graphql_findings',0)+stats.get('github_dork_hits',0)} "
                f"summary={self.reports / 'summary.md'}",
                status="interrupted",
                stage="pipeline",
                severity="HIGH",
                log_file=str(self.logs / "stage_status.jsonl"),
            )
            self._flush_webhooks(timeout_seconds=8.0)
            raise GracefulInterrupt("interrupted")
        self.build_summaries()
        self.finalize_reports()
        self.validate_outputs()
        stats = self.collect_stats()
        self._notify(
            f"Run completed | live_hosts={stats.get('live_hosts',0)} "
            f"endpoints={stats.get('endpoints',0)} findings={stats.get('nuclei_findings',0)+stats.get('nuclei_findings_phase2',0)+stats.get('secrets_findings',0)+stats.get('cors_findings',0)+stats.get('xss_findings',0)+stats.get('bypass_403_findings',0)+stats.get('graphql_findings',0)+stats.get('github_dork_hits',0)} "
            f"summary={self.reports / 'summary.md'}",
            status="completed",
            stage="pipeline",
            severity="INFO",
            log_file=str(self.logs / "stage_status.jsonl"),
        )
        self._flush_webhooks(timeout_seconds=8.0)

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(add_help=True)
    p.add_argument("target", nargs="?")
    p.add_argument("--targets-file", type=str, default="")
    p.add_argument("--run", action="store_true")
    p.add_argument("--parallel", type=int, default=None)
    p.add_argument("--resume", type=str, default="")
    p.add_argument("--resume-from-stage", type=str, default="")
    p.add_argument("-o", "--output", type=str, default="")
    p.add_argument("--config", type=str, default=str(Path.home() / ".reconharvest.conf"))
    p.add_argument("--skip-nuclei", action="store_true")
    p.add_argument("--skip-gau", action="store_true")
    p.add_argument("--skip-secrets", action="store_true")
    p.add_argument("--skip-takeover", action="store_true")
    p.add_argument("--skip-cors", action="store_true")
    p.add_argument("--skip-screenshots", action="store_true")
    p.add_argument("--screenshots-threads", type=int)
    p.add_argument("--screenshots-timeout", type=int)
    p.add_argument("--skip-portscan", action="store_true")
    p.add_argument("--naabu-rate", type=int)
    p.add_argument("--naabu-timeout", type=int)
    p.add_argument("--naabu-top-ports", type=str)
    p.add_argument("--naabu-ports", type=str)
    p.add_argument("--skip-dns-bruteforce", action="store_true")
    p.add_argument("--dns-bruteforce-timeout", type=int)
    p.add_argument("--skip-param-discovery", action="store_true")
    p.add_argument("--arjun-host-cap", type=int)
    p.add_argument("--arjun-threads", type=int)
    p.add_argument("--arjun-timeout", type=int)
    p.add_argument("--skip-xss", action="store_true")
    p.add_argument("--dalfox-url-cap", type=int)
    p.add_argument("--dalfox-workers", type=int)
    p.add_argument("--dalfox-timeout", type=int)
    p.add_argument("--skip-bypass-403", action="store_true")
    p.add_argument("--bypass-403-workers", type=int)
    p.add_argument("--bypass-403-timeout", type=int)
    p.add_argument("--skip-graphql", action="store_true")
    p.add_argument("--graphql-timeout", type=int)
    p.add_argument("--skip-vhost", action="store_true")
    p.add_argument("--vhost-rate", type=int)
    p.add_argument("--vhost-threads", type=int)
    p.add_argument("--vhost-timeout", type=int)
    p.add_argument("--skip-github-dork", action="store_true")
    p.add_argument("--github-dork-timeout", type=int)
    p.add_argument("--skip-osint", action="store_true")
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--auto-suffix", action="store_true")
    p.add_argument("--no-ui", action="store_true", help="Disable rich terminal dashboard")
    p.add_argument("--ffuf-threads", type=int)
    p.add_argument("--ffuf-timeout", type=int)
    p.add_argument("--ffuf-rate", type=int)
    p.add_argument("--ffuf-maxtime-job", type=int)
    p.add_argument("--ffuf-delay", type=str)
    p.add_argument("--host-workers", type=int)
    p.add_argument("--ffuf-workers", type=int)
    p.add_argument("--dirsearch-workers", type=int)
    p.add_argument("--url-workers", type=int)
    p.add_argument("--global-request-budget", type=int)
    p.add_argument("--stop-on-403-ratio", type=float)
    p.add_argument("--stop-on-error", action="store_true", default=None)
    p.add_argument("--no-stop-on-error", dest="stop_on_error", action="store_false")
    p.add_argument("--scan-profile", choices=["stealth", "balanced", "aggressive", "full"], default="balanced")
    p.add_argument("--target-profile", choices=["waf-safe", "normal", "aggressive-lab"], default="waf-safe")
    p.add_argument("--dirsearch-threads", type=int)
    p.add_argument("--dirsearch-timeout", type=int)
    p.add_argument("--dirsearch-delay", type=float)
    p.add_argument("--httpx-threads", type=int)
    p.add_argument("--httpx-timeout", type=int)
    p.add_argument("--httpx-retries", type=int)
    p.add_argument("--subfinder-timeout", type=int)
    p.add_argument("--assetfinder-timeout", type=int)
    p.add_argument("--dnsx-timeout", type=int)
    p.add_argument("--httpx-stage-timeout", type=int)
    p.add_argument("--nuclei-rate-limit", type=int)
    p.add_argument("--nuclei-concurrency", type=int)
    p.add_argument("--nuclei-max-host-error", type=int)
    p.add_argument("--nuclei-timeout", type=int)
    p.add_argument("--nuclei-retries", type=int)
    p.add_argument("--nuclei-severity", type=str, default="")
    p.add_argument("--nuclei-tags", type=str, default="")
    p.add_argument("--secrets-timeout", type=int)
    p.add_argument("--secrets-js-cap", type=int)
    p.add_argument("--secrets-sf-cap", type=int)
    p.add_argument("--secrets-download-delay", type=float)
    p.add_argument("--cors-timeout", type=int)
    p.add_argument("--katana-timeout", type=int)
    p.add_argument("--gospider-timeout", type=int)
    p.add_argument("--hakrawler-timeout", type=int)
    p.add_argument("--katana-depth", type=int)
    p.add_argument("--no-katana-js-crawl", dest="katana_js_crawl", action="store_false")
    p.add_argument("--gau-timeout", type=int)
    p.add_argument("--gau-blacklist", type=str)
    p.add_argument("--force-update-templates", action="store_true")
    p.add_argument("--ffuf-version", type=str)
    p.add_argument("--httpx-version", type=str)
    p.add_argument("--subfinder-version", type=str)
    p.add_argument("--assetfinder-version", type=str)
    p.add_argument("--dnsx-version", type=str)
    p.add_argument("--katana-version", type=str)
    p.add_argument("--gau-version", type=str)
    p.add_argument("--nuclei-version", type=str)
    p.add_argument("--update-tools", action="store_true")
    p.add_argument("--output-format", choices=["md"], default="md")
    p.add_argument("--debug-artifacts", action="store_true")
    p.add_argument("--doctor", action="store_true", help="Run environment/tool diagnostics and exit")
    p.add_argument("--max-report-files", type=int, default=12)
    p.set_defaults(katana_js_crawl=True, stop_on_error=None)
    return p.parse_args()

def ensure_default_config(path: str) -> None:
    if not path:
        return
    p = Path(path).expanduser()
    if p.exists():
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    default_cfg = {
        "PARALLEL": 30,
        "SKIP_TOOLS": "",
        "recon_config": {
            "scan_profile": "balanced",
            "target_profile": "waf-safe",
            "secrets_timeout": 20,
            "secrets_js_cap": 200,
            "secrets_sf_cap": 50,
            "secrets_download_delay": 0.15,
            "skip_secrets": False,
        },
        "tool_versions": {},
    }
    p.write_text(json.dumps(default_cfg, indent=2) + "\n", encoding="utf-8")
    log(f"[*] Created default config: {p}")


def load_json_config(path: str) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    raw = p.read_text(encoding="utf-8", errors="ignore")
    try:
        return json.loads(raw)
    except Exception as e:
        if raw.lstrip().startswith(("{", "[")):
            log(f"[!] Config looks like JSON but failed to parse ({e}); falling back to KEY=VALUE parser.")
        cfg: dict[str, object] = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")
        return cfg


def build_recon_config(args: argparse.Namespace, cfg: dict) -> ReconConfig:
    data = dict(cfg.get("recon_config") or {})

    # Scan profile defaults
    scan_profiles = {
        "stealth": {"ffuf_rate": 20, "ffuf_threads": 8, "host_workers": 8, "ffuf_workers": 4, "dirsearch_workers": 4, "global_request_budget": 40, "ffuf_delay": "0.08-0.25"},
        "balanced": {"ffuf_rate": 40, "ffuf_threads": 16, "host_workers": 20, "ffuf_workers": 8, "dirsearch_workers": 10, "global_request_budget": 120, "ffuf_delay": "0.03-0.12"},
        "aggressive": {"ffuf_rate": 80, "ffuf_threads": 30, "host_workers": 30, "ffuf_workers": 12, "dirsearch_workers": 14, "global_request_budget": 240, "ffuf_delay": "0.0-0.03"},
        "full": {"ffuf_rate": 100, "ffuf_threads": 40, "host_workers": 40, "ffuf_workers": 16, "dirsearch_workers": 16, "global_request_budget": 320, "ffuf_delay": "0.0-0.02"},
    }
    target_profiles = {
        "waf-safe": {"ffuf_rate": 25, "ffuf_threads": 10, "ffuf_delay": "0.08-0.20", "stop_on_403_ratio": 0.80},
        "normal": {},
        "aggressive-lab": {"ffuf_rate": 120, "ffuf_threads": 50, "ffuf_delay": "0.0-0.01", "stop_on_403_ratio": 0.98},
    }
    scan_prof = scan_profiles.get(args.scan_profile or "balanced", {})
    target_prof = target_profiles.get(args.target_profile or "waf-safe", {})
    overlap = sorted(set(scan_prof.keys()) & set(target_prof.keys()))
    if overlap:
        log(f"[*] Profile merge order: scan-profile then target-profile (target overrides: {', '.join(overlap)})")
    data.update(scan_prof)
    data.update(target_prof)

    cli_map = {
        "ffuf_threads": args.ffuf_threads,
        "ffuf_timeout": args.ffuf_timeout,
        "ffuf_rate": args.ffuf_rate,
        "ffuf_maxtime_job": args.ffuf_maxtime_job,
        "ffuf_delay": args.ffuf_delay,
        "host_workers": args.host_workers,
        "ffuf_workers": args.ffuf_workers,
        "dirsearch_workers": args.dirsearch_workers,
        "url_workers": args.url_workers,
        "global_request_budget": args.global_request_budget,
        "stop_on_403_ratio": args.stop_on_403_ratio,
        "stop_on_error": args.stop_on_error,
        "scan_profile": args.scan_profile,
        "target_profile": args.target_profile,
        "dirsearch_threads": args.dirsearch_threads,
        "dirsearch_timeout": args.dirsearch_timeout,
        "dirsearch_delay": args.dirsearch_delay,
        "httpx_threads": args.httpx_threads,
        "httpx_timeout": args.httpx_timeout,
        "httpx_retries": args.httpx_retries,
        "subfinder_timeout": args.subfinder_timeout,
        "assetfinder_timeout": args.assetfinder_timeout,
        "dnsx_timeout": args.dnsx_timeout,
        "httpx_stage_timeout": args.httpx_stage_timeout,
        "nuclei_rate_limit": args.nuclei_rate_limit,
        "nuclei_concurrency": args.nuclei_concurrency,
        "nuclei_max_host_error": args.nuclei_max_host_error,
        "nuclei_timeout": args.nuclei_timeout,
        "nuclei_retries": args.nuclei_retries,
        "secrets_timeout": args.secrets_timeout,
        "secrets_js_cap": args.secrets_js_cap,
        "secrets_sf_cap": args.secrets_sf_cap,
        "secrets_download_delay": args.secrets_download_delay,
        "cors_timeout": args.cors_timeout,
        "katana_timeout": args.katana_timeout,
        "gospider_timeout": args.gospider_timeout,
        "hakrawler_timeout": args.hakrawler_timeout,
        "katana_depth": args.katana_depth,
        "katana_js_crawl": args.katana_js_crawl,
        "gau_timeout": args.gau_timeout,
        "gau_blacklist": args.gau_blacklist,
        "skip_secrets": args.skip_secrets,
        "skip_takeover": args.skip_takeover,
        "skip_cors": args.skip_cors,
        "skip_portscan": args.skip_portscan,
        "naabu_rate": args.naabu_rate,
        "naabu_timeout": args.naabu_timeout,
        "naabu_top_ports": args.naabu_top_ports,
        "naabu_ports": args.naabu_ports,
        "skip_dns_bruteforce": args.skip_dns_bruteforce,
        "dns_bruteforce_timeout": args.dns_bruteforce_timeout,
        "skip_param_discovery": args.skip_param_discovery,
        "arjun_host_cap": args.arjun_host_cap,
        "arjun_threads": args.arjun_threads,
        "arjun_timeout": args.arjun_timeout,
        "skip_xss": args.skip_xss,
        "dalfox_url_cap": args.dalfox_url_cap,
        "dalfox_workers": args.dalfox_workers,
        "dalfox_timeout": args.dalfox_timeout,
        "skip_bypass_403": args.skip_bypass_403,
        "bypass_403_workers": args.bypass_403_workers,
        "bypass_403_timeout": args.bypass_403_timeout,
        "skip_graphql": args.skip_graphql,
        "graphql_timeout": args.graphql_timeout,
        "skip_vhost": args.skip_vhost,
        "vhost_rate": args.vhost_rate,
        "vhost_threads": args.vhost_threads,
        "vhost_timeout": args.vhost_timeout,
        "skip_github_dork": args.skip_github_dork,
        "github_dork_timeout": args.github_dork_timeout,
        "skip_osint": args.skip_osint,
        "skip_screenshots": args.skip_screenshots,
        "screenshots_threads": args.screenshots_threads,
        "screenshots_timeout": args.screenshots_timeout,
        "output_format": args.output_format,
        "debug_artifacts": args.debug_artifacts,
        "max_report_files": args.max_report_files,
    }
    for key, value in cli_map.items():
        if value is not None:
            data[key] = value
    valid = set(ReconConfig.__dataclass_fields__.keys())
    filtered = {k: v for k, v in data.items() if k in valid}
    ignored = sorted(set(data.keys()) - valid)
    if ignored:
        log(f"[!] Ignoring unknown recon_config keys: {', '.join(ignored)}")
    return ReconConfig(**filtered)


def build_tool_versions(args: argparse.Namespace, cfg: dict) -> ToolVersions:
    data = dict(cfg.get("tool_versions") or {})
    cli_map = {
        "ffuf": args.ffuf_version,
        "httpx": args.httpx_version,
        "subfinder": args.subfinder_version,
        "assetfinder": args.assetfinder_version,
        "dnsx": args.dnsx_version,
        "katana": args.katana_version,
        "gau": args.gau_version,
        "nuclei": args.nuclei_version,
    }
    for key, value in cli_map.items():
        if value:
            data[key] = value
    return ToolVersions(**data)


def resolve_targets(args: argparse.Namespace) -> list[str]:
    targets = []
    if args.target:
        targets.append(args.target.strip())
    if args.targets_file:
        for line in Path(args.targets_file).read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return list(dict.fromkeys(targets))


def _build_dashboard(target: str, parallel: int, dashboard_enabled: bool) -> NullDashboard | HackerDashboard:
    if dashboard_enabled:
        global SHARED_CONSOLE
        SHARED_CONSOLE = SHARED_CONSOLE or Console()
        return HackerDashboard(
            target=target,
            parallel=parallel,
            total_stages=len(PIPELINE_STAGES),
            console=SHARED_CONSOLE,
        )
    return NullDashboard()


def preflight_checks(workdir: Path) -> None:
    """Minimal workspace sanity checks before runner setup."""
    workdir.mkdir(parents=True, exist_ok=True)
    probe = workdir / ".preflight.write.test"
    try:
        probe.write_text("ok", encoding="utf-8")
    finally:
        probe.unlink(missing_ok=True)


def _setup_runner(
    workdir: Path,
    target: str,
    args: argparse.Namespace,
    recon_config: ReconConfig,
    dashboard_enabled: bool,
) -> Runner:
    global RUN_LOG_FILE
    RUN_LOG_FILE = workdir / "run.log"
    if not RUN_LOG_FILE.exists():
        RUN_LOG_FILE.write_text("", encoding="utf-8")
    log(f"[*] Working directory: {workdir}")
    preflight_checks(workdir)
    dashboard = _build_dashboard(target, args.parallel, dashboard_enabled)
    return Runner(
        target=target,
        workdir=workdir,
        parallel=args.parallel,
        config=recon_config,
        dashboard=dashboard,
        skip_nuclei=args.skip_nuclei,
        skip_gau=args.skip_gau,
        skip_secrets=args.skip_secrets,
        skip_takeover=args.skip_takeover,
        skip_cors=args.skip_cors,
        force_update_templates=args.force_update_templates,
        nuclei_severity=args.nuclei_severity,
        nuclei_tags=args.nuclei_tags,
    )


def _execute_runner(r: Runner, args: argparse.Namespace, script_name: str) -> None:
    workdir = r.workdir
    target = r.target
    r.resume_mode = bool(args.resume)
    r.write_run_commands_script(sys.argv, script_name)
    log(f"[*] Generated: {workdir / 'run_commands.sh'}")
    if args.run:
        log(f"[*] Running recon for {target}…")
        if args.resume:
            r._notify("🟢 Resume mode enabled — continuing from existing run state", status="completed", stage="pipeline", severity="HIGH", log_file=str(r.logs / "stage_status.jsonl"))
        try:
            r.execute()
            log(f"[*] Done (validated). Summary: {workdir / 'reports' / 'summary.md'}")
        except GracefulInterrupt:
            r.record_stage_status("shutdown", "interrupted", "user pressed Ctrl+C")
            log(f"[!] Interrupted by user. Partial results were saved in: {workdir}")
            raise
    else:
        log(f"[*] Workspace ready: {workdir}")
        log("[*] To run:")
        log(f"    python3 {script_name} --resume \"{workdir}\" --run")

def process_target(target: str, args: argparse.Namespace, recon_config: ReconConfig, script_name: str, dashboard_enabled: bool) -> None:
    out_base = Path("outputs")
    target = normalize_target(target)
    if not validate_target(target):
        raise SystemExit(f"[!] Invalid target: {target}")
    target_dir = out_base / safe_target_dirname(target)
    if args.output:
        workdir = Path(args.output)
    else:
        workdir = target_dir / next_run_name(target_dir)

    if workdir.exists():
        if args.overwrite:
            log(f"[*] Overwriting existing output directory: {workdir}")
            for sub in (".state", "intel", "urls", "ffuf", "dirsearch", "logs"):
                shutil.rmtree(workdir / sub, ignore_errors=True)
            for pattern in ("*.txt", "*.json", "*.jsonl", "*.md"):
                for p in workdir.glob(pattern):
                    p.unlink(missing_ok=True)
            (workdir / "run_commands.sh").unlink(missing_ok=True)
            workdir.mkdir(parents=True, exist_ok=True)
        elif args.auto_suffix:
            base_name = workdir.name
            parent_dir = workdir.parent
            i = 2
            while (parent_dir / f"{base_name}-{i}").exists():
                i += 1
            workdir = parent_dir / f"{base_name}-{i}"
            log(f"[*] Output exists, using auto-suffixed directory: {workdir}")
            workdir.mkdir(parents=True, exist_ok=True)
        else:
            raise SystemExit(f"[!] Output directory already exists: {workdir}\n    Use --overwrite to reuse it or --auto-suffix to create a new name.")
    else:
        workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "workspace_meta.json").write_text(json.dumps({"schema_version": SCHEMA_VERSION, "target": target, "created_at": now_utc_iso()}, indent=2), encoding="utf-8")
    r = _setup_runner(workdir, target, args, recon_config, dashboard_enabled)
    _execute_runner(r, args, script_name)


def run_doctor() -> int:
    core_bins = ["ffuf", "httpx", "subfinder", "dnsx", "katana", "gau", "nuclei"]
    ext_bins = ["naabu", "puredns", "dalfox", "asnmap", "gospider", "hakrawler", "arjun", "dirsearch", "graphw00f"]
    missing_core = []

    log("[*] Doctor: checking PATH and tooling")
    for p in [Path.home() / ".local/bin", Path.home() / "go/bin"]:
        if str(p) not in os.environ.get("PATH", ""):
            log(f"[!] PATH missing: {p}")
        else:
            log(f"[+] PATH ok: {p}")

    def _check_bin(b: str, critical: bool = False):
        r = resolve_tool(b)
        if r:
            log(f"[+] {b}: {r}")
        else:
            tag = "CRITICAL" if critical else "optional"
            log(f"[!] {b}: MISSING ({tag})")
            if critical:
                missing_core.append(b)

    for b in core_bins:
        _check_bin(b, critical=True)
    for b in ext_bins:
        _check_bin(b, critical=False)

    # key deps
    if command_exists("dpkg"):
        cp = subprocess.run(["dpkg", "-s", "libpcap-dev"], capture_output=True, text=True)
        log("[+] libpcap-dev installed" if cp.returncode == 0 else "[!] libpcap-dev not installed (naabu build dependency)")
    _check_bin("massdns", critical=False)

    # optional envs
    for ev in ["GITHUB_TOKEN", "RECONHARVEST_WEBHOOK"]:
        log(f"[+] {ev} set" if os.environ.get(ev, "").strip() else f"[!] {ev} not set")

    if missing_core:
        log(f"[!] Doctor failed: missing core tools: {', '.join(missing_core)}")
        return 2
    log("[*] Doctor passed")
    return 0


def main():
    signal.signal(signal.SIGINT, handle_sigint)
    args = parse_args()
    if args.resume and args.output:
        raise SystemExit("[!] -o/--output cannot be used with --resume.")
    if args.resume and args.targets_file:
        raise SystemExit("[!] --targets-file cannot be used with --resume.")
    if args.resume and args.overwrite:
        raise SystemExit("[!] --overwrite cannot be used with --resume.")
    if args.resume and args.auto_suffix:
        raise SystemExit("[!] --auto-suffix cannot be used with --resume.")
    if args.overwrite and args.auto_suffix:
        raise SystemExit("[!] Use either --overwrite or --auto-suffix, not both.")
    if (not args.resume) and args.resume_from_stage:
        raise SystemExit("[!] --resume-from-stage can only be used with --resume.")

    if args.doctor:
        raise SystemExit(run_doctor())

    ensure_default_config(args.config)
    cfg = load_json_config(args.config)
    if args.parallel is None:
        cfg_parallel = cfg.get("PARALLEL")
        args.parallel = int(cfg_parallel) if cfg_parallel is not None else 30
    if args.parallel <= 0:
        raise SystemExit("[!] --parallel must be a positive integer.")
    if not args.skip_nuclei and str(cfg.get("SKIP_TOOLS", "")).find("nuclei") >= 0:
        args.skip_nuclei = True
    if not args.skip_gau and str(cfg.get("SKIP_TOOLS", "")).find("gau") >= 0:
        args.skip_gau = True
    if not args.skip_secrets and str(cfg.get("SKIP_TOOLS", "")).find("secrets") >= 0:
        args.skip_secrets = True
    if not args.skip_takeover and str(cfg.get("SKIP_TOOLS", "")).find("takeover") >= 0:
        args.skip_takeover = True
    if not args.skip_cors and str(cfg.get("SKIP_TOOLS", "")).find("cors") >= 0:
        args.skip_cors = True
    if not args.skip_portscan and str(cfg.get("SKIP_TOOLS", "")).find("portscan") >= 0:
        args.skip_portscan = True

    recon_config = build_recon_config(args, cfg)
    tool_versions = build_tool_versions(args, cfg)
    script_name = Path(sys.argv[0]).name or "reconharvest.py"
    dashboard_enabled = (not args.no_ui) and RICH_AVAILABLE and sys.stdout.isatty()
    if (not args.no_ui) and not dashboard_enabled:
        if not RICH_AVAILABLE:
            log("[*] Rich library not available; running without Terminal UI dashboard.")
        elif not sys.stdout.isatty():
            log("[*] Non-interactive terminal detected; running without Terminal UI dashboard.")

    set_logger(log)
    if args.update_tools:
        log("[*] --update-tools: forcing reinstall of all tools")
    install_required_tools(tool_versions, skip_secrets=args.skip_secrets, force_update=args.update_tools)

    if args.resume:
        workdir = Path(args.resume)
        if not workdir.is_dir():
            raise SystemExit(f"[!] Resume folder not found: {workdir}")
        meta_target = ""
        meta_path = workdir / "workspace_meta.json"
        if meta_path.exists():
            try:
                meta_target = str(json.loads(meta_path.read_text(encoding="utf-8")).get("target") or "").strip()
            except Exception as e:
                log(f"[!] Failed to parse workspace_meta.json: {e}")
                meta_target = ""
        target = normalize_target(args.target or meta_target or workdir.parent.name or workdir.name)
        r = _setup_runner(workdir, target, args, recon_config, dashboard_enabled)
        if args.resume_from_stage:
            r.resume_from_stage(args.resume_from_stage)
        _execute_runner(r, args, script_name)
        return

    targets = resolve_targets(args)
    if not targets:
        raise SystemExit("[!] target is required unless --resume is used.")
    for target in targets:
        if SHUTTING_DOWN:
            break
        try:
            process_target(target, args, recon_config, script_name, dashboard_enabled)
        except GracefulInterrupt:
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        request_shutdown("Interrupted by user (Ctrl+C). Stopping cleanly...")
        if ACTIVE_DASHBOARD:
            try:
                ACTIVE_DASHBOARD.stop()
            except Exception:
                pass
        log("[!] Interrupted by user (Ctrl+C). Stopping cleanly...")
        raise SystemExit(130)
    except GracefulInterrupt:
        if ACTIVE_DASHBOARD:
            try:
                ACTIVE_DASHBOARD.stop()
            except Exception:
                pass
        raise SystemExit(130)
    except RuntimeError as e:
        log(f"[!] {e}")
        raise SystemExit(1)
