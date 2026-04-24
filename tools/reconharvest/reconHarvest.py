#!/usr/bin/env python3
import atexit
import argparse
import csv
import datetime
import html
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
from typing import Any, Dict, List, Tuple, Set, Optional, Deque
import math

try:
    from installers import (
        command_exists,
        ensure_dns_wordlist,
        ensure_resolvers_list,
        install_required_tools,
        resolve_tool,
        set_logger,
        verify_tool,
    )
except ModuleNotFoundError:
    from tools.reconharvest.installers import (  # type: ignore[import-not-found]
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
SCHEMA_VERSION = "1.1"
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
_RX_HTML_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_RX_FORM_BLOCK = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.I | re.S)
_RX_TAG_INPUT = re.compile(r"<(?:input|textarea|select)\b(?P<attrs>[^>]*)>", re.I | re.S)
_RX_TAG_BUTTON = re.compile(r"<button\b(?P<attrs>[^>]*)>(?P<label>.*?)</button>", re.I | re.S)
_RX_ATTR = re.compile(r'([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(".*?"|\'.*?\'|[^\s>]+)')
_RX_ROBOTS_ALLOW = re.compile(r"^\s*(?:allow|disallow)\s*:\s*(\S+)\s*$", re.I)
_RX_SITEMAP_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_RX_PARAM_IN_TEXT = re.compile(r"[?&]([A-Za-z0-9_.-]{1,64})=", re.I)
_RX_HTTP_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)

_ARCHIVE_URL_SOURCES = frozenset({"gau", "wayback"})
_LIVE_URL_SOURCES = frozenset({"crawl_live", "js_extracted", "xnlinkfinder", "robots", "sitemap", "form_action", "redirect_chain"})
_GF_PATTERN_BUCKETS: dict[str, str] = {
    "xss": "xss",
    "sqli": "sqli",
    "ssrf": "ssrf",
    "lfi": "lfi",
    "redirect": "redirect",
    "rce": "rce",
    "ssti": "ssti",
}
_GF_QSREPLACE_PAYLOADS: dict[str, str] = {
    "xss": "BPXSS",
    "sqli": "BPSQLI",
    "ssrf": "https://bp-oob.invalid",
    "lfi": "../../../../etc/passwd",
    "redirect": "https://bp-redirect.invalid",
    "rce": "$(id)",
    "ssti": "{{7*7}}",
}
_HIGH_RISK_PARAM_NAMES = frozenset({
    "id", "ids", "uid", "user", "user_id", "account", "account_id", "role",
    "redirect", "next", "url", "dest", "destination", "return", "returnurl", "callback",
    "file", "path", "template", "doc", "download",
    "token", "jwt", "auth", "session", "sid", "api_key", "key",
})
_AUTH_KEYWORDS = ("login", "signin", "sign-in", "signup", "register", "auth", "session", "password", "2fa", "otp")
_NOTFOUND_KEYWORDS = ("not found", "404", "page not found", "cannot be found", "doesn't exist")
_SPA_SHELL_KEYWORDS = ("app-root", "id=\"root\"", "id='root'", "id=\"app\"", "ng-version", "__next_data__", "data-reactroot")
_FORM_ACTION_KEYWORDS = ("register", "login", "signup", "submit", "save", "update", "create", "delete")


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


def _templated_path(path: str) -> str:
    parts = []
    for seg in (path or "/").split("/"):
        if not seg:
            continue
        low = seg.lower()
        if seg.isdigit():
            parts.append("{id}")
        elif re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", low):
            parts.append("{uuid}")
        elif re.fullmatch(r"[0-9a-f]{16,}", low):
            parts.append("{hex}")
        elif re.fullmatch(r"[a-z0-9_-]{20,}", low):
            parts.append("{slug}")
        else:
            parts.append(seg)
    return "/" + "/".join(parts) if parts else "/"


def _attr_dict(raw_attrs: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in _RX_ATTR.findall(raw_attrs or ""):
        val = (v or "").strip().strip("\"'").strip()
        if k:
            out[k.lower()] = html.unescape(val)
    return out


def _short_text(value: str, limit: int = 180) -> str:
    txt = re.sub(r"\s+", " ", str(value or "")).strip()
    return txt[:limit] + ("…" if len(txt) > limit else "")


def _extract_html_title(body_text: str) -> str:
    m = _RX_HTML_TITLE.search(body_text or "")
    if not m:
        return ""
    return _short_text(html.unescape(m.group(1)), 140)


def _framework_hints_from_html(body_text: str) -> list[str]:
    low = (body_text or "").lower()
    hints: list[str] = []
    if any(x in low for x in ("react", "data-reactroot", "__next_data__", "next/router")):
        hints.append("react")
    if any(x in low for x in ("angular", "ng-version", "ng-app", "mat-input", "mat-select")):
        hints.append("angular")
    if any(x in low for x in ("vue", "nuxt", "data-v-")):
        hints.append("vue")
    if "svelte" in low:
        hints.append("svelte")
    if "mat-input" in low or "mat-select" in low:
        hints.append("angular-material")
    return sorted(set(hints))


def _extract_form_artifacts(page_url: str, body_text: str, framework_hints: list[str]) -> tuple[list[dict], list[dict]]:
    forms: list[dict] = []
    action_rows: list[dict] = []
    lower_body = (body_text or "").lower()
    discovered_action_guesses: set[str] = set()

    for m in _RX_FORM_BLOCK.finditer(body_text or ""):
        attrs = _attr_dict(m.group("attrs") or "")
        method = (attrs.get("method") or "GET").upper()
        action_attr = attrs.get("action") or ""
        action_guess = urllib.parse.urljoin(page_url, action_attr) if action_attr else page_url
        fields: list[str] = []
        for im in _RX_TAG_INPUT.finditer(m.group("body") or ""):
            iattrs = _attr_dict(im.group("attrs") or "")
            name = (iattrs.get("name") or iattrs.get("id") or iattrs.get("placeholder") or "").strip()
            if name:
                fields.append(name[:64])
        submit_selector = ""
        for bm in _RX_TAG_BUTTON.finditer(m.group("body") or ""):
            battrs = _attr_dict(bm.group("attrs") or "")
            label = _short_text(html.unescape(re.sub(r"<[^>]+>", " ", bm.group("label") or "")), 48).lower()
            btype = (battrs.get("type") or "").lower()
            if btype == "submit" or any(k in label for k in _FORM_ACTION_KEYWORDS):
                submit_selector = battrs.get("id") or battrs.get("name") or label or "button"
                break
        form_row = {
            "page_url": page_url,
            "action_guess": action_guess,
            "method": method,
            "fields": sorted(set(fields))[:40],
            "submit_selector": submit_selector,
            "framework_hints": framework_hints,
            "kind": "html_form",
        }
        forms.append(form_row)
        if action_guess and action_guess not in discovered_action_guesses:
            discovered_action_guesses.add(action_guess)
            action_rows.append({"url": action_guess, "source": "form_action", "method": method})

    input_tags = list(_RX_TAG_INPUT.finditer(body_text or ""))
    button_tags = list(_RX_TAG_BUTTON.finditer(body_text or ""))
    if len(forms) == 0 and len(input_tags) >= 2 and len(button_tags) > 0:
        fields = []
        for im in input_tags[:30]:
            attrs = _attr_dict(im.group("attrs") or "")
            name = (attrs.get("name") or attrs.get("id") or attrs.get("placeholder") or "").strip()
            if name:
                fields.append(name[:64])
        submit_selector = ""
        action_label = ""
        for bm in button_tags:
            battrs = _attr_dict(bm.group("attrs") or "")
            label = _short_text(html.unescape(re.sub(r"<[^>]+>", " ", bm.group("label") or "")), 48).lower()
            if any(k in label for k in _FORM_ACTION_KEYWORDS):
                submit_selector = battrs.get("id") or battrs.get("name") or label or "button"
                action_label = label
                break
        if fields and submit_selector:
            method = "POST" if any(k in action_label for k in ("save", "create", "update", "delete", "register", "signup")) else "GET"
            forms.append({
                "page_url": page_url,
                "action_guess": page_url,
                "method": method,
                "fields": sorted(set(fields))[:40],
                "submit_selector": submit_selector,
                "framework_hints": framework_hints,
                "kind": "virtual_form",
            })
            action_rows.append({"url": page_url, "source": "form_action", "method": method})

    if len(forms) == 0 and any(k in lower_body for k in _SPA_SHELL_KEYWORDS):
        forms.append({
            "page_url": page_url,
            "action_guess": page_url,
            "method": "GET",
            "fields": [],
            "submit_selector": "",
            "framework_hints": framework_hints,
            "kind": "spa_shell",
        })

    return forms, action_rows


def canonicalize_url(url: str, default_scheme: str = "https") -> dict:
    raw_url = (url or "").strip()
    if not raw_url:
        return {"raw_url": "", "normalized_url": "", "templated_url": "", "host": "", "path": "/", "query_pairs": []}
    cleaned = re.sub(r"#.*$", "", raw_url)
    if not cleaned:
        return {"raw_url": raw_url, "normalized_url": "", "templated_url": "", "host": "", "path": "/", "query_pairs": []}
    if cleaned.startswith("/"):
        norm_path = re.sub(r"/{2,}", "/", cleaned) or "/"
        return {
            "raw_url": raw_url,
            "normalized_url": norm_path,
            "templated_url": _templated_path(norm_path),
            "host": "",
            "path": norm_path,
            "query_pairs": sorted(urllib.parse.parse_qsl(urllib.parse.urlsplit(norm_path).query, keep_blank_values=True)),
        }
    prepared = raw_url
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", prepared):
        prepared = f"{default_scheme}://{prepared.lstrip('/')}"
    try:
        parsed = urllib.parse.urlsplit(prepared)
    except Exception:
        return {"raw_url": raw_url, "normalized_url": cleaned, "templated_url": cleaned, "host": "", "path": "/", "query_pairs": []}
    scheme = (parsed.scheme or default_scheme).lower()
    host = (parsed.hostname or parsed.netloc or "").lower()
    port = parsed.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    netloc = host if not port else f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parsed.path or "/") or "/"
    query_pairs = sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query = urllib.parse.urlencode(query_pairs, doseq=True)
    normalized = urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
    return {
        "raw_url": raw_url,
        "normalized_url": normalized,
        "templated_url": urllib.parse.urlunsplit((scheme, netloc, _templated_path(path), "", "")),
        "host": host,
        "path": path,
        "query_pairs": query_pairs,
    }


def normalize_url_for_output(url: str) -> str:
    return canonicalize_url(url).get("normalized_url", "")


def template_url_path(url: str) -> str:
    u = normalize_url_for_output(url)
    if not u:
        return ""
    parsed = urllib.parse.urlsplit(u)
    templated_path = _templated_path(parsed.path or "/")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, templated_path, "", ""))


def classify_param_name(name: str) -> list[str]:
    n = (name or "").strip().lower()
    hints = []
    if not n:
        return hints
    if any(k in n for k in ["id", "uid", "account", "user", "order", "doc"]):
        hints.append("id_like")
    if any(k in n for k in ["redirect", "return", "next", "callback", "url", "dest"]):
        hints.append("redirect_like")
    if any(k in n for k in ["file", "path", "template", "download", "folder"]):
        hints.append("file_like")
    if any(k in n for k in ["token", "jwt", "auth", "session", "key", "secret"]):
        hints.append("auth_like")
    if any(k in n for k in ["q", "query", "search", "filter", "sort", "page", "limit", "offset", "cursor"]):
        hints.append("search_like")
    return hints


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


def calculate_entropy(data: str) -> float:
    if not data:
        return 0.0
    occ = {c: data.count(c) for c in set(data)}
    entropy = 0.0
    for count in occ.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy


def _download_js(url: str, output_path: Path, timeout: int = 12) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": random.choice(_JS_USER_AGENTS)})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            content = r.read().decode("utf-8", errors="ignore")
            output_path.write_text(content, encoding="utf-8")
            return True
    except Exception:
        return False


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
    def __init__(self):
        self.stats: dict[str, int] = {}
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def stage_start(self, stage: str) -> None:
        log(f"[*] Stage: {stage} [STARTED]")
    def stage_done(self, stage: str, duration: float) -> None:
        log(f"[*] Stage: {stage} [DONE] in {duration:.1f}s")
    def set_stats(self, stats: dict[str, int]) -> None:
        self.stats.update(stats)
    def set_context(self, **kwargs) -> None: ...
    def add_event(self, text: str) -> None:
        log(f"[*] Event: {text}")



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
        self.parallel_tasks: dict[str, Any] = {}

        self.stats = {
            "subdomains": 0, "live_hosts": 0, "endpoints": 0, "params": 0,
            "nuclei_findings": 0, "hosts_401_403": 0, "legacy_hosts": 0,
            "throttled_hosts": 0, "skipped_hosts": 0,
            "resolved": 0, "subfinder_count": 0, "assetfinder_count": 0,
            "probed_hosts": 0, "nuclei_findings_phase1": 0, "nuclei_findings_phase2": 0, "secrets_findings": 0, "takeover_findings": 0,
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
        
        main_layout = Layout()
        main_layout.split_column(
            Layout(name="header", size=7),
            Layout(name="status", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=10)
        )

        # Header: Logo & System Stats
        header_table = Table.grid(expand=True)
        header_table.add_column(ratio=1)
        header_table.add_column(justify="right")
        sys_table = Table.grid(expand=True)
        sys_table.add_column()
        sys_table.add_column(justify="right")
        sys_table.add_row("THREADS", Text(str(self.parallel), style="bold cyan"))
        sys_table.add_row("WAF_STATUS", Text("ADAPTIVE" if self.context.get("waf_detected") else "CLEAN", style="bold yellow"))
        sys_table.add_row("UPTIME", Text(f"{int(time.monotonic() - self.run_started_at)}s", style="bold green"))
        header_table.add_row(
            Text(HACKER_LOGO, style="bold green", justify="left"),
            Panel(sys_table, title="[SYS]", border_style="dim")
        )
        main_layout["header"].update(header_table)

        # Status: Core Pipeline Info
        status_line = Table.grid(expand=True)
        status_line.add_column(ratio=1)
        status_line.add_row(
            Text.assemble(
                (" TARGET ", "bold black on cyan"), (f" {self.target} ", "bold cyan"), ("  "),
                (" STAGE ", "bold black on magenta"), (f" {self.current_stage} ", "bold magenta"), ("  "),
                (" MODE ", "bold black on yellow"), (f" {self.context.get('run_mode', '--run')} ", "bold yellow"), ("  "),
                (" DIR ", "bold black on blue"), (f" {self._truncate(str(self.context.get('output_dir', '-')), 30)} ", "bold blue")
            )
        )
        main_layout["status"].update(Panel(status_line, border_style="dim", box=box.HORIZONTALS))

        # Body: Split into Progress (Left) and Telemetry (Right)
        main_layout["body"].split_row(
            Layout(name="progress", ratio=2),
            Layout(name="telemetry", ratio=3)
        )

        # Progress Section
        progress_panel = Panel(
            self.progress,
            title="[PIPELINE_ENGINE]", 
            border_style="cyan",
            padding=(1, 2)
        )
        main_layout["body"]["progress"].update(progress_panel)

        # Telemetry: Triage & Real-time Info
        triage = self._render_triage()
        mission = self._render_mission()
        telemetry_table = Table.grid(expand=True)
        telemetry_table.add_column(ratio=1)
        telemetry_table.add_column(ratio=1)
        telemetry_table.add_row(
            Panel(triage, title="[FINDINGS/METRICS]", border_style="green", padding=(0, 1)),
            Panel(mission, title="[ACTIVE_TASK_CONTEXT]", border_style="magenta", padding=(0, 1))
        )
        main_layout["body"]["telemetry"].update(telemetry_table)

        # Footer: Live Event Log
        event_list = list(self.events)
        event_content = Text("\n").join(event_list) if event_list else Text("Waiting for incoming telemetry...", style="dim italic")
        main_layout["footer"].update(Panel(event_content, title="[REALTIME_LOG]", border_style="yellow", subtitle=f"v{SCHEMA_VERSION} • {self.last_update}"))
        return main_layout
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
        sys.stdout.flush()



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
    subfinder_timeout: int = 600
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
    xnlinkfinder_timeout: int = 300
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

    skip_secrets: bool = False
    skip_takeover: bool = False

    naabu_ports: str = "80,443,8080,8443,8888,8008,9090,9443,3000,4000,5000,6000,7000,8000,9000,9200,9300,10000,27017,3306,5432,6379"
    naabu_rate: int = 1000
    naabu_timeout: int = 300
    naabu_top_ports: str = ""
    skip_portscan: bool = False
    dns_bruteforce_timeout: int = 600
    dns_bruteforce_mode: str = "auto"  # auto|puredns|dnsx
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
    screenshots_timeout: int = 60
    output_format: str = "md"
    debug_artifacts: bool = False
    max_report_files: int = 12
    url_revalidate_timeout: int = 8
    url_revalidate_workers: int = 20
    url_revalidate_cap: int = 2000
    url_revalidate_get_cap: int = 600
    url_revalidate_body_max: int = 200000
    gf_bucket_cap: int = 2000


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
    gf: str = "github.com/tomnomnom/gf@latest"
    qsreplace: str = "github.com/tomnomnom/qsreplace@latest"


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
    "dnsx", "takeover", "httpx", "vhost_fuzz", "portscan", "screenshots",
    "discovery_dirsearch", "discovery_ffuf_dirs", "discovery_ffuf_files", "discovery",
    "bypass_403", "graphql", "urls", "param_discovery",
    "tech", "tech_host_mapping", "nuclei_phase1", "xss_scan", "secrets", "github_dork",
    "nuclei_phase2", "endpoint_ranking",
]

# PIPELINE_STAGES is the user-facing dashboard pipeline order (top-level stages only).
PIPELINE_STAGES = [
    "osint", "nuclei_templates", "subdomains", "dns_bruteforce", "dnsx", "takeover",
    "httpx", "vhost_fuzz", "portscan", "screenshots", "discovery", "bypass_403", "graphql",
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
    def __init__(self, target: str, workdir: Path, parallel: int, config: ReconConfig | None = None, dashboard: NullDashboard | HackerDashboard | None = None, *, skip_nuclei: bool = False, skip_gau: bool = False, skip_secrets: bool = False, skip_takeover: bool = False, force_update_templates: bool = False, nuclei_severity: str = "", nuclei_tags: str = ""):
        self.target = normalize_target(target)
        self.workdir = workdir
        self.parallel = parallel
        self.config = config or ReconConfig()
        self.dashboard = dashboard or NullDashboard()
        self.skip_nuclei = skip_nuclei
        self.skip_gau = skip_gau
        self.skip_secrets = bool(skip_secrets or self.config.skip_secrets)
        self.skip_takeover = bool(skip_takeover or self.config.skip_takeover)

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
        self.waf_detected: bool = False
        self.raw = workdir / "raw"
        self.commands_md = workdir / "COMMANDS_USED.md"
        self.command_log_jsonl = self.logs / "command_log.jsonl"
        self.stats = getattr(self.dashboard, "stats", {})
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
        self._latest_stage_status: dict[str, dict] = {}
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
        self.xnlinkfinder_bin = resolve_tool("xnLinkFinder") or resolve_tool("xnlinkfinder")
        self.gf_bin = resolve_tool("gf")
        self.qsreplace_bin = resolve_tool("qsreplace")
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
        self._latest_stage_status[stage] = row
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
        self._latest_stage_status[stage] = row
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
        self.write_md_report(reports / "vuln_surface.md", f"Vulnerability Surface — {self.target}", [_json_lines(self.intel / "bypass_403_findings.json", "403 Bypass"), _json_lines(self.intel / "xss_findings.json", "XSS"), _json_lines(self.intel / "graphql_findings.json", "GraphQL")])

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
            ("urls/xnlinkfinder_urls.txt", self.urls / "xnlinkfinder_urls.txt"),
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
        subfinder_rc = None
        subfinder_mode = "all"
        if self.subfinder_bin:
            subfinder_log = self.logs / "subfinder.stderr.log"
            result = self.run_tool(
                "subfinder",
                [self.subfinder_bin, "-d", self.target, "-all", "-silent"],
                timeout=self.config.subfinder_timeout,
                stdout_path=subfinder_txt,
                stderr_path=subfinder_log,
                allow_failure=True,
            )
            subfinder_rc = result.returncode
            # If the expansive provider sweep timed out before yielding anything useful,
            # retry once in default mode to salvage a broad but faster baseline.
            if result.returncode == 124 and self._count_lines(subfinder_txt) == 0:
                subfinder_mode = "default"
                result = self.run_tool(
                    "subfinder fallback",
                    [self.subfinder_bin, "-d", self.target, "-silent"],
                    timeout=max(120, min(self.config.subfinder_timeout, 300)),
                    stdout_path=subfinder_txt,
                    stderr_path=subfinder_log,
                    allow_failure=True,
                )
                subfinder_rc = result.returncode
        self.dashboard.set_context(source_running="assetfinder", subtask_done=1, subtask_total=2)
        if self.assetfinder_bin:
            self.run_tool("assetfinder", [self.assetfinder_bin, "--subs-only", self.target], timeout=self.config.assetfinder_timeout, stdout_path=assetfinder_txt, stderr_path=self.logs / "assetfinder.stderr.log", allow_failure=True)
        lines = sorted({self.target} | {x.strip() for x in (subfinder_txt.read_text(encoding='utf-8', errors='ignore') + "\n" + assetfinder_txt.read_text(encoding='utf-8', errors='ignore')).splitlines() if x.strip()})
        all_subdomains.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        if lines:
            for s in list(lines)[:8]:
                self.dashboard.add_event(f"Discovery: host {s}")
        self.dashboard.set_context(source_running="merge complete", subtask_done=2, subtask_total=2)
        self.record_stage_status("subdomains", "completed", "merged passive subdomain sources", metrics={
            "subfinder_count": self._count_lines(subfinder_txt),
            "assetfinder_count": self._count_lines(assetfinder_txt),
            "total_subdomains": len(lines),
            "subfinder_mode": subfinder_mode,
            "subfinder_returncode": subfinder_rc if subfinder_rc is not None else 0,
        })
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
            self.record_stage_status("dnsx", "completed", detail, metrics={
                "resolved_hosts": len(uniq_hosts),
                "mapped_hosts": len(mp),
            })
            self.dashboard.set_context(source_running="dnsx complete", subtask_done=1, subtask_total=1)
        else:
            lines_local = [x.strip() for x in all_subdomains.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
            resolved.write_text("\n".join(lines_local) + ("\n" if lines_local else ""), encoding="utf-8")
            host_ip_map.write_text("{}", encoding="utf-8")
            self.record_stage_status("dnsx", "fallback", "dnsx missing; copied subdomains as resolved hosts", metrics={
                "resolved_hosts": len(lines_local),
                "mapped_hosts": 0,
            })
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
            waf_keywords = {"cloudflare", "akamai", "sucuri", "imperva", "incapsula", "f5", "barracuda", "fortiweb", "aws waf", "azure waf"}
            waf_count = 0
            for line in httpx_json.read_text(encoding="utf-8", errors="ignore").splitlines():
                try: obj = json.loads(line)
                except Exception: continue
                tech = " ".join(obj.get("tech") or []).lower()
                if any(kw in tech for kw in waf_keywords):
                    waf_count += 1
                key = (obj.get("url") or obj.get("input") or "").strip()
                if not key: continue
                self._httpx_cache[key] = {
                    "title": (obj.get("title") or "").lower(),
                    "tech": tech,
                    "status": int(obj.get("status_code") or 0),
                    "waf": any(kw in tech for kw in waf_keywords),
                }

            self.waf_detected = waf_count > (len(s_hosts) * 0.1)
            if self.waf_detected:
                self.dashboard.add_event(f"⚠️  WAF DETECTED on {waf_count} hosts. Auto-throttling active.")

            self.dashboard.set_context(httpx_buckets=f"2xx={buckets['2xx']} 3xx={buckets['3xx']} 401={buckets['401']} 403={buckets['403']} WAF={waf_count}", source_running="httpx complete")
            self.record_stage_status("httpx", "completed", f"single-pass httpx json; waf_detected={self.waf_detected}", metrics={
                "live_hosts": len(s_hosts),
                "waf_count": waf_count,
                "httpx_2xx": buckets["2xx"],
                "httpx_3xx": buckets["3xx"],
                "httpx_401": buckets["401"],
                "httpx_403": buckets["403"],
            })
        else:
            lines = [x.strip() for x in resolved.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
            live_hosts.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            self._httpx_cache = {}
            self.record_stage_status("httpx", "fallback", "httpx missing; reused resolved hosts", metrics={
                "live_hosts": len(lines),
            })
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
            max(1, self.config.dirsearch_workers // 2) if self.waf_detected else self.config.dirsearch_workers,
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
            max(1, self.config.ffuf_workers // 2) if self.waf_detected else self.config.ffuf_workers,
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
            max(1, self.config.ffuf_workers // 2) if self.waf_detected else self.config.ffuf_workers,
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

    def _load_json_items(self, path: Path) -> list[dict]:
        if not path.exists() or path.stat().st_size == 0:
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return []
        if isinstance(data, dict):
            items = data.get("items", [])
            return items if isinstance(items, list) else []
        return data if isinstance(data, list) else []

    def _source_confidence_base(self, sources: set[str]) -> int:
        score = 20
        if any(s in _LIVE_URL_SOURCES for s in sources):
            score += 35
        if "xnlinkfinder" in sources:
            score += 8
        if "form_action" in sources:
            score += 10
        if "js_extracted" in sources:
            score += 8
        if any(s.startswith("gf_") for s in sources):
            score += 10
        if "redirect_chain" in sources:
            score += 6
        if any(s in _ARCHIVE_URL_SOURCES for s in sources):
            score += 8
        if all(s in _ARCHIVE_URL_SOURCES for s in sources):
            score -= 12
        return max(1, min(100, score))

    def _discover_robots_and_sitemap(self, origins: list[str]) -> dict[str, list[str]]:
        out = {"robots": [], "sitemap": []}
        timeout = max(4, min(12, int(self.config.url_revalidate_timeout)))
        headers = {"User-Agent": random.choice(_JS_USER_AGENTS)}
        for origin in origins:
            if SHUTTING_DOWN:
                break
            base = origin.rstrip("/")
            robots_url = f"{base}/robots.txt"
            try:
                req = urllib.request.Request(robots_url, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    body = r.read(256000).decode("utf-8", errors="ignore")
                for ln in body.splitlines():
                    m = _RX_ROBOTS_ALLOW.match(ln)
                    if not m:
                        continue
                    path = (m.group(1) or "").strip()
                    if not path or path == "/" or path == "*":
                        continue
                    if not path.startswith("/"):
                        continue
                    out["robots"].append(urllib.parse.urljoin(base + "/", path))
                    if len(out["robots"]) >= 4000:
                        break
            except Exception:
                pass
            sitemap_candidates = [f"{base}/sitemap.xml"]
            for sitemap_url in sitemap_candidates:
                try:
                    req = urllib.request.Request(sitemap_url, headers=headers)
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        body = r.read(1024000).decode("utf-8", errors="ignore")
                    for loc in _RX_SITEMAP_LOC.findall(body):
                        u = str(loc).strip()
                        if u:
                            out["sitemap"].append(u)
                            if len(out["sitemap"]) >= 5000:
                                break
                except Exception:
                    continue
        out["robots"] = sorted(set(out["robots"]))
        out["sitemap"] = sorted(set(out["sitemap"]))
        return out

    def _extract_urls_from_blob(self, text: str) -> list[str]:
        urls: set[str] = set()
        for m in _RX_HTTP_URL.findall(text or ""):
            u = normalize_url_for_output(m.strip())
            if u:
                urls.add(u)
        stripped = (text or "").strip()
        if stripped.startswith("http://") or stripped.startswith("https://"):
            u = normalize_url_for_output(stripped.split()[0])
            if u:
                urls.add(u)
        return sorted(urls)

    def _run_xnlinkfinder(self, live_hosts: Path, out_file: Path) -> list[str]:
        if not self.xnlinkfinder_bin:
            return []
        if not live_hosts.exists() or live_hosts.stat().st_size == 0:
            return []
        self.run_tool(
            "xnLinkFinder",
            [self.xnlinkfinder_bin, "-i", str(live_hosts), "-o", str(out_file)],
            timeout=max(60, int(self.config.xnlinkfinder_timeout)),
            stdout_path=self.logs / "xnlinkfinder.stdout.log",
            stderr_path=self.logs / "xnlinkfinder.stderr.log",
            allow_failure=True,
        )
        if not out_file.exists():
            return []
        out: set[str] = set()
        for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            for u in self._extract_urls_from_blob(line):
                out.add(u)
        return sorted(out)

    def _build_vuln_url_buckets(self, urls_all_list: list[str], params_urls: list[str]) -> tuple[dict[str, list[str]], dict[str, set[str]]]:
        bucket_sets: dict[str, set[str]] = {name: set() for name in sorted(set(_GF_PATTERN_BUCKETS.values()))}
        source_tags_by_url: dict[str, set[str]] = {}
        corpus = sorted({normalize_url_for_output(u) for u in (urls_all_list + params_urls) if normalize_url_for_output(u)})
        corpus_file = self.urls / "gf_corpus.txt"
        corpus_file.write_text("\n".join(corpus) + ("\n" if corpus else ""), encoding="utf-8")
        if not corpus:
            self.write_json(self.intel / "vuln_url_buckets.json", {"total": 0, "buckets": {}, "generated_at": now_utc_iso()})
            return {}, {}

        # Use gf when available; fall back to heuristic patterning when gf is missing/patterns are absent.
        if self.gf_bin:
            for pattern, bucket in _GF_PATTERN_BUCKETS.items():
                out_path = self.cache / f"gf_{pattern}.txt"
                self.run_tool(
                    f"gf {pattern}",
                    [self.gf_bin, pattern, str(corpus_file)],
                    timeout=90,
                    stdout_path=out_path,
                    stderr_path=self.logs / f"gf_{pattern}.stderr.log",
                    allow_failure=True,
                )
                if out_path.exists() and out_path.stat().st_size > 0:
                    for line in out_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                        for u in self._extract_urls_from_blob(line):
                            bucket_sets[bucket].add(u)

        # Heuristic fill: ensures buckets stay useful even if gf patterns are unavailable.
        for raw in corpus:
            u = normalize_url_for_output(raw)
            if not u:
                continue
            parsed = urllib.parse.urlsplit(u)
            path_l = (parsed.path or "").lower()
            params_l = [k.lower() for k, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]
            hints = set()
            for p in params_l:
                hints.update(classify_param_name(p))

            if any(x in params_l for x in ("q", "s", "search", "query", "keyword", "term", "message", "comment", "text")):
                bucket_sets["xss"].add(u)
            if any(x in params_l for x in ("id", "uid", "user_id", "order", "sort", "where", "group", "filter")):
                bucket_sets["sqli"].add(u)
            if "redirect_like" in hints or any(x in params_l for x in ("url", "uri", "target", "dest", "destination", "callback", "next", "redirect", "return")):
                bucket_sets["ssrf"].add(u)
                bucket_sets["redirect"].add(u)
            if "file_like" in hints or any(x in params_l for x in ("file", "path", "template", "include", "download", "doc", "folder")):
                bucket_sets["lfi"].add(u)
            if any(x in params_l for x in ("cmd", "exec", "command", "shell", "code", "expression")):
                bucket_sets["rce"].add(u)
            if any(x in params_l for x in ("template", "view", "render", "fmt", "format")):
                bucket_sets["ssti"].add(u)
            if any(x in path_l for x in ("/graphql", "/graphiql", "/api", "/admin", "/debug")):
                bucket_sets["ssrf"].add(u)

        # qsreplace fuzz variants improve mutation-ready buckets.
        if self.qsreplace_bin:
            for bucket, payload in _GF_QSREPLACE_PAYLOADS.items():
                seeds = sorted({u for u in bucket_sets.get(bucket, set()) if "?" in u and "=" in u})
                if not seeds:
                    continue
                in_file = self.cache / f"qsreplace_{bucket}_in.txt"
                out_file = self.cache / f"qsreplace_{bucket}_out.txt"
                in_file.write_text("\n".join(seeds) + "\n", encoding="utf-8")
                cmd = f"{shlex.quote(self.qsreplace_bin)} {shlex.quote(payload)} < {shlex.quote(str(in_file))}"
                self.run_tool(
                    f"qsreplace {bucket}",
                    cmd,
                    timeout=90,
                    stdout_path=out_file,
                    stderr_path=self.logs / f"qsreplace_{bucket}.stderr.log",
                    allow_failure=True,
                )
                if out_file.exists() and out_file.stat().st_size > 0:
                    for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                        for u in self._extract_urls_from_blob(line):
                            bucket_sets[bucket].add(u)

        cap = max(200, int(self.config.gf_bucket_cap))
        buckets: dict[str, list[str]] = {}
        for bucket, values in bucket_sets.items():
            rows = sorted(values)[:cap]
            buckets[bucket] = rows
            out_file = self.urls / f"vuln_{bucket}.txt"
            out_file.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
            for u in rows:
                source_tags_by_url.setdefault(u, set()).add(f"gf_{bucket}")

        total = sum(len(v) for v in buckets.values())
        self.write_json(
            self.intel / "vuln_url_buckets.json",
            {
                "total": total,
                "generated_at": now_utc_iso(),
                "sources": {
                    "gf_enabled": bool(self.gf_bin),
                    "qsreplace_enabled": bool(self.qsreplace_bin),
                },
                "buckets": buckets,
            },
        )
        return buckets, source_tags_by_url

    def _revalidate_discovered_urls(self, entries: list[dict]) -> tuple[list[dict], list[dict], list[dict], list[str]]:
        if not entries:
            return [], [], [], []
        timeout = max(4, int(self.config.url_revalidate_timeout))
        workers = max(1, int(self.config.url_revalidate_workers))
        get_cap = max(1, int(self.config.url_revalidate_get_cap))
        body_max = max(1024, int(self.config.url_revalidate_body_max))
        headers = {"User-Agent": random.choice(_JS_USER_AGENTS)}

        def _probe(idx: int, row: dict) -> tuple[dict, list[dict], list[dict], str]:
            url = str(row.get("normalized_url") or "")
            if not url:
                return {}, [], [], ""
            archive_only = bool(row.get("archive_only"))
            method = "GET" if idx < get_cap else "HEAD"
            status = 0
            content_type = ""
            final_url = url
            title = ""
            body_hash = ""
            body_len = 0
            login_required = False
            soft404 = False
            waf_hints: list[str] = []
            framework_hints: list[str] = []
            forms: list[dict] = []
            form_actions: list[dict] = []
            error = ""
            try:
                req = urllib.request.Request(url, headers=headers, method=method)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    status = int(resp.getcode() or 0)
                    final_url = str(resp.geturl() or url)
                    hdr = resp.headers or {}
                    content_type = str(hdr.get("Content-Type") or "").split(";")[0].strip().lower()
                    header_blob = " ".join([f"{k}:{v}" for k, v in hdr.items()]).lower()
                    for kw in ("cloudflare", "akamai", "imperva", "sucuri", "incapsula", "aws waf", "azure front door", "f5"):
                        if kw in header_blob:
                            waf_hints.append(kw)
                    body_text = ""
                    if method == "GET":
                        raw = resp.read(body_max + 1)
                        if len(raw) > body_max:
                            raw = raw[:body_max]
                        body_len = len(raw)
                        body_hash = hashlib.sha256(raw).hexdigest()[:24] if raw else ""
                        body_text = raw.decode("utf-8", errors="ignore")
                        title = _extract_html_title(body_text)
                        framework_hints = _framework_hints_from_html(body_text)
                        is_html = "html" in content_type or "<html" in body_text.lower()
                        if is_html:
                            forms, form_actions = _extract_form_artifacts(final_url, body_text, framework_hints)
                        low = (title + " " + body_text[:3000]).lower()
                        login_required = status in (401, 403) or any(k in low for k in _AUTH_KEYWORDS)
                        soft404 = (
                            status in (200, 301, 302)
                            and any(k in low for k in _NOTFOUND_KEYWORDS)
                            and (urllib.parse.urlsplit(final_url).path or "/") not in ("/", "")
                        )
                    else:
                        login_required = status in (401, 403)
            except urllib.error.HTTPError as e:
                status = int(e.code or 0)
                final_url = str(getattr(e, "url", "") or url)
                content_type = str((e.headers or {}).get("Content-Type") or "").split(";")[0].strip().lower()
                login_required = status in (401, 403)
            except Exception as e:
                error = str(e)

            state = "dead"
            if soft404:
                state = "soft404"
            elif 200 <= status < 300:
                state = "live"
            elif 300 <= status < 400:
                state = "redirected"
            elif status in (401, 403) or login_required:
                state = "auth_walled"
            elif status <= 0:
                state = "dead"
            if archive_only and state in {"dead", "soft404"}:
                state = "stale"

            confidence = int(row.get("initial_confidence") or 30)
            if state == "live":
                confidence += 28
            elif state in {"redirected", "auth_walled"}:
                confidence += 18
            elif state == "stale":
                confidence -= 18
            elif state in {"dead", "soft404"}:
                confidence -= 24
            if form_actions:
                confidence += 8
            confidence = max(1, min(100, confidence))

            ctype_main = content_type or "unknown"
            fingerprint = f"{status}|{ctype_main}|{(title or '').strip().lower()[:80]}|{body_hash or body_len}"
            out_row = {
                "url": url,
                "final_url": final_url,
                "state": state,
                "status_code": status,
                "content_type": content_type,
                "title": title,
                "body_hash": body_hash,
                "body_length": body_len,
                "login_required_hint": login_required,
                "soft_404": soft404,
                "waf_cdn_hints": sorted(set(waf_hints)),
                "framework_fingerprints": sorted(set(framework_hints)),
                "sources": sorted(set(row.get("sources") or [])),
                "source_classes": sorted(set(row.get("source_classes") or [])),
                "archive_only": archive_only,
                "confidence": confidence,
                "param_names": sorted(set(row.get("param_names") or [])),
                "templated_url": row.get("templated_url") or template_url_path(url),
                "response_fingerprint": fingerprint,
                "error": _short_text(error, 200) if error else "",
            }
            redirect_url = final_url if final_url and final_url != url else ""
            return out_row, forms, form_actions, redirect_url

        revalidated: list[dict] = []
        forms_all: list[dict] = []
        form_actions_all: list[dict] = []
        redirect_urls: list[str] = []
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_probe, i, row): row for i, row in enumerate(entries)}
            for fut in as_completed(futs):
                if SHUTTING_DOWN:
                    break
                try:
                    row, forms, actions, redirect_url = fut.result()
                except Exception:
                    continue
                if row:
                    revalidated.append(row)
                if forms:
                    forms_all.extend(forms)
                if actions:
                    form_actions_all.extend(actions)
                if redirect_url:
                    redirect_urls.append(redirect_url)
        return revalidated, forms_all, form_actions_all, sorted(set(redirect_urls))

    def stage_urls(self):
        if self.is_done("urls"):
            return
        katana_urls = self.urls / "katana_urls.txt"
        gau_urls = self.urls / "gau_urls.txt"
        gospider_urls = self.urls / "gospider_urls.txt"
        hakrawler_urls = self.urls / "hakrawler_urls.txt"
        xnlinkfinder_urls = self.urls / "xnlinkfinder_urls.txt"
        urls_all = self.urls / "urls_all.txt"
        urls_params = self.urls / "urls_params.txt"
        urls_live = self.urls / "urls_live.txt"
        urls_archive = self.urls / "urls_archive.txt"
        discovered_json = self.intel / "urls_discovered.json"
        revalidated_json = self.intel / "urls_revalidated.json"
        forms_json = self.intel / "forms_discovered.json"
        workflow_json = self.intel / "browser_workflow_artifacts.json"
        endpoint_clusters_json = self.intel / "endpoint_clusters.json"
        fingerprints_json = self.intel / "response_fingerprints.json"
        response_clusters_json = self.intel / "response_clusters.json"
        vuln_buckets_json = self.intel / "vuln_url_buckets.json"
        inventory_json = self.intel / "recon_inventory.json"
        self.touch_files(katana_urls, gau_urls, gospider_urls, hakrawler_urls, xnlinkfinder_urls, urls_all, urls_params, urls_live, urls_archive)
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
        xn_urls = self._run_xnlinkfinder(live_hosts, xnlinkfinder_urls)

        discovered: dict[str, dict] = {}

        def add_url(raw_url: str, source: str, source_class: str, method: str = "GET") -> None:
            canon = canonicalize_url(raw_url)
            normalized = str(canon.get("normalized_url") or "").strip()
            if not normalized or any(p.search(normalized) for p in _FP_PATTERNS):
                return
            entry = discovered.setdefault(normalized, {
                "raw_urls": set(),
                "normalized_url": normalized,
                "templated_url": canon.get("templated_url") or template_url_path(normalized),
                "host": canon.get("host") or "",
                "path": canon.get("path") or "/",
                "query_pairs": list(canon.get("query_pairs") or []),
                "param_names": set(),
                "sources": set(),
                "source_classes": set(),
                "methods": set(),
            })
            entry["raw_urls"].add(str(raw_url).strip())
            entry["sources"].add(source)
            entry["source_classes"].add(source_class)
            entry["methods"].add((method or "GET").upper())
            for k, _ in (canon.get("query_pairs") or []):
                if k:
                    entry["param_names"].add(str(k).strip())

        for p, source, sclass in [
            (katana_urls, "crawl_live", "live"),
            (gospider_urls, "crawl_live", "live"),
            (hakrawler_urls, "crawl_live", "live"),
            (xnlinkfinder_urls, "xnlinkfinder", "live"),
            (gau_urls, "gau", "archive"),
        ]:
            if not p.exists():
                continue
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                u = line.strip()
                if not u:
                    continue
                add_url(u, source, sclass, "GET")
        for u in xn_urls:
            add_url(u, "xnlinkfinder", "live", "GET")

        js_paths_file = self.intel / "secrets_js_endpoints.txt"
        if js_paths_file.exists():
            host_bases = [x.strip() for x in live_hosts.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()] if live_hosts.exists() else []
            base = host_bases[0] if host_bases else f"https://{self.target}"
            for line in js_paths_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                path = line.strip()
                if not path:
                    continue
                if path.startswith("http://") or path.startswith("https://"):
                    add_url(path, "js_extracted", "live", "GET")
                else:
                    add_url(urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/")), "js_extracted", "live", "GET")

        live_origins = sorted({
            urllib.parse.urlunsplit((urllib.parse.urlsplit(h).scheme, urllib.parse.urlsplit(h).netloc, "", "", ""))
            for h in ([x.strip() for x in live_hosts.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()] if live_hosts.exists() else [])
            if urllib.parse.urlsplit(h).scheme and urllib.parse.urlsplit(h).netloc
        })
        aux = self._discover_robots_and_sitemap(live_origins[:250])
        for u in aux.get("robots") or []:
            add_url(u, "robots", "live", "GET")
        for u in aux.get("sitemap") or []:
            add_url(u, "sitemap", "live", "GET")

        # Vulnerability-focused buckets (reconftw-style gf/qsreplace technique).
        current_urls = sorted(discovered.keys())
        current_params = [u for u in current_urls if "?" in u and "=" in u]
        _, bucket_sources = self._build_vuln_url_buckets(current_urls, current_params)
        for url, tags in bucket_sources.items():
            for tag in sorted(tags):
                add_url(url, tag, "pattern_match", "GET")

        discovered_entries = list(discovered.values())
        for row in discovered_entries:
            sources = set(row.get("sources") or [])
            archive_only = bool(sources) and all(s in _ARCHIVE_URL_SOURCES for s in sources)
            row["archive_only"] = archive_only
            row["initial_confidence"] = self._source_confidence_base(sources)
            row["raw_url"] = sorted(row.get("raw_urls") or [""])[0] if row.get("raw_urls") else row.get("normalized_url")

        discovered_entries.sort(
            key=lambda r: (
                bool(r.get("archive_only")),
                -int(r.get("initial_confidence") or 0),
                str(r.get("normalized_url") or ""),
            )
        )
        cap = max(1, int(self.config.url_revalidate_cap))
        selected = discovered_entries[:cap]
        revalidated_rows, forms_rows, form_action_rows, redirect_urls = self._revalidate_discovered_urls(selected)
        for row in form_action_rows:
            add_url(str(row.get("url") or ""), "form_action", "workflow", str(row.get("method") or "POST"))
        for u in redirect_urls:
            add_url(u, "redirect_chain", "live", "GET")

        if len(revalidated_rows) < cap:
            already = {str(r.get("url") or "") for r in revalidated_rows}
            pending = []
            for row in discovered.values():
                u = str(row.get("normalized_url") or "")
                if u and u not in already:
                    sources = set(row.get("sources") or [])
                    row["archive_only"] = bool(sources) and all(s in _ARCHIVE_URL_SOURCES for s in sources)
                    row["initial_confidence"] = self._source_confidence_base(sources)
                    pending.append(row)
            pending.sort(key=lambda r: (bool(r.get("archive_only")), -int(r.get("initial_confidence") or 0), str(r.get("normalized_url") or "")))
            more_rows, more_forms, more_actions, _ = self._revalidate_discovered_urls(pending[: max(0, cap - len(revalidated_rows))])
            revalidated_rows.extend(more_rows)
            forms_rows.extend(more_forms)
            for row in more_actions:
                add_url(str(row.get("url") or ""), "form_action", "workflow", str(row.get("method") or "POST"))

        revalidated_map: dict[str, dict] = {}
        for row in revalidated_rows:
            url = str(row.get("url") or "")
            if not url:
                continue
            cur = revalidated_map.get(url)
            if cur is None or int(row.get("confidence") or 0) >= int(cur.get("confidence") or 0):
                revalidated_map[url] = row
        revalidated_rows = sorted(revalidated_map.values(), key=lambda r: (-int(r.get("confidence") or 0), str(r.get("url") or "")))

        discovered_items = []
        for u, row in sorted(discovered.items(), key=lambda x: x[0]):
            rv = revalidated_map.get(u, {})
            sources = sorted(set(row.get("sources") or []))
            source_classes = sorted(set(row.get("source_classes") or []))
            archive_only = bool(sources) and all(s in _ARCHIVE_URL_SOURCES for s in sources)
            discovered_items.append({
                "raw_url": sorted(row.get("raw_urls") or [u])[0],
                "raw_urls": sorted(row.get("raw_urls") or [])[:12],
                "normalized_url": u,
                "templated_url": row.get("templated_url") or template_url_path(u),
                "host": row.get("host") or "",
                "path": row.get("path") or "/",
                "param_names": sorted(set(row.get("param_names") or [])),
                "sources": sources,
                "source_classes": source_classes,
                "methods_seen": sorted(set(row.get("methods") or [])),
                "archive_only": archive_only,
                "initial_confidence": self._source_confidence_base(set(sources)),
                "validation_state": rv.get("state") or "unknown",
                "validation_confidence": int(rv.get("confidence") or 0),
            })

        urls_all_list = sorted(discovered.keys())
        params = sorted({u for u in urls_all_list if re.search(r"\?.+=", u)})
        live_urls = sorted({
            str(r.get("final_url") or r.get("url") or "")
            for r in revalidated_rows
            if str(r.get("state") or "") in {"live", "redirected", "auth_walled"}
        })
        archive_urls = sorted({it["normalized_url"] for it in discovered_items if it.get("archive_only")})

        endpoint_clusters: dict[str, dict] = {}
        for it in discovered_items:
            templ = str(it.get("templated_url") or "")
            if not templ:
                continue
            c = endpoint_clusters.setdefault(templ, {
                "templated_route": templ,
                "concrete_urls": [],
                "sources": set(),
                "states": {},
            })
            if len(c["concrete_urls"]) < 20:
                c["concrete_urls"].append(str(it.get("normalized_url") or ""))
            for src in it.get("sources") or []:
                c["sources"].add(src)
            st = str(it.get("validation_state") or "unknown")
            c["states"][st] = int(c["states"].get(st, 0)) + 1
        endpoint_cluster_rows = sorted(
            [{
                "templated_route": k,
                "concrete_count": len(v.get("concrete_urls") or []),
                "concrete_urls": sorted(set(v.get("concrete_urls") or []))[:20],
                "sources": sorted(v.get("sources") or []),
                "states": v.get("states") or {},
            } for k, v in endpoint_clusters.items()],
            key=lambda r: (-int(r.get("concrete_count") or 0), str(r.get("templated_route") or "")),
        )

        fingerprint_rows = [{
            "url": str(r.get("url") or ""),
            "final_url": str(r.get("final_url") or ""),
            "status_code": int(r.get("status_code") or 0),
            "content_type": str(r.get("content_type") or ""),
            "title": str(r.get("title") or ""),
            "body_hash": str(r.get("body_hash") or ""),
            "body_length": int(r.get("body_length") or 0),
            "response_fingerprint": str(r.get("response_fingerprint") or ""),
            "state": str(r.get("state") or ""),
        } for r in revalidated_rows]
        response_clusters: dict[str, dict] = {}
        for row in fingerprint_rows:
            key = str(row.get("response_fingerprint") or "")
            if not key:
                continue
            c = response_clusters.setdefault(key, {
                "response_fingerprint": key,
                "status_code": int(row.get("status_code") or 0),
                "content_type": str(row.get("content_type") or ""),
                "title": str(row.get("title") or ""),
                "count": 0,
                "sample_urls": [],
            })
            c["count"] += 1
            if len(c["sample_urls"]) < 15:
                c["sample_urls"].append(str(row.get("final_url") or row.get("url") or ""))
        response_cluster_rows = sorted(response_clusters.values(), key=lambda r: (-int(r.get("count") or 0), str(r.get("response_fingerprint") or "")))

        workflow_rows = []
        for form in forms_rows:
            method = str(form.get("method") or "GET").upper()
            submit_selector = str(form.get("submit_selector") or "")
            label_blob = (submit_selector + " " + str(form.get("action_guess") or "")).lower()
            workflow_rows.append({
                "page_url": str(form.get("page_url") or ""),
                "route": normalize_url_for_output(str(form.get("action_guess") or "")),
                "method": method,
                "fields": sorted(set(form.get("fields") or []))[:40],
                "kind": str(form.get("kind") or ""),
                "framework_hints": sorted(set(form.get("framework_hints") or [])),
                "auth_action": any(k in label_blob for k in ("login", "signin", "register", "signup", "auth")),
                "write_action": method != "GET" or any(k in label_blob for k in ("save", "create", "update", "delete")),
            })

        urls_all.write_text("\n".join(urls_all_list) + ("\n" if urls_all_list else ""), encoding="utf-8")
        urls_params.write_text("\n".join(params) + ("\n" if params else ""), encoding="utf-8")
        urls_live.write_text("\n".join(live_urls) + ("\n" if live_urls else ""), encoding="utf-8")
        urls_archive.write_text("\n".join(archive_urls) + ("\n" if archive_urls else ""), encoding="utf-8")

        self.write_json(discovered_json, {"total": len(discovered_items), "items": discovered_items})
        self.write_json(revalidated_json, {"total": len(revalidated_rows), "items": revalidated_rows})
        self.write_json(forms_json, {"total": len(forms_rows), "items": forms_rows})
        self.write_json(workflow_json, {"total": len(workflow_rows), "items": workflow_rows})
        self.write_json(endpoint_clusters_json, {"total": len(endpoint_cluster_rows), "items": endpoint_cluster_rows})
        self.write_json(fingerprints_json, {"total": len(fingerprint_rows), "items": fingerprint_rows})
        self.write_json(response_clusters_json, {"total": len(response_cluster_rows), "items": response_cluster_rows})
        if not vuln_buckets_json.exists():
            self.write_json(vuln_buckets_json, {"total": 0, "buckets": {}, "generated_at": now_utc_iso()})
        self.write_json(inventory_json, {
            "hosts_discovered": self._count_lines(self.workdir / "all_subdomains.txt"),
            "origins_live": len(live_origins),
            "urls_live": len(live_urls),
            "urls_archive": len(archive_urls),
            "params_ranked": self._count_lines(urls_params),
            "paths": {
                "hosts_discovered": str(self.workdir / "all_subdomains.txt"),
                "origins_live": str(live_hosts),
                "urls_live": str(urls_live),
                "urls_archive": str(urls_archive),
                "urls_discovered_json": str(discovered_json),
                "urls_revalidated_json": str(revalidated_json),
                "vuln_url_buckets_json": str(vuln_buckets_json),
            },
        })

        self.build_params_ranked(params)
        self.record_stage_status("urls", "completed", "url discovery + revalidation + clustering generated", metrics={
            "urls_discovered": len(discovered_items),
            "urls_revalidated": len(revalidated_rows),
            "urls_live": len(live_urls),
            "urls_archive": len(archive_urls),
            "urls_with_params": len(params),
            "forms": len(forms_rows),
            "workflow_artifacts": len(workflow_rows),
            "endpoint_clusters": len(endpoint_cluster_rows),
            "response_clusters": len(response_cluster_rows),
        })
        self.mark_done("urls")

    def build_params_ranked(self, urls_with_params: list[str]):
        juicy = {
            "id","ids","uid","user","user_id","account","acct","email","phone","token","access_token","refresh_token",
            "auth","jwt","session","sid","key","api_key","redirect","return","returnurl","next","callback","url","dest",
            "destination","continue","file","path","download","doc","document","template","view","q","s","search","query",
            "filter","sort","order","page","limit","offset","cursor","from","to","start","end","lang","locale","debug","test","role",
        }
        stats: dict[str, dict] = {}

        discovered_items = self._load_json_items(self.intel / "urls_discovered.json")
        forms_items = self._load_json_items(self.intel / "forms_discovered.json")
        revalidated_items = self._load_json_items(self.intel / "urls_revalidated.json")
        state_by_url = {str(x.get("url") or ""): str(x.get("state") or "unknown") for x in revalidated_items if str(x.get("url") or "")}

        def _entry(name: str) -> dict:
            return stats.setdefault(name, {
                "count": 0,
                "examples": [],
                "sources": set(),
                "source_classes": set(),
                "endpoint_templates": set(),
                "values": set(),
                "methods": set(),
                "hints": set(),
                "states": set(),
                "reasons": [],
            })

        def _add_param(param_name: str, *, normalized_url: str, templated_url: str, source_tags: list[str], source_classes: list[str], method: str, value: str = "", reason: str = "") -> None:
            k = (param_name or "").strip()
            if not k:
                return
            entry = _entry(k)
            entry["count"] += 1
            for s in source_tags:
                if s:
                    entry["sources"].add(str(s))
            for s in source_classes:
                if s:
                    entry["source_classes"].add(str(s))
            if method:
                entry["methods"].add(str(method).upper())
            if templated_url:
                entry["endpoint_templates"].add(templated_url)
            if normalized_url and normalized_url not in entry["examples"] and len(entry["examples"]) < 5:
                entry["examples"].append(normalized_url)
            if value and len(entry["values"]) < 7:
                entry["values"].add(str(value)[:80])
            for hint in classify_param_name(k):
                entry["hints"].add(hint)
            st = state_by_url.get(normalized_url)
            if st:
                entry["states"].add(st)
            if k.lower() in juicy:
                entry["reasons"].append("keyword matched juicy parameter shortlist")
            if classify_param_name(k):
                entry["reasons"].append("exploit hints derived from parameter name")
            if reason:
                entry["reasons"].append(reason)

        for item in discovered_items:
            normalized = str(item.get("normalized_url") or "").strip()
            if not normalized:
                continue
            canon = canonicalize_url(normalized)
            normalized = canon.get("normalized_url") or ""
            if not normalized:
                continue
            for k, v in canon.get("query_pairs") or []:
                _add_param(
                    k,
                    normalized_url=normalized,
                    templated_url=str(item.get("templated_url") or template_url_path(normalized)),
                    source_tags=[str(x) for x in (item.get("sources") or [])],
                    source_classes=[str(x) for x in (item.get("source_classes") or [])],
                    method="GET",
                    value=str(v),
                    reason="observed in discovered URL query string",
                )

        for raw in urls_with_params:
            canon = canonicalize_url(raw)
            normalized = canon.get("normalized_url") or ""
            if not normalized:
                continue
            for k, v in canon.get("query_pairs") or []:
                _add_param(
                    k,
                    normalized_url=normalized,
                    templated_url=canon.get("templated_url") or template_url_path(normalized),
                    source_tags=["urls"],
                    source_classes=["live"],
                    method="GET",
                    value=str(v),
                    reason="captured in urls_params corpus",
                )

        for form in forms_items:
            page_url = normalize_url_for_output(str(form.get("page_url") or ""))
            action_guess = normalize_url_for_output(str(form.get("action_guess") or "")) or page_url
            method = str(form.get("method") or "POST").upper()
            templated = template_url_path(action_guess or page_url)
            kind = str(form.get("kind") or "form")
            for fld in (form.get("fields") or []):
                name = str(fld).strip()
                if not name:
                    continue
                _add_param(
                    name,
                    normalized_url=action_guess or page_url,
                    templated_url=templated,
                    source_tags=["form_action"],
                    source_classes=["workflow"],
                    method=method,
                    reason=f"captured from {kind}",
                )

        arjun_json = self.cache / "arjun_params.json"
        if arjun_json.exists():
            try:
                arjun_data = json.loads(arjun_json.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                arjun_data = {}
            if isinstance(arjun_data, dict):
                for endpoint, params in arjun_data.items():
                    templated = template_url_path(endpoint)
                    for param in params or []:
                        k = str(param).strip()
                        if not k:
                            continue
                        _add_param(
                            k,
                            normalized_url=normalize_url_for_output(endpoint),
                            templated_url=templated,
                            source_tags=["arjun"],
                            source_classes=["live"],
                            method="GET",
                            reason="confirmed by active parameter discovery",
                        )

        out_md = self.intel / "params_ranked.md"
        out_json = self.intel / "params_ranked.json"
        if not stats:
            out_md.write_text("# Parameter Ranking (Readable)\n\n_No param URLs found._\n", encoding="utf-8")
            self.write_json(out_json, {"total_unique_params": 0, "top": []})
            return

        exploit_map = {"id_like": "idor", "redirect_like": "redirect", "file_like": "file-access", "auth_like": "auth", "search_like": "input-reflection"}
        ranked_rows = []
        for k, entry in stats.items():
            hints = sorted(entry["hints"])
            score = entry["count"] * 4
            if k.lower() in juicy:
                score += 18
            if k.lower() in _HIGH_RISK_PARAM_NAMES:
                score += 16
            score += min(20, len(entry["sources"]) * 6)
            score += min(14, len(entry["endpoint_templates"]) * 3)
            score += min(10, len(entry["methods"]) * 4)
            score += min(24, len(hints) * 8)
            if "workflow" in entry["source_classes"]:
                score += 10
            if "live" in entry["source_classes"]:
                score += 8
            if entry["source_classes"] and all(x == "archive" for x in entry["source_classes"]):
                score -= 8
            if "live" in entry["states"]:
                score += 8
            if "auth_walled" in entry["states"]:
                score += 4
            reasons = list(entry["reasons"])
            reasons.append(f"seen {entry['count']} time(s)")
            reasons.append(f"source coverage: {', '.join(sorted(entry['sources']))}")
            reasons.append(f"endpoint spread: {len(entry['endpoint_templates'])} template(s)")
            if entry["states"]:
                reasons.append(f"state coverage: {', '.join(sorted(entry['states']))}")
            ranked_rows.append({
                "param": k,
                "count": entry["count"],
                "sources": sorted(entry["sources"]),
                "source_classes": sorted(entry["source_classes"]),
                "endpoint_count": len(entry["endpoint_templates"]),
                "endpoint_templates": sorted(entry["endpoint_templates"])[:20],
                "examples": entry["examples"],
                "sample_values": sorted(entry["values"])[:5],
                "method_count": len(entry["methods"]),
                "methods": sorted(entry["methods"]),
                "hints": hints,
                "state_coverage": sorted(entry["states"]),
                "exploit_hints": sorted({exploit_map[h] for h in hints if h in exploit_map}),
                "juicy": k.lower() in juicy,
                "score": min(100, score),
                "reasons": reasons[:8],
            })
        ranked_rows.sort(key=lambda r: (-r["score"], -r["count"], r["param"]))
        md = ["# Parameter Ranking (Readable)\n\n"]
        md.append(f"- Total unique params: **{len(stats)}**\n")
        md.append(f"- High-signal params: **{sum(1 for r in ranked_rows if r['score'] >= 60)}**\n\n")
        for idx, row in enumerate(ranked_rows, 1):
            md.append(f"## {idx}. `{esc_md_pipe(row['param'])}` {'✅' if row['juicy'] else ''}\n")
            md.append(f"- Score: **{row['score']}**\n")
            md.append(f"- Count: **{row['count']}** | Endpoint templates: **{row['endpoint_count']}** | Methods: **{row['method_count']}**\n")
            if row['sources']:
                md.append(f"- Sources: `{esc_md_pipe(', '.join(row['sources']))}`\n")
            if row['source_classes']:
                md.append(f"- Source classes: `{esc_md_pipe(', '.join(row['source_classes']))}`\n")
            if row['exploit_hints']:
                md.append(f"- Exploit hints: `{esc_md_pipe(', '.join(row['exploit_hints']))}`\n")
            if row['state_coverage']:
                md.append(f"- Validation states: `{esc_md_pipe(', '.join(row['state_coverage']))}`\n")
            if row['reasons']:
                md.append("- Why it ranked:\n")
                for reason in row['reasons'][:5]:
                    md.append(f"  - {esc_md_pipe(reason)}\n")
            if row['sample_values']:
                md.append(f"- Sample values: `{esc_md_pipe(', '.join(row['sample_values']))}`\n")
            if row['examples']:
                md.append("- Examples:\n")
                for ex in row['examples'][:3]:
                    md.append(f"  - `{esc_md_pipe(ex[:200])}`\n")
            md.append("\n")
        out_md.write_text("".join(md), encoding="utf-8")
        self.write_json(out_json, {"total_unique_params": len(stats), "top": ranked_rows[:2000]})

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
            cmd = [self.nuclei_bin, "-l", str(live_hosts), "-severity", sev, "-tags", tags, "-silent", "-rl", str(self.config.nuclei_rate_limit), "-c", str(self.config.nuclei_concurrency), "-max-host-error", str(self.config.nuclei_max_host_error), "-timeout", str(self.config.nuclei_timeout), "-retries", str(self.config.nuclei_retries), "-jsonl", "-o", str(js)]
            if not self.nuclei_tags:
                cmd.append("-as") # Automatic tech-based scan
            self.run_tool("nuclei phase1 jsonl", cmd, timeout=960, allow_failure=True)
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
        ranked_items = ranked.get("items", ranked) if isinstance(ranked, dict) else ranked
        for item in (ranked_items or []):
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
            "s3_buckets": [b.get("name", "") for b in buckets_rows],
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

            js_cap = self.config.secrets_js_cap
            total_attempted = len(js_urls[:js_cap])
            log(f"[*] secrets: downloaded {downloaded}/{total_attempted} JS files ({total_attempted - downloaded} skipped)")

            seen_values: set[str] = set()
            js_endpoints_data: list[dict] = []
            seen_endpoints: set[str] = set()

            for fp in sorted(tmp_dir.glob("*.js")):
                try:
                    with fp.open("r", encoding="utf-8", errors="ignore") as f:
                        for i, line in enumerate(f, 1):
                            line_s = line.rstrip("\n")
                            for rx in (_RX_AWS_KEY, _RX_AWS_SECRET, _RX_API_KEY, _RX_BEARER, _RX_GENERIC_SECRET, _RX_JWT):
                                for m in rx.finditer(line_s):
                                    val = m.group(0)[:120]
                                    if len(val) >= 12 and calculate_entropy(val) > 3.5:
                                        if val not in seen_values:
                                            seen_values.add(val)
                                            display = line_s[:300] + ("…" if len(line_s) > 300 else "")
                                            findings.append(f"{fp.name}:{i}: {display}")
                                    break
                            for m in _RX_JS_PATH.finditer(line_s):
                                path = m.group(1)
                                if path not in seen_endpoints:
                                    seen_endpoints.add(path)
                                    js_endpoints_data.append({
                                        "url": path,
                                        "source": fp.name,
                                        "params": []
                                    })
                            for m in _RX_BUCKET_HOST.finditer(line_s):
                                buckets.add(m.group(1))
                            for m in _RX_BUCKET_URI.finditer(line_s):
                                buckets.add(m.group(1))
                except Exception:
                    continue

            quick_hits_file.write_text("\n".join(findings) + ("\n" if findings else ""), encoding="utf-8")
            buckets_file.write_text("\n".join(sorted(buckets)) + ("\n" if buckets else ""), encoding="utf-8")
            if js_endpoints_data:
                ep_json = intel / "js_endpoints.json"
                self.write_json(ep_json, js_endpoints_data)
                ep_txt = intel / "secrets_js_endpoints.txt"
                ep_txt.write_text("\n".join(sorted([it["url"] for it in js_endpoints_data])) + "\n", encoding="utf-8")
                log(f"[*] secrets: extracted {len(js_endpoints_data)} JS endpoint paths → {ep_json}")

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
                self.add_finding("secrets", "HIGH", self.target, "Potential secret exposure", evidence=str(f)[:300], confidence=70, tags=["secrets"])
            self.mark_done("secrets")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def stage_endpoint_ranking(self):
        if self.is_done("endpoint_ranking"):
            return
        out_md = self.intel / "endpoints_ranked.md"
        out_json = self.intel / "endpoints_ranked.json"
        discovered_items = self._load_json_items(self.intel / "urls_discovered.json")
        revalidated_items = self._load_json_items(self.intel / "urls_revalidated.json")
        workflow_items = self._load_json_items(self.intel / "browser_workflow_artifacts.json")
        response_clusters = self._load_json_items(self.intel / "response_clusters.json")
        endpoint_clusters = self._load_json_items(self.intel / "endpoint_clusters.json")
        vuln_bucket_map: dict[str, list[str]] = {}
        vuln_bucket_json = self.intel / "vuln_url_buckets.json"
        if vuln_bucket_json.exists():
            try:
                payload = json.loads(vuln_bucket_json.read_text(encoding="utf-8", errors="ignore"))
                buckets = payload.get("buckets", {}) if isinstance(payload, dict) else {}
                if isinstance(buckets, dict):
                    for bucket_name, urls in buckets.items():
                        if not isinstance(urls, list):
                            continue
                        for item in urls:
                            u = normalize_url_for_output(str(item or ""))
                            if not u:
                                continue
                            vuln_bucket_map.setdefault(u, []).append(str(bucket_name))
            except Exception:
                vuln_bucket_map = {}
        params_payload = {}
        params_ranked_json = self.intel / "params_ranked.json"
        if params_ranked_json.exists():
            try:
                params_payload = json.loads(params_ranked_json.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                params_payload = {}
        params_top = params_payload.get("top", []) if isinstance(params_payload, dict) else []
        param_score = {str(p.get("param") or ""): int(p.get("score") or 0) for p in params_top if isinstance(p, dict)}

        cluster_size_by_fingerprint = {
            str(c.get("response_fingerprint") or ""): int(c.get("count") or 0)
            for c in response_clusters if isinstance(c, dict)
        }
        templated_cluster_count = {
            str(c.get("templated_route") or ""): int(c.get("concrete_count") or 0)
            for c in endpoint_clusters if isinstance(c, dict)
        }

        revalidated_by_url: dict[str, dict] = {}
        for r in revalidated_items:
            if not isinstance(r, dict):
                continue
            u = normalize_url_for_output(str(r.get("url") or ""))
            if not u:
                continue
            revalidated_by_url[u] = r
            fu = normalize_url_for_output(str(r.get("final_url") or ""))
            if fu and fu not in revalidated_by_url:
                revalidated_by_url[fu] = r

        workflow_by_route: dict[str, list[dict]] = {}
        for row in workflow_items:
            if not isinstance(row, dict):
                continue
            route = normalize_url_for_output(str(row.get("route") or row.get("page_url") or ""))
            if route:
                workflow_by_route.setdefault(route, []).append(row)

        candidates: dict[str, dict] = {}

        def _cand(url: str) -> dict:
            norm = normalize_url_for_output(url)
            if not norm:
                return {}
            return candidates.setdefault(norm, {
                "url": norm,
                "templated_route": template_url_path(norm),
                "sources": set(),
                "source_classes": set(),
                "methods": set(),
                "param_names": set(),
            })

        for item in discovered_items:
            if not isinstance(item, dict):
                continue
            u = str(item.get("normalized_url") or "")
            c = _cand(u)
            if not c:
                continue
            for s in (item.get("sources") or []):
                c["sources"].add(str(s))
            for s in (item.get("source_classes") or []):
                c["source_classes"].add(str(s))
            for m in (item.get("methods_seen") or []):
                c["methods"].add(str(m).upper())
            for p in (item.get("param_names") or []):
                c["param_names"].add(str(p).strip())
            c["templated_route"] = str(item.get("templated_url") or c["templated_route"])

        if not candidates:
            # Fallback: basic ranking from urls_all if stage_urls produced no JSON.
            urls_all = self.urls / "urls_all.txt"
            for u in [x.strip() for x in urls_all.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()] if urls_all.exists() else []:
                c = _cand(u)
                if c:
                    c["sources"].add("urls")
                    c["source_classes"].add("live")
                    for k, _ in (canonicalize_url(u).get("query_pairs") or []):
                        c["param_names"].add(k)

        ranked_rows: list[dict] = []
        static_ext_rx = re.compile(r"\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|pdf|zip|gz|rar|7z)$", re.I)
        risky_endpoint_keywords = ("admin", "debug", "internal", "api", "graphql", "swagger", "upload", "export", "import", "login", "auth")
        for u, c in candidates.items():
            reasons: list[str] = []
            score = score_endpoint_url(u)
            rv = revalidated_by_url.get(u, {})
            state = str(rv.get("state") or "unknown")
            status = int(rv.get("status_code") or 0)
            title = str(rv.get("title") or "").lower()
            ctype = str(rv.get("content_type") or "").lower()
            fp = str(rv.get("response_fingerprint") or "")

            if state == "live":
                score += 30
                reasons.append("live_validated")
            elif state == "redirected":
                score += 20
                reasons.append("redirected_live")
            elif state == "auth_walled":
                score += 16
                reasons.append("auth_adjacent_route")
            elif state == "stale":
                score -= 14
                reasons.append("archive_only_stale")
            elif state in {"dead", "soft404"}:
                score -= 22
                reasons.append(state)

            sources = set(c["sources"])
            source_classes = set(c["source_classes"])
            if "crawl_live" in sources:
                score += 12
                reasons.append("seen_in_live_crawl")
            if "form_action" in sources:
                score += 14
                reasons.append("seen_in_form_workflow")
            if "js_extracted" in sources:
                score += 10
                reasons.append("seen_in_js")
            if "xnlinkfinder" in sources:
                score += 9
                reasons.append("seen_in_xnlinkfinder")
            gf_hits = sorted({s.replace("gf_", "", 1) for s in sources if s.startswith("gf_")})
            if gf_hits:
                score += min(18, 5 * len(gf_hits))
                reasons.append("gf_pattern_match")
            if "redirect_chain" in sources:
                score += 6
                reasons.append("redirect_chain")
            if sources and all(s in _ARCHIVE_URL_SOURCES for s in sources):
                score -= 10
                reasons.append("archive_only")
            if "js_extracted" in sources and "crawl_live" in sources:
                score += 8
                reasons.append("seen_in_js_and_live")
            if "pattern_match" in source_classes:
                score += 6
                reasons.append("pattern_matched_surface")
            templated = str(c.get("templated_route") or template_url_path(u))
            matched_buckets = sorted(set(vuln_bucket_map.get(u, []) + vuln_bucket_map.get(templated, [])))
            if matched_buckets:
                score += min(20, 6 * len(matched_buckets))
                reasons.append("vuln_bucket_signal")
                if any(b in {"ssrf", "sqli", "rce", "lfi", "redirect"} for b in matched_buckets):
                    score += 6
                    reasons.append("high_impact_bucket")

            methods = sorted(set(c["methods"]))
            if len(methods) > 1:
                score += min(10, len(methods) * 3)
                reasons.append("method_richness")
            elif methods and methods[0] != "GET":
                score += 6
                reasons.append("non_get_surface")

            param_names = sorted({p for p in c["param_names"] if p})
            if param_names:
                score += min(20, len(param_names) * 3)
                reasons.append("parameter_rich")
                risky_params = sorted({p for p in param_names if p.lower() in _HIGH_RISK_PARAM_NAMES or param_score.get(p, 0) >= 70})
                if risky_params:
                    score += min(18, 4 * len(risky_params))
                    reasons.append("high_risk_params")
            else:
                risky_params = []

            if any(x in templated for x in ("{id}", "{uuid}", "{hex}", "{slug}")):
                score += 11
                reasons.append("object_pattern_route")

            lu = u.lower()
            if any(k in lu for k in risky_endpoint_keywords):
                score += 10
                reasons.append("risky_path_keywords")
            if any(k in title for k in _AUTH_KEYWORDS):
                score += 5
                reasons.append("auth_hint_in_title")
            if static_ext_rx.search(urllib.parse.urlsplit(u).path or ""):
                score -= 18
                reasons.append("static_asset_penalty")

            workflow_hits = workflow_by_route.get(u) or workflow_by_route.get(templated) or []
            if workflow_hits:
                score += 10
                reasons.append("workflow_artifact")
                if any(bool(x.get("write_action")) for x in workflow_hits):
                    score += 6
                    reasons.append("write_action_observed")

            cluster_count = int(templated_cluster_count.get(templated) or 0)
            if cluster_count >= 8:
                score += 6
                reasons.append("route_clustered")
            fp_size = int(cluster_size_by_fingerprint.get(fp) or 0)
            if fp_size >= 12 and any(x in (title + " " + ctype) for x in ("login", "not found", "text/html")):
                score -= 12
                reasons.append("noisy_response_cluster_penalty")

            score = max(0, min(100, score))
            unique_reasons = []
            for r in reasons:
                if r not in unique_reasons:
                    unique_reasons.append(r)
            ranked_rows.append({
                "url": u,
                "score": score,
                "reasons": unique_reasons[:10],
                "sources": sorted(sources),
                "source_classes": sorted(source_classes),
                "state": state,
                "status_code": status,
                "content_type": ctype,
                "templated_route": templated,
                "param_names": param_names[:20],
                "high_risk_params": risky_params[:12],
                "vuln_buckets": matched_buckets[:8],
                "methods": methods,
                "response_fingerprint_cluster_size": fp_size,
                "workflow_hits": len(workflow_hits),
            })

        ranked_rows.sort(key=lambda r: (-int(r.get("score") or 0), r.get("url") or ""))
        md = ["# Endpoint Ranking (Exploitability-Weighted)\n\n", "| Score | URL | State | Sources | Why |\n|---:|---|---|---|---|\n"]
        for row in ranked_rows[:250]:
            md.append(
                f"| {row['score']} | {esc_md_pipe(row['url'])} | {esc_md_pipe(row['state'])} | "
                f"{esc_md_pipe(', '.join(row['sources']))} | {esc_md_pipe(', '.join(row['reasons'][:4]))} |\n"
            )
        out_md.write_text("".join(md), encoding="utf-8")
        self.write_json(out_json, ranked_rows[:3000])
        self.record_stage_status("endpoint_ranking", "completed", "exploitability-weighted endpoint ranking generated", metrics={
            "candidates": len(candidates),
            "ranked": len(ranked_rows),
            "high_score_70": sum(1 for r in ranked_rows if int(r.get("score") or 0) >= 70),
        })
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
            "urls_live": self.urls / "urls_live.txt",
            "urls_archive": self.urls / "urls_archive.txt",
            "nuclei_phase1": self.workdir / "nuclei_phase1.txt",
            "takeover_summary": self.workdir / "takeover_summary.json",
            "urls_discovered_json": self.intel / "urls_discovered.json",
            "urls_revalidated_json": self.intel / "urls_revalidated.json",
            "recon_inventory_json": self.intel / "recon_inventory.json",
        }

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
            f"- URLs (live/revalidated): **{self._count_lines(paths['urls_live'])}**\n",
            f"- URLs (archive-only): **{self._count_lines(paths['urls_archive'])}**\n",
            f"- Nuclei findings (phase1): **{self._count_lines(paths['nuclei_phase1'])}**\n",
            f"- Takeover findings: **{takeover_count}**\n",

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
            f"- URLs discovered (evidence): `{self.intel / 'urls_discovered.json'}`\n",
            f"- URLs revalidated: `{self.intel / 'urls_revalidated.json'}`\n",
            f"- Endpoint clusters: `{self.intel / 'endpoint_clusters.json'}`\n",
            f"- Response clusters: `{self.intel / 'response_clusters.json'}`\n",
            f"- Forms discovered: `{self.intel / 'forms_discovered.json'}`\n",
            f"- Browser workflow artifacts: `{self.intel / 'browser_workflow_artifacts.json'}`\n",
            f"- Host/App inventory split: `{self.intel / 'recon_inventory.json'}`\n",
            f"- Vulnerability URL buckets: `{self.intel / 'vuln_url_buckets.json'}`\n",
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
            "target": self.target,
            "workdir": str(self.workdir),
            "subdomains": str(self.workdir / "all_subdomains.txt"),
            "resolved": str(self.workdir / "resolved_subdomains.txt"),
            "live_hosts": str(self.workdir / "live_hosts.txt"),
            "httpx": {"text": str(self.workdir / "httpx_results.txt"), "jsonl": str(self.workdir / "httpx_results.json")},
            "urls": {
                "katana": str(self.urls / "katana_urls.txt"),
                "xnlinkfinder": str(self.urls / "xnlinkfinder_urls.txt"),
                "gau": str(self.urls / "gau_urls.txt"),
                "all": str(self.urls / "urls_all.txt"),
                "params": str(self.urls / "urls_params.txt"),
                "live": str(self.urls / "urls_live.txt"),
                "archive": str(self.urls / "urls_archive.txt"),
                "discovered_json": str(self.intel / "urls_discovered.json"),
                "revalidated_json": str(self.intel / "urls_revalidated.json"),
            },
            "nuclei": {"phase1_text": str(self.workdir / "nuclei_phase1.txt"), "phase1_jsonl": str(self.workdir / "nuclei_phase1.jsonl"), "phase2_text": str(self.workdir / "nuclei_phase2.txt"), "phase2_jsonl": str(self.workdir / "nuclei_phase2.jsonl")},
            "takeover": {"summary": str(self.workdir / "takeover_summary.json")},
            "host_app_split": {
                "hosts_discovered": str(self.workdir / "all_subdomains.txt"),
                "origins_live": str(self.workdir / "live_hosts.txt"),
                "urls_live": str(self.urls / "urls_live.txt"),
                "urls_archive": str(self.urls / "urls_archive.txt"),
                "params_ranked": str(self.intel / "params_ranked.json"),
                "inventory_json": str(self.intel / "recon_inventory.json"),
            },
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
                "urls_discovered_json": str(self.intel / "urls_discovered.json"),
                "urls_revalidated_json": str(self.intel / "urls_revalidated.json"),
                "forms_discovered_json": str(self.intel / "forms_discovered.json"),
                "browser_workflow_artifacts_json": str(self.intel / "browser_workflow_artifacts.json"),
                "vuln_url_buckets_json": str(self.intel / "vuln_url_buckets.json"),
                "endpoint_clusters_json": str(self.intel / "endpoint_clusters.json"),
                "response_fingerprints_json": str(self.intel / "response_fingerprints.json"),
                "response_clusters_json": str(self.intel / "response_clusters.json"),
                "recon_inventory_json": str(self.intel / "recon_inventory.json"),
                "dns_host_ip_map_json": str(self.intel / "dns_host_ip_map.json"),
                "endpoints_ranked_md": str(self.intel / "endpoints_ranked.md"),
                "endpoints_ranked_json": str(self.intel / "endpoints_ranked.json"),
                "secrets_summary": str(self.intel / "secrets_summary.json"),

                "secrets_findings_md": str(self.intel / "secrets_findings.md"),
                "secrets_findings_json": str(self.intel / "secrets_findings.json"),
                "portscan_results_json": str(self.workdir / "portscan_results.json"),
                "portscan_hosts_txt": str(self.workdir / "portscan_hosts.txt"),
                "js_endpoints_json": str(self.intel / "js_endpoints.json"),
                "nuclei_phase1_jsonl": str(self.workdir / "nuclei_phase1.jsonl"),
                "subdomain_takeover_json": str(self.workdir / "takeover_summary.json"),
                "bypass_403_findings_json": str(self.intel / "bypass_403_findings.json"),
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
            "urls_live": self._count_lines(self.urls / "urls_live.txt"),
            "urls_archive": self._count_lines(self.urls / "urls_archive.txt"),
            "params": self._count_lines(self.urls / "urls_params.txt"),
            "nuclei_findings": nuclei_findings,
            "nuclei_findings_phase1": nuclei_findings,
            "nuclei_findings_phase2": nuclei_findings_phase2,
            "takeover_findings": takeover_findings,

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
        if self.config.skip_dns_bruteforce:
            self.record_stage_status("dns_bruteforce", "skipped", "skip-dns-bruteforce enabled")
            self.mark_done("dns_bruteforce")
            return
        try:
            ipaddress.ip_address(self.target)
            self.record_stage_status("dns_bruteforce", "skipped", "target is an IP; dns bruteforce is hostname-only")
            self.mark_done("dns_bruteforce")
            return
        except Exception:
            pass

        can_puredns = bool(self.puredns_bin)
        can_dnsx = bool(self.dnsx_bin)
        if (not can_puredns) and (not can_dnsx):
            self.record_stage_status("dns_bruteforce", "skipped", "puredns and dnsx are both missing")
            self.mark_done("dns_bruteforce")
            return

        wordlist = ensure_dns_wordlist()
        resolvers = ensure_resolvers_list()
        brute_out = self.workdir / "bruteforce_subdomains.txt"
        dnsx_out = self.workdir / "dnsx_bruteforce_subdomains.txt"
        all_subs = self.workdir / "all_subdomains.txt"
        self.touch_files(brute_out, dnsx_out)

        mode = str(self.config.dns_bruteforce_mode or "auto").strip().lower()
        if mode not in {"auto", "puredns", "dnsx"}:
            mode = "auto"
        resolver_used = ""

        def _read_non_comment_lines(path: Path) -> set[str]:
            if not path.exists() or path.stat().st_size == 0:
                return set()
            return {
                x.strip()
                for x in path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if x.strip() and not x.strip().startswith("#")
            }

        puredns_found: set[str] = set()
        dnsx_found: set[str] = set()

        if can_puredns and mode in {"auto", "puredns"}:
            self.run_tool(
                "puredns bruteforce",
                [self.puredns_bin, "bruteforce", str(wordlist), self.target, "--resolvers", str(resolvers), "--write", str(brute_out), "--quiet"],
                timeout=self.config.dns_bruteforce_timeout,
                allow_failure=True,
            )
            puredns_found = _read_non_comment_lines(brute_out)
            if puredns_found:
                resolver_used = "puredns"

        should_try_dnsx = can_dnsx and (
            mode == "dnsx" or (mode == "auto" and len(puredns_found) == 0)
        )
        if should_try_dnsx:
            self.run_tool(
                "dnsx bruteforce fallback",
                [self.dnsx_bin, "-d", self.target, "-w", str(wordlist), "-silent", "-retry", "2", "-r", str(resolvers), "-o", str(dnsx_out)],
                timeout=max(120, int(self.config.dns_bruteforce_timeout)),
                allow_failure=True,
            )
            dnsx_found = _read_non_comment_lines(dnsx_out)
            if dnsx_found and not resolver_used:
                resolver_used = "dnsx"

        existing = set(
            x.strip() for x in all_subs.read_text(encoding="utf-8", errors="ignore").splitlines()
            if x.strip() and not x.strip().startswith("#")
        ) if all_subs.exists() else set()
        new_subs = set(puredns_found | dnsx_found)
        merged = sorted(existing | new_subs)
        all_subs.write_text("\n".join(merged) + "\n", encoding="utf-8")
        gained = len(new_subs - existing)
        if not resolver_used:
            resolver_used = "none"
        self.record_stage_status("dns_bruteforce", "completed", f"mode={mode} resolver={resolver_used} found={len(new_subs)} new={gained} total={len(merged)}", metrics={
            "mode": mode,
            "resolver_used": resolver_used,
            "puredns_found": len(puredns_found),
            "dnsx_found": len(dnsx_found),
            "found": len(new_subs),
            "new": gained,
            "total_subdomains": len(merged),
        })
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
        self.record_stage_status("portscan", "completed", f"new_hosts={len(extra_hosts)} merged_total={len(merged)}", metrics={
            "new_hosts": len(extra_hosts),
            "merged_total": len(merged),
        })
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
                "--write-db", 
                "--write-db-uri", f"sqlite://{db_path}",
                "--no-http", "--no-https",
                "--threads", str(self.config.screenshots_threads),
                "--timeout", str(self.config.screenshots_timeout),
            ],
            timeout=self.config.screenshots_timeout * 10 + 600,
            stdout_path=gw_log,
            stderr_path=gw_log,
            allow_failure=True,
        )
        count = (
            len(list(out_dir.rglob("*.png")))
            + len(list(out_dir.rglob("*.jpg")))
            + len(list(out_dir.rglob("*.jpeg")))
        )
        self.record_stage_status("screenshots", "completed", f"screenshots={count} db={db_path}", metrics={
            "screenshots": count,
        })
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
            self.record_stage_status("param_discovery", "warning", f"hosts={len(capped)} params_found=0 errors={scan_errors}", metrics={
                "hosts": len(capped),
                "params_found": 0,
                "errors": scan_errors,
            })
        else:
            self.record_stage_status("param_discovery", "completed", f"hosts={len(capped)} params_found={total_params} errors={scan_errors}", metrics={
                "hosts": len(capped),
                "params_found": total_params,
                "errors": scan_errors,
            })
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
                self.record_stage_status("xss_scan", "warning", f"dalfox incomplete; retained stronger findings only ({detail})", metrics={
                    "urls_tested": len(urls),
                    "findings": count,
                    "discarded": discarded,
                    "returncode": result.returncode,
                })
            else:
                self.record_stage_status("xss_scan", "warning", f"dalfox incomplete; discarded partial or reflection-only results ({detail})", metrics={
                    "urls_tested": len(urls),
                    "findings": count,
                    "discarded": discarded,
                    "returncode": result.returncode,
                })
        else:
            self.record_stage_status("xss_scan", "completed", f"urls_tested={len(urls)} findings={count} discarded={discarded}", metrics={
                "urls_tested": len(urls),
                "findings": count,
                "discarded": discarded,
            })
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
        attempts = 0
        negative_http = 0
        transport_errors = 0
        timeouts = 0
        lock=threading.Lock()
        def _probe(host: str):
            nonlocal attempts, negative_http, transport_errors, timeouts
            url=host.rstrip("/")
            for hdrs in bypass_headers:
                with lock:
                    attempts += 1
                try:
                    req=urllib.request.Request(url, headers={"User-Agent": _JS_USER_AGENTS[0], **hdrs})
                    with urllib.request.urlopen(req, timeout=max(5, int(self.config.bypass_403_timeout))) as resp:
                        if resp.status < 400:
                            with lock: findings.append({"host":host,"bypass":"header","header":str(hdrs),"status":resp.status})
                            return
                except urllib.error.HTTPError:
                    with lock:
                        negative_http += 1
                except urllib.error.URLError as e:
                    with lock:
                        transport_errors += 1
                        if isinstance(getattr(e, "reason", None), socket.timeout):
                            timeouts += 1
                except socket.timeout:
                    with lock:
                        transport_errors += 1
                        timeouts += 1
                except Exception:
                    with lock:
                        transport_errors += 1
            for path in bypass_paths:
                with lock:
                    attempts += 1
                try:
                    parsed=urllib.parse.urlsplit(url)
                    probe_url=urllib.parse.urlunsplit(parsed._replace(path=path))
                    req=urllib.request.Request(probe_url, headers={"User-Agent": _JS_USER_AGENTS[0]})
                    with urllib.request.urlopen(req, timeout=max(5, int(self.config.bypass_403_timeout))) as resp:
                        if resp.status < 400:
                            with lock: findings.append({"host":host,"bypass":"path","path":path,"status":resp.status})
                            return
                except urllib.error.HTTPError:
                    with lock:
                        negative_http += 1
                except urllib.error.URLError as e:
                    with lock:
                        transport_errors += 1
                        if isinstance(getattr(e, "reason", None), socket.timeout):
                            timeouts += 1
                except socket.timeout:
                    with lock:
                        transport_errors += 1
                        timeouts += 1
                except Exception:
                    with lock:
                        transport_errors += 1
        with ThreadPoolExecutor(max_workers=min(self.config.bypass_403_workers, len(hosts_403))) as ex:
            futs=[ex.submit(_probe,h) for h in hosts_403]
            stage_deadline_s = max(15, int(self.config.bypass_403_timeout))
            try:
                for fut in as_completed(futs, timeout=stage_deadline_s):
                    if SHUTTING_DOWN: break
                    try: fut.result()
                    except Exception: pass
            except TimeoutError:
                transport_errors += 1
                timeouts += 1
                self.record_stage_status("bypass_403", "warning", f"stage deadline exceeded after {stage_deadline_s}s")
                for f in futs:
                    f.cancel()
        out_json=self.intel / "bypass_403_findings.json"
        self.write_json(out_json, findings)
        if hosts_403 and len(findings) == 0:
            self.record_stage_status("bypass_403", "warning", f"probed={len(hosts_403)} bypassed=0 attempts={attempts} negative_http={negative_http} transport_errors={transport_errors}", metrics={
                "probed": len(hosts_403),
                "bypassed": 0,
                "attempts": attempts,
                "negative_http": negative_http,
                "transport_errors": transport_errors,
                "timeouts": timeouts,
                "errors": transport_errors,
            })
        else:
            self.record_stage_status("bypass_403", "completed", f"probed={len(hosts_403)} bypassed={len(findings)} attempts={attempts} negative_http={negative_http} transport_errors={transport_errors}", metrics={
                "probed": len(hosts_403),
                "bypassed": len(findings),
                "attempts": attempts,
                "negative_http": negative_http,
                "transport_errors": transport_errors,
                "timeouts": timeouts,
                "errors": transport_errors,
            })
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
        negative_http = 0
        transport_errors = 0
        timeouts = 0
        q = json.dumps({"query": "{__schema{types{name}}}", "operationName": None, "variables": {}})

        def _scan_host(host: str) -> tuple[dict | None, int, int, int, int]:
            local_attempts = 0
            local_negative_http = 0
            local_transport_errors = 0
            local_timeouts = 0
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
                                return ({"url":url,"introspection":True,"schema_file":str(sf)}, local_attempts, local_negative_http, local_transport_errors, local_timeouts)
                    except urllib.error.HTTPError:
                        local_negative_http += 1
                        if attempt == 1:
                            _backoff_sleep(0.35, attempt)
                    except urllib.error.URLError as e:
                        local_transport_errors += 1
                        if isinstance(getattr(e, "reason", None), socket.timeout):
                            local_timeouts += 1
                        if attempt == 1:
                            _backoff_sleep(0.35, attempt)
                    except socket.timeout:
                        local_transport_errors += 1
                        local_timeouts += 1
                        if attempt == 1:
                            _backoff_sleep(0.35, attempt)
                    except Exception:
                        local_transport_errors += 1
                        if attempt == 1:
                            _backoff_sleep(0.35, attempt)
            return (None, local_attempts, local_negative_http, local_transport_errors, local_timeouts)

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
                            item, a, nh, te, to = fut.result()
                            attempts += a
                            negative_http += nh
                            transport_errors += te
                            timeouts += to
                            if item:
                                findings.append(item)
                        except Exception:
                            transport_errors += 1
                except TimeoutError:
                    transport_errors += 1
                    timeouts += 1
                    self.record_stage_status("graphql", "warning", f"stage deadline exceeded after {stage_deadline_s}s")
                    for f in futs:
                        f.cancel()
        self.write_json(self.intel / "graphql_findings.json", findings)
        if hosts and attempts > 0 and len(findings) == 0:
            self.record_stage_status("graphql", "warning", f"hosts_checked={len(hosts)} introspection_open=0 attempts={attempts} negative_http={negative_http} transport_errors={transport_errors}", metrics={
                "hosts_checked": len(hosts),
                "introspection_open": 0,
                "attempts": attempts,
                "negative_http": negative_http,
                "transport_errors": transport_errors,
                "timeouts": timeouts,
                "errors": transport_errors,
            })
        else:
            self.record_stage_status("graphql", "completed", f"hosts_checked={len(hosts)} introspection_open={len(findings)} attempts={attempts} negative_http={negative_http} transport_errors={transport_errors}", metrics={
                "hosts_checked": len(hosts),
                "introspection_open": len(findings),
                "attempts": attempts,
                "negative_http": negative_http,
                "transport_errors": transport_errors,
                "timeouts": timeouts,
                "errors": transport_errors,
            })
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
        self.record_stage_status("vhost_fuzz", "completed", f"vhosts_found={count} target_ip={main_ip}", metrics={
            "vhosts_found": count,
            "target_ip": main_ip,
        })
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
        dmarc_val = (report.get("dmarc") or "").lower()
        dmarc_warn = "✅ enforced"
        if not dmarc_val:
            dmarc_warn = "❌  MISSING — domain is highly phishable"
            self.add_finding("osint", "MEDIUM", self.target, "Missing DMARC record", evidence="No _dmarc TXT record found", confidence=90, tags=["dns","phishing"])
        elif "p=none" in dmarc_val:
            dmarc_warn = "⚠️  p=none — reporting only, not enforced"
            self.add_finding("osint", "LOW", self.target, "Weak DMARC policy (p=none)", evidence=dmarc_val, confidence=90, tags=["dns","phishing"])
        elif "p=quarantine" in dmarc_val or "p=reject" in dmarc_val:
            dmarc_warn = "✅ enforced (" + ("reject" if "reject" in dmarc_val else "quarantine") + ")"

        spf_val = (report.get("spf") or "").lower()
        spf_warn = "✅ healthy"
        if "not found" in spf_val:
            spf_warn = "❌  MISSING — spoofing possible"
            self.add_finding("osint", "MEDIUM", self.target, "Missing SPF record", evidence="No v=spf1 TXT record found", confidence=90, tags=["dns","phishing"])
        elif "+all" in spf_val:
            spf_warn = "❌  CRITICAL — +all allows any sender"
            self.add_finding("osint", "HIGH", self.target, "Critically weak SPF (+all)", evidence=spf_val, confidence=95, tags=["dns","phishing"])
        elif "?all" in spf_val or "~all" in spf_val:
            spf_warn = "⚠️  softfail/neutral — spoofing may still deliver"

        md=[f"# OSINT Report — {self.target}\n\n", 
            f"## DMARC\n- Record: `{report.get('dmarc') or 'NOT FOUND'}`\n", 
            f"- Assessment: **{dmarc_warn}**\n\n", 
            f"## SPF\n- Record: `{report.get('spf')}`\n",
            f"- Assessment: **{spf_warn}**\n\n",
            f"## DKIM Selectors Found ({len(report['dkim_probed'])})\n"]
        for d in report["dkim_probed"]:
            md.append(f"- `{d['selector']}`: {d['record'][:120]}\n")
        (self.intel / "osint_report.md").write_text("".join(md), encoding="utf-8")
        self.write_json(self.cache / "osint_report.json", report)
        self.record_stage_status("osint", "completed", f"dmarc={'found' if report.get('dmarc') else 'MISSING'} spf={'found' if 'not found' not in spf_val else 'MISSING'}")
        self.mark_done("osint")

    def write_live_findings(self) -> None:
        out = self.workdir / "findings.md"
        sections=[]
        for title, fn in [("## 403 Bypasses\n", self.intel / "bypass_403_findings.json"), ("## XSS Findings\n", self.intel / "xss_findings.json"), ("## GraphQL Introspection Open\n", self.intel / "graphql_findings.json")]:
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

            + stats.get("xss_findings", 0)
            + stats.get("bypass_403_findings", 0)
            + stats.get("graphql_findings", 0)
            + stats.get("github_dork_hits", 0)
            + stats.get("takeover_findings", 0)
        )
        return [
            {"name": "Subdomains", "value": str(stats.get("subdomains", 0)), "inline": True},
            {"name": "Resolved", "value": str(stats.get("resolved", 0)), "inline": True},
            {"name": "Live Hosts", "value": str(stats.get("live_hosts", 0)), "inline": True},
            {"name": "Endpoints", "value": str(stats.get("endpoints", 0)), "inline": True},
            {"name": "Findings", "value": str(findings_total), "inline": True},
        ]

    def _preview_lines(self, path: Path, *, limit: int = 10) -> list[str]:
        if not path.exists():
            return []
        out: list[str] = []
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                out.append(line)
                if len(out) >= max(1, limit):
                    break
        except Exception:
            return []
        return out

    def _stage_context_fields(self, stage: str) -> list[dict]:
        if not stage:
            return []
        row = self._latest_stage_status.get(stage)
        if not isinstance(row, dict):
            return []

        fields: list[dict] = []
        detail = str(row.get("detail") or "").strip()
        if detail:
            fields.append({"name": "Stage Detail", "value": self._truncate(detail, 1024), "inline": False})

        duration = row.get("duration_seconds")
        if duration is not None:
            fields.append({"name": "Stage Duration", "value": f"{duration}s", "inline": True})

        metrics = row.get("metrics") or {}
        if isinstance(metrics, dict):
            for key in sorted(metrics.keys())[:8]:
                val = metrics.get(key)
                label = str(key).replace("_", " ").title()
                fields.append({"name": self._truncate(label, 256), "value": self._truncate(str(val), 1024), "inline": True})
        return fields

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
        fields.extend(self._stage_context_fields(stage))
        subdomain_preview = self._preview_lines(self.workdir / "all_subdomains.txt", limit=8)
        if subdomain_preview and stage in {"subdomains", "dnsx", "httpx", "pipeline"}:
            fields.append({
                "name": "Subdomain Preview",
                "value": "```\n" + "\n".join(subdomain_preview) + "\n```",
                "inline": False,
            })
        if log_file:
            fields.append({"name": "Log", "value": str(Path(log_file).resolve()), "inline": False})

        event_type = "stage_completed" if st == "completed" and stage and stage != "pipeline" else "run_completed"
        if st in {"warning", "error", "interrupted"}:
            event_type = "run_error"
        elif st == "info" and stage == "startup":
            event_type = "run_started"
        elif st == "warning" and stage in {"xss_scan", "bypass_403", "graphql", "github_dork"}:
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
            "stats": self.collect_stats(),
            "subdomains_path": str((self.workdir / "all_subdomains.txt").resolve()),
            "subdomains_preview": subdomain_preview,
            "stage_status": self._latest_stage_status.get(stage) if stage else None,
            "workdir": str(self.workdir.resolve()),
            "timestamp": now_utc_iso(),
        }
        self._queue_webhook_event({"urls": urls, "body": body, "fingerprint": fingerprint})

    def execute(self) -> None:
        global SHUTTING_DOWN
        reused = self.reuse_previous_artifacts()
        if reused:
            self.record_stage_status("cache", "completed", "reused previous artifacts", metrics={"reused_files": reused})
        # UX-first execution: run top-level stages sequentially so dashboard flow and
        # webhooks remain predictable (one stage update at a time).
        pipeline: list[tuple[str, Any]] = [
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

                already_done = self.resume_mode and self.is_done(stage_name)
                self.dashboard.stage_start(stage_name)
                self.dashboard.set_context(current_host="-", queue_depth=0, active_jobs=0, failed_jobs=0)
                t0 = time.perf_counter()
                fn()
                dt = time.perf_counter() - t0
                self.record_stage_status("pipeline", "completed", f"{stage_name} complete", duration_seconds=dt)
                if not already_done:
                    self._notify(f"Stage done | duration={dt:.1f}s", status="completed", stage=stage_name, severity="INFO", log_file=str(self.logs / "stage_status.jsonl"))
                self.dashboard.set_stats(self.collect_stats())
                self.dashboard.stage_done(stage_name, dt)

                self.dashboard.set_context(httpx_buckets=f"2xx={self.dashboard.stats.get('httpx_2xx',0)} 4xx={self.dashboard.stats.get('httpx_403',0)}")
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
                f"endpoints={stats.get('endpoints',0)} findings={stats.get('nuclei_findings',0)+stats.get('nuclei_findings_phase2',0)+stats.get('secrets_findings',0)+stats.get('xss_findings',0)+stats.get('bypass_403_findings',0)+stats.get('graphql_findings',0)+stats.get('github_dork_hits',0)} "
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
            f"endpoints={stats.get('endpoints',0)} findings={stats.get('nuclei_findings',0)+stats.get('nuclei_findings_phase2',0)+stats.get('secrets_findings',0)+stats.get('xss_findings',0)+stats.get('bypass_403_findings',0)+stats.get('graphql_findings',0)+stats.get('github_dork_hits',0)} "
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
    p.add_argument("--dns-bruteforce-mode", choices=["auto", "puredns", "dnsx"], type=str)
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

    p.add_argument("--katana-timeout", type=int)
    p.add_argument("--gospider-timeout", type=int)
    p.add_argument("--hakrawler-timeout", type=int)
    p.add_argument("--xnlinkfinder-timeout", type=int)
    p.add_argument("--katana-depth", type=int)
    p.add_argument("--no-katana-js-crawl", dest="katana_js_crawl", action="store_false")
    p.add_argument("--gau-timeout", type=int)
    p.add_argument("--gau-blacklist", type=str)
    p.add_argument("--url-revalidate-timeout", type=int)
    p.add_argument("--url-revalidate-workers", type=int)
    p.add_argument("--url-revalidate-cap", type=int)
    p.add_argument("--url-revalidate-get-cap", type=int)
    p.add_argument("--url-revalidate-body-max", type=int)
    p.add_argument("--gf-bucket-cap", type=int)
    p.add_argument("--force-update-templates", action="store_true")
    p.add_argument("--ffuf-version", type=str)
    p.add_argument("--httpx-version", type=str)
    p.add_argument("--subfinder-version", type=str)
    p.add_argument("--assetfinder-version", type=str)
    p.add_argument("--dnsx-version", type=str)
    p.add_argument("--katana-version", type=str)
    p.add_argument("--gau-version", type=str)
    p.add_argument("--nuclei-version", type=str)
    p.add_argument("--gf-version", type=str)
    p.add_argument("--qsreplace-version", type=str)
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

        "katana_timeout": args.katana_timeout,
        "gospider_timeout": args.gospider_timeout,
        "hakrawler_timeout": args.hakrawler_timeout,
        "xnlinkfinder_timeout": args.xnlinkfinder_timeout,
        "katana_depth": args.katana_depth,
        "katana_js_crawl": args.katana_js_crawl,
        "gau_timeout": args.gau_timeout,
        "gau_blacklist": args.gau_blacklist,
        "url_revalidate_timeout": args.url_revalidate_timeout,
        "url_revalidate_workers": args.url_revalidate_workers,
        "url_revalidate_cap": args.url_revalidate_cap,
        "url_revalidate_get_cap": args.url_revalidate_get_cap,
        "url_revalidate_body_max": args.url_revalidate_body_max,
        "gf_bucket_cap": args.gf_bucket_cap,
        "skip_secrets": args.skip_secrets,
        "skip_takeover": args.skip_takeover,

        "skip_portscan": args.skip_portscan,
        "naabu_rate": args.naabu_rate,
        "naabu_timeout": args.naabu_timeout,
        "naabu_top_ports": args.naabu_top_ports,
        "naabu_ports": args.naabu_ports,
        "skip_dns_bruteforce": args.skip_dns_bruteforce,
        "dns_bruteforce_timeout": args.dns_bruteforce_timeout,
        "dns_bruteforce_mode": args.dns_bruteforce_mode,
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
        "gf": args.gf_version,
        "qsreplace": args.qsreplace_version,
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
    ext_bins = ["naabu", "puredns", "dalfox", "asnmap", "gospider", "hakrawler", "xnLinkFinder", "gf", "qsreplace", "arjun", "dirsearch", "graphw00f"]
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


def detect_missing_core_tools_for_bootstrap() -> list[str]:
    core_bins = ["ffuf", "httpx", "subfinder", "dnsx", "katana", "gau", "nuclei", "dirsearch"]
    missing = []
    for b in core_bins:
        if not resolve_tool(b):
            missing.append(b)
    return missing


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
    missing_core = detect_missing_core_tools_for_bootstrap()
    bootstrap_started_at = 0.0
    if missing_core or args.update_tools:
        if missing_core:
            bootstrap_started_at = time.monotonic()
            preview = ", ".join(missing_core[:8])
            extra = "" if len(missing_core) <= 8 else ", ..."
            log(f"[*] First-run tool bootstrap detected: missing core tools ({preview}{extra})")
            log("[*] Installing recon toolchain now. This can take several minutes on a fresh machine.")
        install_required_tools(tool_versions, skip_secrets=args.skip_secrets, force_update=args.update_tools)
        if missing_core and bootstrap_started_at > 0:
            elapsed = time.monotonic() - bootstrap_started_at
            log(f"[+] First-run tool bootstrap completed in {elapsed:.1f}s")

    if args.doctor:
        raise SystemExit(run_doctor())

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
