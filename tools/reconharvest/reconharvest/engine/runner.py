import datetime
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..utils.config import ReconConfig, STAGE_ORDER, PIPELINE_STAGES
from ..utils.logger import setup_logger, append_to_file
from ..utils.network import get_stealth_headers

@dataclass(frozen=True)
class CommandResult:
    returncode: int
    duration_seconds: float
    stdout_path: str | None = None
    stderr_path: str | None = None
    attempts: int = 1

class GracefulInterrupt(Exception):
    pass

def now_utc_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

class Runner:
    def __init__(self, target: str, workdir: Path, parallel: int, config: ReconConfig | None = None):
        self.target = target
        self.workdir = workdir
        self.parallel = parallel
        self.config = config or ReconConfig()
        
        # Paths
        self.state = workdir / ".state"
        self.logs = workdir / "logs"
        self.intel = workdir / "intel"
        self.reports = workdir / "reports"
        
        for d in [self.state, self.logs, self.intel, self.reports]:
            d.mkdir(parents=True, exist_ok=True)
            
        self.status_jsonl = self.logs / "stage_status.jsonl"
        self.command_log_jsonl = self.logs / "command_log.jsonl"
        
        self.logger = setup_logger(f"runner.{target}", self.logs / "reconharvest.log")
        self._child_pgids: set[int] = set()
        self._child_lock = threading.Lock()
        self.shutting_down = False

    def log_cmd(self, label: str, cmd: str):
        self.logger.info(f"[{label}] Executing: {cmd}")

    def record_stage_status(self, stage: str, status: str, detail: str = "", metrics: dict | None = None):
        entry = {
            "schema_version": "1.1",
            "timestamp": now_utc_iso(),
            "stage": stage,
            "status": status,
            "detail": detail,
            "metrics": metrics or {}
        }
        append_to_file(self.status_jsonl, json.dumps(entry))
        self.logger.info(f"Stage {stage} {status}: {detail}")

    def is_done(self, stage: str) -> bool:
        return (self.state / f"{stage}.done").exists()

    def mark_done(self, stage: str):
        (self.state / f"{stage}.done").touch()

    def run_tool(self, label: str, cmd: list[str] | str, *, timeout: int | None = None, retries: int = 0, stdout_path: Path | None = None, stderr_path: Path | None = None, allow_failure: bool = False, env: dict[str, str] | None = None) -> CommandResult:
        display = cmd if isinstance(cmd, str) else " ".join(shlex.quote(part) for part in cmd)
        self.log_cmd(label, display)
        
        attempts = 0
        last_rc = 0
        t0 = time.perf_counter()
        
        # Inject Stealth Headers into ENV if possible
        tool_env = os.environ.copy()
        if env:
            tool_env.update(env)
        
        # Add a common Stealth User-Agent to the environment for tools that respect it
        stealth_headers = get_stealth_headers()
        tool_env["HTTP_USER_AGENT"] = stealth_headers["User-Agent"]
        tool_env["USER_AGENT"] = stealth_headers["User-Agent"]

        for attempt in range(retries + 1):
            if self.shutting_down:
                last_rc = 130
                break
            
            attempts = attempt + 1
            mode = "w" if attempt == 0 else "a"
            out_handle = stdout_path.open(mode, encoding="utf-8") if stdout_path else subprocess.DEVNULL
            err_handle = stderr_path.open(mode, encoding="utf-8") if stderr_path else out_handle if (stderr_path and stdout_path and stderr_path == stdout_path) else subprocess.DEVNULL
            
            proc = None
            try:
                argv = cmd if isinstance(cmd, list) else ["/bin/bash", "-c", cmd]
                proc = subprocess.Popen(
                    argv,
                    stdout=out_handle,
                    stderr=err_handle,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                    env=tool_env,
                )
                
                with self._child_lock:
                    self._child_pgids.add(proc.pid)
                
                try:
                    last_rc = proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    last_rc = 124
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                        proc.wait(timeout=5)
                    except Exception:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except Exception: pass
            except Exception as e:
                self.logger.error(f"Error running {label}: {e}")
                last_rc = 1
            finally:
                if proc is not None:
                    with self._child_lock:
                        self._child_pgids.discard(proc.pid)
                if hasattr(out_handle, "close"): out_handle.close()
                if hasattr(err_handle, "close") and err_handle != out_handle: err_handle.close()
            
            if last_rc == 0:
                break
            if attempt < retries and not self.shutting_down:
                time.sleep(2 ** attempt)

        duration = round(time.perf_counter() - t0, 3)
        result = CommandResult(returncode=last_rc, duration_seconds=duration, stdout_path=str(stdout_path) if stdout_path else None, stderr_path=str(stderr_path) if stderr_path else None, attempts=attempts)
        
        # Log command result
        cmd_entry = {
            "timestamp": now_utc_iso(),
            "label": label,
            "command": display,
            "returncode": result.returncode,
            "duration_seconds": result.duration_seconds,
            "attempts": result.attempts
        }
        append_to_file(self.command_log_jsonl, json.dumps(cmd_entry))
        
        if not allow_failure and result.returncode != 0 and self.config.stop_on_error:
            raise RuntimeError(f"{label} failed with return code {result.returncode}")
            
        return result
