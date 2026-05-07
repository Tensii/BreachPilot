import json
from pathlib import Path
from ..engine.runner import Runner

class HTTPModule:
    def __init__(self, runner: Runner):
        self.runner = runner

    def run_httpx(self, input_file: Path) -> Path:
        out_txt = self.runner.workdir / "httpx_results.txt"
        out_json = self.runner.workdir / "httpx_results.json"
        
        if self.runner.is_done("httpx"):
            return out_json
            
        self.runner.record_stage_status("httpx", "started", "Probing HTTP services")
        
        # Build httpx command with stealth UA
        cmd = [
            "httpx", 
            "-l", str(input_file),
            "-o", str(out_txt),
            "-json", "-oj",
            "-silent",
            "-threads", str(self.runner.config.httpx_threads),
            "-timeout", str(self.runner.config.httpx_timeout),
            "-retries", str(self.runner.config.httpx_retries),
            "-title", "-tech-detect", "-status-code", "-follow-redirects"
        ]
        
        self.runner.run_tool("httpx", cmd, stdout_path=out_json)
        self.runner.mark_done("httpx")
        
        # Parse metrics
        try:
            with open(out_json, 'r') as f:
                lines = f.readlines()
                self.runner.record_stage_status("httpx", "completed", f"Found {len(lines)} live hosts", {"live_hosts": len(lines)})
        except Exception:
            self.runner.record_stage_status("httpx", "completed", "httpx finished")
            
        return out_json

    def run_gowitness(self, input_file: Path) -> Path:
        out_dir = self.runner.workdir / "screenshots"
        if self.runner.is_done("screenshots"):
            return out_dir
            
        self.runner.record_stage_status("screenshots", "started", "Capturing screenshots")
        out_dir.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            "gowitness", "file",
            "-f", str(input_file),
            "--output", str(out_dir),
            "--threads", str(self.runner.config.screenshots_threads),
            "--timeout", str(self.runner.config.screenshots_timeout)
        ]
        
        self.runner.run_tool("gowitness", cmd)
        self.runner.mark_done("screenshots")
        return out_dir
