import os
from pathlib import Path
from ..engine.runner import Runner

class DNSModule:
    def __init__(self, runner: Runner):
        self.runner = runner

    def run_subfinder(self) -> Path:
        out = self.runner.workdir / "subfinder.txt"
        if self.runner.is_done("subdomains_subfinder"):
            return out
            
        self.runner.record_stage_status("subdomains", "started", "Running subfinder")
        cmd = ["subfinder", "-d", self.runner.target, "-o", str(out), "-silent"]
        self.runner.run_tool("subfinder", cmd)
        self.runner.mark_done("subdomains_subfinder")
        return out

    def run_dnsx(self, input_file: Path) -> Path:
        out = self.runner.workdir / "resolved.txt"
        if self.runner.is_done("dnsx"):
            return out
            
        self.runner.record_stage_status("dnsx", "started", "Resolving subdomains")
        cmd = ["dnsx", "-l", str(input_file), "-o", str(out), "-silent", "-retry", "3"]
        self.runner.run_tool("dnsx", cmd)
        self.runner.mark_done("dnsx")
        return out
