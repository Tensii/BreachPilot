import asyncio
from pathlib import Path
from ..engine.runner import Runner
from ..engine.scheduler import AsyncScheduler

class DiscoveryModule:
    def __init__(self, runner: Runner):
        self.runner = runner
        self.scheduler = AsyncScheduler(concurrency=runner.parallel)

    async def run_dirsearch_async(self, host: str) -> Path:
        safe_host = host.replace("://", "_").replace(".", "_").replace(":", "_")
        out = self.runner.workdir / f"dirsearch_{safe_host}.txt"
        
        cmd = [
            "dirsearch",
            "-u", host,
            "-t", str(self.runner.config.dirsearch_threads),
            "--timeout", str(self.runner.config.dirsearch_timeout),
            "--delay", str(self.runner.config.dirsearch_delay),
            "-o", str(out),
            "--format", "plain"
        ]
        
        self.runner.logger.info(f"Async Dirsearch starting for {host}")
        await self.scheduler.run_command(f"dirsearch:{host}", cmd)
        return out

    async def scan_all_hosts(self, hosts: list[str]):
        """Runs discovery on all hosts concurrently using the async scheduler."""
        self.runner.record_stage_status("discovery", "started", f"Starting async discovery on {len(hosts)} hosts")
        
        tasks = []
        for host in hosts:
            tasks.append(self.run_dirsearch_async(host))
            
        results = await asyncio.gather(*tasks)
        self.runner.record_stage_status("discovery", "completed", f"Finished discovery on {len(results)} hosts")
        return results
