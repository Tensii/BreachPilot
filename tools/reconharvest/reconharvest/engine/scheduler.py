import asyncio
import shlex
import time
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class AsyncCommandResult:
    returncode: int
    duration: float
    stdout: str
    stderr: str

class AsyncScheduler:
    def __init__(self, concurrency: int = 10):
        self.semaphore = asyncio.Semaphore(concurrency)

    async def run_command(self, label: str, cmd: List[str] | str, timeout: Optional[int] = None) -> AsyncCommandResult:
        async with self.semaphore:
            t0 = time.perf_counter()
            if isinstance(cmd, list):
                cmd_str = " ".join(shlex.quote(p) for p in cmd)
            else:
                cmd_str = cmd
                
            process = await asyncio.create_subprocess_shell(
                cmd_str,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                returncode = process.returncode
            except asyncio.TimeoutError:
                process.kill()
                stdout, stderr = await process.communicate()
                returncode = 124 # Timeout
            
            duration = round(time.perf_counter() - t0, 3)
            return AsyncCommandResult(
                returncode=returncode,
                duration=duration,
                stdout=stdout.decode(errors="ignore"),
                stderr=stderr.decode(errors="ignore")
            )
            
    async def run_batch(self, tasks):
        """Runs a batch of commands concurrently."""
        return await asyncio.gather(*tasks)
