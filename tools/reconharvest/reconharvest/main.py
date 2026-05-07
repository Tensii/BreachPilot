import asyncio
import argparse
import sys
import json
from pathlib import Path

from .engine.runner import Runner
from .utils.config import ReconConfig, validate_target
from .modules.dns import DNSModule
from .modules.http import HTTPModule
from .modules.cloud import CloudMapper
from .modules.discovery import DiscoveryModule
from .modules.exploit import ExploitModule

async def run_pipeline(args):
    workdir = Path(args.workdir) if args.workdir else Path(f"./artifacts/{args.target}/1")
    
    # Initialize Core
    config = ReconConfig()
    runner = Runner(args.target, workdir, args.parallel, config)
    
    # Initialize Modules
    dns = DNSModule(runner)
    http = HTTPModule(runner)
    cloud = CloudMapper(args.target)
    discovery = DiscoveryModule(runner)
    exploit = ExploitModule(runner)
    
    try:
        runner.record_stage_status("pipeline", "started", f"Starting modular async recon for {args.target}")
        
        # 1. DNS Phase
        subdomains_file = dns.run_subfinder()
        resolved_file = dns.run_dnsx(subdomains_file)
        
        # 2. Cloud Phase (Item 3)
        if not args.skip_cloud:
            runner.record_stage_status("cloud_discovery", "started", "Scanning for cloud assets")
            buckets = cloud.scan() # Could be made async later
            runner.record_stage_status("cloud_discovery", "completed", f"Found {len(buckets)} buckets")
        
        # 3. HTTP Phase
        httpx_json = http.run_httpx(resolved_file)
        
        # Parse live hosts for discovery
        live_hosts = []
        try:
            with open(httpx_json, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    if 'url' in data:
                        live_hosts.append(data['url'])
        except Exception: pass

        # 4. Async Discovery Phase (Item 2)
        if live_hosts:
            await discovery.scan_all_hosts(live_hosts[:20]) # Cap for testing
        
        # 5. Exploit Phase
        if not args.skip_nuclei:
            exploit.run_nuclei(resolved_file)
            
        runner.record_stage_status("pipeline", "completed", "Recon complete")
        
    except KeyboardInterrupt:
        runner.record_stage_status("pipeline", "interrupted", "User stopped scan")
        sys.exit(130)
    except Exception as e:
        runner.record_stage_status("pipeline", "error", str(e))
        print(f"Error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="BreachPilot ReconHarvest — Modular Recon Engine")
    parser.add_argument("-t", "--target", required=True, help="Target domain or IP")
    parser.add_argument("-w", "--workdir", help="Working directory")
    parser.add_argument("-p", "--parallel", type=int, default=10, help="Parallel workers")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip nuclei scanning")
    parser.add_argument("--skip-cloud", action="store_true", help="Skip cloud bucket discovery")
    
    args = parser.parse_args()
    
    if not validate_target(args.target):
        print(f"Error: Invalid target format: {args.target}")
        sys.exit(1)
        
    asyncio.run(run_pipeline(args))

if __name__ == "__main__":
    main()
