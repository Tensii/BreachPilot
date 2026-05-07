import os
import re
import ipaddress
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class ReconConfig:
    ffuf_threads: int = 50
    ffuf_timeout: int = 5
    ffuf_rate: int = 50
    ffuf_maxtime_job: int = 45
    ffuf_delay: str = "0.03-0.12"
    dirsearch_threads: int = 50
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
    ffuf_workers: int = 10
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

STAGE_ORDER = [
    "osint", "nuclei_templates", "subdomains", "dns_bruteforce",
    "dnsx", "takeover", "httpx", "vhost_fuzz", "portscan", "screenshots",
    "discovery_dirsearch", "discovery_ffuf_dirs", "discovery_ffuf_files", "discovery",
    "bypass_403", "graphql", "urls", "param_discovery",
    "tech", "tech_host_mapping", "nuclei_phase1", "xss_scan", "secrets", "github_dork",
    "nuclei_phase2", "endpoint_ranking",
]

PIPELINE_STAGES = [
    "osint", "nuclei_templates", "subdomains", "dns_bruteforce", "dnsx", "takeover",
    "httpx", "vhost_fuzz", "portscan", "screenshots", "discovery", "bypass_403", "graphql",
    "urls", "param_discovery", "tech", "tech_host_mapping", "nuclei_phase1", "xss_scan",
    "secrets", "github_dork", "nuclei_phase2", "endpoint_ranking",
]

# Common Regex and Keywords
SCORE_KEYWORDS = frozenset(["admin","login","signin","signup","oauth","sso","callback","redirect","api","graphql","swagger","openapi","actuator","console","upload","download","export","import","backup","debug","test","staging","internal",".git",".env","config","old","dev"])
AUTH_KEYWORDS = ("login", "signin", "sign-in", "signup", "register", "auth", "session", "password", "2fa", "otp")
NOTFOUND_KEYWORDS = ("not found", "404", "page not found", "cannot be found", "doesn't exist")

def normalize_target(target: str) -> str:
    t = (target or "").strip().lower()
    t = re.sub(r"^https?://", "", t)
    t = re.sub(r"/.*$", "", t)
    return t

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
