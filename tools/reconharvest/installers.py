#!/usr/bin/env python3
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable

_LOGGER: Callable[[str], None] = print

def set_logger(logger_func):
    global _LOGGER
    _LOGGER = logger_func or print

def log(msg: str) -> None:
    _LOGGER(msg)

def command_exists(name: str) -> bool:
    return shutil.which(name) is not None

def run(cmd: list[str] | str, check: bool = False, quiet: bool = False, timeout: int | None = None) -> subprocess.CompletedProcess:
    stdout = subprocess.DEVNULL if quiet else None
    stderr = subprocess.DEVNULL if quiet else None
    if isinstance(cmd, str):
        args = ["/bin/bash", "-c", cmd]
    else:
        args = cmd
    cp = subprocess.run(args, stdout=stdout, stderr=stderr, timeout=timeout)
    if check and cp.returncode != 0:
        raise RuntimeError(f"Command failed ({cp.returncode}): {cmd}")
    return cp

def is_kali_or_debian_like() -> bool:
    p = Path("/etc/os-release")
    if not p.exists():
        return False
    text = p.read_text(encoding="utf-8", errors="ignore").lower()
    return any(x in text for x in ("kali", "debian", "ubuntu", "parrot"))

def sudo_prefix() -> str:
    if os.geteuid() == 0:
        return ""
    if not command_exists("sudo"):
        raise RuntimeError("sudo not found. Install sudo or run as root.")
    return "sudo "


_apt_updated = False

def apt_update_once() -> None:
    """Run apt-get update exactly once per process lifetime."""
    global _apt_updated
    if _apt_updated:
        return
    cmd = ["apt-get", "update", "-y"]
    if os.geteuid() != 0:
        cmd = ["sudo", *cmd]
    run(cmd, check=False)
    _apt_updated = True

def apt_install(*pkgs: str) -> None:
    if not pkgs:
        return
    apt_update_once()
    cmd = ["apt-get", "install", "-y", *pkgs]
    if os.geteuid() != 0:
        cmd = ["sudo", *cmd]
    run(cmd, check=True)

def ensure_system_tool(binary: str, apt_pkg: str | None = None) -> None:
    if command_exists(binary):
        return
    if is_kali_or_debian_like() and command_exists("apt-get"):
        log(f"[*] Installing {binary} via apt…")
        apt_install(apt_pkg or binary)
    if not command_exists(binary):
        raise RuntimeError(f"Required tool missing: {binary}")

def ensure_go() -> None:
    if command_exists("go"):
        return
    log("[*] Installing Go via apt…")
    if is_kali_or_debian_like() and command_exists("apt-get"):
        apt_install("golang")
    if not command_exists("go"):
        raise RuntimeError("Go not found. Install Go and ensure GOPATH/bin is in PATH.")

def ensure_dns_wordlist() -> Path:
    dest = Path.home() / ".local/share/reconharvest/subdomains-top1million-5000.txt"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 1000:
        return dest
    log("[*] Downloading subdomain wordlist from assetnote...")
    url = ("https://wordlists-cdn.assetnote.io/data/manual/"
           "best-dns-wordlist.txt")
    try:
        urllib.request.urlretrieve(url, str(dest))
    except Exception:
        fb = Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        if fb.exists():
            return fb
        dest.write_text("www\nmail\napi\ndev\nstaging\ntest\nadmin\n", encoding="utf-8")
    return dest

def ensure_resolvers_list() -> Path:
    dest = Path.home() / ".local/share/reconharvest/resolvers.txt"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 100:
        return dest
    url = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
    try:
        urllib.request.urlretrieve(url, str(dest))
    except Exception:
        dest.write_text("8.8.8.8\n1.1.1.1\n9.9.9.9\n208.67.222.222\n", encoding="utf-8")
    return dest

def ensure_pipx() -> None:
    if command_exists("pipx"):
        return
    log("[*] Installing pipx (Kali-safe)…")
    if not (is_kali_or_debian_like() and command_exists("apt-get")):
        raise RuntimeError("Non-Debian system: install pipx manually and add ~/.local/bin to PATH.")
    apt_install("pipx")
    if not command_exists("pipx"):
        raise RuntimeError("pipx still not found after install.")

def ensure_seclists() -> None:
    base = Path("/usr/share/seclists")
    web_content = base / "Discovery/Web-Content"
    if web_content.is_dir():
        return
    log("[*] SecLists not found. Attempting installation…")
    if is_kali_or_debian_like() and command_exists("apt-get"):
        log("[*] Trying apt install seclists…")
        try:
            apt_install("seclists")
        except Exception as e:
            log(f"[!] apt install seclists failed: {e}")
        if web_content.is_dir():
            return
    ensure_system_tool("curl")
    ensure_system_tool("unzip")
    seclists_ref = os.environ.get("SECLISTS_REF", "2025.2")
    log(f"[*] apt install did not provide SecLists. Downloading pinned archive from GitHub (ref={seclists_ref})…")
    with tempfile.TemporaryDirectory() as td:
        zpath = Path(td) / "seclists.zip"
        try:
            urllib.request.urlretrieve(f"https://github.com/danielmiessler/SecLists/archive/refs/tags/{seclists_ref}.zip", str(zpath))
        except Exception:
            log("[!] Pinned SecLists ref failed; trying fallback pinned branch snapshot.")
            urllib.request.urlretrieve("https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip", str(zpath))
        extract_dir = Path(td) / "extract"
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zpath, "r") as zf:
            zf.extractall(extract_dir)
        candidates = [p for p in extract_dir.iterdir() if p.is_dir() and p.name.startswith("SecLists-")]
        if not candidates:
            raise RuntimeError("Could not locate extracted SecLists directory.")
        extracted = candidates[0]
        pref = sudo_prefix()
        run(f"{pref}rm -rf /usr/share/seclists", check=False)
        run(f"{pref}mkdir -p /usr/share", check=True)
        run(f"{pref}mv \"{extracted}\" /usr/share/seclists", check=True)
    if not web_content.is_dir():
        raise RuntimeError("SecLists is required and could not be installed.")

def install_go_tool(binary: str, go_install_cmd: str, force: bool = False) -> None:
    ensure_go()

    # Make sure go binaries are globally reachable in this process
    gopath = subprocess.run(
        ["go", "env", "GOPATH"],
        capture_output=True, text=True, timeout=10
    ).stdout.strip()
    go_bin = Path(gopath) / "bin" if gopath else Path.home() / "go/bin"
    local_bin = Path.home() / ".local/bin"

    for bin_dir in (go_bin, local_bin):
        if str(bin_dir) not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{bin_dir}:{os.environ.get('PATH', '')}"

    # Symlink into ~/.local/bin so the tool is reachable as a plain command
    local_bin.mkdir(parents=True, exist_ok=True)
    tool_path = go_bin / binary
    link_path = local_bin / binary
    if tool_path.exists() and ((not link_path.exists()) or force):
        try:
            if link_path.exists() or link_path.is_symlink():
                link_path.unlink(missing_ok=True)
            link_path.symlink_to(tool_path)
        except Exception:
            pass

    if command_exists(binary) and not force:
        return

    log(f"[*] Installing {binary}…")
    rc = run(go_install_cmd).returncode

    # Re-check and relink post-install
    tool_path = go_bin / binary
    if tool_path.exists() and ((not link_path.exists()) or force):
        try:
            if link_path.exists() or link_path.is_symlink():
                link_path.unlink(missing_ok=True)
            link_path.symlink_to(tool_path)
        except Exception:
            pass

    if command_exists(binary):
        return
    if rc != 0:
        log(f"[!] Go install for {binary} failed (no apt fallback to avoid wrong package mapping).")
    if not command_exists(binary):
        raise RuntimeError(f"Failed to install {binary}")

def install_dirsearch_kali_safe() -> None:
    root = Path.home() / ".local/share/dirsearch"
    venv = root / ".venv"
    bin_link = Path.home() / ".local/bin/dirsearch"

    # If already installed and working, do nothing
    if bin_link.exists() and run([str(bin_link), "--help"], quiet=True).returncode == 0:
        os.environ["PATH"] = f"{Path.home() / '.local/bin'}:{os.environ.get('PATH', '')}"
        return

    # Clone or update repo
    if not (root / ".git").exists():
        log("[*] Installing dirsearch via git clone…")
        run(
            ["git", "clone", "--depth", "1",
             "https://github.com/maurosoria/dirsearch.git", str(root)],
            check=False,
        )
    else:
        run(["git", "-C", str(root), "pull", "--ff-only"], check=False, quiet=True)

    # Create venv and install dependencies
    if not venv.exists():
        run(["python3", "-m", "venv", str(venv)], check=False)
    pybin = venv / "bin/python"
    if pybin.exists():
        run([str(pybin), "-m", "pip", "install", "--upgrade", "pip"],
            check=False, quiet=True)
        req = root / "requirements.txt"
        if req.exists():
            run([str(pybin), "-m", "pip", "install", "-r", str(req)],
                check=False, quiet=True)

    # Write a thin launcher into ~/.local/bin/dirsearch
    bin_link.parent.mkdir(parents=True, exist_ok=True)
    launcher = (
        f"#!/usr/bin/env bash\n"
        f'exec "{pybin}" "{root}/dirsearch.py" "$@"\n'
    )
    bin_link.write_text(launcher, encoding="utf-8")
    bin_link.chmod(0o755)

    os.environ["PATH"] = f"{Path.home() / '.local/bin'}:{os.environ.get('PATH', '')}"

    if not (bin_link.exists() and run([str(bin_link), "--help"], quiet=True).returncode == 0):
        log("[!] dirsearch is unavailable; continuing without it.")

def install_trufflehog(force: bool = False) -> None:
    if command_exists("trufflehog") and not force:
        return
    ensure_system_tool("curl")
    ensure_system_tool("tar")
    ensure_system_tool("jq")
    api = "https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest"
    try:
        rel = json.loads(urllib.request.urlopen(api, timeout=20).read().decode("utf-8", errors="ignore"))
    except Exception as e:
        log(f"[!] Failed to query trufflehog release API: {e}")
        return
    assets = rel.get("assets") or []
    url = ""
    for a in assets:
        u = str(a.get("browser_download_url") or "")
        if re.search(r"linux_amd64.*(tar\.gz|tgz)$", u):
            url = u
            break
    if not url:
        log("[!] Could not find trufflehog linux_amd64 asset")
        return
    bindir = Path.home() / ".local/bin"
    bindir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        arc = Path(td) / "trufflehog.tgz"
        try:
            with urllib.request.urlopen(url, timeout=40) as r, arc.open("wb") as f:
                f.write(r.read())
            run(["tar", "-xzf", str(arc), "-C", td], check=True)
            found = next((str(p) for p in Path(td).rglob("trufflehog") if p.is_file()), "")
            if found:
                run(["install", "-m", "0755", found, str(bindir / "trufflehog")], check=True)
        except Exception as e:
            log(f"[!] trufflehog install failed: {e}")

def install_gitleaks(force: bool = False) -> None:
    if command_exists("gitleaks") and not force:
        return
    ensure_system_tool("curl")
    ensure_system_tool("tar")
    api = "https://api.github.com/repos/gitleaks/gitleaks/releases/latest"
    try:
        rel = json.loads(urllib.request.urlopen(api, timeout=20).read().decode("utf-8", errors="ignore"))
    except Exception as e:
        log(f"[!] Failed to query gitleaks release API: {e}")
        return
    url = ""
    for a in (rel.get("assets") or []):
        u = str(a.get("browser_download_url") or "")
        if re.search(r"linux_(x64|amd64)\.tar\.gz$", u):
            url = u
            break
    if not url:
        log("[!] Could not find gitleaks linux asset")
        return
    bindir = Path.home() / ".local/bin"
    bindir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        arc = Path(td) / "gitleaks.tgz"
        try:
            with urllib.request.urlopen(url, timeout=40) as r, arc.open("wb") as f:
                f.write(r.read())
            run(["tar", "-xzf", str(arc), "-C", td], check=True)
            found = next((str(p) for p in Path(td).rglob("gitleaks") if p.is_file()), "")
            if found:
                run(["install", "-m", "0755", found, str(bindir / "gitleaks")], check=True)
        except Exception as e:
            log(f"[!] gitleaks install failed: {e}")

def install_secretfinder(force: bool = False) -> None:
    root = Path.home() / ".local/share/secretfinder"
    venv = root / ".venv"
    if force and root.exists():
        shutil.rmtree(root, ignore_errors=True)
    if not (root / ".git").exists():
        run(["git", "clone", "--depth", "1", "https://github.com/m4ll0k/SecretFinder.git", str(root)], check=False)
    if not venv.exists():
        run(["python3", "-m", "venv", str(venv)], check=False)
    pybin = venv / "bin/python"
    if pybin.exists():
        run([str(pybin), "-m", "pip", "install", "--upgrade", "pip"], check=False, quiet=True)
        run([str(pybin), "-m", "pip", "install", "-r", str(root / "requirements.txt")], check=False, quiet=True)

def install_s3scanner(force: bool = False) -> None:
    if command_exists("s3scanner") and not force:
        return
    ensure_pipx()
    root = Path.home() / ".local/share/s3scanner"
    if force and root.exists():
        shutil.rmtree(root, ignore_errors=True)
    run("pipx install s3scanner", quiet=True)
    if command_exists("s3scanner") and not force:
        return
    venv = root / ".venv"
    root.mkdir(parents=True, exist_ok=True)
    if not venv.exists():
        run(["python3", "-m", "venv", str(venv)], check=False)
    pybin = venv / "bin/python"
    if pybin.exists():
        run([str(pybin), "-m", "pip", "install", "--upgrade", "pip"], check=False, quiet=True)
        run([str(pybin), "-m", "pip", "install", "s3scanner"], check=False, quiet=True)

def install_naabu(force: bool = False) -> None:
    if command_exists("naabu") and not force:
        return
    log("[*] Installing naabu…")
    cmd = "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    cp = run(cmd, quiet=True, check=False)
    if cp.returncode == 0 and command_exists("naabu"):
        # expose into ~/.local/bin for shells that don't include ~/go/bin
        gobin = Path.home() / "go/bin/naabu"
        if gobin.exists():
            link = Path.home() / ".local/bin/naabu"
            link.parent.mkdir(parents=True, exist_ok=True)
            if not link.exists():
                try:
                    link.symlink_to(gobin)
                except Exception:
                    pass
        return
    # naabu requires libpcap headers at build-time on Linux
    if is_kali_or_debian_like() and command_exists("apt-get"):
        log("[*] naabu build failed; installing libpcap-dev and retrying…")
        apt_install("libpcap-dev")
        cp2 = run(cmd, quiet=True, check=False)
        if cp2.returncode == 0 and command_exists("naabu"):
            return
    raise RuntimeError("Failed to install naabu")

def install_puredns(force: bool = False) -> None:
    install_go_tool("puredns", "go install github.com/d3mondev/puredns/v2@latest", force=force)
    if command_exists("massdns"):
        return

    if is_kali_or_debian_like() and command_exists("apt-get"):
        try:
            apt_install("massdns")
        except Exception as e:
            log(f"[!] apt massdns install failed, falling back to source build: {e}")

    if not command_exists("massdns"):
        root = Path.home() / ".local/share/massdns"
        if not (root / ".git").exists():
            run(["git", "clone", "--depth", "1", "https://github.com/blechschmidt/massdns.git", str(root)], check=False)
        run(["make", "-C", str(root)], check=False)
        bin_path = root / "bin/massdns"
        if bin_path.exists():
            dest = Path.home() / ".local/bin/massdns"
            dest.parent.mkdir(parents=True, exist_ok=True)
            run(["install", "-m", "0755", str(bin_path), str(dest)], check=False)

    if not command_exists("massdns"):
        raise RuntimeError("Failed to install massdns (apt and source build both failed)")

def install_arjun(force: bool = False) -> None:
    if command_exists("arjun") and not force:
        return
    ensure_pipx()
    run("pipx install arjun", quiet=True)
    if not command_exists("arjun"):
        run("pipx install arjun", check=False)

    pipx_bin = Path.home() / ".local/bin"
    if str(pipx_bin) not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{pipx_bin}:{os.environ.get('PATH', '')}"

def install_dalfox(force: bool = False) -> None:
    install_go_tool("dalfox", "go install github.com/hahwul/dalfox/v2@latest", force=force)

def install_graphw00f(force: bool = False) -> None:
    root = Path.home() / ".local/share/graphw00f"
    venv = root / ".venv"
    pybin = venv / "bin/python"
    bin_link = Path.home() / ".local/bin/graphw00f"

    if not force and bin_link.exists():
        test = subprocess.run(
            [str(bin_link), "--help"],
            capture_output=True, timeout=10
        )
        if test.returncode == 0:
            os.environ["PATH"] = (
                f"{Path.home() / '.local/bin'}:{os.environ.get('PATH', '')}"
            )
            return

    if not (root / ".git").exists():
        log("[*] Installing graphw00f via git clone...")
        run(["git", "clone", "--depth", "1",
             "https://github.com/dolevf/graphw00f.git", str(root)],
            check=False)
    else:
        run(["git", "-C", str(root), "pull", "--ff-only"],
            check=False, quiet=True)

    if not venv.exists():
        run(["python3", "-m", "venv", str(venv)], check=False)

    if pybin.exists():
        run([str(pybin), "-m", "pip", "install", "--upgrade", "pip"],
            check=False, quiet=True)
        req = root / "requirements.txt"
        if req.exists():
            run([str(pybin), "-m", "pip", "install", "-r", str(req)],
                check=False, quiet=True)
        # Safety fallback if upstream requirements resolution changes
        run([str(pybin), "-m", "pip", "install", "requests"],
            check=False, quiet=True)

    # Write global launcher script
    bin_link.parent.mkdir(parents=True, exist_ok=True)
    launcher = (
        "#!/usr/bin/env bash\n"
        f'exec "{pybin}" "{root}/main.py" "$@"\n'
    )
    bin_link.write_text(launcher, encoding="utf-8")
    bin_link.chmod(0o755)

    os.environ["PATH"] = (
        f"{Path.home() / '.local/bin'}:{os.environ.get('PATH', '')}"
    )

    verify = subprocess.run(
        [str(bin_link), "--help"],
        capture_output=True, timeout=10
    )
    if verify.returncode != 0:
        log("[!] graphw00f is unavailable; continuing without it.")

def install_asnmap(force: bool = False) -> None:
    install_go_tool("asnmap", "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest", force=force)

def install_gospider(force: bool = False) -> None:
    install_go_tool("gospider", "go install github.com/jaeles-project/gospider@latest", force=force)

def install_hakrawler(force: bool = False) -> None:
    if command_exists("hakrawler") and not force:
        return
    ensure_go()
    # Primary path
    cp = run("go install github.com/hakluke/hakrawler@latest", quiet=True, check=False)
    if command_exists("hakrawler"):
        return
    # Fallback for module path/registry edge-cases
    run("go install github.com/hakluke/hakrawler/v2@latest", quiet=True, check=False)
    if command_exists("hakrawler"):
        return
    if cp.returncode != 0:
        log("[!] Go install for hakrawler failed")
    raise RuntimeError("Failed to install hakrawler")

def install_gowitness(force: bool = False) -> None:
    install_go_tool("gowitness", "go install github.com/sensepost/gowitness@latest", force=force)

def install_subzy(force: bool = False) -> None:
    if command_exists("subzy") and not force:
        return
    try:
        install_go_tool("subzy", "go install github.com/PentestPad/subzy@latest", force=force)
    except Exception:
        return

def resolve_tool(name: str) -> str:
    preferred = [Path.home() / ".local/bin" / name, Path.home() / "go/bin" / name]
    for p in preferred:
        if p.exists() and os.access(p, os.X_OK):
            return str(p)
    p = shutil.which(name)
    return p or ""

def verify_tool(bin_name: str, test_cmd: str) -> None:
    if not resolve_tool(bin_name):
        raise RuntimeError(f"Tool not found after install: {bin_name}")
    rc = run(test_cmd, quiet=True, timeout=8).returncode
    if rc != 0:
        raise RuntimeError(f"Tool failed verification: {bin_name}")

def install_required_tools(versions, skip_secrets: bool = False, force_update: bool = False) -> None:
    # Bootstrap all standard binary locations into the current process PATH
    # so that tools installed earlier in this run are immediately visible
    # to tools installed later (e.g. massdns visible to puredns, etc.)
    _path_dirs = [
        Path.home() / ".local/bin",
        Path.home() / "go/bin",
        Path("/usr/local/go/bin"),
        Path("/usr/local/bin"),
    ]
    current_path = os.environ.get("PATH", "")
    for _d in _path_dirs:
        if _d.exists() and str(_d) not in current_path:
            current_path = f"{_d}:{current_path}"
    os.environ["PATH"] = current_path

    ensure_seclists()
    ensure_system_tool("dig", "dnsutils")
    install_dirsearch_kali_safe()
    install_go_tool("ffuf", f"go install {versions.ffuf}", force=force_update)
    install_go_tool("httpx", f"go install -v {versions.httpx}", force=force_update)
    install_go_tool("subfinder", f"go install {versions.subfinder}", force=force_update)
    install_go_tool("assetfinder", f"go install {versions.assetfinder}", force=force_update)
    install_go_tool("dnsx", f"go install -v {versions.dnsx}", force=force_update)
    install_subzy(force=force_update)
    install_go_tool("katana", f"go install -v {versions.katana}", force=force_update)
    install_go_tool("gau", f"go install {versions.gau}", force=force_update)
    install_go_tool("nuclei", f"go install -v {versions.nuclei}", force=force_update)
    install_naabu(force=force_update)
    install_puredns(force=force_update)
    install_arjun(force=force_update)
    install_dalfox(force=force_update)
    install_graphw00f(force=force_update)
    install_asnmap(force=force_update)
    install_gospider(force=force_update)
    install_hakrawler(force=force_update)
    install_gowitness(force=force_update)
    try:
        verify_tool("dirsearch", "dirsearch --help")
    except Exception as e:
        log(f"[!] dirsearch verification skipped: {e}")
    verify_tool("ffuf", "ffuf -V")
    verify_tool("httpx", "httpx -h")
    verify_tool("subfinder", "subfinder -h")
    verify_tool("assetfinder", "assetfinder --help")
    verify_tool("dnsx", "dnsx -h")
    verify_tool("katana", "katana -h")
    verify_tool("gau", "gau --help")
    verify_tool("nuclei", "nuclei -h")
    for _bn, _cmd in [("naabu","naabu -h"),("puredns","puredns --help"),("arjun","arjun --help"),("dalfox","dalfox version"),("graphw00f","graphw00f --help"),("asnmap","asnmap -h"),("gospider","gospider -h"),("gowitness","gowitness --help")]:
        try:
            verify_tool(_bn, _cmd)
        except Exception as e:
            log(f"[!] {_bn} verification skipped: {e}")
    # hakrawler help exits inconsistently across builds; only require binary presence
    if not resolve_tool("hakrawler"):
        log("[!] hakrawler verification skipped: Tool not found after install: hakrawler")
    if not skip_secrets:
        install_trufflehog(force=force_update)
        install_gitleaks(force=force_update)
        install_secretfinder(force=force_update)
        install_s3scanner(force=force_update)

