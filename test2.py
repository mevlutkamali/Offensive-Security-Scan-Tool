"""
01_nmap_main.py — Nmap Scanner
Terminal Pentest Framework | Phase 1: Discovery

Run:  python3 01_nmap_main.py
Root: sudo python3 01_nmap_main.py  (for SYN / OS / UDP scans)
"""

import os
import sys
import json
import logging
import subprocess
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime


# ── Colors ────────────────────────────────────────────────────────────────────

class Colors:
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    RED     = '\033[91m'
    CYAN    = '\033[96m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    WHITE   = '\033[97m'
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'

colors = Colors  # backward-compatible alias


# ── Config ────────────────────────────────────────────────────────────────────

LOG_FILE  = "pentest_scanner.log"
JSON_FILE = "scan_results.json"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ── Known risky ports ─────────────────────────────────────────────────────────

PORT_RISK = {
    21:    "FTP — cleartext creds, anonymous login",
    22:    "SSH — brute-force / outdated version exploits",
    23:    "Telnet — cleartext, highly insecure",
    25:    "SMTP — open relay, user enumeration",
    53:    "DNS — zone transfer (AXFR), amplification",
    80:    "HTTP — SQLi, XSS, Path Traversal",
    110:   "POP3 — cleartext credentials",
    111:   "RPCbind — NFS enumeration",
    135:   "MSRPC — Windows RPC exploitation",
    139:   "NetBIOS — SMB enum, EternalBlue",
    443:   "HTTPS — TLS misconfig, weak ciphers",
    445:   "SMB — EternalBlue (MS17-010), relay attacks",
    1433:  "MSSQL — SA brute-force, xp_cmdshell",
    1521:  "Oracle — default creds, TNS listener poison",
    3306:  "MySQL — remote root login, UDF exploit",
    3389:  "RDP — BlueKeep (CVE-2019-0708), brute-force",
    5432:  "PostgreSQL — default creds, COPY exploit",
    5900:  "VNC — no-auth mode, weak password",
    6379:  "Redis — no-auth RCE, config overwrite",
    8080:  "HTTP-Alt — proxy bypass, web vulns",
    8443:  "HTTPS-Alt — admin panel exposure",
    27017: "MongoDB — no-auth, full data exposure",
}

PORT_COLOR = {
    21: Colors.RED,  23: Colors.RED,  139: Colors.RED,  445: Colors.RED,
    3389: Colors.RED, 6379: Colors.RED, 27017: Colors.RED,
    22: Colors.YELLOW, 25: Colors.YELLOW, 53: Colors.YELLOW,
    80: Colors.YELLOW, 443: Colors.YELLOW, 3306: Colors.YELLOW,
    5432: Colors.YELLOW, 5900: Colors.YELLOW,
}

# First-strike priority list (web > SMB > DB > RDP > SSH)
STRIKE_ORDER = [
    (80,    "HTTP",      "Most developer bugs live here (SQLi, XSS, Auth bypass)."),
    (443,   "HTTPS",     "Same as HTTP but check TLS config too."),
    (8080,  "HTTP-Alt",  "Often a dev server or admin panel with weaker protection."),
    (8443,  "HTTPS-Alt", "Admin interfaces are frequently here."),
    (445,   "SMB",       "EternalBlue is still unpatched on many machines."),
    (139,   "NetBIOS",   "SMB relay attacks and credential capture."),
    (3306,  "MySQL",     "Remote root or UDF code exec if misconfigured."),
    (6379,  "Redis",     "No-auth = instant RCE via config overwrite."),
    (27017, "MongoDB",   "No-auth MongoDB = full database access."),
    (1433,  "MSSQL",     "xp_cmdshell can give OS-level command execution."),
    (3389,  "RDP",       "BlueKeep or credential stuffing."),
    (22,    "SSH",       "Last resort — brute-force or default credentials."),
]


# ── Small helpers ─────────────────────────────────────────────────────────────

def cprint(color, prefix, msg):
    """Colored print with a short prefix like [+] or [!]."""
    print(f"{color}{Colors.BOLD}{prefix}{Colors.RESET} {msg}")


def scan_id():
    """Return a random 8-char hex ID, e.g. 'A3F1C9B2'."""
    return uuid.uuid4().hex[:8].upper()


def nmap_available():
    """Check if nmap is installed."""
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False


def is_root():
    """Return True if running as root, print a message otherwise."""
    if os.geteuid() != 0:
        cprint(Colors.RED,    "[!]", "Please run with sudo for this scan type.")
        cprint(Colors.YELLOW, "[i]", "Command: sudo python3 01_nmap_main.py")
        log.warning("Root check failed — scan needs sudo.")
        return False
    return True


# ── JSON storage ──────────────────────────────────────────────────────────────

def load_results():
    """Load the existing scan results list from disk."""
    if not os.path.exists(JSON_FILE):
        return []
    try:
        data = json.load(open(JSON_FILE, encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_result(entry):
    """Append one scan result to scan_results.json."""
    results = load_results()
    results.append(entry)
    try:
        json.dump(results, open(JSON_FILE, "w", encoding="utf-8"), ensure_ascii=False, indent=4)
        cprint(Colors.BLUE, "[+]", f"Saved to '{JSON_FILE}'.")
    except OSError as e:
        cprint(Colors.RED, "[!]", f"Could not save results: {e}")
        log.error("[ID:%s] JSON write failed: %s", entry.get("scan_id"), e)


# ── XML parser ────────────────────────────────────────────────────────────────

def parse_nmap_xml(xml_str):
    """
    Parse Nmap's XML output and return a clean dict.
    Raw XML is never stored — only the useful bits come out.

    Returns dict with: results, os_guess, open_count, filtered_count,
                       host_status, latency
    """
    out = {
        "results":        [],
        "os_guess":       None,
        "open_count":     0,
        "filtered_count": 0,
        "host_status":    "unknown",
        "latency":        None,
    }

    try:
        tree = ET.fromstring(xml_str)
    except ET.ParseError:
        return out

    for host in tree.findall("host"):

        # Host up/down status
        s = host.find("status")
        if s is not None:
            out["host_status"] = s.get("state", "unknown")

        # Round-trip latency (stored in microseconds)
        t = host.find("times")
        if t is not None:
            srtt = t.get("srtt", "")
            if srtt.isdigit():
                out["latency"] = f"{round(int(srtt) / 1000, 2)}ms"

        # Ports
        ports_elem = host.find("ports")
        if ports_elem:
            for extra in ports_elem.findall("extraports"):
                if extra.get("state") in ("filtered", "closed"):
                    out["filtered_count"] += int(extra.get("count", 0))

            for p in ports_elem.findall("port"):
                state_el = p.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                svc = p.find("service")
                port_entry = {
                    "port":    int(p.get("portid", 0)),
                    "service": svc.get("name", "unknown") if svc is not None else "unknown",
                    "state":   "open",
                }
                out["results"].append(port_entry)

        # OS detection
        os_el = host.find("os")
        if os_el is not None:
            matches = os_el.findall("osmatch")
            if matches:
                best = max(matches, key=lambda x: int(x.get("accuracy", "0")))
                name = best.get("name", "Unknown")
                acc  = best.get("accuracy", "?")
                out["os_guess"] = f"{name} ({acc}%)"

    out["results"].sort(key=lambda x: x["port"])
    out["open_count"] = len(out["results"])
    return out


# ── Terminal summary ──────────────────────────────────────────────────────────

def show_summary(sid, target, data):
    """Print a short, readable scan summary after a scan finishes."""
    border = Colors.MAGENTA + Colors.BOLD + "═" * 50 + Colors.RESET
    print(f"\n{border}")
    print(f"  {Colors.BOLD}{Colors.WHITE}SCAN SUMMARY{Colors.RESET}  "
          f"{Colors.DIM}[{sid}] {target}{Colors.RESET}")
    print(f"{border}\n")

    if not data["results"]:
        cprint(Colors.YELLOW, "[~]", "No open ports found.")
    else:
        print(f"  {Colors.BOLD}{'PORT':<8}{'SERVICE':<16}{'RISK'}{Colors.RESET}")
        print(f"  {'─'*8}{'─'*16}{'─'*30}")
        for p in data["results"]:
            color = PORT_COLOR.get(p["port"], Colors.GREEN)
            risk  = PORT_RISK.get(p["port"], "—")
            print(f"  {color}{Colors.BOLD}{p['port']:<8}{Colors.RESET}"
                  f"{Colors.CYAN}{p['service']:<16}{Colors.RESET}"
                  f"{Colors.DIM}{risk}{Colors.RESET}")
        print()

    # Status line
    sc = Colors.GREEN if data["host_status"] == "up" else Colors.RED
    print(f"  {Colors.BOLD}Host   :{Colors.RESET} {sc}{data['host_status'].upper()}{Colors.RESET}  "
          f"{Colors.DIM}latency: {data['latency'] or 'n/a'}{Colors.RESET}")
    print(f"  {Colors.BOLD}Ports  :{Colors.RESET} "
          f"{Colors.GREEN}{data['open_count']} open{Colors.RESET}  "
          f"{Colors.DIM}{data['filtered_count']} closed/filtered{Colors.RESET}")

    # OS guess
    if data["os_guess"]:
        print(f"  {Colors.BOLD}OS     :{Colors.RESET} {Colors.GREEN}{data['os_guess']}{Colors.RESET}")
    else:
        print(f"  {Colors.BOLD}OS     :{Colors.RESET} {Colors.DIM}n/a (use -O or -A with sudo){Colors.RESET}")

    # First strike suggestion
    print(f"\n  {Colors.BOLD}{'─'*46}{Colors.RESET}")
    _first_strike(data["results"])
    print(f"\n{border}\n")


def _first_strike(open_ports):
    """Suggest the best port to attack first."""
    if not open_ports:
        return

    port_set = {p["port"] for p in open_ports}

    for port, name, reason in STRIKE_ORDER:
        if port in port_set:
            print(f"  {Colors.BOLD}{Colors.MAGENTA}First Strike →{Colors.RESET} "
                  f"{Colors.YELLOW}Port {port} ({name}){Colors.RESET}")
            print(f"  {Colors.DIM}  {reason}{Colors.RESET}")
            return

    # Fallback to lowest open port
    first = open_ports[0]
    print(f"  {Colors.BOLD}{Colors.MAGENTA}First Strike →{Colors.RESET} "
          f"{Colors.YELLOW}Port {first['port']} ({first['service']}){Colors.RESET}")
    print(f"  {Colors.DIM}  Only open port — start here.{Colors.RESET}")


# ── Core scan function ────────────────────────────────────────────────────────

def run_scan(target, args, label="Scan"):
    """
    Run an nmap scan, parse results, save to JSON, show summary.
    Returns the result dict on success, None on failure.
    """
    if not nmap_available():
        cprint(Colors.RED,    "[!]", "nmap not found. Install it first.")
        cprint(Colors.YELLOW, "[i]", "  sudo apt install nmap   # Debian/Ubuntu")
        cprint(Colors.YELLOW, "[i]", "  sudo yum install nmap   # RHEL/CentOS")
        log.error("nmap not installed.")
        return None

    sid       = scan_id()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    command   = ["nmap"] + args.split() + ["-oX", "-", target]

    log.info("[ID:%s] Scan started — %s | args: %s", sid, target, args)
    cprint(Colors.CYAN, "[*]", f"[{sid}] {label} → {Colors.BOLD}{target}{Colors.RESET}")
    cprint(Colors.DIM,  "[>]", f"Command: {' '.join(command)}")
    print()

    entry = {
        "scan_id":  sid,
        "target":   target,
        "status":   "error",
        "timestamp": timestamp,
        "results":  [],
        "os_guess": None,
        "error":    None,
    }

    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate()

        if proc.returncode == 0:
            parsed = parse_nmap_xml(stdout)

            entry["status"]   = "success"
            entry["results"]  = parsed["results"]
            entry["os_guess"] = parsed["os_guess"]

            # Progress bar
            bar = "█" * 30
            print(f"\n  {Colors.CYAN}[{sid}] Scan completed{Colors.RESET}")
            print(f"  {Colors.BLUE}[{bar}]{Colors.RESET} {Colors.GREEN}Done{Colors.RESET}\n")

            cprint(Colors.GREEN, "[+]", "Scan complete.")
            log.info("[ID:%s] Scan done — %s | open_ports=%d | host=%s",
                     sid, target, parsed["open_count"], parsed["host_status"])

            show_summary(sid, target, parsed)

        else:
            entry["error"] = stderr.strip()
            cprint(Colors.RED, "[-]", f"Scan failed:\n  {Colors.DIM}{stderr.strip()}{Colors.RESET}")
            log.error("[ID:%s] Scan failed — %s | %s", sid, target, stderr.strip())

    except FileNotFoundError:
        entry["error"] = "nmap binary not found at runtime"
        cprint(Colors.RED, "[!]", "nmap disappeared — is it still installed?")
        log.error("[ID:%s] nmap missing at runtime.", sid)

    except PermissionError:
        entry["error"] = "insufficient privileges"
        cprint(Colors.RED, "[!]", f"[{sid}] Permission denied. Run with sudo.")
        log.error("[ID:%s] Permission denied — %s", sid, target)

    except Exception as e:
        entry["error"] = str(e)
        cprint(Colors.RED, "[!]", f"Unexpected error: {e}")
        log.exception("[ID:%s] Unexpected error scanning %s.", sid, target)

    save_result(entry)
    return entry if entry["status"] == "success" else None


# ── Menu ──────────────────────────────────────────────────────────────────────

# (label, nmap args, needs root)
MENU = {
    "1":  ("Simple Port Scan",          "",               False),
    "2":  ("Full Port Scan",            "-p-",            False),
    "3":  ("Service & Script Scan",     "-sC -sV",        False),
    "4":  ("OS Detection",              "-O",             True),
    "5":  ("Quick Scan",                "-T4",            False),
    "6":  ("Aggressive Scan",           "-A",             False),
    "7":  ("Version Detection",         "-sV",            False),
    "8":  ("SYN Scan (Stealth)",        "-sS",            True),
    "9":  ("UDP Scan",                  "-sU",            True),
    "10": ("Firewall Bypass",           "-f -T0",         False),
    "11": ("Custom Port Scan",          "_port",          False),
    "12": ("Custom Script Scan",        "_script",        False),
    "13": ("Vulnerability Scan",        "--script vuln",  False),
}

EXIT = "0"


def banner():
    w = 50
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'─'*w}{Colors.RESET}")
    print(f"  {Colors.BOLD}{Colors.WHITE}TERMINAL PENTEST FRAMEWORK{Colors.RESET}")
    print(f"  {Colors.DIM}Phase 1 · Network Discovery & Port Scanning{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'─'*w}{Colors.RESET}\n")


def draw_menu(target):
    print(f"  {Colors.BOLD}Target :{Colors.RESET} {Colors.GREEN}{target}{Colors.RESET}")
    print(f"  {Colors.BOLD}Log    :{Colors.RESET} {Colors.DIM}{LOG_FILE}{Colors.RESET}")
    print(f"  {Colors.BOLD}Output :{Colors.RESET} {Colors.DIM}{JSON_FILE}{Colors.RESET}\n")

    w = 28
    print(f"  {Colors.BOLD}{'#':<5}{'Scan Type':<{w}}Flags{Colors.RESET}")
    print(f"  {'─'*5}{'─'*w}{'─'*18}")

    for k, (label, args, root) in MENU.items():
        tag  = f" {Colors.YELLOW}[sudo]{Colors.RESET}" if root else ""
        disp = args if not args.startswith("_") else "interactive"
        print(f"  {Colors.CYAN}{k:<5}{Colors.RESET}{label:<{w}}{Colors.DIM}{disp}{Colors.RESET}{tag}")

    print(f"\n  {Colors.RED}{EXIT:<5}{Colors.RESET}Exit\n")


def main():
    """Main loop — show menu, handle selections, run scans."""
    banner()

    target = input(f"  {Colors.BOLD}Target IP or domain: {Colors.RESET}").strip()
    if not target:
        cprint(Colors.RED, "[!]", "Target is empty. Exiting.")
        return

    print()

    while True:
        draw_menu(target)

        choice = input(f"  {Colors.BOLD}Choice [{EXIT}-{max(MENU)}]: {Colors.RESET}").strip()

        if choice == EXIT:
            cprint(Colors.YELLOW, "[~]", "Closing. Stay safe!")
            log.info("Session ended.")
            break

        if choice not in MENU:
            cprint(Colors.RED, "[!]", "Invalid choice, try again.\n")
            continue

        label, args, needs_root = MENU[choice]

        if needs_root and not is_root():
            print()
            continue

        if args == "_port":
            ports = input(f"  {Colors.BOLD}Ports (e.g. 80,443 or 1-1000): {Colors.RESET}").strip()
            if not ports:
                cprint(Colors.RED, "[!]", "Port list is empty.\n")
                continue
            args  = f"-p {ports}"
            label = f"Custom Port Scan ({ports})"

        elif args == "_script":
            script = input(f"  {Colors.BOLD}Script name (e.g. http-enum): {Colors.RESET}").strip()
            if not script:
                cprint(Colors.RED, "[!]", "Script name is empty.\n")
                continue
            args  = f"--script {script}"
            label = f"Script Scan ({script})"

        run_scan(target, args, label)

        input(f"\n  {Colors.DIM}Press Enter to go back to the menu…{Colors.RESET}")
        print()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Colors.RED}[!] Closed by user.{Colors.RESET}\n")
        log.info("Session interrupted (Ctrl-C).")
        sys.exit(0)
