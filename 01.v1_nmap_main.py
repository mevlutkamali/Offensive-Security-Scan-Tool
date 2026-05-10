"""
01_nmap_main.py — Nmap Scanning Module
=======================================
Terminal Pentest Framework - Phase 1: Discovery & Port Scanning

This module handles all Nmap-based scanning operations, stores results
in a structured JSON format, and maintains a detailed log file.
Results are consumed by 02_exploit_finder.py via scan_results.json.

Usage:
    python3 01_nmap_main.py          # Interactive menu
    sudo python3 01_nmap_main.py     # Required for SYN/OS/UDP scans

Author: [Your Name]
License: MIT
"""

import os
import sys
import json
import logging
import subprocess
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Terminal Color Definitions
# ---------------------------------------------------------------------------

class Colors:
    """ANSI escape codes for terminal coloring."""

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
    UNDERLINE = '\033[4m'


# Backward-compatible alias so any future module can import `colors` as well.
colors = Colors


# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------

LOG_FILE  = "pentest_scanner.log"
JSON_FILE = "scan_results.json"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper / Utility Functions
# ---------------------------------------------------------------------------

def _print(color: str, prefix: str, message: str) -> None:
    """
    Unified print helper with consistent prefix formatting.

    Args:
        color:   An ANSI color code from the Colors class.
        prefix:  Short tag such as '[+]', '[!]', '[*]'.
        message: The human-readable message to display.
    """
    print(f"{color}{Colors.BOLD}{prefix}{Colors.RESET} {message}")


def _progress_bar(label: str, total: int = 30, char: str = "█") -> None:
    """
    Render a simple animated progress bar in the terminal.

    Args:
        label: Text to display beside the bar.
        total: Width of the bar in characters.
        char:  Character used to fill the bar.
    """
    bar = char * total
    print(f"\n  {Colors.CYAN}{label}{Colors.RESET}")
    print(f"  {Colors.BLUE}[{bar}]{Colors.RESET} {Colors.GREEN}Done{Colors.RESET}\n")


def generate_scan_id() -> str:
    """
    Generate a short, human-readable unique scan identifier.

    Returns:
        A 8-character uppercase hex string (e.g. 'A3F1C9B2').
    """
    return uuid.uuid4().hex[:8].upper()


def check_nmap_installed() -> bool:
    """
    Verify that the 'nmap' binary is available on the system PATH.

    Returns:
        True if nmap is found, False otherwise.
    """
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def check_root() -> bool:
    """
    Check whether the current process has root (UID 0) privileges.

    Returns:
        True if running as root, False otherwise.
    Logs a warning when privilege is insufficient.
    """
    if os.geteuid() != 0:
        _print(Colors.RED, "[!]", "This operation requires 'sudo' (root) privileges.")
        _print(Colors.YELLOW, "[i]", "Re-run with:  sudo python3 01_nmap_main.py")
        logger.warning("Privilege error: root-required scan was attempted without sudo.")
        return False
    return True


# ---------------------------------------------------------------------------
# Quick Summary Parser
# ---------------------------------------------------------------------------

# Risk seviyesi: port numarasına göre ön tanımlı notlar
_PORT_NOTES: dict[int, tuple[str, str]] = {
    21:   ("FTP",         "Cleartext credentials, anonymous login possible"),
    22:   ("SSH",         "Brute-force / outdated version exploits"),
    23:   ("Telnet",      "Cleartext protocol — highly insecure"),
    25:   ("SMTP",        "Open relay, user enumeration"),
    53:   ("DNS",         "Zone transfer (AXFR), amplification attacks"),
    80:   ("HTTP",        "SQLi, XSS, Path Traversal, Host Header injection"),
    110:  ("POP3",        "Cleartext credentials"),
    111:  ("RPCbind",     "NFS enumeration"),
    135:  ("MSRPC",       "Windows RPC exploitation"),
    139:  ("NetBIOS",     "SMB enumeration, EternalBlue"),
    443:  ("HTTPS",       "TLS misconfiguration, weak ciphers, web app vulns"),
    445:  ("SMB",         "EternalBlue (MS17-010), relay attacks"),
    1433: ("MSSQL",       "SA brute-force, xp_cmdshell"),
    1521: ("Oracle DB",   "Default credentials, TNS listener poisoning"),
    3306: ("MySQL",       "Remote root login, UDF exploitation"),
    3389: ("RDP",         "BlueKeep (CVE-2019-0708), brute-force"),
    5432: ("PostgreSQL",  "Default credentials, COPY TO/FROM exploit"),
    5900: ("VNC",         "No-auth mode, weak password"),
    6379: ("Redis",       "No-auth RCE, config overwrite"),
    8080: ("HTTP-Alt",    "Proxy bypass, web app vulns"),
    8443: ("HTTPS-Alt",   "Same as 443 with admin panel exposure"),
    27017:("MongoDB",     "No-auth access, data exfiltration"),
}

_RISK_PRIORITY: dict[int, str] = {
    # port: risk rengi
    21: Colors.RED, 23: Colors.RED, 139: Colors.RED, 445: Colors.RED,
    3389: Colors.RED, 6379: Colors.RED, 27017: Colors.RED,
    22: Colors.YELLOW, 25: Colors.YELLOW, 53: Colors.YELLOW,
    80: Colors.YELLOW, 110: Colors.YELLOW, 443: Colors.YELLOW,
    3306: Colors.YELLOW, 5432: Colors.YELLOW, 5900: Colors.YELLOW,
}


def print_quick_summary(scan_id: str, target: str, parsed: dict) -> None:
    """
    Print a concise pentester-style summary from already-parsed scan data.

    Accepts the structured dict produced by _parse_xml_to_structured so that
    XML is never re-parsed and never reaches this layer.

    Displays:
    - Open ports with service, version, and inline risk notes
    - OS detection best guess and confidence
    - Host latency and status
    - Suggested first-strike port with rationale

    Args:
        scan_id: Unique ID of the completed scan (display only).
        target:  Scanned host IP or hostname.
        parsed:  Dict returned by _parse_xml_to_structured().
    """
    width  = 52
    border = Colors.MAGENTA + Colors.BOLD + "═" * width + Colors.RESET

    print(f"\n{border}")
    print(f"  {Colors.BOLD}{Colors.WHITE}QUICK SCAN SUMMARY{Colors.RESET}  "
          f"{Colors.DIM}[ID:{scan_id}]  {target}{Colors.RESET}")
    print(f"{border}\n")

    open_ports = parsed["results"]
    summary    = parsed["summary"]
    os_guess   = parsed["os_guess"]

    # --- Section 1: Open Ports ---
    if not open_ports:
        _print(Colors.YELLOW, "[~]", "No open ports detected in this scan.")
    else:
        print(f"  {Colors.BOLD}{'PORT':<8}{'PROTO':<7}{'SERVICE':<14}{'VERSION'}{Colors.RESET}")
        print(f"  {'─'*8}{'─'*7}{'─'*14}{'─'*22}")

        for p in open_ports:
            risk_color = _RISK_PRIORITY.get(p["port"], Colors.GREEN)
            ver_str    = p.get("version", "—") or "—"
            print(
                f"  {risk_color}{Colors.BOLD}{p['port']:<8}{Colors.RESET}"
                f"{Colors.DIM}{p['protocol']:<7}{Colors.RESET}"
                f"{Colors.CYAN}{p['service']:<14}{Colors.RESET}"
                f"{ver_str}"
            )
            note_tuple = _PORT_NOTES.get(p["port"])
            if note_tuple:
                print(f"  {Colors.DIM}{'':8}{'':7}↳ Risk: {note_tuple[1]}{Colors.RESET}")

        print()

    # --- Section 2: Host & Network Info ---
    status_color = Colors.GREEN if summary["host_status"] == "up" else Colors.RED
    print(f"  {Colors.BOLD}Status   :{Colors.RESET} "
          f"{status_color}{summary['host_status'].upper()}{Colors.RESET}  "
          f"{Colors.DIM}latency: {summary['latency'] or 'n/a'}{Colors.RESET}")
    print(f"  {Colors.BOLD}Ports    :{Colors.RESET} "
          f"{Colors.GREEN}{summary['open_ports']} open{Colors.RESET}  "
          f"{Colors.DIM}{summary['filtered_ports']} closed/filtered{Colors.RESET}")

    # --- Section 3: OS Detection ---
    if os_guess:
        print(f"  {Colors.BOLD}OS Guess :{Colors.RESET} {Colors.GREEN}{os_guess['name']}{Colors.RESET} "
              f"{Colors.DIM}({os_guess['accuracy']} confidence){Colors.RESET}")
    else:
        print(f"  {Colors.BOLD}OS Guess :{Colors.RESET} "
              f"{Colors.DIM}Not available (use -O or -A with sudo){Colors.RESET}")

    # --- Section 4: First-Strike Recommendation ---
    print(f"\n  {Colors.BOLD}{'─'*48}{Colors.RESET}")
    _suggest_first_strike(open_ports)

    print(f"\n{border}\n")


def _infer_scan_type(nmap_args: str) -> str:
    """
    Derive a human-readable scan type label from the Nmap argument string.

    Args:
        nmap_args: The raw Nmap flags string passed to run_nmap_scan.

    Returns:
        A snake_case label string, e.g. 'service_detection'.
    """
    a = nmap_args.lower()
    if "--script vuln" in a:         return "vuln_scan"
    if "-a" in a.split():            return "aggressive"
    if "-sc" in a and "-sv" in a:    return "service_detection"
    if "-sv" in a.split():           return "version_detection"
    if "-su" in a.split():           return "udp_scan"
    if "-ss" in a.split():           return "syn_scan"
    if "-o" in a.split():            return "os_detection"
    if "-p-" in a:                   return "full_port_scan"
    if "-t4" in a.split():           return "quick_scan"
    if "-f" in a.split():            return "firewall_bypass"
    if "--script" in a:              return "script_scan"
    if "-p" in a.split():            return "custom_port_scan"
    return "simple_port_scan"


def _parse_xml_to_structured(xml_str: str) -> dict:
    """
    Convert raw Nmap XML output into a clean, frontend-friendly dict.

    XML is fully consumed here and never stored or surfaced to the user.
    Only meaningful fields are extracted; all Nmap metadata noise is dropped.

    Args:
        xml_str: Raw Nmap XML string captured from stdout.

    Returns:
        A dict with keys:
            results        – list of open port dicts
            os_guess       – {name, accuracy} or None
            summary        – {open_ports, filtered_ports, host_status, latency}
    """
    structured: dict = {
        "results":  [],
        "os_guess": None,
        "summary": {
            "open_ports":     0,
            "filtered_ports": 0,
            "host_status":    "unknown",
            "latency":        None,
        },
    }

    try:
        tree = ET.fromstring(xml_str)
    except ET.ParseError:
        return structured

    for host in tree.findall("host"):

        # ── Host status ──────────────────────────────────────────────────────
        status_elem = host.find("status")
        if status_elem is not None:
            structured["summary"]["host_status"] = status_elem.get("state", "unknown")

        # ── Latency (srtt is stored in microseconds by Nmap) ─────────────────
        times_elem = host.find("times")
        if times_elem is not None:
            srtt = times_elem.get("srtt", "")
            if srtt.isdigit():
                structured["summary"]["latency"] = f"{round(int(srtt) / 1000, 2)}ms"

        # ── Ports ────────────────────────────────────────────────────────────
        ports_elem = host.find("ports")
        if ports_elem is not None:

            # Closed/filtered bulk counts from <extraports>
            for extra in ports_elem.findall("extraports"):
                if extra.get("state") in ("filtered", "closed"):
                    structured["summary"]["filtered_ports"] += int(
                        extra.get("count", 0)
                    )

            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None:
                    continue

                state  = state_elem.get("state", "unknown")
                reason = state_elem.get("reason", "")

                if state != "open":
                    continue

                portid   = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")
                svc_elem = port_elem.find("service")

                svc_name = svc_elem.get("name", "unknown")    if svc_elem is not None else "unknown"
                svc_prod = svc_elem.get("product", "")        if svc_elem is not None else ""
                svc_ver  = svc_elem.get("version", "")        if svc_elem is not None else ""

                port_entry: dict = {
                    "port":     portid,
                    "protocol": protocol,
                    "service":  svc_name,
                    "state":    state,
                    "reason":   reason,
                }
                full_ver = f"{svc_prod} {svc_ver}".strip()
                if full_ver:
                    port_entry["version"] = full_ver

                structured["results"].append(port_entry)

        # ── OS Detection ─────────────────────────────────────────────────────
        os_elem = host.find("os")
        if os_elem is not None:
            os_matches = os_elem.findall("osmatch")
            if os_matches:
                best = max(os_matches, key=lambda x: int(x.get("accuracy", "0")))
                structured["os_guess"] = {
                    "name":     best.get("name", "Unknown"),
                    "accuracy": f"{best.get('accuracy', '?')}%",
                }

    # Sort by port number ascending
    structured["results"].sort(key=lambda p: p["port"])
    structured["summary"]["open_ports"] = len(structured["results"])

    return structured


def _suggest_first_strike(open_ports: list[dict]) -> None:
    """
    Print a short first-strike recommendation based on open ports.

    Priority order (descending): web (80/443/8080/8443) → SMB (445/139) →
    DB (3306/5432/1433/27017/6379) → RDP (3389) → SSH (22) → first open port.

    Args:
        open_ports: List of dicts produced by print_quick_summary.
    """
    if not open_ports:
        return

    port_nums  = {p["port"] for p in open_ports}
    priorities = [
        (80,    "HTTP",       "Web apps carry the most developer mistakes (SQLi, XSS, Auth bypass)."),
        (443,   "HTTPS",      "Encrypted but same web attack surface — check TLS config too."),
        (8080,  "HTTP-Alt",   "Often an admin panel or dev server with weaker protections."),
        (8443,  "HTTPS-Alt",  "Admin interfaces frequently exposed here."),
        (445,   "SMB",        "MS17-010 / EternalBlue is still unpatched on many systems."),
        (139,   "NetBIOS",    "SMB enumeration gateway — credential relay potential."),
        (3306,  "MySQL",      "Remote root or UDF code execution if misconfigured."),
        (6379,  "Redis",      "Unauthenticated Redis = instant RCE via config overwrite."),
        (27017, "MongoDB",    "No-auth MongoDB exposes full database with zero effort."),
        (1433,  "MSSQL",      "xp_cmdshell can give OS-level code execution."),
        (3389,  "RDP",        "BlueKeep or credential stuffing — juicy target."),
        (22,    "SSH",        "Last resort: brute-force or check for default credentials."),
    ]

    for port, name, reason in priorities:
        if port in port_nums:
            print(f"  {Colors.BOLD}{Colors.MAGENTA}First Strike →{Colors.RESET} "
                  f"{Colors.YELLOW}Port {port} ({name}){Colors.RESET}")
            print(f"  {Colors.DIM}  Reason: {reason}{Colors.RESET}")
            return

    # Fallback: lowest open port
    first = sorted(open_ports, key=lambda x: x["port"])[0]
    print(f"  {Colors.BOLD}{Colors.MAGENTA}First Strike →{Colors.RESET} "
          f"{Colors.YELLOW}Port {first['port']} ({first['service']}){Colors.RESET}")
    print(f"  {Colors.DIM}  Reason: Only open port — start enumeration here.{Colors.RESET}")


# ---------------------------------------------------------------------------
# JSON Result Store
# ---------------------------------------------------------------------------

def _load_results() -> list:
    """
    Load existing scan results from JSON_FILE.

    Returns:
        A list of previous scan result dicts, or an empty list if the
        file does not exist or contains invalid JSON.
    """
    if not os.path.exists(JSON_FILE):
        return []
    try:
        with open(JSON_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_result(entry: dict) -> None:
    """
    Append a single scan result entry to the persistent JSON store.

    The file uses a top-level JSON array so that 02_exploit_finder.py
    can iterate over all historical scans without any pre-processing.

    Args:
        entry: A dict representing one completed (or failed) scan.
    """
    results = _load_results()
    results.append(entry)
    try:
        with open(JSON_FILE, "w", encoding="utf-8") as fh:
            json.dump(results, fh, ensure_ascii=False, indent=4)
        _print(Colors.BLUE, "[+]", f"Results appended to '{JSON_FILE}'.")
    except OSError as exc:
        _print(Colors.RED, "[!]", f"Could not write to '{JSON_FILE}': {exc}")
        logger.error("[ID:%s] Failed to write JSON: %s", entry.get("id", "?"), exc)


# ---------------------------------------------------------------------------
# Core Scanning Function
# ---------------------------------------------------------------------------

def run_nmap_scan(target: str, extra_args: str, scan_label: str = "Custom Scan") -> Optional[dict]:
    """
    Execute an Nmap command, persist results, and emit structured logs.

    The function:
    - Assigns a unique scan ID and infers a scan type label.
    - Logs start/finish events including the ID and open-port summary.
    - Parses Nmap XML output internally via _parse_xml_to_structured();
      raw XML is never stored or surfaced.
    - Stores a clean, frontend-friendly JSON entry regardless of outcome.

    Args:
        target:     IP address or hostname to scan.
        extra_args: Nmap flag string (e.g. '-sC -sV -p 1-1000').
        scan_label: Human-readable name for the scan type.

    Returns:
        The completed scan result dict on success, None on failure.
    """
    if not check_nmap_installed():
        _print(Colors.RED, "[!]", "'nmap' could not be found on this system.")
        _print(Colors.YELLOW, "[i]", "Install it with:  sudo apt install nmap   (Debian/Ubuntu)")
        _print(Colors.YELLOW, "[i]", "                  sudo yum install nmap   (RHEL/CentOS)")
        logger.error("Nmap binary not found. Scan aborted.")
        return None

    scan_id   = generate_scan_id()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_type = _infer_scan_type(extra_args)
    command   = ["nmap"] + extra_args.split() + ["-oX", "-", target]

    logger.info("[ID:%s] Scanning started for %s | type: %s | args: %s",
                scan_id, target, scan_type, extra_args)
    _print(Colors.CYAN, "[*]", f"[ID:{scan_id}] {scan_label}  →  {Colors.BOLD}{target}{Colors.RESET}")
    _print(Colors.DIM,  "[>]", f"Command: {' '.join(command)}")
    print()

    # Base entry — populated with parsed results on success, error details on failure.
    # xml_output is intentionally absent; XML stays internal to this function.
    result_entry: dict = {
        "scan_id":   scan_id,
        "target":    target,
        "status":    "pending",
        "scan_type": scan_type,
        "timestamp": timestamp,
        "results":   [],
        "os_guess":  None,
        "summary":   {
            "open_ports":     0,
            "filtered_ports": 0,
            "host_status":    "unknown",
            "latency":        None,
        },
        "error":     None,
    }

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            # Parse XML once — result used for both JSON storage and terminal display
            parsed = _parse_xml_to_structured(stdout)

            result_entry["status"]   = "success"
            result_entry["results"]  = parsed["results"]
            result_entry["os_guess"] = parsed["os_guess"]
            result_entry["summary"]  = parsed["summary"]

            _progress_bar(f"[ID:{scan_id}] Scan completed")
            _print(Colors.GREEN, "[+]", f"[ID:{scan_id}] Scan finished successfully for {target}.")
            logger.info(
                "[ID:%s] Scanning finished for %s | status=success | open_ports=%d | host=%s",
                scan_id, target,
                parsed["summary"]["open_ports"],
                parsed["summary"]["host_status"],
            )

            print_quick_summary(scan_id, target, parsed)

        else:
            result_entry["status"] = "error"
            result_entry["error"]  = stderr.strip()

            _print(Colors.RED, "[-]", f"[ID:{scan_id}] Scan ended with an error:")
            print(f"        {Colors.DIM}{stderr.strip()}{Colors.RESET}\n")
            logger.error(
                "[ID:%s] Scanning failed for %s | stderr: %s",
                scan_id, target, stderr.strip(),
            )

    except FileNotFoundError:
        result_entry["status"] = "error"
        result_entry["error"]  = "nmap binary not found at runtime"
        _print(Colors.RED, "[!]", "'nmap' disappeared unexpectedly. Is it still installed?")
        logger.error("[ID:%s] nmap binary missing at runtime.", scan_id)

    except PermissionError:
        result_entry["status"] = "error"
        result_entry["error"]  = "insufficient privileges"
        _print(Colors.RED, "[!]", f"[ID:{scan_id}] Permission denied. Run with sudo.")
        logger.error(
            "[ID:%s] Permission denied for %s | args: %s",
            scan_id, target, extra_args,
        )

    except Exception as exc:  # pylint: disable=broad-except
        result_entry["status"] = "error"
        result_entry["error"]  = str(exc)
        _print(Colors.RED, "[!]", f"[ID:{scan_id}] Unexpected error: {exc}")
        logger.exception("[ID:%s] Unexpected exception during scan of %s.", scan_id, target)

    _save_result(result_entry)
    return result_entry if result_entry["status"] == "success" else None


# ---------------------------------------------------------------------------
# Menu Definition
# ---------------------------------------------------------------------------

# Each entry: (display_label, nmap_args_string, requires_root)
MENU_OPTIONS: dict[str, tuple[str, str, bool]] = {
    "1":  ("Simple Port Scan",               "",                False),
    "2":  ("Full Port Scan",                 "-p-",             False),
    "3":  ("Service & Script Scan",          "-sC -sV",         False),
    "4":  ("OS Detection",                   "-O",              True),
    "5":  ("Quick Scan",                     "-T4",             False),
    "6":  ("Aggressive Scan",                "-A",              False),
    "7":  ("Version Detection",              "-sV",             False),
    "8":  ("SYN Scan (Stealth)",             "-sS",             True),
    "9":  ("UDP Scan",                       "-sU",             True),
    "10": ("Firewall Bypass / Low & Slow",   "-f -T0",          False),
    "11": ("Custom Port Scan",               "_custom_port",    False),
    "12": ("Custom Script Scan",             "_custom_script",  False),
    "13": ("Vulnerability Script Scan",      "--script vuln",   False),
}

EXIT_KEY = "0"


def _render_banner() -> None:
    """Print the framework ASCII banner to the terminal."""
    width = 52
    border = Colors.CYAN + Colors.BOLD + "─" * width + Colors.RESET
    title  = "TERMINAL  PENTEST  FRAMEWORK"
    sub    = "Phase 1  ·  Network Discovery & Port Scanning"

    print(f"\n{border}")
    print(f"  {Colors.BOLD}{Colors.WHITE}{title}{Colors.RESET}")
    print(f"  {Colors.DIM}{sub}{Colors.RESET}")
    print(f"{border}\n")


def _render_menu(target: str) -> None:
    """
    Render the scan option menu with the current target highlighted.

    Args:
        target: The IP address or hostname currently being targeted.
    """
    print(f"  {Colors.BOLD}Target :{Colors.RESET} {Colors.GREEN}{target}{Colors.RESET}")
    print(f"  {Colors.BOLD}Log    :{Colors.RESET} {Colors.DIM}{LOG_FILE}{Colors.RESET}")
    print(f"  {Colors.BOLD}Results:{Colors.RESET} {Colors.DIM}{JSON_FILE}{Colors.RESET}\n")

    col_width = 30
    print(f"  {Colors.BOLD}{'#':<4}  {'Scan Type':<{col_width}}  {'Flags'}{Colors.RESET}")
    print(f"  {'─'*4}  {'─'*col_width}  {'─'*20}")

    for key, (label, args, root) in MENU_OPTIONS.items():
        root_tag = f" {Colors.YELLOW}[root]{Colors.RESET}" if root else ""
        display_args = args if not args.startswith("_") else "interactive"
        print(
            f"  {Colors.CYAN}{key:<4}{Colors.RESET} "
            f" {label:<{col_width}} "
            f" {Colors.DIM}{display_args}{Colors.RESET}{root_tag}"
        )

    print(f"\n  {Colors.RED}{EXIT_KEY:<4}{Colors.RESET}  Exit\n")


# ---------------------------------------------------------------------------
# Main Interactive Loop
# ---------------------------------------------------------------------------

def show_menu() -> None:
    """
    Run the interactive terminal menu loop.

    Prompts for a target, then accepts repeated scan-type selections until
    the user chooses to exit or hits Ctrl-C.
    """
    _render_banner()

    target = input(
        f"  {Colors.BOLD}Enter target IP or domain:{Colors.RESET} "
    ).strip()

    if not target:
        _print(Colors.RED, "[!]", "Target cannot be empty. Exiting.")
        return

    print()

    while True:
        _render_menu(target)

        choice = input(
            f"  {Colors.BOLD}Your choice [{EXIT_KEY}-{max(MENU_OPTIONS)}]: {Colors.RESET}"
        ).strip()

        if choice == EXIT_KEY:
            _print(Colors.YELLOW, "[~]", "Terminal Pentest Framework closed. Stay safe!")
            logger.info("Session ended by user.")
            break

        if choice not in MENU_OPTIONS:
            _print(Colors.RED, "[!]", "Invalid selection — please try again.\n")
            continue

        label, args, needs_root = MENU_OPTIONS[choice]

        if needs_root and not check_root():
            print()
            continue

        # Handle interactive (custom) scan types
        if args == "_custom_port":
            ports = input(
                f"  {Colors.BOLD}Ports to scan (e.g. 80,443 or 1-1000): {Colors.RESET}"
            ).strip()
            if not ports:
                _print(Colors.RED, "[!]", "Port specification cannot be empty.\n")
                continue
            args = f"-p {ports}"
            label = f"Custom Port Scan ({ports})"

        elif args == "_custom_script":
            script = input(
                f"  {Colors.BOLD}Nmap script name (e.g. http-enum): {Colors.RESET}"
            ).strip()
            if not script:
                _print(Colors.RED, "[!]", "Script name cannot be empty.\n")
                continue
            args = f"--script {script}"
            label = f"Script Scan ({script})"

        run_nmap_scan(target, args, scan_label=label)

        input(f"\n  {Colors.DIM}Press Enter to return to the menu…{Colors.RESET}")
        print()


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        show_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {Colors.RED}[!] Interrupted by user (Ctrl-C). Exiting.{Colors.RESET}\n")
        logger.info("Session interrupted by user (KeyboardInterrupt).")
        sys.exit(0)
