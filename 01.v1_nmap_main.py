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


def print_quick_summary(scan_id: str, target: str, xml_output: str) -> None:
    """
    Parse Nmap XML output and print a concise pentester-style summary.

    Displays:
    - Open ports with service name and version
    - Risk note per port (from the built-in knowledge base)
    - OS detection best guess (if available)
    - Uptime hint (if available)
    - Suggested first-strike port

    Args:
        scan_id:    The unique ID of the completed scan (for display only).
        target:     The scanned host IP or hostname.
        xml_output: Raw Nmap XML string captured from stdout.
    """
    width = 52
    border = Colors.MAGENTA + Colors.BOLD + "═" * width + Colors.RESET

    print(f"\n{border}")
    print(f"  {Colors.BOLD}{Colors.WHITE}QUICK SCAN SUMMARY{Colors.RESET}  "
          f"{Colors.DIM}[ID:{scan_id}]  {target}{Colors.RESET}")
    print(f"{border}\n")

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        _print(Colors.YELLOW, "[~]", "XML could not be parsed — summary skipped.")
        return

    open_ports: list[dict] = []

    for host in root.findall("host"):
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            portid   = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")
            service  = port_elem.find("service")
            svc_name = service.get("name", "unknown")    if service is not None else "unknown"
            svc_ver  = service.get("version", "")        if service is not None else ""
            svc_prod = service.get("product", "")        if service is not None else ""

            open_ports.append({
                "port": portid,
                "proto": protocol,
                "service": svc_name,
                "product": svc_prod,
                "version": svc_ver,
            })

    # --- Section 1: Open Ports ---
    if not open_ports:
        _print(Colors.YELLOW, "[~]", "No open ports detected in this scan.")
    else:
        print(f"  {Colors.BOLD}{'PORT':<8}{'PROTO':<7}{'SERVICE':<14}{'PRODUCT / VERSION'}{Colors.RESET}")
        print(f"  {'─'*8}{'─'*7}{'─'*14}{'─'*22}")

        for p in sorted(open_ports, key=lambda x: x["port"]):
            risk_color = _RISK_PRIORITY.get(p["port"], Colors.GREEN)
            full_ver   = f"{p['product']} {p['version']}".strip() or "—"
            print(
                f"  {risk_color}{Colors.BOLD}{p['port']:<8}{Colors.RESET}"
                f"{Colors.DIM}{p['proto']:<7}{Colors.RESET}"
                f"{Colors.CYAN}{p['service']:<14}{Colors.RESET}"
                f"{full_ver}"
            )

            note_tuple = _PORT_NOTES.get(p["port"])
            if note_tuple:
                print(f"  {Colors.DIM}{'':8}{'':7}↳ Risk: {note_tuple[1]}{Colors.RESET}")

        print()

    # --- Section 2: OS Detection ---
    os_matches = root.findall(".//osmatch")
    if os_matches:
        best = max(os_matches, key=lambda x: int(x.get("accuracy", "0")))
        accuracy = best.get("accuracy", "?")
        os_name  = best.get("name", "Unknown")
        print(f"  {Colors.BOLD}OS Guess :{Colors.RESET} {Colors.GREEN}{os_name}{Colors.RESET} "
              f"{Colors.DIM}({accuracy}% confidence){Colors.RESET}")
    else:
        print(f"  {Colors.BOLD}OS Guess :{Colors.RESET} {Colors.DIM}Not available "
              f"(run with -O or -A as root){Colors.RESET}")

    # --- Section 3: Uptime ---
    uptime_elem = root.find(".//uptime")
    if uptime_elem is not None:
        seconds   = int(uptime_elem.get("seconds", 0))
        days      = seconds // 86400
        hours     = (seconds % 86400) // 3600
        last_boot = uptime_elem.get("lastboot", "")
        uptime_str = f"{days}d {hours}h"
        patch_note = (
            f"{Colors.RED}  ← No recent reboot; patches may be missing!{Colors.RESET}"
            if days > 7 else ""
        )
        print(f"  {Colors.BOLD}Uptime   :{Colors.RESET} {uptime_str}{patch_note}")
        if last_boot:
            print(f"  {Colors.BOLD}Last Boot:{Colors.RESET} {Colors.DIM}{last_boot}{Colors.RESET}")
    else:
        print(f"  {Colors.BOLD}Uptime   :{Colors.RESET} {Colors.DIM}Not available{Colors.RESET}")

    # --- Section 4: First-Strike Recommendation ---
    print(f"\n  {Colors.BOLD}{'─'*48}{Colors.RESET}")
    _suggest_first_strike(open_ports)

    print(f"\n{border}\n")


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
    - Assigns a unique scan ID.
    - Logs start/finish events that include the ID and summary outcome.
    - Captures XML output for downstream parsing by 02_exploit_finder.py.
    - Stores a structured entry in scan_results.json regardless of outcome.

    Args:
        target:     IP address or hostname to scan.
        extra_args: Nmap flag string (e.g. '-sC -sV -p 1-1000').
        scan_label: Human-readable name for the scan type.

    Returns:
        The scan result dict on success, None on failure.
    """
    if not check_nmap_installed():
        _print(Colors.RED, "[!]", "'nmap' could not be found on this system.")
        _print(Colors.YELLOW, "[i]", "Install it with:  sudo apt install nmap   (Debian/Ubuntu)")
        _print(Colors.YELLOW, "[i]", "                  sudo yum install nmap   (RHEL/CentOS)")
        logger.error("Nmap binary not found. Scan aborted.")
        return None

    scan_id   = generate_scan_id()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    command   = ["nmap"] + extra_args.split() + ["-oX", "-", target]

    # --- Log: scan started ---
    logger.info("[ID:%s] Scanning started for %s | args: %s", scan_id, target, extra_args)
    _print(Colors.CYAN, "[*]", f"[ID:{scan_id}] {scan_label}  →  {Colors.BOLD}{target}{Colors.RESET}")
    _print(Colors.DIM,  "[>]", f"Command: {' '.join(command)}")
    print()

    result_entry = {
        "id":        scan_id,
        "label":     scan_label,
        "target":    target,
        "timestamp": timestamp,
        "nmap_args": extra_args,
        "command":   " ".join(command),
        "status":    "pending",
        "xml_output": None,
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
            result_entry["status"]     = "success"
            result_entry["xml_output"] = stdout

            _progress_bar(f"[ID:{scan_id}] Scan completed")
            _print(Colors.GREEN, "[+]", f"[ID:{scan_id}] Scan finished successfully for {target}.")

            # Derive a compact summary for the log line
            open_port_count = stdout.count("<state state=\"open\"")
            summary = (
                f"open_ports_found={open_port_count}"
                if open_port_count >= 0
                else "no summary available"
            )
            logger.info(
                "[ID:%s] Scanning finished for %s | status=success | %s",
                scan_id, target, summary,
            )

            # Print inline pentester summary immediately after scan
            print_quick_summary(scan_id, target, stdout)

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
        # Nmap disappeared between the check and execution (edge case).
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
