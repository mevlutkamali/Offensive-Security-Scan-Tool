
import os
import sys
import logging
from datetime import datetime
import subprocess

class colors:
    GREEN = '\033[92m'   
    YELLOW = '\033[93m'  
    RED = '\033[91m'    
    CYAN = '\033[96m'    
    BLUE = '\033[94m'    
    RESET = '\033[0m'    
    BOLD = '\033[1m'
   
# --- LOGGING CONFIGURATION ---
logging.basicConfig(
    filename='pentest_scanner.log', 
    level=logging.INFO,              
    format='%(asctime)s - %(levelname)s - %(message)s'  
)
    
""" Performs UID check for commands requiring root privileges. """
def check_root():
    if os.geteuid() != 0:
        print(f"{colors.RED}[!] ERROR: This operation requires 'sudo' (root) privileges.{colors.RESET}")  
        logging.warning("Yetki hatası: Root gerektiren tarama izinsiz başlatılmak istendi.")
        return False  # Returns False if not Root.
    return True # Root returns True.

""" Creates and runs the Nmap command. """
def run_nmap_command(target, extra_args, save_to_file=False):
    # We create the command as a list.
    command = ["nmap"] + extra_args.split() + [target]
    
    # If the user wants to save the data to a file.
    if save_to_file:
        # scan_URL_20260504_1205.txt || scan_IP_20260504_1205.txt
        file_name = f"scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
        command += ["-oN", file_name]
        
        print(f"{colors.BLUE}[+] The results will be saved to the '{file_name}' file.{colors.RESET}")
        
    try:
        # Commands selected by the user.
        print(f"{colors.YELLOW}[*] Command is being executed: {' '.join(command)}{colors.RESET}\n")
        
        logging.info(f"Scanning has started: {' '.join(command)}")
        
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        for line in process.stdout:
            print(line, end='')
            
        process.wait()
        
        # Check if the command was successful.
        if process.returncode == 0:
            print(f"\n{colors.GREEN}[+] The scan was completed successfully.{colors.RESET}")
            logging.info(f"The scan was completed successfully:{target}")
        else:
            print(f"\n{colors.RED}[-] The scan ended with an error.{colors.RESET}")
    
    except FileNotFoundError:
        print(f"{colors.RED}[!] ERROR: 'nmap' could not be found installed on the system!{colors.RESET}")
    
    except Exception as e:
        print(f"{colors.RED}[!] Unexpected Error: {e}{colors.RESET}")
        logging.error(f"An error occurred: {str(e)}")
   
def show_menu():
    # Menu title.
    banner = f"""
        {colors.CYAN}{colors.BOLD}{'='*45}
            TERMINAL PENTEST FRAMEWORK
        {colors.RESET}{'='*45}
    """
    print(banner)
    
    target = input(f"{colors.BOLD}Target IP or Domain:{colors.RESET}").strip()

    if not target:
        print(f"{colors.RED}[!][!][!] The target cannot be empty.{colors.RESET}")
        return
    
    while True:
        print(f"\n{colors.BLUE}{colors.BOLD}[ MENU OPTIONS ]{colors.RESET}")
        
        menu_items = {
            "0": ("Simple Port Scanning", ""),
            "1": ("Scan all ports", "-p-"),
            "2": ("Service & Script Scanning", "-sC -sV"),
            "3": ("Operating System Detection (Root)", "-O"),
            "4": ("Quick Scan", "-T4"),
            "5": ("Aggressive Scan", "-A"),
            "6": ("Version Detection", "-sV"),
            "7": ("SYN Scan", "-sS"),
            "8": ("UDP Scan (Root)", "-sU"),
            "9": ("Firewall Bypass / Timing", "-f -t 0"),
            "10": ("Specific Port Scanning", "custom_port"),
            "11": ("Script Seçerek Tarama", "custom_script"),
            "12": ("Vulnerability Script Scan", "--script vuln"),
            "13": ("Save the output to a file.", "save_mode"),
            "14": ("[!]EXIT[!]", "exit"),
        }
        
        for key, value in menu_items.items():
            print(f"{colors.GREEN}{key}{colors.RESET} - {value[0]}")

        choice = input(f"\n{colors.BOLD}Your choice: {colors.RESET}").strip()
        
        # Processes that require 'root' access.
        if choice in ["3", "7", "8"] and not check_root():
            continue
        
        # Those requiring special access.
        if choice == "10":
            ports = input("Ports to scan (ör., 80, 443, 8080, ...):")
            run_nmap_command(target, f"-p {ports}")
        
        elif choice == "11":
            script = input("Nmap script name (ör., http-enum):")
            run_nmap_command(target, f"--script {script}")
            
        elif choice == "13":
            run_nmap_command(target, "-F", save_to_file=True)
            
        elif choice in menu_items:
            run_nmap_command(target, menu_items[choice][1])
        
        # Exit.
        if choice == "14":
            print(f"{colors.YELLOW}TERMINAL PENTEST is closing. Stay safe!{colors.RESET}")
            break
        
        else:
            print(f"{colors.RED}Invalid selection, please try again.{colors.RESET}")

# Program starting point.
if __name__ == "__main__":
    try:
        show_menu()
    except KeyboardInterrupt:
        # CTRL + C. 
        print(f"\n{colors.RED}[!] Program kullanıcı tarafından kapatıldı.{colors.RESET}")
        # sys.exit(): Programı işletim sistemi seviyesinde güvenli bir şekilde sonlandırır.
        sys.exit()

print("Finish:)")