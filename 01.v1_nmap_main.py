import os
import sys
import logging
from datetime import datetime
import subprocess
import json

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
        return False  
    return True 

""" Creates and runs the Nmap command. """
def run_nmap_command(target, extra_args, save_to_file=False):
    # -oX - ekleyerek Nmap çıktısını XML formatında alıyoruz ki sonra işleyebilelim
    command = ["nmap"] + extra_args.split() + ["-oX", "-", target]
    
    try:
        print(f"{colors.YELLOW}[*] Command is being executed: {' '.join(command)}{colors.RESET}\n")
        logging.info(f"Scanning has started: {' '.join(command)}")
        
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, # Hataları ayrı yakalamak için PIPE yaptık
            text=True
        )
        
        # Çıktıyı yakalıyoruz
        stdout, stderr = process.communicate()
        
        # Ekranda hala bir şeyler görmek istersen (XML yerine temiz çıktı):
        # Nmap XML bastığı için burayı terminale basmak kalabalık yapabilir.
        # Ama işlemin bittiğini anlamak için sonucu kontrol ediyoruz.
        
        if process.returncode == 0:
            print(f"{colors.GREEN}[+] Scan completed. Processing data...{colors.RESET}")
            
            # --- JSON KAYIT MANTIĞI ---
            scan_data = {
                "target": target,
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "arguments": extra_args,
                "xml_output": stdout  # 02_exploit_finder.py bu XML'i parse edecek
            }
            
            with open("scan_results.json", "w", encoding="utf-8") as f:
                json.dump(scan_data, f, ensure_ascii=False, indent=4)
            
            print(f"{colors.BLUE}[+] Results exported to 'scan_results.json' successfully.{colors.RESET}")
            logging.info(f"The scan was completed and saved to JSON: {target}")
            
        else:
            print(f"\n{colors.RED}[-] The scan ended with an error: {stderr}{colors.RESET}")
    
    except FileNotFoundError:
        print(f"{colors.RED}[!] ERROR: 'nmap' could not be found!{colors.RESET}")
    except Exception as e:
        print(f"{colors.RED}[!] Unexpected Error: {e}{colors.RESET}")
        logging.error(f"An error occurred: {str(e)}")

def show_menu():
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
            "14": ("[!]EXIT[!]", "exit"),
        }
        
        for key, value in menu_items.items():
            print(f"{colors.GREEN}{key}{colors.RESET} - {value[0]}")

        choice = input(f"\n{colors.BOLD}Your choice: {colors.RESET}").strip()
        
        if choice in ["3", "7", "8"] and not check_root():
            continue
        
        if choice == "10":
            ports = input("Ports to scan (ör., 80, 443):")
            run_nmap_command(target, f"-p {ports}")
        elif choice == "11":
            script = input("Nmap script name (ör., http-enum):")
            run_nmap_command(target, f"--script {script}")
        elif choice == "14":
            print(f"{colors.YELLOW}TERMINAL PENTEST is closing. Stay safe!{colors.RESET}")
            break
        elif choice in menu_items:
            run_nmap_command(target, menu_items[choice][1])
        else:
            print(f"{colors.RED}Invalid selection, please try again.{colors.RESET}")

if __name__ == "__main__":
    try:
        show_menu()
    except KeyboardInterrupt:
        print(f"\n{colors.RED}[!] Program kullanıcı tarafından kapatıldı.{colors.RESET}")
        sys.exit()