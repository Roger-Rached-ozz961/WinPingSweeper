import subprocess
import re
import os
import sys
import datetime
import concurrent.futures
import ipaddress
from tqdm import tqdm
from colorama import Fore, init

init(autoreset=True)

RESULTS_DIR = "Active_Hosts"
os.makedirs(RESULTS_DIR, exist_ok=True)

BANNER = f"""
{Fore.LIGHTMAGENTA_EX}****************************************************
{Fore.LIGHTMAGENTA_EX}*                                                  *
{Fore.LIGHTMAGENTA_EX}*         Windows IP Sweeper - Network Tool        *
{Fore.LIGHTMAGENTA_EX}*              Author: Ozz961                      *
{Fore.LIGHTMAGENTA_EX}*              Version: 1.0                        *
{Fore.LIGHTMAGENTA_EX}*         Sweep your network using ICMP and ARP    *
{Fore.LIGHTMAGENTA_EX}*                                                  *
{Fore.LIGHTMAGENTA_EX}****************************************************
"""

def get_local_subnet():
    """Detect local IPv4 Address and Subnet Mask from ipconfig."""
    try:
        output = subprocess.run(["ipconfig"], capture_output=True, text=True, shell=True).stdout
        ip_match = re.search(r"IPv4 Address[^\d]+(\d+\.\d+\.\d+\.\d+)", output)
        mask_match = re.search(r"Subnet Mask[^\d]+(\d+\.\d+\.\d+\.\d+)", output)

        if ip_match and mask_match:
            ip = ip_match.group(1)
            mask = mask_match.group(1)

            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            print(f"Detected local subnet: {network}")
            return str(network)
        else:
            print(Fore.RED + "IPv4 Address or Subnet Mask not found.")
            return None

    except Exception as e:
        print(Fore.RED + f"Error detecting local subnet: {e}")
        return None

def ping_host(ip):
    """Ping a single host using ICMP."""
    command = ['ping', '-n', '1', ip]
    try:
        response = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True, timeout=1)
        if "TTL" in response:
            return ip, True
    except subprocess.CalledProcessError:
        pass
    except subprocess.TimeoutExpired:
        pass
    return ip, False

def arp_ping_host(ip):
    """Ping a single host using ARP."""
    command = ['arp-ping.exe', ip]
    try:
        response = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True, timeout=5)
        mac_match = re.search(r"Reply that ([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2} is (\d+\.\d+\.\d+\.\d+)", response)
        if mac_match:
            return ip, True
    except subprocess.CalledProcessError:
        pass
    except subprocess.TimeoutExpired:
        pass
    return ip, False

def sweep_network(ip_list, use_icmp=True, use_arp=False):
    """Sweep network using ICMP and/or ARP."""
    active_hosts = set()  # Use a set to avoid duplicates
    
    scan_type = []
    if use_icmp: scan_type.append("ICMP")
    if use_arp: scan_type.append("ARP")
    scan_type = " & ".join(scan_type)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for ip in ip_list:
            if use_icmp:
                futures.append(executor.submit(ping_host, ip))
            if use_arp:
                futures.append(executor.submit(arp_ping_host, ip))
        
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc=f"Scanning using {scan_type}...", ncols=100):
            try:
                result = future.result()
                if result[1]:
                    active_hosts.add(result[0])  # Ensure unique entries using set
            except KeyboardInterrupt:
                print(Fore.RED + "\nScan interrupted by user (CTRL+C). Exiting gracefully...")
                return list(active_hosts)
    
    return list(active_hosts)

def save_results(active_hosts, scan_type):
    """Save active hosts to file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    if "ICMP" in scan_type:
        filename = os.path.join(RESULTS_DIR, f"icmp_active_hosts_{timestamp}.txt")
    if "ARP" in scan_type:
        filename = os.path.join(RESULTS_DIR, f"arp_active_hosts_{timestamp}.txt")
    
    with open(filename, 'w') as f:
        f.write(f"Active Hosts detected by {scan_type}:\n")
        for host in active_hosts:
            f.write(f"{host}\n")
    print(Fore.LIGHTWHITE_EX + f"Results saved to {filename}")

def is_valid_ip_range(ip_range):
    """Validates IP range format: CIDR or IP range."""
    if '/' in ip_range:
        try:
            ipaddress.IPv4Network(ip_range, strict=False)
            return True
        except ValueError:
            return False
    elif '-' in ip_range:
        parts = ip_range.split('-')
        if len(parts) == 2:
            try:
                start_ip = ipaddress.IPv4Address(parts[0].strip())
                end_ip = ipaddress.IPv4Address(parts[1].strip())
                if int(start_ip) <= int(end_ip):
                    return True
            except ValueError:
                return False
    return False

def generate_ip_range(ip_range):
    """Generate a list of IP addresses from a range like '192.168.1.1-192.168.1.10'."""
    if '-' in ip_range:
        start_ip, end_ip = ip_range.split('-')
        start_ip = ipaddress.IPv4Address(start_ip.strip())
        end_ip = ipaddress.IPv4Address(end_ip.strip())
        return [str(ip) for ip in range(int(start_ip), int(end_ip) + 1)]
    return []

def is_private_ip(ip):
    """Check if the IP address is within a private IP range."""
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def main():
    try:
        while True:
            print(BANNER)
            
            print(Fore.CYAN + "Choose scan type:")
            print("1. ICMP Scan")
            print("2. ARP Scan")
            print("3. Both ICMP & ARP Scan")
            print("4. Exit")
            
            choice = input("Enter your choice: ").strip()
            
            if not choice:
                print(Fore.RED + "Error: No option selected. Please choose a valid option.\n")
                continue
            
            if choice == '4':
                print("Exiting...")
                sys.exit()
            
            if choice not in ['1', '2', '3']:
                print(Fore.RED + "Error: Invalid option selected. Please choose a valid option.\n")
                continue
            
            use_icmp = choice in ['1', '3']
            use_arp = choice in ['2', '3']
            
            while True:
                print("\nSelect the Target Range:")
                print("1 - Default (Auto-Detected Subnet)")
                print("2 - Enter Specific Range (CIDR or Range e.g., 192.168.1.1/24 OR 192.168.1.1-210)")

                range_choice = input("Enter your choice: ").strip()

                if not range_choice:
                    print(Fore.RED + "Error: No option selected. Please choose a valid option.\n")
                    continue

                if range_choice not in ['1', '2']:
                    print(Fore.RED + "Error: Invalid range option selected. Please choose a valid option.\n")
                    continue

                ip_list = []

                if range_choice == "1":
                    detected_subnet = get_local_subnet()
                    if detected_subnet:
                        print(Fore.LIGHTCYAN_EX + f"Using Detected Subnet: {detected_subnet}")
                        network = ipaddress.IPv4Network(detected_subnet, strict=False)
                        ip_list = [str(ip) for ip in network.hosts() if is_private_ip(str(ip))]
                    else:
                        print(Fore.RED + "Could not detect subnet. Please enter a range manually.")
                        continue

                elif range_choice == "2":
                    ip_input = input("Enter Specific Range (CIDR or IP range): ").strip()
                    if not is_valid_ip_range(ip_input):
                        print(Fore.RED + "Invalid range format. Please provide a valid CIDR or IP range.")
                        continue

                    try:
                        if '/' in ip_input:
                            network = ipaddress.IPv4Network(ip_input, strict=False)
                            ip_list = [str(ip) for ip in network.hosts() if is_private_ip(str(ip))]
                        elif '-' in ip_input:
                            ip_list = generate_ip_range(ip_input)
                    except ValueError:
                        print(Fore.RED + "Invalid IP input. Try again.")
                        continue
                
                break  # Exit the loop once valid range is selected

            print(f"\nSweeping: {len(ip_list)} hosts using {', '.join([x for x in ['ICMP' if use_icmp else '', 'ARP' if use_arp else ''] if x])}...\n")
            active_hosts = sweep_network(ip_list, use_icmp, use_arp)
            
            if active_hosts:
                print(Fore.LIGHTGREEN_EX + "\nActive hosts found:")
                for host in active_hosts:
                    print(Fore.LIGHTGREEN_EX + f" - {host}")
                save_results(active_hosts, "ICMP" if use_icmp else "ARP")
            else:
                print(Fore.LIGHTYELLOW_EX + "No active hosts found.")

    except KeyboardInterrupt:
        print(Fore.RED + "\nScan interrupted by user (CTRL+C). Exiting gracefully...")
        sys.exit()

if __name__ == "__main__":
    main()
