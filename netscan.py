#for comand line arguments and exiting
import sys
#for networking interface and ip operations
import socket
#for ip netweork calculations 
import ipaddress
#for parallel threads execution
import concurrent.futures
#for detecting operating system
import platform
#to run operating system commands
import subprocess
#for regular expressions
import re
#for possible future os operations
import os


def print_app_name():
    print(r"""
    
 __    __              __       ______                                
/  \  /  |            /  |     /      \                               
$$  \ $$ |  ______   _$$ |_   /$$$$$$  |  _______   ______   _______  
$$$  \$$ | /      \ / $$   |  $$ \__$$/  /       | /      \ /       \ 
$$$$  $$ |/$$$$$$  |$$$$$$/   $$      \ /$$$$$$$/  $$$$$$  |$$$$$$$  |
$$ $$ $$ |$$    $$ |  $$ | __  $$$$$$  |$$ |       /    $$ |$$ |  $$ |
$$ |$$$$ |$$$$$$$$/   $$ |/  |/  \__$$ |$$ \_____ /$$$$$$$ |$$ |  $$ |
$$ | $$$ |$$       |  $$  $$/ $$    $$/ $$       |$$    $$ |$$ |  $$ |
$$/   $$/  $$$$$$$/    $$$$/   $$$$$$/   $$$$$$$/  $$$$$$$/ $$/   $$/ 
                                                                      
                                                                      
                                                                      
          """)

def get_local_ip_and_mask():
    system = platform.system().lower() # detect the os type
    if system == 'windows':
        output = subprocess.check_output("ipconfig", universal_newlines=True) 
        ip_match = re.search(r'IPv4 Address[. ]*: ([\d.]+)', output)          
        mask_match = re.search(r'Subnet Mask[. ]*: ([\d.]+)', output)         
        if ip_match and mask_match:
            return ip_match.group(1), mask_match.group(1)                    
    else:
        # For Linux/macOS, use ifconfig and parse output
        output = subprocess.check_output("ifconfig", shell=True, universal_newlines=True)
        ip_match = re.search(r'inet ([\d.]+).*?netmask (0x[\da-f]+|[\d.]+)', output)
        if ip_match:
            ip = ip_match.group(1)                                        
            mask = ip_match.group(2)                                           
            if mask.startswith("0x"):                                         
                mask = socket.inet_ntoa(int(mask,16).to_bytes(4, "big"))     
            return ip, mask
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))                                         
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip, '255.255.255.0'                                         
# =================================================================================================================

def mask_to_cidr(mask):
    return sum(bin(int(x)).count('1') for x in mask.split('.'))
# =================================================================================================================

def parse_network(arg=None):
    if not arg:
        ip, mask = get_local_ip_and_mask()                                  
        cidr = mask_to_cidr(mask)                                            
        return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)              
    if '/' in arg:
        return ipaddress.ip_network(arg, strict=False)                     
    elif re.match(r'^\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '.0/24', strict=False)         
    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '/24', strict=False)             
    else:
        raise ValueError("Invalid network format")                       

# =================================================================================================================

def ping(ip):
    ip = str(ip)                                                            
    system = platform.system().lower()                                       
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]                           
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]                           
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        if re.search(r"ttl", result.stdout, re.IGNORECASE):                  
            return ip
    except subprocess.TimeoutExpired:
        return None                                                        
    except Exception:
        return None                                                       
# =================================================================================================================

def scan_network(network):
    print(f"Scanning network: {network}")                                   
    online = []                                                              
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:   
            futures = {executor.submit(ping, ip): ip for ip in network.hosts()}  
            for future in concurrent.futures.as_completed(futures):             
                try:
                    result = future.result()                                     
                    if result:
                        online.append(result)                                   
                except Exception:
                    continue                                                   
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Showing results so far...")        
    return online
# =================================================================================================================

def show_help():
    print(
        "Usage: netscan [network]\n"
        "Scan a network for online devices.\n\n"
        "Options:\n"
        "  -h, --help     Show this help message\n"
        "Examples:\n"
        "  netscan                 # Scan current local network\n"
        "  netscan 192.168.1.0     # Scan 192.168.1.0/24\n"
        "  netscan 192.168.1       # Scan 192.168.1.0/24\n"
        "  netscan 192.168.1.0/24  # Scan 192.168.1.0/24"
    )
# =================================================================================================================
def main():
    args = sys.argv[1:]                                                  
    if not args:
        try:
            network = parse_network()                                      
        except Exception as e:
            print(f"Error: {e}")
            show_help()
            return
    elif args[0] in ['-h', '--help']:
        show_help()                                            
        return
    elif len(args) == 1:
        try:
            network = parse_network(args[0])                             
        except Exception as e:
            print(f"Error: {e}")
            show_help()
            return
    else:
        show_help()                                                       
        return
    try:
        online_hosts = scan_network(network)                                  
        print("\nOnline hosts:")                                               
        for host in sorted(online_hosts, key=lambda x: tuple(map(int, x.split('.')))):
            print(host)                                                        
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")                                   

if __name__ == "__main__":
    main()