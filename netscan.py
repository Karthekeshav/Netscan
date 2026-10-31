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
import json

MAX_HOSTS = 4096


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
    """Read local interface configuration; never guess a /24 or contact an external host."""
    system = platform.system().lower()
    try:
        if system == "windows":
            output = subprocess.check_output(["ipconfig"], text=True, timeout=5)
            # Keep an address and its mask within the same adapter block.
            for block in re.split(r"\n(?=\S)", output):
                ip = re.search(r"IPv4 Address[. ]*:\s*([\d.]+)", block)
                mask = re.search(r"Subnet Mask[. ]*:\s*([\d.]+)", block)
                if ip and mask and not ipaddress.IPv4Address(ip.group(1)).is_loopback:
                    mask_to_cidr(mask.group(1))
                    return ip.group(1), mask.group(1)
        else:
            if system == "linux":
                try:
                    output = subprocess.check_output(["ip", "-j", "address", "show", "up"], text=True, timeout=5)
                    for interface in json.loads(output):
                        for address in interface.get("addr_info", []):
                            if address.get("family") == "inet" and address.get("scope") == "global":
                                ip = ipaddress.IPv4Address(address["local"])
                                prefix = int(address["prefixlen"])
                                if not ip.is_loopback:
                                    return str(ip), str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
                except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
                    pass  # Older Linux systems may provide ifconfig instead.
            output = subprocess.check_output(["ifconfig"], text=True, timeout=5)
            for match in re.finditer(r"\binet\s+([\d.]+)[^\n]*?netmask\s+(0x[\da-fA-F]+|[\d.]+)", output):
                ip, mask = match.groups()
                if ipaddress.IPv4Address(ip).is_loopback:
                    continue
                if mask.startswith("0x"):
                    mask = socket.inet_ntoa(int(mask, 16).to_bytes(4, "big"))
                mask_to_cidr(mask)
                return ip, mask
    except (OSError, subprocess.SubprocessError, ValueError, OverflowError):
        pass
    raise ValueError("Cannot determine the local IPv4 subnet. Supply it explicitly, e.g. 192.168.1.0/24")
# =================================================================================================================

def mask_to_cidr(mask):
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
# =================================================================================================================

def parse_network(arg=None):
    if not arg:
        ip, mask = get_local_ip_and_mask()                                  
        cidr = mask_to_cidr(mask)                                            
        return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)              
    if '/' in arg:
        network = ipaddress.ip_network(arg, strict=False)
        if network.version != 4:
            raise ValueError("Only IPv4 networks are supported")
        return network
    elif re.match(r'^\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '.0/24', strict=False)         
    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '/24', strict=False)             
    else:
        raise ValueError("Invalid network format")                       

# =================================================================================================================

def ping(ip):
    try:
        ip = str(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        return None
    system = platform.system().lower()                                       
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]                           
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]                           
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        if result.returncode == 0 and re.search(r"\bttl\s*=\s*\d+", result.stdout, re.IGNORECASE):
            return ip
    except subprocess.TimeoutExpired:
        return None                                                        
    except Exception:
        return None                                                       
# =================================================================================================================

def scan_network(network):
    network = ipaddress.ip_network(network, strict=False)
    host_count = network.num_addresses - (2 if network.prefixlen < 31 else 0)
    if network.version != 4 or host_count > MAX_HOSTS:
        raise ValueError(f"Use an IPv4 subnet with at most {MAX_HOSTS} hosts")
    print(f"Scanning network: {network}")                                   
    online = []                                                              
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=100)
    try:
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
    finally:
        # Do not wait for every queued address after Ctrl+C; only running pings finish.
        executor.shutdown(wait=True, cancel_futures=True)
    return online
# =================================================================================================================

def show_help():
    print(
        "Usage: netscan [network]\n"
        "Scan a network for online devices.\n\n"
        "IPv4 only; at most 4096 hosts per scan. Scan only networks you are authorised to test.\n\n"
        "Options:\n"
        "  -h, --help     Show this help message\n"
        "Examples:\n"
        "  netscan                 # Scan current local network\n"
        "  netscan 192.168.1.0     # Scan 192.168.1.0/24\n"
        "  netscan 192.168.1       # Scan 192.168.1.0/24\n"
        "  netscan 192.168.1.0/24  # Scan 192.168.1.0/24"
    )
# =================================================================================================================
def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if not args:
        try:
            network = parse_network()                                      
        except Exception as e:
            print(f"Error: {e}")
            show_help()
            return 1
    elif args[0] in ['-h', '--help']:
        show_help()                                            
        return
    elif len(args) == 1:
        try:
            network = parse_network(args[0])                             
        except Exception as e:
            print(f"Error: {e}")
            show_help()
            return 1
    else:
        show_help()                                                       
        return 1
    try:
        online_hosts = scan_network(network)                                  
        print("\nOnline hosts:")                                               
        for host in sorted(online_hosts, key=lambda x: tuple(map(int, x.split('.')))):
            print(host)                                                        
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")                                   
        return 130
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
