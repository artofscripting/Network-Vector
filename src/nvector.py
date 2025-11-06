#!/usr/bin/env python3
"""
Network Vector - Advanced Network Topology Scanner
Performs comprehensive TCP port scanning and network discovery without using nmap or masscan.
Creates interactive D3.js visualizations to map network topology and security posture.
Includes SMB share enumeration and professional network visualization.
"""

import socket
import threading
import ipaddress
import time
import json
import argparse
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Import our custom D3 graph generator
from custom_d3_graph import CustomD3ForceGraph, create_custom_graph_from_scan

# Top 750 most commonly used TCP ports
TOP_750_PORTS = [
    # Core services (1-100)
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631,
    
    # Extended common services (636-1000)
    636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995,
    
    # System and database ports (1000-2000)
    1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999,
    
    # Application and web services (2000-3000)
    2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998,
    
    # Development and remote access (3000-4000)
    3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998,
    
    # High-numbered services (4000-5000)
    4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998,
    
    # System and specialized services (5000-6000)
    5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999,
    
    # Extended application ports (6000-8000)
    6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999,
    
    # Web and proxy services (8000-9000)
    8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899, 8994,
    
    # High-numbered and specialized (9000+)
    9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389
]

class SMBShareEnumerator:
    def __init__(self):
        self.is_windows = platform.system().lower() == 'windows'
    
    def enumerate_shares(self, target_ip):
        """Enumerate SMB shares on a target"""
        try:
            if self.is_windows:
                # Use Windows built-in 'net view' command
                cmd = ['net', 'view', f'\\\\{target_ip}', '/all']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    shares = []
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.strip() and not line.startswith('The command completed') and not line.startswith('Share name'):
                            if '\\\\' not in line and line.strip() != '':
                                parts = line.split()
                                if parts and not parts[0].startswith('-') and parts[0] not in ['The', 'Share']:
                                    share_name = parts[0]
                                    if share_name and share_name not in ['IPC$', 'ADMIN$'] and not share_name.endswith('$'):
                                        shares.append(share_name)
                    return shares
            else:
                # Use smbclient on Linux/Mac
                cmd = ['smbclient', '-L', target_ip, '-N']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    shares = []
                    lines = result.stdout.split('\n')
                    in_sharelist = False
                    for line in lines:
                        if 'Sharename' in line:
                            in_sharelist = True
                            continue
                        if in_sharelist and line.strip():
                            if line.startswith('\t'):
                                share_name = line.strip().split()[0]
                                if share_name and not share_name.endswith('$'):
                                    shares.append(share_name)
                            elif not line.startswith('\t') and line.strip():
                                break
                    return shares
                    
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass
        except Exception as e:
            print(f"  Error enumerating shares: {e}")
        
        return []

class RawPortScanner:
    def __init__(self, timeout=1.0, max_threads=100, resolve_hostnames=False, enumerate_shares=False):
        self.timeout = timeout
        self.max_threads = max_threads
        self.resolve_hostnames = resolve_hostnames
        self.enumerate_shares = enumerate_shares
        self.scan_results = defaultdict(list)
        self.share_results = defaultdict(list) if enumerate_shares else None
        self.smb_enumerator = SMBShareEnumerator() if enumerate_shares else None
        self.hostname_cache = {}
        
    def resolve_hostname(self, ip):
        """Resolve hostname for an IP address with caching and timeout"""
        if ip in self.hostname_cache:
            return self.hostname_cache[ip]
        
        try:
            # Set a shorter timeout for hostname resolution
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(2.0)  # 2 second timeout for DNS
            hostname = socket.gethostbyaddr(ip)[0]
            display_name = f"{ip}-{hostname}"
            self.hostname_cache[ip] = display_name
            socket.setdefaulttimeout(old_timeout)
            return display_name
        except (socket.herror, socket.gaierror, socket.timeout):
            socket.setdefaulttimeout(old_timeout) if 'old_timeout' in locals() else None
            self.hostname_cache[ip] = ip
            return ip
    
    def scan_port(self, host, port):
        """Scan a single port on a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except socket.error:
            return False
    
    def scan_host(self, host_ip, ports):
        """Scan all ports on a single host"""
        # Get display name (with hostname if resolution is enabled)
        if self.resolve_hostnames:
            host_display = self.resolve_hostname(host_ip)
        else:
            host_display = host_ip
        
        #print(f"Scanning {host_display}... ({len(ports)} ports)")
        
        open_ports = []
        file_service_ports = []
        
        # Scan all ports with optimized threading
        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(ports))) as executor:
            future_to_port = {executor.submit(self.scan_port, host_ip, port): port for port in ports}
            
            completed = 0
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1
                try:
                    if future.result():
                        open_ports.append(port)
                        print(f"  {host_display}:{port} - OPEN")
                        
                        # Check if this is a file service port
                        if port in [445, 139, 2049]:  # SMB and NFS ports
                            file_service_ports.append(port)
                            
                except Exception as exc:
                    pass  # Silently ignore port scan errors for speed
                
                # Show progress every 25 ports
                #if completed % 25 == 0:
                    #print(f"  Progress: {completed}/{len(ports)} ports scanned...")
        
        if open_ports:
            self.scan_results[host_display] = sorted(open_ports)
            
            # Enumerate SMB shares if file services detected
            if self.enumerate_shares and file_service_ports and self.smb_enumerator:
                print(f"  File services detected on {host_display} (ports: {file_service_ports})")
                print(f"  Enumerating shares...")
                shares = self.smb_enumerator.enumerate_shares(host_ip)
                if shares:
                    print(f"    Found {len(shares)} shares: {shares}")
                    self.share_results[host_display] = shares
                    print(f"  Found shares: {shares}")
   
    
    def scan_network(self, target, ports=None):
        """Scan a network or single host"""
        if ports is None:
            ports = TOP_750_PORTS
        
        start_time = time.time()
        
        # Parse target
        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
            
            # Limit scan to avoid overwhelming
            if len(hosts) > 255:
                print(f"Warning: Network too large ({len(hosts)} hosts). Limiting to first 255 hosts.")
                hosts = hosts[:255]
                
        except ipaddress.AddressValueError:
            # Single IP address
            hosts = [target]
        
        print(f"Starting scan of {len(hosts)} hosts with {len(ports)} ports each...")
        
        # Scan hosts in parallel - increased parallelism for faster scanning
        max_host_workers = min(50, len(hosts)) if len(hosts) > 10 else len(hosts)
        with ThreadPoolExecutor(max_workers=max_host_workers) as executor:
            futures = [executor.submit(self.scan_host, host, ports) for host in hosts]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    print(f"Host generated an exception: {exc}")
        
        end_time = time.time()
        print(f"\nScan completed in {end_time - start_time:.2f} seconds")
        return self.scan_results

def main():
    parser = argparse.ArgumentParser(description='Network Vector - Advanced Network Topology Scanner')
    parser.add_argument('target', help='Target IP address or network (e.g., 192.168.1.1 or 192.168.1.0/24)')
    parser.add_argument('--timeout', type=float, default=0.5, help='Connection timeout in seconds (default: 0.5)')
    parser.add_argument('--threads', type=int, default=200, help='Maximum number of threads (default: 200)')
    parser.add_argument('--ports', nargs='+', type=int, help='Custom ports to scan (default: top 100)')
    parser.add_argument('--output', default='scan_results.json', help='Output JSON file (default: scan_results.json)')
    parser.add_argument('--no-graph', action='store_true', help='Skip graph visualization')
    parser.add_argument('--no-resolve-hostnames', action='store_true', help='Disable hostname resolution (enabled by default)')
    parser.add_argument('--no-enumerate-shares', action='store_true', help='Disable SMB share enumeration (enabled by default)')
    
    args = parser.parse_args()
    
    # Use custom ports if provided, otherwise use top 750
    ports_to_scan = args.ports if args.ports else TOP_750_PORTS
    
    print("=" * 50)
    print("🌐 Network Vector - Advanced Network Scanner")
    print(f"Target: {args.target}")
    print(f"Ports: {len(ports_to_scan)} ports")
    print(f"Timeout: {args.timeout}s")
    print(f"Max Threads: {args.threads}")
    print(f"Hostname Resolution: {'Enabled' if not args.no_resolve_hostnames else 'Disabled'}")
    print(f"Share Enumeration: {'Enabled' if not args.no_enumerate_shares else 'Disabled'}")
    print("=" * 50)
    
    try:
        # Create and run scanner
        scanner = RawPortScanner(
            timeout=args.timeout,
            max_threads=args.threads,
            resolve_hostnames=not args.no_resolve_hostnames,
            enumerate_shares=not args.no_enumerate_shares
        )
        
        results = scanner.scan_network(args.target, ports_to_scan)
        
        # Display results
        if results:
            print(f"\nScan Results:")
            print(f"Found {len(results)} hosts with open ports:")
            for host, ports in results.items():
                print(f"  {host}: {len(ports)} open ports - {ports}")
            
            if scanner.share_results:
                print(f"\nShare Enumeration Results:")
                for host, shares in scanner.share_results.items():
                    if shares:
                        print(f"  {host}: {len(shares)} shares - {shares}")
            
            # Generate custom D3 graph
            if not args.no_graph:
                print("\nGenerating custom D3.js visualization...")
                if not args.no_resolve_hostnames:
                    print("Note: Hostnames will be shown in the graph as 'IP-hostname' format")
                if not args.no_enumerate_shares and scanner.share_results:
                    print("Note: Discovered shares will be connected to dedicated 'Shares' nodes for each host")
                
                # Use custom D3.js graph (now the only option)
                custom_graph = create_custom_graph_from_scan(results, scanner.share_results)
                output_file = custom_graph.save_and_show("network_scan.html")
                print(f"Custom D3 graph saved to: {output_file}")
                print("Interactive graph opened in browser!")
                
                # Save results to JSON
                with open(args.output, 'w') as f:
                    json.dump({
                        'scan_results': results,
                        'share_results': scanner.share_results if scanner.share_results else {},
                        'timestamp': time.time(),
                        'scan_info': {
                            'target': args.target,
                            'timeout': args.timeout,
                            'threads': args.threads,
                            'resolve_hostnames': not args.no_resolve_hostnames,
                            'enumerate_shares': not args.no_enumerate_shares
                        }
                    }, f, indent=2)
                
                print(f"Results saved to {args.output}")
            
        else:
            print("\nNo open ports found on any hosts.")
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"\nError during scan: {e}")

if __name__ == "__main__":
    main()

