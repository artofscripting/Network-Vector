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
import random
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Import our custom D3 graph generator
from custom_d3_graph import CustomD3ForceGraph, create_custom_graph_from_scan, create_custom_3d_graph_from_scan

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

TOP_UDP_PORTS = [
    # Core infrastructure and discovery
    7, 9, 17, 19, 37, 49, 53, 67, 68, 69, 80, 88, 111, 119, 123,
    135, 137, 138, 139, 161, 162, 177, 389, 427, 443, 445, 500,
    514, 520, 523, 623, 626, 631,

    # RPC, directory, auth, VPN, and routing services
    996, 997, 998, 999, 1022, 1023, 1025, 1026, 1027, 1028, 1029,
    1030, 1031, 1434, 1645, 1646, 1701, 1718, 1719, 1812, 1813,
    1900, 2000, 2048, 2049, 2222, 3283, 3456, 3702, 4444, 4500,
    5000, 5060, 5061, 5351, 5353, 5355, 5632, 5683, 6000, 7000,

    # Common appliance, game, telemetry, and high ephemeral targets
    9200, 10000, 11211, 17185, 20031, 30718, 31337, 32768, 32769,
    32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778,
    32779, 32780, 32815, 33281, 49152, 49153, 49154, 49155, 49156,
]

# Service-specific UDP payloads improve detection accuracy.
# Values can be a single payload or a tuple of payloads. Ports not listed here
# get an empty datagram (sufficient to trigger ICMP unreachable on closed ports).
UDP_PROBES = {
    7: b'NetworkVector\r\n',                                      # Echo
    17: b'\r\n',                                                   # Quote of the day
    19: b'\x00',                                                   # Chargen
    37: b'\x00',                                                   # Time
    53: (                                                          # DNS version.bind + A query
        b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x07version\x04bind\x00\x00\x10\x00\x03',
        b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x07example\x03com\x00\x00\x01\x00\x01',
    ),
    69: b'\x00\x01test\x00octet\x00',                             # TFTP RRQ
    111: (b'\x72\xfe\x1d\x13\x00\x00\x00\x00\x00\x00\x00\x02'      # rpcbind NULL v2
          b'\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x00'
          b'\x00\x00\x00\x00\x00\x00\x00\x00'),
    123: b'\x1b' + b'\x00' * 47,                                  # NTP v3 client request
    137: (b'\x80\xf0\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'      # NetBIOS name status
          b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'),
    161: (b'\x30\x26\x02\x01\x00\x04\x06public'                   # SNMP v1 GetRequest (sysDescr)
          b'\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00'
          b'\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'),
    389: (b'\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00'      # CLDAP RootDSE search
          b'\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00'
          b'\x87\x0bobjectClass\x30\x00'),
    427: (b'\x02\x01\x00\x2a\x00\x00\x00\x00\x00\x00\x65\x6e'      # SLP service request
          b'\x00\x00\x00\x15service:service-agent\x00\x07default\x00\x00'),
    500: (b'\x00' * 8 + b'\x00' * 8 + b'\x01\x10\x02\x00'          # IKEv1 SA probe
          b'\x00\x00\x00\x00\x00\x00\x00\x1c'),
    520: b'\x01\x02\x00\x00\x00\x00\x00\x00',                     # RIP request
    623: b'\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00',     # IPMI/RMCP ping
    1434: b'\x02',                                                # MS SQL Browser enumerate
    1900: (b'M-SEARCH * HTTP/1.1\r\n'                             # SSDP M-SEARCH
           b'HOST: 239.255.255.250:1900\r\n'
           b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'),
    3702: (b'<?xml version="1.0" encoding="UTF-8"?>'              # WS-Discovery probe
           b'<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
           b'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
           b'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
           b'<e:Header><w:MessageID>uuid:00000000-0000-0000-0000-000000000000</w:MessageID>'
           b'<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
           b'<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
           b'</e:Header><e:Body><d:Probe /></e:Body></e:Envelope>'),
    4500: b'\xff',                                                # IPsec NAT-T keepalive
    5060: (b'OPTIONS sip:localhost SIP/2.0\r\n'                   # SIP OPTIONS
           b'Via: SIP/2.0/UDP localhost;branch=z9hG4bKnv\r\n'
           b'From: <sip:nvector@localhost>;tag=nv\r\n'
           b'To: <sip:localhost>\r\nCall-ID: nvector\r\n'
           b'CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n'),
    5061: (b'OPTIONS sip:localhost SIP/2.0\r\n'                   # SIP/TLS over UDP or SIP alt
           b'Via: SIP/2.0/UDP localhost;branch=z9hG4bKnv\r\n'
           b'From: <sip:nvector@localhost>;tag=nv\r\n'
           b'To: <sip:localhost>\r\nCall-ID: nvector\r\n'
           b'CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n'),
    5351: b'\x00\x00',                                            # NAT-PMP external address request
    5353: (b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'    # mDNS service enum
           b'\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01'),
    5355: (b'\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'    # LLMNR name query
           b'\x09localhost\x00\x00\x01\x00\x01'),
    5683: b'\x40\x01\x00\x01\xbb.well-known\x04core',             # CoAP GET /.well-known/core
    11211: b'stats\r\n',                                          # Memcached stats
}

def iter_udp_probes(port):
    probes = UDP_PROBES.get(port, b'\x00')
    if isinstance(probes, tuple):
        return probes
    return (probes,)

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
    def __init__(self, timeout=1.0, max_threads=1000, resolve_hostnames=False, enumerate_shares=False, randomize_scan=True, scan_delay=0.0, exempt_list=None, livelog=False, no_ping_sweep=False):
        self.timeout = timeout
        self.max_threads = max_threads
        self.resolve_hostnames = resolve_hostnames
        self.enumerate_shares = enumerate_shares
        self.randomize_scan = randomize_scan
        self.scan_delay = scan_delay
        self.exempt_list = exempt_list or []
        self.exempt_networks = self._parse_exemptions()
        self.scan_results = defaultdict(list)
        self.host_details = {}  # Store detailed host information
        self.share_results = defaultdict(list) if enumerate_shares else None
        self.smb_enumerator = SMBShareEnumerator() if enumerate_shares else None
        self.hostname_cache = {}
        self.livelog = livelog
        self.no_ping_sweep = no_ping_sweep
        self.udp_results = {}  # {host_display: {'open': [...], 'open|filtered': [...]}}
        # Cap concurrent open sockets globally to avoid exhausting file descriptors.
        # 50 host workers × 750 port threads would otherwise attempt ~37,500 simultaneous
        # sockets; the OS default fd limit (~1024) silently kills most of them.
        self._conn_semaphore = threading.Semaphore(500)

    def _parse_exemptions(self):
        """Parse exemption list into IP networks for efficient checking"""
        networks = []
        for item in self.exempt_list:
            item = item.strip()
            if not item:
                continue
            try:
                # Try parsing as network (handles both single IPs and CIDRs)
                if '/' not in item:
                    item = f"{item}/32"  # Convert single IP to /32 network
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError as e:
                print(f"Warning: Invalid exemption '{item}': {e}")
        return networks

    def is_exempt(self, ip):
        """Check if an IP address is in the exemption list"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.exempt_networks:
                if ip_obj in network:
                    return True
            return False
        except ValueError:
            return False

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
        """Scan a single port on a host and return (is_open, response_time)"""
        try:
            with self._conn_semaphore:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                result = sock.connect_ex((host, port))
                response_time = time.time() - start_time
                sock.close()

            if result == 0:
                return True, response_time
            else:
                return False, None
        except socket.error:
            return False, None

    def scan_udp_port(self, host, port):
        """Send a UDP probe to a single port and return (status, response_time).

        status values:
          'open'         — service sent a response datagram
          'closed'       — host sent ICMP port-unreachable (ConnectionRefusedError on connected UDP)
          'open|filtered'— no reply within timeout (port may be open or silently dropped)
        """
        try:
            with self._conn_semaphore:
                start_time = time.time()
                for probe in iter_udp_probes(port):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.timeout)
                    try:
                        sock.connect((host, port))
                        sock.send(probe)
                        try:
                            sock.recv(4096)
                            response_time = time.time() - start_time
                            return 'open', response_time
                        except ConnectionRefusedError:
                            return 'closed', None
                        except socket.timeout:
                            continue
                    finally:
                        sock.close()
                return 'open|filtered', None
        except socket.error:
            return 'closed', None

    def scan_host(self, host_ip, ports):
        """Scan all ports on a single host"""
        # Get display name (with hostname if resolution is enabled)
        if self.resolve_hostnames:
            host_display = self.resolve_hostname(host_ip)
        else:
            host_display = host_ip

        # Randomize port order for stealth scanning (if enabled)
        if self.randomize_scan:
            randomized_ports = ports.copy()
            random.shuffle(randomized_ports)
            # Add small random delay between hosts for stealth
            if self.scan_delay > 0:
                delay = random.uniform(0, self.scan_delay)
                time.sleep(delay)
        else:
            randomized_ports = ports

        #print(f"Scanning {host_display}... ({len(randomized_ports)} ports)")

        open_ports = []
        file_service_ports = []
        response_times = []
        port_info = {}  # Store detailed port information

        # Scan all ports with optimized threading
        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(randomized_ports))) as executor:
            future_to_port = {executor.submit(self.scan_port, host_ip, port): port for port in randomized_ports}

            completed = 0
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1
                try:
                    is_open, response_time = future.result()
                    if is_open:
                        open_ports.append(port)
                        port_info[port] = {
                            'state': 'open',
                            'response_time': response_time
                        }
                        response_times.append(response_time)
                        if self.livelog:
                            print(f"[LIVELOG] PORT OPEN  {host_display}:{port}  ({response_time*1000:.0f}ms)")

                        # Check if this is a file service port
                        if port in [445, 139, 2049]:  # SMB and NFS ports
                            file_service_ports.append(port)

                except Exception as exc:
                    pass  # Silently ignore port scan errors for speed

                # Show progress every 25 ports
                #if completed % 25 == 0:
                    #print(f"  Progress: {completed}/{len(randomized_ports)} ports scanned...")

        if open_ports:
            self.scan_results[host_display] = sorted(open_ports)
            if self.livelog:
                print(f"[LIVELOG] HOST FOUND {host_display}  {len(open_ports)} open port(s): {sorted(open_ports)}")

            # Calculate average response time for the host
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0

            # Store detailed host information
            self.host_details[host_display] = {
                'ip': host_ip,
                'hostname': host_display.split('-', 1)[1] if '-' in host_display else None,
                'open_ports': [{'port': port, 'response_time': port_info[port]['response_time']} for port in open_ports],
                'avg_response_time': avg_response_time,
                'os_detection': self.detect_os(open_ports),
                'port_count': len(open_ports)
            }

            # Enumerate SMB shares if file services detected
            if self.enumerate_shares and file_service_ports and self.smb_enumerator:
                shares = self.smb_enumerator.enumerate_shares(host_ip)
                if shares:
                    self.share_results[host_display] = shares

    def detect_os(self, open_ports):
        """Enhanced OS detection based on comprehensive port patterns and signatures"""
        if not open_ports:
            return {'os': 'Unknown', 'confidence': 'Low', 'details': 'No open ports detected'}

        # Initialize scoring systems
        windows_score = 0
        linux_score = 0
        macos_score = 0
        embedded_score = 0

        detected_services = []

        # Windows-specific port signatures (high confidence indicators)
        windows_signatures = {
            135: {'score': 4, 'service': 'RPC Endpoint Mapper'},
            139: {'score': 3, 'service': 'NetBIOS Session Service'},
            445: {'score': 3, 'service': 'Microsoft-DS (SMB)'},
            3389: {'score': 5, 'service': 'Remote Desktop Protocol'},
            1433: {'score': 3, 'service': 'MS SQL Server'},
            1434: {'score': 3, 'service': 'MS SQL Monitor'},
            5357: {'score': 4, 'service': 'Windows Service Discovery'},
            5985: {'score': 4, 'service': 'WinRM HTTP'},
            5986: {'score': 4, 'service': 'WinRM HTTPS'},
            593: {'score': 3, 'service': 'HTTP RPC Ep Map'},
            49152: {'score': 2, 'service': 'Windows Dynamic RPC'},
            49153: {'score': 2, 'service': 'Windows Dynamic RPC'},
            49154: {'score': 2, 'service': 'Windows Dynamic RPC'},
            49155: {'score': 2, 'service': 'Windows Dynamic RPC'},
            1024: {'score': 2, 'service': 'Windows Reserved'},
            1025: {'score': 2, 'service': 'Windows NFS or IIS'},
            1026: {'score': 2, 'service': 'Windows Calendar'},
            1027: {'score': 2, 'service': 'Windows ICQ'},
            8080: {'score': 1, 'service': 'Windows IIS Alt HTTP'},
        }

        # Linux/Unix-specific port signatures
        linux_signatures = {
            22: {'score': 3, 'service': 'SSH (OpenSSH)'},
            111: {'score': 3, 'service': 'RPC Portmapper'},
            2049: {'score': 4, 'service': 'Network File System'},
            514: {'score': 3, 'service': 'Remote Shell (rsh)'},
            515: {'score': 3, 'service': 'Line Printer Daemon'},
            993: {'score': 2, 'service': 'IMAPS (Linux bias)'},
            995: {'score': 2, 'service': 'POP3S (Linux bias)'},
            6000: {'score': 3, 'service': 'X11 Display'},
            6001: {'score': 3, 'service': 'X11 Display'},
            6002: {'score': 3, 'service': 'X11 Display'},
            7000: {'score': 2, 'service': 'X11 Font Server'},
            10000: {'score': 3, 'service': 'Webmin (Linux admin)'},
            20000: {'score': 2, 'service': 'DNP (Linux)'},
        }

        # macOS-specific signatures
        macos_signatures = {
            548: {'score': 4, 'service': 'AFP (Apple Filing Protocol)'},
            631: {'score': 3, 'service': 'CUPS (macOS printing)'},
            5009: {'score': 4, 'service': 'AirPort Admin Utility'},
            5353: {'score': 2, 'service': 'Bonjour/mDNS'},
            62078: {'score': 4, 'service': 'Apple iPhoto sharing'},
            3283: {'score': 3, 'service': 'Apple NetAssistant'},
            5222: {'score': 2, 'service': 'Apple iChat'},
        }

        # Embedded/IoT device signatures
        embedded_signatures = {
            81: {'score': 3, 'service': 'Embedded Web Interface'},
            82: {'score': 3, 'service': 'Embedded Web Interface'},
            8008: {'score': 3, 'service': 'Embedded HTTP Alt'},
            9999: {'score': 3, 'service': 'Embedded Telnet'},
            4444: {'score': 3, 'service': 'Embedded Admin'},
            8888: {'score': 3, 'service': 'Embedded Web Admin'},
            9000: {'score': 2, 'service': 'Embedded Management'},
            10001: {'score': 3, 'service': 'Embedded Control'},
        }

        # Platform-neutral but commonly found services with OS bias
        database_services = {
            3306: {'windows': 1, 'linux': 2, 'service': 'MySQL'},
            5432: {'windows': 1, 'linux': 3, 'service': 'PostgreSQL'},
            1521: {'windows': 2, 'linux': 2, 'service': 'Oracle DB'},
            27017: {'windows': 1, 'linux': 2, 'service': 'MongoDB'},
            6379: {'windows': 1, 'linux': 2, 'service': 'Redis'},
        }

        web_services = {
            80: {'windows': 1, 'linux': 2, 'service': 'HTTP'},
            443: {'windows': 1, 'linux': 2, 'service': 'HTTPS'},
            8080: {'windows': 2, 'linux': 1, 'service': 'HTTP Alt'},
            8443: {'windows': 1, 'linux': 2, 'service': 'HTTPS Alt'},
            9080: {'windows': 1, 'linux': 2, 'service': 'HTTP Management'},
            9443: {'windows': 1, 'linux': 2, 'service': 'HTTPS Management'},
        }

        # Score based on specific OS signatures
        for port in open_ports:
            if port in windows_signatures:
                score = windows_signatures[port]['score']
                windows_score += score
                detected_services.append(f"Windows: {windows_signatures[port]['service']}")

            if port in linux_signatures:
                score = linux_signatures[port]['score']
                linux_score += score
                detected_services.append(f"Linux: {linux_signatures[port]['service']}")

            if port in macos_signatures:
                score = macos_signatures[port]['score']
                macos_score += score
                detected_services.append(f"macOS: {macos_signatures[port]['service']}")

            if port in embedded_signatures:
                score = embedded_signatures[port]['score']
                embedded_score += score
                detected_services.append(f"Embedded: {embedded_signatures[port]['service']}")

            # Add database service bias
            if port in database_services:
                windows_score += database_services[port].get('windows', 0)
                linux_score += database_services[port].get('linux', 0)
                detected_services.append(f"Database: {database_services[port]['service']}")

            # Add web service bias
            if port in web_services:
                windows_score += web_services[port].get('windows', 0)
                linux_score += web_services[port].get('linux', 0)
                detected_services.append(f"Web: {web_services[port]['service']}")

        # Advanced pattern analysis
        port_combinations = {
            # Windows combinations
            (135, 139, 445): {'os': 'Windows', 'bonus': 5, 'desc': 'Classic Windows file sharing stack'},
            (135, 445, 3389): {'os': 'Windows', 'bonus': 6, 'desc': 'Windows with Remote Desktop'},
            (139, 445): {'os': 'Windows', 'bonus': 3, 'desc': 'SMB file sharing'},
            (1433, 1434): {'os': 'Windows', 'bonus': 4, 'desc': 'MS SQL Server setup'},

            # Linux combinations
            (22, 111, 2049): {'os': 'Linux', 'bonus': 5, 'desc': 'Linux NFS server'},
            (22, 80, 443): {'os': 'Linux', 'bonus': 3, 'desc': 'Linux web server'},
            (22, 3306): {'os': 'Linux', 'bonus': 3, 'desc': 'Linux MySQL server'},
            (22, 5432): {'os': 'Linux', 'bonus': 3, 'desc': 'Linux PostgreSQL server'},

            # macOS combinations
            (548, 631): {'os': 'macOS', 'bonus': 4, 'desc': 'macOS file and print sharing'},
            (22, 548): {'os': 'macOS', 'bonus': 3, 'desc': 'macOS with SSH and AFP'},
        }

        # Check for port combinations
        combination_bonuses = []
        for combo, info in port_combinations.items():
            if all(port in open_ports for port in combo):
                if info['os'] == 'Windows':
                    windows_score += info['bonus']
                elif info['os'] == 'Linux':
                    linux_score += info['bonus']
                elif info['os'] == 'macOS':
                    macos_score += info['bonus']
                combination_bonuses.append(info['desc'])

        # Determine final OS with enhanced logic
        max_score = max(windows_score, linux_score, macos_score, embedded_score)

        if max_score == 0:
            return {
                'os': 'Unknown',
                'confidence': 'Low',
                'details': f'No distinctive OS patterns found. Ports: {sorted(open_ports)}'
            }

        # Determine OS and confidence
        if windows_score == max_score and windows_score > 0:
            confidence = 'High' if windows_score >= 6 else 'Medium' if windows_score >= 3 else 'Low'
            os_name = 'Windows Server' if any(p in [1433, 1434, 5985, 5986] for p in open_ports) else 'Windows'
            details = f'Score: {windows_score}, Services: {len([s for s in detected_services if "Windows" in s])}'
        elif linux_score == max_score and linux_score > 0:
            confidence = 'High' if linux_score >= 5 else 'Medium' if linux_score >= 3 else 'Low'
            os_name = 'Linux/Unix'
            details = f'Score: {linux_score}, Services: {len([s for s in detected_services if "Linux" in s])}'
        elif macos_score == max_score and macos_score > 0:
            confidence = 'High' if macos_score >= 4 else 'Medium' if macos_score >= 2 else 'Low'
            os_name = 'macOS'
            details = f'Score: {macos_score}, Services: {len([s for s in detected_services if "macOS" in s])}'
        elif embedded_score == max_score and embedded_score > 0:
            confidence = 'Medium' if embedded_score >= 3 else 'Low'
            os_name = 'Embedded/IoT'
            details = f'Score: {embedded_score}, Embedded services detected'
        else:
            return {
                'os': 'Unknown',
                'confidence': 'Low',
                'details': f'Conflicting indicators. W:{windows_score} L:{linux_score} M:{macos_score} E:{embedded_score}'
            }

        # Add combination bonus details
        if combination_bonuses:
            details += f', Patterns: {", ".join(combination_bonuses[:2])}'

        return {
            'os': os_name,
            'confidence': confidence,
            'details': details,
            'detected_services': detected_services[:5],  # Top 5 services
            'port_analysis': {
                'windows_score': windows_score,
                'linux_score': linux_score,
                'macos_score': macos_score,
                'embedded_score': embedded_score
            }
        }

    def scan_udp_host(self, host_ip, udp_ports):
        """Scan UDP ports on a single host and store results in self.udp_results."""
        if self.resolve_hostnames:
            host_display = self.resolve_hostname(host_ip)
        else:
            host_display = host_ip

        open_ports = []
        filtered_ports = []

        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(udp_ports))) as executor:
            future_to_port = {executor.submit(self.scan_udp_port, host_ip, port): port for port in udp_ports}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    status, response_time = future.result()
                    if status == 'open':
                        open_ports.append(port)
                        if self.livelog:
                            rt = f"{response_time*1000:.0f}ms" if response_time else "?"
                            print(f"[LIVELOG] UDP OPEN       {host_display}:{port}  ({rt})")
                    elif status == 'open|filtered':
                        filtered_ports.append(port)
                        if self.livelog:
                            print(f"[LIVELOG] UDP FILTERED   {host_display}:{port}")
                except Exception:
                    pass

        if open_ports or filtered_ports:
            self.udp_results[host_display] = {
                'open': sorted(open_ports),
                'open|filtered': sorted(filtered_ports),
            }
            if self.livelog:
                print(f"[LIVELOG] UDP HOST DONE  {host_display}: "
                      f"{len(open_ports)} open, {len(filtered_ports)} open|filtered")

    def discover_live_hosts(self, hosts):
        """Ping sweep to find which IPs are alive before port scanning.

        Uses the system ping binary (works without root). Falls back to scanning
        all addresses if ping finds nothing (ICMP may be firewalled).
        """
        live = []
        lock = threading.Lock()

        def ping(ip):
            try:
                if platform.system().lower() == 'windows':
                    cmd = ['ping', '-n', '1', '-w', '500', ip]
                else:
                    cmd = ['ping', '-c', '1', '-W', '1', ip]
                r = subprocess.run(cmd, capture_output=True, timeout=3)
                if r.returncode == 0:
                    with lock:
                        live.append(ip)
            except Exception:
                pass

        print(f"  Ping sweep: probing {len(hosts)} addresses...", flush=True)
        with ThreadPoolExecutor(max_workers=min(200, len(hosts))) as executor:
            list(executor.map(ping, hosts))

        return live

    def scan_network(self, target, ports=None, on_host_complete=None, udp_ports=None):
        """Scan a network or single host

        Args:
            target: IP address or CIDR network to scan
            ports: List of ports to scan
            on_host_complete: Optional callback function called after each host with open ports is found.
                              Receives (scan_results, share_results, host_details) as arguments.
        """
        if ports is None:
            ports = TOP_750_PORTS

        start_time = time.time()
        self.host_details.clear()  # Clear previous scan data
        self.on_host_complete = on_host_complete

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

        # Filter out exempt hosts
        if self.exempt_networks:
            original_count = len(hosts)
            hosts = [h for h in hosts if not self.is_exempt(h)]
            exempt_count = original_count - len(hosts)
            if exempt_count > 0:
                print(f"Exempted {exempt_count} host(s) from scan based on exclusion rules")

        # Ping sweep: only port-scan addresses that respond, so we don't burn the
        # connection semaphore on the hundreds of dead IPs in a typical /24.
        # Skipped when -Pn is set (treat all hosts as live).
        if len(hosts) > 1 and not self.no_ping_sweep:
            live_hosts = self.discover_live_hosts(hosts)
            if live_hosts:
                print(f"  {len(live_hosts)}/{len(hosts)} host(s) responded to ping — port scanning live hosts only.")
                hosts = live_hosts
            else:
                print(f"  Ping sweep got no replies (ICMP may be filtered) — port scanning all {len(hosts)} addresses.")

        # Randomize host order for stealth scanning (if enabled)
        if self.randomize_scan:
            random.shuffle(hosts)
            print(f"Starting port scan: {len(hosts)} host(s), {len(ports)} ports each...")
            if self.scan_delay > 0:
                print(f"Note: Using delays up to {self.scan_delay}s between hosts")
        else:
            print(f"Starting port scan: {len(hosts)} host(s), {len(ports)} ports each...")

        # Scan hosts in parallel - increased parallelism for faster scanning
        max_host_workers = min(50, len(hosts)) if len(hosts) > 10 else len(hosts)
        total_hosts = len(hosts)
        completed_hosts = 0

        with ThreadPoolExecutor(max_workers=max_host_workers) as executor:
            futures = [executor.submit(self.scan_host, host, ports) for host in hosts]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    print(f"Host generated an exception: {exc}")

                completed_hosts += 1
                percent = (completed_hosts / total_hosts) * 100
                print(f"\rProgress: {completed_hosts}/{total_hosts} hosts ({percent:.1f}%)", end="", flush=True)

                # Call live callback if new hosts with open ports were found
                if self.on_host_complete and len(self.host_details) > 0:
                    try:
                        self.on_host_complete(
                            dict(self.scan_results),
                            dict(self.share_results) if self.share_results else {},
                            dict(self.host_details)
                        )
                    except Exception as e:
                        pass  # Silently ignore callback errors to not interrupt scan

        end_time = time.time()
        print(f"\nScan completed in {end_time - start_time:.2f} seconds")
        print(f"Found {len(self.scan_results)} open TCP ports across {len(self.host_details)} hosts.")

        # Print OS detection results
        for host_ip, host_info in self.host_details.items():
            if host_info['open_ports']:
                os_info = host_info.get('os_detection', {'os': 'Unknown', 'confidence': 'Low'})
                print(f"Host {host_ip}: OS Detection - {os_info['os']} ({os_info['confidence']} confidence)")

        # UDP scan phase (runs on the same live-host list used for TCP)
        if udp_ports:
            print(f"\nStarting UDP scan: {len(hosts)} host(s), {len(udp_ports)} UDP port(s) each...")
            udp_workers = min(max_host_workers, len(hosts))
            completed_udp = 0
            with ThreadPoolExecutor(max_workers=udp_workers) as executor:
                udp_futures = [executor.submit(self.scan_udp_host, host, udp_ports) for host in hosts]
                for future in as_completed(udp_futures):
                    try:
                        future.result()
                    except Exception:
                        pass
                    completed_udp += 1
                    pct = (completed_udp / len(hosts)) * 100
                    print(f"\rUDP Progress: {completed_udp}/{len(hosts)} hosts ({pct:.1f}%)", end="", flush=True)
            print()
            udp_open_total = sum(len(v['open']) for v in self.udp_results.values())
            print(f"UDP scan complete. Found {udp_open_total} confirmed open UDP port(s) "
                  f"across {len(self.udp_results)} host(s).")

        return {
            'scan_results': self.scan_results,
            'share_results': self.share_results,
            'host_details': self.host_details,
            'udp_results': dict(self.udp_results),
        }

SERVICE_CATEGORIES = {
    'Remote access': {22, 23, 3389, 5900, 5901, 5902, 5985, 5986, 6000},
    'File sharing': {20, 21, 69, 111, 135, 137, 138, 139, 445, 548, 873, 2049},
    'Web/admin': {80, 443, 631, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 10000},
    'Databases': {1433, 1434, 1521, 3306, 5432, 6379, 9200, 11211, 27017},
    'Discovery/broadcast': {7, 9, 17, 19, 37, 53, 67, 68, 123, 137, 138, 161, 162, 1900, 3702, 5353, 5355},
    'VPN/auth': {49, 88, 389, 500, 1701, 1812, 1813, 4500, 5060, 5061},
    'Printers/IoT': {515, 631, 623, 9100, 47808, 5683},
}

RISK_ORDER = {
    'HIGH RISK': 4,
    'MEDIUM RISK': 3,
    'UNKNOWN RISK': 2,
    'LOW RISK': 1,
    'SECURE': 0,
}

def split_host_key(host_key):
    parts = host_key.split('-', 1)
    return {
        'ip': parts[0],
        'hostname': parts[1] if len(parts) > 1 else None,
    }

def get_service_category(port, protocol='tcp'):
    for category, ports in SERVICE_CATEGORIES.items():
        if port in ports:
            return category
    if protocol == 'udp':
        return 'Discovery/broadcast'
    return 'Other'

def get_risk_level(port):
    from port_descriptions import get_port_security_level
    return get_port_security_level(port)

def get_port_service(port):
    from port_descriptions import get_port_description
    info = get_port_description(port)
    return info.get('description', f'Port {port}')

def build_service_row(host_key, port, protocol, status, host_details):
    host_parts = split_host_key(host_key)
    host_detail = host_details.get(host_key, {})
    response_time = ''
    confidence = 'confirmed' if status == 'open' else status

    if protocol == 'tcp':
        for port_data in host_detail.get('open_ports', []):
            if port_data.get('port') == port and port_data.get('response_time') is not None:
                response_time = f"{port_data['response_time'] * 1000:.3f}ms"
                break
    elif status == 'open':
        response_time = 'response received'

    risk_level = get_risk_level(port)
    return {
        'type': 'port',
        'host': host_key,
        'ip': host_parts['ip'],
        'hostname': host_parts['hostname'] or 'Unknown',
        'protocol': protocol,
        'port': port,
        'service': get_port_service(port),
        'category': get_service_category(port, protocol),
        'risk_level': risk_level,
        'risk_score': RISK_ORDER.get(risk_level, 2),
        'status': status,
        'confidence': confidence,
        'response_time': response_time,
    }

def build_host_profiles(scan_results, share_results, host_details, udp_results):
    hosts = sorted(set(host_details) | set(scan_results) | set(share_results) | set(udp_results))
    profiles = []
    service_rows = []

    for host_key in hosts:
        host_parts = split_host_key(host_key)
        os_detection = host_details.get(host_key, {}).get('os_detection', {})
        tcp_ports = sorted(scan_results.get(host_key, []))
        udp_open = sorted(udp_results.get(host_key, {}).get('open', []))
        udp_filtered = sorted(udp_results.get(host_key, {}).get('open|filtered', []))
        shares = sorted(share_results.get(host_key, []))

        host_rows = []
        for port in tcp_ports:
            row = build_service_row(host_key, port, 'tcp', 'open', host_details)
            service_rows.append(row)
            host_rows.append(row)
        for port in udp_open:
            row = build_service_row(host_key, port, 'udp', 'open', host_details)
            service_rows.append(row)
            host_rows.append(row)
        for port in udp_filtered:
            row = build_service_row(host_key, port, 'udp', 'open|filtered', host_details)
            service_rows.append(row)
            host_rows.append(row)

        highest_risk = max((row['risk_score'] for row in host_rows), default=0)
        risk_level = next((name for name, score in RISK_ORDER.items() if score == highest_risk), 'SECURE')
        notes = []
        if udp_filtered:
            notes.append(f"{len(udp_filtered)} UDP port(s) are open|filtered")
        if shares:
            notes.append(f"{len(shares)} SMB/NFS share(s) discovered")

        profiles.append({
            'host': host_key,
            'ip': host_parts['ip'],
            'hostname': host_parts['hostname'] or 'Unknown',
            'os_guess': os_detection.get('os', 'Unknown'),
            'os_confidence': os_detection.get('confidence', 'Unknown'),
            'tcp_ports': tcp_ports,
            'udp_open_ports': udp_open,
            'udp_open_filtered_ports': udp_filtered,
            'smb_shares': shares,
            'risk_level': risk_level,
            'risk_score': highest_risk,
            'service_count': len(tcp_ports) + len(udp_open) + len(udp_filtered),
            'notes': notes,
        })

    return profiles, service_rows

def build_executive_summary(host_profiles, service_rows):
    high_risk = [row for row in service_rows if row['risk_level'] == 'HIGH RISK']
    top_hosts = sorted(host_profiles, key=lambda h: (h['service_count'], h['risk_score']), reverse=True)[:10]
    return {
        'total_live_hosts': len(host_profiles),
        'total_open_tcp_ports': sum(1 for row in service_rows if row['protocol'] == 'tcp' and row['status'] == 'open'),
        'confirmed_udp_open_ports': sum(1 for row in service_rows if row['protocol'] == 'udp' and row['status'] == 'open'),
        'udp_open_filtered_count': sum(1 for row in service_rows if row['protocol'] == 'udp' and row['status'] == 'open|filtered'),
        'high_risk_services_found': len(high_risk),
        'high_risk_services': high_risk[:25],
        'top_exposed_hosts': top_hosts,
    }

def build_report_data(scan_results, share_results, host_details, udp_results, scan_info):
    host_profiles, service_rows = build_host_profiles(scan_results, share_results, host_details, udp_results)
    return {
        'schema_version': 1,
        'scan_info': scan_info,
        'executive_summary': build_executive_summary(host_profiles, service_rows),
        'host_profiles': host_profiles,
        'service_rows': sorted(service_rows, key=lambda r: (-r['risk_score'], r['host'], r['protocol'], r['port'])),
        'service_categories': sorted(SERVICE_CATEGORIES.keys()) + ['Other'],
        'raw': {
            'scan_results': scan_results,
            'share_results': share_results,
            'host_details': host_details,
            'udp_results': udp_results,
        },
    }

def export_to_csv(report_data, target, args):
    """
    Export scan results to CSV file when --no-graph is used.
    """
    from datetime import datetime

    # Create timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"network_scan_{timestamp}.csv"

    try:
        with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)

            # Write header
            writer.writerow([
                'Type', 'IP Address', 'Hostname', 'Protocol', 'Port', 'Service',
                'Category', 'Risk Level', 'Status', 'Confidence', 'SMB Share',
                'OS Detection', 'Response Time', 'Notes'
            ])

            # Helper function to escape fields
            def clean_field(field):
                if field is None:
                    return ''
                return str(field).replace('\n', ' ').replace('\r', ' ')

            os_by_host = {
                profile['host']: f"{profile['os_guess']} ({profile['os_confidence']} confidence)"
                for profile in report_data.get('host_profiles', [])
            }

            for row in report_data.get('service_rows', []):
                writer.writerow([
                    'Port',
                    clean_field(row['ip']),
                    clean_field(row['hostname']),
                    row['protocol'],
                    row['port'],
                    clean_field(row['service']),
                    clean_field(row['category']),
                    clean_field(row['risk_level']),
                    clean_field(row['status']),
                    clean_field(row['confidence']),
                    '',
                    clean_field(os_by_host.get(row['host'], 'Not Available')),
                    clean_field(row['response_time']),
                    '',
                ])

            for profile in report_data.get('host_profiles', []):
                for share in profile.get('smb_shares', []):
                    writer.writerow([
                        'Share',
                        clean_field(profile['ip']),
                        clean_field(profile['hostname']),
                        '',
                        '',
                        '',
                        'File sharing',
                        clean_field(profile['risk_level']),
                        'open',
                        'enumerated',
                        clean_field(share),
                        clean_field(f"{profile['os_guess']} ({profile['os_confidence']} confidence)"),
                        '',
                        clean_field('; '.join(profile.get('notes', []))),
                    ])

            # Add scan metadata
            writer.writerow([])  # Empty row
            writer.writerow(['# Scan Metadata'])
            writer.writerow([f'# Target: {target}'])
            writer.writerow([f'# Scan Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'])
            writer.writerow([f'# Total Hosts: {report_data["executive_summary"]["total_live_hosts"]}'])
            writer.writerow([f'# TCP Ports Scanned: {report_data["scan_info"].get("ports_scanned", "Unknown")}'])
            writer.writerow([f'# UDP Ports Scanned: {report_data["scan_info"].get("udp_ports_scanned", 0)}'])
            writer.writerow([f'# Hostname Resolution: {"Enabled" if not args.no_resolve_hostnames else "Disabled"}'])
            writer.writerow([f'# Share Enumeration: {"Enabled" if not args.no_enumerate_shares else "Disabled"}'])
            writer.writerow([f'# Randomized Scanning: {"Enabled" if not args.no_randomize else "Disabled"}'])
            writer.writerow([f'# Stealth Mode: {"Enabled" if args.scan_delay > 0 else "Disabled"}'])

        print(f"\n📊 CSV export completed: {csv_filename}")
        print(f"📁 File contains detailed scan results and metadata")
        return csv_filename

    except Exception as e:
        print(f"\n❌ CSV export failed: {e}")
        return None

def export_to_json(report_data, timestamp=None):
    from datetime import datetime

    timestamp = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    json_filename = f"network_scan_{timestamp}.json"
    try:
        with open(json_filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(report_data, jsonfile, indent=2, default=str)
        print(f"\n📄 JSON report completed: {json_filename}")
        return json_filename
    except Exception as e:
        print(f"\n❌ JSON export failed: {e}")
        return None

def load_report_json(path):
    with open(path, 'r', encoding='utf-8') as report_file:
        data = json.load(report_file)
    if 'raw' in data and 'executive_summary' in data:
        return data
    return {
        'schema_version': 0,
        'scan_info': data.get('scan_info', {}),
        'executive_summary': data.get('executive_summary', {}),
        'host_profiles': data.get('host_profiles', []),
        'service_rows': data.get('service_rows', []),
        'raw': {
            'scan_results': data.get('scan_results', {}),
            'share_results': data.get('share_results', {}),
            'host_details': data.get('host_details', {}),
            'udp_results': data.get('udp_results', {}),
        },
    }

def service_identity(row):
    return (row.get('host'), row.get('protocol'), row.get('port'))

def compare_reports(current_report, previous_report):
    current_hosts = {profile['host']: profile for profile in current_report.get('host_profiles', [])}
    previous_hosts = {profile['host']: profile for profile in previous_report.get('host_profiles', [])}
    current_services = {service_identity(row): row for row in current_report.get('service_rows', [])}
    previous_services = {service_identity(row): row for row in previous_report.get('service_rows', [])}

    changed_os = []
    for host in sorted(set(current_hosts) & set(previous_hosts)):
        old_os = previous_hosts[host].get('os_guess', 'Unknown')
        new_os = current_hosts[host].get('os_guess', 'Unknown')
        if old_os != new_os:
            changed_os.append({
                'host': host,
                'previous_os': old_os,
                'current_os': new_os,
            })

    return {
        'previous_scan': previous_report.get('scan_info', {}),
        'current_scan': current_report.get('scan_info', {}),
        'new_hosts': [current_hosts[host] for host in sorted(set(current_hosts) - set(previous_hosts))],
        'missing_hosts': [previous_hosts[host] for host in sorted(set(previous_hosts) - set(current_hosts))],
        'newly_opened_ports': [current_services[key] for key in sorted(set(current_services) - set(previous_services))],
        'closed_ports': [previous_services[key] for key in sorted(set(previous_services) - set(current_services))],
        'changed_os_guesses': changed_os,
    }

def normalize_port_list(ports):
    """Return sorted unique ports after validating the TCP/UDP port range."""
    normalized = sorted(set(ports))
    invalid_ports = [port for port in normalized if port < 1 or port > 65535]
    if invalid_ports:
        raise ValueError(f"Invalid port(s): {invalid_ports}. Ports must be between 1 and 65535.")
    return normalized

def main():
    parser = argparse.ArgumentParser(description='Network Vector - Advanced Network Topology Scanner')
    parser.add_argument('target', help='Target IP address or network(s) - supports comma-separated CIDRs (e.g., 192.168.1.0/24 or 192.168.1.0/24,10.0.0.0/24,172.16.1.0/24)')
    parser.add_argument('--timeout', type=float, default=3.0, help='Connection timeout in seconds (default: 3.0)')
    parser.add_argument('--threads', type=int, default=1000, help='Maximum number of threads (default: 1000)')
    parser.add_argument('--ports', nargs='+', type=int, help='Custom ports to scan (default: top 100)')
    parser.add_argument('--all-ports', action='store_true', help='Scan all 65535 ports (warning: slow)')
    parser.add_argument('--dig', action='store_true', help='Deep scan: scan all 65535 ports on any host found with open ports')
    parser.add_argument('--no-graph', action='store_true', help='Skip graph visualization and export results to CSV')
    parser.add_argument('--no-resolve-hostnames', action='store_true', help='Disable hostname resolution (enabled by default)')
    parser.add_argument('--no-enumerate-shares', action='store_true', help='Disable SMB share enumeration (enabled by default)')
    parser.add_argument('--no-randomize', action='store_true', help='Disable randomized scanning order (randomization enabled by default)')
    parser.add_argument('--scan-delay', type=float, default=0.0, help='Maximum random delay between host scans in seconds (default: 0.0)')
    parser.add_argument('--3d', '--force-3d', dest='force_3d', action='store_true', help='Generate an additional 3D force-directed graph using d3-force-3d')
    parser.add_argument('--live', action='store_true', help='Live mode: regenerate graphs after each host is scanned (requires graphs enabled)')
    parser.add_argument('--exempt', type=str, help='Comma-separated list of IPs or CIDRs to exclude from scanning (e.g., 192.168.1.1,10.0.0.0/24)')
    parser.add_argument('--livelog', action='store_true', help='Print a line to stdout each time a port or host is discovered')
    parser.add_argument('-Pn', dest='no_ping_sweep', action='store_true', help='Skip host discovery ping sweep and treat all addresses as live (like nmap -Pn)')
    parser.add_argument('--udp', action='store_true', help=f'Also scan top {len(TOP_UDP_PORTS)} UDP ports (53, 123, 161, 1900…)')
    parser.add_argument('--all-udp', action='store_true', help='Scan all 65535 UDP ports (warning: very slow and noisy)')
    parser.add_argument('--udp-ports', nargs='+', type=int, metavar='PORT', help='Custom UDP ports to scan (implies --udp)')
    parser.add_argument('--json', dest='json_report', action='store_true', default=True, help='Write JSON report for automation (default: enabled)')
    parser.add_argument('--no-json', dest='json_report', action='store_false', help='Disable JSON report export')
    parser.add_argument('--compare-json', metavar='PATH', help='Compare this scan against a previous Network Vector JSON report')

    args = parser.parse_args()

    # Use custom ports if provided, all ports if requested, otherwise use top 750
    if args.all_ports:
        ports_to_scan = list(range(1, 65536))
    elif args.ports:
        ports_to_scan = args.ports
    else:
        ports_to_scan = TOP_750_PORTS

    # UDP port list (--udp-ports implies --udp; --all-udp implies UDP scanning)
    if args.udp_ports:
        try:
            udp_ports_to_scan = normalize_port_list(args.udp_ports)
        except ValueError as e:
            parser.error(str(e))
        udp_scan_mode = 'custom'
    elif args.all_udp:
        udp_ports_to_scan = list(range(1, 65536))
        udp_scan_mode = 'all'
    elif args.udp:
        udp_ports_to_scan = TOP_UDP_PORTS
        udp_scan_mode = 'top'
    else:
        udp_ports_to_scan = None
        udp_scan_mode = None

    # Parse multiple CIDR networks separated by commas
    target_networks = [target.strip() for target in args.target.split(',')]

    print("=" * 50)
    print("🌐 Network Vector - Advanced Network Scanner")
    if len(target_networks) > 1:
        print(f"Targets: {len(target_networks)} networks - {', '.join(target_networks)}")
    else:
        print(f"Target: {target_networks[0]}")
    print(f"Ports: {len(ports_to_scan)} ports")
    print(f"Timeout: {args.timeout}s")
    print(f"Max Threads: {args.threads}")
    print(f"Hostname Resolution: {'Enabled' if not args.no_resolve_hostnames else 'Disabled'}")
    print(f"Share Enumeration: {'Enabled' if not args.no_enumerate_shares else 'Disabled'}")
    print(f"Randomized Scanning: {'Enabled' if not args.no_randomize else 'Disabled'}")
    if args.no_ping_sweep:
        print(f"Host Discovery: Disabled (-Pn) — treating all addresses as live")
    if udp_ports_to_scan:
        udp_mode_label = {'all': 'all ports', 'custom': 'custom ports', 'top': 'common ports'}[udp_scan_mode]
        print(f"UDP Scan: Enabled — {udp_mode_label}, {len(udp_ports_to_scan)} ports ({', '.join(str(p) for p in udp_ports_to_scan[:8])}{'…' if len(udp_ports_to_scan) > 8 else ''})")
    if args.dig:
        print(f"Deep Scan (Dig): Enabled - will scan all ports on discovered hosts")
    if args.live and not args.no_graph:
        print(f"Live Mode: Enabled - graphs will update after each host")
    if args.scan_delay > 0:
        print(f"Scan Delay: Random delays up to {args.scan_delay}s between hosts")
    if args.exempt:
        print(f"Exemptions: {args.exempt}")
    if args.livelog:
        print(f"Live Log: Enabled - printing discoveries as they occur")
    if args.json_report:
        print(f"JSON Report: Enabled")
    if args.compare_json:
        print(f"Delta Compare: {args.compare_json}")
    print("=" * 50)

    try:
        # Parse exemption list
        exempt_list = []
        if args.exempt:
            exempt_list = [e.strip() for e in args.exempt.split(',')]

        # Create scanner instance
        scanner = RawPortScanner(
            timeout=args.timeout,
            max_threads=args.threads,
            resolve_hostnames=not args.no_resolve_hostnames,
            enumerate_shares=not args.no_enumerate_shares,
            randomize_scan=not args.no_randomize,
            scan_delay=args.scan_delay,
            exempt_list=exempt_list,
            livelog=args.livelog,
            no_ping_sweep=args.no_ping_sweep
        )

        # Initialize combined results
        combined_scan_results = {}
        combined_share_results = {}
        combined_host_details = {}
        combined_udp_results = {}

        # Create timestamped filename for live mode
        from datetime import datetime
        live_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        live_html_filename = f"network_scan_{live_timestamp}.html"
        live_html_filename_3d = f"network_scan_{live_timestamp}_3d.html"
        live_last_host_count = [0]  # Use list to allow modification in closure

        # Live callback function for real-time graph updates
        def live_graph_callback(scan_results, share_results, host_details):
            if args.no_graph or not args.live:
                return

            # Only regenerate if new hosts were found
            current_host_count = len(host_details)
            if current_host_count <= live_last_host_count[0]:
                return
            live_last_host_count[0] = current_host_count

            try:
                # Prepare scan data for embedding
                scan_data = {
                    'scan_results': scan_results,
                    'share_results': share_results,
                    'host_details': host_details,
                    'timestamp': time.time(),
                    'scan_info': {
                        'target': args.target,
                        'networks_scanned': len(target_networks),
                        'total_hosts': len(host_details),
                        'scan_time': f"Live scan - {time.strftime('%Y-%m-%d %H:%M:%S')}",
                        'ports_scanned': len(ports_to_scan),
                        'hostname_resolution': not args.no_resolve_hostnames,
                        'share_enumeration': not args.no_enumerate_shares,
                        'randomized_scan': not args.no_randomize,
                        'live_mode': True
                    }
                }

                # Regenerate 2D graph (don't open browser, just save)
                custom_graph = create_custom_graph_from_scan(scan_results, share_results, host_details)
                custom_graph.save_html(live_html_filename, scan_data)

                # Regenerate 3D graph if requested
                if args.force_3d:
                    custom_graph_3d = create_custom_3d_graph_from_scan(scan_results, share_results, host_details)
                    custom_graph_3d.save_html(live_html_filename_3d, scan_data)

            except Exception as e:
                pass  # Silently ignore errors to not interrupt scan

        # Scan each target network
        for i, target in enumerate(target_networks):
            if len(target_networks) > 1:
                print(f"\n🎯 Scanning network {i+1}/{len(target_networks)}: {target}")
                print("-" * 40)

            # Scan current network with live callback if enabled
            live_callback = live_graph_callback if args.live and not args.no_graph else None
            results = scanner.scan_network(target, ports_to_scan, on_host_complete=live_callback, udp_ports=udp_ports_to_scan)

            # Extract results from current scan
            current_scan_results = results.get('scan_results', {}) if isinstance(results, dict) else results
            current_share_results = results.get('share_results', {}) if isinstance(results, dict) else scanner.share_results
            current_host_details = results.get('host_details', {}) if isinstance(results, dict) else {}
            current_udp_results = results.get('udp_results', {}) if isinstance(results, dict) else {}

            # Merge results into combined data
            if current_scan_results:
                combined_scan_results.update(current_scan_results)
            if current_share_results:
                combined_share_results.update(current_share_results)
            if current_host_details:
                combined_host_details.update(current_host_details)
            if current_udp_results:
                combined_udp_results.update(current_udp_results)

        # Deep scan (dig) - scan all ports on discovered hosts
        if args.dig and combined_host_details:
            discovered_hosts = list(combined_host_details.keys())
            print(f"\n🔍 Deep Scan (Dig): Scanning all 65535 ports on {len(discovered_hosts)} discovered host(s)...")
            print("=" * 50)

            all_ports = list(range(1, 65536))

            for i, host_display in enumerate(discovered_hosts):
                host_ip = combined_host_details[host_display].get('ip', host_display)

                print(f"\n🎯 Deep scanning host {i+1}/{len(discovered_hosts)}: {host_display}")

                # Clear scanner results for this host to get fresh full scan
                if host_display in scanner.scan_results:
                    del scanner.scan_results[host_display]
                if host_display in scanner.host_details:
                    del scanner.host_details[host_display]

                # Scan single host with all ports
                scanner.scan_host(host_ip, all_ports)

                # Update combined results with deep scan findings
                if host_display in scanner.scan_results:
                    combined_scan_results[host_display] = scanner.scan_results[host_display]
                if host_display in scanner.host_details:
                    combined_host_details[host_display] = scanner.host_details[host_display]

            print(f"\n✅ Deep scan complete!")

        scan_results = combined_scan_results
        share_results = combined_share_results
        host_details = combined_host_details
        udp_results = combined_udp_results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_info = {
            'target': args.target,
            'networks_scanned': len(target_networks),
            'total_hosts': len(host_details),
            'scan_time': f"Completed at {time.strftime('%Y-%m-%d %H:%M:%S')}",
            'ports_scanned': len(ports_to_scan),
            'udp_ports_scanned': len(udp_ports_to_scan) if udp_ports_to_scan else 0,
            'udp_scan_mode': udp_scan_mode,
            'hostname_resolution': not args.no_resolve_hostnames,
            'share_enumeration': not args.no_enumerate_shares,
            'randomized_scan': not args.no_randomize,
            'stealth_mode': args.scan_delay > 0,
        }
        report_data = build_report_data(scan_results, share_results, host_details, udp_results, scan_info)

        if args.compare_json:
            try:
                previous_report = load_report_json(args.compare_json)
                report_data['delta_report'] = compare_reports(report_data, previous_report)
                report_data['comparison_executive_summary'] = previous_report.get('executive_summary', {})
                print(f"\nDelta report prepared against: {args.compare_json}")
            except Exception as e:
                print(f"\n⚠️ Delta compare skipped: {e}")

        if args.json_report:
            export_to_json(report_data, timestamp)

        summary = report_data['executive_summary']
        print("\nExecutive Summary:")
        print(f"  Live hosts: {summary['total_live_hosts']}")
        print(f"  Open TCP ports: {summary['total_open_tcp_ports']}")
        print(f"  Confirmed UDP open ports: {summary['confirmed_udp_open_ports']}")
        print(f"  UDP open|filtered: {summary['udp_open_filtered_count']}")
        print(f"  High-risk services: {summary['high_risk_services_found']}")
        if summary['top_exposed_hosts']:
            exposed = ', '.join(
                f"{host['host']} ({host['service_count']})"
                for host in summary['top_exposed_hosts'][:5]
            )
            print(f"  Top exposed hosts: {exposed}")

        # Display results
        if scan_results or udp_results:
            if scan_results:
                print(f"\nScan Results:")
                print(f"Found {len(scan_results)} open TCP ports across {len(host_details)} hosts:")
                for host_ip, host_info in host_details.items():
                    open_ports = [port_data['port'] for port_data in host_info['open_ports']]
                    os_info = host_info.get('os_detection', {'os': 'Unknown'})
                    avg_response = host_info.get('avg_response_time', 'N/A')
                    print(f"  {host_ip}: {len(open_ports)} open TCP ports - {open_ports}")
                    print(f"    OS: {os_info['os']}, Avg Response: {avg_response:.3f}ms" if avg_response != 'N/A' else f"    OS: {os_info['os']}, Avg Response: N/A")
            else:
                print(f"\nNo open TCP ports found.")

            if share_results:
                print(f"\nShare Enumeration Results:")
                for host, shares in share_results.items():
                    if shares:
                        print(f"  {host}: {len(shares)} shares - {shares}")

            if udp_results:
                print(f"\nUDP Scan Results:")
                for host, udp in sorted(udp_results.items()):
                    open_p = udp.get('open', [])
                    filtered_p = udp.get('open|filtered', [])
                    if open_p:
                        print(f"  {host}: UDP open — {open_p}")
                    if filtered_p:
                        print(f"  {host}: UDP open|filtered — {filtered_p}")

            # Generate custom D3 graph
            if not args.no_graph:
                print("\nGenerating custom D3.js visualization...")
                if not args.no_resolve_hostnames:
                    print("Note: Hostnames will be shown in the graph as 'IP-hostname' format")
                if not args.no_enumerate_shares and share_results:
                    print("Note: Discovered shares will be connected to dedicated 'Shares' nodes for each host")

                html_filename = f"network_scan_{timestamp}.html"

                # Prepare scan data for embedding with host details
                scan_data = {
                    'scan_results': scan_results,
                    'share_results': share_results,
                    'host_details': host_details,
                    'udp_results': udp_results,
                    'report': report_data,
                    'timestamp': time.time(),
                    'scan_info': scan_info
                }

                # Use custom D3.js graph (now the only option)
                custom_graph = create_custom_graph_from_scan(scan_results, share_results, host_details)
                output_file = custom_graph.save_and_show(html_filename, scan_data)
                print(f"Custom D3 graph saved to: {output_file}")
                print("Interactive graph opened in browser!")

                # Generate 3D graph if requested
                if args.force_3d:
                    print("\nGenerating 3D force-directed visualization...")
                    html_filename_3d = f"network_scan_{timestamp}_3d.html"
                    custom_graph_3d = create_custom_3d_graph_from_scan(scan_results, share_results, host_details)
                    output_file_3d = custom_graph_3d.save_and_show(html_filename_3d, scan_data)
                    print(f"3D graph saved to: {output_file_3d}")
                    print("Interactive 3D graph opened in browser!")
            else:
                # Export to CSV when graph generation is skipped
                print("\nGraph generation skipped. Exporting results to CSV...")
                csv_file = export_to_csv(report_data, args.target, args)
                if csv_file:
                    print("💡 Use Excel, Google Sheets, or any CSV viewer to analyze the data")

        else:
            print("\nNo open ports found on any hosts.")

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"\nError during scan: {e}")

if __name__ == "__main__":
    main()
