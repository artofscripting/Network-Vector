#!/usr/bin/env python3
"""
Custom D3.js Force-Directed Graph Generator
Creates a pure D3.js force-directed chart without using the d3graph library.
This gives us full control over styling, including yellow edges and sticky nodes.
"""

import json
import os
import tempfile
import webbrowser
from typing import Dict, List, Set, Any

# Port descriptions database with enhanced information and learning links
PORT_DESCRIPTIONS = {
    # System and well-known ports (1-1023)
    1: {
        "description": "TCP Port Service Multiplexer",
        "details": "System port for TCP port service multiplexer. Rarely used in modern systems.",
        "security": "LOW RISK - System reserved port",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    2: {
        "description": "CompressNET Management Utility",
        "details": "Legacy compression service management. Not commonly used.",
        "security": "LOW RISK - Legacy system service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    3: {
        "description": "Compression Process",
        "details": "Data compression service. Legacy protocol rarely seen today.",
        "security": "LOW RISK - Legacy compression service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    5: {
        "description": "Remote Job Entry",
        "details": "Remote job entry protocol for mainframe systems. Legacy service.",
        "security": "MEDIUM RISK - Legacy remote access",
        "link": "https://en.wikipedia.org/wiki/Remote_job_entry"
    },
    7: {
        "description": "Echo Protocol",
        "details": "Simple network testing protocol that echoes back received data.",
        "security": "LOW RISK - Network testing service",
        "link": "https://tools.ietf.org/html/rfc862"
    },
    9: {
        "description": "Discard Protocol",
        "details": "Null service that discards all received data. Used for testing.",
        "security": "LOW RISK - Testing service",
        "link": "https://tools.ietf.org/html/rfc863"
    },
    11: {
        "description": "Active Users (systat)",
        "details": "System status protocol showing active users. Security risk if exposed.",
        "security": "MEDIUM RISK - Exposes system information",
        "link": "https://tools.ietf.org/html/rfc866"
    },
    13: {
        "description": "Daytime Protocol",
        "details": "Returns current date and time in human-readable format.",
        "security": "LOW RISK - Time service",
        "link": "https://tools.ietf.org/html/rfc867"
    },
    15: {
        "description": "Netstat Service",
        "details": "Returns network status information. Can expose network topology.",
        "security": "MEDIUM RISK - Network information disclosure",
        "link": "https://en.wikipedia.org/wiki/Netstat"
    },
    17: {
        "description": "Quote of the Day (QOTD)",
        "details": "Returns a quote or message. Sometimes exploited for DDoS amplification.",
        "security": "MEDIUM RISK - Can be used for amplification attacks",
        "link": "https://tools.ietf.org/html/rfc865"
    },
    18: {
        "description": "Message Send Protocol",
        "details": "Legacy messaging protocol. Rarely used in modern systems.",
        "security": "LOW RISK - Legacy messaging",
        "link": "https://tools.ietf.org/html/rfc1312"
    },
    19: {
        "description": "Character Generator (chargen)",
        "details": "Generates continuous stream of characters. DDoS amplification risk.",
        "security": "HIGH RISK - DDoS amplification vector",
        "link": "https://tools.ietf.org/html/rfc864"
    },
    20: {
        "description": "FTP Data Transfer",
        "details": "File Transfer Protocol data channel for active mode transfers.",
        "security": "HIGH RISK - Unencrypted file transfer",
        "link": "https://en.wikipedia.org/wiki/File_Transfer_Protocol"
    },
    21: {
        "description": "FTP Control - File Transfer Protocol control channel",
        "details": "Used for uploading/downloading files. Often a security risk if unencrypted.",
        "security": "HIGH RISK - Unencrypted, credentials sent in plaintext",
        "link": "https://en.wikipedia.org/wiki/File_Transfer_Protocol"
    },
    22: {
        "description": "SSH - Secure Shell remote access",
        "details": "Encrypted remote terminal access and secure file transfer (SFTP/SCP).",
        "security": "SECURE - Encrypted communication",
        "link": "https://www.openssh.com/"
    },
    23: {
        "description": "Telnet - Unencrypted remote terminal",
        "details": "Legacy remote terminal protocol. Sends passwords in plaintext.",
        "security": "HIGH RISK - Unencrypted, avoid using",
        "link": "https://en.wikipedia.org/wiki/Telnet"
    },
    25: {
        "description": "SMTP - Simple Mail Transfer Protocol",
        "details": "Email server communication for sending emails between servers.",
        "security": "MEDIUM - Can be secured with TLS",
        "link": "https://tools.ietf.org/html/rfc5321"
    },
    37: {
        "description": "Time Protocol",
        "details": "Network time protocol that returns time since Unix epoch.",
        "security": "LOW RISK - Time synchronization",
        "link": "https://tools.ietf.org/html/rfc868"
    },
    39: {
        "description": "Resource Location Protocol",
        "details": "Legacy resource discovery protocol. Rarely used today.",
        "security": "LOW RISK - Legacy discovery service",
        "link": "https://tools.ietf.org/html/rfc887"
    },
    42: {
        "description": "Host Name Server",
        "details": "Legacy hostname resolution service. Superseded by DNS.",
        "security": "LOW RISK - Legacy naming service",
        "link": "https://tools.ietf.org/html/rfc953"
    },
    43: {
        "description": "WHOIS - Domain registration lookup",
        "details": "Domain and IP address registration information lookup service.",
        "security": "LOW RISK - Public information service",
        "link": "https://tools.ietf.org/html/rfc3912"
    },
    49: {
        "description": "TACACS Login Host Protocol",
        "details": "Terminal Access Controller Access Control System authentication.",
        "security": "MEDIUM RISK - Authentication service",
        "link": "https://tools.ietf.org/html/rfc1492"
    },
    50: {
        "description": "Remote Mail Checking Protocol",
        "details": "Legacy protocol for checking remote mail. Rarely used.",
        "security": "LOW RISK - Legacy mail service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    53: {
        "description": "DNS - Domain Name System",
        "details": "Translates domain names to IP addresses. Critical internet infrastructure.",
        "security": "LOW RISK - Standard service, can be secured with DoT/DoH",
        "link": "https://www.cloudflare.com/learning/dns/what-is-dns/"
    },
    57: {
        "description": "MTP - Mail Transfer Protocol",
        "details": "Legacy mail transfer protocol. Superseded by SMTP.",
        "security": "LOW RISK - Legacy mail protocol",
        "link": "https://tools.ietf.org/html/rfc780"
    },
    58: {
        "description": "XNS Mail Protocol",
        "details": "Xerox Network Systems mail protocol. Legacy system.",
        "security": "LOW RISK - Legacy Xerox protocol",
        "link": "https://en.wikipedia.org/wiki/Xerox_Network_Systems"
    },
    67: {
        "description": "DHCP/BOOTP Server",
        "details": "Dynamic Host Configuration Protocol server for IP address assignment.",
        "security": "MEDIUM RISK - Network configuration service",
        "link": "https://tools.ietf.org/html/rfc2131"
    },
    68: {
        "description": "DHCP/BOOTP Client",
        "details": "Dynamic Host Configuration Protocol client for receiving IP configuration.",
        "security": "LOW RISK - DHCP client communication",
        "link": "https://tools.ietf.org/html/rfc2131"
    },
    69: {
        "description": "TFTP - Trivial File Transfer Protocol",
        "details": "Simple file transfer protocol without authentication. Often insecure.",
        "security": "HIGH RISK - No authentication, plaintext transfer",
        "link": "https://tools.ietf.org/html/rfc1350"
    },
    70: {
        "description": "Gopher Protocol",
        "details": "Legacy hierarchical document system predating the World Wide Web.",
        "security": "LOW RISK - Legacy document protocol",
        "link": "https://tools.ietf.org/html/rfc1436"
    },
    71: {
        "description": "NETRJS Protocol",
        "details": "Network Remote Job Service. Legacy mainframe job submission.",
        "security": "LOW RISK - Legacy mainframe service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    72: {
        "description": "NETRJS Protocol (continued)",
        "details": "Network Remote Job Service continuation. Legacy mainframe service.",
        "security": "LOW RISK - Legacy mainframe service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    73: {
        "description": "NETRJS Protocol (continued)",
        "details": "Network Remote Job Service continuation. Legacy mainframe service.",
        "security": "LOW RISK - Legacy mainframe service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    74: {
        "description": "NETRJS Protocol (continued)",
        "details": "Network Remote Job Service continuation. Legacy mainframe service.",
        "security": "LOW RISK - Legacy mainframe service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    79: {
        "description": "Finger Protocol",
        "details": "User information lookup protocol. Exposes user details and system info.",
        "security": "HIGH RISK - Information disclosure, privacy concerns",
        "link": "https://tools.ietf.org/html/rfc1288"
    },
    80: {
        "description": "HTTP - HyperText Transfer Protocol",
        "details": "Web server communication. Unencrypted web traffic.",
        "security": "MEDIUM RISK - Unencrypted, use HTTPS instead",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP"
    },
    81: {
        "description": "HTTP Alternate",
        "details": "Alternative HTTP port often used for web administration or proxies.",
        "security": "MEDIUM RISK - Unencrypted web traffic",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP"
    },
    82: {
        "description": "XFER Utility",
        "details": "File transfer utility. Implementation varies by system.",
        "security": "MEDIUM RISK - File transfer service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    83: {
        "description": "MIT ML Device",
        "details": "MIT Machine Learning device protocol. Research/academic use.",
        "security": "LOW RISK - Academic research protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    84: {
        "description": "Common Trace Facility",
        "details": "System tracing and debugging facility.",
        "security": "MEDIUM RISK - System debugging information",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    85: {
        "description": "MIT ML Device (continued)",
        "details": "MIT Machine Learning device protocol continuation.",
        "security": "LOW RISK - Academic research protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    87: {
        "description": "Terminal Link",
        "details": "Legacy terminal linking protocol. Rarely used today.",
        "security": "LOW RISK - Legacy terminal service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    88: {
        "description": "Kerberos Authentication",
        "details": "Network authentication protocol using tickets and encryption.",
        "security": "SECURE - Strong authentication protocol",
        "link": "https://web.mit.edu/kerberos/"
    },
    89: {
        "description": "SU-MIT Telnet Gateway",
        "details": "Stanford University MIT Telnet gateway service.",
        "security": "MEDIUM RISK - Telnet gateway service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    90: {
        "description": "DNSIX Security Attribute Token Map",
        "details": "Defense Intelligence Agency security token mapping.",
        "security": "MEDIUM RISK - Security token service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    95: {
        "description": "SUPDUP Protocol",
        "details": "Stanford University Display Protocol for remote terminals.",
        "security": "MEDIUM RISK - Remote terminal protocol",
        "link": "https://en.wikipedia.org/wiki/SUPDUP"
    },
    98: {
        "description": "Linuxconf",
        "details": "Linux system configuration tool web interface.",
        "security": "HIGH RISK - System configuration access",
        "link": "https://en.wikipedia.org/wiki/Linuxconf"
    },
    99: {
        "description": "WIP Message Protocol",
        "details": "Wireless Internet Protocol message service.",
        "security": "MEDIUM RISK - Wireless messaging service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    100: {
        "description": "NEWACCT Account Creation",
        "details": "Automated account creation service. Security risk if exposed.",
        "security": "HIGH RISK - Account creation service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    
    # Additional well-known ports (101-200)
    101: {
        "description": "NIC Host Name Server",
        "details": "Network Information Center hostname resolution service.",
        "security": "LOW RISK - Legacy naming service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    102: {
        "description": "ISO-TSAP Protocol",
        "details": "ISO Transport Service Access Point. Legacy networking protocol.",
        "security": "LOW RISK - Legacy ISO protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    103: {
        "description": "Genesis Point-to-Point Trans Net",
        "details": "Legacy networking protocol for point-to-point communication.",
        "security": "LOW RISK - Legacy networking protocol",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    104: {
        "description": "ACR-NEMA Digital Imaging",
        "details": "Medical imaging communication protocol (predecessor to DICOM).",
        "security": "MEDIUM RISK - Medical data transmission",
        "link": "https://en.wikipedia.org/wiki/DICOM"
    },
    105: {
        "description": "CCSO Nameserver (CSNet)",
        "details": "Computer Science Network nameserver protocol.",
        "security": "LOW RISK - Legacy nameserver",
        "link": "https://en.wikipedia.org/wiki/CSNET"
    },
    106: {
        "description": "3COM-TSMUX",
        "details": "3COM terminal server multiplexer protocol.",
        "security": "MEDIUM RISK - Terminal server access",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    107: {
        "description": "Remote Telnet Service",
        "details": "Remote telnet service with additional features.",
        "security": "HIGH RISK - Remote terminal access",
        "link": "https://en.wikipedia.org/wiki/Telnet"
    },
    108: {
        "description": "SNA Gateway Access Server",
        "details": "IBM Systems Network Architecture gateway service.",
        "security": "MEDIUM RISK - Legacy IBM networking",
        "link": "https://en.wikipedia.org/wiki/Systems_Network_Architecture"
    },
    109: {
        "description": "POP2 - Post Office Protocol v2",
        "details": "Legacy email retrieval protocol. Superseded by POP3.",
        "security": "HIGH RISK - Legacy, unencrypted email protocol",
        "link": "https://tools.ietf.org/html/rfc937"
    },
    110: {
        "description": "POP3 - Post Office Protocol v3",
        "details": "Email retrieval protocol. Downloads emails to client device.",
        "security": "MEDIUM RISK - Can be secured with SSL/TLS",
        "link": "https://tools.ietf.org/html/rfc1939"
    },
    111: {
        "description": "RPC Portmapper - Remote Procedure Call",
        "details": "Maps RPC program numbers to network ports. Used by NFS and other services.",
        "security": "HIGH RISK - Can expose other services",
        "link": "https://en.wikipedia.org/wiki/Open_Network_Computing_Remote_Procedure_Call"
    },
    112: {
        "description": "McIDAS Data Transmission Protocol",
        "details": "Meteorological data transmission for weather systems.",
        "security": "LOW RISK - Weather data service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    113: {
        "description": "Ident - User identification protocol",
        "details": "Identifies the user of a TCP connection. Privacy and security concerns.",
        "security": "MEDIUM RISK - User information disclosure",
        "link": "https://tools.ietf.org/html/rfc1413"
    },
    115: {
        "description": "SFTP - Simple File Transfer Protocol",
        "details": "Legacy simple file transfer protocol (not SSH SFTP).",
        "security": "MEDIUM RISK - Legacy file transfer",
        "link": "https://tools.ietf.org/html/rfc913"
    },
    117: {
        "description": "UUCP Path Service",
        "details": "Unix-to-Unix Copy Protocol path information service.",
        "security": "LOW RISK - Legacy Unix networking",
        "link": "https://en.wikipedia.org/wiki/UUCP"
    },
    118: {
        "description": "SQL Services",
        "details": "Structured Query Language database services.",
        "security": "HIGH RISK - Database access",
        "link": "https://en.wikipedia.org/wiki/SQL"
    },
    119: {
        "description": "NNTP - Network News Transfer Protocol",
        "details": "Protocol for reading and posting Usenet news articles.",
        "security": "MEDIUM RISK - News/forum service",
        "link": "https://tools.ietf.org/html/rfc3977"
    },
    120: {
        "description": "CFDPTKT - Configuration File Transfer",
        "details": "Configuration file transfer protocol.",
        "security": "MEDIUM RISK - Configuration transfer",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    121: {
        "description": "ERPC - Encore RPC",
        "details": "Encore Computer Corporation Remote Procedure Call.",
        "security": "MEDIUM RISK - Legacy RPC service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    123: {
        "description": "NTP - Network Time Protocol",
        "details": "Synchronizes computer clocks across networks.",
        "security": "LOW RISK - Time synchronization service",
        "link": "https://www.ntp.org/"
    },
    125: {
        "description": "LOCUS-MAP - Network Mapping",
        "details": "LOCUS distributed system mapping protocol.",
        "security": "MEDIUM RISK - Network topology information",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    129: {
        "description": "PWDGEN Password Generator",
        "details": "Password generation service. Security risk if exposed.",
        "security": "HIGH RISK - Password generation service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    135: {
        "description": "Microsoft RPC Endpoint Mapper",
        "details": "Windows RPC service that maps RPC endpoints. Critical Windows service.",
        "security": "HIGH RISK - Common attack target, restrict access",
        "link": "https://docs.microsoft.com/en-us/windows/win32/rpc/rpc-start-page"
    },
    137: {
        "description": "NetBIOS Name Service",
        "details": "Windows NetBIOS name resolution service. Legacy networking.",
        "security": "HIGH RISK - Legacy protocol, information disclosure",
        "link": "https://en.wikipedia.org/wiki/NetBIOS"
    },
    138: {
        "description": "NetBIOS Datagram Service",
        "details": "Windows NetBIOS datagram distribution service.",
        "security": "HIGH RISK - Legacy protocol, security issues",
        "link": "https://en.wikipedia.org/wiki/NetBIOS"
    },
    139: {
        "description": "NetBIOS Session Service - Windows networking",
        "details": "Legacy Windows file sharing protocol. Part of SMB over NetBIOS.",
        "security": "HIGH RISK - Legacy protocol, disable if possible",
        "link": "https://en.wikipedia.org/wiki/NetBIOS"
    },
    143: {
        "description": "IMAP - Internet Message Access Protocol",
        "details": "Email access protocol that keeps emails on server. More advanced than POP3.",
        "security": "MEDIUM RISK - Should use SSL/TLS (port 993)",
        "link": "https://tools.ietf.org/html/rfc3501"
    },
    144: {
        "description": "NewS - Network News System",
        "details": "Network news distribution system.",
        "security": "MEDIUM RISK - News distribution service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    145: {
        "description": "UAAC Protocol",
        "details": "Unix-to-Unix Copy Protocol with authentication.",
        "security": "MEDIUM RISK - File transfer with authentication",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    146: {
        "description": "ISO-IP0 - ISO Transport Protocol",
        "details": "ISO transport protocol over IP networks.",
        "security": "LOW RISK - Legacy ISO networking",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    150: {
        "description": "NetBIOS Session Service (continued)",
        "details": "Extended NetBIOS session service functionality.",
        "security": "HIGH RISK - Legacy Windows networking",
        "link": "https://en.wikipedia.org/wiki/NetBIOS"
    },
    152: {
        "description": "Background File Transfer Program",
        "details": "Background file transfer service for batch operations.",
        "security": "MEDIUM RISK - File transfer service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    153: {
        "description": "SGMP - Simple Gateway Monitoring Protocol",
        "details": "Legacy network monitoring protocol. Superseded by SNMP.",
        "security": "MEDIUM RISK - Network monitoring service",
        "link": "https://tools.ietf.org/html/rfc1028"
    },
    156: {
        "description": "SQL Service",
        "details": "Database SQL service access.",
        "security": "HIGH RISK - Database service access",
        "link": "https://en.wikipedia.org/wiki/SQL"
    },
    158: {
        "description": "DMSP - Distributed Mail System Protocol",
        "details": "Distributed mail system communication protocol.",
        "security": "MEDIUM RISK - Mail system service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    161: {
        "description": "SNMP - Simple Network Management Protocol",
        "details": "Network device monitoring and management. Often uses weak community strings.",
        "security": "HIGH RISK - Often misconfigured, use SNMPv3",
        "link": "https://www.paessler.com/snmp"
    },
    162: {
        "description": "SNMP Trap",
        "details": "SNMP trap receiver for network device notifications.",
        "security": "MEDIUM RISK - Network monitoring notifications",
        "link": "https://www.paessler.com/snmp"
    },
    163: {
        "description": "CMIP-MAN - Network Management",
        "details": "Common Management Information Protocol management.",
        "security": "MEDIUM RISK - Network management service",
        "link": "https://en.wikipedia.org/wiki/Common_Management_Information_Protocol"
    },
    164: {
        "description": "CMIP-AGENT",
        "details": "Common Management Information Protocol agent.",
        "security": "MEDIUM RISK - Management agent service",
        "link": "https://en.wikipedia.org/wiki/Common_Management_Information_Protocol"
    },
    174: {
        "description": "MAILQ - Mail Queue",
        "details": "Mail queue management service.",
        "security": "MEDIUM RISK - Mail queue access",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    177: {
        "description": "XDMCP - X Display Manager Control Protocol",
        "details": "X Window System display manager protocol.",
        "security": "HIGH RISK - Remote X11 access, often unencrypted",
        "link": "https://en.wikipedia.org/wiki/X_Display_Manager_Control_Protocol"
    },
    178: {
        "description": "NextStep Window Server",
        "details": "NextStep operating system window server.",
        "security": "MEDIUM RISK - GUI access service",
        "link": "https://en.wikipedia.org/wiki/NeXTSTEP"
    },
    179: {
        "description": "BGP - Border Gateway Protocol",
        "details": "Internet routing protocol for exchanging routing information.",
        "security": "HIGH RISK - Critical routing protocol, secure properly",
        "link": "https://tools.ietf.org/html/rfc4271"
    },
    191: {
        "description": "Prospero Directory Service",
        "details": "Distributed directory service protocol.",
        "security": "MEDIUM RISK - Directory service access",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    194: {
        "description": "IRC - Internet Relay Chat",
        "details": "Real-time chat protocol for group communication.",
        "security": "MEDIUM RISK - Chat service, monitor for abuse",
        "link": "https://tools.ietf.org/html/rfc1459"
    },
    199: {
        "description": "SMUX - SNMP Multiplexer",
        "details": "SNMP protocol multiplexer for network management.",
        "security": "MEDIUM RISK - Network management multiplexer",
        "link": "https://tools.ietf.org/html/rfc1227"
    },
    110: {
        "description": "POP3 - Post Office Protocol v3",
        "details": "Email retrieval protocol. Downloads emails to client device.",
        "security": "MEDIUM RISK - Can be secured with SSL/TLS",
        "link": "https://tools.ietf.org/html/rfc1939"
    },
    199: {
        "description": "SMUX - SNMP Multiplexer",
        "details": "SNMP protocol multiplexer for network management.",
        "security": "MEDIUM RISK - Network management multiplexer",
        "link": "https://tools.ietf.org/html/rfc1227"
    },
    
    # Additional common ports (200-400)
    201: {
        "description": "AppleTalk Routing Maintenance",
        "details": "Apple networking protocol routing maintenance.",
        "security": "LOW RISK - Legacy Apple networking",
        "link": "https://en.wikipedia.org/wiki/AppleTalk"
    },
    202: {
        "description": "AppleTalk Name Binding",
        "details": "Apple networking protocol name binding service.",
        "security": "LOW RISK - Legacy Apple networking",
        "link": "https://en.wikipedia.org/wiki/AppleTalk"
    },
    204: {
        "description": "AppleTalk Echo",
        "details": "Apple networking protocol echo service.",
        "security": "LOW RISK - Legacy Apple networking",
        "link": "https://en.wikipedia.org/wiki/AppleTalk"
    },
    206: {
        "description": "AppleTalk Zone Information",
        "details": "Apple networking protocol zone information service.",
        "security": "LOW RISK - Legacy Apple networking",
        "link": "https://en.wikipedia.org/wiki/AppleTalk"
    },
    209: {
        "description": "Quick Mail Transfer Protocol",
        "details": "Alternative mail transfer protocol.",
        "security": "MEDIUM RISK - Mail transfer service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    210: {
        "description": "ANSI Z39.50",
        "details": "Information retrieval protocol for bibliographic databases.",
        "security": "LOW RISK - Database query protocol",
        "link": "https://en.wikipedia.org/wiki/Z39.50"
    },
    213: {
        "description": "IPX - Internetwork Packet Exchange",
        "details": "Novell NetWare networking protocol.",
        "security": "MEDIUM RISK - Legacy Novell networking",
        "link": "https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange"
    },
    220: {
        "description": "IMAP3 - Internet Message Access Protocol v3",
        "details": "Legacy version of IMAP email protocol.",
        "security": "MEDIUM RISK - Legacy email protocol",
        "link": "https://tools.ietf.org/html/rfc1203"
    },
    245: {
        "description": "LINK - Link Protocol",
        "details": "Network link establishment protocol.",
        "security": "MEDIUM RISK - Network link service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    347: {
        "description": "Fatmen Server",
        "details": "File and Tape Management system server.",
        "security": "MEDIUM RISK - File management service",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    363: {
        "description": "RSVP Tunnel",
        "details": "Resource Reservation Protocol tunnel service.",
        "security": "MEDIUM RISK - Quality of Service protocol",
        "link": "https://tools.ietf.org/html/rfc2205"
    },
    389: {
        "description": "LDAP - Lightweight Directory Access Protocol",
        "details": "Directory service protocol for accessing user/computer information.",
        "security": "MEDIUM RISK - Should use LDAPS (port 636)",
        "link": "https://ldap.com/"
    },
    401: {
        "description": "UPS Uninterruptible Power Supply",
        "details": "Network UPS monitoring and management protocol.",
        "security": "MEDIUM RISK - Infrastructure monitoring",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    },
    427: {
        "description": "SLP - Service Location Protocol",
        "details": "Service discovery protocol for network services.",
        "security": "MEDIUM RISK - Service discovery",
        "link": "https://tools.ietf.org/html/rfc2608"
    },
    443: {
        "description": "HTTPS - HTTP over SSL/TLS",
        "details": "Secure web server communication with encrypted traffic.",
        "security": "SECURE - Encrypted web traffic",
        "link": "https://developer.mozilla.org/en-US/docs/Glossary/HTTPS"
    },
    444: {
        "description": "SNPP - Simple Network Paging Protocol",
        "details": "Protocol for sending pager messages over networks.",
        "security": "MEDIUM RISK - Paging service",
        "link": "https://tools.ietf.org/html/rfc1861"
    },
    445: {
        "description": "Microsoft-DS - SMB file sharing",
        "details": "Modern Windows file sharing protocol. Replaced NetBIOS SMB.",
        "security": "HIGH RISK - Common ransomware target, secure properly",
        "link": "https://docs.microsoft.com/en-us/windows-server/storage/file-server/file-server-smb-overview"
    },
    464: {
        "description": "Kerberos Change/Set Password",
        "details": "Kerberos protocol for changing user passwords.",
        "security": "SECURE - Encrypted password change",
        "link": "https://web.mit.edu/kerberos/"
    },
    465: {
        "description": "SMTP over SSL - Secure email submission",
        "details": "Encrypted email submission protocol. More secure than plain SMTP.",
        "security": "SECURE - Encrypted email transmission",
        "link": "https://tools.ietf.org/html/rfc8314"
    },
    500: {
        "description": "ISAKMP - Internet Security Association",
        "details": "IPSec key exchange and security association management.",
        "security": "SECURE - VPN key exchange protocol",
        "link": "https://tools.ietf.org/html/rfc2408"
    },
    512: {
        "description": "Remote Process Execution (rexec)",
        "details": "Remote command execution with authentication.",
        "security": "HIGH RISK - Remote command execution",
        "link": "https://en.wikipedia.org/wiki/Berkeley_r-commands"
    },
    513: {
        "description": "Remote Login (rlogin)",
        "details": "Remote login protocol similar to telnet but less secure.",
        "security": "HIGH RISK - Unencrypted remote login",
        "link": "https://en.wikipedia.org/wiki/Rlogin"
    },
    514: {
        "description": "Remote Shell (rsh)",
        "details": "Remote shell command execution without passwords.",
        "security": "HIGH RISK - Unencrypted remote shell",
        "link": "https://en.wikipedia.org/wiki/Remote_Shell"
    },
    515: {
        "description": "Line Printer Daemon (LPD)",
        "details": "Network printing protocol for Unix/Linux systems.",
        "security": "MEDIUM RISK - Network printing service",
        "link": "https://tools.ietf.org/html/rfc1179"
    },
    524: {
        "description": "NCP - NetWare Core Protocol",
        "details": "Novell NetWare file and print sharing protocol.",
        "security": "MEDIUM RISK - Legacy Novell networking",
        "link": "https://en.wikipedia.org/wiki/NetWare_Core_Protocol"
    },
    543: {
        "description": "Klogin - Kerberized Login",
        "details": "Kerberos-authenticated remote login service.",
        "security": "SECURE - Kerberos-authenticated login",
        "link": "https://web.mit.edu/kerberos/"
    },
    544: {
        "description": "Kshell - Kerberized Shell",
        "details": "Kerberos-authenticated remote shell service.",
        "security": "SECURE - Kerberos-authenticated shell",
        "link": "https://web.mit.edu/kerberos/"
    },
    548: {
        "description": "AFP - Apple Filing Protocol",
        "details": "Apple file sharing protocol for macOS systems.",
        "security": "MEDIUM RISK - Apple file sharing",
        "link": "https://en.wikipedia.org/wiki/Apple_Filing_Protocol"
    },
    554: {
        "description": "RTSP - Real Time Streaming Protocol",
        "details": "Multimedia streaming control protocol.",
        "security": "MEDIUM RISK - Media streaming service",
        "link": "https://tools.ietf.org/html/rfc2326"
    },
    563: {
        "description": "SNEWS - Secure Network News",
        "details": "Secure Network News Transfer Protocol over SSL/TLS.",
        "security": "SECURE - Encrypted news transfer",
        "link": "https://tools.ietf.org/html/rfc4642"
    },
    587: {
        "description": "SMTP Submission - Email submission with STARTTLS",
        "details": "Modern email submission port that supports encryption via STARTTLS.",
        "security": "SECURE - Can be encrypted",
        "link": "https://tools.ietf.org/html/rfc6409"
    },
    631: {
        "description": "IPP - Internet Printing Protocol",
        "details": "Network printing protocol used by CUPS and modern printers.",
        "security": "LOW RISK - Printing service",
        "link": "https://tools.ietf.org/html/rfc8011"
    },
    636: {
        "description": "LDAPS - LDAP over SSL/TLS",
        "details": "Secure LDAP directory service with encrypted communication.",
        "security": "SECURE - Encrypted directory access",
        "link": "https://ldap.com/ldap-over-ssl-tls-and-starttls/"
    },
    989: {
        "description": "FTPS Data - FTP over SSL/TLS Data",
        "details": "Secure FTP data channel with SSL/TLS encryption.",
        "security": "SECURE - Encrypted file transfer data",
        "link": "https://tools.ietf.org/html/rfc4217"
    },
    990: {
        "description": "FTPS Control - FTP over SSL/TLS Control",
        "details": "Secure FTP control channel with SSL/TLS encryption.",
        "security": "SECURE - Encrypted file transfer control",
        "link": "https://tools.ietf.org/html/rfc4217"
    },
    993: {
        "description": "IMAPS - IMAP over SSL/TLS",
        "details": "Secure IMAP email access with encrypted communication.",
        "security": "SECURE - Encrypted email access",
        "link": "https://tools.ietf.org/html/rfc8314"
    },
    995: {
        "description": "POP3S - POP3 over SSL/TLS",
        "details": "Secure POP3 email retrieval with encrypted communication.",
        "security": "SECURE - Encrypted email retrieval",
        "link": "https://tools.ietf.org/html/rfc8314"
    },
    1080: {
        "description": "SOCKS Proxy",
        "details": "SOCKS proxy protocol for network traffic routing.",
        "security": "MEDIUM RISK - Proxy service, monitor usage",
        "link": "https://tools.ietf.org/html/rfc1928"
    },
    1433: {
        "description": "Microsoft SQL Server - Database server",
        "details": "Microsoft SQL Server database engine. Contains sensitive business data.",
        "security": "HIGH RISK - Database contains sensitive data",
        "link": "https://docs.microsoft.com/en-us/sql/sql-server/"
    },
    1521: {
        "description": "Oracle Database - TNS Listener",
        "details": "Oracle database listener service. Handles database connections.",
        "security": "HIGH RISK - Database access, secure properly",
        "link": "https://docs.oracle.com/en/database/"
    },
    1723: {
        "description": "PPTP - Point-to-Point Tunneling Protocol",
        "details": "Legacy VPN protocol with known security vulnerabilities.",
        "security": "HIGH RISK - Deprecated, use modern VPN protocols",
        "link": "https://en.wikipedia.org/wiki/Point-to-Point_Tunneling_Protocol"
    },
    1900: {
        "description": "UPnP - Universal Plug and Play",
        "details": "Automatic device discovery and configuration. Often insecure.",
        "security": "HIGH RISK - Can expose internal services",
        "link": "https://en.wikipedia.org/wiki/Universal_Plug_and_Play"
    },
    2049: {
        "description": "NFS - Network File System",
        "details": "Unix/Linux network file sharing protocol.",
        "security": "MEDIUM RISK - Secure with proper authentication",
        "link": "https://en.wikipedia.org/wiki/Network_File_System"
    },
    2179: {
        "description": "VMware SOAP API - Virtual machine management",
        "details": "VMware vSphere management interface for virtual machines.",
        "security": "HIGH RISK - Critical infrastructure access",
        "link": "https://docs.vmware.com/en/VMware-vSphere/"
    },
    3306: {
        "description": "MySQL Database Server",
        "details": "Popular open-source database management system.",
        "security": "HIGH RISK - Database contains sensitive data",
        "link": "https://dev.mysql.com/doc/"
    },
    3389: {
        "description": "Microsoft RDP - Remote Desktop Protocol",
        "details": "Windows remote desktop access. Frequently targeted by attackers.",
        "security": "HIGH RISK - Common attack target, secure with NLA",
        "link": "https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/understanding-remote-desktop-protocol"
    },
    5357: {
        "description": "WSDAPI - Web Services Discovery",
        "details": "Windows service discovery protocol for network devices.",
        "security": "LOW RISK - Device discovery service",
        "link": "https://docs.microsoft.com/en-us/windows/win32/wsdapi/wsd-portal"
    },
    5432: {
        "description": "PostgreSQL Database Server",
        "details": "Advanced open-source relational database management system.",
        "security": "HIGH RISK - Database contains sensitive data",
        "link": "https://www.postgresql.org/docs/"
    },
    5900: {
        "description": "VNC - Virtual Network Computing",
        "details": "Remote desktop protocol. Often poorly secured by default.",
        "security": "HIGH RISK - Often weak passwords, encrypt traffic",
        "link": "https://en.wikipedia.org/wiki/Virtual_Network_Computing"
    },
    6379: {
        "description": "Redis - In-memory data structure store",
        "details": "Fast in-memory database, cache, and message broker.",
        "security": "HIGH RISK - Often exposed without authentication",
        "link": "https://redis.io/documentation"
    },
    8080: {
        "description": "HTTP Alternate - Web cache/proxy server",
        "details": "Alternative HTTP port often used by web applications and proxies.",
        "security": "MEDIUM RISK - Unencrypted web traffic",
        "link": "https://developer.mozilla.org/en-US/docs/Web/HTTP"
    },
    24800: {
        "description": "Synergy - Screen and keyboard sharing",
        "details": "Software for sharing mouse and keyboard between computers.",
        "security": "MEDIUM RISK - Can intercept keystrokes",
        "link": "https://symless.com/synergy"
    }
}

def get_port_description(port):
    """Get enhanced description for a given port number"""
    port_info = PORT_DESCRIPTIONS.get(port)
    if port_info:
        if isinstance(port_info, dict):
            return port_info["description"]
        else:
            return port_info  # Handle any legacy string entries
    return f"Port {port} - Unknown/Custom application"

def get_port_details(port):
    """Get detailed information for a given port number"""
    port_info = PORT_DESCRIPTIONS.get(port)
    if port_info and isinstance(port_info, dict):
        return port_info
    return {
        "description": f"Port {port} - Unknown/Custom application",
        "details": "No detailed information available for this port.",
        "security": "UNKNOWN",
        "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
    }

class CustomD3ForceGraph:
    """
    Generate custom D3.js force-directed graphs with full control over styling.
    """
    
    def __init__(self):
        self.nodes = []
        self.links = []
        self.node_colors = {}
        self.node_groups = {}
        
    def add_node(self, node_id: str, label: str = None, group: str = "default", color: str = None, size: int = 10, description: str = None, port: int = None):
        """Add a node to the graph."""
        node_data = {
            "id": node_id,
            "label": label or node_id,
            "group": group,
            "color": color,
            "size": size,
            "description": description or ""
        }
        # Add port number if provided
        if port is not None:
            node_data["port"] = port
        
        self.nodes.append(node_data)
        
    def add_link(self, source: str, target: str, weight: int = 1, color: str = "#FFFF00"):
        """Add a link between two nodes."""
        self.links.append({
            "source": source,
            "target": target,
            "weight": weight,
            "color": color
        })
    
    def generate_from_scan_results(self, scan_results: Dict[str, List[int]], share_results: Dict[str, List[str]] = None):
        """
        Generate graph data from port scan results.
        """
        share_results = share_results or {}
        
        # Clear existing data
        self.nodes = []
        self.links = []
        
        # Service mapping for individual ports
        def get_service_name(port):
            service_map = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
                143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
                1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP", 
                5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
                8443: "HTTPS-Alt", 8888: "HTTP-Alt", 2049: "NFS", 548: "AFP",
                587: "SMTP", 993: "IMAPS", 995: "POP3S", 389: "LDAP", 636: "LDAPS",
                3268: "AD-GC", 3269: "AD-GC-SSL", 5985: "WinRM", 5986: "WinRM-S"
            }
            return service_map.get(port, "Unknown")
        
        # Define risky ports that should be highlighted in red
        def is_risky_port(port):
            risky_ports = {
                21,    # FTP - often insecure, plaintext
                23,    # Telnet - plaintext, no encryption
                135,   # RPC - Windows vulnerability target
                139,   # NetBIOS - security risk
                445,   # SMB - ransomware target, lateral movement
                1433,  # MSSQL - database access
                3306,  # MySQL - database access  
                3389,  # RDP - brute force target
                5432,  # PostgreSQL - database access
                5900,  # VNC - remote access, often weak auth
                6379,  # Redis - often unsecured
                1521,  # Oracle - database access
                2049,  # NFS - file sharing risks
                111,   # RPC portmapper - attack vector
                5985,  # WinRM - Windows remote management
                5986,  # WinRM HTTPS - Windows remote management
            }
            return port in risky_ports
        
        # Add host nodes
        for host, ports in scan_results.items():
            # Determine if this is a hostname (contains IP-hostname format)
            is_hostname = '-' in host and any(char.isdigit() for char in host.split('-')[0])
            
            self.add_node(
                node_id=host,
                label=host,
                group="host",
                color="#4CAF50",  # Green for hosts
                size=15
            )
            
            # Add port nodes with service information in label
            for port in ports:
                port_id = f"{host}::{port}"
                service_name = get_service_name(port)
                port_description = get_port_description(port)
                
                # Create combined port/service label
                port_label = f"{port}/{service_name}"
                
                # Determine port color based on risk level
                if is_risky_port(port):
                    port_color = "#F44336"  # Red for risky ports
                    port_group = "risky_port"
                else:
                    port_color = "#2196F3"  # Blue for safe ports
                    port_group = "port"
                
                # Add port node with combined label, risk-based color, and description
                self.add_node(
                    node_id=port_id,
                    label=port_label,
                    group=port_group,
                    color=port_color,
                    size=10,  # Slightly larger since they now contain service info
                    description=port_description,
                    port=port  # Add port number directly for JavaScript access
                )
                
                # Link host to port (no service nodes needed)
                self.add_link(host, port_id, weight=2, color="#FFFF00")
        
        # Add network topology (CIDR class A, B, C networks)
        network_hierarchy = {}
        
        for host in scan_results.keys():
            # Extract IP from display name (format: "IP-hostname" or just "IP")
            if '-' in host:
                ip_address = host.split('-')[0]
            else:
                ip_address = host
            
            # Parse IP address for network hierarchy
            ip_parts = ip_address.split('.')
            if len(ip_parts) == 4:
                # Class A network (e.g., "192")
                class_a = ip_parts[0]
                # Class B network (e.g., "192.168")
                class_b = f"{ip_parts[0]}.{ip_parts[1]}"
                # Class C network (e.g., "192.168.1.0/24")
                class_c = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                
                # Store hierarchy
                if class_a not in network_hierarchy:
                    network_hierarchy[class_a] = {"class_b": set(), "class_c": set(), "hosts": set()}
                
                network_hierarchy[class_a]["class_b"].add(class_b)
                network_hierarchy[class_a]["class_c"].add(class_c)
                network_hierarchy[class_a]["hosts"].add(host)
        
        # Create network nodes and links
        for class_a, data in network_hierarchy.items():
            # Add Class A network node
            class_a_id = f"network::class_a::{class_a}"
            self.add_node(
                node_id=class_a_id,
                label=f"Network {class_a}.x.x.x",
                group="network_a",
                color="#607D8B",  # Blue-grey for Class A
                size=18
            )
            
            for class_b in data["class_b"]:
                # Add Class B network node
                class_b_id = f"network::class_b::{class_b}"
                self.add_node(
                    node_id=class_b_id,
                    label=f"Network {class_b}.x.x",
                    group="network_b", 
                    color="#795548",  # Brown for Class B
                    size=16
                )
                
                # Link Class A to Class B
                self.add_link(class_a_id, class_b_id, weight=3, color="#FFFF00")
            
            for class_c in data["class_c"]:
                # Add Class C network node
                class_c_id = f"network::class_c::{class_c}"
                self.add_node(
                    node_id=class_c_id,
                    label=class_c,
                    group="network_c",
                    color="#8BC34A",  # Light green for Class C
                    size=14
                )
                
                # Find corresponding Class B for this Class C
                class_c_prefix = '.'.join(class_c.split('.')[:2])
                class_b_id = f"network::class_b::{class_c_prefix}"
                
                # Link Class B to Class C
                self.add_link(class_b_id, class_c_id, weight=2, color="#FFFF00")
            
            # Link hosts to their Class C network
            for host in data["hosts"]:
                host_ip = host.split('-')[0] if '-' in host else host
                ip_parts = host_ip.split('.')
                if len(ip_parts) == 4:
                    host_class_c = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                    class_c_id = f"network::class_c::{host_class_c}"
                    
                    # Link Class C to host
                    self.add_link(class_c_id, host, weight=2, color="#FFFF00")
        
        # Handle share enumeration
        for host, shares in share_results.items():
            if shares:
                # Create a shares node for this host
                shares_node_id = f"{host}::Shares"
                self.add_node(
                    node_id=shares_node_id,
                    label=f"{host.split('-')[0]}-Shares",  # Clean label
                    group="shares",
                    color="#8B0000",  # Dark red for shares container
                    size=10
                )
                
                # Link host to shares node
                self.add_link(host, shares_node_id, weight=2, color="#FFFF00")
                
                # Add individual share nodes
                for share in shares:
                    share_node_id = f"{host}::share::{share}"
                    self.add_node(
                        node_id=share_node_id,
                        label=f"Share: {share}",
                        group="share",
                        color="#B71C1C",  # Dark red for individual shares
                        size=6
                    )
                    
                    # Link shares node to individual share
                    self.add_link(shares_node_id, share_node_id, weight=1, color="#FFFF00")
    
    def generate_html(self, title: str = "Network Topology", width: int = 1200, height: int = 800):
        """
        Generate the complete HTML with embedded D3.js force-directed graph.
        """
        
        # Convert data to JSON
        nodes_json = json.dumps(self.nodes, indent=2)
        links_json = json.dumps(self.links, indent=2)
        port_descriptions_json = json.dumps(PORT_DESCRIPTIONS, indent=2)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            margin: 0;
            padding: 0;
            background: radial-gradient(circle at center, #1a237e 0%, #0d1421 50%, #000000 100%);
            font-family: 'Arial', sans-serif;
            color: white;
            overflow: hidden;
        }}
        
        .graph-container {{
            width: 100vw;
            height: 100vh;
            position: relative;
        }}
        
        .controls {{
            position: absolute;
            top: 10px;
            left: 10px;
            z-index: 1000;
            background: rgba(0, 0, 0, 0.8);
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
        }}
        
        .info-panel {{
            position: absolute;
            top: 10px;
            right: 10px;
            z-index: 1000;
            background: rgba(0, 0, 0, 0.8);
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
            max-width: 300px;
        }}
        
        .node {{
            cursor: move;
            stroke: #fff;
            stroke-width: 1.5px;
        }}
        
        .node:hover {{
            stroke: #FFD700;
            stroke-width: 3px;
        }}
        
        .link {{
            stroke: #FFFF00 !important;
            stroke-width: 2px !important;
            opacity: 0.8 !important;
            fill: none !important;
        }}
        
        .node-label {{
            font-size: 10px;
            font-weight: bold;
            fill: white;
            text-anchor: start;
            pointer-events: none;
            text-shadow: 
                -1px -1px 0 #000,
                1px -1px 0 #000,
                -1px 1px 0 #000,
                1px 1px 0 #000,
                0px 0px 3px rgba(0,0,0,0.9);
            stroke: #000;
            stroke-width: 0.5px;
            paint-order: stroke fill;
        }}
        
        .legend {{
            position: absolute;
            bottom: 10px;
            left: 10px;
            background: rgba(0, 0, 0, 0.8);
            padding: 10px;
            border-radius: 5px;
            font-size: 11px;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            margin: 2px 0;
        }}
        
        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 5px;
        }}
        
        .share-node {{
            cursor: pointer !important;
        }}
        
        .share-node:hover {{
            stroke-width: 3px !important;
            filter: brightness(1.2);
        }}
        
        /* Security risk styling */
        .high-risk {{
            color: #FF4444 !important;
            font-weight: bold;
        }}
        
        .medium-risk {{
            color: #FFA500 !important;
            font-weight: bold;
        }}
        
        .secure {{
            color: #4CAF50 !important;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="graph-container">
        <div class="controls">
            <div><strong>🎮 Controls</strong></div>
            <div>• Drag nodes to move them</div>
            <div>• Scroll to zoom</div>
            <div>• Nodes stick where dragged</div>
            <div>• Click port nodes to see descriptions</div>
            <div>• Double-click non-share nodes to release</div>
            <div>• Double-click share nodes to open in Explorer</div>
        </div>
        
        <div class="info-panel">
            <div><strong>📊 Network Graph</strong></div>
            <div id="node-count">Nodes: {len(self.nodes)}</div>
            <div id="link-count">Links: {len(self.links)}</div>
            <div id="selected-info"></div>
        </div>
        
        <div class="legend">
            <div><strong>🎯 Legend</strong></div>
            <div class="legend-item">
                <div class="legend-color" style="background: #607D8B;"></div>
                <span>Class A Networks</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #795548;"></div>
                <span>Class B Networks</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #8BC34A;"></div>
                <span>Class C Networks</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #4CAF50;"></div>
                <span>Hosts</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #F44336;"></div>
                <span>⚠️ Risky Ports (FTP, RDP, DBs, etc.)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #2196F3;"></div>
                <span>Safe Ports (HTTP, HTTPS, SSH, etc.)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #8B0000;"></div>
                <span>Shares Container</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #B71C1C;"></div>
                <span>Individual Shares (double-click to open)</span>
            </div>
            <div style="margin-top: 10px; font-size: 10px; color: #ccc;">
                💡 Double-click share nodes to open in File Explorer<br>
                🔒 Red ports indicate high security risk
            </div>
        </div>
        
        <svg id="graph-svg"></svg>
    </div>

    <script>
        // Data
        const nodes = {nodes_json};
        const links = {links_json};
        const portDescriptions = {port_descriptions_json};
        
        console.log("🎯 Loading custom D3 force-directed graph...");
        console.log("📊 Nodes:", nodes.length, "Links:", links.length);
        
        // Set up SVG
        const width = window.innerWidth;
        const height = window.innerHeight;
        
        const svg = d3.select("#graph-svg")
            .attr("width", width)
            .attr("height", height);
        
        // Add zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on("zoom", function(event) {{
                container.attr("transform", event.transform);
            }});
        
        // Disable double-click zoom behavior, apply zoom to SVG
        svg.call(zoom).on("dblclick.zoom", null);
        
        // Container for zoomable content
        const container = svg.append("g");
        
        // Set up force simulation
        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).id(d => d.id).distance(100).strength(0.5))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(d => d.size + 5));
        
        // Create links
        const link = container.append("g")
            .attr("class", "links")
            .selectAll("line")
            .data(links)
            .enter().append("line")
            .attr("class", "link")
            .style("stroke", d => d.color || "#FFFF00")
            .style("stroke-width", d => Math.sqrt(d.weight) * 2)
            .style("opacity", 0.8);
        
        // Create nodes with different shapes for different types
        const nodeContainer = container.append("g").attr("class", "nodes");
        
        // Separate network nodes (SVG icons), host nodes (PNG icons), and other nodes (circles)
        const networkNodes = nodes.filter(d => d.group.startsWith("network"));
        const hostNodes = nodes.filter(d => d.group === "host");
        const otherNodes = nodes.filter(d => !d.group.startsWith("network") && d.group !== "host");
        
        // Create SVG icon nodes for network types
        const networkNodeElements = nodeContainer.selectAll(".network-node")
            .data(networkNodes)
            .enter().append("g")
            .attr("class", "network-node node")
            .style("cursor", "default")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));
        
        // Add invisible circle for better click area
        networkNodeElements.append("circle")
            .attr("r", d => d.size * 1.5) // Larger hit area than visual size
            .style("fill", "transparent")
            .style("stroke", "none")
            .style("pointer-events", "all"); // Ensure it captures click events

        // Add SVG icon for network nodes
        networkNodeElements.append("path")
            .attr("d", "M512.941,515.189c-11.311,0-21.43,3.572-29.169,10.12L369.478,412.207c8.93-10.12,16.073-21.43,20.24-34.526l76.195-5.357c8.334,14.287,23.812,23.811,41.074,23.811c26.192,0,47.623-21.43,47.623-47.623c0-26.192-21.431-47.622-47.623-47.622s-47.622,21.43-47.622,47.622c0,4.167,0.596,8.334,1.786,11.906l-68.457,4.762c1.19-5.357,1.785-11.31,1.785-16.668c0-46.432-32.74-84.53-76.791-93.459l-5.357-80.958c19.645-5.953,33.931-23.811,33.931-45.836c0-26.192-21.43-47.623-47.622-47.623s-47.622,21.43-47.622,47.623s21.43,47.622,47.622,47.622c0.596,0,1.19,0,1.786,0l4.762,77.982c-2.381,0-4.167-0.595-6.548-0.595c-23.216,0-44.051,8.334-60.719,22.025L121.842,157.427c6.548-8.334,10.119-18.454,10.119-29.169c0-26.192-21.43-47.623-47.622-47.623s-47.622,21.43-47.622,47.623s21.43,47.623,47.622,47.623c10.715,0,20.835-3.572,29.169-10.12l116.079,117.271c-16.072,17.263-26.191,39.884-26.191,65.48c0,23.812,8.929,45.837,23.216,62.504L112.912,524.715c-7.738-5.953-17.858-9.525-28.573-9.525c-26.192,0-47.622,21.431-47.622,47.623s21.43,47.622,47.622,47.622s47.622-21.43,47.622-47.622c0-11.311-4.166-22.025-10.715-29.764L234.946,419.35c16.667,15.478,39.288,24.406,63.694,24.406c23.812,0,45.837-8.929,62.505-23.215l114.293,113.103c-5.952,8.334-10.119,17.858-10.119,29.169c0,26.192,21.43,47.622,47.622,47.622s47.622-21.43,47.622-47.622S539.133,515.189,512.941,515.189z M506.988,312.795c19.645,0,35.717,16.072,35.717,35.716c0,19.645-16.072,35.717-35.717,35.717c-19.644,0-35.717-16.073-35.717-35.717C471.271,328.867,487.344,312.795,506.988,312.795z M262.923,128.258c0-19.645,16.073-35.717,35.717-35.717c19.645,0,35.717,16.072,35.717,35.717c0,19.644-16.072,35.717-35.717,35.717C278.996,163.975,262.923,147.902,262.923,128.258z M48.622,128.258c0-19.645,16.072-35.717,35.717-35.717s35.717,16.072,35.717,35.717c0,19.644-16.072,35.717-35.717,35.717S48.622,147.902,48.622,128.258z M84.339,598.529c-19.645,0-35.717-16.072-35.717-35.717s16.072-35.717,35.717-35.717s35.717,16.072,35.717,35.717S103.984,598.529,84.339,598.529z M215.301,348.511c0-45.836,37.503-83.339,83.339-83.339c45.837,0,83.339,37.502,83.339,83.339c0,45.837-37.502,83.339-83.339,83.339C252.804,431.851,215.301,394.348,215.301,348.511z M512.941,598.529c-19.645,0-35.717-16.072-35.717-35.717s16.072-35.717,35.717-35.717s35.717,16.072,35.717,35.717S532.585,598.529,512.941,598.529z")
            .attr("fill", d => d.color || '#607D8B')
            .attr("transform", d => `scale(0.05) translate(-300, -350)`) // Scale down and center the icon
            .style("stroke", "#fff")
            .style("stroke-width", 2)
            .style("pointer-events", "none"); // Let the invisible circle handle clicks
        
        // Create host nodes (using PNG icons)
        const hostNodeElements = nodeContainer.selectAll(".host-node")
            .data(hostNodes)
            .enter().append("g")
            .attr("class", "host-node node")
            .style("cursor", "pointer")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));
        
        // Add invisible circle for better click area on host nodes
        hostNodeElements.append("circle")
            .attr("r", d => d.size * 1.5) // Larger hit area than visual size
            .style("fill", "transparent")
            .style("stroke", "none")
            .style("pointer-events", "all"); // Ensure it captures click events

        // Add white background circle for host icons
        hostNodeElements.append("circle")
            .attr("r", d => d.size * 1.1) // Slightly larger than the icon
            .style("fill", "white")
            .style("stroke", "#ccc")
            .style("stroke-width", 1)
            .style("pointer-events", "none");

        // Add PNG icon for host nodes
        hostNodeElements.append("image")
            .attr("href", "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAAXNSR0IB2cksfwAAAARnQU1BAACxjwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAAlwSFlzAAAuIwAALiMBeKU/dgAAAAd0SU1FB+kLBhIeEHlw1oIAAAIESURBVHja7ddPbtNQEAbwb17cpNmitGkcJ0RdIJZQKnGCKluknoADAL0Lt0CABKzoHSqQWLBMgpuQNGFHaf7YMywCu6hFtR1c+H5ydtZo5nvv2Q5ARERERERERPSfkTSLVWr+ripuZdasCJxz38aDsJOrAOqt3fosmr81kb2UM13dtNlJecM7DDudXtJaXhoNLaLoNeD2nAGx6g+YaUZboOCcKwPy4GKxeAHg4V/fAX5Qr82lMIAZxPTRuN9/k+Xq1263DhexvoQAJbNa/zQcJqnnkjY0iyLfYDA1zXp4APja676KTRUGTBfzetJ6DjeQqKVW60YGkCYGwAAYAANgAAyAATAABsAAGMB1GSCy5q4lPwFsFktdmEGcc1uNxtODdjvTXVUNgidOnAOAUqkYJv5nmUZT283msaodAPL7yozCAAi8ghyPur120nqFNJryypvvi553B8Dd5firfsvTcuWKiPy6bXUdAeDU3sWL6eOL7+fnudgBf6oSND8AuHd5APg4Dr/c/yffAgZEV99j0Tp78tYagEWf1C4f0Il8XmdPqR+BatDcUbNnKtJMs3gB0jWNn58NToe5DWDL97fheSemCDJZLZHQ5tP9yWh0ls9ngLijrIZfHiFrwNs4yu1D0OB21vAVWM3tEajV/dYMWsl0/tgmk+GoCyIiIiIiIiIiup6fNVaqDe59VwsAAAAASUVORK5CYII=")
            .attr("width", d => d.size * 2)
            .attr("height", d => d.size * 2)
            .attr("x", d => -d.size)
            .attr("y", d => -d.size)
            .style("pointer-events", "none"); // Let the invisible circle handle clicks
        
        // Create circle nodes for all other types
        const otherNodeElements = nodeContainer.selectAll(".circle-node")
            .data(otherNodes)
            .enter().append("circle")
            .attr("class", d => d.group === "share" ? "node share-node circle-node" : "node circle-node")
            .attr("r", d => d.size)
            .style("fill", d => d.color || "#69b3a2")
            .style("cursor", d => d.group === "share" ? "pointer" : "default")
            .style("stroke", d => d.group === "share" ? "#fff" : "none")
            .style("stroke-width", d => d.group === "share" ? "2px" : "0")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));
        
        // Combine all node types for unified operations
        const allNodeElements = d3.selectAll(".node");
        
        // Track collapsed state for each node
        const collapsedNodes = new Set();
        
        // Function to get child nodes of a given node
        function getChildNodes(nodeId) {{
            return links.filter(l => l.source.id === nodeId).map(l => l.target.id);
        }}
        
        // Function to get all descendant nodes recursively
        function getAllDescendants(nodeId, visited = new Set()) {{
            if (visited.has(nodeId)) return [];
            visited.add(nodeId);
            
            const children = getChildNodes(nodeId);
            let descendants = [...children];
            
            children.forEach(childId => {{
                descendants = descendants.concat(getAllDescendants(childId, visited));
            }});
            
            return [...new Set(descendants)]; // Remove duplicates
        }}
        
        // Function to toggle node collapse/expand
        function toggleNodeCollapse(nodeId) {{
            const descendants = getAllDescendants(nodeId);
            
            if (collapsedNodes.has(nodeId)) {{
                // Expand: remove from collapsed set and show descendants
                collapsedNodes.delete(nodeId);
                
                descendants.forEach(descId => {{
                    // Show descendant nodes
                    d3.selectAll(".node").filter(d => d.id === descId)
                        .style("display", "block");
                    
                    // Show descendant labels
                    d3.selectAll(".node-label").filter(d => d.id === descId)
                        .style("display", "block");
                    
                    // Show edges connected to descendants
                    d3.selectAll(".link").filter(d => 
                        d.source.id === descId || d.target.id === descId ||
                        (d.source.id === nodeId && descendants.includes(d.target.id))
                    ).style("display", "block");
                }});
                
            }} else {{
                // Collapse: add to collapsed set and hide descendants
                collapsedNodes.add(nodeId);
                
                descendants.forEach(descId => {{
                    // Hide descendant nodes
                    d3.selectAll(".node").filter(d => d.id === descId)
                        .style("display", "none");
                    
                    // Hide descendant labels
                    d3.selectAll(".node-label").filter(d => d.id === descId)
                        .style("display", "none");
                    
                    // Hide edges connected to descendants
                    d3.selectAll(".link").filter(d => 
                        d.source.id === descId || d.target.id === descId ||
                        (d.source.id === nodeId && descendants.includes(d.target.id))
                    ).style("display", "none");
                }});
            }}
            
            // Restart simulation to adjust layout
            simulation.alpha(0.3).restart();
        }}
        
        // Add labels
        const labels = container.append("g")
            .attr("class", "labels")
            .selectAll("text")
            .data(nodes)
            .enter().append("text")
            .attr("class", "node-label")
            .text(d => d.label)
            .style("font-size", d => Math.max(8, d.size * 0.7) + "px");
        
        // Add click handlers
        allNodeElements.on("click", function(event, d) {{
            const info = document.getElementById("selected-info");
            let infoHtml = `<strong>Selected:</strong><br>` +
                          `ID: ${{d.id}}<br>` +
                          `Type: ${{d.group}}<br>` +
                          `Label: ${{d.label}}`;
            
            // Enhanced port information for port nodes
            if ((d.group === "port" || d.group === "risky_port") && d.description) {{
                // Get port number from node data (direct property or parse from ID)
                const portNumber = d.port || d.id.split("::")[1]; // Use direct port property or extract from ID
                const portInfo = getPortDetails(parseInt(portNumber));
                
                const securityClass = portInfo.security.includes('HIGH RISK') ? 'high-risk' :
                                     portInfo.security.includes('SECURE') ? 'secure' : 'medium-risk';
                
                infoHtml += `<br><br><strong>🔌 Port ${{portNumber}} Details:</strong><br>` +
                           `<span style="color: #4CAF50; font-weight: bold;">${{portInfo.description}}</span><br><br>` +
                           `<strong>Service Details:</strong><br>` +
                           `<span style="color: #BBB;">${{portInfo.details}}</span><br><br>` +
                           `<strong>Security Assessment:</strong><br>` +
                           `<span class="${{securityClass}}" style="font-weight: bold;">${{portInfo.security}}</span><br><br>` +
                           `<strong>Learn More:</strong><br>` +
                           `<a href="${{portInfo.link}}" target="_blank" rel="noopener" style="color: #4CAF50;">📖 Documentation</a>`;
            }}
            
            info.innerHTML = infoHtml;
        }});
        
        // JavaScript function to get port details (mirrors Python function)
        function getPortDetails(port) {{
            const portInfo = portDescriptions[port];
            if (portInfo && typeof portInfo === 'object') {{
                return portInfo;
            }}
            
            return {{
                "description": `Port ${{port}} - Unknown/Custom application`,
                "details": "No detailed information available for this port.",
                "security": "UNKNOWN",
                "link": "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers"
            }};
        }}
        
        // Add double-click handler for share nodes
        allNodeElements.on("dblclick", function(event, d) {{
            event.stopPropagation(); // Prevent zoom behavior
            
            if (d.group === "share") {{
                // Extract IP and share name from share node
                const parts = d.id.split("::");
                if (parts.length >= 3 && parts[1] === "share") {{
                    const hostPart = parts[0];
                    const shareName = parts[2];
                    
                    // Extract IP from host (handle IP-hostname format)
                    let ip = hostPart;
                    if (hostPart.includes('-')) {{
                        ip = hostPart.split('-')[0];
                    }}
                    
                    // Construct UNC path
                    const uncPath = `\\\\\\\\${{ip}}\\\\${{shareName}}`;
                    
                    // Try to open in file explorer
                    try {{
                        // For Windows, use file:// protocol with UNC path
                        window.open(`file://${{uncPath}}`, '_blank');
                        
                        // Also try alternative method
                        const link = document.createElement('a');
                        link.href = `file://${{uncPath}}`;
                        link.target = '_blank';
                        link.click();
                        
                    }} catch (error) {{
                        // Fallback: show path for manual access
                        const result = prompt(`Double-clicked share: ${{shareName}}\\n\\nUNC Path (copy to File Explorer):`, uncPath);
                        if (result !== null) {{
                            // Try to copy to clipboard if possible
                            if (navigator.clipboard) {{
                                navigator.clipboard.writeText(uncPath).then(() => {{
                                    alert('UNC path copied to clipboard!');
                                }}).catch(() => {{
                                    console.log('Could not copy to clipboard');
                                }});
                            }}
                        }}
                    }}
                }}
            }} else {{
                // For non-share nodes, release the fixed position
                d.fx = null;
                d.fy = null;
                simulation.alpha(0.3).restart();
            }}
        }});

        // Add right-click handlers for collapse/expand functionality
        allNodeElements.on("contextmenu", function(event, d) {{
            event.preventDefault(); // Prevent browser context menu
            toggleNodeCollapse(d.id);
        }});
        
        // Update positions on each tick
        simulation.on("tick", function() {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            // Update circle nodes
            d3.selectAll(".circle-node")
                .attr("cx", d => d.x)
                .attr("cy", d => d.y);
            
            // Update SVG network nodes
            d3.selectAll(".network-node")
                .attr("transform", d => `translate(${{d.x}},${{d.y}})`);
            
            // Update PNG host nodes
            d3.selectAll(".host-node")
                .attr("transform", d => `translate(${{d.x}},${{d.y}})`);
            
            labels
                .attr("x", d => d.x + d.size + 5)
                .attr("y", d => d.y + 3);
        }});
        
        // Drag functions with sticky behavior
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}
        
        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}
        
        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            // Keep nodes sticky - don't reset fx and fy
        }}
        
        // Ensure yellow edges are maintained
        function enforceYellowEdges() {{
            d3.selectAll(".link")
                .style("stroke", "#FFFF00")
                .style("stroke-width", "2px")
                .style("opacity", "0.8");
        }}
        
        // Run yellow edge enforcement periodically
        setInterval(enforceYellowEdges, 1000);
        
        // Handle window resize
        window.addEventListener('resize', function() {{
            const newWidth = window.innerWidth;
            const newHeight = window.innerHeight;
            
            svg.attr("width", newWidth).attr("height", newHeight);
            simulation.force("center", d3.forceCenter(newWidth / 2, newHeight / 2));
            simulation.alpha(0.3).restart();
        }});
        
        console.log("✅ Custom D3 force-directed graph loaded successfully!");
        console.log("🟡 Yellow edges enforced automatically");
        console.log("📌 Sticky node behavior enabled");
    </script>
</body>
</html>
        """
        
        return html_content
    
    def save_and_show(self, filename: str = "custom_network_graph.html", auto_open: bool = True):
        """
        Save the HTML file and optionally open it in the browser.
        """
        html_content = self.generate_html()
        
        # Save to file
        filepath = os.path.abspath(filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Custom D3 force-directed graph saved to: {filepath}")
        print(f"📊 Graph contains {len(self.nodes)} nodes and {len(self.links)} links")
        print(f"🟡 All edges are bright yellow with 2px width")
        print(f"📌 Sticky node behavior: drag nodes to move them permanently")
        
        if auto_open:
            try:
                webbrowser.open(f"file://{filepath}")
                print("🌐 Graph opened in browser!")
            except Exception as e:
                print(f"⚠️ Could not auto-open browser: {e}")
                print(f"📂 Manually open: {filepath}")
        
        return filepath

def create_custom_graph_from_scan(scan_results: Dict[str, List[int]], share_results: Dict[str, List[str]] = None):
    """
    Helper function to create a custom D3 graph from scan results.
    """
    graph = CustomD3ForceGraph()
    graph.generate_from_scan_results(scan_results, share_results)
    return graph

# Example usage
if __name__ == "__main__":
    # Test with sample data
    test_results = {
        "192.168.1.10-server": [80, 443, 22, 3389],
        "192.168.1.20-database": [3306, 1433, 5432],
        "192.168.1.30-fileserver": [445, 139, 21]
    }
    
    test_shares = {
        "192.168.1.30-fileserver": ["BACKUP", "PUBLIC", "SHARED"]
    }
    
    print("🎨 Creating custom D3.js force-directed graph...")
    graph = create_custom_graph_from_scan(test_results, test_shares)
    graph.save_and_show("test_custom_graph.html")