# 🌐 Network Vector

**Advanced Network Topology Scanner with Interactive D3.js Visualization**

Network Vector is a powerful, Python-based network scanning tool that performs comprehensive TCP port discovery, optional UDP probing, and network discovery without relying on external tools like nmap or masscan. It creates beautiful, interactive D3.js visualizations to map network topology and security posture.

## 🎥 See Network Vector in Action

[![Network Vector Demo](https://img.youtube.com/vi/JDTW9TA8Odg/maxresdefault.jpg)](https://youtu.be/JDTW9TA8Odg)

*Click the image above to watch Network Vector scanning and visualizing enterprise networks*

![Network Vector Banner](https://img.shields.io/badge/Network-Vector-blue?style=for-the-badge&logo=network&logoColor=white)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

### 🚀 Core Capabilities
- **Ping Sweep Host Discovery** - ICMP ping sweep identifies live hosts before port scanning, dramatically reducing wasted connections on dead IPs
- **Raw TCP Port Scanning** - Scans 750 unique ports without external dependencies
- **UDP Service Probing** - Optional UDP scanning with service-aware payloads for DNS, NTP, SNMP, SSDP, SIP, mDNS, LLMNR, CoAP, IPMI, memcached, and more
- **Automation JSON Reports** - Writes structured JSON reports by default for dashboards, deltas, and repeatable analysis
- **Executive Reporting** - Summarizes live hosts, TCP/UDP exposure, high-risk services, and top exposed hosts
- **Delta Reports** - Compare against a previous JSON scan to find new hosts, missing hosts, newly opened ports, closed ports, and changed OS guesses
- **Connection Semaphore** - Caps concurrent open sockets at 500 to prevent silent failures from OS file-descriptor exhaustion
- **Multi-threaded Performance** - Up to 1000 concurrent threads for fast scanning
- **Deep Scan (Dig)** - Scan all 65535 ports on every host that had at least one open port with `--dig`
- **All Ports Mode** - Scan all 65535 ports on the entire network with `--all-ports`
- **All UDP Mode** - Scan all 65535 UDP ports with `--all-udp` when you need exhaustive UDP coverage
- **Skip Discovery (-Pn)** - Treat all addresses as live and skip the ping sweep (useful when ICMP is filtered)
- **Live Log** - Print each port or host discovery to stdout in real-time with `--livelog`
- **Progress Indicator** - Real-time percentage progress shown during scanning
- **Live Mode** - Regenerate graphs in real-time as hosts are discovered with `--live`
- **Randomized Scanning** - Randomizes IP and port scan order for balanced network load
- **Configurable Delays** - Optional random delays between hosts for controlled scanning
- **Host Exemptions** - Exclude specific IPs or CIDRs from scanning with `--exempt`
- **Multi-CIDR Support** - Scan multiple networks in a single command with comma-separated targets
- **Network Topology Discovery** - Automatic CIDR-based network hierarchy visualization
- **Interactive D3.js Graphs** - Professional force-directed network visualizations
- **SMB Share Enumeration** - Cross-platform Windows/Linux share discovery
- **Hostname Resolution** - Automatic reverse DNS lookup for discovered hosts
- **Comprehensive OS Detection** - Advanced fingerprinting using 100+ port signatures
- **Host Categorization** - Visual host coloring based on detected operating systems

### 🎨 Visualization Features
- **2D Force-Directed Graph** - Interactive D3.js v7 network visualization
- **3D Force-Directed Graph** - Immersive 3D network topology using 3d-force-graph
- **Search & Navigation** - Find nodes by IP, hostname, or port with Previous/Next navigation
- **Glow Highlighting** - Light blue glow effect on search results and selected nodes
- **Click-to-Select** - Click any node to highlight with red label emphasis
- **Double-Click Zoom** - Double-click nodes to center and zoom the view
- **Host Tour Animation** - Play/Pause/Stop animated tour through all discovered hosts (3D)
- **Host Synopsis Panel** - View connected ports and shares when selecting a host
- **Dimming Effect** - Non-matching nodes dim during search for focus
- **Professional Network Icons** - SVG-based network topology representation
- **Host Icons** - PNG icons with embedded base64 encoding for self-contained HTML
- **Text Labels** - Floating labels for hosts and shares in 3D view
- **Color-coded Security** - Risk-based port classification (red=dangerous, blue=safe)
- **Interactive Port Information** - Click ports for detailed descriptions and security assessments
- **Sticky Node Behavior** - Drag-and-drop node positioning with persistence (2D)
- **Camera Controls** - Left-click rotate, right-click pan, scroll to zoom (3D)
- **Node Focus** - Double-click nodes to focus camera view (3D)
- **Collapsible UI Panels** - Hide/show Controls, Info Panel, and Legend to maximize graph space
- **Collapse/Expand** - Right-click network nodes to manage complexity (2D)
- **Self-contained Output** - HTML files with embedded assets, no external dependencies
- **Embedded Scan Data** - Complete scan results embedded in HTML with "Show Scan Data" button
- **Report View** - Open executive summaries, service groups, host profiles, and delta reports from generated HTML
- **JSON Loader** - Load a previous scan JSON in the HTML report to generate a browser-side comparison
- **CSV/JSON Data Export** - Download comprehensive scan data as CSV or structured JSON for automation

### 🔍 Port Intelligence
- **Comprehensive Database** - Detailed information for 130+ common services
- **Security Assessment** - Risk levels and vulnerability information for each port
- **Educational Links** - Direct links to service documentation and security resources
- **Service Detection** - Automatic identification of running services
- **Real-time Display** - Interactive port information on double-click

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- Windows, Linux, or macOS

### Option 1: Debian Package (Linux — Recommended)
```bash
# Download the .deb from the Releases tab
sudo dpkg -i networkvector_1.0.0_all.deb

# Run from anywhere
nvector 192.168.1.0/24
```

To uninstall:
```bash
sudo dpkg -r networkvector
```

### Option 2: Python Source
```bash
# Clone the repository
git clone https://github.com/artofscripting/networkvector.git
cd networkvector

# No dependencies required — uses only the Python standard library
python3 src/nvector.py 192.168.1.0/24
```

### Option 3: Pre-built Executable
```bash
# Download the latest executable from the Releases tab on GitHub
./nvector.exe 192.168.1.0/24
```

### Build Executable (Optional)
```bash
pip install pyinstaller
cd src
pyinstaller --onefile --add-data "custom_d3_graph.py;." --hidden-import=webbrowser --name="nvector" nvector.py
./dist/nvector 192.168.1.0/24
```

## 📖 Usage Examples

### Basic Scans
```bash
# Scan a single host
python3 src/nvector.py 192.168.1.100

# Scan an entire subnet (ping sweep runs first to find live hosts)
python3 src/nvector.py 192.168.1.0/24

# Skip ping sweep — treat all addresses as live (useful when ICMP is filtered)
python3 src/nvector.py 192.168.1.0/24 -Pn
```

### Discovery & Logging
```bash
# Print each discovered port and host to the terminal as scanning runs
python3 src/nvector.py 192.168.1.0/24 --livelog

# Combine with -Pn for environments where ping is blocked
python3 src/nvector.py 192.168.1.0/24 -Pn --livelog

# Pipe live discoveries to a log file
python3 src/nvector.py 192.168.1.0/24 --livelog | tee scan.log
```

### Deep Scanning
```bash
# Deep scan — after initial pass, scan all 65535 ports on any host with open ports
python3 src/nvector.py 192.168.1.0/24 --dig

# Scan all 65535 ports on the entire subnet (slow but thorough)
python3 src/nvector.py 192.168.1.0/24 --all-ports

# Custom port list
python3 src/nvector.py 192.168.1.0/24 --ports 22 80 443 3389 5432
```

### UDP Scanning
```bash
# Add common UDP service probing to the normal TCP scan
python3 src/nvector.py 192.168.1.0/24 --udp

# Probe specific UDP ports only
python3 src/nvector.py 192.168.1.0/24 --udp-ports 53 123 161 1900 5353

# Exhaustive UDP scan across all 65535 UDP ports (very slow/noisy)
python3 src/nvector.py 192.168.1.0/24 --all-udp

# Combine TCP and UDP full scans for a single host
python3 src/nvector.py 192.168.1.100 --all-ports --all-udp
```

UDP scanning uses service-aware payloads for common protocols, including DNS, TFTP, rpcbind, NTP, NetBIOS, SNMP, CLDAP, SLP, IKE, RIP, IPMI, SQL Browser, SSDP, WS-Discovery, SIP, NAT-PMP, mDNS, LLMNR, CoAP, and memcached. Ports without a specific payload receive an empty datagram so closed ports can still be identified when the host returns ICMP port-unreachable.

UDP results may include:
- **open** — The service sent a UDP response.
- **open|filtered** — No response was received. The port may be open, silently filtered, or dropped by a firewall.

### Visualization
```bash
# Generate both 2D and 3D visualizations
python3 src/nvector.py 192.168.1.0/24 --3d

# Live mode — graphs regenerate in real-time as hosts are found
python3 src/nvector.py 192.168.1.0/24 --live --3d

# Export to CSV only, no graph
python3 src/nvector.py 192.168.1.0/24 --no-graph
```

### Reporting & Automation
```bash
# JSON reports are written by default
python3 src/nvector.py 192.168.1.0/24

# Disable JSON output
python3 src/nvector.py 192.168.1.0/24 --no-json

# Compare current results against a previous JSON report
python3 src/nvector.py 192.168.1.0/24 --compare-json network_scan_20260628_120000.json
```

Generated HTML reports include a Report button for executive summaries, service groups, host profiles, and delta reports. Use the JSON file picker in the HTML report to load an older scan and generate a browser-side comparison summary.

The report view includes:
- **Executive summary** - Live hosts, open TCP ports, confirmed UDP ports, UDP `open|filtered` counts, high-risk services, and top exposed hosts
- **Service groups** - Remote access, File sharing, Web/admin, Databases, Discovery/broadcast, VPN/auth, Printers/IoT, and Other
- **Host profiles** - Hostname/IP, OS guess, TCP ports, UDP ports, SMB shares, risk level, service count, and notes
- **Delta report** - New hosts, missing hosts, newly opened ports, closed ports, and changed OS guesses

### Multi-Network & Advanced
```bash
# Scan multiple networks in one run
python3 src/nvector.py 192.168.1.0/24,10.0.0.0/24,172.16.0.0/24 --3d

# Exclude sensitive hosts or subnets
python3 src/nvector.py 192.168.1.0/24 --exempt 192.168.1.1,192.168.1.254
python3 src/nvector.py 10.0.0.0/16 --exempt 10.0.1.0/24,10.0.2.0/24

# Stealth scanning — randomize order and add delays
python3 src/nvector.py 192.168.1.0/24 --scan-delay 1.0 --threads 50

# Custom timeout for slow or high-latency networks
python3 src/nvector.py 192.168.1.0/24 --timeout 5.0

# Full-featured scan
python3 src/nvector.py 192.168.1.0/24 --3d --livelog --dig --timeout 2.0
```

## 🎯 Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | IP, CIDR, or comma-separated CIDRs to scan | Required |
| `--timeout` | Connection timeout per port in seconds | `3.0` |
| `--threads` | Maximum concurrent scanning threads | `1000` |
| `--ports` | Custom port list to scan | Top 750 ports |
| `--all-ports` | Scan all 65535 ports on every address | Off |
| `--dig` | After initial pass, scan all 65535 ports on hosts with any open port | Off |
| `--udp` | Also scan the common UDP port set with service-aware probes | Off |
| `--udp-ports` | Custom UDP port list to scan; implies UDP scanning | None |
| `--all-udp` | Scan all 65535 UDP ports; very slow/noisy on large networks | Off |
| `--json` | Write a structured JSON report for automation | On |
| `--no-json` | Disable structured JSON report output | Off |
| `--compare-json` | Compare current scan to a previous JSON report | None |
| `-Pn` | Skip ping sweep — treat all addresses as live | Off |
| `--livelog` | Print a line to stdout for each discovered port and host | Off |
| `--live` | Regenerate graphs after each host is found (requires graphs) | Off |
| `--3d`, `--force-3d` | Generate an additional 3D force-directed graph | Off |
| `--no-graph` | Skip graph generation; export results to CSV instead | Off |
| `--no-resolve-hostnames` | Disable reverse DNS lookup | Off |
| `--no-enumerate-shares` | Disable SMB share enumeration | Off |
| `--no-randomize` | Disable randomized scan order | Off |
| `--scan-delay` | Max random delay between host scans (seconds) | `0.0` |
| `--exempt` | Comma-separated IPs or CIDRs to exclude | None |

## 🎯 3D Visualization

Network Vector supports immersive 3D network topology visualization using the 3d-force-graph library.

### Enable 3D Mode
```bash
python3 src/nvector.py 192.168.1.0/24 --3d
python3 src/nvector.py 192.168.1.0/24,10.0.0.0/24 --3d
```

### Controls (3D View)
- **Left-click + drag** — Rotate view
- **Right-click + drag** — Pan view
- **Scroll** — Zoom in/out
- **Click node** — Select and display node details
- **Double-click node** — Center and zoom to node
- **Play button** — Start host tour animation
- **Pause / Stop** — Control host tour
- **Alt+C** — Toggle Controls panel
- **Alt+I** — Toggle Info panel
- **Alt+L** — Toggle Legend
- **Alt+S** — Focus search box
- **Escape** — Clear search

## 📄 Output Format

### Interactive HTML (Default)
Network Vector generates self-contained HTML files with all assets embedded — no internet connection required to view them.

| File | Contents |
|------|----------|
| `network_scan_YYYYMMDD_HHMMSS.html` | 2D force-directed graph (always generated) |
| `network_scan_YYYYMMDD_HHMMSS_3d.html` | 3D force-directed graph (`--3d` flag) |

Both files include:
- Complete embedded scan data with "Show Scan Data" button
- In-browser Report button for executive and host-profile reporting
- In-browser CSV export button with TCP and UDP rows
- In-browser JSON export button for automation workflows
- Previous JSON file loader for browser-side delta comparisons
- Color-coded risk classification for ports
- OS detection results per host

### CSV Export (`--no-graph`)
When graph generation is skipped, results are written to `network_scan_YYYYMMDD_HHMMSS.csv` with separate rows for ports, SMB shares, and scan metadata — compatible with Excel, Google Sheets, and databases. CSV rows include protocol (`tcp`/`udp`), status/confidence, service category, and risk level.

CSV columns:
- `Type`
- `IP Address`
- `Hostname`
- `Protocol`
- `Port`
- `Service`
- `Category`
- `Risk Level`
- `Status`
- `Confidence`
- `SMB Share`
- `OS Detection`
- `Response Time`
- `Notes`

### JSON Report
JSON reports are written by default to `network_scan_YYYYMMDD_HHMMSS.json`. The structured report includes:
- Executive summary
- Host profiles
- TCP and UDP service rows
- Service grouping categories
- Raw scan data
- Delta report data when `--compare-json` is used

Top-level JSON keys:
- `schema_version`
- `scan_info`
- `executive_summary`
- `host_profiles`
- `service_rows`
- `service_categories`
- `raw`
- `delta_report` when comparing with `--compare-json`

### Delta Reports
Delta reports can be generated two ways:
- CLI: run with `--compare-json previous_scan.json`
- HTML: open a generated report, choose a previous JSON file with the file picker, then open the Report view

Delta output highlights:
- New hosts
- Missing hosts
- Newly opened ports
- Closed ports
- Changed OS guesses

### Service Categories
Network Vector assigns each discovered service to a reporting category:
- **Remote access** - SSH, Telnet, RDP, VNC, WinRM, X11
- **File sharing** - FTP, TFTP, SMB, NetBIOS, NFS, AFP, rsync
- **Web/admin** - HTTP, HTTPS, CUPS, alternate web ports, admin consoles
- **Databases** - SQL Server, Oracle, MySQL, PostgreSQL, Redis, Elasticsearch, memcached
- **Discovery/broadcast** - DNS, DHCP, NTP, SNMP, SSDP, WS-Discovery, mDNS, LLMNR
- **VPN/auth** - TACACS, Kerberos, LDAP, IPsec/IKE, RADIUS, SIP
- **Printers/IoT** - LPD, IPP, IPMI, JetDirect, BACnet, CoAP
- **Other** - Services that do not match a known reporting group

### Live Log (`--livelog`)
Each discovery prints immediately to stdout:
```
[LIVELOG] PORT OPEN  192.168.1.5:22   (12ms)
[LIVELOG] PORT OPEN  192.168.1.5:443  (8ms)
[LIVELOG] HOST FOUND 192.168.1.5  2 open port(s): [22, 443]
```

## 🔧 Technical Details

### Architecture
- **Pure Python** — No external scanning tools required; standard library only
- **Ping Sweep First** — ICMP ping discovers live hosts before port scanning to avoid wasting connections on dead IPs; falls back to scanning all addresses if ICMP is filtered
- **Socket Semaphore** — A global semaphore caps concurrent open sockets at 500, preventing the OS file-descriptor limit from silently dropping scan results
- **Multi-threaded Design** — Concurrent host and port scanning with coordinated thread pools
- **Modular Structure** — Separate scanning (`nvector.py`), visualization (`custom_d3_graph.py`), and port database (`port_descriptions.py`) components

### Port Coverage
Network Vector scans **750 unique ports** covering:
- **System Services** (1–1024): SSH, HTTP, HTTPS, FTP, Telnet, etc.
- **Database Ports** (1433, 3306, 5432, etc.): SQL Server, MySQL, PostgreSQL
- **Application Services** (8080, 9000, etc.): Web applications and APIs
- **Development Ports** (3000–4000): Node.js, Rails, Django applications
- **Enterprise Services** (389, 636, etc.): LDAP, Active Directory

### UDP Coverage
UDP scanning is optional and runs after the TCP phase against the same discovered/live host list. By default, `--udp` scans 101 common UDP ports. `--udp-ports` accepts an explicit list, and `--all-udp` expands the scan to ports 1-65535.

Network Vector includes active UDP payloads for 26 common services to improve detection accuracy. Some UDP protocols answer only to well-formed requests, while others stay silent even when open; this is why UDP output distinguishes confirmed `open` ports from `open|filtered` ports.

### Visualization Technology
- **D3.js v7** — Force-directed 2D graph
- **3d-force-graph v1.73.6** — Three.js-based 3D graph
- **SVG Rendering** — Scalable vector graphics for crisp visuals
- **Base64 Embedding** — Self-contained HTML with no external dependencies at runtime

## 🛡️ Security Considerations

Network Vector performs TCP scanning and optional UDP probing, both of which generate network traffic. Use responsibly:

- Only scan networks you own or have explicit permission to test
- Use `--exempt` to exclude sensitive or critical hosts
- Use `--scan-delay` and lower `--threads` for gentler scanning
- Use `-Pn` only when you know hosts are live — it skips discovery and port-scans every address
- Use `--all-udp` carefully; exhaustive UDP scans can be slow, noisy, and more likely to trigger monitoring systems

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Development Setup
```bash
git clone https://github.com/yourusername/networkvector.git
cd networkvector
git checkout -b feature/your-feature
python3 src/nvector.py 127.0.0.1 --threads 10
```

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **D3.js Community** — For the incredible visualization framework
- **Python Community** — For the robust standard library that makes this possible
- **Network Security Community** — For inspiration and best practices

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/artofscripting/networkvector/issues)
- **Discussions**: [GitHub Discussions](https://github.com/artofscripting/networkvector/discussions)
- **Documentation**: [Project Wiki](https://github.com/artofscripting/networkvector/wiki)

---

**Network Vector** — Mapping networks, visualizing security, empowering defenders.

*Made with ❤️ by the ArtOfScripting community*
