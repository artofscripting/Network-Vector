#!/usr/bin/env python3
"""
Custom D3.js Force-Directed Graph Generator for Network Vector

Creates interactive network topology visualizations with D3.js v7.
Features include force simulation, node interactions, and enhanced UI.
"""

import json
import os
import tempfile
import webbrowser
from typing import Dict, List, Set, Any

# Import port descriptions database
import sys
import os
sys.path.append(os.path.dirname(__file__))
from port_descriptions import PORT_DESCRIPTIONS, get_port_description, get_port_security_level

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
    
    def generate_from_scan_results(self, scan_results: Dict[str, List[int]], share_results: Dict[str, List[str]] = None, host_details: Dict = None):
        """
        Generate graph data from port scan results.
        """
        share_results = share_results or {}
        host_details = host_details or {}
        
        # Clear existing data
        self.nodes = []
        self.links = []
        
        # Function to get OS-based colors
        def get_os_color(host_key):
            host_detail = host_details.get(host_key, {})
            os_detection = host_detail.get('os_detection', {})
            os_name = os_detection.get('os', '').lower()
            
            if 'windows' in os_name:
                return "#0078D4"  # Microsoft Blue
            elif 'linux' in os_name or 'unix' in os_name:
                return "#FCC624"  # Linux Yellow/Orange
            elif 'macos' in os_name or 'mac os' in os_name:
                return "#9C27B0"  # Purple for macOS
            elif 'embedded' in os_name or 'iot' in os_name:
                return "#FF5722"  # Orange-Red for embedded/IoT
            else:
                return "#607D8B"  # Default Gray for Unknown/Other OS
        
        # Service mapping for individual ports - enhanced to use our comprehensive database
        def get_service_name(port):
            # First try our comprehensive database
            port_data = PORT_DESCRIPTIONS.get(port)
            if port_data and isinstance(port_data, dict):
                # Extract service name from description (get first part before " - ")
                description = port_data.get('description', f'Port {port}')
                service_name = description.split(" - ")[0] if " - " in description else description
                # Clean up common patterns to make shorter labels
                service_name = service_name.replace("Apple ", "").replace("Microsoft ", "MS ").replace("Windows ", "Win ")
                return service_name
            
            # Fallback to hardcoded common services for very basic mapping
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
            # Add host node with OS-based color
            host_color = get_os_color(host)
            self.add_node(
                node_id=host,
                label=host,
                group="host",
                color=host_color,  # OS-based color
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
    
    def generate_html(self, title: str = "Network Topology", width: int = 1200, height: int = 800, scan_data: Dict = None):
        """
        Generate the complete HTML with embedded D3.js force-directed graph and optional scan data.
        """
        
        # Convert data to JSON
        nodes_json = json.dumps(self.nodes, indent=2)
        links_json = json.dumps(self.links, indent=2)
        port_descriptions_json = json.dumps(PORT_DESCRIPTIONS, indent=2)
        
        # Embed scan data if provided
        scan_data_js = ""
        if scan_data:
            scan_data_json = json.dumps(scan_data, indent=2)
            scan_data_js = f"""
        // Embedded scan results for self-contained analysis
        window.SCAN_DATA = {scan_data_json};
        console.log('📊 Scan data embedded:', window.SCAN_DATA);"""
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
        
        /* Search styling */
        .search-container {{
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid #333;
        }}
        
        .search-input {{
            width: calc(100% - 30px);
            padding: 6px 10px;
            border: 1px solid #3949ab;
            border-radius: 4px;
            background: #1a237e;
            color: white;
            font-size: 12px;
            outline: none;
        }}
        
        .search-input:focus {{
            border-color: #7C4DFF;
            box-shadow: 0 0 5px rgba(124, 77, 255, 0.5);
        }}
        
        .search-input::placeholder {{
            color: #888;
        }}
        
        .search-results {{
            margin-top: 5px;
            font-size: 11px;
            color: #AAA;
        }}
        
        .clear-search {{
            background: #D32F2F;
            color: white;
            border: none;
            padding: 3px 8px;
            border-radius: 3px;
            cursor: pointer;
            margin-left: 5px;
            font-size: 11px;
        }}
        
        .clear-search:hover {{
            background: #F44336;
        }}
        
        .nav-buttons {{
            display: flex;
            gap: 5px;
            margin-top: 5px;
        }}
        
        .nav-btn {{
            background: #1976D2;
            color: white;
            border: 1px solid #2196F3;
            padding: 3px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 11px;
            flex: 1;
        }}
        
        .nav-btn:hover {{
            background: #2196F3;
        }}
        
        .nav-btn:disabled {{
            background: #555;
            border-color: #666;
            cursor: not-allowed;
            opacity: 0.5;
        }}
        
        .search-highlight {{
            stroke: #00BFFF !important;
            stroke-width: 4px !important;
            filter: drop-shadow(0 0 8px #00BFFF);
        }}
        
        .search-highlight-label {{
            fill: #00BFFF !important;
            font-weight: bold !important;
            text-shadow: 0 0 10px #00BFFF, 0 0 20px #00BFFF;
        }}
    </style>
</head>
<body>
    <div class="graph-container">
        <div class="controls">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <strong>🎮 Controls</strong>
                <button onclick="toggleControls()" style="background: #1a237e; color: white; border: 1px solid #3949ab; padding: 2px 6px; border-radius: 3px; cursor: pointer; font-size: 12px;" id="controls-toggle">📚 Hide</button>
            </div>
            <div id="controls-content">
                <div>• Drag nodes to move them</div>
                <div>• Scroll to zoom (1% - 1000%)</div>
                <div>• Nodes stick where dragged</div>
                <div>• Click port nodes to see descriptions</div>
                <div>• Double-click non-share nodes to release</div>
                <div>• Double-click share nodes to open in Explorer</div>
                <div>• Right-click network nodes to collapse/expand</div>
                <div style="margin-top: 8px; font-size: 11px; color: #AAA;">
                    <strong>Keyboard Shortcuts:</strong><br>
                    • Alt+C: Toggle Controls<br>
                    • Alt+I: Toggle Info Panel<br>
                    • Alt+L: Toggle Legend<br>
                    • Alt+S: Focus Search<br>
                    • Escape: Clear Search
                </div>
                <button onclick="showScanData()" style="margin-top: 10px; background: #1a237e; color: white; border: 1px solid #FFFF00; padding: 5px; border-radius: 3px; cursor: pointer;">📄 Show Scan Data</button>
                <button onclick="downloadCSV()" style="margin-top: 10px; margin-left: 5px; background: #388E3C; color: white; border: 1px solid #4CAF50; padding: 5px; border-radius: 3px; cursor: pointer;">📊 Download CSV</button>
                <div style="margin-top: 10px;">
                    <button onclick="zoomToFit()" style="background: #2E7D32; color: white; border: 1px solid #4CAF50; padding: 3px 6px; border-radius: 3px; cursor: pointer; margin-right: 5px;">🔍 Fit All</button>
                    <button onclick="zoomReset()" style="background: #1976D2; color: white; border: 1px solid #2196F3; padding: 3px 6px; border-radius: 3px; cursor: pointer; margin-right: 5px;">🎯 Reset</button>
                    <button onclick="zoomOut()" style="background: #D32F2F; color: white; border: 1px solid #F44336; padding: 3px 6px; border-radius: 3px; cursor: pointer; margin-right: 5px;">🔍− Out</button>
                    <button onclick="zoomIn()" style="background: #388E3C; color: white; border: 1px solid #4CAF50; padding: 3px 6px; border-radius: 3px; cursor: pointer;">🔍+ In</button>
                </div>
                <div class="search-container">
                    <strong>🔎 Search Graph</strong>
                    <div style="margin-top: 5px; display: flex; align-items: center;">
                        <input type="text" id="search-input" class="search-input" placeholder="Search nodes (IP, port, service...)" oninput="performSearch(this.value)" />
                        <button class="clear-search" onclick="clearSearch()">✕</button>
                    </div>
                    <div id="search-results" class="search-results"></div>
                    <div class="nav-buttons">
                        <button class="nav-btn" id="prev-btn" onclick="navigatePrev()" disabled>◀ Previous</button>
                        <button class="nav-btn" id="next-btn" onclick="navigateNext()" disabled>Next ▶</button>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="info-panel">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <strong>📊 Network Graph</strong>
                <button onclick="toggleInfoPanel()" style="background: #1a237e; color: white; border: 1px solid #3949ab; padding: 2px 6px; border-radius: 3px; cursor: pointer; font-size: 12px;" id="info-toggle">📚 Hide</button>
            </div>
            <div id="info-content">
                <div id="node-count">Nodes: {len(self.nodes)}</div>
                <div id="link-count">Links: {len(self.links)}</div>
                <div id="selected-info"></div>
            </div>
        </div>
        
        <div class="legend">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <strong>🎯 Legend</strong>
                <button onclick="toggleLegend()" style="background: #1a237e; color: white; border: 1px solid #3949ab; padding: 2px 6px; border-radius: 3px; cursor: pointer; font-size: 12px;" id="legend-toggle">📚 Hide</button>
            </div>
            <div id="legend-content">
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
                    <span>Network Classes</span>
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
                <hr style="border-color: #555; margin: 8px 0;">
                <div style="font-weight: bold; margin-bottom: 5px; color: #fff;">🖥️ Host OS Detection</div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #0078D4;"></div>
                    <span>Windows Systems</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #FCC624;"></div>
                    <span>Linux/Unix Systems</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #9C27B0;"></div>
                    <span>macOS Systems</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #FF5722;"></div>
                    <span>Embedded/IoT Devices</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #607D8B;"></div>
                    <span>Unknown/Other OS</span>
                </div>
                <hr style="border-color: #555; margin: 8px 0;">
                <div class="legend-item">
                    <div class="legend-color" style="background: #00BFFF;"></div>
                    <span>🔎 Search Result Highlight</span>
                </div>
                <div style="margin-top: 10px; font-size: 10px; color: #ccc;">
                    💡 Double-click share nodes to open in File Explorer<br>
                    🔒 Red ports indicate high security risk<br>
                    🎯 Host colors indicate detected operating system<br>
                    🔍 Enhanced detection uses 100+ port signatures<br>
                    🔎 Alt+S to search, Escape to clear
                </div>
            </div>
        </div>
        
        <svg id="graph-svg"></svg>
    </div>

    <script>
        // Data
        const nodes = {nodes_json};
        const links = {links_json};
        const portDescriptions = {port_descriptions_json};
        {scan_data_js}
        
        console.log("🎯 Loading custom D3 force-directed graph...");
        console.log("📊 Nodes:", nodes.length, "Links:", links.length);
        
        // Set up SVG
        const width = window.innerWidth;
        const height = window.innerHeight;
        
        const svg = d3.select("#graph-svg")
            .attr("width", width)
            .attr("height", height);
        
        // Add zoom behavior with extended zoom out capability for large networks
        const zoom = d3.zoom()
            .scaleExtent([0.01, 10])  // Allow zoom out to 1% and zoom in to 1000%
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

        // Add background circle for host icons (colored by OS)
        hostNodeElements.append("circle")
            .attr("r", d => d.size * 1.1) // Slightly larger than the icon
            .style("fill", d => d.color || "#607D8B") // Use OS-based color
            .style("stroke", "#fff")
            .style("stroke-width", 2)
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
        
        // Add labels - create them AFTER nodes so they render on top
        const labels = container.append("g")
            .attr("class", "labels")
            .selectAll("text")
            .data(nodes)
            .enter().append("text")
            .attr("class", "node-label")
            .text(d => d.label)
            .attr("x", d => d.x || 0)
            .attr("y", d => d.y || 0)
            .style("font-size", "10px")
            .style("fill", "white")
            .style("font-weight", "bold")
            .style("pointer-events", "none")
            .style("text-shadow", "-1px -1px 0 #000, 1px -1px 0 #000, -1px 1px 0 #000, 1px 1px 0 #000, 0px 0px 3px rgba(0,0,0,0.9)")
            .style("stroke", "#000")
            .style("stroke-width", "0.5px")
            .style("paint-order", "stroke fill")
            .style("visibility", "visible");
        
        // Add click handlers
        allNodeElements.on("click", function(event, d) {{
            // Highlight the selected node
            highlightSelectedNode(d.id);
            
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
                
                // Extract host information from node ID (format: "host::port")
                const hostPart = d.id.split("::")[0];
                const hostIP = hostPart.split("-")[0]; // Extract IP from "IP-hostname" format
                
                const securityClass = portInfo.security.includes('HIGH RISK') ? 'high-risk' :
                                     portInfo.security.includes('SECURE') ? 'secure' : 'medium-risk';
                
                infoHtml += `<br><br><strong>🔌 Port ${{portNumber}} Details:</strong><br>` +
                           `<span style="color: #4CAF50; font-weight: bold;">${{portInfo.description}}</span><br><br>` +
                           `<strong>Service Details:</strong><br>` +
                           `<span style="color: #BBB;">${{portInfo.details}}</span><br><br>` +
                           `<strong>Security Assessment:</strong><br>` +
                           `<span class="${{securityClass}}" style="font-weight: bold;">${{portInfo.security}}</span><br><br>` +
                           `<strong>Learn More:</strong><br>` +
                           `<a href="${{portInfo.link}}" target="_blank" rel="noopener" style="color: #4CAF50;">📖 Documentation</a><br><br>` +
                           `<strong>🌐 Quick Access Links:</strong><br>` +
                           `<a href="http://${{hostIP}}:${{portNumber}}" target="_blank" rel="noopener" style="color: #2196F3; margin-right: 10px;">🔗 HTTP</a>` +
                           `<a href="https://${{hostIP}}:${{portNumber}}" target="_blank" rel="noopener" style="color: #4CAF50;">🔒 HTTPS</a><br><br>` +
                           `<strong>🌐 Network Access:</strong><br>` +
                           `<span style="color: #FCC624; font-size: 11px;">💡 Try: telnet ${{hostIP}} ${{portNumber}} or nc ${{hostIP}} ${{portNumber}}</span>`;
            }}
            
            // Show synopsis of child nodes for host nodes
            if (d.group === "host") {{
                // Find all connected child nodes (ports, shares, etc.)
                const childLinks = graphData.links.filter(link => {{
                    const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
                    const targetId = typeof link.target === 'object' ? link.target.id : link.target;
                    return sourceId === d.id || targetId === d.id;
                }});
                
                const childNodeIds = childLinks.map(link => {{
                    const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
                    const targetId = typeof link.target === 'object' ? link.target.id : link.target;
                    return sourceId === d.id ? targetId : sourceId;
                }});
                
                const childNodes = graphData.nodes.filter(n => childNodeIds.includes(n.id));
                
                // Categorize child nodes
                const ports = childNodes.filter(n => n.group === 'port');
                const riskyPorts = childNodes.filter(n => n.group === 'risky_port');
                const shares = childNodes.filter(n => n.group === 'share');
                
                infoHtml += `<br><br><strong>📊 Host Synopsis:</strong>`;
                
                // Show risky ports first
                if (riskyPorts.length > 0) {{
                    infoHtml += `<br><br><span style="color: #F44336;">⚠️ Risky Ports (${{riskyPorts.length}}):</span><br>`;
                    riskyPorts.slice(0, 5).forEach(p => {{
                        const portNum = p.port || p.id.split("::")[1];
                        const portInfo = getPortDetails(parseInt(portNum));
                        infoHtml += `<span style="color: #F44336; margin-left: 10px;">• ${{portNum}} - ${{portInfo.description.split(' - ')[1] || 'Unknown'}}</span><br>`;
                    }});
                    if (riskyPorts.length > 5) {{
                        infoHtml += `<span style="color: #888; margin-left: 10px;">... and ${{riskyPorts.length - 5}} more</span><br>`;
                    }}
                }}
                
                // Show safe ports
                if (ports.length > 0) {{
                    infoHtml += `<br><span style="color: #2196F3;">🔌 Open Ports (${{ports.length}}):</span><br>`;
                    ports.slice(0, 5).forEach(p => {{
                        const portNum = p.port || p.id.split("::")[1];
                        const portInfo = getPortDetails(parseInt(portNum));
                        infoHtml += `<span style="color: #2196F3; margin-left: 10px;">• ${{portNum}} - ${{portInfo.description.split(' - ')[1] || 'Unknown'}}</span><br>`;
                    }});
                    if (ports.length > 5) {{
                        infoHtml += `<span style="color: #888; margin-left: 10px;">... and ${{ports.length - 5}} more</span><br>`;
                    }}
                }}
                
                // Show shares
                if (shares.length > 0) {{
                    infoHtml += `<br><span style="color: #B71C1C;">📁 Shares (${{shares.length}}):</span><br>`;
                    shares.slice(0, 5).forEach(s => {{
                        const shareName = s.label || s.id.split("::")[2] || 'Unknown';
                        infoHtml += `<span style="color: #B71C1C; margin-left: 10px;">• ${{shareName}}</span><br>`;
                    }});
                    if (shares.length > 5) {{
                        infoHtml += `<span style="color: #888; margin-left: 10px;">... and ${{shares.length - 5}} more</span><br>`;
                    }}
                }}
                
                // Summary
                const totalItems = ports.length + riskyPorts.length + shares.length;
                infoHtml += `<br><span style="color: #888; font-size: 11px;">Total: ${{totalItems}} connected items</span>`;
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
        
        // Add double-click handler to center and zoom to node
        allNodeElements.on("dblclick", function(event, d) {{
            event.stopPropagation(); // Prevent zoom behavior
            
            // Center and zoom to the double-clicked node
            const scale = 2.0; // Zoom level
            const x = -d.x * scale + width / 2;
            const y = -d.y * scale + height / 2;
            
            svg.transition()
                .duration(750)
                .call(zoom.transform, d3.zoomIdentity.translate(x, y).scale(scale));
            
            // Also highlight the node
            highlightSelectedNode(d.id);
            
            // Special handling for share nodes - also try to open them
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
                        window.open(`file://${{uncPath}}`, '_blank');
                    }} catch (error) {{
                        console.log('Could not open share:', error);
                    }}
                }}
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
        
        // Function to display embedded scan data
        function showScanData() {{
            if (window.SCAN_DATA) {{
                const scanInfo = window.SCAN_DATA.scan_info;
                const totalHosts = Object.keys(window.SCAN_DATA.scan_results).length;
                const totalShares = Object.keys(window.SCAN_DATA.share_results || {{}}).length;
                
                const info = `📊 SCAN RESULTS SUMMARY
                
🎯 Target: ${{scanInfo.target}}
🖥️  Total Hosts Found: ${{totalHosts}}
📂 Hosts with Shares: ${{totalShares}}
🔍 Ports Scanned: ${{scanInfo.ports_scanned}}
🌐 Hostname Resolution: ${{scanInfo.hostname_resolution ? 'Enabled' : 'Disabled'}}
🗂️  Share Enumeration: ${{scanInfo.share_enumeration ? 'Enabled' : 'Disabled'}}
⏰ Scan Time: ${{scanInfo.scan_time}}

📋 DETAILED RESULTS:
${{JSON.stringify(window.SCAN_DATA, null, 2)}}`;
                
                // Create a popup window or alert with the data
                const popup = window.open('', 'ScanData', 'width=800,height=600,scrollbars=yes');
                popup.document.write(`
                    <html>
                        <head><title>Network Vector - Scan Results</title></head>
                        <body style="font-family: monospace; background: #1a237e; color: white; padding: 20px;">
                            <h2>🌐 Network Vector - Embedded Scan Data</h2>
                            <pre style="white-space: pre-wrap; background: #000; padding: 15px; border-radius: 5px;">${{info}}</pre>
                            <button onclick="window.close()" style="margin-top: 20px; background: #FFFF00; color: #000; padding: 10px; border: none; border-radius: 5px; cursor: pointer;">Close</button>
                        </body>
                    </html>
                `);
            }} else {{
                alert('❌ No scan data found embedded in this file.');
            }}
        }}
        
        // Zoom control functions for large network navigation
        function zoomToFit() {{
            const bounds = container.node().getBBox();
            const parent = container.node().parentElement;
            const fullWidth = parent.clientWidth;
            const fullHeight = parent.clientHeight;
            const width = bounds.width;
            const height = bounds.height;
            const midX = bounds.x + width / 2;
            const midY = bounds.y + height / 2;
            
            if (width == 0 || height == 0) return; // nothing to fit
            
            const scale = Math.min(fullWidth / width, fullHeight / height) * 0.8; // 80% to add margin
            const translate = [fullWidth / 2 - midX * scale, fullHeight / 2 - midY * scale];
            
            svg.transition()
                .duration(750)
                .call(zoom.transform, d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale));
        }}
        
        function zoomReset() {{
            svg.transition()
                .duration(500)
                .call(zoom.transform, d3.zoomIdentity);
        }}
        
        function zoomIn() {{
            svg.transition()
                .duration(200)
                .call(zoom.scaleBy, 1.5);
        }}
        
        function zoomOut() {{
            svg.transition()
                .duration(200)
                .call(zoom.scaleBy, 1 / 1.5);
        }}
        
        // Panel toggle functions for better screen space management
        function toggleControls() {{
            const content = document.getElementById('controls-content');
            const toggle = document.getElementById('controls-toggle');
            
            if (content.style.display === 'none') {{
                content.style.display = 'block';
                toggle.innerHTML = '📚 Hide';
            }} else {{
                content.style.display = 'none';
                toggle.innerHTML = '📖 Show';
            }}
        }}
        
        function toggleInfoPanel() {{
            const content = document.getElementById('info-content');
            const toggle = document.getElementById('info-toggle');
            
            if (content.style.display === 'none') {{
                content.style.display = 'block';
                toggle.innerHTML = '📚 Hide';
            }} else {{
                content.style.display = 'none';
                toggle.innerHTML = '📖 Show';
            }}
        }}
        
        function toggleLegend() {{
            const content = document.getElementById('legend-content');
            const toggle = document.getElementById('legend-toggle');
            
            if (content.style.display === 'none') {{
                content.style.display = 'block';
                toggle.innerHTML = '📚 Hide';
            }} else {{
                content.style.display = 'none';
                toggle.innerHTML = '📖 Show';
            }}
        }}
        
        // CSV Download functionality
        function downloadCSV() {{
            if (!window.SCAN_DATA || !window.SCAN_DATA.scan_results) {{
                alert('❌ No scan data available for CSV export.');
                return;
            }}
            
            const scanResults = window.SCAN_DATA.scan_results;
            const shareResults = window.SCAN_DATA.share_results || {{}};
            const hostDetails = window.SCAN_DATA.host_details || {{}};
            const scanInfo = window.SCAN_DATA.scan_info;
            
            // Create CSV header
            let csvContent = "data:text/csv;charset=utf-8,";
            csvContent += "Type,IP Address,Hostname,Port,Service,SMB Share,OS Detection,Response Time\\n";
            
            // Process each host from scan_results
            Object.keys(scanResults).forEach(hostKey => {{
                // Extract IP and hostname from the key (format: "192.168.1.1-hostname" or "192.168.1.1")
                const parts = hostKey.split('-');
                const ip = parts[0];
                const hostname = parts.length > 1 ? parts.slice(1).join('-') : 'Unknown';
                const ports = scanResults[hostKey];
                const shares = shareResults[hostKey] || [];
                
                // Get actual OS detection and response time from host_details
                const hostDetail = hostDetails[hostKey] || {{}};
                const osDetection = hostDetail.os_detection || {{}};
                const osInfo = osDetection.os ? `${{osDetection.os}} (${{osDetection.confidence || 'Unknown'}} confidence)` : 'Not Available';
                const avgResponseTime = hostDetail.avg_response_time !== undefined ? 
                    `${{(hostDetail.avg_response_time * 1000).toFixed(3)}}ms` : 'N/A';
                
                // Escape commas in data fields
                const escapeCsv = (field) => {{
                    if (typeof field === 'string' && field.includes(',')) {{
                        return `"${{field.replace(/"/g, '""')}}"`;
                    }}
                    return field;
                }};
                
                // Create separate rows for ports and shares
                
                // Add rows for open ports
                if (ports && ports.length > 0) {{
                    ports.forEach(port => {{
                        // Look up service name from port descriptions
                        const portInfo = portDescriptions[port];
                        const service = portInfo ? portInfo.description : `Port ${{port}}`;
                        
                        // Get individual port response time if available from host_details
                        let portResponseTime = avgResponseTime; // fallback to average
                        if (hostDetail.open_ports && Array.isArray(hostDetail.open_ports)) {{
                            const portData = hostDetail.open_ports.find(p => p.port === port);
                            if (portData && portData.response_time !== undefined) {{
                                portResponseTime = `${{(portData.response_time * 1000).toFixed(3)}}ms`;
                            }}
                        }}
                        
                        csvContent += `Port,${{escapeCsv(ip)}},${{escapeCsv(hostname)}},${{port}},${{escapeCsv(service)}},,${{escapeCsv(osInfo)}},${{portResponseTime}}\\n`;
                    }});
                }}
                
                // Add rows for SMB shares
                if (shares && shares.length > 0) {{
                    shares.forEach(share => {{
                        csvContent += `Share,${{escapeCsv(ip)}},${{escapeCsv(hostname)}},,,${{escapeCsv(share)}},${{escapeCsv(osInfo)}},${{avgResponseTime}}\\n`;
                    }});
                }}
                
                // If host has neither ports nor shares (shouldn't happen but handle gracefully)
                if ((!ports || ports.length === 0) && (!shares || shares.length === 0)) {{
                    csvContent += `Host,${{escapeCsv(ip)}},${{escapeCsv(hostname)}},,,,,${{escapeCsv(osInfo)}},${{avgResponseTime}}\\n`;
                }}
            }});
            
            // Add scan metadata at the end
            csvContent += "\\n# Scan Metadata\\n";
            csvContent += `# Target: ${{scanInfo.target}}\\n`;
            csvContent += `# Scan Time: ${{scanInfo.scan_time || 'Unknown'}}\\n`;
            csvContent += `# Total Hosts: ${{Object.keys(scanResults).length}}\\n`;
            csvContent += `# Ports Scanned: ${{scanInfo.ports_scanned || 'Unknown'}}\\n`;
            csvContent += `# Hostname Resolution: ${{scanInfo.hostname_resolution ? 'Enabled' : 'Disabled'}}\\n`;
            csvContent += `# Share Enumeration: ${{scanInfo.share_enumeration ? 'Enabled' : 'Disabled'}}\\n`;
            
            // Create and trigger download
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            
            // Generate filename with timestamp
            const now = new Date();
            const timestamp = now.toISOString().replace(/[:.]/g, '-').split('T')[0] + '_' + 
                            now.toTimeString().split(' ')[0].replace(/:/g, '');
            link.setAttribute("download", `network_scan_${{timestamp}}.csv`);
            
            // Trigger download
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            console.log('📊 CSV export completed successfully');
        }}
        
        // Search functionality
        let searchHighlightedNodes = [];
        let originalNodeColors = new Map();
        let currentSearchIndex = -1;
        let currentNodeId = null; // Currently selected node via navigation
        let selectedNodeId = null; // Node selected by clicking
        
        // Function to highlight the clicked/selected node
        function highlightSelectedNode(nodeId) {{
            selectedNodeId = nodeId;
            
            // Remove previous selection highlight (only if not in search mode)
            if (searchHighlightedNodes.length === 0) {{
                // Reset all nodes to normal
                d3.selectAll('.circle-node')
                    .style('filter', d => d.id === nodeId ? 'drop-shadow(0 0 10px #00BFFF)' : 'none')
                    .style('stroke', d => d.id === nodeId ? '#00BFFF' : 'none')
                    .style('stroke-width', d => d.id === nodeId ? '3px' : '0');
                
                d3.selectAll('.network-node path')
                    .style('filter', d => d.id === nodeId ? 'drop-shadow(0 0 10px #00BFFF)' : 'none');
                
                d3.selectAll('.host-node circle:nth-child(2)')
                    .style('filter', d => d.id === nodeId ? 'drop-shadow(0 0 10px #00BFFF)' : 'none')
                    .style('stroke', d => d.id === nodeId ? '#00BFFF' : 'none')
                    .style('stroke-width', d => d.id === nodeId ? '3px' : '0');
                
                // Highlight the label of selected node - RED color, bigger and bold
                d3.selectAll('.node-label')
                    .style('fill', d => d.id === nodeId ? '#FF0000' : '#fff')
                    .style('font-size', d => d.id === nodeId ? '14px' : null)
                    .style('font-weight', d => d.id === nodeId ? 'bold' : null);
            }}
        }}
        
        function updateNavButtons() {{
            const prevBtn = document.getElementById('prev-btn');
            const nextBtn = document.getElementById('next-btn');
            const count = searchHighlightedNodes.length;
            
            prevBtn.disabled = count === 0 || currentSearchIndex <= 0;
            nextBtn.disabled = count === 0 || currentSearchIndex >= count - 1;
        }}
        
        function navigateToNode(nodeId) {{
            // Find the node data
            const node = nodes.find(n => n.id === nodeId);
            if (!node || node.x === undefined || node.y === undefined) return;
            
            // Set current node and update label styling
            currentNodeId = nodeId;
            updateCurrentNodeLabel();
            
            // Calculate zoom transform to center on node
            const scale = 1.5;
            const x = -node.x * scale + width / 2;
            const y = -node.y * scale + height / 2;
            
            // Animate to the node
            svg.transition()
                .duration(500)
                .call(zoom.transform, d3.zoomIdentity.translate(x, y).scale(scale));
            
            // Update info panel
            const info = document.getElementById("selected-info");
            info.innerHTML = `<strong>Navigated to:</strong><br>${{node.label}}<br><span style="color: #FF0000;">(${{currentSearchIndex + 1}} of ${{searchHighlightedNodes.length}})</span>`;
        }}
        
        function updateCurrentNodeLabel() {{
            // Reset all labels to default styling
            d3.selectAll('.node-label')
                .style('fill', d => searchHighlightedNodes.includes(d.id) ? '#00BFFF' : '#fff')
                .style('font-size', null)
                .style('font-weight', d => d.id === currentNodeId ? 'bold' : null);
            
            // Apply red styling to current node label
            d3.selectAll('.node-label')
                .filter(d => d.id === currentNodeId)
                .style('fill', '#FF0000')
                .style('font-size', '1.5em')
                .style('font-weight', 'bold');
        }}
        
        function navigatePrev() {{
            if (searchHighlightedNodes.length === 0 || currentSearchIndex <= 0) return;
            currentSearchIndex--;
            navigateToNode(searchHighlightedNodes[currentSearchIndex]);
            updateNavButtons();
            updateResultsDisplay();
        }}
        
        function navigateNext() {{
            if (searchHighlightedNodes.length === 0 || currentSearchIndex >= searchHighlightedNodes.length - 1) return;
            currentSearchIndex++;
            navigateToNode(searchHighlightedNodes[currentSearchIndex]);
            updateNavButtons();
            updateResultsDisplay();
        }}
        
        function updateResultsDisplay() {{
            const resultsDiv = document.getElementById('search-results');
            const count = searchHighlightedNodes.length;
            if (count > 0) {{
                resultsDiv.innerHTML = `<span style="color: #00BFFF;">✓ ${{currentSearchIndex + 1}} of ${{count}} match${{count > 1 ? 'es' : ''}}</span>`;
            }}
        }}
        
        function performSearch(searchTerm) {{
            // Clear previous highlights
            clearSearchHighlights();
            currentSearchIndex = -1;
            
            const resultsDiv = document.getElementById('search-results');
            
            if (!searchTerm || searchTerm.trim() === '') {{
                resultsDiv.innerHTML = '';
                updateNavButtons();
                return;
            }}
            
            const term = searchTerm.toLowerCase().trim();
            let matchCount = 0;
            
            // Search through all nodes
            nodes.forEach(node => {{
                const matchesId = node.id.toLowerCase().includes(term);
                const matchesLabel = node.label.toLowerCase().includes(term);
                const matchesDescription = node.description && typeof node.description === 'string' && node.description.toLowerCase().includes(term);
                const matchesGroup = node.group.toLowerCase().includes(term);
                
                if (matchesId || matchesLabel || matchesDescription || matchesGroup) {{
                    // Store original color if not already stored
                    if (!originalNodeColors.has(node.id)) {{
                        originalNodeColors.set(node.id, node.color);
                    }}
                    searchHighlightedNodes.push(node.id);
                    matchCount++;
                }}
            }});
            
            // Apply highlights
            applySearchHighlights();
            
            // Update results display and navigation
            if (matchCount > 0) {{
                currentSearchIndex = 0;
                resultsDiv.innerHTML = `<span style="color: #00BFFF;">✓ 1 of ${{matchCount}} match${{matchCount > 1 ? 'es' : ''}}</span>`;
                navigateToNode(searchHighlightedNodes[0]);
            }} else {{
                resultsDiv.innerHTML = `<span style="color: #FF6B6B;">✗ No matches found</span>`;
            }}
            updateNavButtons();
        }}
        
        function applySearchHighlights() {{
            const isSearchActive = searchHighlightedNodes.length > 0;
            
            // Helper to check if a link connects to highlighted nodes
            function isLinkHighlighted(d) {{
                const sourceId = typeof d.source === 'object' ? d.source.id : d.source;
                const targetId = typeof d.target === 'object' ? d.target.id : d.target;
                return searchHighlightedNodes.includes(sourceId) || searchHighlightedNodes.includes(targetId);
            }}
            
            // Dim non-highlighted links FIRST (before nodes to ensure it works)
            link.style('stroke', function(d) {{
                    if (isSearchActive && !isLinkHighlighted(d)) return '#333333';
                    return d.color || '#FFFF00';
                }})
                .style('opacity', function(d) {{
                    if (isSearchActive && !isLinkHighlighted(d)) return 0.1;
                    return 0.8;
                }});
            
            // Highlight/dim circle nodes
            d3.selectAll('.circle-node')
                .classed('search-highlight', d => searchHighlightedNodes.includes(d.id))
                .style('fill', d => {{
                    if (searchHighlightedNodes.includes(d.id)) return d.color; // Keep original color, glow will highlight
                    if (isSearchActive) return '#444444'; // Dim gray
                    return d.color;
                }})
                .style('opacity', d => isSearchActive && !searchHighlightedNodes.includes(d.id) ? 0.3 : 1)
                .style('filter', d => searchHighlightedNodes.includes(d.id) ? 'drop-shadow(0 0 8px #00BFFF)' : 'none');
            
            // Highlight/dim network nodes
            d3.selectAll('.network-node path')
                .style('fill', d => {{
                    if (searchHighlightedNodes.includes(d.id)) return d.color;
                    if (isSearchActive) return '#444444';
                    return d.color;
                }})
                .style('opacity', d => isSearchActive && !searchHighlightedNodes.includes(d.id) ? 0.3 : 1)
                .style('filter', d => searchHighlightedNodes.includes(d.id) ? 'drop-shadow(0 0 8px #00BFFF)' : 'none');
            
            // Highlight/dim host nodes
            d3.selectAll('.host-node circle:nth-child(2)')
                .style('fill', d => {{
                    if (searchHighlightedNodes.includes(d.id)) return d.color;
                    if (isSearchActive) return '#444444';
                    return d.color;
                }})
                .style('opacity', d => isSearchActive && !searchHighlightedNodes.includes(d.id) ? 0.3 : 1)
                .style('filter', d => searchHighlightedNodes.includes(d.id) ? 'drop-shadow(0 0 8px #00BFFF)' : 'none');
            
            // Dim host node images
            d3.selectAll('.host-node image')
                .style('opacity', d => isSearchActive && !searchHighlightedNodes.includes(d.id) ? 0.3 : 1);
            
            // Highlight/dim labels
            d3.selectAll('.node-label')
                .classed('search-highlight-label', d => searchHighlightedNodes.includes(d.id))
                .style('fill', d => {{
                    if (d.id === currentNodeId) return '#FF0000'; // Current node is red
                    if (searchHighlightedNodes.includes(d.id)) return '#00BFFF';
                    if (isSearchActive) return 'rgba(128,128,128,0.4)';
                    return '#fff';
                }})
                .style('opacity', d => isSearchActive && !searchHighlightedNodes.includes(d.id) ? 0.4 : 1);
        }}
        
        function clearSearchHighlights() {{
            searchHighlightedNodes = [];
            currentNodeId = null; // Clear current node marker
            
            // Remove highlights from circle nodes and restore original colors
            d3.selectAll('.circle-node')
                .classed('search-highlight', false)
                .style('fill', d => d.color)
                .style('opacity', 1)
                .style('filter', 'none');
            
            // Remove highlights from network nodes
            d3.selectAll('.network-node path')
                .style('fill', d => d.color)
                .style('opacity', 1)
                .style('filter', 'none');
            
            // Remove highlights from host nodes
            d3.selectAll('.host-node circle:nth-child(2)')
                .style('fill', d => d.color)
                .style('opacity', 1)
                .style('filter', 'none');
            
            // Restore host node images
            d3.selectAll('.host-node image')
                .style('opacity', 1);
            
            // Remove label highlights and reset styling
            d3.selectAll('.node-label')
                .classed('search-highlight-label', false)
                .style('fill', '#fff')
                .style('opacity', 1)
                .style('font-size', null)
                .style('font-weight', null);
            
            // Restore links to original colors using the link variable
            link.style('stroke', function(d) {{ return d.color || '#FFFF00'; }})
                .style('opacity', 0.8);
        }}
        
        function clearSearch() {{
            const searchInput = document.getElementById('search-input');
            const resultsDiv = document.getElementById('search-results');
            
            searchInput.value = '';
            resultsDiv.innerHTML = '';
            clearSearchHighlights();
            currentSearchIndex = -1;
            updateNavButtons();
        }}
        
        // Add keyboard shortcuts for quick panel toggling
        document.addEventListener('keydown', function(event) {{
            // Handle Escape key to clear search
            if (event.key === 'Escape') {{
                clearSearch();
                document.getElementById('search-input').blur();
                event.preventDefault();
                return;
            }}
            
            if (event.altKey) {{
                switch(event.key) {{
                    case 'c':
                    case 'C':
                        toggleControls();
                        event.preventDefault();
                        break;
                    case 'i':
                    case 'I':
                        toggleInfoPanel();
                        event.preventDefault();
                        break;
                    case 'l':
                    case 'L':
                        toggleLegend();
                        event.preventDefault();
                        break;
                    case 's':
                    case 'S':
                        // Focus search input
                        const searchInput = document.getElementById('search-input');
                        searchInput.focus();
                        searchInput.select();
                        event.preventDefault();
                        break;
                }}
            }}
        }});
    </script>
</body>
</html>
        """
        
        return html_content
    
    def save_and_show(self, filename: str = "custom_network_graph.html", scan_data: Dict = None, auto_open: bool = True):
        """
        Save the HTML file with embedded scan data and optionally open it in the browser.
        """
        html_content = self.generate_html(scan_data=scan_data)
        
        # Save to file
        filepath = os.path.abspath(filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Custom D3 force-directed graph saved to: {filepath}")
        print(f"📊 Graph contains {len(self.nodes)} nodes and {len(self.links)} links")
        #print(f"🟡 All edges are bright yellow with 2px width")
        #print(f"📌 Sticky node behavior: drag nodes to move them permanently")
        if scan_data:
            print(f"📄 Scan results embedded in HTML for self-contained analysis")
        
        if auto_open:
            try:
                webbrowser.open(f"file://{filepath}")
                #print("🌐 Graph opened in browser!")
            except Exception as e:
                print(f"⚠️ Could not auto-open browser: {e}")
                print(f"📂 Manually open: {filepath}")
        
        return filepath
    
    def save_html(self, filename: str = "custom_network_graph.html", scan_data: Dict = None):
        """
        Save the HTML file without opening in browser (for live mode updates).
        """
        html_content = self.generate_html(scan_data=scan_data)
        filepath = os.path.abspath(filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return filepath

def create_custom_graph_from_scan(scan_results: Dict[str, List[int]], share_results: Dict[str, List[str]] = None, host_details: Dict = None):
    """
    Helper function to create a custom D3 graph from scan results.
    """
    graph = CustomD3ForceGraph()
    graph.generate_from_scan_results(scan_results, share_results, host_details)
    return graph

class CustomD3Force3DGraph:
    """
    Generate 3D force-directed graphs using 3d-force-graph library.
    """
    
    def __init__(self):
        self.nodes = []
        self.links = []
        
    def add_node(self, node_id: str, label: str = None, group: str = "default", color: str = None, size: int = 10, description: str = None, port: int = None):
        """Add a node to the 3D graph."""
        node_data = {
            "id": node_id,
            "label": label or node_id,
            "group": group,
            "color": color,
            "size": size,
            "description": description or ""
        }
        if port is not None:
            node_data["port"] = port
        
        self.nodes.append(node_data)
        
    def add_link(self, source: str, target: str, weight: int = 1, color: str = "#FFFF00"):
        """Add a link between two nodes in 3D."""
        self.links.append({
            "source": source,
            "target": target,
            "weight": weight,
            "color": color
        })
    
    def generate_from_scan_results(self, scan_results: Dict[str, List[int]], share_results: Dict[str, List[str]] = None, host_details: Dict = None):
        """
        Generate 3D graph data from port scan results.
        Uses the same logic as 2D graph for consistency.
        """
        share_results = share_results or {}
        host_details = host_details or {}
        
        # Clear existing data
        self.nodes = []
        self.links = []
        
        # Function to get OS-based colors (same as 2D)
        def get_os_color(host_key):
            host_detail = host_details.get(host_key, {})
            os_detection = host_detail.get('os_detection', {})
            os_name = os_detection.get('os', '').lower()
            
            if 'windows' in os_name:
                return "#0078D4"
            elif 'linux' in os_name or 'unix' in os_name:
                return "#FCC624"
            elif 'macos' in os_name or 'mac os' in os_name:
                return "#9C27B0"
            elif 'embedded' in os_name or 'iot' in os_name:
                return "#FF5722"
            else:
                return "#607D8B"
        
        # Service mapping (same as 2D)
        def get_service_name(port):
            port_data = PORT_DESCRIPTIONS.get(port)
            if port_data and isinstance(port_data, dict):
                description = port_data.get('description', f'Port {port}')
                service_name = description.split(" - ")[0] if " - " in description else description
                service_name = service_name.replace("Apple ", "").replace("Microsoft ", "MS ").replace("Windows ", "Win ")
                return service_name
            
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
        
        def is_risky_port(port):
            risky_ports = {
                21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 1521, 2049, 111, 5985, 5986
            }
            return port in risky_ports
        
        # Add host nodes
        for host, ports in scan_results.items():
            host_color = get_os_color(host)
            self.add_node(
                node_id=host,
                label=host,
                group="host",
                color=host_color,
                size=15
            )
            
            # Add port nodes
            for port in ports:
                port_id = f"{host}::{port}"
                service_name = get_service_name(port)
                port_description = get_port_description(port)
                port_label = f"{port}/{service_name}"
                
                if is_risky_port(port):
                    port_color = "#F44336"
                    port_group = "risky_port"
                else:
                    port_color = "#2196F3"
                    port_group = "port"
                
                self.add_node(
                    node_id=port_id,
                    label=port_label,
                    group=port_group,
                    color=port_color,
                    size=10,
                    description=port_description,
                    port=port
                )
                
                self.add_link(host, port_id, weight=2, color="#FFFF00")
        
        # Add network topology
        network_hierarchy = {}
        
        for host in scan_results.keys():
            if '-' in host:
                ip_address = host.split('-')[0]
            else:
                ip_address = host
            
            ip_parts = ip_address.split('.')
            if len(ip_parts) == 4:
                class_a = ip_parts[0]
                class_b = f"{ip_parts[0]}.{ip_parts[1]}"
                class_c = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                
                if class_a not in network_hierarchy:
                    network_hierarchy[class_a] = {"class_b": set(), "class_c": set(), "hosts": set()}
                
                network_hierarchy[class_a]["class_b"].add(class_b)
                network_hierarchy[class_a]["class_c"].add(class_c)
                network_hierarchy[class_a]["hosts"].add(host)
        
        # Create network nodes and links
        for class_a, data in network_hierarchy.items():
            class_a_id = f"network::class_a::{class_a}"
            self.add_node(
                node_id=class_a_id,
                label=f"Network {class_a}.x.x.x",
                group="network_a",
                color="#607D8B",
                size=18
            )
            
            for class_b in data["class_b"]:
                class_b_id = f"network::class_b::{class_b}"
                self.add_node(
                    node_id=class_b_id,
                    label=f"Network {class_b}.x.x",
                    group="network_b", 
                    color="#795548",
                    size=16
                )
                self.add_link(class_a_id, class_b_id, weight=3, color="#FFFF00")
            
            for class_c in data["class_c"]:
                class_c_id = f"network::class_c::{class_c}"
                self.add_node(
                    node_id=class_c_id,
                    label=class_c,
                    group="network_c",
                    color="#8BC34A",
                    size=14
                )
                
                class_c_prefix = '.'.join(class_c.split('.')[:2])
                class_b_id = f"network::class_b::{class_c_prefix}"
                self.add_link(class_b_id, class_c_id, weight=2, color="#FFFF00")
            
            for host in data["hosts"]:
                host_ip = host.split('-')[0] if '-' in host else host
                ip_parts = host_ip.split('.')
                if len(ip_parts) == 4:
                    host_class_c = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                    class_c_id = f"network::class_c::{host_class_c}"
                    self.add_link(class_c_id, host, weight=2, color="#FFFF00")
        
        # Handle share enumeration
        for host, shares in share_results.items():
            if shares:
                shares_node_id = f"{host}::Shares"
                self.add_node(
                    node_id=shares_node_id,
                    label=f"{host.split('-')[0]}-Shares",
                    group="shares",
                    color="#8B0000",
                    size=10
                )
                self.add_link(host, shares_node_id, weight=2, color="#FFFF00")
                
                for share in shares:
                    share_node_id = f"{host}::share::{share}"
                    self.add_node(
                        node_id=share_node_id,
                        label=f"Share: {share}",
                        group="share",
                        color="#B71C1C",
                        size=6
                    )
                    self.add_link(shares_node_id, share_node_id, weight=1, color="#FFFF00")
    
    def generate_html(self, title: str = "3D Network Topology", scan_data: Dict = None):
        """
        Generate HTML with 3d-force-graph library.
        """
        nodes_json = json.dumps(self.nodes, indent=2)
        links_json = json.dumps(self.links, indent=2)
        port_descriptions_json = json.dumps(PORT_DESCRIPTIONS, indent=2)
        
        scan_data_js = ""
        if scan_data:
            scan_data_json = json.dumps(scan_data, indent=2)
            scan_data_js = f"""
        window.SCAN_DATA = {scan_data_json};
        console.log('📊 Scan data embedded:', window.SCAN_DATA);"""
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://unpkg.com/three@0.160.0/build/three.min.js"></script>
    <script src="https://unpkg.com/three-spritetext@1.8.2/dist/three-spritetext.min.js"></script>
    <script src="https://unpkg.com/3d-force-graph@1.73.6/dist/3d-force-graph.min.js"></script>
    <style>
        body {{
            margin: 0;
            padding: 0;
            background: #000000;
            font-family: 'Arial', sans-serif;
            color: white;
            overflow: hidden;
        }}
        
        #3d-graph {{
            width: 100vw;
            height: 100vh;
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
        
        /* Search styling */
        .search-container {{
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid #333;
        }}
        
        .search-input {{
            width: calc(100% - 30px);
            padding: 6px 10px;
            border: 1px solid #3949ab;
            border-radius: 4px;
            background: #1a237e;
            color: white;
            font-size: 12px;
            outline: none;
        }}
        
        .search-input:focus {{
            border-color: #7C4DFF;
            box-shadow: 0 0 5px rgba(124, 77, 255, 0.5);
        }}
        
        .search-input::placeholder {{
            color: #888;
        }}
        
        .search-results {{
            margin-top: 5px;
            font-size: 11px;
            color: #AAA;
        }}
        
        .clear-search {{
            background: #D32F2F;
            color: white;
            border: none;
            padding: 3px 8px;
            border-radius: 3px;
            cursor: pointer;
            margin-left: 5px;
            font-size: 11px;
        }}
        
        .clear-search:hover {{
            background: #F44336;
        }}
        
        .nav-buttons {{
            display: flex;
            gap: 5px;
            margin-top: 5px;
        }}
        
        .nav-btn {{
            background: #1976D2;
            color: white;
            border: 1px solid #2196F3;
            padding: 3px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 11px;
            flex: 1;
        }}
        
        .nav-btn:hover {{
            background: #2196F3;
        }}
        
        .nav-btn:disabled {{
            background: #555;
            border-color: #666;
            cursor: not-allowed;
            opacity: 0.5;
        }}
    </style>
</head>
<body>
    <div id="3d-graph"></div>
    
    <div class="controls">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong>🎮 3D Controls</strong>
            <button onclick="toggleControls()" style="background: #1a237e; color: white; border: 1px solid #3949ab; padding: 2px 6px; border-radius: 3px; cursor: pointer; font-size: 12px;" id="controls-toggle">📚 Hide</button>
        </div>
        <div id="controls-content">
            <div>• Left-click + drag to rotate</div>
            <div>• Right-click + drag to pan</div>
            <div>• Scroll to zoom</div>
            <div>• Click nodes for details</div>
            <div>• Double-click nodes to focus</div>
            <div style="margin-top: 8px; font-size: 11px; color: #AAA;">
                <strong>Keyboard Shortcuts:</strong><br>
                • Alt+C: Toggle Controls<br>
                • Alt+I: Toggle Info Panel<br>
                • Alt+L: Toggle Legend<br>
                • Alt+S: Focus Search<br>
                • Escape: Clear Search
            </div>
            <button onclick="showScanData()" style="margin-top: 10px; background: #1a237e; color: white; border: 1px solid #FFFF00; padding: 5px; border-radius: 3px; cursor: pointer;">📄 Show Scan Data</button>
            <button onclick="downloadCSV()" style="margin-top: 10px; margin-left: 5px; background: #388E3C; color: white; border: 1px solid #4CAF50; padding: 5px; border-radius: 3px; cursor: pointer;">📊 Download CSV</button>
            <div class="search-container">
                <strong>🔎 Search Graph</strong>
                <div style="margin-top: 5px; display: flex; align-items: center;">
                    <input type="text" id="search-input" class="search-input" placeholder="Search nodes (IP, port, service...)" oninput="performSearch(this.value)" />
                    <button class="clear-search" onclick="clearSearch()">✕</button>
                </div>
                <div id="search-results" class="search-results"></div>
                <div class="nav-buttons">
                    <button class="nav-btn" id="prev-btn" onclick="navigatePrev()" disabled>◀ Previous</button>
                    <button class="nav-btn" id="next-btn" onclick="navigateNext()" disabled>Next ▶</button>
                </div>
            </div>
            <div style="margin-top: 15px; border-top: 1px solid #555; padding-top: 10px;">
                <strong>🎬 Host Tour</strong>
                <div class="nav-buttons" style="margin-top: 5px;">
                    <button class="nav-btn" id="play-btn" onclick="toggleHostTour()" style="background: #388E3C;">▶ Play</button>
                    <button class="nav-btn" id="stop-btn" onclick="stopHostTour()" disabled>⏹ Stop</button>
                </div>
                <div id="tour-status" style="margin-top: 5px; font-size: 11px; color: #aaa;"></div>
            </div>
        </div>
    </div>
    
    <div class="info-panel">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong>📊 3D Network Graph</strong>
            <button onclick="toggleInfoPanel()" style="background: #1a237e; color: white; border: 1px solid #3949ab; padding: 2px 6px; border-radius: 3px; cursor: pointer; font-size: 12px;" id="info-toggle">📚 Hide</button>
        </div>
        <div id="info-content">
            <div id="node-count">Nodes: {len(self.nodes)}</div>
            <div id="link-count">Links: {len(self.links)}</div>
            <div id="selected-info"></div>
        </div>
    </div>
    
    <div class="legend">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong>🎯 Legend</strong>
            <button onclick="toggleLegend()" style="background: #1a237e; color: white; border: 1px solid #3949ab; padding: 2px 6px; border-radius: 3px; cursor: pointer; font-size: 12px;" id="legend-toggle">📚 Hide</button>
        </div>
        <div id="legend-content">
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
                <div class="legend-color" style="background: #F44336;"></div>
                <span>⚠️ Risky Ports</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #2196F3;"></div>
                <span>Safe Ports</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #8B0000;"></div>
                <span>Shares Container</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #B71C1C;"></div>
                <span>Individual Shares</span>
            </div>
            <hr style="border-color: #555; margin: 8px 0;">
            <div style="font-weight: bold; margin-bottom: 5px; color: #fff;">🖥️ Host OS Detection</div>
            <div class="legend-item">
                <div class="legend-color" style="background: #0078D4;"></div>
                <span>Windows Systems</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #FCC624;"></div>
                <span>Linux/Unix Systems</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #9C27B0;"></div>
                <span>macOS Systems</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #FF5722;"></div>
                <span>Embedded/IoT Devices</span>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background: #607D8B;"></div>
                <span>Unknown/Other OS</span>
            </div>
            <hr style="border-color: #555; margin: 8px 0;">
            <div class="legend-item">
                <div class="legend-color" style="background: #00BFFF;"></div>
                <span>🔎 Search Result Highlight</span>
            </div>
            <div style="margin-top: 10px; font-size: 10px; color: #ccc;">
                🔎 Alt+S to search, Escape to clear
            </div>
        </div>
    </div>

    <script>
        const graphData = {{
            nodes: {nodes_json},
            links: {links_json}
        }};
        const portDescriptions = {port_descriptions_json};
        {scan_data_js}
        
        console.log("🎯 Loading 3D force-directed graph...");
        console.log("📊 Nodes:", graphData.nodes.length, "Links:", graphData.links.length);
        
        // Variables for node selection (must be declared before createNodeWithLabel)
        let selectedNodeId = null; // Node selected by clicking
        let searchActive = false; // Flag to track if search is active
        let searchHighlightedNodes = new Set();
        const originalNodeColors = new Map();
        
        // Store original colors
        graphData.nodes.forEach(node => {{
            originalNodeColors.set(node.id, node.color);
        }});
        
        // Helper function to create node with label
        function createNodeWithLabel(node, isHighlighted) {{
            const group = new THREE.Group();
            const nodeSize = (node.size || 5) * 0.5; // 50% smaller spheres
            const isCurrent = node.__currentNode; // Currently selected via navigation
            const isSelected = node.id === selectedNodeId; // Selected by clicking
            const isDimmed = searchActive && !isHighlighted; // Dim if search active but not highlighted
            const showGlow = isHighlighted || isSelected; // Show glow for highlighted OR selected nodes
            // Keep original node color, don't change to light blue when highlighted
            const originalColor = originalNodeColors.get(node.id) || node.color || '#69b3a2';
            const nodeColor = parseInt(originalColor.replace('#', ''), 16);
            
            // Create the main sphere
            const geometry = new THREE.SphereGeometry(nodeSize);
            const material = new THREE.MeshLambertMaterial({{
                color: isDimmed ? 0x444444 : nodeColor, // Gray out if dimmed
                transparent: isDimmed,
                opacity: isDimmed ? 0.3 : 1.0
            }});
            const sphere = new THREE.Mesh(geometry, material);
            group.add(sphere);
            
            // Add glow effect for highlighted or selected nodes (single glow sphere)
            if (showGlow) {{
                const glowGeometry = new THREE.SphereGeometry(nodeSize * 2.0);
                const glowMaterial = new THREE.MeshBasicMaterial({{
                    color: 0x00BFFF,
                    transparent: true,
                    opacity: 0.25
                }});
                const glowSphere = new THREE.Mesh(glowGeometry, glowMaterial);
                group.add(glowSphere);
            }}
            
            // Create text label using SpriteText - always render on top
            // Selected or currently navigated node gets red, bigger label on top layer
            const isSpecial = isCurrent || isSelected; // Either clicked or navigated to
            const sprite = new SpriteText(node.label);
            // Label color: red for selected/current, dimmed gray if not highlighted during search, otherwise white
            sprite.color = isSpecial ? '#FF0000' : (isDimmed ? 'rgba(128,128,128,0.4)' : 'white');
            sprite.textHeight = isSpecial ? nodeSize * 0.6 : nodeSize * 0.4;  // 50% bigger for selected/current node
            sprite.position.y = nodeSize + 2;
            sprite.backgroundColor = isSpecial ? 'rgba(0,0,0,0.8)' : (isDimmed ? 'rgba(0,0,0,0.2)' : 'rgba(0,0,0,0.6)');
            sprite.padding = 0.5;
            sprite.borderRadius = 1;
            // Make label always visible on top layer (not hidden by nodes)
            sprite.material.depthTest = false;
            sprite.material.depthWrite = false;
            sprite.renderOrder = isSpecial ? 9999 : 999;  // Selected/current node label on topmost layer
            group.add(sprite);
            
            return group;
        }}
        
        // Helper function to check if a link connects to highlighted nodes
        function isLinkHighlighted(link) {{
            const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
            const targetId = typeof link.target === 'object' ? link.target.id : link.target;
            return searchHighlightedNodes.has(sourceId) || searchHighlightedNodes.has(targetId);
        }}
        
        // Function to refresh node rendering (will be set after Graph is created)
        let refreshNodes = null;
        
        // Create 3D force graph
        const Graph = ForceGraph3D()
            (document.getElementById('3d-graph'))
            .graphData(graphData)
            .nodeLabel(null) // Disable hover labels since we have permanent ones
            .nodeColor(node => node.color || '#69b3a2')
            .nodeVal(node => node.size)
            .nodeThreeObject(node => createNodeWithLabel(node, node.__glowHighlight))
            .nodeThreeObjectExtend(false)
            .linkColor(link => {{
                if (searchActive && !isLinkHighlighted(link)) {{
                    return '#333333'; // Dimmed gray for non-highlighted links
                }}
                return link.color || '#FFFF00';
            }})
            .linkWidth(link => link.weight || 1)
            .linkOpacity(link => {{
                if (searchActive && !isLinkHighlighted(link)) {{
                    return 0.1; // Very dim for non-highlighted links
                }}
                return 0.6;
            }});
        
        // Double-click detection variables
        let lastClickTime = 0;
        let lastClickedNode = null;
        const DOUBLE_CLICK_DELAY = 300; // ms
        
        // Handle node clicks (single and double)
        Graph.onNodeClick(node => {{
            const currentTime = Date.now();
            const isDoubleClick = (currentTime - lastClickTime < DOUBLE_CLICK_DELAY) && (lastClickedNode === node.id);
            
            lastClickTime = currentTime;
            lastClickedNode = node.id;
            
            if (isDoubleClick) {{
                // DOUBLE CLICK - Center camera on node and zoom in
                const distance = 80; // Closer zoom for double-click
                const distRatio = 1 + distance / Math.hypot(node.x || 0, node.y || 0, node.z || 0);
                
                Graph.cameraPosition(
                    {{ x: (node.x || 0) * distRatio, y: (node.y || 0) * distRatio, z: (node.z || 0) * distRatio }},
                    node,
                    1000 // Animation duration
                );
            }}
            
            // SINGLE CLICK (always) - Set selected node and refresh to show glow
            selectedNodeId = node.id;
            // Use setTimeout to ensure Graph is fully initialized
            setTimeout(() => {{
                if (!searchActive) {{
                        Graph.nodeThreeObject(n => createNodeWithLabel(n, n.__glowHighlight));
                    }}
                }}, 0);
                
                const info = document.getElementById("selected-info");
                let infoHtml = `<strong>Selected:</strong><br>` +
                              `ID: ${{node.id}}<br>` +
                              `Type: ${{node.group}}<br>` +
                              `Label: ${{node.label}}`;
                
                if ((node.group === "port" || node.group === "risky_port") && node.description) {{
                    const portNumber = node.port || node.id.split("::")[1];
                    const portInfo = getPortDetails(parseInt(portNumber));
                    const hostPart = node.id.split("::")[0];
                    const hostIP = hostPart.split("-")[0];
                    const securityClass = portInfo.security.includes('HIGH RISK') ? 'high-risk' :
                                         portInfo.security.includes('SECURE') ? 'secure' : 'medium-risk';
                    
                    infoHtml += `<br><br><strong>🔌 Port ${{portNumber}} Details:</strong><br>` +
                               `<span style="color: #4CAF50; font-weight: bold;">${{portInfo.description}}</span><br><br>` +
                               `<strong>Service Details:</strong><br>` +
                               `<span style="color: #BBB;">${{portInfo.details}}</span><br><br>` +
                               `<strong>Security Assessment:</strong><br>` +
                               `<span class="${{securityClass}}" style="font-weight: bold;">${{portInfo.security}}</span><br><br>` +
                               `<strong>Learn More:</strong><br>` +
                               `<a href="${{portInfo.link}}" target="_blank" rel="noopener" style="color: #4CAF50;">📖 Documentation</a><br><br>` +
                               `<strong>🌐 Quick Access Links:</strong><br>` +
                               `<a href="http://${{hostIP}}:${{portNumber}}" target="_blank" rel="noopener" style="color: #2196F3; margin-right: 10px;">🔗 HTTP</a>` +
                               `<a href="https://${{hostIP}}:${{portNumber}}" target="_blank" rel="noopener" style="color: #4CAF50;">🔒 HTTPS</a>`;
                }}
                
                // Show synopsis of child nodes for host nodes
                if (node.group === "host") {{
                    // Find all connected child nodes (ports, shares, etc.)
                    const childLinks = graphData.links.filter(link => {{
                        const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
                        const targetId = typeof link.target === 'object' ? link.target.id : link.target;
                        return sourceId === node.id || targetId === node.id;
                    }});
                    
                    const childNodeIds = childLinks.map(link => {{
                        const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
                        const targetId = typeof link.target === 'object' ? link.target.id : link.target;
                        return sourceId === node.id ? targetId : sourceId;
                    }});
                    
                    const childNodes = graphData.nodes.filter(n => childNodeIds.includes(n.id));
                    
                    // Categorize child nodes
                    const ports = childNodes.filter(n => n.group === 'port');
                    const riskyPorts = childNodes.filter(n => n.group === 'risky_port');
                    const shares = childNodes.filter(n => n.group === 'share');
                    const shareContainers = childNodes.filter(n => n.group === 'shares_container');
                    
                    infoHtml += `<br><br><strong>📊 Host Synopsis:</strong>`;
                    
                    // Show risky ports first
                    if (riskyPorts.length > 0) {{
                        infoHtml += `<br><br><span style="color: #F44336;">⚠️ Risky Ports (${{riskyPorts.length}}):</span><br>`;
                        riskyPorts.slice(0, 5).forEach(p => {{
                            const portNum = p.port || p.id.split("::")[1];
                            const portInfo = getPortDetails(parseInt(portNum));
                            infoHtml += `<span style="color: #F44336; margin-left: 10px;">• ${{portNum}} - ${{portInfo.description.split(' - ')[1] || 'Unknown'}}</span><br>`;
                        }});
                        if (riskyPorts.length > 5) {{
                            infoHtml += `<span style="color: #888; margin-left: 10px;">... and ${{riskyPorts.length - 5}} more</span><br>`;
                        }}
                    }}
                    
                    // Show safe ports
                    if (ports.length > 0) {{
                        infoHtml += `<br><span style="color: #2196F3;">🔌 Open Ports (${{ports.length}}):</span><br>`;
                        ports.slice(0, 5).forEach(p => {{
                            const portNum = p.port || p.id.split("::")[1];
                            const portInfo = getPortDetails(parseInt(portNum));
                            infoHtml += `<span style="color: #2196F3; margin-left: 10px;">• ${{portNum}} - ${{portInfo.description.split(' - ')[1] || 'Unknown'}}</span><br>`;
                        }});
                        if (ports.length > 5) {{
                            infoHtml += `<span style="color: #888; margin-left: 10px;">... and ${{ports.length - 5}} more</span><br>`;
                        }}
                    }}
                    
                    // Show shares
                    if (shares.length > 0) {{
                        infoHtml += `<br><span style="color: #B71C1C;">📁 Shares (${{shares.length}}):</span><br>`;
                        shares.slice(0, 5).forEach(s => {{
                            const shareName = s.label || s.id.split("::")[2] || 'Unknown';
                            infoHtml += `<span style="color: #B71C1C; margin-left: 10px;">• ${{shareName}}</span><br>`;
                        }});
                        if (shares.length > 5) {{
                            infoHtml += `<span style="color: #888; margin-left: 10px;">... and ${{shares.length - 5}} more</span><br>`;
                        }}
                    }}
                    
                    // Summary
                    const totalItems = ports.length + riskyPorts.length + shares.length;
                    infoHtml += `<br><span style="color: #888; font-size: 11px;">Total: ${{totalItems}} connected items</span>`;
                }}
                
                info.innerHTML = infoHtml;
            }});
        
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
        
        function showScanData() {{
            if (window.SCAN_DATA) {{
                const scanInfo = window.SCAN_DATA.scan_info;
                const totalHosts = Object.keys(window.SCAN_DATA.scan_results).length;
                const totalShares = Object.keys(window.SCAN_DATA.share_results || {{}}).length;
                
                const info = `📊 SCAN RESULTS SUMMARY
                
🎯 Target: ${{scanInfo.target}}
🖥️  Total Hosts Found: ${{totalHosts}}
📂 Hosts with Shares: ${{totalShares}}
🔍 Ports Scanned: ${{scanInfo.ports_scanned}}
🌐 Hostname Resolution: ${{scanInfo.hostname_resolution ? 'Enabled' : 'Disabled'}}
🗂️  Share Enumeration: ${{scanInfo.share_enumeration ? 'Enabled' : 'Disabled'}}
⏰ Scan Time: ${{scanInfo.scan_time}}

📋 DETAILED RESULTS:
${{JSON.stringify(window.SCAN_DATA, null, 2)}}`;
                
                const popup = window.open('', 'ScanData', 'width=800,height=600,scrollbars=yes');
                popup.document.write(`
                    <html>
                        <head><title>Network Vector - Scan Results (3D)</title></head>
                        <body style="font-family: monospace; background: #1a237e; color: white; padding: 20px;">
                            <h2>🌐 Network Vector - 3D Embedded Scan Data</h2>
                            <pre style="white-space: pre-wrap; background: #000; padding: 15px; border-radius: 5px;">${{info}}</pre>
                            <button onclick="window.close()" style="margin-top: 20px; background: #FFFF00; color: #000; padding: 10px; border: none; border-radius: 5px; cursor: pointer;">Close</button>
                        </body>
                    </html>
                `);
            }} else {{
                alert('❌ No scan data found embedded in this file.');
            }}
        }}
        
        function downloadCSV() {{
            if (!window.SCAN_DATA || !window.SCAN_DATA.scan_results) {{
                alert('❌ No scan data available for CSV export.');
                return;
            }}
            
            const scanResults = window.SCAN_DATA.scan_results;
            const shareResults = window.SCAN_DATA.share_results || {{}};
            const hostDetails = window.SCAN_DATA.host_details || {{}};
            const scanInfo = window.SCAN_DATA.scan_info;
            
            let csvContent = "data:text/csv;charset=utf-8,";
            csvContent += "Type,IP Address,Hostname,Port,Service,SMB Share,OS Detection,Response Time\\n";
            
            const escapeCsv = (field) => {{
                if (typeof field === 'string' && field.includes(',')) {{
                    return `"${{field.replace(/"/g, '""')}}"`;
                }}
                return field;
            }};
            
            Object.keys(scanResults).forEach(hostKey => {{
                const parts = hostKey.split('-');
                const ip = parts[0];
                const hostname = parts.length > 1 ? parts.slice(1).join('-') : 'Unknown';
                const ports = scanResults[hostKey];
                const shares = shareResults[hostKey] || [];
                
                const hostDetail = hostDetails[hostKey] || {{}};
                const osDetection = hostDetail.os_detection || {{}};
                const osInfo = osDetection.os ? `${{osDetection.os}} (${{osDetection.confidence || 'Unknown'}} confidence)` : 'Not Available';
                const avgResponseTime = hostDetail.avg_response_time !== undefined ? 
                    `${{(hostDetail.avg_response_time * 1000).toFixed(3)}}ms` : 'N/A';
                
                if (ports && ports.length > 0) {{
                    ports.forEach(port => {{
                        const portInfo = portDescriptions[port];
                        const service = portInfo ? portInfo.description : `Port ${{port}}`;
                        
                        let portResponseTime = avgResponseTime;
                        if (hostDetail.open_ports && Array.isArray(hostDetail.open_ports)) {{
                            const portData = hostDetail.open_ports.find(p => p.port === port);
                            if (portData && portData.response_time !== undefined) {{
                                portResponseTime = `${{(portData.response_time * 1000).toFixed(3)}}ms`;
                            }}
                        }}
                        
                        csvContent += `Port,${{escapeCsv(ip)}},${{escapeCsv(hostname)}},${{port}},${{escapeCsv(service)}},,${{escapeCsv(osInfo)}},${{portResponseTime}}\\n`;
                    }});
                }}
                
                if (shares && shares.length > 0) {{
                    shares.forEach(share => {{
                        csvContent += `Share,${{escapeCsv(ip)}},${{escapeCsv(hostname)}},,,${{escapeCsv(share)}},${{escapeCsv(osInfo)}},${{avgResponseTime}}\\n`;
                    }});
                }}
                
                if ((!ports || ports.length === 0) && (!shares || shares.length === 0)) {{
                    csvContent += `Host,${{escapeCsv(ip)}},${{escapeCsv(hostname)}},,,,,${{escapeCsv(osInfo)}},${{avgResponseTime}}\\n`;
                }}
            }});
            
            csvContent += "\\n# Scan Metadata\\n";
            csvContent += `# Target: ${{scanInfo.target}}\\n`;
            csvContent += `# Scan Time: ${{scanInfo.scan_time || 'Unknown'}}\\n`;
            csvContent += `# Total Hosts: ${{Object.keys(scanResults).length}}\\n`;
            csvContent += `# Ports Scanned: ${{scanInfo.ports_scanned || 'Unknown'}}\\n`;
            
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            
            const now = new Date();
            const timestamp = now.toISOString().replace(/[:.]/g, '-').split('T')[0] + '_' + 
                            now.toTimeString().split(' ')[0].replace(/:/g, '');
            link.setAttribute("download", `network_scan_3d_${{timestamp}}.csv`);
            
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            console.log('📊 CSV export completed successfully');
        }}
        
        function toggleControls() {{
            const content = document.getElementById('controls-content');
            const toggle = document.getElementById('controls-toggle');
            
            if (content.style.display === 'none') {{
                content.style.display = 'block';
                toggle.innerHTML = '📚 Hide';
            }} else {{
                content.style.display = 'none';
                toggle.innerHTML = '📖 Show';
            }}
        }}
        
        function toggleInfoPanel() {{
            const content = document.getElementById('info-content');
            const toggle = document.getElementById('info-toggle');
            
            if (content.style.display === 'none') {{
                content.style.display = 'block';
                toggle.innerHTML = '📚 Hide';
            }} else {{
                content.style.display = 'none';
                toggle.innerHTML = '📖 Show';
            }}
        }}
        
        function toggleLegend() {{
            const content = document.getElementById('legend-content');
            const toggle = document.getElementById('legend-toggle');
            
            if (content.style.display === 'none') {{
                content.style.display = 'block';
                toggle.innerHTML = '📚 Hide';
            }} else {{
                content.style.display = 'none';
                toggle.innerHTML = '📖 Show';
            }}
        }}
        
        // Host Tour Animation
        let hostTourInterval = null;
        let hostTourIndex = 0;
        let hostNodes = [];
        let isTourPlaying = false;
        
        // Get all host nodes
        hostNodes = graphData.nodes.filter(n => n.group === 'host');
        
        function toggleHostTour() {{
            if (isTourPlaying) {{
                pauseHostTour();
            }} else {{
                startHostTour();
            }}
        }}
        
        function startHostTour() {{
            if (hostNodes.length === 0) {{
                document.getElementById('tour-status').innerHTML = '<span style="color: #FF6B6B;">No hosts found</span>';
                return;
            }}
            
            isTourPlaying = true;
            const playBtn = document.getElementById('play-btn');
            const stopBtn = document.getElementById('stop-btn');
            playBtn.innerHTML = '⏸ Pause';
            playBtn.style.background = '#F57C00';
            stopBtn.disabled = false;
            
            // Start the tour
            animateToHost(hostTourIndex);
            
            hostTourInterval = setInterval(() => {{
                hostTourIndex = (hostTourIndex + 1) % hostNodes.length;
                animateToHost(hostTourIndex);
            }}, 4000); // 4 seconds per host for smooth transitions
        }}
        
        function pauseHostTour() {{
            isTourPlaying = false;
            const playBtn = document.getElementById('play-btn');
            playBtn.innerHTML = '▶ Play';
            playBtn.style.background = '#388E3C';
            
            if (hostTourInterval) {{
                clearInterval(hostTourInterval);
                hostTourInterval = null;
            }}
        }}
        
        function stopHostTour() {{
            pauseHostTour();
            hostTourIndex = 0;
            const stopBtn = document.getElementById('stop-btn');
            stopBtn.disabled = true;
            document.getElementById('tour-status').innerHTML = '';
            
            // Clear selection
            selectedNodeId = null;
            Graph.nodeThreeObject(n => createNodeWithLabel(n, n.__glowHighlight));
        }}
        
        function animateToHost(index) {{
            const node = hostNodes[index];
            if (!node) return;
            
            // Update status
            document.getElementById('tour-status').innerHTML = 
                `<span style="color: #00BFFF;">🎯 ${{index + 1}}/${{hostNodes.length}}: ${{node.label}}</span>`;
            
            // Select the node
            selectedNodeId = node.id;
            Graph.nodeThreeObject(n => createNodeWithLabel(n, n.__glowHighlight));
            
            // Animate camera to node with smooth orbit-style movement
            const distance = 150;
            const nodePos = {{ x: node.x || 0, y: node.y || 0, z: node.z || 0 }};
            const nodeDist = Math.hypot(nodePos.x, nodePos.y, nodePos.z) || 1;
            
            // Calculate camera position - slightly offset for cinematic effect
            const angle = (index * 0.3) % (Math.PI * 2); // Vary angle per host
            const cameraX = nodePos.x + Math.cos(angle) * distance;
            const cameraY = nodePos.y + distance * 0.5; // Slightly above
            const cameraZ = nodePos.z + Math.sin(angle) * distance;
            
            Graph.cameraPosition(
                {{ x: cameraX, y: cameraY, z: cameraZ }},
                nodePos,
                2500 // Longer, smoother animation duration
            );
            
            // Update info panel with full host synopsis
            const info = document.getElementById("selected-info");
            let infoHtml = `<strong>🎬 Touring Host ${{index + 1}}/${{hostNodes.length}}:</strong><br>` +
                          `ID: ${{node.id}}<br>` +
                          `Type: ${{node.group}}<br>` +
                          `Label: ${{node.label}}`;
            
            // Build host synopsis - find all connected child nodes
            const childLinks = graphData.links.filter(link => {{
                const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
                const targetId = typeof link.target === 'object' ? link.target.id : link.target;
                return sourceId === node.id || targetId === node.id;
            }});
            
            const childNodeIds = childLinks.map(link => {{
                const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
                const targetId = typeof link.target === 'object' ? link.target.id : link.target;
                return sourceId === node.id ? targetId : sourceId;
            }});
            
            const childNodes = graphData.nodes.filter(n => childNodeIds.includes(n.id));
            
            // Categorize child nodes
            const ports = childNodes.filter(n => n.group === 'port');
            const riskyPorts = childNodes.filter(n => n.group === 'risky_port');
            const shares = childNodes.filter(n => n.group === 'share');
            
            infoHtml += `<br><br><strong>📊 Host Synopsis:</strong>`;
            
            // Show risky ports first
            if (riskyPorts.length > 0) {{
                infoHtml += `<br><br><span style="color: #F44336;">⚠️ Risky Ports (${{riskyPorts.length}}):</span><br>`;
                riskyPorts.slice(0, 5).forEach(p => {{
                    const portNum = p.port || p.id.split("::")[1];
                    const portInfo = getPortDetails(parseInt(portNum));
                    infoHtml += `<span style="color: #F44336; margin-left: 10px;">• ${{portNum}} - ${{portInfo.description.split(' - ')[1] || 'Unknown'}}</span><br>`;
                }});
                if (riskyPorts.length > 5) {{
                    infoHtml += `<span style="color: #888; margin-left: 10px;">... and ${{riskyPorts.length - 5}} more</span><br>`;
                }}
            }}
            
            // Show safe ports
            if (ports.length > 0) {{
                infoHtml += `<br><span style="color: #2196F3;">🔌 Open Ports (${{ports.length}}):</span><br>`;
                ports.slice(0, 5).forEach(p => {{
                    const portNum = p.port || p.id.split("::")[1];
                    const portInfo = getPortDetails(parseInt(portNum));
                    infoHtml += `<span style="color: #2196F3; margin-left: 10px;">• ${{portNum}} - ${{portInfo.description.split(' - ')[1] || 'Unknown'}}</span><br>`;
                }});
                if (ports.length > 5) {{
                    infoHtml += `<span style="color: #888; margin-left: 10px;">... and ${{ports.length - 5}} more</span><br>`;
                }}
            }}
            
            // Show shares
            if (shares.length > 0) {{
                infoHtml += `<br><span style="color: #B71C1C;">📁 Shares (${{shares.length}}):</span><br>`;
                shares.slice(0, 5).forEach(s => {{
                    const shareName = s.label || s.id.split("::")[2] || 'Unknown';
                    infoHtml += `<span style="color: #B71C1C; margin-left: 10px;">• ${{shareName}}</span><br>`;
                }});
                if (shares.length > 5) {{
                    infoHtml += `<span style="color: #888; margin-left: 10px;">... and ${{shares.length - 5}} more</span><br>`;
                }}
            }}
            
            // Summary
            const totalItems = ports.length + riskyPorts.length + shares.length;
            infoHtml += `<br><span style="color: #888; font-size: 11px;">Total: ${{totalItems}} connected items</span>`;
            
            info.innerHTML = infoHtml;
        }}
        
        document.addEventListener('keydown', function(event) {{
            // Handle Escape key to clear search
            if (event.key === 'Escape') {{
                clearSearch();
                document.getElementById('search-input').blur();
                event.preventDefault();
                return;
            }}
            
            if (event.altKey) {{
                switch(event.key) {{
                    case 'c':
                    case 'C':
                        toggleControls();
                        event.preventDefault();
                        break;
                    case 'i':
                    case 'I':
                        toggleInfoPanel();
                        event.preventDefault();
                        break;
                    case 'l':
                    case 'L':
                        toggleLegend();
                        event.preventDefault();
                        break;
                    case 's':
                    case 'S':
                        // Focus search input
                        const searchInput = document.getElementById('search-input');
                        searchInput.focus();
                        searchInput.select();
                        event.preventDefault();
                        break;
                }}
            }}
        }});
        
        // Search functionality for 3D graph (some variables declared earlier for createNodeWithLabel)
        let searchResultsArray = []; // For navigation
        let currentSearchIndex = -1;
        const HIGHLIGHT_COLOR = '#00BFFF'; // Light blue
        
        function updateNavButtons() {{
            const prevBtn = document.getElementById('prev-btn');
            const nextBtn = document.getElementById('next-btn');
            const count = searchResultsArray.length;
            
            prevBtn.disabled = count === 0 || currentSearchIndex <= 0;
            nextBtn.disabled = count === 0 || currentSearchIndex >= count - 1;
        }}
        
        function navigateToNode(nodeId) {{
            // Find the node data
            const node = graphData.nodes.find(n => n.id === nodeId);
            if (!node) return;
            
            // Clear previous current node marker and set new one
            graphData.nodes.forEach(n => {{ n.__currentNode = false; }});
            node.__currentNode = true;
            
            // Refresh graph to update node labels (current node gets red label)
            Graph.nodeThreeObject(n => createNodeWithLabel(n, n.__glowHighlight));
            
            // Focus camera on the node with animation
            const distance = 150;
            const distRatio = 1 + distance / Math.hypot(node.x || 0, node.y || 0, node.z || 0);
            
            Graph.cameraPosition(
                {{ x: (node.x || 0) * distRatio, y: (node.y || 0) * distRatio, z: (node.z || 0) * distRatio }},
                node,
                1000 // Animation duration in ms
            );
            
            // Update info panel
            const info = document.getElementById("selected-info");
            info.innerHTML = `<strong>Navigated to:</strong><br>${{node.label}}<br><span style="color: #FF0000;">(${{currentSearchIndex + 1}} of ${{searchResultsArray.length}})</span>`;
        }}
        
        function navigatePrev() {{
            if (searchResultsArray.length === 0 || currentSearchIndex <= 0) return;
            currentSearchIndex--;
            navigateToNode(searchResultsArray[currentSearchIndex]);
            updateNavButtons();
            updateResultsDisplay();
        }}
        
        function navigateNext() {{
            if (searchResultsArray.length === 0 || currentSearchIndex >= searchResultsArray.length - 1) return;
            currentSearchIndex++;
            navigateToNode(searchResultsArray[currentSearchIndex]);
            updateNavButtons();
            updateResultsDisplay();
        }}
        
        function updateResultsDisplay() {{
            const resultsDiv = document.getElementById('search-results');
            const count = searchResultsArray.length;
            if (count > 0) {{
                resultsDiv.innerHTML = `<span style="color: #00BFFF;">✓ ${{currentSearchIndex + 1}} of ${{count}} match${{count > 1 ? 'es' : ''}} (with glow)</span>`;
            }}
        }}
        
        function performSearch(searchTerm) {{
            // Clear previous highlights
            clearSearchHighlights();
            currentSearchIndex = -1;
            searchResultsArray = [];
            
            const resultsDiv = document.getElementById('search-results');
            
            if (!searchTerm || searchTerm.trim() === '') {{
                resultsDiv.innerHTML = '';
                updateNavButtons();
                return;
            }}
            
            const term = searchTerm.toLowerCase().trim();
            let matchCount = 0;
            
            // Search through all nodes
            graphData.nodes.forEach(node => {{
                const matchesId = node.id.toLowerCase().includes(term);
                const matchesLabel = node.label.toLowerCase().includes(term);
                const matchesDescription = node.description && typeof node.description === 'string' && node.description.toLowerCase().includes(term);
                const matchesGroup = node.group.toLowerCase().includes(term);
                
                if (matchesId || matchesLabel || matchesDescription || matchesGroup) {{
                    searchHighlightedNodes.add(node.id);
                    searchResultsArray.push(node.id);
                    node.__glowHighlight = true; // Enable glow effect (keep original color)
                    matchCount++;
                }}
            }});
            
            // Set search active flag for dimming non-highlighted nodes
            searchActive = matchCount > 0;
            
            // Refresh the graph to show updated nodes with glow and labels
            Graph.nodeThreeObject(node => createNodeWithLabel(node, node.__glowHighlight));
            
            // Force refresh links by re-setting linkColor and linkOpacity with new functions
            Graph
                .linkColor(link => {{
                    if (searchActive && !isLinkHighlighted(link)) {{
                        return '#333333';
                    }}
                    return link.color || '#FFFF00';
                }})
                .linkOpacity(link => {{
                    if (searchActive && !isLinkHighlighted(link)) {{
                        return 0.1;
                    }}
                    return 0.6;
                }});
            
            // Update results display and navigation
            if (matchCount > 0) {{
                currentSearchIndex = 0;
                resultsDiv.innerHTML = `<span style="color: #00BFFF;">✓ 1 of ${{matchCount}} match${{matchCount > 1 ? 'es' : ''}} (with glow)</span>`;
                navigateToNode(searchResultsArray[0]);
            }} else {{
                resultsDiv.innerHTML = `<span style="color: #FF6B6B;">✗ No matches found</span>`;
            }}
            updateNavButtons();
        }}
        
        function clearSearchHighlights() {{
            // Remove glow and current node marker (no color restoration needed)
            searchActive = false; // Clear search active flag
            graphData.nodes.forEach(node => {{
                node.__glowHighlight = false; // Disable glow effect
                node.__currentNode = false; // Clear current node marker
            }});
            searchHighlightedNodes.clear();
            searchResultsArray = [];
            
            // Refresh the graph - reset to normal rendering with labels
            Graph.nodeThreeObject(node => createNodeWithLabel(node, node.__glowHighlight));
            
            // Force refresh links to restore original colors
            Graph
                .linkColor(link => link.color || '#FFFF00')
                .linkOpacity(0.6);
        }}
        
        function clearSearch() {{
            const searchInput = document.getElementById('search-input');
            const resultsDiv = document.getElementById('search-results');
            
            searchInput.value = '';
            resultsDiv.innerHTML = '';
            clearSearchHighlights();
            currentSearchIndex = -1;
            updateNavButtons();
        }}
        
        console.log("✅ 3D force-directed graph loaded successfully!");
    </script>
</body>
</html>
        """
        
        return html_content
    
    def save_and_show(self, filename: str = "custom_network_graph_3d.html", scan_data: Dict = None, auto_open: bool = True):
        """
        Save the 3D HTML file with embedded scan data and optionally open it in the browser.
        """
        html_content = self.generate_html(scan_data=scan_data)
        
        filepath = os.path.abspath(filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ 3D force-directed graph saved to: {filepath}")
        print(f"📊 Graph contains {len(self.nodes)} nodes and {len(self.links)} links")
        if scan_data:
            print(f"📄 Scan results embedded in HTML for self-contained analysis")
        
        if auto_open:
            try:
                webbrowser.open(f"file://{filepath}")
            except Exception as e:
                print(f"⚠️ Could not auto-open browser: {e}")
                print(f"📂 Manually open: {filepath}")
        
        return filepath
    
    def save_html(self, filename: str = "custom_network_graph_3d.html", scan_data: Dict = None):
        """
        Save the 3D HTML file without opening in browser (for live mode updates).
        """
        html_content = self.generate_html(scan_data=scan_data)
        filepath = os.path.abspath(filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return filepath

def create_custom_3d_graph_from_scan(scan_results: Dict[str, List[int]], share_results: Dict[str, List[str]] = None, host_details: Dict = None):
    """
    Helper function to create a custom 3D graph from scan results.
    """
    graph = CustomD3Force3DGraph()
    graph.generate_from_scan_results(scan_results, share_results, host_details)
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