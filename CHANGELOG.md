# Changelog

All notable changes to Network Vector will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-11-06

### Added
- Initial release of Network Vector
- Raw TCP port scanning for 998 unique ports
- Multi-threaded scanning with configurable thread count (up to 200)
- Interactive D3.js force-directed graph visualizations
- Network topology discovery with CIDR-based hierarchy
- SMB share enumeration for Windows/Linux systems
- Hostname resolution with reverse DNS lookup
- Professional network and host icons (SVG/PNG)
- Comprehensive port information database (130+ services)
- Color-coded security risk assessment for ports
- Interactive port descriptions with educational links
- Sticky node behavior in visualizations
- Right-click collapse/expand functionality for network nodes
- Self-contained HTML output with embedded base64 assets
- JSON export of scan results
- Cross-platform compatibility (Windows, Linux, macOS)
- Standalone executable generation with PyInstaller
- Command-line interface with extensive options
- Security-focused design with ethical use guidelines

### Security
- Implements responsible disclosure guidelines
- Includes security policy and best practices
- Designed for authorized network testing only
- Rate limiting and timeout controls to prevent abuse

### Documentation
- Comprehensive README with usage examples
- API documentation for developers
- Contributing guidelines for open source collaboration
- Security policy and vulnerability reporting process
- Quick start examples and tutorials

### Technical Features
- Pure Python implementation using only standard library
- Socket-based TCP connection scanning
- Modular architecture with separation of concerns
- Base64 embedding for self-contained visualizations
- Professional network topology representation
- Risk-based port classification system
- Educational security assessment information