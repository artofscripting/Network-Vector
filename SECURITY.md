# Security Policy

## Supported Versions

We actively support the following versions of Network Vector:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

The Network Vector team takes security bugs seriously. We appreciate your efforts to responsibly disclose your findings, and will make every effort to acknowledge your contributions.

### How to Report Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: [security@artofscripting.com](mailto:security@artofscripting.com)

If you prefer to use encryption, you can use our PGP key (if available).

Include the following information in your report:

- Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

This information will help us triage your report more quickly.

### Response Timeline

- **Acknowledgment**: Within 72 hours
- **Initial Assessment**: Within 1 week
- **Regular Updates**: Every 2 weeks until resolution
- **Resolution Target**: Critical issues within 30 days, others within 90 days

### Safe Harbor

We support safe harbor for security researchers who:

- Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our services
- Only interact with accounts you own or with explicit permission of the account holder
- Do not access, modify, or delete data belonging to others
- Contact us immediately if you inadvertently access sensitive data
- Do not share or publicize unresolved vulnerabilities with others

## Security Best Practices for Users

### Network Scanning Ethics
- Only scan networks you own or have explicit permission to test
- Be aware that port scanning may trigger security monitoring systems
- Use appropriate rate limiting to avoid overwhelming target systems

### Running Network Vector Safely
- Run with minimal privileges when possible
- Use timeouts and thread limits appropriate for your network
- Monitor your scanning activity for unintended behavior
- Keep the software updated to the latest version

### Data Protection
- Scan results may contain sensitive network information
- Secure storage of scan outputs is your responsibility
- Consider the privacy implications of hostname resolution and share enumeration

## Scope

This security policy applies to:
- The core Network Vector application (`src/nvector.py`)
- The visualization module (`src/custom_d3_graph.py`)
- Generated HTML outputs and their embedded JavaScript
- Distribution packages and executables

Out of scope:
- Third-party dependencies (report directly to their maintainers)
- User-specific configurations or custom modifications
- Issues arising from misuse contrary to documentation

## Attribution

We believe in recognizing security researchers who help improve our software. With your permission, we will:
- Credit you in our security advisories
- Include your name in our Hall of Fame (if we create one)
- Provide you with early access to fixes for verification

Thank you for helping keep Network Vector and our users safe!