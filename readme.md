# Web Application Reconnaissance Tool

A powerful security tool for performing comprehensive reconnaissance on web applications. This tool helps identify potential security issues by gathering information about a target web application in a non-intrusive manner.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- **DNS Enumeration**
  - A, AAAA, MX, NS, TXT, SOA, and CNAME record analysis
  - Subdomain enumeration
  - DNS security checks

- **Port Scanning**
  - Common web ports scanning
  - Service detection
  - Multi-threaded scanning

- **Web Technology Fingerprinting**
  - Framework detection
  - JavaScript library detection
  - CMS identification
  - Server software detection

- **Security Analysis**
  - HTTP headers analysis
  - SSL/TLS configuration analysis
  - Security headers check
  - Cookie security analysis

- **Content Discovery**
  - Directory/path discovery
  - Common web directories scanning
  - Robots.txt and sitemap.xml analysis
  - API endpoint discovery

- **Vulnerability Checks**
  - Basic XSS detection
  - SQL injection testing
  - Directory listing checks
  - CORS misconfiguration detection
  - WAF detection

- **JavaScript Analysis**
  - Endpoint discovery
  - Secret detection
  - API key identification
  - Sensitive information scanning

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/web-recon.git
cd web-recon
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python web_recon.py -u https://example.com
```

### Command Line Options

- `-u, --url`: Target URL (required)
- `-o, --output`: Output file (JSON format)
- `-t, --threads`: Number of threads (default: 5)
- `--timeout`: Request timeout in seconds (default: 10)
- `-v, --verbose`: Enable verbose output
- `-i, --interactive`: Run in interactive mode

### Examples

1. Basic scan with output file:
```bash
python web_recon.py -u https://example.com -o results.json
```

2. Interactive mode:
```bash
python web_recon.py -u https://example.com -i
```

3. Verbose output with custom threads:
```bash
python web_recon.py -u https://example.com -v -t 10
```

### Interactive Mode Commands

1. `dns` - DNS Enumeration
2. `ports` - Port Scanning
3. `headers` - HTTP Headers Analysis
4. `methods` - HTTP Methods Detection
5. `ssl` - SSL/TLS Analysis
6. `dirs` - Directory Discovery
7. `robots` - Robots.txt & Sitemap Analysis
8. `techs` - Technology Fingerprinting
9. `apis` - API Endpoint Discovery
10. `js` - JavaScript Analysis
11. `cors` - CORS Misconfiguration Check
12. `waf` - WAF Detection
13. `vulns` - Basic Vulnerability Checks
14. `subdomains` - Subdomain Enumeration
15. `all` - Run All Modules
16. `save` - Save Results to File

## Output

The tool generates two types of reports:

1. **JSON Report**: Contains all raw data in JSON format
2. **HTML Report**: A beautifully formatted HTML report with:
   - Target summary
   - DNS information
   - Open ports
   - HTTP headers
   - Technologies detected
   - Subdomains discovered
   - Potential vulnerabilities
   - WAF detection results
   - API endpoints
   - CORS misconfigurations
   - JavaScript analysis results

## Security Notice

This tool is designed for security research and authorized penetration testing only. Always:

- Obtain proper authorization before testing any website
- Respect robots.txt directives
- Follow responsible disclosure practices
- Do not use for malicious purposes

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Made by viphacker100

## Disclaimer

This tool is for educational and authorized security testing purposes only. The author is not responsible for any misuse or damage caused by this program.
