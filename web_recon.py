#!/usr/bin/env python3
"""
Web Application Reconnaissance Tool

A security tool for performing reconnaissance on web applications.
This tool helps identify potential security issues by gathering information
about a target web application in a non-intrusive manner.

Made by viphacker100

Usage:
  python web_recon.py -u https://example.com [options]

Features:
  - DNS enumeration
  - Port scanning (common web ports)
  - Web technology fingerprinting
  - Directory/path discovery
  - Headers analysis
  - SSL/TLS analysis
  - Basic robots.txt and sitemap.xml analysis
  - HTTP methods discovery
"""

import argparse
import concurrent.futures
import dns.resolver
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Requests module not found. Install it using: pip install requests")
    sys.exit(1)

VERSION = "1.0.0"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Common web ports to scan
WEB_PORTS = [80, 443, 8080, 8443, 3000, 8000, 8008, 8800, 8888]

# Common directories to check
COMMON_DIRS = [
    "admin", "login", "wp-admin", "administrator", "phpmyadmin",
    "dashboard", "api", "v1", "v2", "api/v1", "api/v2",
    "backup", "db", "database", "dev", "development", 
    "test", "testing", "staging", "prod", "config", 
    "setup", "install", "wp-content", "wp-includes",
    "uploads", "bak", "old", "new", "temp", "assets"
]

class ColorOutput:
    """Class for colored terminal output"""
    
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    @staticmethod
    def info(message):
        """Print info message"""
        print(f"{ColorOutput.BLUE}[*]{ColorOutput.ENDC} {message}")
    
    @staticmethod
    def success(message):
        """Print success message"""
        print(f"{ColorOutput.GREEN}[+]{ColorOutput.ENDC} {message}")
    
    @staticmethod
    def warning(message):
        """Print warning message"""
        print(f"{ColorOutput.YELLOW}[!]{ColorOutput.ENDC} {message}")
    
    @staticmethod
    def error(message):
        """Print error message"""
        print(f"{ColorOutput.RED}[-]{ColorOutput.ENDC} {message}")
    
    @staticmethod
    def section(title):
        """Print section title"""
        print(f"\n{ColorOutput.BOLD}{ColorOutput.UNDERLINE}{title}{ColorOutput.ENDC}\n")


class WebRecon:
    """Main class for web application reconnaissance"""
    
    def __init__(self, url, output=None, threads=5, timeout=10, verbose=False):
        """Initialize the class with the target URL and options"""
        self.target_url = self._normalize_url(url)
        self.domain = urllib.parse.urlparse(self.target_url).netloc.split(':')[0]
        self.output_file = output
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.results = {
            "target": self.target_url,
            "domain": self.domain,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "dns_info": {},
            "open_ports": [],
            "technologies": {},
            "headers": {},
            "methods": [],
            "ssl_info": {},
            "directories": [],
            "robots_sitemap": {}
        }
    
    def _normalize_url(self, url):
        """Normalize URL format"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    def run(self):
        """Run all reconnaissance modules"""
        ColorOutput.section(f"Starting Web Reconnaissance on {self.target_url}")
        ColorOutput.info(f"Target domain: {self.domain}")
        
        try:
            # Run modules
            self._dns_enumeration()
            self._port_scanning()
            self._analyze_headers()
            self._detect_methods()
            self._analyze_ssl()
            self._check_robots_sitemap()
            self._directory_discovery()
            self._advanced_fingerprinting()
            self._subdomain_enumeration()
            self._vulnerability_checks()
            self._detect_waf()
            self._api_discovery()
            self._check_cors_misconfig()
            self._js_analysis()
            
            # Write results to file if specified
            if self.output_file:
                self._write_results()
                self.generate_html_report()
                
            ColorOutput.section("Reconnaissance Complete")
            
        except KeyboardInterrupt:
            ColorOutput.warning("Reconnaissance aborted by user.")
            # Still write collected results
            if self.output_file:
                self._write_results()
                self.generate_html_report()
            return False
            
        return True
    
    def _write_results(self):
        """Write results to output file"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=4)
            ColorOutput.success(f"Results saved to {self.output_file}")
        except Exception as e:
            ColorOutput.error(f"Error writing results to file: {str(e)}")
    
    def _dns_enumeration(self):
        """Perform DNS enumeration"""
        ColorOutput.section("DNS Enumeration")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                ColorOutput.info(f"Querying {record_type} records...")
                answers = dns.resolver.resolve(self.domain, record_type)
                
                results = []
                for rdata in answers:
                    results.append(str(rdata))
                    ColorOutput.success(f"{record_type} record: {rdata}")
                
                self.results["dns_info"][record_type] = results
                
            except dns.resolver.NoAnswer:
                ColorOutput.warning(f"No {record_type} records found")
            except dns.resolver.NXDOMAIN:
                ColorOutput.error(f"Domain {self.domain} does not exist")
                break
            except Exception as e:
                ColorOutput.error(f"Error querying {record_type} records: {str(e)}")
    
    def _check_port(self, port):
        """Check if a specific port is open"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            result = sock.connect_ex((self.domain, port))
            if result == 0:
                return port
        except Exception:
            pass
        finally:
            sock.close()
        
        return None
    
    def _port_scanning(self):
        """Scan common web ports"""
        ColorOutput.section("Port Scanning (Common Web Ports)")
        ColorOutput.info(f"Scanning {len(WEB_PORTS)} common web ports...")
        
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self._check_port, port): port for port in WEB_PORTS}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                
                try:
                    result = future.result()
                    if result:
                        ColorOutput.success(f"Port {port} - OPEN")
                        open_ports.append(port)
                    elif self.verbose:
                        ColorOutput.error(f"Port {port} - CLOSED")
                except Exception as e:
                    ColorOutput.error(f"Error scanning port {port}: {str(e)}")
        
        self.results["open_ports"] = open_ports
    
    def _analyze_headers(self):
        """Analyze HTTP headers"""
        ColorOutput.section("HTTP Headers Analysis")
        
        try:
            response = requests.get(
                self.target_url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            ColorOutput.info(f"HTTP Status: {response.status_code}")
            
            # Analyze interesting headers
            sensitive_headers = [
                "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
                "X-Generator", "X-Runtime", "X-Version", "X-Framework",
                "X-Content-Type-Options", "X-XSS-Protection", "X-Frame-Options",
                "Content-Security-Policy", "Strict-Transport-Security"
            ]
            
            # Check for security headers
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-XSS-Protection": "1; mode=block",
                "X-Frame-Options": ["DENY", "SAMEORIGIN"],
                "Content-Security-Policy": True,  # Just check if present
                "Strict-Transport-Security": True  # Just check if present
            }
            
            for header, value in response.headers.items():
                self.results["headers"][header] = value
                
                if header in sensitive_headers:
                    ColorOutput.success(f"{header}: {value}")
                
                # Check for missing or misconfigured security headers
                if header in security_headers:
                    if isinstance(security_headers[header], list):
                        if value not in security_headers[header]:
                            ColorOutput.warning(f"Security header {header} has potentially insecure value: {value}")
                    elif isinstance(security_headers[header], bool):
                        ColorOutput.success(f"Security header {header} is present: {value}")
            
            # Check for missing security headers
            for header in security_headers:
                if header not in response.headers:
                    ColorOutput.warning(f"Missing security header: {header}")
            
            # Check for cookies without secure flags
            if response.cookies:
                for cookie in response.cookies:
                    cookie_info = f"Cookie: {cookie.name}"
                    if not cookie.secure:
                        cookie_info += " (missing Secure flag)"
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        cookie_info += " (missing HttpOnly flag)"
                    
                    if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly'):
                        ColorOutput.warning(cookie_info)
                    else:
                        ColorOutput.success(cookie_info)
            
            # Technology fingerprinting based on headers
            tech_signatures = {
                "PHP": ["X-Powered-By: PHP", "Set-Cookie: PHPSESSID"],
                "ASP.NET": ["X-AspNet-Version", "ASP.NET", "X-AspNetMvc-Version"],
                "Apache": ["Server: Apache"],
                "nginx": ["Server: nginx"],
                "Express.js": ["X-Powered-By: Express"],
                "Django": ["X-Frame-Options: SAMEORIGIN", "Vary: Cookie"],
                "Ruby on Rails": ["X-Runtime", "X-Powered-By: Rails"],
                "Laravel": ["Set-Cookie: laravel_session"],
                "WordPress": ["wp-content", "wp-includes", "WordPress"],
                "Drupal": ["X-Generator: Drupal", "X-Drupal-"],
                "Joomla": ["Set-Cookie: joomla", "X-Content-Encoded-By: Joomla"]
            }
            
            # Check response data and headers for technology signatures
            header_data = str(response.headers)
            content = response.text[:4096]  # Check first part of content
            
            for tech, signatures in tech_signatures.items():
                for sig in signatures:
                    if sig.lower() in header_data.lower() or sig.lower() in content.lower():
                        ColorOutput.success(f"Detected technology: {tech}")
                        self.results["technologies"][tech] = True
                        break
            
        except requests.exceptions.RequestException as e:
            ColorOutput.error(f"Error analyzing headers: {str(e)}")
    
    def _detect_methods(self):
        """Detect allowed HTTP methods"""
        ColorOutput.section("HTTP Methods Detection")
        
        methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"]
        allowed_methods = []
        
        # Try OPTIONS method first
        try:
            response = requests.options(
                self.target_url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            
            if 'Allow' in response.headers:
                allowed = response.headers['Allow'].split(', ')
                ColorOutput.success(f"Allowed methods (from OPTIONS): {', '.join(allowed)}")
                allowed_methods = allowed
            else:
                # Try each method individually
                ColorOutput.info("Testing methods individually...")
                for method in methods:
                    try:
                        response = requests.request(
                            method,
                            self.target_url,
                            headers={"User-Agent": USER_AGENT},
                            timeout=self.timeout,
                            verify=False
                        )
                        
                        # If we don't get a 405 Method Not Allowed, the method is likely supported
                        if response.status_code != 405:
                            ColorOutput.success(f"Method {method} - Allowed (Status: {response.status_code})")
                            allowed_methods.append(method)
                        elif self.verbose:
                            ColorOutput.warning(f"Method {method} - Not Allowed")
                            
                    except requests.exceptions.RequestException:
                        pass
        
        except requests.exceptions.RequestException as e:
            ColorOutput.error(f"Error detecting methods: {str(e)}")
        
        # Check for potentially dangerous methods
        dangerous_methods = ["PUT", "DELETE", "TRACE"]
        for method in dangerous_methods:
            if method in allowed_methods:
                ColorOutput.warning(f"Potentially dangerous method allowed: {method}")
        
        self.results["methods"] = allowed_methods
    
    def _analyze_ssl(self):
        """Analyze SSL/TLS configuration"""
        ColorOutput.section("SSL/TLS Analysis")
        
        # Only analyze HTTPS URLs
        if not self.target_url.startswith("https://"):
            ColorOutput.warning("Target is not using HTTPS, skipping SSL/TLS analysis")
            return
        
        try:
            hostname = self.domain
            port = 443
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_OPTIONAL
            
            ColorOutput.info(f"Connecting to {hostname}:{port}...")
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Extract certificate information
                    not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                    not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    
                    # Check certificate expiration
                    now = datetime.now()
                    days_left = (not_after - now).days
                    
                    self.results["ssl_info"] = {
                        "version": version,
                        "cipher": cipher[0],
                        "issuer": issuer.get('organizationName', 'Unknown'),
                        "subject": subject.get('commonName', 'Unknown'),
                        "valid_from": str(not_before),
                        "valid_until": str(not_after),
                        "days_remaining": days_left
                    }
                    
                    ColorOutput.success(f"SSL/TLS Version: {version}")
                    ColorOutput.success(f"Cipher: {cipher[0]}")
                    ColorOutput.success(f"Issuer: {issuer.get('organizationName', 'Unknown')}")
                    ColorOutput.success(f"Subject: {subject.get('commonName', 'Unknown')}")
                    ColorOutput.success(f"Valid From: {not_before}")
                    ColorOutput.success(f"Valid Until: {not_after}")
                    
                    if days_left < 0:
                        ColorOutput.error(f"Certificate EXPIRED ({abs(days_left)} days ago)")
                    elif days_left < 30:
                        ColorOutput.warning(f"Certificate expires soon ({days_left} days remaining)")
                    else:
                        ColorOutput.success(f"Certificate valid ({days_left} days remaining)")
                    
                    # Check for weak protocols (requires OpenSSL for complete check)
                    weak_protocols = ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]
                    if any(proto in version for proto in weak_protocols):
                        ColorOutput.warning(f"Weak protocol detected: {version}")
                    
                    # Check for domain mismatch
                    alt_names = []
                    if 'subjectAltName' in cert:
                        for type_name, value in cert['subjectAltName']:
                            if type_name == 'DNS':
                                alt_names.append(value)
                    
                    self.results["ssl_info"]["subject_alt_names"] = alt_names
                    
                    if hostname not in subject.get('commonName', '') and not any(hostname == name for name in alt_names):
                        ColorOutput.warning(f"Hostname mismatch: {hostname} not found in certificate")
        
        except ssl.SSLError as e:
            ColorOutput.error(f"SSL Error: {str(e)}")
        except socket.error as e:
            ColorOutput.error(f"Socket Error: {str(e)}")
        except Exception as e:
            ColorOutput.error(f"Error analyzing SSL/TLS: {str(e)}")
    
    def _check_robots_sitemap(self):
        """Check robots.txt and sitemap.xml"""
        ColorOutput.section("Robots.txt and Sitemap.xml Analysis")
        
        results = {}
        
        # Check robots.txt
        robots_url = f"{self.target_url}/robots.txt"
        ColorOutput.info(f"Checking {robots_url}")
        
        try:
            response = requests.get(
                robots_url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200 and 'text/plain' in response.headers.get('Content-Type', ''):
                ColorOutput.success("Found robots.txt")
                
                disallowed = []
                sitemaps = []
                
                for line in response.text.splitlines():
                    line = line.strip().lower()
                    
                    if line.startswith('disallow:'):
                        path = line[len('disallow:'):].strip()
                        if path:
                            disallowed.append(path)
                            ColorOutput.warning(f"Disallowed path: {path}")
                    
                    elif line.startswith('sitemap:'):
                        sitemap_url = line[len('sitemap:'):].strip()
                        if sitemap_url:
                            sitemaps.append(sitemap_url)
                            ColorOutput.success(f"Sitemap reference: {sitemap_url}")
                
                results["robots_txt"] = {
                    "found": True,
                    "disallowed_paths": disallowed,
                    "sitemap_references": sitemaps
                }
            else:
                ColorOutput.warning("No robots.txt found or it's not a text file")
                results["robots_txt"] = {"found": False}
        
        except requests.exceptions.RequestException as e:
            ColorOutput.error(f"Error checking robots.txt: {str(e)}")
            results["robots_txt"] = {"found": False, "error": str(e)}
        
        # Check sitemap.xml
        sitemap_url = f"{self.target_url}/sitemap.xml"
        ColorOutput.info(f"Checking {sitemap_url}")
        
        try:
            response = requests.get(
                sitemap_url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200 and ('application/xml' in response.headers.get('Content-Type', '') or 
                                               'text/xml' in response.headers.get('Content-Type', '')):
                ColorOutput.success("Found sitemap.xml")
                
                # Very basic parsing - for a real tool, use proper XML parsing
                urls_count = response.text.count('<loc>')
                ColorOutput.success(f"Sitemap contains approximately {urls_count} URLs")
                
                results["sitemap_xml"] = {
                    "found": True,
                    "approximate_url_count": urls_count
                }
            else:
                ColorOutput.warning("No sitemap.xml found or it's not an XML file")
                results["sitemap_xml"] = {"found": False}
        
        except requests.exceptions.RequestException as e:
            ColorOutput.error(f"Error checking sitemap.xml: {str(e)}")
            results["sitemap_xml"] = {"found": False, "error": str(e)}
        
        self.results["robots_sitemap"] = results
    
    def _directory_discovery(self):
        """Discover common directories"""
        ColorOutput.section("Directory Discovery")
        ColorOutput.info(f"Testing {len(COMMON_DIRS)} common directories...")
        
        found_dirs = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for directory in COMMON_DIRS:
                target_url = f"{self.target_url}/{directory}"
                futures.append(executor.submit(self._check_directory, target_url, directory))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        found_dirs.append(result)
                except Exception as e:
                    if self.verbose:
                        ColorOutput.error(f"Error in directory discovery: {str(e)}")
        
        self.results["directories"] = found_dirs
    
    def _check_directory(self, url, directory):
        """Check if a directory exists"""
        try:
            response = requests.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False,
                allow_redirects=False  # Don't follow redirects for directory discovery
            )
            
            # Consider 2xx, 3xx, and some 4xx as "found"
            if response.status_code < 404 or response.status_code in [401, 403]:
                status_info = ""
                if response.status_code == 200:  # OK
                    status_info = "OK"
                elif response.status_code == 401:  # Unauthorized
                    status_info = "Unauthorized"
                elif response.status_code == 403:  # Forbidden
                    status_info = "Forbidden"
                elif 300 <= response.status_code < 400:  # Redirect
                    status_info = f"Redirect to {response.headers.get('Location', 'unknown')}"
                
                ColorOutput.success(f"/{directory}/ - Found (Status: {response.status_code} {status_info})")
                
                return {
                    "path": f"/{directory}/",
                    "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type", "unknown"),
                    "content_length": len(response.content)
                }
        
        except requests.exceptions.RequestException:
            # Silently ignore errors unless verbose
            if self.verbose:
                ColorOutput.error(f"Error checking directory /{directory}/")
        
        return None

    def _advanced_fingerprinting(self):
        """Advanced web technology fingerprinting"""
        ColorOutput.section("Advanced Technology Fingerprinting")
        
        try:
            response = requests.get(
                self.target_url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            
            # Extract JavaScript library references
            js_patterns = {
                "jQuery": r'jquery[.-](\d+\.\d+\.\d+)',
                "React": r'react[.-](\d+\.\d+\.\d+)',
                "Angular": r'angular[.-](\d+\.\d+\.\d+)',
                "Vue.js": r'vue[.-](\d+\.\d+\.\d+)',
                "Bootstrap": r'bootstrap[.-](\d+\.\d+\.\d+)',
                "Lodash": r'lodash[.-](\d+\.\d+\.\d+)',
            }
            
            for tech, pattern in js_patterns.items():
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    version = matches[0]
                    ColorOutput.success(f"Detected {tech} version {version}")
                    self.results["technologies"][tech] = version
            
            # Check for common frameworks by HTML patterns
            framework_patterns = {
                "WordPress": [r'wp-content', r'wp-includes', r'wordpress'],
                "Drupal": [r'drupal\.js', r'drupal\.css', r'Drupal\.settings'],
                "Joomla": [r'joomla', r'com_content', r'com_contact'],
                "Magento": [r'magento', r'Mage\.', r'skin/frontend'],
                "Laravel": [r'laravel', r'csrf-token'],
                "Django": [r'csrfmiddlewaretoken', r'django'],
            }
            
            for framework, patterns in framework_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        ColorOutput.success(f"Detected {framework} framework")
                        self.results["technologies"][framework] = True
                        break
                        
        except requests.exceptions.RequestException as e:
            ColorOutput.error(f"Error in advanced fingerprinting: {str(e)}")

    def _subdomain_enumeration(self):
        """Enumerate subdomains using various techniques"""
        ColorOutput.section("Subdomain Enumeration")
        
        # Extract root domain
        domain_parts = self.domain.split('.')
        if len(domain_parts) > 2:
            root_domain = '.'.join(domain_parts[-2:])
        else:
            root_domain = self.domain
        
        ColorOutput.info(f"Enumerating subdomains for {root_domain}")
        
        subdomains = set()
        
        # Method 1: DNS brute force with common subdomains
        common_subdomains = ["www", "mail", "ftp", "webmail", "login", "admin", "test", 
                         "dev", "staging", "api", "portal", "blog", "shop", "store",
                         "support", "help", "forum", "news", "app", "m", "mobile",
                         "secure", "vpn", "internal", "cdn", "media", "images", "docs"]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {executor.submit(self._check_subdomain, f"{sub}.{root_domain}"): sub 
                                  for sub in common_subdomains}
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                
                try:
                    result = future.result()
                    if result:
                        subdomains.add(result)
                        ColorOutput.success(f"Found subdomain: {result}")
                except Exception as e:
                    if self.verbose:
                        ColorOutput.error(f"Error checking subdomain {subdomain}: {str(e)}")
        
        self.results["subdomains"] = list(subdomains)
        ColorOutput.success(f"Found {len(subdomains)} subdomains")

    def _check_subdomain(self, hostname):
        """Check if a subdomain resolves"""
        try:
            socket.gethostbyname(hostname)
            return hostname
        except socket.error:
            return None

    def _vulnerability_checks(self):
        """Basic checks for common vulnerabilities"""
        ColorOutput.section("Basic Vulnerability Checks")
        
        vulnerabilities = []
        
        # Check for Cross-Site Scripting (XSS) reflected in error pages
        test_payloads = [
            "<script>alert(1)</script>",
            "1'\"<script>alert(1)</script>",
            "\"><script>alert(1)</script>"
        ]
        
        ColorOutput.info("Testing for basic XSS vulnerabilities")
        
        for payload in test_payloads:
            test_url = f"{self.target_url}/?test={urllib.parse.quote(payload)}"
            try:
                response = requests.get(
                    test_url,
                    headers={"User-Agent": USER_AGENT},
                    timeout=self.timeout,
                    verify=False
                )
                
                if payload in response.text:
                    vuln = {
                        "type": "Potential XSS",
                        "url": test_url,
                        "details": f"Payload was reflected in the response: {payload}"
                    }
                    vulnerabilities.append(vuln)
                    ColorOutput.warning(f"Potential XSS found at: {test_url}")
                    break
            except requests.exceptions.RequestException:
                pass
        
        # Check for SQL Injection
        sql_payloads = ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1"]
        
        ColorOutput.info("Testing for basic SQL Injection vulnerabilities")
        
        for payload in sql_payloads:
            test_url = f"{self.target_url}/?id={urllib.parse.quote(payload)}"
            try:
                response = requests.get(
                    test_url,
                    headers={"User-Agent": USER_AGENT},
                    timeout=self.timeout,
                    verify=False
                )
                
                # Check for SQL error messages
                sql_errors = [
                    "SQL syntax", "mysql_fetch_array", "ORA-", "Oracle Error",
                    "PostgreSQL ERROR", "SQLite3::", "Microsoft OLE DB Provider for SQL Server"
                ]
                
                for error in sql_errors:
                    if error in response.text:
                        vuln = {
                            "type": "Potential SQL Injection",
                            "url": test_url,
                            "details": f"SQL error detected: {error}"
                        }
                        vulnerabilities.append(vuln)
                        ColorOutput.warning(f"Potential SQL Injection found at: {test_url}")
                        break
            except requests.exceptions.RequestException:
                pass
        
        # Check for security misconfigurations
        ColorOutput.info("Checking for security misconfigurations")
        
        # Test for directory listing
        common_dirs_listing = ["images", "uploads", "files", "backup", "data"]
        for directory in common_dirs_listing:
            test_url = f"{self.target_url}/{directory}/"
            try:
                response = requests.get(
                    test_url,
                    headers={"User-Agent": USER_AGENT},
                    timeout=self.timeout,
                    verify=False
                )
                
                dir_listing_indicators = [
                    "Index of /", "Directory Listing For", "Parent Directory",
                    "<title>Index of", "Last modified</a>"
                ]
                
                for indicator in dir_listing_indicators:
                    if indicator in response.text:
                        vuln = {
                            "type": "Directory Listing",
                            "url": test_url,
                            "details": "Directory listing is enabled"
                        }
                        vulnerabilities.append(vuln)
                        ColorOutput.warning(f"Directory listing found at: {test_url}")
                        break
            except requests.exceptions.RequestException:
                pass
        
        self.results["vulnerabilities"] = vulnerabilities

    def _detect_waf(self):
        """Detect Web Application Firewall presence"""
        ColorOutput.section("WAF Detection")
        
        # WAF signatures to check
        waf_signatures = {
            "Cloudflare": [
                "cf-ray",  # Header
                "__cfduid",  # Cookie
                "cloudflare-nginx"  # Server header
            ],
            "AWS WAF/Shield": [
                "awselb",
                "x-amzn-",
                "x-amz-cf-id"
            ],
            "Akamai": [
                "akamaighost",
                "ak_bmsc",
                "x-akamai"
            ],
            "Imperva/Incapsula": [
                "incap_ses",
                "visid_incap",
                "_incapsula_"
            ],
            "F5 BIG-IP ASM": [
                "BigIP",
                "F5-TrafficShield",
                "TS"
            ],
            "Sucuri": [
                "sucuri",
                "x-sucuri"
            ]
        }
        
        ColorOutput.info("Checking for WAF presence...")
        detected_wafs = []
        
        # Normal request
        try:
            response = requests.get(
                self.target_url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            
            # Check response headers and cookies
            headers_str = str(response.headers).lower()
            cookies_str = str(response.cookies).lower()
            
            for waf_name, signatures in waf_signatures.items():
                for signature in signatures:
                    sig_lower = signature.lower()
                    if sig_lower in headers_str or sig_lower in cookies_str:
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)
                            ColorOutput.warning(f"Detected {waf_name} WAF")
        except requests.exceptions.RequestException as e:
            ColorOutput.error(f"Error in WAF detection: {str(e)}")
        
        # If no WAF detected with normal request, try potentially malicious request
        if not detected_wafs:
            try:
                # Use a request that might trigger WAF
                malicious_headers = {
                    "User-Agent": USER_AGENT,
                    "X-XSS-Protection": "0",
                    "Acunetix-Aspect": "enabled",  # Trigger WAF
                    "X-Forwarded-For": "127.0.0.1",  # Potential trigger
                }
                
                malicious_url = f"{self.target_url}/?q=<script>alert(1)</script>&id=1' OR '1'='1"
                
                response = requests.get(
                    malicious_url,
                    headers=malicious_headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False
                )
                
                # Check if we got blocked
                if response.status_code in [403, 406, 501, 502]:
                    ColorOutput.warning("Request was blocked - WAF likely present but type unknown")
                    detected_wafs.append("Unknown WAF")
            except requests.exceptions.RequestException:
                pass
        
        if not detected_wafs:
            ColorOutput.info("No WAF detected")
        
        self.results["waf"] = detected_wafs

    def _api_discovery(self):
        """Discover API endpoints"""
        ColorOutput.section("API Endpoint Discovery")
        
        api_paths = [
            "api", "api/v1", "api/v2", "api/v3", 
            "rest", "graphql", "v1", "v2", "v3",
            "swagger", "swagger-ui", "swagger-ui.html", "swagger/ui", 
            "api-docs", "api/docs", "openapi.json", "openapi.yaml",
            "graphiql", "playground"
        ]
        
        discovered_apis = []
        
        ColorOutput.info("Searching for API endpoints...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_path = {executor.submit(self._check_api_path, f"{self.target_url}/{path}"): path 
                             for path in api_paths}
            
            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                
                try:
                    result = future.result()
                    if result:
                        discovered_apis.append(result)
                except Exception as e:
                    if self.verbose:
                        ColorOutput.error(f"Error checking API path {path}: {str(e)}")
        
        self.results["api_endpoints"] = discovered_apis
        
        if discovered_apis:
            ColorOutput.success(f"Discovered {len(discovered_apis)} potential API endpoints")
        else:
            ColorOutput.info("No API endpoints discovered")

    def _check_api_path(self, url):
        """Check if a path returns API-like content"""
        try:
            response = requests.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            
            # Return None for 404s and server errors
            if response.status_code in [404, 500, 502, 503, 504]:
                return None
            
            content_type = response.headers.get('Content-Type', '')
            
            # Check if it's likely an API endpoint
            api_indicators = [
                # Content type indicators
                'application/json' in content_type,
                'application/xml' in content_type,
                'application/graphql' in content_type,
                # Content indicators
                response.text.strip().startswith('{') and response.text.strip().endswith('}'),
                response.text.strip().startswith('[') and response.text.strip().endswith(']'),
                # Try to parse as JSON
                self._is_valid_json(response.text),
                # Keywords in the response
                'api' in url.lower() and (response.status_code != 404),
                'swagger' in response.text.lower(),
                'openapi' in response.text.lower(),
                'graphql' in response.text.lower()
            ]
            
            if any(api_indicators):
                api_info = {
                    "url": url,
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "content_length": len(response.text)
                }
                
                ColorOutput.success(f"Potential API endpoint: {url} (Status: {response.status_code})")
                return api_info
                
        except requests.exceptions.RequestException:
            pass
            
        return None

    def _is_valid_json(self, text):
        """Check if text is valid JSON"""
        try:
            if not text.strip():
                return False
            json.loads(text)
            return True
        except ValueError:
            return False

    def _check_cors_misconfig(self):
        """Check for CORS misconfigurations"""
        ColorOutput.section("CORS Misconfiguration Check")
        
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            f"https://{self.domain}.evil.com",
            f"https://{self.domain}.attacker.com",
            f"https://{self.domain}.com",  # Subdomain confusion
            f"https://evil{self.domain}",    # Domain confusion
        ]
        
        cors_issues = []
        
        for origin in test_origins:
            try:
                headers = {
                    "User-Agent": USER_AGENT,
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "X-Requested-With"
                }
                
                response = requests.get(
                    self.target_url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False
                )
                
                acao_header = response.headers.get('Access-Control-Allow-Origin')
                acac_header = response.headers.get('Access-Control-Allow-Credentials')
                
                if acao_header:
                    issue = {
                        "origin_tested": origin,
                        "acao_header": acao_header,
                        "acac_header": acac_header
                    }
                    
                    if acao_header == '*':
                        if acac_header == 'true':
                            issue["severity"] = "High"
                            issue["description"] = "Wildcard CORS with credentials allowed"
                            ColorOutput.error(f"Critical CORS misconfiguration: Wildcard (*) with credentials")
                        else:
                            issue["severity"] = "Medium"
                            issue["description"] = "Wildcard CORS without credentials"
                            ColorOutput.warning(f"CORS misconfiguration: Wildcard (*) origin allowed")
                            
                    elif acao_header == origin and origin != self.target_url:
                        if acac_header == 'true':
                            issue["severity"] = "High"
                            issue["description"] = f"Reflects arbitrary origin ({origin}) with credentials"
                            ColorOutput.error(f"Critical CORS misconfiguration: Reflects {origin} with credentials")
                        else:
                            issue["severity"] = "Medium"
                            issue["description"] = f"Reflects arbitrary origin ({origin})"
                            ColorOutput.warning(f"CORS misconfiguration: Reflects arbitrary origin {origin}")
                    
                    if "severity" in issue:
                        cors_issues.append(issue)
                
            except requests.exceptions.RequestException as e:
                if self.verbose:
                    ColorOutput.error(f"Error testing CORS with origin {origin}: {str(e)}")
        
        if not cors_issues:
            ColorOutput.success("No CORS misconfigurations detected")
        
        self.results["cors_issues"] = cors_issues

    def _js_analysis(self):
        """Analyze JavaScript files for endpoints and secrets"""
        ColorOutput.section("JavaScript Analysis")
        
        # Find JavaScript files
        try:
            response = requests.get(
                self.target_url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            
            # Extract all JS file references
            js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', response.text)
            
            if not js_files:
                ColorOutput.info("No JavaScript files found")
                return
            
            ColorOutput.info(f"Found {len(js_files)} JavaScript files")
            
            # Make URLs absolute
            for i in range(len(js_files)):
                if js_files[i].startswith('//'):
                    js_files[i] = 'https:' + js_files[i]
                elif js_files[i].startswith('/'):
                    js_files[i] = self.target_url + js_files[i]
                elif not js_files[i].startswith(('http://', 'https://')):
                    js_files[i] = self.target_url + '/' + js_files[i]
            
            # Process up to 5 JS files
            js_data = []
            for js_file in js_files[:5]:
                try:
                    js_response = requests.get(
                        js_file,
                        headers={"User-Agent": USER_AGENT},
                        timeout=self.timeout,
                        verify=False
                    )
                    
                    if js_response.status_code == 200:
                        js_content = js_response.text
                        
                        # Extract endpoints (URLs, API paths)
                        endpoints = set()
                        url_patterns = [
                            r'https?://[^"\'\s]+',  # Full URLs
                            r'"/api/[^"]+',         # API endpoints
                            r"'/api/[^']+",
                            r'"/v[0-9]+/[^"]+',     # Versioned API endpoints
                            r"'/v[0-9]+/[^']+"
                        ]
                        
                        for pattern in url_patterns:
                            for match in re.findall(pattern, js_content):
                                # Clean up the match
                                endpoint = match.strip('\'"')
                                endpoints.add(endpoint)
                        
                        # Look for potential secrets
                        secrets = []
                        secret_patterns = [
                            (r'apikey\s*[=:]\s*["\']([^"\']{8,})["\']', "API Key"),
                            (r'api_key\s*[=:]\s*["\']([^"\']{8,})["\']', "API Key"),
                            (r'secret\s*[=:]\s*["\']([^"\']{8,})["\']', "Secret"),
                            (r'password\s*[=:]\s*["\']([^"\']{8,})["\']', "Password"),
                            (r'aws_access_key_id\s*[=:]\s*["\']([^"\']{16,})["\']', "AWS Key"),
                            (r'aws_secret_access_key\s*[=:]\s*["\']([^"\']{16,})["\']', "AWS Secret")
                        ]
                        
                        for pattern, secret_type in secret_patterns:
                            for match in re.findall(pattern, js_content, re.IGNORECASE):
                                secrets.append({
                                    "type": secret_type,
                                    "partial_value": match[:4] + '****'  # Don't store full secrets
                                })
                        
                        file_info = {
                            "url": js_file,
                            "size": len(js_content),
                            "endpoints": list(endpoints)
                        }
                        
                        if secrets:
                            file_info["potential_secrets"] = secrets
                            ColorOutput.warning(f"Found {len(secrets)} potential secrets in {js_file}")
                        
                        if endpoints:
                            ColorOutput.success(f"Found {len(endpoints)} endpoints in {js_file}")
                        
                        js_data.append(file_info)
                        
                except requests.exceptions.RequestException as e:
                    if self.verbose:
                        ColorOutput.error(f"Error analyzing JavaScript file {js_file}: {str(e)}")
            
            self.results["javascript_analysis"] = js_data
            
        except requests.exceptions.RequestException as e:
            ColorOutput.error(f"Error in JavaScript analysis: {str(e)}")

    def interactive_mode(self):
        """Run the tool in interactive mode"""
        ColorOutput.section("Interactive Mode")
        print(f"""
    Welcome to the interactive mode of Web Application Recon Tool.
    Target: {self.target_url}
    
    Commands:
      1. dns       - DNS Enumeration
      2. ports     - Port Scanning
      3. headers   - HTTP Headers Analysis
      4. methods   - HTTP Methods Detection
      5. ssl       - SSL/TLS Analysis
      6. dirs      - Directory Discovery
      7. robots    - Robots.txt & Sitemap Analysis
      8. techs     - Technology Fingerprinting
      9. apis      - API Endpoint Discovery
      10. js       - JavaScript Analysis
      11. cors     - CORS Misconfiguration Check
      12. waf      - WAF Detection
      13. vulns    - Basic Vulnerability Checks
      14. subdomains - Subdomain Enumeration
      15. all      - Run All Modules
      16. save     - Save Results to File
      q. quit      - Exit Interactive Mode
    """)
        
        while True:
            try:
                choice = input("\nEnter command (1-16 or q): ").strip().lower()
                
                if choice == 'q':
                    break
                elif choice == '1' or choice == 'dns':
                    self._dns_enumeration()
                elif choice == '2' or choice == 'ports':
                    self._port_scanning()
                elif choice == '3' or choice == 'headers':
                    self._analyze_headers()
                elif choice == '4' or choice == 'methods':
                    self._detect_methods()
                elif choice == '5' or choice == 'ssl':
                    self._analyze_ssl()
                elif choice == '6' or choice == 'dirs':
                    self._directory_discovery()
                elif choice == '7' or choice == 'robots':
                    self._check_robots_sitemap()
                elif choice == '8' or choice == 'techs':
                    self._advanced_fingerprinting()
                elif choice == '9' or choice == 'apis':
                    self._api_discovery()
                elif choice == '10' or choice == 'js':
                    self._js_analysis()
                elif choice == '11' or choice == 'cors':
                    self._check_cors_misconfig()
                elif choice == '12' or choice == 'waf':
                    self._detect_waf()
                elif choice == '13' or choice == 'vulns':
                    self._vulnerability_checks()
                elif choice == '14' or choice == 'subdomains':
                    self._subdomain_enumeration()
                elif choice == '15' or choice == 'all':
                    self.run()
                elif choice == '16' or choice == 'save':
                    filename = input("Enter filename to save results: ").strip()
                    if filename:
                        if not filename.endswith('.json'):
                            filename += '.json'
                        self.output_file = filename
                        self._write_results()
                        self.generate_html_report()
                else:
                    print("Invalid choice. Please try again.")
                    
            except KeyboardInterrupt:
                print("\nExiting interactive mode...")
                break
            except Exception as e:
                ColorOutput.error(f"Error: {str(e)}")

    def generate_html_report(self):
        """Generate an HTML report of findings"""
        if not self.output_file:
            report_file = f"recon_report_{self.domain}_{int(time.time())}.html"
        else:
            report_file = self.output_file.replace('.json', '.html')
        
        ColorOutput.info(f"Generating HTML report: {report_file}")
        
        try:
            with open(report_file, 'w') as f:
                # Write HTML report header
                f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Web Recon Report - {self.domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; background: #fff; color: #333; }}
        h1, h2, h3 {{ color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .section {{ margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; padding: 15px; }}
        .danger {{ color: #d9534f; font-weight: bold; }}
        .warning {{ color: #f0ad4e; font-weight: bold; }}
        .success {{ color: #5cb85c; font-weight: bold; }}
        .info {{ color: #5bc0de; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 15px; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #f5f5f5; }}
        ul {{ padding-left: 20px; }}
        .footer {{ margin-top: 30px; text-align: center; font-size: 12px; color: #777; }}
        pre {{ background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Web Application Reconnaissance Report</h1>
        <div class="summary">
            <h2>Target Summary</h2>
            <p><strong>Target URL:</strong> {self.target_url}</p>
            <p><strong>Domain:</strong> {self.domain}</p>
            <p><strong>Scan Date:</strong> {self.results.get('timestamp', 'N/A')}</p>
            <p><strong>Tool Version:</strong> {VERSION}</p>
        </div>
""")

                # DNS Information
                if "dns_info" in self.results and self.results["dns_info"]:
                    f.write(f"""
        <div class="section">
            <h2>DNS Information</h2>
            <table>
                <tr>
                    <th>Record Type</th>
                    <th>Values</th>
                </tr>
""")
                    for record_type, values in self.results["dns_info"].items():
                        f.write(f"""
                <tr>
                    <td>{record_type}</td>
                    <td>{', '.join(values) if values else 'None'}</td>
                </tr>
""")
                    f.write("""
            </table>
        </div>
""")

                # Open Ports
                if "open_ports" in self.results and self.results["open_ports"]:
                    f.write(f"""
        <div class="section">
            <h2>Open Ports</h2>
            <p>The following ports were found to be open:</p>
            <ul>
""")
                    for port in self.results["open_ports"]:
                        f.write(f"                <li>{port}</li>\n")
                    f.write("""
            </ul>
        </div>
""")

                # HTTP Headers
                if "headers" in self.results and self.results["headers"]:
                    f.write(f"""
        <div class="section">
            <h2>HTTP Headers</h2>
            <table>
                <tr>
                    <th>Header</th>
                    <th>Value</th>
                </tr>
""")
                    for header, value in self.results["headers"].items():
                        header_class = ""
                        if header.lower() in ["server", "x-powered-by"]:
                            header_class = "warning"
                        elif header.lower() in ["content-security-policy", "strict-transport-security", "x-frame-options"]:
                            header_class = "success"
                        f.write(f"""
                <tr class="{header_class}">
                    <td>{header}</td>
                    <td>{value}</td>
                </tr>
""")
                    f.write("""
            </table>
        </div>
""")

                # Technologies Detected
                if "technologies" in self.results and self.results["technologies"]:
                    f.write(f"""
        <div class="section">
            <h2>Technologies Detected</h2>
            <ul>
""")
                    for tech, version in self.results["technologies"].items():
                        if isinstance(version, bool):
                            version_str = "Detected"
                        else:
                            version_str = f"Version: {version}"
                        f.write(f"                <li>{tech} - {version_str}</li>\n")
                    f.write("""
            </ul>
        </div>
""")

                # Subdomains
                if "subdomains" in self.results and self.results["subdomains"]:
                    f.write(f"""
        <div class="section">
            <h2>Subdomains Discovered</h2>
            <ul>
""")
                    for subdomain in self.results["subdomains"]:
                        f.write(f"                <li>{subdomain}</li>\n")
                    f.write("""
            </ul>
        </div>
""")

                # Vulnerabilities
                if "vulnerabilities" in self.results and self.results["vulnerabilities"]:
                    f.write(f"""
        <div class="section">
            <h2>Potential Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Details</th>
                </tr>
""")
                    for vuln in self.results["vulnerabilities"]:
                        vuln_type = vuln.get("type", "Unknown")
                        url = vuln.get("url", "N/A")
                        details = vuln.get("details", "")
                        severity_class = "danger" if "Potential" in vuln_type else ""
                        f.write(f"""
                <tr class="{severity_class}">
                    <td>{vuln_type}</td>
                    <td><a href="{url}" target="_blank" rel="noopener noreferrer">{url}</a></td>
                    <td>{details}</td>
                </tr>
""")
                    f.write("""
            </table>
        </div>
""")

                # WAF Detection
                if "waf" in self.results and self.results["waf"]:
                    f.write(f"""
        <div class="section">
            <h2>WAF Detection</h2>
            <ul>
""")
                    for waf in self.results["waf"]:
                        f.write(f"                <li>{waf}</li>\n")
                    f.write("""
            </ul>
        </div>
""")

                # API Endpoints
                if "api_endpoints" in self.results and self.results["api_endpoints"]:
                    f.write(f"""
        <div class="section">
            <h2>API Endpoints Discovered</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Status Code</th>
                    <th>Content Type</th>
                    <th>Content Length</th>
                </tr>
""")
                    for api in self.results["api_endpoints"]:
                        url = api.get("url", "N/A")
                        status = api.get("status_code", "N/A")
                        ctype = api.get("content_type", "N/A")
                        clen = api.get("content_length", "N/A")
                        f.write(f"""
                <tr>
                    <td><a href="{url}" target="_blank" rel="noopener noreferrer">{url}</a></td>
                    <td>{status}</td>
                    <td>{ctype}</td>
                    <td>{clen}</td>
                </tr>
""")
                    f.write("""
            </table>
        </div>
""")

                # CORS Issues
                if "cors_issues" in self.results and self.results["cors_issues"]:
                    f.write(f"""
        <div class="section">
            <h2>CORS Misconfigurations</h2>
            <table>
                <tr>
                    <th>Origin Tested</th>
                    <th>Access-Control-Allow-Origin</th>
                    <th>Access-Control-Allow-Credentials</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
""")
                    for issue in self.results["cors_issues"]:
                        origin = issue.get("origin_tested", "N/A")
                        acao = issue.get("acao_header", "N/A")
                        acac = issue.get("acac_header", "N/A")
                        severity = issue.get("severity", "N/A")
                        description = issue.get("description", "")
                        severity_class = "danger" if severity.lower() == "high" else "warning" if severity.lower() == "medium" else "info"
                        f.write(f"""
                <tr class="{severity_class}">
                    <td>{origin}</td>
                    <td>{acao}</td>
                    <td>{acac}</td>
                    <td>{severity}</td>
                    <td>{description}</td>
                </tr>
""")
                    f.write("""
            </table>
        </div>
""")

                # JavaScript Analysis
                if "javascript_analysis" in self.results and self.results["javascript_analysis"]:
                    f.write(f"""
        <div class="section">
            <h2>JavaScript Analysis</h2>
""")
                    for js_file in self.results["javascript_analysis"]:
                        f.write(f"""
            <h3>File: {js_file['url']}</h3>
            <p>Size: {js_file['size']} bytes</p>
""")
                        if "endpoints" in js_file and js_file["endpoints"]:
                            f.write("""
            <h4>Discovered Endpoints:</h4>
            <ul>
""")
                            for endpoint in js_file["endpoints"]:
                                f.write(f"                <li>{endpoint}</li>\n")
                            f.write("""
            </ul>
""")
                        if "potential_secrets" in js_file and js_file["potential_secrets"]:
                            f.write("""
            <h4>Potential Secrets:</h4>
            <ul>
""")
                            for secret in js_file["potential_secrets"]:
                                f.write(f"                <li>{secret['type']}: {secret['partial_value']}</li>\n")
                            f.write("""
            </ul>
""")
                    f.write("""
        </div>
""")

                # Footer
                f.write(f"""
        <div class="footer">
            <p>Report generated by Web Recon Tool version {VERSION} on {self.results.get('timestamp', 'N/A')}</p>
        </div>
    </div>
</body>
</html>
""")
            ColorOutput.success(f"HTML report generated successfully: {report_file}")
        except Exception as e:
            ColorOutput.error(f"Failed to generate HTML report: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description=f"Web Application Reconnaissance Tool v{VERSION}")
    
    parser.add_argument("-u", "--url", dest="url", help="Target URL", required=True)
    parser.add_argument("-o", "--output", dest="output", help="Output file (JSON format)", default=None)
    parser.add_argument("-t", "--threads", dest="threads", help="Number of threads", type=int, default=5)
    parser.add_argument("--timeout", dest="timeout", help="Request timeout in seconds", type=int, default=10)
    parser.add_argument("-v", "--verbose", dest="verbose", help="Verbose output", action="store_true")
    parser.add_argument("-i", "--interactive", dest="interactive", help="Run in interactive mode", action="store_true")
    
    args = parser.parse_args()
    
    print(f"""
    _       __     __      ____                        
   | |     / /__  / /_    / __ \___  _________  ____   
   | | /| / / _ \/ __ \  / /_/ / _ \/ ___/ __ \/ __ \  
   | |/ |/ /  __/ /_/ / / _, _/  __/ /__/ /_/ / / / /  
   |__/|__/\___/_.___/ /_/ |_|\___/\___/\____/_/ /_/   
                                                      
   Web Application Reconnaissance Tool v{VERSION}
   Made by viphacker100
   
   """)
    
    recon = WebRecon(
        url=args.url,
        output=args.output,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    if args.interactive:
        recon.interactive_mode()
    else:
        recon.run()


if __name__ == "__main__":
    main()
