#!/usr/bin/env python3
"""
Advanced Web Application Reconnaissance Tool (ADVWebRecon)

A comprehensive security tool for performing advanced reconnaissance on web applications.
This tool helps identify potential security issues by gathering information
about a target web application in a non-intrusive manner.

Made by viphacker100

Usage:
  python web_recon.py -u https://example.com [options]

Features:
  - Advanced DNS enumeration
  - Intelligent port scanning
  - Web technology fingerprinting
  - Directory/path discovery
  - Headers analysis
  - SSL/TLS analysis
  - Robots.txt and sitemap analysis
  - HTTP methods discovery
  - WAF detection
  - CORS misconfiguration checks
  - JavaScript analysis
  - API endpoint discovery
  - Subdomain enumeration
  - Vulnerability scanning
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
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from functools import lru_cache
from threading import Lock

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Requests module not found. Install it using: pip install requests")
    sys.exit(1)

try:
    import dns.resolver
except ImportError:
    print("[!] dnspython module not found. Install it using: pip install dnspython")
    sys.exit(1)

VERSION = "2.0.0"  # Updated version for ADVWebRecon
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Common web ports to scan
WEB_PORTS = [80, 443, 8080, 8443, 3000, 8000, 8008, 8800, 8888]

# Common directories to check
COMMON_DIRS = [
    # Original directories
    "admin", "login", "wp-admin", "administrator", "phpmyadmin",
    "dashboard", "api", "v1", "v2", "api/v1", "api/v2",
    "backup", "db", "database", "dev", "development", 
    "test", "testing", "staging", "prod", "config", 
    "setup", "install", "wp-content", "wp-includes",
    "uploads", "bak", "old", "new", "temp", "assets",
    "css", "js", "images", "img", "fonts", "includes",
    "lib", "logs", "scripts", "secure", "private", "tmp",
    "cache", "static", "media", "files", "docs", "documentation",
    "tools", "vendor", "node_modules", "components", "src",
    "public", "htdocs", "cgi-bin", "error", "errors", "auth",
    "oauth", "sessions", "users", "profiles", "account",
    "settings", "configurations", "reports", "analytics",
    "mail", "email", "newsletter", "forum", "blog", "news",
    "shop", "store", "cart", "checkout", "payment", "orders",
    "api-docs", "swagger", "graphql", "graphql-api",
    "system", "core", "bin", "etc", "var", "run", "tmp",
    "backup-old", "archive", "old-backup", "release", "releases",
    "logs-old", "private_html", "public_html", "web", "www",
    "downloads", "installers", "patches", "updates", "upgrade",
    "config_old", "config_backup", "secrets", "keys", "certs",
    "ssl", "security", "firewall", "monitoring", "metrics",
    "health", "status", "maintenance", "tmpfiles", "tempfiles",
    
    # Additional admin interfaces
    "adm", "admincp", "admindashboard", "adminer", "adminpanel",
    "adminzone", "backend", "cpanel", "manage", "management",
    "manager", "portal", "webadmin", "siteadmin", "superadmin",
    "wp-login", "joomla/administrator", "admin-console", "control",
    "acp", "acpanel", "moderator", "mod", "webmaster", "console",
    "cockpit", "mission-control", "cms", "panel", "sys", "mgt",
    
    # Framework-specific directories
    "laravel", "symfony", "django", "rails", "flask", "spring",
    "angular", "react", "vue", "next", "nuxt", "gatsby", "zend",
    "codeigniter", "yii", "cake", "drupal", "typo3", "magento",
    "shopify", "woocommerce", "prestashop", "opencart", "flask-admin",
    "rails-admin", "django-admin", "node-admin", "strapi-admin",
    "wp-json", "rest", "restful", "restapi", "rest-api", "rpc",
    "xmlrpc", "jsonrpc", "soap", "grpc", "webpack", "parcel",
    
    # Database-related
    "mysql", "postgres", "postgresql", "mongodb", "mongo",
    "redis", "mariadb", "oracle", "mssql", "sqlserver", "sqlite",
    "adminer", "dbadmin", "sqlbuddy", "pma", "myadmin", "phpliteadmin",
    "sqlite", "supabase", "firebase", "dynamodb", "cosmosdb",
    
    # Cloud services
    "aws", "azure", "gcp", "firebase", "cloudflare", "netlify",
    "vercel", "heroku", "digitalocean", "aws-lambda", "s3",
    "storage", "functions", "lambda", "serverless", "cloudfront",
    "cdn", "bucket", "containers", "kubernetes", "k8s", "pods",
    "terraform", "ansible", "chef", "puppet", "salt", "docker",
    
    # Authentication/Authorization
    "jwt", "saml", "sso", "ldap", "kerberos", "oauth2", "openid",
    "2fa", "mfa", "totp", "login-verify", "auth0", "keycloak",
    "okta", "cognito", "identity", "permissions", "roles", "acl",
    "access-control", "rbac", "single-sign-on", "password-reset",
    
    # CMS and eCommerce platforms
    "wordpress", "joomla", "drupal", "magento", "prestashop",
    "shopify", "bigcommerce", "wix", "squarespace", "ghost",
    "contentful", "strapi", "sanity", "directus", "prismic",
    "craft", "umbraco", "sitecore", "kentico", "hubspot",
    "wix-media", "hubspot-assets", "elementor", "wix-code",
    "admin/login", "login/admin", "customer", "client-area",
    
    # Development & API
    "dev-api", "sandbox", "playground", "local", "localhost",
    "beta", "alpha", "canary", "nightly", "rc", "edge",
    "internal", "internal-api", "preview", "stage", "uat",
    "qa", "integration", "int", "demo", "pilot", "labs",
    "graphiql", "apollo", "postman", "insomnia", "swagger-ui",
    "api-explorer", "api-console", "api-client", "webhooks",
    
    # Internationalization
    "en", "fr", "es", "de", "it", "pt", "ru", "zh", "ja",
    "ko", "ar", "hi", "bn", "pa", "te", "mr", "ta", "ur",
    "i18n", "l10n", "locales", "translations", "intl",
    "lang", "language", "languages", "country", "region",
    
    # Security
    "security-txt", ".well-known", "sitemap", "robots", 
    "wp-content/debug.log", "wp-config.php", "env", ".env",
    "waf", "ids", "ips", "pentest", "security-check", "audit",
    "vulnerabilities", "csp", "cors", "xss", "csrf", "captcha",
    "recaptcha", "hcaptcha", "turnstile", "abuse", "dmarc",
    "spf", "dkim", "honeypot", "security-headers", "web-security",
    
    # Content & Media
    "galleries", "photos", "videos", "audio", "podcasts",
    "streaming", "feed", "feeds", "rss", "atom", "sitemap.xml",
    "uploads/large", "uploads/thumbnails", "uploads/avatars",
    "content-delivery", "asset-management", "media-library",
    "documents", "ebooks", "pdf", "presentations", "downloads/private",
    
    # Infrastructure & DevOps
    "jenkins", "gitlab", "github", "bitbucket", "travis",
    "circleci", "teamcity", "bamboo", "sonarqube", "nagios",
    "zabbix", "prometheus", "grafana", "kibana", "logstash",
    "elasticsearch", "splunk", "datadog", "sentry", "newrelic",
    "uptimerobot", "pingdom", "statuscake", "statuspage",
    "deploy", "deployment", "packer", "vault", "consul",
    
    # Legacy systems
    "cgi", "perl", "php", "asp", "aspx", "jsp", "coldfusion",
    "cfm", "cfml", "action", "do", "asmx", "ashx", "php4",
    "php5", "php7", "php8", "classic", "legacy", "old-site",
    "archive-site", "v1-deprecated", "v2-deprecated", "historical",
    
    # Misc functionality
    "search", "sitesearch", "advanced-search", "cron", "scheduler",
    "task", "jobs", "worker", "queue", "process", "background",
    "timer", "webhook", "callback", "redirect", "goto", "calendar",
    "chat", "support", "helpdesk", "ticket", "knowledgebase", "faq",
    "forms", "surveys", "feedback", "contact", "newsletter-signup",
    "subscribe", "unsubscribe", "preferences", "notifications",
    "alerts", "events", "bookings", "appointments", "reservations",
    "reviews", "comments", "ratings", "votes", "likes", "social",
    "share", "export", "import", "print", "preview", "embed", "widgets",
    "ajax", "rpc", "ws", "websocket", "sse", "hooks", "robots.txt",
    
    # Specialized platforms
    "moodle", "blackboard", "canvas", "lms", "elearning",
    "courseware", "classroom", "training", "learn", "courses",
    "lessons", "modules", "quiz", "exams", "assignments",
    "discourse", "vanilla", "phpbb", "vbulletin", "xenforo",
    "community", "members", "buddypress", "membership",
    "stripe", "paypal", "braintree", "checkout", "payout",
    "transaction", "wallet", "billing", "invoice", "subscription",
    
    # Mobile specific
    "mobile", "m", "app", "android", "ios", "pwa", "amp",
    "mobile-api", "app-api", "deep-links", "universal-links",
    "api/mobile", "responsive", "touch", "devices", "native",
    
    # Utilities and tooling
    "utilities", "utils", "helpers", "tools", "toolkit",
    "playground", "sandbox", "editor", "calculator", "converter",
    "generator", "analyzer", "debugger", "profiler", "optimizer",
    "minifier", "compressor", "prettifier", "linter", "formatter",
    "validator", "tester", "benchmark", "speed-test", "connectivity",
    
    # Dangerous exposure paths
    ".git", ".svn", ".hg", ".bzr", ".env.local", ".env.dev",
    ".env.prod", ".env.production", ".env.staging", ".env.test",
    "config.php", "settings.php", "web.config", "phpinfo.php",
    "info.php", "test.php", "config.json", "connections.xml",
    "credentials.json", "secret.json", "password.txt", "backup.sql",
    "dump.sql", "database.sql", "users.sql", "customers.csv",
    ".bash_history", ".ssh", "id_rsa", "known_hosts", ".htpasswd",
    ".htaccess", "web.config", "elmah.axd"
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

class RateLimiter:
    """Rate limiter class to control request rates"""
    def __init__(self, max_requests, time_window):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
        self.lock = Lock()

    def acquire(self):
        """Acquire permission to make a request"""
        with self.lock:
            now = time.time()
            # Remove old requests
            self.requests = [req_time for req_time in self.requests if now - req_time < self.time_window]
            
            if len(self.requests) >= self.max_requests:
                # Calculate sleep time
                sleep_time = self.requests[0] + self.time_window - now
                if sleep_time > 0:
                    time.sleep(sleep_time)
                # Remove the oldest request
                self.requests.pop(0)
            
            self.requests.append(now)

class ADVWebRecon:
    """Advanced Web Application Reconnaissance Tool"""
    
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
            "robots_sitemap": {},
            "security_score": 0,  # New field for security scoring
            "risk_level": "Unknown",  # New field for risk assessment
            "recommendations": []  # New field for security recommendations
        }
        
        # Initialize session with connection pooling
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.threads,
            pool_maxsize=self.threads
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.verify = False
        
        # Initialize cache
        self.cache = {}
        self.cache_timeout = timedelta(minutes=5)  # Cache timeout of 5 minutes
        
        # Initialize rate limiters
        self.http_limiter = RateLimiter(max_requests=10, time_window=1)  # 10 requests per second
        self.dns_limiter = RateLimiter(max_requests=5, time_window=1)    # 5 DNS queries per second

    def _calculate_security_score(self):
        """Calculate overall security score based on findings"""
        score = 100  # Start with perfect score
        
        # Deduct points for missing security headers
        security_headers = {
            "Strict-Transport-Security": 10,
            "Content-Security-Policy": 10,
            "X-Frame-Options": 5,
            "X-Content-Type-Options": 5,
            "X-XSS-Protection": 5,
            "Referrer-Policy": 5
        }
        
        for header, points in security_headers.items():
            if header not in self.results["headers"]:
                score -= points
                self.results["recommendations"].append(f"Missing security header: {header}")
        
        # Deduct points for SSL/TLS issues
        if "ssl_info" in self.results:
            ssl_info = self.results["ssl_info"]
            if "version" in ssl_info:
                if "TLSv1.0" in ssl_info["version"] or "TLSv1.1" in ssl_info["version"]:
                    score -= 15
                    self.results["recommendations"].append("Outdated TLS version detected")
            
            if "days_remaining" in ssl_info and ssl_info["days_remaining"] < 30:
                score -= 10
                self.results["recommendations"].append("SSL certificate expiring soon")
        
        # Deduct points for open ports
        dangerous_ports = [21, 23, 3389, 445, 1433, 3306, 5432, 27017]
        for port in self.results["open_ports"]:
            if port in dangerous_ports:
                score -= 5
                self.results["recommendations"].append(f"Dangerous port {port} is open")
        
        # Deduct points for CORS misconfigurations
        if "cors_issues" in self.results and self.results["cors_issues"]:
            score -= 15
            self.results["recommendations"].append("CORS misconfiguration detected")
        
        # Deduct points for WAF absence
        if "waf" in self.results and not self.results["waf"]:
            score -= 10
            self.results["recommendations"].append("No WAF detected")
        
        # Set risk level based on score
        if score >= 80:
            self.results["risk_level"] = "Low"
        elif score >= 60:
            self.results["risk_level"] = "Medium"
        elif score >= 40:
            self.results["risk_level"] = "High"
        else:
            self.results["risk_level"] = "Critical"
        
        self.results["security_score"] = max(0, score)  # Ensure score doesn't go below 0

    def run(self):
        """Run all reconnaissance modules with enhanced reporting"""
        ColorOutput.section(f"Starting Advanced Web Reconnaissance on {self.target_url}")
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
            
            # Calculate security score and risk level
            self._calculate_security_score()
            
            # Write results to file if specified
            if self.output_file:
                self._write_results()
                self.generate_html_report()
            
            # Display summary
            ColorOutput.section("Reconnaissance Summary")
            ColorOutput.info(f"Security Score: {self.results['security_score']}/100")
            ColorOutput.info(f"Risk Level: {self.results['risk_level']}")
            
            if self.results["recommendations"]:
                ColorOutput.section("Security Recommendations")
                for rec in self.results["recommendations"]:
                    ColorOutput.warning(f"- {rec}")
            
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
    
    @lru_cache(maxsize=100)
    def _dns_query(self, domain, record_type):
        """Cached DNS query with rate limiting"""
        # Apply rate limiting
        self.dns_limiter.acquire()
        
        try:
            answers = dns.resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    def _get_cached_response(self, url, method="GET", headers=None):
        """Get cached response if available and not expired"""
        cache_key = f"{method}:{url}:{str(headers)}"
        if cache_key in self.cache:
            timestamp, response = self.cache[cache_key]
            if datetime.now() - timestamp < self.cache_timeout:
                return response
            else:
                del self.cache[cache_key]
        return None

    def _cache_response(self, url, method="GET", headers=None, response=None):
        """Cache response with timestamp"""
        if response:
            cache_key = f"{method}:{url}:{str(headers)}"
            self.cache[cache_key] = (datetime.now(), response)

    def _make_request(self, url, method="GET", headers=None, timeout=None, verify=False, allow_redirects=True):
        """Make an HTTP request with proper error handling, connection pooling, caching, and rate limiting"""
        if headers is None:
            headers = {}
        if timeout is None:
            timeout = self.timeout
        
        # Check cache first
        cached_response = self._get_cached_response(url, method, headers)
        if cached_response:
            return cached_response
        
        # Apply rate limiting
        self.http_limiter.acquire()
        
        try:
            response = self.session.request(
                method,
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=allow_redirects
            )
            
            # Cache successful responses
            if response.status_code == 200:
                self._cache_response(url, method, headers, response)
            
            return response
        except requests.exceptions.Timeout:
            ColorOutput.error(f"Request timed out after {timeout} seconds: {url}")
            return None
        except requests.exceptions.ConnectionError:
            ColorOutput.error(f"Connection error: {url}")
            return None
        except requests.exceptions.RequestException as e:
            ColorOutput.error(f"Request failed: {url} - {str(e)}")
            return None

    def _dns_enumeration(self):
        """Perform enhanced DNS enumeration with caching"""
        ColorOutput.section("DNS Enumeration")

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'PTR', 'SPF', 'DNSKEY']

        # Initialize results dict if not present
        if "dns_info" not in self.results:
            self.results["dns_info"] = {}

        def query_record(record_type):
            try:
                ColorOutput.info(f"Querying {record_type} records...")
                results = self._dns_query(self.domain, record_type)
                for rdata in results:
                    ColorOutput.success(f"{record_type} record: {rdata}")
                return record_type, results
            except dns.resolver.NoAnswer:
                ColorOutput.warning(f"No {record_type} records found")
                return record_type, []
            except dns.resolver.NXDOMAIN:
                ColorOutput.error(f"Domain {self.domain} does not exist")
                return record_type, None
            except Exception as e:
                ColorOutput.error(f"Error querying {record_type} records: {str(e)}")
                return record_type, []

        # Query all record types concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(query_record, rt): rt for rt in record_types}
            for future in concurrent.futures.as_completed(futures):
                rt = futures[future]
                record_type, results = future.result()
                if results is None:
                    # NXDOMAIN or fatal error, stop further processing
                    break
                self.results["dns_info"][record_type] = results

        # Additional: Reverse DNS lookup for A and AAAA records with caching
        def reverse_lookup(ip):
            try:
                rev_name = dns.reversename.from_address(ip)
                answers = self._dns_query(str(rev_name), 'PTR')
                ptrs = [str(rdata) for rdata in answers]
                for ptr in ptrs:
                    ColorOutput.success(f"Reverse DNS PTR record for {ip}: {ptr}")
                return ip, ptrs
            except Exception:
                return ip, []

        ips = self.results["dns_info"].get('A', []) + self.results["dns_info"].get('AAAA', [])
        if ips:
            ColorOutput.info("Performing reverse DNS lookups on IP addresses...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = {executor.submit(reverse_lookup, ip): ip for ip in ips}
                reverse_results = {}
                for future in concurrent.futures.as_completed(futures):
                    ip, ptrs = future.result()
                    if ptrs:
                        reverse_results[ip] = ptrs
                if reverse_results:
                    self.results["dns_info"]["reverse_dns"] = reverse_results

        # Optional: Subdomain enumeration (basic example)
        # You can replace this with a wordlist or integrate with external services
        subdomains = ['www', 'mail', 'ftp', 'api', 'dev', 'test']
        discovered_subdomains = []

        def check_subdomain(sub):
            fqdn = f"{sub}.{self.domain}"
            try:
                answers = dns.resolver.resolve(fqdn, 'A')
                ColorOutput.success(f"Discovered subdomain: {fqdn} -> {answers[0]}")
                return fqdn
            except Exception:
                return None

        ColorOutput.info("Starting basic subdomain enumeration...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    discovered_subdomains.append(result)

        if discovered_subdomains:
            self.results["dns_info"]["discovered_subdomains"] = discovered_subdomains
    
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
        """Scan common web ports with improved performance"""
        ColorOutput.section("Port Scanning (Common Web Ports)")
        ColorOutput.info(f"Scanning {len(WEB_PORTS)} common web ports...")
        
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Create a list of futures
            future_to_port = {executor.submit(self._check_port, port): port for port in WEB_PORTS}
            
            # Process results as they complete
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
        """
        Analyze HTTP headers for security issues, information disclosure,
        and misconfiguration. Provides detailed reporting on findings.
        """
        ColorOutput.section("HTTP Headers Analysis")
        
        response = self._make_request(self.target_url)
        if not response:
            return
        
        ColorOutput.info(f"HTTP Status: {response.status_code} ({response.reason})")
        
        # Expanded list of sensitive headers that might reveal information
        sensitive_headers = [
            # Server identification
            "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
            "X-Generator", "X-Runtime", "X-Version", "X-Framework", "X-UA-Compatible",
            "X-PHP-Version", "X-Node-Version", "X-App-Version", "X-Application",
            "X-Environment", "X-Middleware", "X-Drupal-Cache", "X-Varnish", "Via",
            "X-Backend-Server", "X-Served-By", "X-Cocoon-Version", "X-Servlet-Engine",
            "X-Drupal-Dynamic-Cache", "X-HashCache-Store", "X-Magnolia-Registration",
            "X-Drupal-Cache-Tags", "X-Drupal-Cache-Contexts", "X-Oracle-DMS-ECID",
            "X-Application-Context", "X-SourceFiles", "X-Pingback", "X-Requested-With",
            "MicrosoftOfficeWebServer", "MicrosoftSharePointTeamServices", 
            "X-MS-InvokeApp", "X-OWA-Version", "X-FEServer",
            
            # Framework fingerprints
            "X-Rails-Version", "X-Django-Version", "X-Rack-Cache", "X-Wix-Request-Id",
            "X-Shopify-Stage", "X-Heroku-Dynos-In-Use", "X-WP-Total", "X-WP-TotalPages",
            "X-Litespeed-Cache", "X-Page-Speed", "Liferay-Portal", "X-Akamai-Transformed",
            "X-Mod-Pagespeed", "X-Drupal-Cache", "X-Varnish-Cache", "X-AEM-Request-Processed",
            "X-Pantheon-Styx-Hostname", "X-CloudFlare-Cache-Status", "X-Cache",
            
            # Debug headers
            "X-Debug-Token", "X-Debug-Token-Link", "X-Debug", "X-Error", "X-Error-Message",
            "X-Flow-Powered", "X-Cascade", "X-Request-ID", "X-Correlation-ID", "X-Trace-ID",
            "X-API-Version", "X-API-Revision", "X-Log-ID", "X-TraceID", "X-WebKit-CSP",
            "X-Content-Duration", "X-Resources", "X-UA-Device", "X-Cloud-Trace-Context",
        ]
        
        # Enhanced security headers with expected values and descriptions
        security_headers = {
            # Classic security headers
            "X-Content-Type-Options": {
                "expected": ["nosniff"],
                "description": "Prevents browsers from MIME-sniffing a response away from the declared content-type"
            },
            "X-XSS-Protection": {
                "expected": ["1", "1; mode=block"],
                "description": "Enables cross-site scripting filtering in browsers"
            },
            "X-Frame-Options": {
                "expected": ["DENY", "SAMEORIGIN"],
                "description": "Protects against clickjacking attacks"
            },
            "Content-Security-Policy": {
                "expected": True,  # Just check if present
                "description": "Controls resources the user agent is allowed to load"
            },
            "Strict-Transport-Security": {
                "expected": True,  # Check if present, ideally should contain max-age
                "description": "Forces browsers to use HTTPS"
            },
            
            # Modern security headers
            "Permissions-Policy": {
                "expected": True,  # Just check if present (replaces Feature-Policy)
                "description": "Controls which browser features can be used"
            },
            "Referrer-Policy": {
                "expected": ["no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"],
                "description": "Controls how much referrer information is included with requests"
            },
            "Cross-Origin-Embedder-Policy": {
                "expected": ["require-corp"],
                "description": "Prevents loading of non-same-origin resources without explicit permission"
            },
            "Cross-Origin-Opener-Policy": {
                "expected": ["same-origin"],
                "description": "Prevents sharing browsing context with cross-origin documents"
            },
            "Cross-Origin-Resource-Policy": {
                "expected": ["same-origin", "same-site"],
                "description": "Prevents other websites from embedding your resources"
            },
            "Cache-Control": {
                "expected": True,  # Complex analysis done separately
                "description": "Directives for caching mechanisms"
            },
            "Clear-Site-Data": {
                "expected": True,  # Just check if present
                "description": "Clears browsing data (cookies, storage, cache) associated with the site"
            },
            "Access-Control-Allow-Origin": {
                "expected": True,  # Complex analysis done separately
                "description": "Indicates whether the response can be shared with requesting code"
            },
            "Content-Security-Policy-Report-Only": {
                "expected": True,  # Just check if present
                "description": "Reports CSP violations without enforcing them"
            },
            "Expect-CT": {
                "expected": True,  # Just check if present
                "description": "Certificate Transparency monitoring"
            },
            "Report-To": {
                "expected": True,  # Just check if present
                "description": "Configures reporting endpoints for various browser features"
            },
            "NEL": {
                "expected": True,  # Just check if present
                "description": "Network Error Logging configuration"
            }
        }
        
        # Headers that shouldn't be present in production
        development_headers = [
            "X-Debug", "X-Debug-Token", "Access-Control-Allow-Origin: *",
            "X-Debug-Token-Link", "X-Runtime", "X-Powered-By", "X-Source-Tags",
            "X-ASPNet-Version", "X-AspNetMvc-Version", "Server-Timing", "X-Debug-Mode",
            "X-Environment"
        ]
        
        # Store all headers in results
        for header, value in response.headers.items():
            self.results["headers"][header] = value
            
            # Check for information disclosure in headers
            if header in sensitive_headers:
                ColorOutput.attention(f"{header}: {value} (Information Disclosure)")
            
            # Check security headers against expected values
            if header in security_headers:
                expected = security_headers[header]["expected"]
                description = security_headers[header]["description"]
                
                if isinstance(expected, list):
                    if value not in expected:
                        ColorOutput.warning(f"Security header {header} has potentially insecure value: {value}")
                        ColorOutput.info(f"  └─ Description: {description}")
                        ColorOutput.info(f"  └─ Expected: {', '.join(expected)}")
                    else:
                        ColorOutput.success(f"{header}: {value}")
                elif expected is True:
                    ColorOutput.success(f"{header}: {value}")
                    ColorOutput.info(f"  └─ Description: {description}")
            
            # Check for development headers in production
            for dev_header in development_headers:
                if dev_header.lower() in f"{header.lower()}: {value.lower()}":
                    ColorOutput.warning(f"Development header detected: {header}: {value}")
        
        # Detailed analysis of specific headers
        
        # 1. Cache-Control analysis
        if "Cache-Control" in response.headers:
            cache_control = response.headers["Cache-Control"]
            if "private" not in cache_control and "no-store" not in cache_control:
                for sensitive_route in ["login", "admin", "dashboard", "account", "profile", "settings", "user"]:
                    if sensitive_route in self.target_url:
                        ColorOutput.warning(f"Cache-Control header ({cache_control}) may be insufficient for sensitive page")
                        ColorOutput.info("  └─ Consider using 'Cache-Control: no-store, max-age=0' for sensitive routes")
                        break
        
        # 2. CORS header analysis
        if "Access-Control-Allow-Origin" in response.headers:
            cors_value = response.headers["Access-Control-Allow-Origin"]
            if cors_value == "*":
                ColorOutput.warning("Access-Control-Allow-Origin set to wildcard (*)")
                ColorOutput.info("  └─ This is insecure for resources requiring authentication")
        
        # 3. HSTS header analysis
        if "Strict-Transport-Security" in response.headers:
            hsts = response.headers["Strict-Transport-Security"]
            if "max-age=" in hsts:
                try:
                    max_age = int(hsts.split("max-age=")[1].split(";")[0].strip())
                    if max_age < 15768000:  # Less than 6 months
                        ColorOutput.warning(f"HSTS max-age is too short: {max_age} seconds")
                        ColorOutput.info("  └─ Recommended: at least 15768000 seconds (6 months)")
                except (ValueError, IndexError):
                    ColorOutput.warning(f"Invalid HSTS header format: {hsts}")
                    
            if "includeSubDomains" not in hsts:
                ColorOutput.info("HSTS header is missing 'includeSubDomains' directive")
                
            if "preload" not in hsts:
                ColorOutput.info("HSTS header is missing 'preload' directive")
        
        # 4. Content-Type and charset analysis
        if "Content-Type" in response.headers:
            content_type = response.headers["Content-Type"]
            if "charset" not in content_type.lower():
                ColorOutput.info("Content-Type header is missing charset specification")
            elif "utf-8" not in content_type.lower():
                ColorOutput.info(f"Content-Type uses non-UTF-8 charset: {content_type}")
        
        # Check for missing security headers
        for header, details in security_headers.items():
            if header not in response.headers:
                # Categorize by importance
                primary_headers = ["X-Content-Type-Options", "X-Frame-Options", 
                                 "Content-Security-Policy", "Strict-Transport-Security"]
                
                if header in primary_headers:
                    ColorOutput.warning(f"Missing critical security header: {header}")
                    ColorOutput.info(f"  └─ Purpose: {details['description']}")
                else:
                    ColorOutput.info(f"Missing security header: {header}")
                    ColorOutput.info(f"  └─ Purpose: {details['description']}")
        
        # Enhanced cookie analysis
        if response.cookies:
            ColorOutput.section("Cookie Analysis")
            for cookie in response.cookies:
                issues = []
                
                # Build detailed cookie info
                cookie_info = [f"Cookie: {cookie.name}"]
                
                # Check for secure attributes
                if not cookie.secure:
                    issues.append("missing Secure flag")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("missing HttpOnly flag")
                
                # Check SameSite attribute
                samesite = None
                for attr in cookie._rest:
                    if attr.lower() == 'samesite':
                        samesite = cookie._rest[attr]
                
                if not samesite:
                    issues.append("missing SameSite attribute")
                elif samesite.lower() not in ['strict', 'lax', 'none']:
                    issues.append(f"invalid SameSite value: {samesite}")
                elif samesite.lower() == 'none' and not cookie.secure:
                    issues.append("SameSite=None without Secure flag")
                
                # Check expiration
                if cookie.expires:
                    from datetime import datetime
                    expiry_date = datetime.fromtimestamp(cookie.expires)
                    now = datetime.now()
                    days_until_expiry = (expiry_date - now).days
                    
                    if days_until_expiry > 365:
                        issues.append(f"long expiration time ({days_until_expiry} days)")
                    
                    cookie_info.append(f"expires in {days_until_expiry} days")
                
                # Check for potential session cookies
                if cookie.name.lower() in ['sessionid', 'session', 'sid', 'jsessionid', 'phpsessid', 'aspsessionid']:
                    if cookie.expires:
                        issues.append("session cookie with explicit expiration")
                
                # Check path
                if cookie.path == "/" or not cookie.path:
                    cookie_info.append("path=/")
                    
                # Check domain
                if cookie.domain:
                    if cookie.domain.startswith('.'):
                        cookie_info.append(f"domain={cookie.domain}")
                        issues.append("wildcard domain")
                    else:
                        cookie_info.append(f"domain={cookie.domain}")
                
                # Output results
                if issues:
                    ColorOutput.warning(f"{' | '.join(cookie_info)} - Issues: {', '.join(issues)}")
                else:
                    ColorOutput.success(f"{' | '.join(cookie_info)} - Properly configured")
                    
        # Server fingerprinting
        if "Server" in response.headers:
            server = response.headers["Server"]
            if len(server) > 1:  # Not just a single character to hide server info
                ColorOutput.attention(f"Server header reveals: {server}")
                
                # Check for version information in server header
                import re
                version_pattern = re.compile(r'[\d\.]+')
                if version_pattern.search(server):
                    ColorOutput.warning("Server header contains version information")
                    
        # Response analysis based on status code
        if response.status_code >= 400:
            if len(response.text) > 100:  # Arbitrary length to detect verbose error messages
                ColorOutput.warning("Response may contain verbose error information")
        
        # Detect WAF presence
        waf_headers = [
            "X-Sucuri-ID", "X-Sucuri-Cache", "X-CDN", "X-Varnish",
            "X-Cloudflare", "X-Powered-By-Plesk", "CF-Ray", "CF-Cache-Status",
            "X-Akamai-Transformed", "X-Akamai-Debug-Host", "X-Cache",
            "X-ModSecurity", "X-FW-Server", "X-FW-Dynamic", "X-FW-Static",
            "X-FW-Blocktype", "X-FW-Block", "X-Distil-CS"
        ]
        
        waf_detected = False
        for waf_header in waf_headers:
            if waf_header in response.headers:
                if not waf_detected:
                    ColorOutput.info("Web Application Firewall (WAF) detection:")
                    waf_detected = True
                ColorOutput.success(f"WAF detected: {waf_header}: {response.headers[waf_header]}")
                
        # Server timing headers (performance insights)
        if "Server-Timing" in response.headers:
            ColorOutput.info(f"Server-Timing header found: {response.headers['Server-Timing']}")
            ColorOutput.info("  └─ May reveal internal timing information")
            
        # Check for feature policies
        if "Feature-Policy" in response.headers:
            ColorOutput.info("Feature-Policy header (deprecated) found")
            ColorOutput.info("  └─ Consider upgrading to Permissions-Policy")
            
        # Check for potentially dangerous API exposures in CORS headers
        cors_headers = [h for h in response.headers if h.startswith("Access-Control-")]
        if cors_headers:
            for header in cors_headers:
                if header == "Access-Control-Allow-Credentials" and response.headers[header].lower() == "true":
                    if "Access-Control-Allow-Origin" in response.headers and response.headers["Access-Control-Allow-Origin"] == "*":
                        ColorOutput.warning("Dangerous CORS configuration: Credentials allowed with wildcard origin")
                        
        # Check for powered-by headers
        for header, value in response.headers.items():
            if "powered" in header.lower() or "powered" in value.lower():
                ColorOutput.attention(f"Technology disclosure: {header}: {value}")
                
        # Analyze custom headers that might indicate frameworks/technologies
        custom_header_indicators = {
            "laravel": ["x-laravel", "laravel_session"],
            "django": ["x-django", "csrftoken"],
            "rails": ["x-rails", "_rails_session"],
            "aspnet": ["x-aspnet", "__VIEWSTATE"],
            "wordpress": ["x-wp", "wp-", "wordpress_"],
            "drupal": ["x-drupal", "drupal-"],
            "joomla": ["x-joomla", "joomla_"],
            "magento": ["x-magento", "magento-"],
            "react": ["x-react", "react-"],
            "angular": ["x-angular", "ng-"]
        }
        
        for header, value in response.headers.items():
            header_lower = header.lower()
            value_lower = value.lower()
            
            for tech, indicators in custom_header_indicators.items():
                for indicator in indicators:
                    if indicator in header_lower or indicator in value_lower:
                        ColorOutput.attention(f"Technology detected via headers: {tech}")
                        break
        
        # Analyze Content-Type headers
        if "Content-Type" in response.headers:
            content_type = response.headers["Content-Type"].lower()
            if "application/json" in content_type:
                ColorOutput.info("API endpoint detected (JSON response)")
            elif "text/xml" in content_type or "application/xml" in content_type:
                ColorOutput.info("API endpoint or XML service detected")
            elif "text/html" in content_type:
                ColorOutput.info("HTML response detected")

        # Check for uncommon headers that might be custom implementations
        common_headers = [
            "date", "content-type", "content-length", "connection", "cache-control",
            "server", "content-encoding", "vary", "transfer-encoding", "expires",
            "location", "pragma", "x-content-type-options", "x-xss-protection",
            "content-language", "set-cookie", "x-frame-options", "last-modified",
            "accept-ranges", "strict-transport-security", "etag", "x-powered-by",
            "content-security-policy", "x-content-security-policy", "age", "via"
        ]
        
        for header in response.headers:
            if header.lower() not in common_headers:
                ColorOutput.info(f"Uncommon header detected: {header}: {response.headers[header]}")
                
        # Check for timing attack potential by analyzing Authorization headers
        if "Authorization" in self.custom_headers:
            ColorOutput.info("Authorization header is being sent - consider analyzing server timing differences")

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
            context.verify_mode = ssl.CERT_NONE  # Changed from CERT_OPTIONAL to CERT_NONE
            
            ColorOutput.info(f"Connecting to {hostname}:{port}...")
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert is None:
                        ColorOutput.error("Could not retrieve SSL certificate")
                        return
                        
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Extract certificate information
                    try:
                        not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                        not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                        issuer = dict(x[0] for x in cert['issuer'])
                        subject = dict(x[0] for x in cert['subject'])
                    except (KeyError, ValueError) as e:
                        ColorOutput.error(f"Error parsing certificate dates: {str(e)}")
                        return
                    
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
                    
                    # Check for weak protocols
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
        
        response = self._make_request(robots_url)
        if response and response.status_code == 200 and 'text/plain' in response.headers.get('Content-Type', ''):
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
        
        # Check sitemap.xml
        sitemap_url = f"{self.target_url}/sitemap.xml"
        ColorOutput.info(f"Checking {sitemap_url}")
        
        response = self._make_request(sitemap_url)
        if response and response.status_code == 200 and ('application/xml' in response.headers.get('Content-Type', '') or 
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
        
        self.results["robots_sitemap"] = results
    
    def _directory_discovery(self):
        """Discover common directories with improved performance and rate limiting"""
        ColorOutput.section("Directory Discovery")
        ColorOutput.info(f"Testing {len(COMMON_DIRS)} common directories...")
        
        found_dirs = []
        chunk_size = 50  # Process directories in chunks to avoid overwhelming the server
        
        for i in range(0, len(COMMON_DIRS), chunk_size):
            chunk = COMMON_DIRS[i:i + chunk_size]
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                
                for directory in chunk:
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
            
            # Add a small delay between chunks to avoid overwhelming the server
            if i + chunk_size < len(COMMON_DIRS):
                time.sleep(1)  # Increased delay to respect rate limits
        
        self.results["directories"] = found_dirs
    
    def _check_directory(self, url, directory):
        """Check if a directory exists"""
        response = self._make_request(url, allow_redirects=False)
        if not response:
            return None
        
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
        """Enumerate subdomains with improved performance and rate limiting"""
        ColorOutput.section("Subdomain Enumeration")
        
        # Extract root domain
        domain_parts = self.domain.split('.')
        if len(domain_parts) > 2:
            root_domain = '.'.join(domain_parts[-2:])
        else:
            root_domain = self.domain
        
        ColorOutput.info(f"Enumerating subdomains for {root_domain}")
        
        subdomains = set()
        chunk_size = 20  # Process subdomains in chunks
        
        # Method 1: DNS brute force with common subdomains
        common_subdomains = ["www", "mail", "ftp", "webmail", "login", "admin", "test", 
                         "dev", "staging", "api", "portal", "blog", "shop", "store",
                         "support", "help", "forum", "news", "app", "m", "mobile",
                         "secure", "vpn", "internal", "cdn", "media", "images", "docs"]
        
        for i in range(0, len(common_subdomains), chunk_size):
            chunk = common_subdomains[i:i + chunk_size]
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_subdomain = {executor.submit(self._check_subdomain, f"{sub}.{root_domain}"): sub 
                                      for sub in chunk}
                
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
            
            # Add a small delay between chunks to avoid overwhelming DNS servers
            if i + chunk_size < len(common_subdomains):
                time.sleep(2)  # Increased delay to respect rate limits
        
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
                "cf-ray",
                "__cfduid",
                "cloudflare-nginx",
                "cf-request-id",
                "cf-cache-status",
                "cf-edge-cache",
                "cf-waf",
                "cloudflare-waf"
            ],
            "AWS WAF/Shield": [
                "awselb",
                "x-amzn-",
                "x-amz-cf-id",
                "x-amzn-trace-id",
                "x-amzn-requestid",
                "x-amz-cf-pop",
                "aws-waf",
                "cloudfront",
                "cloudfront-waf"
            ],
            "Akamai": [
                "akamaighost",
                "ak_bmsc",
                "x-akamai",
                "akamaiedge",
                "akamaitechnologies",
                "akamaicdn",
                "akamaiwaf",
                "akamai-waf"
            ],
            "Imperva/Incapsula": [
                "incap_ses",
                "visid_incap",
                "_incapsula_",
                "incap-client-ip",
                "incap-request-id",
                "incapsula",
                "imperva",
                "imperva-waf",
                "securesphere",
                "incapsula-waf"
            ],
            "F5 BIG-IP ASM": [
                "BigIP",
                "F5-TrafficShield",
                "TS",
                "F5-Auth-Token",
                "F5-Client-IP",
                "bigipserver",
                "f5asm",
                "f5-asm",
                "f5-bigip",
                "f5-bigip-asm"
            ],
            "Sucuri": [
                "sucuri",
                "x-sucuri",
                "sucuri_cloudproxy",
                "sucuri-firewall",
                "sucuri-waf"
            ],
            "ModSecurity": [
                "mod_security",
                "modsec",
                "mod_security2",
                "mod_security3",
                "modsec-audit",
                "modsecurity"
            ],
            "Barracuda": [
                "barracuda",
                "barracuda-waf",
                "barracuda-nginx",
                "barracuda-csrf"
            ],
            "Fortinet FortiWeb": [
                "fortinet",
                "fortiweb",
                "fortiweb-waf",
                "fortigate",
                "fortinet-fortiweb",
                "fortigate-waf"
            ],
            "DenyAll": [
                "denyall",
                "denyall-waf",
                "denyall-proxy"
            ],
            "Wallarm": [
                "wallarm",
                "wallarm-waf",
                "wallarm-proxy"
            ],
            "Signal Sciences": [
                "signalsciences",
                "signalsciences-waf",
                "signalsciences-proxy"
            ],
            "Radware AppWall": [
                "radware",
                "radware-waf",
                "radware-proxy",
                "defensepro"
            ],
            "Citrix NetScaler": [
                "netscaler",
                "citrix-netscaler",
                "citrix",
                "citrix-adc"
            ],
            "Cloudbric": [
                "cloudbric",
                "cloudbric-waf",
                "cloudbric-proxy"
            ],
            "Reblaze": [
                "reblaze",
                "reblaze-waf",
                "reblaze-proxy"
            ],
            "Tencent WAF": [
                "tencentwaf",
                "tencent-waf",
                "tencent-proxy",
                "tencent-cloud-waf"
            ],
            "Microsoft Azure WAF": [
                "azurewaf",
                "x-azure-ref",
                "x-azure-waf",
                "azurefd",
                "azure-frontdoor"
            ],
            "Google Cloud Armor": [
                "google-cloud-armor",
                "x-cloud-trace-context",
                "x-google-cache-control",
                "gfe",
                "google-frontends"
            ],
            "Alibaba Cloud WAF": [
                "aliyun-waf",
                "x-acs-waf",
                "aliyun-proxy"
            ],
            "Fastly": [
                "fastly",
                "fastly-debug",
                "fastly-proxy"
            ],
            "StackPath": [
                "stackpath",
                "stackpathcdn",
                "stackpath-proxy"
            ],
            "AppTrana": [
                "apptrana",
                "apptrana-waf"
            ],
            "BlazingFast": [
                "blazingfast",
                "blazingfast-waf"
            ],
            "Cdn77": [
                "cdn77",
                "cdn77-waf"
            ],
            "NAXSI": [
                "naxsi",
                "naxsi-waf"
            ],
            "OpenResty WAF": [
                "openresty",
                "openresty-waf"
            ],
            "WebKnight": [
                "webknight"
            ],
            "Safe3 WAF": [
                "safe3"
            ],
            "360 WAF": [
                "360waf"
            ],
            "Yundun WAF": [
                "yundun"
            ],
            "Qiniu WAF": [
                "qiniu"
            ],
            "Baidu WAF": [
                "baidu"
            ],
            "Huawei WAF": [
                "huawei"
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
        """Discover API endpoints with improved performance and rate limiting"""
        ColorOutput.section("API Endpoint Discovery")
        
        api_paths = [
            "api", "api/v1", "api/v2", "api/v3", 
            "rest", "graphql", "v1", "v2", "v3",
            "swagger", "swagger-ui", "swagger-ui.html", "swagger/ui", 
            "api-docs", "api/docs", "openapi.json", "openapi.yaml",
            "graphiql", "playground"
        ]
        
        discovered_apis = []
        chunk_size = 5  # Process API paths in small chunks
        
        ColorOutput.info("Searching for API endpoints...")
        
        for i in range(0, len(api_paths), chunk_size):
            chunk = api_paths[i:i + chunk_size]
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_path = {executor.submit(self._check_api_path, f"{self.target_url}/{path}"): path 
                                 for path in chunk}
                
                for future in concurrent.futures.as_completed(future_to_path):
                    path = future_to_path[future]
                    try:
                        result = future.result()
                        if result:
                            discovered_apis.append(result)
                    except Exception as e:
                        if self.verbose:
                            ColorOutput.error(f"Error checking API path {path}: {str(e)}")
            
            # Add a small delay between chunks to avoid overwhelming the server
            if i + chunk_size < len(api_paths):
                time.sleep(1)  # Increased delay to respect rate limits
        
        self.results["api_endpoints"] = discovered_apis
        
        if discovered_apis:
            ColorOutput.success(f"Discovered {len(discovered_apis)} potential API endpoints")
        else:
            ColorOutput.info("No API endpoints discovered")

    def _check_api_path(self, url):
        """Check if a path returns API-like content"""
        response = self._make_request(url)
        if not response:
            return None
        
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
        """Check for CORS misconfigurations with enhanced tests and reporting"""
        ColorOutput.section("CORS Misconfiguration Check")

        # Expanded test origins to cover more edge cases and common bypasses
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            f"https://{self.domain}.evil.com",
            f"https://{self.domain}.attacker.com",
            f"https://{self.domain}.com",  # Subdomain confusion
            f"https://evil{self.domain}",  # Domain confusion
            f"http://{self.domain}",  # HTTP instead of HTTPS
            f"https://{self.domain}:443",  # Explicit port
            f"https://{self.domain}:444",  # Non-standard port
            f"https://{self.domain}.",  # Trailing dot
            f"https://{self.domain}%00.evil.com",  # Null byte injection
            f"https://{self.domain}.com.evil.com",  # Nested subdomain
            "file://",  # File scheme
            "chrome-extension://",  # Browser extension scheme
            "https://localhost",  # Localhost origin
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

                response = self._make_request(
                    self.target_url,
                    headers=headers,
                    verify=False
                )
                
                if not response:
                    continue

                acao_header = response.headers.get('Access-Control-Allow-Origin')
                acac_header = response.headers.get('Access-Control-Allow-Credentials')
                acah_header = response.headers.get('Access-Control-Allow-Headers')
                acam_header = response.headers.get('Access-Control-Allow-Methods')

                if acao_header:
                    issue = {
                        "origin_tested": origin,
                        "acao_header": acao_header,
                        "acac_header": acac_header,
                        "acah_header": acah_header,
                        "acam_header": acam_header,
                    }

                    # Check for wildcard with credentials
                    if acao_header == '*':
                        if acac_header == 'true':
                            issue["severity"] = "Critical"
                            issue["description"] = "Wildcard CORS with credentials allowed"
                            ColorOutput.error(f"Critical CORS misconfiguration: Wildcard (*) with credentials")
                        else:
                            issue["severity"] = "High"
                            issue["description"] = "Wildcard CORS without credentials"
                            ColorOutput.warning(f"CORS misconfiguration: Wildcard (*) origin allowed")

                    # Check if reflected origin matches the origin header and is not the target domain itself
                    elif acao_header == origin and origin != self.target_url:
                        if acac_header == 'true':
                            issue["severity"] = "Critical"
                            issue["description"] = f"Reflects arbitrary origin ({origin}) with credentials"
                            ColorOutput.error(f"Critical CORS misconfiguration: Reflects {origin} with credentials")
                        else:
                            issue["severity"] = "High"
                            issue["description"] = f"Reflects arbitrary origin ({origin})"
                            ColorOutput.warning(f"CORS misconfiguration: Reflects arbitrary origin {origin}")

                    # Check for partial matches or suspicious patterns
                    elif self.domain in acao_header and acao_header != self.target_url:
                        issue["severity"] = "Medium"
                        issue["description"] = f"Partial origin reflection or subdomain mismatch: {acao_header}"
                        ColorOutput.warning(f"CORS misconfiguration: Partial origin reflection {acao_header}")

                    # Check for missing or empty ACAO header when Origin was sent
                    elif acao_header == 'null' or acao_header == '':
                        issue["severity"] = "Low"
                        issue["description"] = "Empty or null Access-Control-Allow-Origin header"
                        ColorOutput.warning(f"CORS misconfiguration: Empty/null ACAO header")

                    if "severity" in issue:
                        cors_issues.append(issue)

            except requests.exceptions.RequestException as e:
                if self.verbose:
                    ColorOutput.error(f"Error testing CORS with origin {origin}: {str(e)}")

        if not cors_issues:
            ColorOutput.success("No CORS misconfigurations detected")

        self.results["cors_issues"] = cors_issues

    def _js_analysis(self):
        """Analyze JavaScript files for endpoints, secrets, and suspicious patterns"""
        ColorOutput.section("JavaScript Analysis")

        try:
            response = self._make_request(
                self.target_url,
                headers={"User-Agent": USER_AGENT},
                verify=False
            )
            
            if not response:
                return

            # Extract all JS file references
            js_files = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', response.text, re.IGNORECASE)

            if not js_files:
                ColorOutput.info("No JavaScript files found")
                return

            ColorOutput.info(f"Found {len(js_files)} JavaScript files")

            # Normalize URLs to absolute
            def normalize_url(js_url):
                if js_url.startswith('//'):
                    return 'https:' + js_url
                elif js_url.startswith('/'):
                    return urllib.parse.urljoin(self.target_url, js_url)
                elif not js_url.startswith(('http://', 'https://')):
                    return urllib.parse.urljoin(self.target_url + '/', js_url)
                return js_url

            js_files = [normalize_url(js) for js in js_files]

            # Limit to 5 JS files for analysis
            js_files = js_files[:5]

            def analyze_js(js_file):
                try:
                    js_response = self._make_request(
                        js_file,
                        headers={"User-Agent": USER_AGENT},
                        verify=False
                    )
                    
                    if not js_response:
                        return None
                        
                    js_content = js_response.text

                    endpoints = set()
                    # Expanded URL and API endpoint patterns
                    url_patterns = [
                        r'https?://[^\s"\'<>]+',  # Full URLs
                        r'["\']\/api\/[^\s"\'<>]+',  # API endpoints starting with /api/
                        r'["\']\/v[0-9]+\/[^\s"\'<>]+',  # Versioned API endpoints
                        r'["\']\/graphql[^\s"\'<>]*',  # GraphQL endpoints
                        r'["\']\/auth[^\s"\'<>]*',  # Auth endpoints
                        r'["\']\/static[^\s"\'<>]*',  # Static resource endpoints
                    ]

                    for pattern in url_patterns:
                        for match in re.findall(pattern, js_content, re.IGNORECASE):
                            endpoint = match.strip('\'"')
                            endpoints.add(endpoint)

                    secrets = []
                    # More comprehensive secret patterns
                    secret_patterns = [
                        (r'(?:api[_-]?key|apikey|apiKey|token|access[_-]?token|auth[_-]?token|secret|password|passwd|pwd|jwt)[\s:=]{1,3}["\']([^"\']{8,})["\']', "Potential Secret"),
                        (r'aws_access_key_id[\s:=]{1,3}["\']([^"\']{16,})["\']', "AWS Access Key"),
                        (r'aws_secret_access_key[\s:=]{1,3}["\']([^"\']{16,})["\']', "AWS Secret Key"),
                        (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token"),
                        (r'eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}', "JWT Token"),
                    ]

                    for pattern, secret_type in secret_patterns:
                        for match in re.findall(pattern, js_content, re.IGNORECASE):
                            secrets.append({
                                "type": secret_type,
                                "partial_value": match[:4] + '****'
                            })

                    # Detect suspicious patterns
                    suspicious_patterns = {
                        "eval_usage": r'\beval\s*\(',
                        "document_write": r'document\.write\s*\(',
                        "innerHTML_assignment": r'\.innerHTML\s*=',
                        "console_log": r'console\.log\s*\(',
                        "debugger_statement": r'\bdebugger\b',
                    }
                    suspicious_findings = {}
                    for name, pattern in suspicious_patterns.items():
                        matches = re.findall(pattern, js_content)
                        if matches:
                            suspicious_findings[name] = len(matches)

                    file_info = {
                        "url": js_file,
                        "size": len(js_content),
                        "endpoints": list(endpoints),
                        "suspicious_patterns": suspicious_findings
                    }

                    if secrets:
                        file_info["potential_secrets"] = secrets
                        ColorOutput.warning(f"Found {len(secrets)} potential secrets in {js_file}")

                    if endpoints:
                        ColorOutput.success(f"Found {len(endpoints)} endpoints in {js_file}")

                    if suspicious_findings:
                        ColorOutput.info(f"Found suspicious patterns in {js_file}: {', '.join(suspicious_findings.keys())}")

                    return file_info

                except requests.exceptions.RequestException as e:
                    if self.verbose:
                        ColorOutput.error(f"Error analyzing JavaScript file {js_file}: {str(e)}")
                    return None

            # Use ThreadPoolExecutor for concurrent fetching and analysis
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                results = list(executor.map(analyze_js, js_files))

            # Filter out None results
            js_data = [res for res in results if res]

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
            with open(report_file, 'w', encoding='utf-8') as f:
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
        .no-data {{ color: #999; font-style: italic; }}
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

                # Helper function to safely get nested dictionary values
                def safe_get(data, *keys, default="N/A"):
                    try:
                        for key in keys:
                            data = data[key]
                        return data if data is not None else default
                    except (KeyError, TypeError):
                        return default

                # DNS Information
                dns_info = safe_get(self.results, "dns_info", default={})
                if dns_info:
                    f.write(f"""
        <div class="section">
            <h2>DNS Information</h2>
            <table>
                <tr>
                    <th>Record Type</th>
                    <th>Values</th>
                </tr>
""")
                    for record_type, values in dns_info.items():
                        if values:
                            f.write(f"""
                <tr>
                    <td>{record_type}</td>
                    <td>{', '.join(str(v) for v in values)}</td>
                </tr>
""")
                    f.write("""
            </table>
        </div>
""")

                # Open Ports
                open_ports = safe_get(self.results, "open_ports", default=[])
                if open_ports:
                    f.write("""
        <div class="section">
            <h2>Open Ports</h2>
            <p>The following ports were found to be open:</p>
            <ul>
""")
                    for port in open_ports:
                        f.write(f"                <li>{port}</li>\n")
                    f.write("""
            </ul>
        </div>
""")

                # HTTP Headers
                headers = safe_get(self.results, "headers", default={})
                if headers:
                    f.write("""
        <div class="section">
            <h2>HTTP Headers</h2>
            <table>
                <tr>
                    <th>Header</th>
                    <th>Value</th>
                </tr>
""")
                    for header, value in headers.items():
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
                technologies = safe_get(self.results, "technologies", default={})
                if technologies:
                    f.write("""
        <div class="section">
            <h2>Technologies Detected</h2>
            <ul>
""")
                    for tech, version in technologies.items():
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
                subdomains = safe_get(self.results, "subdomains", default=[])
                if subdomains:
                    f.write("""
        <div class="section">
            <h2>Subdomains Discovered</h2>
            <ul>
""")
                    for subdomain in subdomains:
                        f.write(f"                <li>{subdomain}</li>\n")
                    f.write("""
            </ul>
        </div>
""")

                # Vulnerabilities
                vulnerabilities = safe_get(self.results, "vulnerabilities", default=[])
                if vulnerabilities:
                    f.write("""
        <div class="section">
            <h2>Potential Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>URL</th>
                    <th>Details</th>
                </tr>
""")
                    for vuln in vulnerabilities:
                        vuln_type = safe_get(vuln, "type", default="Unknown")
                        url = safe_get(vuln, "url", default="N/A")
                        details = safe_get(vuln, "details", default="")
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
                waf = safe_get(self.results, "waf", default=[])
                if waf:
                    f.write("""
        <div class="section">
            <h2>WAF Detection</h2>
            <ul>
""")
                    for waf_name in waf:
                        f.write(f"                <li>{waf_name}</li>\n")
                    f.write("""
            </ul>
        </div>
""")

                # API Endpoints
                api_endpoints = safe_get(self.results, "api_endpoints", default=[])
                if api_endpoints:
                    f.write("""
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
                    for api in api_endpoints:
                        url = safe_get(api, "url", default="N/A")
                        status = safe_get(api, "status_code", default="N/A")
                        ctype = safe_get(api, "content_type", default="N/A")
                        clen = safe_get(api, "content_length", default="N/A")
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
                cors_issues = safe_get(self.results, "cors_issues", default=[])
                if cors_issues:
                    f.write("""
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
                    for issue in cors_issues:
                        origin = safe_get(issue, "origin_tested", default="N/A")
                        acao = safe_get(issue, "acao_header", default="N/A")
                        acac = safe_get(issue, "acac_header", default="N/A")
                        severity = safe_get(issue, "severity", default="N/A")
                        description = safe_get(issue, "description", default="")
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
                js_analysis = safe_get(self.results, "javascript_analysis", default=[])
                if js_analysis:
                    f.write("""
        <div class="section">
            <h2>JavaScript Analysis</h2>
""")
                    for js_file in js_analysis:
                        f.write(f"""
            <h3>File: {safe_get(js_file, 'url', default='N/A')}</h3>
            <p>Size: {safe_get(js_file, 'size', default='N/A')} bytes</p>
""")
                        endpoints = safe_get(js_file, "endpoints", default=[])
                        if endpoints:
                            f.write("""
            <h4>Discovered Endpoints:</h4>
            <ul>
""")
                            for endpoint in endpoints:
                                f.write(f"                <li>{endpoint}</li>\n")
                            f.write("""
            </ul>
""")
                        secrets = safe_get(js_file, "potential_secrets", default=[])
                        if secrets:
                            f.write("""
            <h4>Potential Secrets:</h4>
            <ul>
""")
                            for secret in secrets:
                                secret_type = safe_get(secret, "type", default="Unknown")
                                partial_value = safe_get(secret, "partial_value", default="N/A")
                                f.write(f"                <li>{secret_type}: {partial_value}</li>\n")
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
            ColorOutput.error(f"Failed to generate HTML report: {str(e)}")
            if self.verbose:
                import traceback
                ColorOutput.error(traceback.format_exc())

    def __del__(self):
        """Cleanup resources when the object is destroyed"""
        if hasattr(self, 'session'):
            self.session.close()
        # Clear cache
        self.cache.clear()
        # Clear LRU cache
        self._dns_query.cache_clear()


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description=f"Advanced Web Application Reconnaissance Tool (ADVWebRecon) v{VERSION}")
    
    parser.add_argument("-u", "--url", dest="url", help="Target URL", required=True)
    parser.add_argument("-o", "--output", dest="output", help="Output file (JSON format)", default=None)
    parser.add_argument("-t", "--threads", dest="threads", help="Number of threads", type=int, default=5)
    parser.add_argument("--timeout", dest="timeout", help="Request timeout in seconds", type=int, default=10)
    parser.add_argument("-v", "--verbose", dest="verbose", help="Verbose output", action="store_true")
    parser.add_argument("-i", "--interactive", dest="interactive", help="Run in interactive mode", action="store_true")
    
    args = parser.parse_args()
    
    print(f"""
    █████╗ ██████╗ ██╗   ██╗    ██╗    ██╗███████╗██████╗     ██████╗ ███████╗ ██████╗ ███╗   ██╗
   ██╔══██╗██╔══██╗██║   ██║    ██║    ██║██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔═══██╗████╗  ██║
   ███████║██║  ██║██║   ██║    ██║ █╗ ██║█████╗  ██████╔╝    ██████╔╝█████╗  ██║   ██║██╔██╗ ██║
   ██╔══██║██║  ██║╚██╗ ██╔╝    ██║███╗██║██╔══╝  ██╔══██╗    ██╔══██╗██╔══╝  ██║   ██║██║╚██╗██║
   ██║  ██║██████╔╝ ╚████╔╝     ╚███╔███╔╝███████╗██████ ║    ██║  ██║███████╗╚██████╔╝██║ ╚████║
   ╚═╝  ╚═╝╚═════╝   ╚═══╝       ╚══╝╚══╝ ╚══════╝╚══════╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                                                 
   Advanced Web Application Reconnaissance Tool v{VERSION}
   Made by viphacker100
   
   """)
    
    recon = ADVWebRecon(
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
