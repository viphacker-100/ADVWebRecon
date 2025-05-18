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
    
    # Colors
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Box drawing characters
    BOX_TOP_LEFT = '┌'
    BOX_TOP_RIGHT = '┐'
    BOX_BOTTOM_LEFT = '└'
    BOX_BOTTOM_RIGHT = '┘'
    BOX_HORIZONTAL = '─'
    BOX_VERTICAL = '│'
    BOX_T_DOWN = '┬'
    BOX_T_UP = '┴'
    BOX_T_RIGHT = '├'
    BOX_T_LEFT = '┤'
    BOX_CROSS = '┼'
    
    @staticmethod
    def _print_boxed(text, color=None, width=80):
        """Print text in a box with optional color"""
        lines = text.split('\n')
        max_length = max(len(line) for line in lines)
        box_width = min(max_length + 4, width)
        
        # Print top border
        print(f"{color if color else ''}{ColorOutput.BOX_TOP_LEFT}{ColorOutput.BOX_HORIZONTAL * (box_width - 2)}{ColorOutput.BOX_TOP_RIGHT}{ColorOutput.ENDC}")
        
        # Print content
        for line in lines:
            padding = ' ' * ((box_width - len(line) - 2) // 2)
            print(f"{color if color else ''}{ColorOutput.BOX_VERTICAL}{padding}{line}{padding}{' ' if (box_width - len(line)) % 2 else ''}{ColorOutput.BOX_VERTICAL}{ColorOutput.ENDC}")
        
        # Print bottom border
        print(f"{color if color else ''}{ColorOutput.BOX_BOTTOM_LEFT}{ColorOutput.BOX_HORIZONTAL * (box_width - 2)}{ColorOutput.BOX_BOTTOM_RIGHT}{ColorOutput.ENDC}")

    @staticmethod
    def _print_separator(char='─', color=None, width=80):
        """Print a separator line"""
        print(f"{color if color else ''}{char * width}{ColorOutput.ENDC}")

    @staticmethod
    def info(message):
        """Print info message in blue"""
        print(f"{ColorOutput.BLUE}[*] {message}{ColorOutput.ENDC}")

    @staticmethod
    def success(message):
        """Print success message in green"""
        print(f"{ColorOutput.GREEN}[+] {message}{ColorOutput.ENDC}")

    @staticmethod
    def warning(message):
        """Print warning message in yellow"""
        print(f"{ColorOutput.YELLOW}[!] {message}{ColorOutput.ENDC}")

    @staticmethod
    def error(message):
        """Print error message in red"""
        print(f"{ColorOutput.RED}[-] {message}{ColorOutput.ENDC}")

    @staticmethod
    def section(title):
        """Print section title in purple with box"""
        ColorOutput._print_separator(ColorOutput.PURPLE)
        ColorOutput._print_boxed(title, ColorOutput.PURPLE + ColorOutput.BOLD)
        ColorOutput._print_separator(ColorOutput.PURPLE)

    @staticmethod
    def attention(message):
        """Print attention message in bold yellow"""
        print(f"{ColorOutput.YELLOW}{ColorOutput.BOLD}[!] {message}{ColorOutput.ENDC}")

    @staticmethod
    def table(headers, rows, title=None):
        """Print a formatted table"""
        if not rows:
            return
        
        # Calculate column widths
        col_widths = [len(str(header)) for header in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Print title if provided
        if title:
            ColorOutput.section(title)
        
        # Print headers
        header_str = f"{ColorOutput.BOX_VERTICAL} "
        for i, header in enumerate(headers):
            header_str += f"{ColorOutput.BOLD}{header}{ColorOutput.ENDC}{' ' * (col_widths[i] - len(str(header)))} {ColorOutput.BOX_VERTICAL} "
        print(header_str)
        
        # Print separator
        separator = f"{ColorOutput.BOX_T_RIGHT}"
        for width in col_widths:
            separator += f"{ColorOutput.BOX_HORIZONTAL * (width + 2)}{ColorOutput.BOX_CROSS}"
        separator = separator[:-1] + ColorOutput.BOX_T_LEFT
        print(separator)
        
        # Print rows
        for row in rows:
            row_str = f"{ColorOutput.BOX_VERTICAL} "
            for i, cell in enumerate(row):
                row_str += f"{str(cell)}{' ' * (col_widths[i] - len(str(cell)))} {ColorOutput.BOX_VERTICAL} "
            print(row_str)
        
        # Print bottom border
        bottom = f"{ColorOutput.BOX_BOTTOM_LEFT}"
        for width in col_widths:
            bottom += f"{ColorOutput.BOX_HORIZONTAL * (width + 2)}{ColorOutput.BOX_T_UP}"
        bottom = bottom[:-1] + ColorOutput.BOX_BOTTOM_RIGHT
        print(bottom)

    @staticmethod
    def progress(current, total, prefix='', suffix='', length=50):
        """Print a progress bar"""
        percent = current / total
        filled_length = int(length * percent)
        bar = '█' * filled_length + '░' * (length - filled_length)
        print(f'\r{prefix} |{bar}| {percent:.1%} {suffix}', end='')
        if current == total:
            print()

    @staticmethod
    def key_value(key, value, indent=0):
        """Print a key-value pair with proper formatting"""
        indent_str = ' ' * indent
        print(f"{indent_str}{ColorOutput.BOLD}{key}:{ColorOutput.ENDC} {value}")

    @staticmethod
    def list_item(item, indent=0, bullet='•'):
        """Print a list item with proper formatting"""
        indent_str = ' ' * indent
        print(f"{indent_str}{ColorOutput.YELLOW}{bullet}{ColorOutput.ENDC} {item}")

    @staticmethod
    def highlight(text, color=YELLOW):
        """Highlight specific text in a message"""
        return f"{color}{text}{ColorOutput.ENDC}"

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
        self.custom_headers = {}  # Add custom headers attribute
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

    def _normalize_url(self, url):
        """Normalize the URL to include a scheme if missing"""
        if not url.startswith(('http://', 'https://')):
            ColorOutput.warning(f"URL scheme missing, assuming https:// for {url}")
            return 'https://' + url
        return url

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
        """Run all reconnaissance modules with enhanced error handling and reporting"""
        ColorOutput.section(f"Starting Advanced Web Reconnaissance on {self.target_url}")
        ColorOutput.info(f"Target domain: {self.domain}")
        
        try:
            # Run modules with error handling
            modules = [
                (self._dns_enumeration, "DNS Enumeration"),
                (self._port_scanning, "Port Scanning"),
                (self._analyze_headers, "Headers Analysis"),
                (self._detect_methods, "Methods Detection"),
                (self._analyze_ssl, "SSL/TLS Analysis"),
                (self._check_robots_sitemap, "Robots.txt & Sitemap Analysis"),
                (self._directory_discovery, "Directory Discovery"),
                (self._advanced_fingerprinting, "Technology Fingerprinting"),
                (self._subdomain_enumeration, "Subdomain Enumeration"),
                (self._vulnerability_checks, "Vulnerability Checks"),
                (self._detect_waf, "WAF Detection"),
                (self._api_discovery, "API Discovery"),
                (self._check_cors_misconfig, "CORS Misconfiguration Check"),
                (self._js_analysis, "JavaScript Analysis")
            ]
            
            for module, name in modules:
                try:
                    ColorOutput.section(f"Running {name}")
                    module()
                except Exception as e:
                    ColorOutput.error(f"Error in {name}: {str(e)}")
                    if self.verbose:
                        import traceback
                        ColorOutput.error(traceback.format_exc())
                    continue
            
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
        except Exception as e:
            ColorOutput.error(f"Unexpected error during reconnaissance: {str(e)}")
            if self.verbose:
                import traceback
                ColorOutput.error(traceback.format_exc())
            return False
            
        return True
    
    def _write_results(self, format='json'):
        """Write results to output file with multiple format options"""
        try:
            # Fix and validate results before writing
            if not self._fix_results():
                ColorOutput.error("Failed to fix results, aborting write")
                return

            if not self.output_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.output_file = f"recon_results_{self.domain}_{timestamp}"

            # Add additional analysis to results
            self._enhance_results()

            # Display results in terminal first
            self._display_results()

            # Write to file based on format
            if format.lower() == 'json':
                output_file = f"{self.output_file}.json"
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=4)
                ColorOutput.success(f"Results saved to {output_file}")

            elif format.lower() == 'yaml':
                try:
                    import yaml
                    output_file = f"{self.output_file}.yaml"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        yaml.dump(self.results, f, default_flow_style=False)
                    ColorOutput.success(f"Results saved to {output_file}")
                except ImportError:
                    ColorOutput.error("PyYAML not installed. Install it using: pip install pyyaml")
                    return

            elif format.lower() == 'csv':
                output_file = f"{self.output_file}.csv"
                self._write_csv_results(output_file)
                ColorOutput.success(f"Results saved to {output_file}")

            elif format.lower() == 'txt':
                output_file = f"{self.output_file}.txt"
                self._write_txt_results(output_file)
                ColorOutput.success(f"Results saved to {output_file}")

            else:
                ColorOutput.error(f"Unsupported format: {format}")
                return

            # Generate HTML report
            self.generate_html_report()

        except Exception as e:
            ColorOutput.error(f"Error writing results to file: {str(e)}")
            if self.verbose:
                import traceback
                ColorOutput.error(traceback.format_exc())

    def _display_results(self):
        """Display results in a professional format in the terminal"""
        ColorOutput.section("Reconnaissance Results")
        
        # Target Information
        ColorOutput.section("Target Information")
        ColorOutput.key_value("Target URL", self.target_url)
        ColorOutput.key_value("Domain", self.domain)
        ColorOutput.key_value("Scan Date", self.results.get('timestamp', 'N/A'))
        
        # Security Score
        score = self.results.get('security_score', 0)
        risk_level = self.results.get('risk_level', 'Unknown')
        ColorOutput.section("Security Assessment")
        
        # Create a visual score representation
        score_bar = '█' * (score // 10) + '░' * (10 - (score // 10))
        ColorOutput.info(f"Security Score: {score}/100")
        print(f"{ColorOutput.BOLD}Score: {ColorOutput.ENDC}[{score_bar}] {score}%")
        ColorOutput.key_value("Risk Level", risk_level)
        
        # DNS Information
        if "dns_info" in self.results and self.results["dns_info"]:
            ColorOutput.section("DNS Information")
            headers = ["Record Type", "Values"]
            rows = []
            for record_type, values in self.results["dns_info"].items():
                if values:
                    rows.append([record_type, ', '.join(values)])
            ColorOutput.table(headers, rows)
        
        # Open Ports
        if "open_ports" in self.results and self.results["open_ports"]:
            ColorOutput.section("Open Ports")
            headers = ["Port", "Service"]
            rows = [[port, self._get_service_name(port)] for port in self.results["open_ports"]]
            ColorOutput.table(headers, rows)
        
        # Technologies
        if "technologies" in self.results and self.results["technologies"]:
            ColorOutput.section("Technologies Detected")
            headers = ["Technology", "Version"]
            rows = []
            for tech, version in self.results["technologies"].items():
                version_str = "Detected" if isinstance(version, bool) else f"Version: {version}"
                rows.append([tech, version_str])
            ColorOutput.table(headers, rows)
        
        # Vulnerabilities
        if "vulnerabilities" in self.results and self.results["vulnerabilities"]:
            ColorOutput.section("Potential Vulnerabilities")
            headers = ["Type", "URL", "Details"]
            rows = []
            for vuln in self.results["vulnerabilities"]:
                rows.append([
                    vuln.get('type', 'Unknown'),
                    vuln.get('url', 'N/A'),
                    vuln.get('details', '')
                ])
            ColorOutput.table(headers, rows)
        
        # WAF Detection
        if "waf" in self.results and self.results["waf"]:
            ColorOutput.section("WAF Detection")
            for waf in self.results["waf"]:
                ColorOutput.list_item(waf)
        
        # API Endpoints
        if "api_endpoints" in self.results and self.results["api_endpoints"]:
            ColorOutput.section("API Endpoints")
            headers = ["URL", "Status", "Content Type"]
            rows = []
            for api in self.results["api_endpoints"]:
                rows.append([
                    api.get('url', 'N/A'),
                    api.get('status_code', 'N/A'),
                    api.get('content_type', 'N/A')
                ])
            ColorOutput.table(headers, rows)
        
        # CORS Issues
        if "cors_issues" in self.results and self.results["cors_issues"]:
            ColorOutput.section("CORS Misconfigurations")
            headers = ["Severity", "Origin", "Description", "Details"]
            rows = []
            for issue in self.results["cors_issues"]:
                details = issue.get('details', {})
                details_str = ""
                if isinstance(details, dict):
                    if 'risk' in details:
                        details_str += f"Risk: {details['risk']}\n"
                    if 'recommendation' in details:
                        details_str += f"Recommendation: {details['recommendation']}"
                
                severity_color = {
                    "Critical": ColorOutput.RED,
                    "High": ColorOutput.RED,
                    "Medium": ColorOutput.YELLOW,
                    "Low": ColorOutput.BLUE
                }.get(issue.get('severity', 'Unknown'), ColorOutput.ENDC)
                
                rows.append([
                    f"{severity_color}{issue.get('severity', 'N/A')}{ColorOutput.ENDC}",
                    issue.get('origin', 'N/A'),
                    issue.get('description', ''),
                    details_str
                ])
            ColorOutput.table(headers, rows)
            
            # Display CORS score
            cors_score = self.results.get('cors_score', 0)
            ColorOutput.info(f"CORS Security Score: {cors_score}/100")
            score_bar = '█' * (cors_score // 10) + '░' * (10 - (cors_score // 10))
            print(f"{ColorOutput.BOLD}CORS Score: {ColorOutput.ENDC}[{score_bar}] {cors_score}%")
        
        # Recommendations
        if "recommendations" in self.results and self.results["recommendations"]:
            ColorOutput.section("Security Recommendations")
            for rec in self.results["recommendations"]:
                ColorOutput.list_item(rec)
        
        ColorOutput.section("End of Report")

    def _enhance_results(self):
        """Add additional analysis and enhancements to results"""
        # Add security score breakdown
        self.results["security_analysis"] = {
            "score_breakdown": {
                "headers": self._calculate_headers_score(),
                "ssl": self._calculate_ssl_score(),
                "cors": self._calculate_cors_score(),
                "waf": self._calculate_waf_score(),
                "vulnerabilities": self._calculate_vuln_score()
            },
            "recommendations": self._generate_recommendations(),
            "risk_assessment": self._assess_risks()
        }

        # Add technology stack analysis
        self.results["technology_analysis"] = {
            "frontend": self._analyze_frontend_tech(),
            "backend": self._analyze_backend_tech(),
            "frameworks": self._analyze_frameworks(),
            "databases": self._analyze_databases(),
            "servers": self._analyze_servers()
        }

        # Add infrastructure analysis
        self.results["infrastructure_analysis"] = {
            "cdn": self._analyze_cdn(),
            "hosting": self._analyze_hosting(),
            "dns": self._analyze_dns_setup(),
            "email": self._analyze_email_setup()
        }

        # Add performance metrics
        self.results["performance_metrics"] = {
            "response_times": self._measure_response_times(),
            "resource_usage": self._analyze_resource_usage(),
            "caching": self._analyze_caching()
        }

    def _calculate_headers_score(self):
        """Calculate security score based on headers"""
        score = 100
        deductions = []
        
        security_headers = {
            "Strict-Transport-Security": 10,
            "Content-Security-Policy": 10,
            "X-Frame-Options": 5,
            "X-Content-Type-Options": 5,
            "X-XSS-Protection": 5,
            "Referrer-Policy": 5,
            "Permissions-Policy": 5,
            "Cross-Origin-Embedder-Policy": 5,
            "Cross-Origin-Opener-Policy": 5,
            "Cross-Origin-Resource-Policy": 5
        }

        for header, points in security_headers.items():
            if header not in self.results.get("headers", {}):
                score -= points
                deductions.append(f"Missing {header} (-{points} points)")

        return {
            "score": max(0, score),
            "deductions": deductions
        }

    def _calculate_ssl_score(self):
        """Calculate security score based on SSL/TLS configuration"""
        score = 100
        deductions = []
        
        ssl_info = self.results.get("ssl_info", {})
        
        # Check SSL version
        if "version" in ssl_info:
            if "TLSv1.0" in ssl_info["version"] or "TLSv1.1" in ssl_info["version"]:
                score -= 20
                deductions.append("Outdated TLS version (-20 points)")
        
        # Check certificate expiration
        if "days_remaining" in ssl_info:
            if ssl_info["days_remaining"] < 30:
                score -= 15
                deductions.append("Certificate expiring soon (-15 points)")
            elif ssl_info["days_remaining"] < 0:
                score -= 30
                deductions.append("Certificate expired (-30 points)")
        
        return {
            "score": max(0, score),
            "deductions": deductions
        }

    def _calculate_cors_score(self):
        """Calculate security score based on CORS configuration"""
        score = 100
        deductions = []
        
        cors_issues = self.results.get("cors_issues", [])
        for issue in cors_issues:
            if issue.get("severity") == "Critical":
                score -= 30
                deductions.append("Critical CORS misconfiguration (-30 points)")
            elif issue.get("severity") == "High":
                score -= 20
                deductions.append("High severity CORS issue (-20 points)")
            elif issue.get("severity") == "Medium":
                score -= 10
                deductions.append("Medium severity CORS issue (-10 points)")
        
        return {
            "score": max(0, score),
            "deductions": deductions
        }

    def _calculate_waf_score(self):
        """Calculate security score based on WAF presence"""
        score = 100
        deductions = []
        
        waf = self.results.get("waf", [])
        if not waf:
            score -= 20
            deductions.append("No WAF detected (-20 points)")
        
        return {
            "score": max(0, score),
            "deductions": deductions
        }

    def _calculate_vuln_score(self):
        """Calculate security score based on vulnerabilities"""
        score = 100
        deductions = []
        
        vulnerabilities = self.results.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            if "Critical" in str(vuln.get("type", "")):
                score -= 30
                deductions.append("Critical vulnerability (-30 points)")
            elif "High" in str(vuln.get("type", "")):
                score -= 20
                deductions.append("High severity vulnerability (-20 points)")
            elif "Medium" in str(vuln.get("type", "")):
                score -= 10
                deductions.append("Medium severity vulnerability (-10 points)")
        
        return {
            "score": max(0, score),
            "deductions": deductions
        }

    def _generate_recommendations(self):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Header recommendations
        headers = self.results.get("headers", {})
        if "Strict-Transport-Security" not in headers:
            recommendations.append("Implement HSTS to enforce HTTPS")
        if "Content-Security-Policy" not in headers:
            recommendations.append("Implement Content Security Policy")
        
        # SSL recommendations
        ssl_info = self.results.get("ssl_info", {})
        if "version" in ssl_info and ("TLSv1.0" in ssl_info["version"] or "TLSv1.1" in ssl_info["version"]):
            recommendations.append("Upgrade to TLS 1.2 or higher")
        
        # CORS recommendations
        cors_issues = self.results.get("cors_issues", [])
        for issue in cors_issues:
            if issue.get("severity") in ["Critical", "High"]:
                recommendations.append(f"Fix CORS misconfiguration: {issue.get('description', '')}")
        
        # WAF recommendations
        if not self.results.get("waf", []):
            recommendations.append("Consider implementing a Web Application Firewall")
        
        return recommendations

    def _assess_risks(self):
        """Assess overall security risks"""
        risks = []
        
        # Check for critical vulnerabilities
        vulnerabilities = self.results.get("vulnerabilities", [])
        if any("Critical" in str(v.get("type", "")) for v in vulnerabilities):
            risks.append({
                "level": "Critical",
                "description": "Critical vulnerabilities detected",
                "impact": "High risk of system compromise"
            })
        
        # Check SSL/TLS configuration
        ssl_info = self.results.get("ssl_info", {})
        if "version" in ssl_info and ("TLSv1.0" in ssl_info["version"] or "TLSv1.1" in ssl_info["version"]):
            risks.append({
                "level": "High",
                "description": "Outdated TLS version",
                "impact": "Vulnerable to known attacks"
            })
        
        # Check CORS configuration
        cors_issues = self.results.get("cors_issues", [])
        if any(issue.get("severity") == "Critical" for issue in cors_issues):
            risks.append({
                "level": "High",
                "description": "Critical CORS misconfiguration",
                "impact": "Potential for cross-origin attacks"
            })
        
        return risks

    def _analyze_frontend_tech(self):
        """Analyze frontend technologies"""
        frontend = {
            "frameworks": [],
            "libraries": [],
            "ui_components": []
        }
        
        technologies = self.results.get("technologies", {})
        
        # Check for frontend frameworks
        frontend_frameworks = ["React", "Angular", "Vue.js", "Next.js", "Nuxt.js", "Gatsby"]
        for framework in frontend_frameworks:
            if framework in technologies:
                frontend["frameworks"].append(framework)
        
        # Check for UI libraries
        ui_libraries = ["Bootstrap", "Material-UI", "Tailwind CSS", "Foundation"]
        for library in ui_libraries:
            if library in technologies:
                frontend["libraries"].append(library)
        
        return frontend

    def _analyze_backend_tech(self):
        """Analyze backend technologies"""
        backend = {
            "frameworks": [],
            "languages": [],
            "databases": []
        }
        
        technologies = self.results.get("technologies", {})
        
        # Check for backend frameworks
        backend_frameworks = ["Django", "Flask", "Express.js", "Laravel", "Ruby on Rails", "ASP.NET"]
        for framework in backend_frameworks:
            if framework in technologies:
                backend["frameworks"].append(framework)
        
        # Check for programming languages
        languages = ["PHP", "Python", "Node.js", "Ruby", "Java", ".NET"]
        for language in languages:
            if language in technologies:
                backend["languages"].append(language)
        
        return backend

    def _analyze_frameworks(self):
        """Analyze detected frameworks"""
        frameworks = {
            "web": [],
            "cms": [],
            "ecommerce": []
        }
        
        technologies = self.results.get("technologies", {})
        
        # Web frameworks
        web_frameworks = ["Django", "Flask", "Express.js", "Laravel", "Ruby on Rails", "ASP.NET"]
        for framework in web_frameworks:
            if framework in technologies:
                frameworks["web"].append(framework)
        
        # CMS platforms
        cms_platforms = ["WordPress", "Drupal", "Joomla", "Magento"]
        for cms in cms_platforms:
            if cms in technologies:
                frameworks["cms"].append(cms)
        
        # E-commerce platforms
        ecommerce_platforms = ["Shopify", "WooCommerce", "Magento", "PrestaShop"]
        for platform in ecommerce_platforms:
            if platform in technologies:
                frameworks["ecommerce"].append(platform)
        
        return frameworks

    def _analyze_databases(self):
        """Analyze potential database technologies"""
        databases = []
        
        technologies = self.results.get("technologies", {})
        headers = self.results.get("headers", {})
        
        # Check for database indicators
        db_indicators = {
            "MySQL": ["mysql", "mysqli"],
            "PostgreSQL": ["postgres", "postgresql"],
            "MongoDB": ["mongodb", "mongoose"],
            "Redis": ["redis"],
            "SQLite": ["sqlite"],
            "Oracle": ["oracle", "oracle-database"],
            "SQL Server": ["mssql", "sqlserver"]
        }
        
        for db, indicators in db_indicators.items():
            if any(indicator in str(technologies).lower() or indicator in str(headers).lower() for indicator in indicators):
                databases.append(db)
        
        return databases

    def _analyze_servers(self):
        """Analyze web server technologies"""
        servers = []
        
        technologies = self.results.get("technologies", {})
        headers = self.results.get("headers", {})
        
        # Check for server indicators
        server_indicators = {
            "Apache": ["apache", "apache2"],
            "Nginx": ["nginx"],
            "IIS": ["iis", "microsoft-iis"],
            "Tomcat": ["tomcat", "apache-tomcat"],
            "Node.js": ["node", "nodejs"],
            "LiteSpeed": ["litespeed"],
            "OpenResty": ["openresty"]
        }
        
        for server, indicators in server_indicators.items():
            if any(indicator in str(technologies).lower() or indicator in str(headers).lower() for indicator in indicators):
                servers.append(server)
        
        return servers

    def _analyze_cdn(self):
        """Analyze CDN usage"""
        cdn_info = {
            "provider": None,
            "features": [],
            "headers": []
        }
        
        headers = self.results.get("headers", {})
        
        # Check for CDN providers
        cdn_providers = {
            "Cloudflare": ["cf-ray", "cf-cache-status", "cf-request-id"],
            "Akamai": ["x-akamai-transformed", "akamai-origin-hop"],
            "Fastly": ["fastly-io", "x-fastly"],
            "Amazon CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
            "Google Cloud CDN": ["x-goog-generation", "x-goog-metageneration"]
        }
        
        for provider, indicators in cdn_providers.items():
            if any(indicator.lower() in str(headers).lower() for indicator in indicators):
                cdn_info["provider"] = provider
                break
        
        # Check for CDN features
        if "cf-cache-status" in headers:
            cdn_info["features"].append("Caching")
        if "cf-wan-error" in headers:
            cdn_info["features"].append("Error Handling")
        
        # Store CDN-related headers
        cdn_headers = [header for header in headers if any(
            cdn in header.lower() for cdn in ["cf-", "x-cdn-", "x-cache", "x-cache-status"]
        )]
        cdn_info["headers"] = cdn_headers
        
        return cdn_info

    def _analyze_hosting(self):
        """Analyze hosting infrastructure"""
        hosting_info = {
            "provider": None,
            "type": None,
            "indicators": []
        }
        
        headers = self.results.get("headers", {})
        technologies = self.results.get("technologies", {})
        
        # Check for hosting providers
        hosting_providers = {
            "AWS": ["x-amz-cf-id", "x-amz-request-id", "x-amz-id-2"],
            "Google Cloud": ["x-goog-generation", "x-goog-metageneration"],
            "Azure": ["x-azure-ref", "x-azure-requestid"],
            "DigitalOcean": ["x-datacenter", "x-droplet-id"],
            "Heroku": ["x-request-id", "x-runtime"],
            "Cloudflare": ["cf-ray", "cf-cache-status"]
        }
        
        for provider, indicators in hosting_providers.items():
            if any(indicator.lower() in str(headers).lower() for indicator in indicators):
                hosting_info["provider"] = provider
                break
        
        # Determine hosting type
        if "serverless" in str(technologies).lower() or "lambda" in str(technologies).lower():
            hosting_info["type"] = "Serverless"
        elif "kubernetes" in str(technologies).lower() or "k8s" in str(technologies).lower():
            hosting_info["type"] = "Container"
        elif "vps" in str(technologies).lower() or "droplet" in str(technologies).lower():
            hosting_info["type"] = "VPS"
        else:
            hosting_info["type"] = "Traditional"
        
        return hosting_info

    def _analyze_dns_setup(self):
        """Analyze DNS configuration"""
        dns_info = {
            "nameservers": [],
            "records": {},
            "security": {
                "spf": False,
                "dmarc": False,
                "dkim": False
            }
        }
        
        # Get DNS records
        dns_records = self.results.get("dns_info", {})
        
        # Check nameservers
        if "NS" in dns_records:
            dns_info["nameservers"] = dns_records["NS"]
        
        # Check security records
        if "TXT" in dns_records:
            txt_records = dns_records["TXT"]
            dns_info["security"]["spf"] = any("v=spf1" in record for record in txt_records)
            dns_info["security"]["dmarc"] = any("v=DMARC1" in record for record in txt_records)
        
        # Store all record types
        for record_type, records in dns_records.items():
            if records:  # Only store non-empty records
                dns_info["records"][record_type] = records
        
        return dns_info

    def _analyze_email_setup(self):
        """Analyze email configuration"""
        email_info = {
            "mx_records": [],
            "spf": False,
            "dmarc": False,
            "dkim": False,
            "autodiscover": False
        }
        
        # Get DNS records
        dns_records = self.results.get("dns_info", {})
        
        # Check MX records
        if "MX" in dns_records:
            email_info["mx_records"] = dns_records["MX"]
        
        # Check security records
        if "TXT" in dns_records:
            txt_records = dns_records["TXT"]
            email_info["spf"] = any("v=spf1" in record for record in txt_records)
            email_info["dmarc"] = any("v=DMARC1" in record for record in txt_records)
            email_info["dkim"] = any("v=DKIM1" in record for record in txt_records)
        
        # Check for autodiscover
        autodiscover_paths = [
            "/autodiscover/autodiscover.xml",
            "/autodiscover/autodiscover.json",
            "/.well-known/autoconfig/mail/config-v1.1.xml"
        ]
        
        for path in autodiscover_paths:
            try:
                response = requests.get(
                    f"{self.target_url}{path}",
                    headers={"User-Agent": USER_AGENT},
                    timeout=self.timeout,
                    verify=False
                )
                if response.status_code == 200:
                    email_info["autodiscover"] = True
                    break
            except:
                continue
        
        return email_info

    def _measure_response_times(self):
        """Measure response times for different endpoints"""
        response_times = {
            "main_page": None,
            "api_endpoints": [],
            "static_resources": []
        }
        
        # Measure main page response time
        try:
            start_time = time.time()
            response = requests.get(
                self.target_url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            end_time = time.time()
            response_times["main_page"] = {
                "time": round((end_time - start_time) * 1000, 2),  # Convert to milliseconds
                "status_code": response.status_code
            }
        except:
            pass
        
        # Measure API endpoint response times
        api_endpoints = self.results.get("api_endpoints", [])
        for endpoint in api_endpoints[:5]:  # Limit to first 5 endpoints
            try:
                start_time = time.time()
                response = requests.get(
                    endpoint["url"],
                    headers={"User-Agent": USER_AGENT},
                    timeout=self.timeout,
                    verify=False
                )
                end_time = time.time()
                response_times["api_endpoints"].append({
                    "url": endpoint["url"],
                    "time": round((end_time - start_time) * 1000, 2),
                    "status_code": response.status_code
                })
            except:
                continue
        
        return response_times

    def _analyze_resource_usage(self):
        """Analyze resource usage patterns"""
        resource_usage = {
            "content_types": {},
            "compression": False,
            "caching": False
        }
        
        headers = self.results.get("headers", {})
        
        # Analyze content types
        if "Content-Type" in headers:
            content_type = headers["Content-Type"]
            resource_usage["content_types"][content_type] = resource_usage["content_types"].get(content_type, 0) + 1
        
        # Check for compression
        resource_usage["compression"] = any(
            header.lower() in ["gzip", "deflate", "br"] 
            for header in headers.get("Content-Encoding", "").lower().split(",")
        )
        
        # Check for caching
        cache_headers = ["Cache-Control", "Expires", "ETag", "Last-Modified"]
        resource_usage["caching"] = any(header in headers for header in cache_headers)
        
        return resource_usage

    def _analyze_caching(self):
        """Analyze caching configuration"""
        caching_info = {
            "enabled": False,
            "headers": {},
            "directives": []
        }
        
        headers = self.results.get("headers", {})
        
        # Check for cache headers
        cache_headers = {
            "Cache-Control": headers.get("Cache-Control", ""),
            "Expires": headers.get("Expires", ""),
            "ETag": headers.get("ETag", ""),
            "Last-Modified": headers.get("Last-Modified", "")
        }
        
        caching_info["headers"] = {k: v for k, v in cache_headers.items() if v}
        
        # Check if caching is enabled
        if "Cache-Control" in headers:
            caching_info["enabled"] = True
            directives = headers["Cache-Control"].split(",")
            caching_info["directives"] = [d.strip() for d in directives]
        
        return caching_info

    def _write_csv_results(self, output_file):
        """Write results in CSV format"""
        import csv
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['Category', 'Item', 'Value', 'Details'])
            
            # DNS Information
            if "dns_info" in self.results:
                for record_type, values in self.results["dns_info"].items():
                    for value in values:
                        writer.writerow(['DNS', record_type, value, ''])
            
            # Open Ports
            if "open_ports" in self.results:
                for port in self.results["open_ports"]:
                    writer.writerow(['Ports', 'Open Port', port, ''])
            
            # Technologies
            if "technologies" in self.results:
                for tech, version in self.results["technologies"].items():
                    writer.writerow(['Technologies', tech, version if isinstance(version, str) else 'Detected', ''])
            
            # Vulnerabilities
            if "vulnerabilities" in self.results:
                for vuln in self.results["vulnerabilities"]:
                    writer.writerow([
                        'Vulnerabilities',
                        vuln.get('type', 'Unknown'),
                        vuln.get('url', 'N/A'),
                        vuln.get('details', '')
                    ])
            
            # WAF Detection
            if "waf" in self.results:
                for waf in self.results["waf"]:
                    writer.writerow(['WAF', 'Detected', waf, ''])
            
            # API Endpoints
            if "api_endpoints" in self.results:
                for api in self.results["api_endpoints"]:
                    writer.writerow([
                        'API',
                        api.get('url', 'N/A'),
                        api.get('status_code', 'N/A'),
                        f"Content-Type: {api.get('content_type', 'N/A')}"
                    ])
            
            # CORS Issues
            if "cors_issues" in self.results:
                for issue in self.results["cors_issues"]:
                    writer.writerow([
                        'CORS',
                        issue.get('severity', 'N/A'),
                        issue.get('origin', 'N/A'),
                        issue.get('description', '')
                    ])

    def _write_txt_results(self, output_file):
        """Write results in a formatted text file"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"Web Reconnaissance Report for {self.target_url}\n")
            f.write("=" * 80 + "\n\n")
            
            # Target Information
            f.write("Target Information\n")
            f.write("-" * 80 + "\n")
            f.write(f"URL: {self.target_url}\n")
            f.write(f"Domain: {self.domain}\n")
            f.write(f"Scan Date: {self.results.get('timestamp', 'N/A')}\n\n")
            
            # Security Score
            f.write("Security Assessment\n")
            f.write("-" * 80 + "\n")
            f.write(f"Security Score: {self.results.get('security_score', 0)}/100\n")
            f.write(f"Risk Level: {self.results.get('risk_level', 'Unknown')}\n\n")
            
            # DNS Information
            if "dns_info" in self.results and self.results["dns_info"]:
                f.write("DNS Information\n")
                f.write("-" * 80 + "\n")
                for record_type, values in self.results["dns_info"].items():
                    if values:
                        f.write(f"{record_type} Records:\n")
                        for value in values:
                            f.write(f"  - {value}\n")
                f.write("\n")
            
            # Open Ports
            if "open_ports" in self.results and self.results["open_ports"]:
                f.write("Open Ports\n")
                f.write("-" * 80 + "\n")
                for port in self.results["open_ports"]:
                    f.write(f"  - Port {port}\n")
                f.write("\n")
            
            # Technologies
            if "technologies" in self.results and self.results["technologies"]:
                f.write("Technologies Detected\n")
                f.write("-" * 80 + "\n")
                for tech, version in self.results["technologies"].items():
                    if isinstance(version, bool):
                        version_str = "Detected"
                    else:
                        version_str = f"Version: {version}"
                    f.write(f"  - {tech}: {version_str}\n")
                f.write("\n")
            
            # Vulnerabilities
            if "vulnerabilities" in self.results and self.results["vulnerabilities"]:
                f.write("Potential Vulnerabilities\n")
                f.write("-" * 80 + "\n")
                for vuln in self.results["vulnerabilities"]:
                    f.write(f"  - {vuln.get('type', 'Unknown')}: {vuln.get('url', 'N/A')}\n")
                    if vuln.get('details'):
                        f.write(f"    Details: {vuln['details']}\n")
            
            # WAF Detection
            if "waf" in self.results and self.results["waf"]:
                f.write("WAF Detection\n")
                f.write("-" * 80 + "\n")
                for waf in self.results["waf"]:
                    f.write(f"  - {waf}\n")
                f.write("\n")
            
            # API Endpoints
            if "api_endpoints" in self.results and self.results["api_endpoints"]:
                f.write("API Endpoints\n")
                f.write("-" * 80 + "\n")
                for api in self.results["api_endpoints"]:
                    f.write(f"  - {api.get('url', 'N/A')} ({api.get('status_code', 'N/A')})\n")
                f.write("\n")
            
            # CORS Issues
            if "cors_issues" in self.results and self.results["cors_issues"]:
                f.write("\n" + "=" * 80 + "\n")
                f.write("CORS MISCONFIGURATIONS\n")
                f.write("=" * 80 + "\n\n")
                
                for issue in self.results["cors_issues"]:
                    f.write(f"Severity: {issue.get('severity', 'N/A')}\n")
                    f.write(f"Origin: {issue.get('origin', 'N/A')}\n")
                    f.write(f"Description: {issue.get('description', '')}\n")
                    
                    details = issue.get('details', {})
                    if details:
                        f.write("Details:\n")
                        if isinstance(details, dict):
                            if 'risk' in details:
                                f.write(f"Risk: {details['risk']}\n")
                            if 'recommendation' in details:
                                f.write(f"Recommendation: {details['recommendation']}\n")
                    
                    f.write("\n" + "-" * 40 + "\n\n")
                
                # Add CORS score
                cors_score = self.results.get('cors_score', 0)
                f.write(f"CORS Security Score: {cors_score}/100\n")
                f.write(f"Risk Level: {self.results.get('cors_risk_level', 'Unknown')}\n\n")
            
            # Recommendations
            if "recommendations" in self.results and self.results["recommendations"]:
                f.write("Security Recommendations\n")
                f.write("-" * 80 + "\n")
                for rec in self.results["recommendations"]:
                    f.write(f"  - {rec}\n")
                f.write("\n")
            
            f.write("=" * 80 + "\n")
            f.write("End of Report\n")
            f.write("=" * 80 + "\n")

    def _fix_results(self):
        """Fix and validate results before saving"""
        try:
            # Ensure all required fields exist
            required_fields = {
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
                "security_score": 0,
                "risk_level": "Unknown",
                "recommendations": []
            }
            
            # Add missing required fields
            for field, default_value in required_fields.items():
                if field not in self.results:
                    self.results[field] = default_value
            
            # Fix DNS info
            if isinstance(self.results["dns_info"], dict):
                for record_type, values in self.results["dns_info"].items():
                    if not isinstance(values, list):
                        self.results["dns_info"][record_type] = []
            
            # Fix open ports
            if not isinstance(self.results["open_ports"], list):
                self.results["open_ports"] = []
            self.results["open_ports"] = [int(port) for port in self.results["open_ports"] if str(port).isdigit()]
            
            # Fix technologies
            if not isinstance(self.results["technologies"], dict):
                self.results["technologies"] = {}
            
            # Fix headers
            if not isinstance(self.results["headers"], dict):
                self.results["headers"] = {}
            
            # Fix methods
            if not isinstance(self.results["methods"], list):
                self.results["methods"] = []
            
            # Fix SSL info
            if not isinstance(self.results["ssl_info"], dict):
                self.results["ssl_info"] = {}
            
            # Fix directories
            if not isinstance(self.results["directories"], list):
                self.results["directories"] = []
            
            # Fix robots_sitemap
            if not isinstance(self.results["robots_sitemap"], dict):
                self.results["robots_sitemap"] = {}
            
            # Fix security score
            try:
                self.results["security_score"] = int(self.results["security_score"])
            except (ValueError, TypeError):
                self.results["security_score"] = 0
            
            # Fix risk level
            valid_risk_levels = ["Unknown", "Low", "Medium", "High", "Critical"]
            if self.results["risk_level"] not in valid_risk_levels:
                self.results["risk_level"] = "Unknown"
            
            # Fix recommendations
            if not isinstance(self.results["recommendations"], list):
                self.results["recommendations"] = []
            
            # Remove any None values
            def clean_dict(d):
                if isinstance(d, dict):
                    return {k: clean_dict(v) for k, v in d.items() if v is not None}
                elif isinstance(d, list):
                    return [clean_dict(x) for x in d if x is not None]
                return d
            
            self.results = clean_dict(self.results)
            
            # Ensure all string values are properly encoded
            def encode_strings(obj):
                if isinstance(obj, str):
                    return obj.encode('utf-8', 'ignore').decode('utf-8')
                elif isinstance(obj, dict):
                    return {k: encode_strings(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [encode_strings(x) for x in obj]
                return obj
            
            self.results = encode_strings(self.results)
            
            # Add metadata
            self.results["metadata"] = {
                "tool_version": VERSION,
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_duration": getattr(self, '_scan_duration', 0),
                "target_url": self.target_url,
                "domain": self.domain
            }
            
            return True
            
        except Exception as e:
            ColorOutput.error(f"Error fixing results: {str(e)}")
            if self.verbose:
                import traceback
                ColorOutput.error(traceback.format_exc())
            return False

    @lru_cache(maxsize=128)
    def _dns_query(self, domain, record_type):
        """Cached DNS query with rate limiting and error handling"""
        # Apply rate limiting
        self.dns_limiter.acquire()
        
        try:
            if self.verbose:
                ColorOutput.info(f"Querying {record_type} records for {domain}")
            
            answers = dns.resolver.resolve(domain, record_type)
            results = [str(rdata) for rdata in answers]
            
            if self.verbose:
                ColorOutput.info(f"Found {len(results)} {record_type} records")
            
            return tuple(results)  # Convert to tuple for caching
        except dns.resolver.NoAnswer:
            if self.verbose:
                ColorOutput.warning(f"No {record_type} records found for {domain}")
            return tuple()  # Return empty tuple for caching
        except dns.resolver.NXDOMAIN:
            ColorOutput.error(f"Domain {domain} does not exist")
            return tuple()  # Return empty tuple for caching
        except dns.resolver.Timeout:
            ColorOutput.error(f"DNS query timed out for {domain}")
            return tuple()  # Return empty tuple for caching
        except dns.resolver.NoNameservers:
            ColorOutput.error(f"No nameservers found for {domain}")
            return tuple()  # Return empty tuple for caching
        except Exception as e:
            ColorOutput.error(f"Error querying {record_type} records for {domain}: {str(e)}")
            if self.verbose:
                import traceback
                ColorOutput.error(traceback.format_exc())
            return tuple()  # Return empty tuple for caching

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
            # Add debug logging
            if self.verbose:
                ColorOutput.info(f"Making {method} request to {url}")
                if headers:
                    ColorOutput.info(f"Headers: {headers}")
            
            response = self.session.request(
                method,
                url,
                headers=headers,
                timeout=timeout,
                verify=verify,
                allow_redirects=allow_redirects
            )
            
            # Cache successful responses
            if response.status_code == 200:
                self._cache_response(url, method, headers, response)
            
            # Add debug logging for response
            if self.verbose:
                ColorOutput.info(f"Response status: {response.status_code}")
                ColorOutput.info(f"Response headers: {dict(response.headers)}")
            
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
        except Exception as e:
            ColorOutput.error(f"Unexpected error during request: {url} - {str(e)}")
            if self.verbose:
                import traceback
                ColorOutput.error(traceback.format_exc())
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
        """Analyze HTTP headers for security issues, information disclosure, and misconfiguration"""
        ColorOutput.section("HTTP Headers Analysis")
        
        response = self._make_request(self.target_url)
        if not response:
            return
        
        ColorOutput.info(f"HTTP Status: {response.status_code} ({response.reason})")
        
        # Enhanced cookie analysis
        if response.cookies:
            ColorOutput.section("Cookie Analysis")
            for cookie in response.cookies:
                issues = []
                recommendations = []
                
                # Build detailed cookie info
                cookie_info = [f"Cookie: {cookie.name}"]
                
                # Check for secure attributes
                if not cookie.secure:
                    issues.append("missing Secure flag")
                    recommendations.append("Add Secure flag to prevent cookie transmission over unencrypted connections")
                
                if not getattr(cookie, 'httponly', False):
                    issues.append("missing HttpOnly flag")
                    recommendations.append("Add HttpOnly flag to prevent JavaScript access to the cookie")
                
                # Check SameSite attribute
                samesite = None
                if hasattr(cookie, '_rest'):
                    for attr in cookie._rest:
                        if attr.lower() == 'samesite':
                            samesite = cookie._rest[attr]
                
                if not samesite:
                    issues.append("missing SameSite attribute")
                    recommendations.append("Add SameSite attribute (preferably 'Strict' or 'Lax') to prevent CSRF attacks")
                elif samesite.lower() not in ['strict', 'lax', 'none']:
                    issues.append(f"invalid SameSite value: {samesite}")
                    recommendations.append("Set SameSite to 'Strict' or 'Lax' for better security")
                elif samesite.lower() == 'none' and not cookie.secure:
                    issues.append("SameSite=None without Secure flag")
                    recommendations.append("When using SameSite=None, the Secure flag must be set")
                
                # Check expiration
                if cookie.expires:
                    from datetime import datetime
                    expiry_date = datetime.fromtimestamp(cookie.expires)
                    now = datetime.now()
                    days_until_expiry = (expiry_date - now).days
                    
                    if days_until_expiry > 365:
                        issues.append(f"long expiration time ({days_until_expiry} days)")
                        recommendations.append("Consider reducing cookie expiration time for better security")
                    elif days_until_expiry < 0:
                        issues.append("cookie has expired")
                        recommendations.append("Remove expired cookies")
                    
                    cookie_info.append(f"expires in {days_until_expiry} days")
                
                # Check for potential session cookies
                if cookie.name.lower() in ['sessionid', 'session', 'sid', 'jsessionid', 'phpsessid', 'aspsessionid']:
                    if cookie.expires:
                        issues.append("session cookie with explicit expiration")
                        recommendations.append("Session cookies should not have explicit expiration times")
                    if not cookie.secure:
                        recommendations.append("Session cookies should always use the Secure flag")
                    if not getattr(cookie, 'httponly', False):
                        recommendations.append("Session cookies should always use the HttpOnly flag")
                
                # Check path
                if cookie.path == "/" or not cookie.path:
                    cookie_info.append("path=/")
                    if cookie.name.lower() in ['sessionid', 'session', 'sid', 'jsessionid', 'phpsessid', 'aspsessionid']:
                        recommendations.append("Consider restricting session cookie path to specific application paths")
                
                # Check domain
                if cookie.domain:
                    if cookie.domain.startswith('.'):
                        cookie_info.append(f"domain={cookie.domain}")
                        issues.append("wildcard domain")
                        recommendations.append("Avoid using wildcard domains for cookies unless necessary")
                    else:
                        cookie_info.append(f"domain={cookie.domain}")
                
                # Check for sensitive cookie names
                sensitive_names = ['auth', 'token', 'key', 'secret', 'password', 'credential', 'session']
                if any(name in cookie.name.lower() for name in sensitive_names):
                    if not cookie.secure:
                        recommendations.append("Sensitive cookies should always use the Secure flag")
                    if not getattr(cookie, 'httponly', False):
                        recommendations.append("Sensitive cookies should always use the HttpOnly flag")
                    if not samesite or samesite.lower() != 'strict':
                        recommendations.append("Sensitive cookies should use SameSite=Strict")
                
                # Output results
                if issues:
                    ColorOutput.warning(f"{' | '.join(cookie_info)} - Issues: {', '.join(issues)}")
                    if recommendations:
                        ColorOutput.info("Recommendations:")
                        for rec in recommendations:
                            ColorOutput.info(f"  └─ {rec}")
                else:
                    ColorOutput.success(f"{' | '.join(cookie_info)} - Properly configured")
                
                # Store cookie analysis in results
                if "cookie_analysis" not in self.results:
                    self.results["cookie_analysis"] = []
                
                self.results["cookie_analysis"].append({
                    "name": cookie.name,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "httponly": getattr(cookie, 'httponly', False),
                    "samesite": samesite,
                    "expires": str(expiry_date) if cookie.expires else None,
                    "issues": issues,
                    "recommendations": recommendations
                })
        
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
                    
                    # Initialize SSL info dictionary
                    ssl_info = {
                        "version": version,
                        "cipher": {
                            "name": cipher[0],
                            "version": cipher[1],
                            "bits": cipher[2]
                        },
                        "issuer": issuer.get('organizationName', 'Unknown'),
                        "subject": subject.get('commonName', 'Unknown'),
                        "valid_from": str(not_before),
                        "valid_until": str(not_after),
                        "days_remaining": days_left,
                        "issues": [],
                        "recommendations": []
                    }
                    
                    # Display basic SSL/TLS information
                    ColorOutput.section("Certificate Information")
                    ColorOutput.key_value("SSL/TLS Version", version)
                    ColorOutput.key_value("Cipher Suite", f"{cipher[0]} ({cipher[2]} bits)")
                    ColorOutput.key_value("Issuer", issuer.get('organizationName', 'Unknown'))
                    ColorOutput.key_value("Subject", subject.get('commonName', 'Unknown'))
                    ColorOutput.key_value("Valid From", str(not_before))
                    ColorOutput.key_value("Valid Until", str(not_after))
                    
                    # Certificate expiration check
                    if days_left < 0:
                        ColorOutput.error(f"Certificate EXPIRED ({abs(days_left)} days ago)")
                        ssl_info["issues"].append({
                            "severity": "Critical",
                            "description": f"Certificate expired {abs(days_left)} days ago",
                            "recommendation": "Renew the SSL certificate immediately"
                        })
                    elif days_left < 30:
                        ColorOutput.warning(f"Certificate expires soon ({days_left} days remaining)")
                        ssl_info["issues"].append({
                            "severity": "High",
                            "description": f"Certificate expires in {days_left} days",
                            "recommendation": "Plan certificate renewal"
                        })
                    else:
                        ColorOutput.success(f"Certificate valid ({days_left} days remaining)")
                    
                    # Protocol security checks
                    ColorOutput.section("Protocol Security")
                    weak_protocols = {
                        "TLSv1": "TLS 1.0 is considered insecure",
                        "TLSv1.1": "TLS 1.1 is considered insecure",
                        "SSLv3": "SSL 3.0 is considered insecure",
                        "SSLv2": "SSL 2.0 is considered insecure"
                    }
                    
                    for proto, reason in weak_protocols.items():
                        if proto in version:
                            ColorOutput.warning(f"Weak protocol detected: {version}")
                            ssl_info["issues"].append({
                                "severity": "High",
                                "description": f"Using {proto} - {reason}",
                                "recommendation": "Upgrade to TLS 1.2 or higher"
                            })
                    
                    # Cipher security checks
                    ColorOutput.section("Cipher Security")
                    weak_ciphers = {
                        "RC4": "RC4 is considered insecure",
                        "DES": "DES is considered insecure",
                        "3DES": "3DES is considered weak",
                        "NULL": "NULL cipher provides no encryption",
                        "EXPORT": "Export-grade ciphers are weak"
                    }
                    
                    for weak_cipher, reason in weak_ciphers.items():
                        if weak_cipher in cipher[0]:
                            ColorOutput.warning(f"Weak cipher detected: {cipher[0]}")
                            ssl_info["issues"].append({
                                "severity": "High",
                                "description": f"Using {weak_cipher} - {reason}",
                                "recommendation": "Use strong ciphers (AES-GCM, ChaCha20)"
                            })
                    
                    # Check key strength
                    if cipher[2] < 128:
                        ColorOutput.warning(f"Weak key length: {cipher[2]} bits")
                        ssl_info["issues"].append({
                            "severity": "High",
                            "description": f"Using weak key length ({cipher[2]} bits)",
                            "recommendation": "Use at least 128-bit keys"
                        })
                    
                    # Domain validation checks
                    ColorOutput.section("Domain Validation")
                    alt_names = []
                    if 'subjectAltName' in cert:
                        for type_name, value in cert['subjectAltName']:
                            if type_name == 'DNS':
                                alt_names.append(value)
                    
                    ssl_info["subject_alt_names"] = alt_names
                    
                    if hostname not in subject.get('commonName', '') and not any(hostname == name for name in alt_names):
                        ColorOutput.warning(f"Hostname mismatch: {hostname} not found in certificate")
                        ssl_info["issues"].append({
                            "severity": "High",
                            "description": f"Hostname {hostname} not found in certificate",
                            "recommendation": "Add hostname to certificate's Subject Alternative Names"
                        })
                    
                    # Generate recommendations
                    if not ssl_info["issues"]:
                        ssl_info["recommendations"].append({
                            "priority": "Low",
                            "description": "SSL/TLS configuration is secure",
                            "action": "Maintain current security practices"
                        })
                    else:
                        for issue in ssl_info["issues"]:
                            ssl_info["recommendations"].append({
                                "priority": issue["severity"],
                                "description": issue["description"],
                                "action": issue["recommendation"]
                            })
                    
                    # Calculate SSL score
                    ssl_score = 100
                    for issue in ssl_info["issues"]:
                        if issue["severity"] == "Critical":
                            ssl_score -= 40
                        elif issue["severity"] == "High":
                            ssl_score -= 20
                        elif issue["severity"] == "Medium":
                            ssl_score -= 10
                        elif issue["severity"] == "Low":
                            ssl_score -= 5
                    
                    ssl_score = max(0, ssl_score)
                    ssl_info["score"] = ssl_score
                    
                    # Display SSL score
                    ColorOutput.section("SSL/TLS Security Score")
                    score_bar = '█' * (ssl_score // 10) + '░' * (10 - (ssl_score // 10))
                    print(f"{ColorOutput.BOLD}Score: {ColorOutput.ENDC}[{score_bar}] {ssl_score}%")
                    
                    # Display issues if any
                    if ssl_info["issues"]:
                        ColorOutput.section("Security Issues")
                        headers = ["Severity", "Description", "Recommendation"]
                        rows = []
                        for issue in ssl_info["issues"]:
                            severity_color = {
                                "Critical": ColorOutput.RED,
                                "High": ColorOutput.RED,
                                "Medium": ColorOutput.YELLOW,
                                "Low": ColorOutput.BLUE
                            }.get(issue["severity"], ColorOutput.ENDC)
                            
                            rows.append([
                                f"{severity_color}{issue['severity']}{ColorOutput.ENDC}",
                                issue["description"],
                                issue["recommendation"]
                            ])
                        ColorOutput.table(headers, rows)
                    
                    # Store results
                    self.results["ssl_info"] = ssl_info
                    
        except ssl.SSLError as e:
            ColorOutput.error(f"SSL Error: {str(e)}")
            self.results["ssl_info"] = {
                "error": str(e),
                "issues": [{
                    "severity": "Critical",
                    "description": f"SSL Error: {str(e)}",
                    "recommendation": "Check SSL/TLS configuration"
                }],
                "score": 0
            }
        except socket.error as e:
            ColorOutput.error(f"Socket Error: {str(e)}")
            self.results["ssl_info"] = {
                "error": str(e),
                "issues": [{
                    "severity": "Critical",
                    "description": f"Connection Error: {str(e)}",
                    "recommendation": "Check network connectivity and server availability"
                }],
                "score": 0
            }
        except Exception as e:
            ColorOutput.error(f"Error analyzing SSL/TLS: {str(e)}")
            self.results["ssl_info"] = {
                "error": str(e),
                "issues": [{
                    "severity": "Critical",
                    "description": f"Analysis Error: {str(e)}",
                    "recommendation": "Check server configuration and try again"
                }],
                "score": 0
            }
    
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
        """Check if a directory exists with improved error handling"""
        try:
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
        except Exception as e:
            if self.verbose:
                ColorOutput.error(f"Error checking directory {directory}: {str(e)}")
                import traceback
                ColorOutput.error(traceback.format_exc())
            return None

    def _advanced_fingerprinting(self):
        """Advanced web technology fingerprinting"""
        ColorOutput.section("Advanced Technology Fingerprinting")
        
        try:
            response = self._make_request(
                self.target_url,
                headers={"User-Agent": USER_AGENT},
                verify=False
            )
            
            if not response:
                return

            # Comprehensive technology signatures
            tech_signatures = {
                "PHP": ["X-Powered-By: PHP", "Set-Cookie: PHPSESSID"],
                "ASP.NET": ["X-AspNet-Version", "ASP.NET", "X-AspNetMvc-Version", "Set-Cookie: ASP.NET_SessionId"],
                "Apache": ["Server: Apache"],
                "nginx": ["Server: nginx"],
                "Express.js": ["X-Powered-By: Express"],
                "Django": ["X-Frame-Options: SAMEORIGIN", "Vary: Cookie", "Set-Cookie: sessionid"],
                "Ruby on Rails": ["X-Runtime", "X-Powered-By: Rails", "Set-Cookie: _rails_session"],
                "Laravel": ["Set-Cookie: laravel_session", "X-Powered-By: PHP"],
                "WordPress": ["wp-content", "wp-includes", "WordPress", "Set-Cookie: wordpress_"],
                "Drupal": ["X-Generator: Drupal", "X-Drupal-", "Set-Cookie: SESS"],
                "Joomla": ["Set-Cookie: joomla", "X-Content-Encoded-By: Joomla"],
                "Tomcat": ["Server: Apache-Coyote", "Set-Cookie: JSESSIONID"],
                "IIS": ["Server: Microsoft-IIS", "X-Powered-By: ASP.NET"],
                "GlassFish": ["Server: GlassFish"],
                "WebLogic": ["Server: WebLogic"],
                "Node.js": ["X-Powered-By: Node.js", "X-Powered-By: Express"],
                "Flask": ["Set-Cookie: session", "Server: Werkzeug"],
                "Magento": ["Set-Cookie: frontend", "X-Magento-Cache-Debug"],
                "Shopify": ["X-ShopId", "X-Shopify-Stage"],
                "Google Frontend": ["Server: GSE", "X-Goog-Backend-Server"],
                "Cloudflare": ["Server: cloudflare", "CF-RAY"],
                "Varnish": ["Server: Varnish", "X-Varnish"],
                "Squid": ["Server: squid"],
                "HAProxy": ["Server: haproxy"],
                "LiteSpeed": ["Server: LiteSpeed"],
                "OpenResty": ["Server: openresty"],
                "Elasticsearch": ["X-Elastic-Product", "Server: Elasticsearch"],
                "Kubernetes": ["Server: kube-proxy"],
                "Traefik": ["Server: traefik"],
                "Caddy": ["Server: Caddy"],
                "Next.js": ["X-Powered-By: Next.js"],
                "React": ["X-Powered-By: React"],
                "Angular": ["X-Powered-By: Angular"],
                "Vue.js": ["X-Powered-By: Vue"],
            }

            # Additional JavaScript framework patterns
            js_frameworks = {
                "jQuery": r'jquery[.-](\d+\.\d+\.\d+)',
                "React": r'react[.-](\d+\.\d+\.\d+)',
                "Angular": r'angular[.-](\d+\.\d+\.\d+)',
                "Vue.js": r'vue[.-](\d+\.\d+\.\d+)',
                "Bootstrap": r'bootstrap[.-](\d+\.\d+\.\d+)',
                "Lodash": r'lodash[.-](\d+\.\d+\.\d+)',
                "Moment.js": r'moment[.-](\d+\.\d+\.\d+)',
                "Underscore.js": r'underscore[.-](\d+\.\d+\.\d+)',
                "Ember.js": r'ember[.-](\d+\.\d+\.\d+)',
                "Backbone.js": r'backbone[.-](\d+\.\d+\.\d+)',
                "Knockout.js": r'knockout[.-](\d+\.\d+\.\d+)',
                "Dojo": r'dojo[.-](\d+\.\d+\.\d+)',
                "ExtJS": r'ext[.-](\d+\.\d+\.\d+)',
                "Prototype": r'prototype[.-](\d+\.\d+\.\d+)',
                "MooTools": r'mootools[.-](\d+\.\d+\.\d+)',
            }

            # Additional CMS patterns
            cms_patterns = {
                "WordPress": [r'wp-content', r'wp-includes', r'wordpress'],
                "Drupal": [r'drupal\.js', r'drupal\.css', r'Drupal\.settings'],
                "Joomla": [r'joomla', r'com_content', r'com_contact'],
                "Magento": [r'magento', r'Mage\.', r'skin/frontend'],
                "Laravel": [r'laravel', r'csrf-token'],
                "Django": [r'csrfmiddlewaretoken', r'django'],
                "Shopify": [r'shopify', r'shopify\.com'],
                "WooCommerce": [r'woocommerce', r'wc-api'],
                "PrestaShop": [r'prestashop', r'presta-'],
                "OpenCart": [r'opencart', r'route=common'],
                "TYPO3": [r'typo3', r'typo3conf'],
                "Concrete5": [r'concrete5', r'concrete'],
                "Craft CMS": [r'craft', r'craftcms'],
                "ExpressionEngine": [r'expressionengine', r'ee\.'],
                "MODX": [r'modx', r'assets/snippets'],
            }

            detected_techs = {}
            response_text = response.text.lower()
            headers_str = str(response.headers).lower()
            cookies_str = str(response.cookies).lower()

            # Check technology signatures
            for tech, signatures in tech_signatures.items():
                for signature in signatures:
                    sig_lower = signature.lower()
                    if sig_lower in headers_str or sig_lower in cookies_str:
                        if tech not in detected_techs:
                            detected_techs[tech] = True
                            ColorOutput.success(f"Detected {tech}")
                            break

            # Check JavaScript frameworks
            for framework, pattern in js_frameworks.items():
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                if matches:
                    version = matches[0]
                    detected_techs[framework] = version
                    ColorOutput.success(f"Detected {framework} version {version}")

            # Check CMS patterns
            for cms, patterns in cms_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        if cms not in detected_techs:
                            detected_techs[cms] = True
                            ColorOutput.success(f"Detected {cms}")
                            break

            # Check for security headers and their versions
            security_headers = {
                "Content-Security-Policy": "CSP",
                "X-Frame-Options": "Frame Protection",
                "X-Content-Type-Options": "MIME Protection",
                "X-XSS-Protection": "XSS Protection",
                "Strict-Transport-Security": "HSTS",
                "Referrer-Policy": "Referrer Policy",
                "Permissions-Policy": "Permissions Policy",
                "Cross-Origin-Embedder-Policy": "COEP",
                "Cross-Origin-Opener-Policy": "COOP",
                "Cross-Origin-Resource-Policy": "CORP"
            }

            for header, description in security_headers.items():
                if header in response.headers:
                    value = response.headers[header]
                    detected_techs[f"{description} ({header})"] = value
                    ColorOutput.info(f"Security Header: {header} = {value}")

            # Check for CDN presence
            cdn_headers = {
                "CF-RAY": "Cloudflare",
                "X-CDN-Pop": "CDN",
                "X-Cache": "CDN",
                "X-CDN": "CDN",
                "X-Edge-Location": "CDN",
                "X-Fastly": "Fastly",
                "X-Akamai-Transformed": "Akamai",
                "X-Edge-IP": "CDN",
                "X-CDN-Geo": "CDN",
                "X-CDN-Request-ID": "CDN"
            }

            for header, cdn in cdn_headers.items():
                if header in response.headers:
                    detected_techs[cdn] = True
                    ColorOutput.info(f"Detected {cdn} CDN")

            # Store results
            self.results["technologies"] = detected_techs

            if not detected_techs:
                ColorOutput.warning("No technologies detected")
            else:
                ColorOutput.success(f"Detected {len(detected_techs)} technologies")

        except requests.exceptions.RequestException as e:
            ColorOutput.error(f"Error in advanced fingerprinting: {str(e)}")
            if self.verbose:
                import traceback
                ColorOutput.error(traceback.format_exc())

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
        """Check if a path returns API-like content with improved error handling"""
        try:
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
        except Exception as e:
            if self.verbose:
                ColorOutput.error(f"Error checking API path {url}: {str(e)}")
                import traceback
                ColorOutput.error(traceback.format_exc())
            return None

    def _is_valid_json(self, text):
        """Check if text is valid JSON with error handling"""
        try:
            if not text.strip():
                return False
            json.loads(text)
            return True
        except json.JSONDecodeError:
            return False
        except Exception as e:
            if self.verbose:
                ColorOutput.error(f"Error validating JSON: {str(e)}")
            return False

    def _check_cors_misconfig(self):
        """Check for CORS misconfigurations"""
        if self.verbose:
            ColorOutput.info("Running CORS Misconfiguration Check...")
        
        cors_issues = []
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "https://malicious.com",
            "null",
            "https://trusted.com",
            "http://localhost",
            "http://127.0.0.1"
        ]
        
        # Test different HTTP methods
        methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        
        for origin in test_origins:
            headers = {
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Content-Type"
            }
            
            try:
                # First check OPTIONS request
                response = self._make_request(
                    self.target_url,
                    method="OPTIONS",
                    headers=headers,
                    timeout=self.timeout
                )
                
                if response:
                    acao = response.headers.get("Access-Control-Allow-Origin", "")
                    acac = response.headers.get("Access-Control-Allow-Credentials", "")
                    acam = response.headers.get("Access-Control-Allow-Methods", "")
                    acah = response.headers.get("Access-Control-Allow-Headers", "")
                    acma = response.headers.get("Access-Control-Max-Age", "")
                    
                    # Check for wildcard origin
                    if acao == "*":
                        cors_issues.append({
                            "severity": "High",
                            "origin": origin,
                            "description": "Wildcard CORS policy detected",
                            "details": {
                                "header": "Access-Control-Allow-Origin: *",
                                "risk": "Allows any domain to make cross-origin requests",
                                "recommendation": "Restrict to specific trusted domains"
                            }
                        })
                    
                    # Check for credentials with wildcard
                    if acao == "*" and acac.lower() == "true":
                        cors_issues.append({
                            "severity": "Critical",
                            "origin": origin,
                            "description": "Wildcard CORS with credentials enabled",
                            "details": {
                                "headers": {
                                    "Access-Control-Allow-Origin": "*",
                                    "Access-Control-Allow-Credentials": "true"
                                },
                                "risk": "Allows any domain to make authenticated cross-origin requests",
                                "recommendation": "Never use wildcard with credentials"
                            }
                        })
                    
                    # Check for reflected origin
                    if acao == origin:
                        cors_issues.append({
                            "severity": "Medium",
                            "origin": origin,
                            "description": "Origin reflection detected",
                            "details": {
                                "header": f"Access-Control-Allow-Origin: {origin}",
                                "risk": "Origin reflection can be exploited if origin validation is weak",
                                "recommendation": "Implement strict origin validation"
                            }
                        })
                    
                    # Check for missing security headers
                    if not acam or not acah:
                        cors_issues.append({
                            "severity": "Low",
                            "origin": origin,
                            "description": "Incomplete CORS headers",
                            "details": {
                                "missing_headers": {
                                    "Access-Control-Allow-Methods": acam,
                                    "Access-Control-Allow-Headers": acah
                                },
                                "risk": "May lead to unexpected CORS behavior",
                                "recommendation": "Specify all required CORS headers"
                            }
                        })
                    
                    # Check for overly permissive methods
                    if acam and "*" in acam:
                        cors_issues.append({
                            "severity": "Medium",
                            "origin": origin,
                            "description": "Overly permissive CORS methods",
                            "details": {
                                "header": f"Access-Control-Allow-Methods: {acam}",
                                "risk": "Allows all HTTP methods",
                                "recommendation": "Restrict to specific required methods"
                            }
                        })
                    
                    # Test actual requests with different methods
                    for method in methods:
                        try:
                            method_response = self._make_request(
                                self.target_url,
                                method=method,
                                headers={"Origin": origin},
                                timeout=self.timeout
                            )
                            
                            if method_response:
                                method_acao = method_response.headers.get("Access-Control-Allow-Origin", "")
                                
                                # Check for method-specific issues
                                if method_acao == "*" and method != "GET":
                                    cors_issues.append({
                                        "severity": "High",
                                        "origin": origin,
                                        "description": f"Wildcard CORS for {method} method",
                                        "details": {
                                            "method": method,
                                            "header": "Access-Control-Allow-Origin: *",
                                            "risk": f"Allows any domain to make {method} requests",
                                            "recommendation": f"Restrict {method} method to specific domains"
                                        }
                                    })
                        except Exception as e:
                            if self.verbose:
                                ColorOutput.warning(f"Error testing {method} method: {str(e)}")
            
            except Exception as e:
                if self.verbose:
                    ColorOutput.warning(f"Error checking CORS for origin {origin}: {str(e)}")
        
        # Add CORS issues to results
        self.results["cors_issues"] = cors_issues
        
        # Calculate CORS score
        self._calculate_cors_score()
        
        if self.verbose:
            if cors_issues:
                ColorOutput.warning(f"Found {len(cors_issues)} CORS misconfigurations")
            else:
                ColorOutput.success("No CORS misconfigurations detected")

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
                    <th>Severity</th>
                    <th>Origin</th>
                    <th>Description</th>
                    <th>Details</th>
                </tr>
""")
                    for issue in cors_issues:
                        severity = issue.get('severity', 'N/A')
                        origin = issue.get('origin', 'N/A')
                        description = issue.get('description', '')
                        details = issue.get('details', {})
                        details_str = ""
                        if isinstance(details, dict):
                            if 'risk' in details:
                                details_str += f"Risk: {details['risk']}\n"
                            if 'recommendation' in details:
                                details_str += f"Recommendation: {details['recommendation']}"
                        
                        severity_color = {
                            "Critical": ColorOutput.RED,
                            "High": ColorOutput.RED,
                            "Medium": ColorOutput.YELLOW,
                            "Low": ColorOutput.BLUE
                        }.get(severity, ColorOutput.ENDC)
                        
                        f.write(f"""
                <tr class="{severity_color}">
                    <td>{severity}</td>
                    <td>{origin}</td>
                    <td>{description}</td>
                    <td>{details_str}</td>
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
        try:
            # Close the session if it exists
            if hasattr(self, 'session'):
                self.session.close()
            
            # Clear the cache dictionary
            if hasattr(self, 'cache'):
                self.cache.clear()
            
            # Clear DNS resolver cache
            if hasattr(self, '_dns_query'):
                try:
                    # Clear the DNS resolver cache
                    dns.resolver.reset_default_resolver()
                    # Clear the LRU cache
                    self._dns_query.cache_clear()
                except Exception:
                    pass
        except Exception:
            pass  # Ignore any cleanup errors during object destruction

    def _get_service_name(self, port):
        """Get common service name for a port"""
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            27017: "MongoDB"
        }
        return common_ports.get(port, "Unknown")


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
   Made by viphacker100 'Aryan Ahirwar'
   
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
