# PyVulnHunter PRO v4.0

## Advanced Security Scanner for Professional Bug Hunters & Penetration Testers

![Version](https://img.shields.io/badge/version-4.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)

---

## 📋 Deskripsi

PyVulnHunter PRO adalah scanner keamanan aplikasi web berperforma tinggi yang dirancang khusus untuk bug hunter dan penetration tester profesional. Tools ini menggunakan teknologi asynchronous scanning yang mampu mendeteksi berbagai jenis kerentanan web security dengan tingkat akurasi tinggi dan false positive yang minimal.

Scanner ini dikembangkan dengan arsitektur modular yang memungkinkan penambahan payload dan teknik deteksi baru, serta menggunakan multiple threading untuk efisiensi maksimal dalam proses scanning.

## 🎯 Fungsi & Kegunaan

### **Fungsi Utama:**
- **Vulnerability Assessment**: Mengidentifikasi kerentanan keamanan pada aplikasi web
- **Penetration Testing**: Membantu proses penetration testing dengan automated scanning
- **Bug Bounty Hunting**: Accelerate bug discovery untuk program bug bounty
- **Security Audit**: Melakukan audit keamanan terhadap aplikasi web
- **Compliance Testing**: Memverifikasi compliance terhadap standar keamanan web

### **Manfaat:**
- **Efisiensi Waktu**: Mengurangi waktu manual testing hingga 80%
- **Akurasi Tinggi**: Menggunakan multiple detection techniques untuk minimalisir false positive
- **Comprehensive Coverage**: Mendeteksi berbagai jenis kerentanan dalam satu tool
- **Professional Output**: Menghasilkan report yang sesuai dengan standar industri
- **Scalability**: Dapat digunakan untuk testing skala kecil hingga enterprise

## ⚡ Fitur Unggulan

### **1. Asynchronous Scanning Engine**
- Menggunakan `asyncio` dan `aiohttp` untuk concurrent request processing
- Capable of handling 100-500 concurrent requests
- Intelligent rate limiting untuk menghindari target overload

### **2. Advanced Payload Database**
- **1000+ Premium Payloads** untuk berbagai jenis vulnerability
- Kategori payload yang terorganisir (basic, advanced, WAF bypass)
- Automatic payload encoding dan obfuscation

### **3. Intelligent Detection System**
- **Multi-layer detection algorithm** untuk mengurangi false positive
- Pattern matching dengan regular expressions
- Response analysis berdasarkan status code, response time, dan content

### **4. WAF Bypass Capabilities**
- Automatic WAF detection dan bypass techniques
- Multiple encoding methods (URL, HTML, Unicode, etc.)
- Header manipulation untuk evading security controls

### **5. Professional Reporting**
- JSON output format untuk integration dengan tools lain
- Detailed vulnerability information dengan CVSS scoring
- Timestamp dan metadata untuk audit trail

## 🔧 Fitur yang Tersedia

### **Vulnerability Detection Modules:**

#### **1. Cross-Site Scripting (XSS)**
- Reflected XSS detection
- Stored XSS detection
- DOM-based XSS detection
- Blind XSS detection
- Context-aware payload injection

#### **2. SQL Injection**
- Boolean-based blind SQL injection
- Time-based blind SQL injection
- Union-based SQL injection
- Error-based SQL injection
- Second-order SQL injection

#### **3. Remote Code Execution (RCE)**
- Command injection detection
- Code injection detection
- Server-side template injection
- Deserialization attacks
- Log4j vulnerability detection

#### **4. Local File Inclusion (LFI)**
- Path traversal detection
- PHP wrapper exploitation
- File inclusion via various protocols
- Log poisoning detection

#### **5. Additional Vulnerabilities**
- Authentication bypass
- JWT token manipulation
- XXE (XML External Entity) injection
- SSRF (Server-Side Request Forgery)
- Directory traversal
- File upload vulnerabilities
- NoSQL injection
- LDAP injection
- XPath injection

### **Scanning Features:**
- **Multi-threading**: Concurrent request processing
- **Rate limiting**: Configurable request throttling
- **Retry mechanism**: Automatic retry for failed requests
- **User-agent rotation**: Randomized user-agent strings
- **Header manipulation**: Custom headers for evasion
- **Proxy support**: HTTP/HTTPS proxy integration
- **Cookie handling**: Automatic session management

## 🔄 Cara Kerja Tools

### **1. Initialization Phase**
- Load configuration parameters
- Initialize payload database
- Setup HTTP client dengan connection pooling
- Configure threading dan rate limiting

### **2. Target Analysis Phase**
- Parse target URL dan extract parameters
- Identify potential injection points
- Analyze response patterns untuk baseline establishment

### **3. Payload Injection Phase**
- Inject payloads secara concurrent ke setiap parameter
- Monitor response patterns untuk anomaly detection
- Analyze response time, status code, dan content

### **4. Vulnerability Detection Phase**
- Pattern matching terhadap known vulnerability signatures
- Statistical analysis untuk blind vulnerability detection
- False positive filtering menggunakan multiple verification

### **5. Reporting Phase**
- Aggregate hasil scanning
- Generate detailed vulnerability report
- Export hasil dalam format JSON

## 🛠️ Bahan dan Alat yang Diperlukan

### **Sistem Requirements:**
- **Operating System**: Windows 10/11, Linux (Ubuntu/Debian/CentOS), macOS 10.14+
- **Python Version**: Python 3.7 atau yang lebih baru
- **Memory**: Minimum 2GB RAM (Recommended 4GB+)
- **Storage**: Minimum 500MB free disk space
- **Network**: Stable internet connection

### **Dependencies yang Dibutuhkan:**
```bash
asyncio>=3.4.3
aiohttp>=3.8.0
beautifulsoup4>=4.11.0
colorama>=0.4.6
requests>=2.28.0
```

### **Tools Pendukung (Opsional):**
- **Burp Suite**: Untuk manual verification
- **OWASP ZAP**: Untuk cross-validation
- **Wireshark**: Untuk network traffic analysis
- **Nmap**: Untuk port scanning
- **Subfinder**: Untuk subdomain enumeration

## 📦 Cara Penggunaan

### **1. Instalasi di Termux (Android)**

```bash
# Update package list
pkg update && pkg upgrade

# Install Python dan dependencies
pkg install python git

# Clone repository
git clone https://github.com/HolyBytes/pyvulnhunter_pro.git

# Navigate to directory
cd pyvulnhunter_pro

# Install Python dependencies
pip install -r requirements.txt

# Grant execution permission
chmod +x pyvulnhunter_pro.py

# Run the tool
python pyvulnhunter_pro.py -u https://example.com -t 50 -l 3
```

### **2. Instalasi di Windows Command Prompt**

```cmd
REM Install Python from https://python.org (if not installed)
REM Open Command Prompt as Administrator

REM Install Git (if not installed)
REM Download from https://git-scm.com/download/win

REM Clone repository
git clone https://github.com/HolyBytes/pyvulnhunter_pro.git

REM Navigate to directory
cd pyvulnhunter_pro

REM Install dependencies
pip install -r requirements.txt

REM Run the tool
python pyvulnhunter_pro.py -u https://example.com -t 100 -l 3
```

### **3. Instalasi di Windows PowerShell**

```powershell
# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Install Python dari Microsoft Store atau python.org

# Clone repository
git clone https://github.com/HolyBytes/pyvulnhunter_pro.git

# Navigate to directory
Set-Location pyvulnhunter_pro

# Install dependencies
pip install -r requirements.txt

# Run the tool
python pyvulnhunter_pro.py -u https://example.com -t 100 -l 3
```

### **4. Instalasi di Linux Terminal (Ubuntu/Debian)**

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python dan dependencies
sudo apt install python3 python3-pip git -y

# Clone repository
git clone https://github.com/HolyBytes/pyvulnhunter_pro.git

# Navigate to directory
cd pyvulnhunter_pro

# Install Python dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x pyvulnhunter_pro.py

# Run the tool
python3 pyvulnhunter_pro.py -u https://example.com -t 100 -l 3
```

### **5. Instalasi di macOS Terminal**

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python dan Git
brew install python3 git

# Clone repository
git clone https://github.com/HolyBytes/pyvulnhunter_pro.git

# Navigate to directory
cd pyvulnhunter_pro

# Install dependencies
pip3 install -r requirements.txt

# Run the tool
python3 pyvulnhunter_pro.py -u https://example.com -t 100 -l 3
```

### **Parameter Command Line:**

```bash
python pyvulnhunter_pro.py [OPTIONS]

Required Arguments:
  -u, --url URL         Target URL to scan

Optional Arguments:
  -t, --threads N       Number of concurrent threads (default: 100)
  -l, --level N         Scan intensity level 1-5 (default: 3)
  -o, --output FILE     Output file for JSON report
  -h, --help           Show help message
```

### **Contoh Penggunaan:**

```bash
# Basic scan
python pyvulnhunter_pro.py -u https://example.com

# Advanced scan dengan 200 threads
python pyvulnhunter_pro.py -u https://example.com -t 200 -l 5

# Scan dengan output ke file
python pyvulnhunter_pro.py -u https://example.com -o report.json

# Scan dengan level tinggi
python pyvulnhunter_pro.py -u https://example.com -l 5 -t 150
```

## 🚨 Mengatasi Error Instalasi

### **Error: ModuleNotFoundError**
```bash
# Solusi 1: Install dependencies manually
pip install asyncio aiohttp beautifulsoup4 colorama

# Solusi 2: Upgrade pip
python -m pip install --upgrade pip

# Solusi 3: Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

### **Error: Permission Denied (Linux/Mac)**
```bash
# Give execute permission
chmod +x pyvulnhunter_pro.py

# Or run with sudo
sudo python3 pyvulnhunter_pro.py -u https://example.com
```

### **Error: SSL Certificate Verification**
```bash
# Install certificates
pip install --upgrade certifi

# For macOS
/Applications/Python\ 3.x/Install\ Certificates.command
```

### **Error: Too Many Open Files**
```bash
# Increase file descriptor limit (Linux/Mac)
ulimit -n 4096

# Or reduce thread count
python pyvulnhunter_pro.py -u https://example.com -t 50
```

## 🔍 Kerentanan yang Dapat Dideteksi

### **1. Injection Attacks**
- **SQL Injection**: All types including blind, boolean, time-based
- **NoSQL Injection**: MongoDB, CouchDB, Redis injection
- **LDAP Injection**: Directory traversal via LDAP
- **XPath Injection**: XML database injection
- **Command Injection**: OS command execution
- **Code Injection**: Server-side code execution

### **2. Cross-Site Scripting (XSS)**
- **Reflected XSS**: Input reflection dalam response
- **Stored XSS**: Persistent XSS dalam database
- **DOM-based XSS**: Client-side script manipulation
- **Blind XSS**: Out-of-band XSS detection

### **3. File-based Vulnerabilities**
- **Local File Inclusion (LFI)**: Unauthorized file access
- **Remote File Inclusion (RFI)**: Remote file execution
- **Directory Traversal**: Path traversal attacks
- **File Upload**: Malicious file upload vulnerabilities

### **4. Authentication & Authorization**
- **Authentication Bypass**: Login mechanism bypass
- **Session Management**: Session fixation, hijacking
- **JWT Vulnerabilities**: Token manipulation attacks
- **Privilege Escalation**: Unauthorized access elevation

### **5. Server-Side Vulnerabilities**
- **Server-Side Request Forgery (SSRF)**: Internal network access
- **XML External Entity (XXE)**: XML parser exploitation
- **Server-Side Template Injection**: Template engine abuse
- **Deserialization**: Unsafe object deserialization

## ⚠️ Peringatan Penting

### **Legal Disclaimer:**
- **HANYA** gunakan tools ini pada target yang Anda miliki atau memiliki izin eksplisit untuk testing
- **TIDAK** melakukan scanning terhadap target tanpa persetujuan tertulis
- **PATUH** terhadap semua hukum dan regulasi yang berlaku di wilayah Anda
- **TIDAK** bertanggung jawab atas penyalahgunaan tools ini

### **Ethical Guidelines:**
- **Responsible Disclosure**: Laporkan kerentanan yang ditemukan secara bertanggung jawab
- **No Malicious Intent**: Jangan gunakan untuk tujuan merusak atau merugikan
- **Respect Rate Limits**: Jangan overload target server dengan request berlebihan
- **Data Privacy**: Jangan mengekstrak atau menyimpan data sensitif yang tidak perlu

### **Technical Warnings:**
- **High Resource Usage**: Tools ini dapat menggunakan bandwidth dan CPU yang tinggi
- **False Positives**: Selalu verify hasil secara manual sebelum reporting
- **Network Impact**: Scanning dapat mempengaruhi performance target aplikasi
- **Detection Risk**: Aktivitas scanning dapat terdeteksi oleh security monitoring

## 🔧 Bagian yang Dapat Diedit

### **1. Konfigurasi Scanning (`ScanConfig` class)**
```python
@dataclass
class ScanConfig:
    threads: int = 100              # DAPAT DIEDIT: Jumlah concurrent threads
    max_threads: int = 500          # DAPAT DIEDIT: Maximum thread limit
    timeout: int = 5                # DAPAT DIEDIT: Request timeout dalam detik
    retry_count: int = 2            # DAPAT DIEDIT: Jumlah retry untuk failed request
    rate_limit: float = 0.05        # DAPAT DIEDIT: Delay antar request (detik)
    max_payload_per_test: int = 50  # DAPAT DIEDIT: Maximum payload per vulnerability test
    deep_scan: bool = True          # DAPAT DIEDIT: Enable/disable deep scanning
    async_mode: bool = True         # DAPAT DIEDIT: Enable/disable async mode
```

**Penjelasan Editable Parameters:**
- **threads**: Mengatur jumlah concurrent request (50-500 recommended)
- **timeout**: Timeout untuk setiap request (3-10 detik recommended)
- **rate_limit**: Delay antar request untuk menghindari rate limiting
- **max_payload_per_test**: Membatasi jumlah payload untuk setiap test

### **2. Payload Database (`PayloadDatabase` class)**
```python
def _load_mega_payloads(self) -> Dict[str, List[str]]:
    return {
        "xss_basic": [
            # DAPAT DIEDIT: Tambahkan XSS payload baru
            "<script>alert(1)</script>",
            # Tambahkan payload Anda di sini
        ],
        "sqli_basic": [
            # DAPAT DIEDIT: Tambahkan SQL injection payload
            "' OR '1'='1",
            # Tambahkan payload Anda di sini
        ]
        # DAPAT DIEDIT: Tambahkan kategori payload baru
    }
```

**Penjelasan Payload Editing:**
- **Menambah Payload Baru**: Tambahkan string payload ke list yang sesuai
- **Membuat Kategori Baru**: Buat key baru dengan list payload
- **Modifikasi Payload**: Edit payload yang ada sesuai kebutuhan testing

### **3. User-Agent Strings (`EnhancedHttpClient` class)**
```python
self.user_agents = [
    # DAPAT DIEDIT: Tambahkan user-agent baru
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    # Tambahkan user-agent Anda di sini
]
```

### **4. HTTP Headers (`_get_random_headers` method)**
```python
def _get_random_headers(self) -> Dict[str, str]:
    return {
        # DAPAT DIEDIT: Modifikasi headers sesuai kebutuhan
        'User-Agent': random.choice(self.user_agents),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
        # Tambahkan header custom di sini
    }
```

### **5. Vulnerability Detection Patterns**
```python
# Dalam method _check_sqli_indicators
error_patterns = [
    # DAPAT DIEDIT: Tambahkan pattern error database baru
    'sql syntax', 'mysql_fetch', 'postgresql query failed',
    # Tambahkan pattern Anda di sini
]

# Dalam method _check_xss_reflection
rce_patterns = [
    # DAPAT DIEDIT: Tambahkan pattern RCE detection
    'root:', 'uid=', 'gid=',
    # Tambahkan pattern Anda di sini
]
```

### **6. Command Line Arguments**
```python
# Dalam main() function
parser.add_argument("-t", "--threads", type=int, default=100)
# DAPAT DIEDIT: Tambahkan argument baru
# parser.add_argument("--proxy", help="HTTP proxy URL")
# parser.add_argument("--cookie", help="Cookie string")
```

### **7. Output Formatting**
```python
# Dalam _print_vulnerability method
color = {
    'Critical': Fore.RED,
    'High': Fore.MAGENTA,
    # DAPAT DIEDIT: Tambahkan severity level baru
    'Medium': Fore.YELLOW,
    'Low': Fore.GREEN
}
```

## 🚫 Bagian yang TIDAK Boleh Diedit

### **1. Core Async Functions**
```python
async def make_request(self, method: str, url: str, **kwargs):
    # JANGAN EDIT: Core request handling logic
    # Mengubah bagian ini dapat menyebabkan tool tidak berfungsi
```

**Penjelasan**: Function ini mengatur core HTTP request handling dengan async/await. Modifikasi dapat menyebabkan:
- Connection pool errors
- Memory leaks
- Async coroutine conflicts
- Request timeout issues

### **2. Threading dan Concurrency Logic**
```python
# JANGAN EDIT: Asyncio event loop handling
tasks = [
    self.detector.detect_xss(base_url, params),
    self.detector.detect_sqli(base_url, params),
]
await asyncio.gather(*tasks)
```

**Penjelasan**: Bagian ini mengatur concurrent execution. Modifikasi dapat menyebabkan:
- Race conditions
- Deadlocks
- Resource exhaustion
- Performance degradation

### **3. Session Management**
```python
def _create_session(self):
    # JANGAN EDIT: aiohttp session configuration
    session = aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=self.config.timeout),
        connector=aiohttp.TCPConnector(...)
    )
```

**Penjelasan**: Session configuration yang optimal untuk security scanning. Modifikasi dapat menyebabkan:
- Connection errors
- SSL verification issues
- Performance problems
- Memory leaks

### **4. Vulnerability Detection Logic**
```python
async def _check_sqli_indicators(self, response, payload):
    # JANGAN EDIT: Core detection algorithm
    # Pattern matching logic yang sudah dioptimasi
```

**Penjelasan**: Algoritma deteksi yang sudah dioptimasi untuk akurasi tinggi. Modifikasi dapat menyebabkan:
- False positive increase
- False negative increase
- Detection bypass
- Performance degradation

### **5. Error Handling Mechanisms**
```python
try:
    # Request logic
except Exception as e:
    # JANGAN EDIT: Critical error handling
    if attempt == self.config.retry_count - 1:
        return None
```

**Penjelasan**: Error handling yang ensures tool stability. Modifikasi dapat menyebabkan:
- Unhandled exceptions
- Tool crashes
- Resource leaks
- Inconsistent behavior

### **6. Data Structure Definitions**
```python
@dataclass
class VulnerabilityResult:
    # JANGAN EDIT: Field definitions
    vuln_type: str
    severity: str
    # Mengubah dapat merusak reporting
```

**Penjelasan**: Data structure yang digunakan untuk reporting. Modifikasi dapat menyebabkan:
- Serialization errors
- Report generation failures
- Data integrity issues
- Compatibility problems

### **7. Import Statements**
```python
# JANGAN EDIT: Required imports
import asyncio
import aiohttp
import json
# Menghapus import dapat menyebabkan ModuleNotFoundError
```

**Penjelasan**: Dependencies yang critical untuk tool functionality. Modifikasi dapat menyebabkan:
- Import errors
- Module not found exceptions
- Feature unavailability
- Runtime errors

## 📊 Performance Optimization

### **Threading Configuration:**
- **Low-end Systems**: 50-100 threads
- **Mid-range Systems**: 100-200 threads
- **High-end Systems**: 200-500 threads

### **Rate Limiting:**
- **Aggressive Scanning**: 0.01-0.05 seconds
- **Moderate Scanning**: 0.05-0.1 seconds
- **Gentle Scanning**: 0.1-0.5 seconds

### **Memory Management:**
- Tool menggunakan approximately 100-500MB RAM
- Automatic garbage collection untuk response objects
- Connection pooling untuk efficiency

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch
3. **Make** your changes dengan proper testing
4. **Submit** a pull request dengan detailed description

## 📞 Support & Contact

- **GitHub Repository**: https://github.com/HolyBytes/pyvulnhunter_pro.git
- **Support Donation**: https://saweria.co/HolyBytes
- **Developer**: ADE PRATAMA
- **Team**: Bugpent_Cybercore

---

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for details.

## 🔒 Security Notice

This tool is designed untuk legitimate security testing purposes only. Users are fully responsible untuk ensuring compliance dengan applicable laws dan regulations dalam menggunakan tool ini.

---

**© 2024 PyVulnHunter PRO - Developed by ADE PRATAMA & Team Bugpent_Cybercore**
