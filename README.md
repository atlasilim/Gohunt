# 🚀 GoHunt - All-in-One Web Pentest Tool

<div align="center">

![GoHunt Logo](https://img.shields.io/badge/GoHunt-v1.0-red?style=for-the-badge&logo=go)
![Go Version](https://img.shields.io/badge/Go-1.21+-blue?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)

**Comprehensive Web Security Scanning Tool**

</div>

---

## 📋 Table of Contents

- [🎯 Overview](#-overview)
- [✨ Features](#-features)
- [🚀 Installation](#-installation)
- [📖 Usage](#-usage)
- [🔧 Parameters](#-parameters)
- [📊 Output Formats](#-output-formats)
- [💡 Examples](#-examples)
- [⚠️ Security Warnings](#️-security-warnings)
- [🤝 Contributing](#-contributing)

---

## 🎯 Overview

**GoHunt** is a powerful pentest tool written in Go that comprehensively analyzes the security status of web applications. With a single command, you can perform multiple security tests, detect open ports, discover subdomains, and identify security vulnerabilities.

### 🎨 Why GoHunt?

- **🚀 Fast**: Results in seconds thanks to Go's performance
- **🔍 Comprehensive**: 7 different security tests in one tool
- **💻 Cross-Platform**: Works on Windows, Linux and macOS
- **📊 Multi-Format**: JSON, HTML, CSV, XML and TXT output support
- **⚡ Parallel Processing**: Fast scanning with multiple goroutines
- **🌐 OSINT Integration**: Subdomain discovery with HackerTarget API

---

## ✨ Features

### 🔍 **Scan Modes**
- **Subdomain Discovery**: DNS brute force + OSINT sources + Custom wordlist support
- **Port Scanning**: TCP connect + banner grabbing
- **CVE Analysis**: CIRCL API + heuristic matching
- **Web Technology Detection**: HTTP headers + HTML analysis
- **Reverse IP Lookup**: IP resolution and PTR records
- **WHOIS Lookup**: Domain registration information
- **Vulnerability Testing**: XSS, SQLi, LFI, SSTI, Open Redirect

### 🚀 **Performance Features**
- Parallel scanning (goroutine-based)
- Rate limiting and timeout management
- Retry mechanism
- Progress tracking
- Memory-efficient processing

### 📊 **Output Formats**
- **JSON**: For API integration
- **HTML**: For web reports
- **CSV**: For Excel analysis
- **XML**: For system integration
- **TXT**: For simple text reports

---

## 🚀 Installation

### 📋 Requirements
- Go 1.21 or higher
- Windows, Linux or macOS

### 🔧 Installation Steps

#### 1. Go Installation
```bash
# Windows
# Download from https://golang.org/dl/

# Linux
sudo apt-get install golang-go

# macOS
brew install go
```

#### 2. GoHunt Installation
```bash
# Clone repository
git clone https://github.com/yourusername/gohunt.git
cd gohunt

# Install dependencies
go mod tidy

# Build
go build -o gohunt.exe main.go

# Add executable to PATH (optional)
# Windows: Copy gohunt.exe to C:\Windows\System32\
# Linux/macOS: sudo cp gohunt /usr/local/bin/
```

#### 3. Quick Test
```bash
# Test scan
./gohunt.exe --target example.com --all-in-one
```

---

## 📖 Usage

### 🎯 **Basic Usage**
```bash
# Run all scans
gohunt --target example.com --all-in-one

# Subdomain scan only
gohunt --target example.com --subdomain

# Subdomain scan with custom wordlist
gohunt --target example.com --subdomain --sub-wordlist wordlist.txt

# Port scan with custom port list
gohunt --target example.com --port-scan --ports 1-1024

# CVE scan
gohunt --target example.com --cve-scan

# XSS test
gohunt --target example.com --xss
```

### 🔧 **Advanced Usage**
```bash
# All scans with verbose output
gohunt --target example.com --all-in-one --verbose

# Custom output format
gohunt --target example.com --all-in-one --output report.json

# Subdomain scan with custom wordlist
gohunt --target example.com --subdomain --sub-wordlist custom_wordlist.txt

# Custom port list and timeout
gohunt --target example.com --port-scan --ports 22,80,443,3306 --port-timeout-ms 1000

# OSINT subdomain limit
gohunt --target example.com --subdomain --osint-max 1000

# Rate limiting
gohunt --target example.com --all-in-one --rate-limit-ps 5
```

---

## 🔧 Parameters

### 🎯 **Basic Parameters**
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--target` | Target domain/IP | Required |
| `--all-in-one` | Run all scans | false |
| `--verbose` | Verbose output | false |
| `--help, -h` | Show help menu | - |

### 🔍 **Scan Parameters**
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--subdomain` | Subdomain scan | false |
| `--sub-wordlist` | Custom subdomain wordlist file | Default wordlist |
| `--port-scan` | Port scan | false |
| `--cve-scan` | CVE scan | false |
| `--reverse-ip` | Reverse IP lookup | false |
| `--whois` | WHOIS lookup | false |
| `--xss` | XSS test | false |
| `--sqli` | SQLi test | false |
| `--lfi` | LFI test | false |

### ⚙️ **Performance Parameters**
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--ports` | Ports to scan | 22,21,25,53,80,110,143,443,587,993,995,3306,5432,6379,8080,8443 |
| `--port-timeout-ms` | Port timeout (ms) | 800 |
| `--port-concurrency` | Port scan concurrency | 200 |
| `--sub-concurrency` | Subdomain scan concurrency | 150 |
| `--http-timeout-ms` | HTTP timeout (ms) | 4000 |
| `--rate-limit-ps` | HTTP rate limit | 3 |

### 🌐 **OSINT Parameters**
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--osint` | Use OSINT sources | true |
| `--osint-max` | OSINT subdomain limit | 5000 |
| `--osint-timeout-ms` | OSINT timeout (ms) | 10000 |
| `--osint-rate-limit-ps` | OSINT rate limit | 1 |

**Note**: OSINT sources are automatically disabled when custom wordlist is used.

### 📤 **Output Parameters**
| Parameter | Description | Supported Formats |
|-----------|-------------|-------------------|
| `--output` | Output file | .json, .html, .csv, .xml, .txt |
| `--log-file` | Log file | .log, .txt |

---

## 📊 Output Formats

### 🔍 **JSON Output**
```json
{
  "target": "example.com",
  "subdomains": [
    {"name": "www", "status": "Active"},
    {"name": "mail", "status": "Active"}
  ],
  "openPorts": [
    {"port": 80, "service": "HTTP", "banner": "Apache/2.4.41"}
  ],
  "cves": [
    {"id": "CVE-2021-41773", "severity": "High", "cvss": 7.5}
  ]
}
```

### 📝 **Wordlist Format Example**
```txt
# subdomains.txt - One subdomain per line
www
mail
dev
test
api
blog
staging
admin
ftp
smtp
vpn
portal
mobile
cdn
static
beta
old
new
ns1
ns2
shop
app
support
help
git
jira
grafana
monitor
status
cache
db
node
edge
proxy
gateway
pay
payment
auth
```

### 🌐 **HTML Output**
- Modern web-based reports
- Responsive design
- Interactive elements
- Export features

### 📋 **CSV Output**
- Excel compatible
- Easy analysis
- Optimized for large datasets

---

## 💡 Examples

### 🎯 **Basic Scan**
```bash
# Quick scan for example.com
gohunt --target example.com --all-in-one
```

### 🔍 **Subdomain Wordlist Examples**
```bash
# Subdomain scan with custom wordlist
gohunt --target example.com --subdomain --sub-wordlist subdomains.txt

# Comprehensive scan with large wordlist
gohunt --target example.com --subdomain --sub-wordlist large_wordlist.txt --sub-concurrency 300

# Wordlist + OSINT combination
gohunt --target example.com --subdomain --sub-wordlist custom.txt --osint-max 2000
```

### 🔍 **Detailed Analysis**
```bash
# Comprehensive scan with verbose output
gohunt --target example.com --all-in-one --verbose --output detailed_report.json
```

### 🚀 **Performance Optimization**
```bash
# Fast scan settings
gohunt --target example.com --all-in-one \
  --port-concurrency 500 \
  --sub-concurrency 300 \
  --rate-limit-ps 5
```

### 📊 **Custom Output Format**
```bash
# Create HTML report
gohunt --target example.com --all-in-one --output report.html

# Create CSV report
gohunt --target example.com --all-in-one --output report.csv
```

---

## ⚠️ Security Warnings

### 🚨 **Important Notes**
- This tool should only be used for **legal and ethical** purposes
- Test on your own systems or systems with **written permission**
- Use carefully in **production environments**
- Adjust rate limiting settings according to the **target system's capacity**

### 🔒 **Security Measures**
- Keep `--rate-limit-ps` parameter low
- Increase `--port-timeout-ms` value
- Limit `--osint-rate-limit-ps` value
- Store log files securely

### 📝 **Wordlist Usage Notes**
- Wordlist file should be formatted with one subdomain per line
- Maximum 20,000 lines supported
- Empty lines and comments starting with # are automatically skipped
- OSINT sources are disabled when custom wordlist is used
- Wordlist file should be in UTF-8 format

---

## 🤝 Contributing

### 🔧 **Development Environment Setup**
```bash
# Fork repository
git clone https://github.com/yourusername/gohunt.git
cd gohunt

# Create development branch
git checkout -b feature/new-feature

# Commit changes
git add .
git commit -m "Add new feature"

# Send pull request
git push origin feature/new-feature
```

### 📝 **Contribution Areas**
- 🐛 Bug fixes
- ✨ New features
- 📚 Documentation improvements
- 🎨 UI/UX enhancements
- 🚀 Performance optimizations

### 📋 **Code Standards**
- Follow Go standard code format
- Maintain test coverage
- Update README
- Write descriptive commit messages

---

## 📞 Contact

- **GitHub**: [@atlasilim](https://github.com/atlasilim)


---

<div align="center">

**⭐ Don't forget to star this project if you liked it! ⭐**

**🔒 Thanks for safe and ethical usage!**

</div>
