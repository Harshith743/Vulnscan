# 🔍 VulnScan — Custom Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)  
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)  
[![Status](https://img.shields.io/badge/Status-Learning%20%26%20Development-yellow.svg)]()  

VulnScan is a **Python-based modular vulnerability scanner** with **Nmap integration**.  
It’s designed for learning, labs, and demonstrating applied cybersecurity skills — scanning for open ports, grabbing service banners, and matching potential vulnerabilities.  

⚠️ **Ethical Note:** This tool is for **educational purposes only**. Use it **only on systems you own or have explicit permission to test**.

---

## 📌 Features
- ✅ Basic TCP/UDP port scanning  
- ✅ Nmap integration (`python-nmap` or subprocess)  
- ✅ Banner grabbing & simple vulnerability detection  
- ✅ JSON/HTML reporting for scan results  
- ✅ Modular architecture (easily add HTTP, SSH, DB modules)  
- ✅ Example outputs for vulnerable VM labs (Metasploitable, Juice Shop)  

---

## 🛠️ Requirements

### Hardware / Environment
- Development machine (Windows / macOS / Linux) with **8+ GB RAM** recommended  
- Vulnerable VM lab: **Metasploitable** or **OWASP Juice Shop** (VirtualBox/VMware/Docker)  
- *(Optional)* Raspberry Pi or VPS for testing network discovery  

### Software
- [Python 3.9+](https://www.python.org/downloads/)  
- [Nmap](https://nmap.org/download.html) (required)  
- Git + GitHub account  
- Virtual environment (`venv` or `virtualenv`)  
- *(Optional)* Docker & VS Code  

### Python Libraries
```bash
pip install -r requirements.txt
