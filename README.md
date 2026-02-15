<div align="center">

<br/>

<a href="https://github.com/chadi0x/better-call-chadi">
  <img src="https://github.com/user-attachments/assets/b01f5806-a8b0-4b47-b9fa-ab6b7a4a6fec" width="100%" alt="Better Call Chadi Banner" style="border-radius: 10px; box-shadow: 0 0 20px rgba(0, 255, 0, 0.2);">
</a>

<br/>

# 🚀 BETTER CALL CHADI 🚀
### Advanced Vulnerability Scanner & Red Team Operations Framework

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-red?style=for-the-badge)](https://github.com/chadi0x/better-call-chadi)

<br/>

> **"Stop staring at terminal output. Start visualizing the battlefield."**

**Better Call Chadi** is a unified **Cyber Defense & Offense Platform** that transforms your browser into a command center for Penetration Testing, Red Teaming, and Threat Intelligence. Built with a responsive **Dark Mode** aesthetic, it combines powerful vulnerability scanners, offensive engineering tools, and real-time 3D visualization.

[**Features**](#-ex-machina) • [**Visuals**](#-ghost-view) • [**Installation**](#-deployment) • [**Usage**](#-operations)

</div>

---

## ⚔️ Ex Machina (The Arsenal)

### 🛡️ **Vulnerability Scanner**
*Automated reconnaissance and vulnerability assessment for web applications and infrastructure.*

| Icon | Tool | Description |
| :---: | :--- | :--- |
| 🕷️ | **Wapiti Integration** | Deep web vulnerability scanning (SQLi, XSS, RCE, SSRF) with custom profiles (Quick, Stealth, Critical). |
| 🌐 | **Subdomain Enum** | Fast enumeration of subdomains to expand your attack surface. |
| 🔌 | **Port Scanner** | Rapid TCP port scanning to identify open services and potential entry points. |
| 🧬 | **Tech Detector** | Fingerprint web technologies (Server, CMS, Frameworks) to tailor your attacks. |
| 📜 | **SSL Inspector** | Analyze SSL/TLS certificates for validity, issuer verification, and security posture. |
| 🔍 | **Header Analyzer** | Check for missing security headers (HSTS, CSP, X-Frame-Options) to harden defenses. |

### 🔬 **Engineering Lab**
*Analyze artifacts, generate payloads, and reverse engineer suspicious files.*

| Icon | Tool | Description |
| :---: | :--- | :--- |
| 🦠 | **Malware Analysis** | Upload files for static analysis, YARA rule matching, and ClamAV scanning. |
| 🧩 | **YARA Engine** | Custom YARA rules to detect malware families and suspicious byte patterns. |
| 📦 | **Archive Inspector** | Deep recursive scanning of ZIP archives to find hidden threats. |
| 💾 | **Hash Database** | Check file hashes against a known malware database for instant identification. |

### 🧱 **The Wall (Red Team)**
*Offensive tools for the modern operator. "Safe with the devil."*

| Icon | Tool | Description |
| :---: | :--- | :--- |
| 🎭 | **Social Engineer** | Generate high-fidelity phishing templates for various platforms (Google, Microsoft, etc.). |
| 👻 | **Obfuscator** | Evade detection by obfuscating payloads (Python, Shell) with Base64 and junk code. |
| 🌍 | **Proxy Scraper** | Harvest fresh HTTP/SOCKS proxies for anonymous operations. |
| 🔑 | **VPN Gate** | Fetch valid OpenVPN configurations from around the world. |

### 📡 **Global Intelligence**
*Visualize the cyber war in real-time.*

| Icon | Tool | Description |
| :---: | :--- | :--- |
| 🗺️ | **3D Threat Map** | WebGL-based globe visualizing live attack vectors and geolocation data. |
| 📰 | **Intel Feeds** | Aggregated real-time news from CISA, Exploit-DB, and The Hacker News. |
| 🏴‍☠️ | **APT Encyclopedia** | Searchable database of Threat Groups (APTs), their tools, and country of origin. |

---

## 📸 Ghost View (Visuals)

<div align="center">

| 📡 **Live Threat Intelligence Dashboard** |
| :---: |
| <img src="https://github.com/user-attachments/assets/82483119-c103-40c2-9445-3d0854e1aabe" width="100%" alt="Live Threat Map" style="border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.5); border: 1px solid #333;"/> |
| *Real-time attack vectors, active malware beacons, and global threat monitoring.* |

</div>

<br/>

---

## 🚀 Deployment

### Docker Quick Start (Recommended)

The fastest way to get **Better Call Chadi** running is via Docker Compose.

```bash
# 1. Clone the repository
git clone https://github.com/chadi0x/better-call-chadi.git
cd better-call-chadi

# 2. Launch with Docker Compose
docker-compose up --build -d
```

*   **Frontend**: `http://localhost`
*   **Backend API**: `http://localhost:8000`

### Manual Installation

<details>
<summary>Click to expand manual setup instructions</summary>

#### Backend (Python)
```bash
cd backend/python
pip install -r requirements.txt
python app.py
```

#### Frontend
```bash
cd frontend
npm install
npm run dev
```
</details>

---

## ⚠️ Disclaimer

<div align="center" style="border: 2px solid #ef4444; padding: 20px; border-radius: 8px; background-color: rgba(239, 68, 68, 0.1);">

### 🚨 LEGAL WARNING 🚨

This project is for **EDUCATIONAL PURPOSES and AUTHORIZED SECURITY TESTING ONLY**.

The developers are **not responsible** for any misuse, damage, or illegal acts caused by this software. Scanning targets without explicit written permission is illegal and punishable by law.

**Do not use this tool on systems you do not own.**

</div>

---

<div align="center">

Made with ❤️, ☕, and 🐍 by **Chadi**

[![GitHub](https://img.shields.io/badge/GitHub-chadi0x-181717?style=social&logo=github)](https://github.com/chadi0x)
[![Twitter](https://img.shields.io/badge/Twitter-@chadi0x-1DA1F2?style=social&logo=twitter)](https://twitter.com/chadi0x)

</div>
