# Better Call Chadi 🚀

### The Ultimate Cyberpunk SOC Dashboard & Pentesting Toolkit

> **Better Call Chadi** is a comprehensive, browser-based security operations and penetration testing platform designed for ethical hackers, red teamers, and SOC analysts. Built with a sleek, responsive Cyberpunk aesthetic, it integrates powerful scanning, forensics, and intelligence capabilities into a single unified interface.

---

### 🔥 Features

#### 🛡️ 1. Advanced Scanner
Perform extensive reconnaissance and vulnerability assessments with dedicated profiles:
*   **Web / API / Infra Scan**: Custom scopes.
*   **Vulnerability Profiles**: Quick, Stealth, SQLi, XSS, RCE hunting.
*   **Active Toolkit**:
    *   🏷️ **Subdomain Enumeration**
    *   🕸️ **App Crawler**
    *   🔌 **Port Scanner**
    *   🆔 **Whois Lookup**
    *   🌍 **DNS Records**
    *   🔒 **SSL Inspector**
    *   ⚙️ **Tech Stack Detection**

#### 🔬 2. Engineer Mode
Deep dive into artifacts and binaries:
*   **Binary Inspector**: Static analysis and YARA scanning for malware detection.
*   **Wordlist Generator**: Create custom intelligent wordlists based on charset/patterns.
*   **PCAP Analyzer**: Network traffic inspection with protocol breakdown and threat alerts.

#### 🕶️ 3. Behind the Wall (Red Team Tools)
Tools designed for the offensive operator:
*   **Shadow Cloak**: Payload obfuscation and evasion techniques.
*   **Social Engineer**: High-fidelity phishing template generator with scenario support.
*   **Ghost Proxies**: Real-time proxy scraper and tester.
*   **VPN Gate**: Grab OpenVPN configs by country code.

#### 🌍 4. Global Intelligence (Live Map)
Visualize cyber threats in real-time on an interactive 3D Globe:
*   **Active Threats**: Top malware families currently active in the wild.
*   **Real-Time Feed**: Streaming attacks and C2 beacons with geolocation flags.
*   **3D Visualization**: Dynamic arcs and points representing attack vectors.

#### 🔎 5. Threat Intelligence & Forensics
*   **Threat Groups**: Detailed wiki of known APT groups and their TTPs.
*   **Intel Feed**: Latest cybersecurity news aggregation.
*   **Forensics**: APK Analysis and System Triage data parsing.

---

### 📸 Screenshots

| Dashboard Overview | Live Global Map | Engineer Mode | Behind The Wall |
|:---:|:---:|:---:|:---:|
| <img src="screenshots/dash.png" width="200" alt="Dashboard" /> | <img src="screenshots/globe.png" width="200" alt="Live Map" /> | <img src="screenshots/engineer.png" width="200" alt="Engineer" /> | <img src="screenshots/wall.png" width="200" alt="Red Team Tools" /> |

---

### 🚀 Getting Started

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/chadi0x/better-call-chadi.git
    cd better-call-chadi
    ```

2.  **Start Services (Docker):**
    ```bash
    docker-compose up --build
    ```

3.  **Access the Dashboard:**
    Open your browser and navigate to `http://localhost:3000`.

---

### 🛡️ Security Philosophy

> *"The only truly secure system is one that is powered off, cast in a block of concrete and sealed in a lead-lined room with armed guards - and even then I have my doubts."*
> 
> — **Gene Spafford**

---

### 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request if you have any cool ideas or bug fixes.

**Disclaimer:** This tool is for **educational and authorized testing purposes only**. The developers are not responsible for any misuse or damage caused by this software. Use responsibly.
