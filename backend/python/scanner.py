import uuid
import time
import subprocess
import threading
import json
import logging
import requests
import socket
import dns.resolver
import random
import whois
import ssl
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScannerWrapper:
    def __init__(self):
        self.scans = {}

    def start_scan(self, target, profile, scope=None):
        scan_id = str(uuid.uuid4())
        self.scans[scan_id] = {
            "id": scan_id,
            "target": target,
            "profile": profile,
            "scope": scope or [],
            "status": "RUNNING",
            "progress": 0,
            "findings": [],
            "timestamp": time.time()
        }
        
        thread = threading.Thread(target=self._run_wapiti, args=(scan_id, target, profile, scope))
        thread.daemon = True
        thread.start()
        
        return scan_id

    def _run_wapiti(self, scan_id, target, profile, scope):
        logger.info(f"Starting Wapiti scan {scan_id} for {target} (Profile: {profile}, Scope: {scope})")
        
        output_file = f"/tmp/wapiti_{scan_id}.json"
        cmd = ["wapiti", "-u", target, "-f", "json", "-o", output_file, "--flush-session"]
        
        if profile == "quick":
            cmd.extend(["-m", "xss,sql,blindsql,exec,file", "--depth", "1", "--max-scan-time", "120"])
        elif profile == "stealth":
            agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15"
            ]
            ua = random.choice(agents)
            cmd.extend(["--wait", "2.0", "--header", f"User-Agent: {ua}", "--depth", "1"])
            
        elif profile == "sqli":
            # SQL Injection Focus
            cmd.extend(["-m", "sql,blindsql", "--depth", "2", "--level", "2"])
            
        elif profile == "xss":
            # XSS Focus
            cmd.extend(["-m", "xss,xss_permanent", "--depth", "2", "--level", "2"])
            
        elif profile == "critical":
            # Critical Risks: RCE, LFI, SSRF, Shellshock
            cmd.extend(["-m", "exec,file,ssrf,shellshock,crlf", "--depth", "2"])
            
        elif profile == "aggressive":
            # Aggressive: Fast, no wait, high threads (if supported via cmd args, or just relying on internal concurrency)
            # We'll use default modules but remove timeout limits if possible or just rely on default
            cmd.extend(["--max-scan-time", "0", "--depth", "2", "--verify-ssl", "0"])
            
        else: # full
            # Full: All modules (default), deeper scan, higher level
            # Uses default modules (all active)
            # --level 1 is default, we'll keep it to avoid extremely long scans, but depth 2
            cmd.extend(["--depth", "2", "--verify-ssl", "0"])
            
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            while process.poll() is None:
                if self.scans[scan_id]["progress"] < 90:
                    self.scans[scan_id]["progress"] += 5
                time.sleep(2)
            
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                self._parse_wapiti_report(scan_id, output_file)
                self.scans[scan_id]["status"] = "COMPLETED"
                self.scans[scan_id]["progress"] = 100
            else:
                logger.error(f"Scan failed: {stderr}")
                self.scans[scan_id]["status"] = "FAILED"
                self.scans[scan_id]["progress"] = 0
        except Exception as e:
            logger.error(f"Scan error: {e}")
            self.scans[scan_id]["status"] = "ERROR"

    def _parse_wapiti_report(self, scan_id, report_file):
        try:
            with open(report_file, 'r') as f:
                data = json.load(f)
            vulns = data.get("vulnerabilities", {})
            findings = []
            for category, items in vulns.items():
                for item in items:
                    evidence = ""
                    if "http_request" in item: evidence += f"Request:\n{item['http_request']}\n\n"
                    if "curl_command" in item: evidence += f"Curl Replay:\n{item['curl_command']}"
                    if not evidence and "parameter" in item: evidence = f"Vulnerable Parameter: {item['parameter']}"

                    findings.append({
                        "severity": self._map_severity(item.get("level", 0)),
                        "title": category,
                        "description": item.get("info", "No description provided"),
                        "endpoint": item.get("path", item.get("url", "Unknown")),
                        "method": item.get("method", "GET"),
                        "parameter": item.get("parameter", "Unknown"),
                        "evidence": evidence,
                        "scan_id": scan_id
                    })
            self.scans[scan_id]["findings"] = findings
        except Exception as e:
            logger.error(f"Report parsing error: {e}")

    def _map_severity(self, level):
        if level >= 3: return "critical"
        if level == 2: return "high"
        if level == 1: return "medium"
        return "low"
    
    def get_scan(self, scan_id): return self.scans.get(scan_id)
    def get_all_scans(self): return list(self.scans.values())

class Crawler:
    def crawl(self, start_url, max_pages=20):
        if not start_url.startswith("http"):
            start_url = "http://" + start_url
            
        visited = set()
        to_visit = [start_url]
        results = []
        
        try:
            base_domain = urlparse(start_url).netloc
        except:
            return [{"error": "Invalid URL"}]

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited: continue
                
            try:
                visited.add(url)
                response = requests.get(url, timeout=3, headers={"User-Agent": "ChadiBot/1.0"})
                if response.status_code == 200:
                    title = self._get_title(response.text)
                    results.append({
                        "url": url, 
                        "status": response.status_code, 
                        "title": title
                    })
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        full_url = urljoin(url, link['href'])
                        # Only crawl same domain and http/https
                        if full_url.startswith("http") and urlparse(full_url).netloc == base_domain:
                            if full_url not in visited and full_url not in to_visit:
                                to_visit.append(full_url)
            except Exception as e:
                logger.error(f"Crawl error for {url}: {e}")
                
        return results

    def _get_title(self, html):
        try:
            soup = BeautifulSoup(html, 'html.parser')
            return soup.title.string.strip()[:50] if soup.title else "No Title"
        except:
            return "No Title"

class SubdomainScanner:
    def scan(self, domain):
        subdomains = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "web", "test", "dev", "api", "shop", "admin", "vpn", "remote", "blog", "secure", "portal", "beta"]
        found = []
        domain = domain.replace("http://", "").replace("https://", "").split('/')[0]
        for sub in subdomains:
            hostname = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(hostname, 'A')
                ip = answers[0].to_text()
                found.append({"hostname": hostname, "ip": ip})
            except: pass
        return found

class PortScanner:
    def scan(self, target):
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 27017]
        open_ports = []
        target = target.replace("http://", "").replace("https://", "").split('/')[0]
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((target, port)) == 0:
                open_ports.append({"port": port, "service": self._get_service_name(port)})
            sock.close()
        return open_ports
    def _get_service_name(self, port):
        common = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL"}
        return common.get(port, "Unknown")

class WhoisLookup:
    def lookup(self, domain):
        try:
            domain = domain.replace("http://", "").replace("https://", "").split('/')[0]
            w = whois.whois(domain)
            return str(w)
        except Exception as e:
            return f"Whois lookup failed: {str(e)}"

class DNSEnumerator:
    def scan(self, domain):
        records = {}
        domain = domain.replace("http://", "").replace("https://", "").split('/')[0]
        for r_type in ['A', 'MX', 'NS', 'TXT', 'SOA']:
            try:
                answers = dns.resolver.resolve(domain, r_type)
                records[r_type] = [r.to_text() for r in answers]
            except:
                records[r_type] = []
        return records

class HeaderAnalyzer:
    def analyze(self, url):
        try:
            if not url.startswith("http"): url = "http://" + url
            res = requests.get(url, timeout=5)
            headers = res.headers
            missing = []
            secure_headers = {
                "Strict-Transport-Security": "HSTS not enforced.",
                "Content-Security-Policy": "No CSP detected.",
                "X-Frame-Options": "Clickjacking protection missing.",
                "X-Content-Type-Options": "MIME-sniffing protection missing.",
                "Referrer-Policy": "Referrer policy missing."
            }
            analysis = {"present": dict(headers), "missing": []}
            for header, msg in secure_headers.items():
                if header not in headers:
                    analysis["missing"].append(f"{header}: {msg}")
            return analysis
        except Exception as e:
            return {"error": str(e)}

class SSLInspector:
    def inspect(self, domain):
        try:
            domain = domain.replace("http://", "").replace("https://", "").split('/')[0]
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "version": cert['version'],
                        "notBefore": cert['notBefore'],
                        "notAfter": cert['notAfter']
                    }
        except Exception as e:
            return {"error": str(e)}

class TechDetector:
    def detect(self, url):
        try:
            if not url.startswith("http"): url = "http://" + url
            res = requests.get(url, timeout=5)
            tech = []
            
            # Checks
            if "Server" in res.headers: tech.append(f"Server: {res.headers['Server']}")
            if "X-Powered-By" in res.headers: tech.append(f"Powered By: {res.headers['X-Powered-By']}")
            
            soup = BeautifulSoup(res.text, 'html.parser')
            meta_gen = soup.find("meta", attrs={"name": "generator"})
            if meta_gen: tech.append(f"Generator: {meta_gen['content']}")
            
            return tech if tech else ["No obvious signature found."]
        except Exception as e:
            return {"error": str(e)}

class PayloadGenerator:
    def get_payloads(self, p_type):
        if p_type == "xss":
            return [
                "<script>alert(1)</script>",
                "javascript:alert(1)",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "\"><script>alert(1)</script>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<xss onmouseover=alert(1)>",
                "<scr<script>ipt>alert(1)</script>",
                "JaVaScRiPt:alert(1)"
            ]
        elif p_type == "sql":
            return [
                "' OR '1'='1",
                "admin' --",
                "UNION SELECT 1,2,3--",
                "1' ORDER BY 1--",
                "' OR 1=1 #",
                "' UNION SELECT null, null, version() --",
                "admin' #",
                "' AND 1=0 UNION ALL SELECT table_name FROM information_schema.tables --"
            ]
        elif p_type == "rce":
            return [
                "; cat /etc/passwd",
                "| whoami",
                "& ping -c 1 127.0.0.1",
                "; netstat -a",
                "$(whoami)",
                "`whoami`",
                "; system('cat /etc/passwd')"
            ]
        elif p_type == "lfi":
            return [
                "../../../../etc/passwd",
                "....//....//....//etc//passwd",
                "/etc/passwd%00",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "..%2f..%2f..%2fetc%2fpasswd"
            ]
        return []

class ThreatService:
    def __init__(self):
        self.data_file = "data/threat_groups.json"
        self.groups = self._load_data()

    def _load_data(self):
        try:
            with open(self.data_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load threat groups: {e}")
            return []

    def get_groups(self, query=None, country=None, category=None):
        results = self.groups
        
        if country:
            results = [g for g in results if g.get('country', '').lower() == country.lower()]
            
        if category:
            results = [g for g in results if g.get('category', '').lower() == category.lower()]
            
        if query:
            q = query.lower()
            results = [g for g in results if 
                       q in g.get('name', '').lower() or 
                       any(q in a.lower() for a in g.get('aliases', [])) or
                       any(q in t.lower() for t in g.get('tools', []))]
                       
        return results

                       
        return results

class IntelService:
    def __init__(self):
        self.feeds = [
            # ADVISORIES / ALERTS
            {"name": "CISA US-CERT", "url": "https://www.cisa.gov/uscert/ncas/alerts.xml", "type": "advisory"},
            {"name": "CERT-EU", "url": "https://media.cert.europa.eu/static/MEMO/rss/rss_latest_advisories.xml", "type": "advisory"},
            {"name": "Google Project Zero", "url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "type": "advisory"},
            
            # EXPLOITS
            {"name": "Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "type": "exploit"},
            {"name": "Packet Storm", "url": "https://rss.packetstormsecurity.com/files/tags/exploit/", "type": "exploit"},
            {"name": "CXSecurity", "url": "https://cxsecurity.com/wlb/rss/recent/", "type": "exploit"},
            
            # NEWS / RANSOMWARE
            {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "news"},
            {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "news"},
            {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "type": "news"},
            {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "type": "news"},
            {"name": "Threatpost", "url": "https://threatpost.com/feed/", "type": "news"},
            {"name": "Trend Micro", "url": "https://feeds.feedburner.com/TrendMicroRansomware", "type": "news"}
        ]
        self.cache = []
        self.last_update = 0
        self.cache_duration = 300 # 5 minutes

    def get_feed(self, limit=50, type_filter=None):
        import time
        import feedparser # Import here to avoid dependency if not used, but we added it to reqs

        now = time.time()
        if not self.cache or (now - self.last_update > self.cache_duration):
            self._fetch_feeds()

        results = self.cache
        
        if type_filter:
            results = [x for x in results if x['type'] == type_filter]
            
        return results[:limit]

    def _fetch_feeds(self):
        import feedparser
        import time
        from datetime import datetime
        
        normalized = []
        
        for feed in self.feeds:
            try:
                # Set timeout usage if possible, or just rely on feedparser default
                d = feedparser.parse(feed['url'])
                
                for entry in d.entries:
                    # Normalize
                    published = "Unknown"
                    timestamp = 0
                    
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        timestamp = time.mktime(entry.published_parsed)
                        published = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')
                    elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                        timestamp = time.mktime(entry.updated_parsed)
                        published = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')
                    
                    # Tag detection
                    tags = []
                    title_lower = entry.title.lower()
                    summary_lower = (entry.summary if hasattr(entry, 'summary') else "").lower()
                    
                    if "cve-" in title_lower or "cve-" in summary_lower:
                        tags.append("CVE")
                    if "ransomware" in title_lower or "ransomware" in summary_lower:
                        tags.append("Ransomware")
                    if "zero-day" in title_lower or "0-day" in title_lower:
                        tags.append("Zero-Day")
                    if feed['type'] == 'exploit':
                        tags.append("Exploit")

                    normalized.append({
                        "id": getattr(entry, 'id', entry.link),
                        "title": entry.title,
                        "link": entry.link,
                        "summary": self._clean_html(entry.summary)[:200] + "..." if hasattr(entry, 'summary') else "",
                        "source": feed['name'],
                        "type": feed['type'],
                        "published": published,
                        "timestamp": timestamp,
                        "tags": tags
                    })
            except Exception as e:
                logger.error(f"Error fetching feed {feed['name']}: {e}")

        # Sort by timestamp desc
        normalized.sort(key=lambda x: x['timestamp'], reverse=True)
        
        self.cache = normalized
        self.last_update = time.time()

    def _clean_html(self, raw_html):
        import re
        cleanr = re.compile('<.*?>')
        cleantext = re.sub(cleanr, '', raw_html)
        return cleantext.replace('&nbsp;', ' ')

# Singletons
scanner_service = ScannerWrapper()
crawler_service = Crawler()
subdomain_service = SubdomainScanner()
port_service = PortScanner()
payload_service = PayloadGenerator()
whois_service = WhoisLookup()
dns_service = DNSEnumerator()
header_service = HeaderAnalyzer()
ssl_service = SSLInspector()
tech_service = TechDetector()
threat_service = ThreatService()
intel_service = IntelService()
