from flask import Flask, jsonify, request, send_file, send_from_directory
import io
from scanner import ScannerWrapper, Crawler, SubdomainScanner, PortScanner, PayloadGenerator, WhoisLookup, DNSEnumerator, HeaderAnalyzer, SSLInspector, TechDetector, ThreatService, IntelService
import logging
import os

from engineer_service import EngineerService
from wordlist_service import WordlistService
from pcap_service import PcapService
from forensics_service import ForensicsService # Added this import
from wall_service import WallService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Max upload size (500MB for PCAP/APK)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024 

# Initialize services
scanner_service = ScannerWrapper()
crawler_service = Crawler()
intel_service = IntelService()
forensics_service = ForensicsService()
engineer_service = EngineerService()
wordlist_service = WordlistService(download_folder='/tmp')
pcap_service = PcapService(upload_folder='/tmp')
wall_service = WallService(upload_folder='/tmp')
whois_service = WhoisLookup()
dns_service = DNSEnumerator()
header_service = HeaderAnalyzer()
ssl_service = SSLInspector()
tech_service = TechDetector()
ssl_service = SSLInspector()
tech_service = TechDetector()
threat_service = ThreatService()
subdomain_service = SubdomainScanner()
port_service = PortScanner()
payload_service = PayloadGenerator()

# In-memory store for targets
targets = []

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        "status": "ok",
        "service": "python",
        "message": "Hello from Python Backend!"
    })

# --- Forensics Endpoints ---

@app.route('/api/forensics/apk', methods=['POST'])
def analyze_apk():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    if file.filename == '':
         return jsonify({"error": "No file selected"}), 400
    
    report = forensics_service.analyze_apk(file)
    return jsonify(report)

@app.route('/api/forensics/triage', methods=['POST'])
def analyze_triage():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    if file.filename == '':
         return jsonify({"error": "No file selected"}), 400
         
    report = forensics_service.parse_triage_data(file)
    return jsonify(report)

@app.route('/api/forensics/scripts/<os_type>', methods=['GET'])
def download_triage_script(os_type):
    script_path = forensics_service.get_triage_script(os_type)
    if script_path and os.path.exists(script_path):
        return send_file(script_path, as_attachment=True)
    return jsonify({"error": "Script not found"}), 404

# --- Engineer Mode Endpoints ---

@app.route('/api/engineer/scan', methods=['POST'])
def engineer_scan():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    report = engineer_service.scan_file(file)
    return jsonify(report)

@app.route('/api/engineer/wordlist', methods=['POST'])
def generate_wordlist():
    try:
        options = request.json
        result = wordlist_service.generate_wordlist(options)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/engineer/wordlist/download/<filename>', methods=['GET'])
def download_wordlist(filename):
    return send_from_directory(wordlist_service.download_folder, filename, as_attachment=True)

@app.route('/api/engineer/pcap', methods=['POST'])
def analyze_pcap():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    
    result = pcap_service.analyze_pcap(file)
    return jsonify(result)

# --- Threat Groups ---

@app.route('/api/scanner/targets', methods=['POST'])
def add_target():
    data = request.json
    target = {
        "id": len(targets) + 1,
        "url": data.get('url'),
        "profile": data.get('profile', 'quick'),
        "scope": data.get('scope', [])
    }
    targets.append(target)
    return jsonify({"status": "created", "target": target}), 201

@app.route('/api/scanner/targets', methods=['GET'])
def get_targets():
    return jsonify(targets)

@app.route('/api/scanner/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    profile = data.get('profile', 'quick')
    scope = data.get('scope', []) 
    
    if not target:
        return jsonify({"error": "Target URL is required"}), 400
        
    # Pass scope to scanner
    scan_id = scanner_service.start_scan(target, profile, scope)
    return jsonify({"status": "started", "scan_id": scan_id})

@app.route('/api/scanner/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    scan = scanner_service.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)

@app.route('/api/scanner/scans', methods=['GET'])
def get_all_scans():
    return jsonify(scanner_service.get_all_scans())

@app.route('/api/scanner/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    scan = scanner_service.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan.get("findings", []))

@app.route('/api/scanner/crawl', methods=['POST'])
def crawl_target():
    data = request.json
    target = data.get('target')
    results = crawler_service.crawl(target)
    return jsonify(results)

# --- New Tool Endpoints ---

@app.route('/api/scanner/subdomains', methods=['POST'])
def scan_subdomains():
    data = request.json
    target = data.get('target')
    results = subdomain_service.scan(target)
    return jsonify(results)

@app.route('/api/scanner/ports', methods=['POST'])
def scan_ports():
    data = request.json
    target = data.get('target')
    results = port_service.scan(target)
    return jsonify(results)

@app.route('/api/scanner/payloads/<ptype>', methods=['GET'])
def get_payloads(ptype):
    results = payload_service.get_payloads(ptype)
    return jsonify(results)

@app.route('/api/scanner/whois', methods=['POST'])
def tool_whois():
    target = request.json.get('target')
    return jsonify(whois_service.lookup(target))

@app.route('/api/scanner/dns', methods=['POST'])
def tool_dns():
    target = request.json.get('target')
    return jsonify(dns_service.scan(target))

@app.route('/api/scanner/headers', methods=['POST'])
def tool_headers():
    target = request.json.get('target')
    return jsonify(header_service.analyze(target))

@app.route('/api/scanner/ssl', methods=['POST'])
def tool_ssl():
    target = request.json.get('target')
    return jsonify(ssl_service.inspect(target))

@app.route('/api/scanner/tech', methods=['POST'])
def tool_tech():
    target = request.json.get('target')
    return jsonify(tech_service.detect(target))

@app.route('/api/threat-groups', methods=['GET'])
def get_threat_groups():
    query = request.args.get('q')
    country = request.args.get('country')
    category = request.args.get('category')
    return jsonify(threat_service.get_groups(query, country, category))

@app.route('/api/intel/feed', methods=['GET'])
def get_intel_feed():
    limit = int(request.args.get('limit', 50))
    type_filter = request.args.get('type')
    return jsonify(intel_service.get_feed(limit, type_filter))

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled Exception: {e}", exc_info=True)
    return jsonify({"error": str(e)}), 500

# --- Wall Service (Exploits & Tools) ---
@app.route('/api/wall/evade', methods=['POST'])
def wall_evade():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    result = wall_service.obfuscate_payload(file)
    if "error" in result:
        return jsonify(result), 500
        
    # Return as downloadable file
    return send_file(
        io.BytesIO(result['content']),
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=result['filename']
    )

@app.route('/api/wall/phish', methods=['POST'])
def wall_phish():
    data = request.json
    result = wall_service.generate_phish_template(
        data.get('target'),
        data.get('platform'),
        data.get('scenario'),
        data.get('link')
    )
    if "error" in result:
        return jsonify(result), 500
        
    return send_file(
        io.BytesIO(result['content'].encode()),
        mimetype='text/html',
        as_attachment=True,
        download_name=result['filename']
    )

@app.route('/api/wall/phish/options', methods=['GET'])
def wall_phish_options():
    return jsonify(wall_service.get_phish_options())

@app.route('/api/wall/proxies', methods=['GET'])
def wall_proxies():
    proxies = wall_service.scrape_proxies()
    return jsonify(proxies)

@app.route('/api/wall/vpn', methods=['GET'])
def wall_vpn():
    country = request.args.get('country')
    configs = wall_service.fetch_vpn_configs(country)
    return jsonify(configs)

# --- Live Map Endpoints ---
from live_feed_service import LiveFeedService
live_service = LiveFeedService()

@app.route('/api/live/map', methods=['GET'])
def live_map():
    return jsonify(live_service.get_live_attacks())

@app.route('/api/live/tools', methods=['GET'])
def live_tools():
    return jsonify(live_service.get_top_tools())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
