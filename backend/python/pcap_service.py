import logging
import os
from scapy.all import PcapReader, IP, TCP, UDP, DNS, DNSQR, load_layer

# Try to load HTTP layer
try:
    load_layer("http")
    from scapy.layers.http import HTTP
except ImportError:
    from scapy.all import HTTP
except Exception as e:
    # Fallback if HTTP layer fails (rudimentary check will be used)
    HTTP = None

from collections import Counter

logger = logging.getLogger(__name__)

class PcapService:
    def __init__(self, upload_folder='/tmp'):
        self.upload_folder = upload_folder
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

    def analyze_pcap(self, file):
        filename = file.filename
        filepath = os.path.join(self.upload_folder, filename)
        file.save(filepath)
        
        try:
            stats = {
                "packet_count": 0,
                "protocols": Counter(),
                "top_talkers": Counter(),
                "conversations": {}, # (src, dst, proto) -> count
                "dns_queries": set(),
                "user_agents": set(),
                "http_requests": [], # {method, host, uri}
                "tls_sni": set(),
                "files_detected": [], # {type, src, dst}
                "suspicious": []
            }

            # Magic Bytes for file detection
            FILE_SIGNATURES = {
                b'MZ': 'Windows EXE',
                b'%PDF': 'PDF Document',
                b'\x7fELF': 'Linux ELF',
                b'PK\x03\x04': 'ZIP Archive'
            }

            # Use PcapReader for streaming to avoid OOM
            with PcapReader(filepath) as pcap_reader:
                for pkt in pcap_reader:
                    stats["packet_count"] += 1
                    
                    if IP in pkt:
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        proto = pkt[IP].proto
                        stats["top_talkers"][src] += 1
                        
                        # Conversation Tracking
                        conv_key = f"{src} -> {dst}"
                        if conv_key not in stats["conversations"]:
                            stats["conversations"][conv_key] = {"count": 0, "proto": proto}
                        stats["conversations"][conv_key]["count"] += 1

                        # Protocol Stats & Suspicious Ports
                        if TCP in pkt:
                            stats["protocols"]['TCP'] += 1
                            dport = pkt[TCP].dport
                            payload = bytes(pkt[TCP].payload)

                            # Suspicious Ports
                            if dport in [4444, 1337, 6667]:
                                stats["suspicious"].append(f"Suspicious traffic on port {dport} from {src}")

                            # File Signature Detection in Payload
                            if payload:
                                for sig, name in FILE_SIGNATURES.items():
                                    if payload.startswith(sig):
                                        stats["files_detected"].append({"type": name, "src": src, "dst": dst})
                            
                            # TLS SNI Extraction (simplified)
                            if dport == 443 and len(payload) > 5:
                                try:
                                    # Very basic TLS Client Hello check
                                    if payload[0] == 0x16 and payload[5] == 0x01:
                                        # Skip to SessionID length
                                        pos = 43 
                                        sess_id_len = payload[pos]
                                        pos += 1 + sess_id_len
                                        # Cipher Suites length
                                        cs_len = int.from_bytes(payload[pos:pos+2], 'big')
                                        pos += 2 + cs_len
                                        # Compression methods length
                                        cm_len = payload[pos]
                                        pos += 1 + cm_len
                                        # Extensions length
                                        ext_len = int.from_bytes(payload[pos:pos+2], 'big')
                                        pos += 2
                                        
                                        end = pos + ext_len
                                        while pos < end:
                                            ext_type = int.from_bytes(payload[pos:pos+2], 'big')
                                            ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
                                            pos += 4
                                            if ext_type == 0: # SNI
                                                list_len = int.from_bytes(payload[pos:pos+2], 'big')
                                                name_type = payload[pos+2]
                                                name_len = int.from_bytes(payload[pos+3:pos+5], 'big')
                                                sni = payload[pos+5:pos+5+name_len].decode('utf-8')
                                                stats["tls_sni"].add(sni)
                                                break
                                            pos += ext_len
                                except:
                                    pass

                        elif UDP in pkt:
                            stats["protocols"]['UDP'] += 1

                    # DNS Extraction
                    if DNS in pkt and pkt.haslayer(DNSQR):
                        try:
                            qname = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                            stats["dns_queries"].add(qname)
                        except:
                            pass

                    # HTTP Analysis
                    if HTTP and pkt.haslayer(HTTP):
                        stats["protocols"]['HTTP'] += 1
                        try:
                            if pkt.haslayer('HTTPRequest'):
                                req = pkt['HTTPRequest']
                                method = req.Method.decode() if req.Method else "?"
                                host = req.Host.decode() if req.Host else "?"
                                uri = req.Path.decode() if req.Path else "?"
                                ua = req.User_Agent.decode() if req.User_Agent else None

                                stats["http_requests"].append({
                                    "method": method,
                                    "host": host,
                                    "uri": uri
                                })
                                
                                if ua:
                                    stats["user_agents"].add(ua)
                                    
                                # Cleartext Creds Check (Basic Auth)
                                if req.Authorization and b"Basic" in req.Authorization:
                                    stats["suspicious"].append(f"Cleartext Basic Auth to {host}")

                        except:
                            pass

            # Format Conversations
            sorted_convs = sorted(stats["conversations"].items(), key=lambda x: x[1]['count'], reverse=True)[:10]
            formatted_convs = [{"pair": k, "proto": v["proto"], "count": v["count"]} for k,v in sorted_convs]

            return {
                "filename": filename,
                "packet_count": stats["packet_count"],
                "protocols": dict(stats["protocols"]),
                "top_talkers": stats["top_talkers"].most_common(5),
                "conversations": formatted_convs,
                "dns_queries": list(stats["dns_queries"])[:20],
                "user_agents": list(stats["user_agents"]),
                "http_requests": stats["http_requests"][:10], # Limit
                "tls_sni": list(stats["tls_sni"])[:10],
                "files_detected": stats["files_detected"][:5],
                "suspicious": list(set(stats["suspicious"]))
            }
            
        except Exception as e:
            logger.error(f"PCAP Analysis failed: {e}")
            return {"error": str(e)}
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)
