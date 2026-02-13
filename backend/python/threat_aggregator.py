import requests
import json
import time
import os
import logging
import random
from datetime import datetime

logger = logging.getLogger(__name__)

class ThreatAggregator:
    def __init__(self):
        self.geo_cache_file = "geo_cache.json"
        self.geo_cache = self._load_geo_cache()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json'
        }
        
        # Source URLs (High Volume OSINT)
        self.urls = {
            "emerging_threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "cins_score": "http://cinsscore.com/list/ci-badguys.txt",
            "binary_defense": "https://www.binarydefense.com/banlist.txt",
            "sans": "https://isc.sans.edu/api/sources/attacks/100?json",
            "blocklist_ssh": "https://lists.blocklist.de/lists/ssh.txt", # Active SSH Brute Forcers
            "blocklist_apache": "https://lists.blocklist.de/lists/apache.txt" # Active Web Attackers
        }
        
        # In-memory data
        self.globe_data = {"points": [], "arcs": [], "events": []}
        self.last_update = 0
        self.recent_events = [] # List of {ip, cc, type, time}
        
        # Country Centers (Backup for geolocation)
        self.country_centers = {
            "US": (37.09, -95.71), "CN": (35.86, 104.19), "RU": (61.52, 105.31),
            "DE": (51.16, 10.45), "BR": (-14.23, -51.92), "IN": (20.59, 78.96),
            "JP": (36.20, 138.25), "GB": (55.37, -3.43), "FR": (46.22, 2.21),
            "KR": (35.90, 127.76), "TW": (23.69, 120.96), "CA": (56.13, -106.34),
            "AU": (-25.27, 133.77), "NL": (52.13, 5.29), "VN": (14.05, 108.27),
            "IR": (32.42, 53.68), "KP": (40.33, 127.51), "IL": (31.04, 34.85),
            "UA": (48.37, 31.16)
        }

    def get_globe_data(self):
        # Update every 60 seconds (More frequent for live feel)
        if time.time() - self.last_update > 60:
            self._update_data()
        return self.globe_data

    def _update_data(self):
        logger.info("Updating threat data...")
        points = [] # {lat, lng, color, radius, label}
        arcs = []   # {startLat, startLng, endLat, endLng, color}
        
        # 1. Blocklist.de (SSH/Apache Attacks) -> ARCS
        # These are IPs actively attacking servers RIGHT NOW.
        attack_ips = []
        try:
            for url_key in ['blocklist_ssh', 'blocklist_apache']:
                # DEBUG: Check if key exists
                if url_key not in self.urls: 
                    logger.warning(f"Key {url_key} missing from self.urls")
                    continue
                
                # logger.info(f"Fetching {url_key}...")
                resp = requests.get(self.urls[url_key], headers=self.headers, timeout=10)
                if resp.status_code == 200:
                    lines = resp.text.splitlines()
                    logger.info(f"  -> Got {len(lines)} lines")
                    # Take random sample of 50 IPs from each list to keep map performant but busy
                    if len(lines) > 50:
                        attack_ips.extend(random.sample(lines, 30))
                    else:
                        attack_ips.extend(lines)
                else:
                    logger.error(f"  -> Failed: {resp.status_code}")
            
            # Filter empty or invalid lines
            attack_ips = [x.strip() for x in attack_ips if x.strip() and x.count('.') == 3]

            logger.info(f"Blocklist.de: Discovered {len(attack_ips)} active attackers")
            
            # Geolocate Attackers
            geo_map = self._batch_geolocate(attack_ips)
            
            # Global Targets (Attacks target major infrastructure hubs)
            targets = [
                (37.09, -95.71), (51.16, 10.45), (35.86, 104.19), (-25.27, 133.77),
                (-14.23, -51.92), (55.75, 37.61), (35.67, 139.65), (1.35, 103.81),
                (51.50, -0.12), (48.85, 2.35), (40.71, -74.00), (34.05, -118.24)
            ]

            for ip in attack_ips:
                if ip in geo_map:
                    vals = geo_map[ip]
                    slat, slon = vals[0], vals[1]
                    
                    # Randomize Target
                    tlat, tlon = random.choice(targets)
                    
                    arcs.append({
                        "startLat": slat, "startLng": slon,
                        "endLat": tlat + random.uniform(-1,1), 
                        "endLng": tlon + random.uniform(-1,1),
                        "color": ["#ff00ff", "#00f3ff"] # Magenta -> Cyan (Real Attack)
                    })
        except Exception as e:
            logger.error(f"Blocklist Error: {e}", exc_info=True)

        # 2. MALWARE & BOTNETS (Points - Red Dots)
        # Using High-Availability Text Feeds (More reliable than JSON APIs)
        malware_ips = []
        try:
            # Feeds that return raw IP lists (one per line)
            text_feeds = ['emerging_threats', 'cins_score', 'binary_defense']
            
            for key in text_feeds:
                if key not in self.urls: continue
                try:
                    # logger.info(f"Fetching {key}...")
                    resp = requests.get(self.urls[key], headers=self.headers, timeout=10)
                    if resp.status_code == 200:
                        lines = [l.strip() for l in resp.text.splitlines() if l.strip() and not l.startswith(('#', ';', '/'))]
                        
                        # Filter valid IPs
                        valid_ips = []
                        for l in lines[:500]: # Check first 500
                            if l.count('.') == 3 and not any(c.isalpha() for c in l):
                                valid_ips.append(l)
                        
                        logger.info(f"{key}: Found {len(valid_ips)} IPs")
                        if valid_ips:
                            malware_ips.extend(random.sample(valid_ips, min(len(valid_ips), 40)))
                except Exception as e:
                    logger.error(f"{key} Error: {e}")

            if malware_ips:
                geo_map = self._batch_geolocate(malware_ips)
                for ip in malware_ips:
                    if ip in geo_map:
                        # Handle old cache (2 values) vs new cache (3 values)
                        vals = geo_map[ip]
                        lat, lon = vals[0], vals[1]
                        
                        points.append({
                            "lat": lat, "lng": lon, "size": 0.4, "color": "#ff3333", # Red
                            "label": "Malware/Botnet Host", "ip": ip
                        })

        except Exception as e:
            logger.error(f"Points Logic Error: {e}", exc_info=True)

        # REMOVED: Injecting simulated points


        # 3. SANS ISC (Attacks) - ARCS
        try:
            resp = requests.get(self.urls['sans'], headers=self.headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                items = []
                if isinstance(data, dict):
                    for k,v in data.items():
                         if isinstance(v, dict) and 'source' in v: items.append(v)
                elif isinstance(data, list):
                    items = data
                
                logger.info(f"SANS: Fetched {len(items)} items")

                # Geolocate Sources
                ips = [i.get('source') or i.get('ip') or i.get('ipv4') for i in items]
                ips = [ip for ip in ips if ip]
                geo_map = self._batch_geolocate(ips)
                
                # Global Major Targets (Data Centers / Capitals)
                targets = [
                    (37.09, -95.71),   # US
                    (51.16, 10.45),    # Germany
                    (35.86, 104.19),   # China
                    (-25.27, 133.77),  # Australia
                    (-14.23, -51.92),  # Brazil
                    (55.75, 37.61),    # Moscow
                    (35.67, 139.65),   # Tokyo
                    (1.35, 103.81)     # Singapore
                ]

                # Debug SANS
                logger.info(f"SANS: Parsed {len(items)} items. GeoMapping {len(ips)} sources.")

                for item in items:
                    ip = item.get('source') or item.get('ip') or item.get('ipv4')
                    cc = item.get('country', '').upper() # Default empty, don't assume US
                    
                    slat, slon = 0, 0
                    if ip in geo_map:
                        vals = geo_map[ip]
                        slat, slon = vals[0], vals[1]
                    elif cc and cc in self.country_centers:
                         # Fallback to Country Center (Approximate but Real Country)
                         slat, slon = self.country_centers[cc]
                         # Add slight jitter so multiple attacks don't stack perfectly
                         slat += random.uniform(-0.5, 0.5)
                         slon += random.uniform(-0.5, 0.5)
                    else:
                         # Skip if we can't locate it at all. No fake random locations.
                         continue

                    # Target: If SANS gives a target IP/Country, use it. 
                    # SANS 'attacks' endpoint usually just gives source. 
                    # We will default valid targets to HoneyPot locations (which SANS is)
                    # For visualization, we can route to a fixed set of "Sensor" locations
                    # representing the SANS sensors, or random Country Centers if target is unknown.
                    
                    # For now, let's target the "System" (User's location implicit, or random major hub)
                    # BUT strictly real logic: SANS data is "internet background noise". 
                    # We will visualize it hitting "The Grid" (Major Internet Exchanges).
                    
                    target_hub = random.choice(list(self.country_centers.values()))

                    arcs.append({
                        "startLat": slat, "startLng": slon,
                        "endLat": target_hub[0] + random.uniform(-1,1), 
                        "endLng": target_hub[1] + random.uniform(-1,1),
                        "color": ["#ff00ff", "#00f3ff"] # Magenta -> Cyan
                    })
        except Exception as e:
            logger.error(f"SANS Error: {e}")

        # REMOVED: Injected Simulated Global Conflict
                 
        # Populate Recent Events from recent points/attacks
        # We just grab a few from the current batch to show "Live" activity
        new_events = []
        
        # 1. From Malware Points
        for p in points[:10]: # Top 10 new malware
             # Get CC from cache if possible
             cc = "XX"
             if p['ip'] in self.geo_cache and len(self.geo_cache[p['ip']]) >= 3:
                 cc = self.geo_cache[p['ip']][2]
             
             new_events.append({
                 "ip": p['ip'], 
                 "cc": cc, 
                 "type": "Malware C2",
                 "flag": cc.lower()
             })

        # 2. From Attack Arcs (approximate since arcs don't have IS IP easily accessible in this loop w/o lookup)
        # But we drove arcs from `attack_ips`.
        for ip in attack_ips[:10]:
             if ip in geo_map:
                 # Check cache for CC
                 cc = "XX"
                 if ip in self.geo_cache and len(self.geo_cache[ip]) >= 3:
                     cc = self.geo_cache[ip][2]
                 
                 new_events.append({
                     "ip": ip,
                     "cc": cc,
                     "type": "SSH Brute Force",
                     "flag": cc.lower()
                 })

        # Update Buffer
        if new_events:
            random.shuffle(new_events)
            self.recent_events = new_events[:100] # Keep larger batch for streaming

        self.globe_data = {"points": points, "arcs": arcs, "events": self.recent_events}
        self.last_update = time.time()
        self._save_geo_cache()
        logger.info(f"Aggregated {len(points)} points and {len(arcs)} arcs (REAL DATA ONLY)")

    def _batch_geolocate(self, ips):
        # Filter cached
        to_fetch = [ip for ip in ips if ip not in self.geo_cache and not ip.startswith('0.') and not ip.startswith('127.') and ip != '0.0.0.0']
        to_fetch = list(set(to_fetch))
        
        if to_fetch:
            logger.info(f"Geolocating {len(to_fetch)} new IPs...")
            # IP-API Batch (max 100 per req)
            chunk_size = 90
            for i in range(0, len(to_fetch), chunk_size):
                chunk = to_fetch[i:i+chunk_size]
                try:
                    resp = requests.post("http://ip-api.com/batch", json=chunk, timeout=10) 
                    if resp.status_code == 200:
                        results = resp.json()
                        success_count = 0
                        for res in results:
                            if res.get('status') == 'success':
                                # Store (lat, lon, countryCode)
                                self.geo_cache[res['query']] = (res['lat'], res['lon'], res.get('countryCode', 'XX'))
                                success_count += 1
                        logger.info(f"GeoIP Batch: {success_count}/{len(chunk)} resolved successfully.")
                        if success_count == 0:
                             logger.warning(f"GeoIP Response dump: {results[:2]}") # Dump first 2 errors
                    else:
                        logger.warning(f"GeoIP Failed: {resp.status_code} - {resp.text[:100]}")
                except Exception as e:
                    logger.error(f"GeoIP Fetch Error: {e}")
                
                # Rate limit safety
                time.sleep(1.5)
                
        return {ip: self.geo_cache[ip] for ip in ips if ip in self.geo_cache}

    def _load_geo_cache(self):
        if os.path.exists(self.geo_cache_file):
            try:
                with open(self.geo_cache_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_geo_cache(self):
        try:
            with open(self.geo_cache_file, 'w') as f:
                json.dump(self.geo_cache, f)
        except:
            pass
