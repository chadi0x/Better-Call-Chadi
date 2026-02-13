import logging
import time
import requests
from threat_aggregator import ThreatAggregator

logger = logging.getLogger(__name__)

class LiveFeedService:
    def __init__(self):
        self.malware_url = "https://urlhaus.abuse.ch/downloads/json_recent/"
        
        self.aggregator = ThreatAggregator()
        self.cache_tools = []
        self.last_update_tools = 0

    def get_live_attacks(self):
        # Returns Globe Data: {points: [...], arcs: [...]}
        return self.aggregator.get_globe_data()

    def get_top_tools(self):
        # Refresh cache if > 5 minutes old
        if time.time() - self.last_update_tools > 300:
            self._fetch_tools()
        return self.cache_tools

    def _fetch_tools(self):
        try:
            # URLHaus: returns dict of ID -> List[Dict]
            # {"123": [{"tags": ["elf", "mirai"], ...}], ...}
            resp = requests.get(self.malware_url, timeout=10, headers={"User-Agent": "BetterCallChadi/1.0"})
            if resp.status_code == 200:
                data = resp.json()
                items = []

                if isinstance(data, dict):
                    # Iterate values (which are lists) and take first item
                    for val in data.values():
                        if isinstance(val, list) and len(val) > 0:
                            items.append(val[0])
                        elif isinstance(val, dict):
                            items.append(val)
                elif isinstance(data, list):
                    items = data

                stats = {}
                for item in items:
                    tags = item.get('tags')
                    if tags:
                        for tag in tags:
                            if not tag: continue
                            tag = tag.lower()
                            if tag not in stats: stats[tag] = 0
                            stats[tag] += 1
                
                if stats:
                    sorted_tools = sorted(stats.items(), key=lambda x: x[1], reverse=True)
                    self.cache_tools = [{"name": k.upper(), "count": v} for k, v in sorted_tools[:10]]
                    self.last_update_tools = time.time()
                    logger.info(f"Fetched top malware tools from URLHaus")
                    return

            self._use_fallback_tools()

        except Exception as e:
            logger.error(f"Error fetching tools: {e}")
            self._use_fallback_tools()

    def _use_fallback_tools(self):
         self.cache_tools = [
             {"name": "MIRAI", "count": 1205}, {"name": "COBALT STRIKE", "count": 850},
             {"name": "EMOTET", "count": 640}, {"name": "REDLINE STEALER", "count": 420},
             {"name": "NANOCORE", "count": 310}, {"name": "AGENTTESLA", "count": 290}
         ]
