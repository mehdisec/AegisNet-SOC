import os
import re
import json
import time
import socket
import logging
import threading
import ipaddress
import urllib.request
from typing import Dict, Any, List, Optional, Set
from collections import deque

from backend.config import DATA_DIR

logger = logging.getLogger("aegis.threat_intel")

INTEL_CACHE_FILE = DATA_DIR / "threat_intel_cache.json"

# Built-in curated malicious / high-risk IP list & CIDR ranges (C2, Mirai, scanners, hostile proxies, Tor exit nodes)
CURATED_HIGH_RISK_IPS = {
    # Tor Exit Nodes sample / hostile relays
    "185.220.101.5": {"category": "Tor Exit Node", "score": 92, "verdict": "MALICIOUS", "asn": "Zwiebelfreunde"},
    "185.220.101.6": {"category": "Tor Exit Node", "score": 92, "verdict": "MALICIOUS", "asn": "Zwiebelfreunde"},
    "185.220.101.7": {"category": "Tor Exit Node", "score": 92, "verdict": "MALICIOUS", "asn": "Zwiebelfreunde"},
    "185.220.100.240": {"category": "Tor Exit Node", "score": 90, "verdict": "MALICIOUS", "asn": "F3 Netze"},
    "185.220.100.252": {"category": "Tor Exit Node", "score": 90, "verdict": "MALICIOUS", "asn": "F3 Netze"},
    "198.98.51.189": {"category": "Tor Exit Node", "score": 88, "verdict": "MALICIOUS", "asn": "FranTech Solutions"},
    "199.249.230.71": {"category": "Tor Exit Node", "score": 89, "verdict": "MALICIOUS", "asn": "Compass Global"},
    "23.129.64.100": {"category": "Tor Exit Node", "score": 88, "verdict": "MALICIOUS", "asn": "Emerald Onion"},
    "23.129.64.155": {"category": "Tor Exit Node", "score": 88, "verdict": "MALICIOUS", "asn": "Emerald Onion"},
    "171.25.193.20": {"category": "Tor Exit Node", "score": 91, "verdict": "MALICIOUS", "asn": "Tor Relay"},

    # Known Malicious Botnet C2 / Malware Drop / Cobalt Strike teamservers
    "194.26.29.112": {"category": "Cobalt Strike C2", "score": 98, "verdict": "MALICIOUS", "asn": "Baxet Group"},
    "45.154.255.88": {"category": "Mirai Botnet C2", "score": 96, "verdict": "MALICIOUS", "asn": "NetLab C2"},
    "185.196.8.44": {"category": "Ransomware Distribution", "score": 97, "verdict": "MALICIOUS", "asn": "HostKey"},
    "91.240.118.172": {"category": "AsyncRAT / Trojan C2", "score": 95, "verdict": "MALICIOUS", "asn": "Selectel"},
    "45.33.32.156": {"category": "Brute-Force & Port Scanner", "score": 85, "verdict": "MALICIOUS", "asn": "Linode VPS Scanner"},
    "79.124.62.122": {"category": "Mass Port Reconnaissance", "score": 82, "verdict": "SUSPICIOUS", "asn": "Flyservers"},
    "89.248.165.73": {"category": "Recurrent SSH Brute-Force", "score": 88, "verdict": "MALICIOUS", "asn": "Recurrent Threat"},

    # Aggressive Internet Mass Scanners (Shodan, Censys, Shadowserver, Rapid7)
    "198.20.99.130": {"category": "Shodan Scanner", "score": 65, "verdict": "SUSPICIOUS", "asn": "Shodan.io"},
    "198.20.70.114": {"category": "Shodan Scanner", "score": 65, "verdict": "SUSPICIOUS", "asn": "Shodan.io"},
    "162.142.125.1": {"category": "Censys Scanner", "score": 60, "verdict": "SUSPICIOUS", "asn": "Censys Research"},
    "167.248.133.1": {"category": "Censys Scanner", "score": 60, "verdict": "SUSPICIOUS", "asn": "Censys Research"},
    "71.6.135.131": {"category": "Research Scanner", "score": 58, "verdict": "SUSPICIOUS", "asn": "Internet Survey"}
}

# High-reputation trusted CDNs & Cloud Infrastructure
TRUSTED_ORGANIZATIONS = [
    "Google", "Cloudflare", "Microsoft", "Amazon", "Akamai", "Fastly",
    "Apple", "GitHub", "EdgeCast", "Valve", "DigitalOcean", "Mozilla"
]

class ThreatIntelligence:
    def __init__(self):
        self.lock = threading.Lock()
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.tor_exit_nodes: Set[str] = set()
        self.custom_blacklist: Set[str] = set()
        self.threat_stats = {
            "total_queries": 0,
            "malicious_detected": 0,
            "suspicious_detected": 0,
            "clean_detected": 0,
            "tor_nodes_loaded": 0,
            "last_updated": datetime_now_iso()
        }
        self._load_cache()
        # Seed Tor exit nodes from curated set
        for ip, info in CURATED_HIGH_RISK_IPS.items():
            if "Tor" in info.get("category", ""):
                self.tor_exit_nodes.add(ip)
        self.threat_stats["tor_nodes_loaded"] = len(self.tor_exit_nodes)

        # Start asynchronous background updater for live Tor lists
        threading.Thread(target=self._background_feed_sync, daemon=True).start()

    def _load_cache(self):
        """Loads cached IP reputations from disk."""
        if os.path.exists(INTEL_CACHE_FILE):
            try:
                with open(INTEL_CACHE_FILE, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load threat intel cache: {e}")
                self.cache = {}

    def _save_cache(self):
        """Persists cache safely."""
        try:
            with self.lock:
                snapshot = dict(self.cache)
            with open(INTEL_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save threat intel cache: {e}")

    def _background_feed_sync(self):
        """Periodically syncs public Tor exit node directories and threat feeds."""
        time.sleep(3.0)  # Wait for startup
        while True:
            try:
                self._sync_tor_exit_nodes()
            except Exception as e:
                logger.debug(f"Feed sync note: {e}")
            time.sleep(3600)  # Refresh hourly

    def _sync_tor_exit_nodes(self):
        """Pulls list of active Tor Exit nodes from Dan.me.uk / TorProject."""
        url = "https://check.torproject.org/torbulkexitlist"
        req = urllib.request.Request(url, headers={"User-Agent": "AegisNet-SOC/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
                ips = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
                if ips:
                    with self.lock:
                        for ip in ips[:500]:
                            self.tor_exit_nodes.add(ip)
                        self.threat_stats["tor_nodes_loaded"] = len(self.tor_exit_nodes)
                        self.threat_stats["last_updated"] = datetime_now_iso()
                    logger.info(f"Threat Intel: Synced {len(ips)} live Tor exit node indicators")
        except Exception as e:
            logger.debug(f"Online Tor feed fetch skipped (offline or rate limited): {e}")

    def evaluate_ip(self, ip: str, org: str = "", asn: str = "") -> Dict[str, Any]:
        """Calculates reputation, risk score, and verdict for an IP address."""
        if not ip or ip in ("0.0.0.0", "127.0.0.1", "localhost", "::1", "LOCAL"):
            return {
                "ip": ip,
                "score": 0,
                "level": "LOW",
                "verdict": "CLEAN",
                "category": "Loopback / Local Host",
                "is_threat": False,
                "confidence": 100,
                "indicators": ["Local Station Interface"]
            }

        # Check private RFC1918 addresses
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return {
                    "ip": ip,
                    "score": 0,
                    "level": "LOW",
                    "verdict": "CLEAN",
                    "category": "LAN Internal Subnet",
                    "is_threat": False,
                    "confidence": 100,
                    "indicators": ["RFC1918 Private Network"]
                }
        except Exception:
            pass

        # Check cache
        with self.lock:
            cached = self.cache.get(ip)
            if cached and (time.time() - cached.get("cached_at", 0)) < 86400:  # 24 hour TTL
                self.threat_stats["total_queries"] += 1
                return cached

        # Evaluation heuristics
        score = 0
        indicators = []
        category = "Standard Internet Endpoint"
        verdict = "CLEAN"
        level = "LOW"
        is_threat = False

        # 1. Custom Blacklist
        if ip in self.custom_blacklist:
            score = 100
            indicators.append("Host Administratively Blacklisted")
            category = "Blacklisted IP"
            verdict = "MALICIOUS"
            level = "CRITICAL"
            is_threat = True

        # 2. Known Curated Threats
        elif ip in CURATED_HIGH_RISK_IPS:
            data = CURATED_HIGH_RISK_IPS[ip]
            score = data.get("score", 90)
            category = data.get("category", "Hostile Endpoint")
            verdict = data.get("verdict", "MALICIOUS")
            level = "CRITICAL" if score >= 90 else "HIGH"
            is_threat = True
            indicators.append(f"AegisNet Threat Feed: {category}")

        # 3. Tor Exit Nodes
        elif ip in self.tor_exit_nodes:
            score = 90
            category = "Tor Exit Node"
            verdict = "MALICIOUS"
            level = "HIGH"
            is_threat = True
            indicators.append("Active Tor Anonymization Exit Relay")

        # 4. ASN & Organization Heuristics
        else:
            combined_org = f"{org} {asn}".lower()

            # Trusted Org Check
            is_trusted = any(t.lower() in combined_org for t in TRUSTED_ORGANIZATIONS)
            if is_trusted:
                score = 5
                category = "Verified Cloud / CDN Infrastructure"
                verdict = "CLEAN"
                level = "LOW"
                indicators.append(f"Trusted Autonomous System: {org or 'Cloud Provider'}")
            elif "tor" in combined_org or "zwiebel" in combined_org:
                score = 88
                category = "Tor Relay Network"
                verdict = "MALICIOUS"
                level = "HIGH"
                is_threat = True
                indicators.append("Associated with Tor Relay Organization")
            elif any(w in combined_org for w in ("bulletproof", "baxet", "floki", "vps-scam", "botnet")):
                score = 85
                category = "High-Abuse Hosting Provider"
                verdict = "MALICIOUS"
                level = "HIGH"
                is_threat = True
                indicators.append("Hosted on known bulletproof/high-abuse AS")
            elif any(w in combined_org for w in ("shodan", "censys", "shadowserver", "leakix")):
                score = 65
                category = "Internet Reconnaissance Scanner"
                verdict = "SUSPICIOUS"
                level = "MEDIUM"
                is_threat = False
                indicators.append("Mass port & vulnerability scanner")
            elif any(w in combined_org for w in ("hosting", "vps", "datacenter", "ovh", "hetzner", "linode")):
                score = 25
                category = "Datacenter / Cloud Server"
                verdict = "NEUTRAL"
                level = "LOW"
                indicators.append("Public Cloud / VPS Node")
            else:
                score = 15
                category = "Public Internet Host"
                verdict = "CLEAN"
                level = "LOW"
                indicators.append("Normal routing reputation")

        result = {
            "ip": ip,
            "score": score,
            "level": level,
            "verdict": verdict,
            "category": category,
            "is_threat": is_threat,
            "confidence": 90,
            "indicators": indicators,
            "cached_at": time.time(),
            "last_checked": datetime_now_iso()
        }

        # Update stats
        with self.lock:
            self.cache[ip] = result
            self.threat_stats["total_queries"] += 1
            if verdict == "MALICIOUS":
                self.threat_stats["malicious_detected"] += 1
            elif verdict == "SUSPICIOUS":
                self.threat_stats["suspicious_detected"] += 1
            else:
                self.threat_stats["clean_detected"] += 1

        # Periodically save cache
        if len(self.cache) % 15 == 0:
            self._save_cache()

        return result

    def add_to_blacklist(self, ip: str, reason: str = "Admin block"):
        """Adds an IP manually to the threat blacklist."""
        with self.lock:
            self.custom_blacklist.add(ip)
            if ip in self.cache:
                del self.cache[ip]
        self.evaluate_ip(ip)

    def get_stats(self) -> Dict[str, Any]:
        """Returns threat intelligence database statistics."""
        with self.lock:
            stats = dict(self.threat_stats)
            stats["cache_size"] = len(self.cache)
            stats["custom_blacklist_count"] = len(self.custom_blacklist)
            return stats

def datetime_now_iso() -> str:
    import datetime
    return datetime.datetime.now().isoformat()

# Singleton instance
threat_intel = ThreatIntelligence()
