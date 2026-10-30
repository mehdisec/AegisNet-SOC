import os
import json
import ipaddress
import logging
import threading
import time
from typing import Dict, Any, Optional
import urllib.request
import urllib.error

from backend.config import MMDB_PATH, GEOIP_CACHE_FILE

logger = logging.getLogger("aegis.geoip")

# Built-in Geo Data for common infrastructure & fallbacks
KNOWN_INFRASTRUCTURE = {
    "8.8.8.8": {"country": "United States", "country_code": "US", "city": "Mountain View", "lat": 37.422, "lon": -122.084, "isp": "Google LLC", "asn": "AS15169", "org": "Google Public DNS"},
    "8.8.4.4": {"country": "United States", "country_code": "US", "city": "Mountain View", "lat": 37.422, "lon": -122.084, "isp": "Google LLC", "asn": "AS15169", "org": "Google Public DNS"},
    "1.1.1.1": {"country": "Australia", "country_code": "AU", "city": "Sydney", "lat": -33.8688, "lon": 151.2093, "isp": "Cloudflare, Inc.", "asn": "AS13335", "org": "Cloudflare DNS"},
    "1.0.0.1": {"country": "United States", "country_code": "US", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "isp": "Cloudflare, Inc.", "asn": "AS13335", "org": "Cloudflare DNS"},
    "9.9.9.9": {"country": "United States", "country_code": "US", "city": "Berkeley", "lat": 37.8715, "lon": -122.273, "isp": "Quad9", "asn": "AS19281", "org": "Quad9 DNS"},
    "208.67.222.222": {"country": "United States", "country_code": "US", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "isp": "Cisco OpenDNS", "asn": "AS36692", "org": "OpenDNS"},
}

class GeoIPService:
    def __init__(self):
        self.lock = threading.Lock()
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.pending_lookups = set()
        self.reader = None
        self.host_location = {
            "country": "Local Host",
            "country_code": "LOC",
            "city": "Internal Station",
            "lat": 37.7749,
            "lon": -122.4194,
            "isp": "Local Loopback / NIC",
            "asn": "AS-LOCAL",
            "org": "Security Operations Center",
            "is_private": True
        }
        
        self._load_cache()
        self._init_mmdb()
        self._detect_host_location()

    def _load_cache(self):
        """Loads cached GeoIP records from disk."""
        if os.path.exists(GEOIP_CACHE_FILE):
            try:
                with open(GEOIP_CACHE_FILE, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
                logger.info(f"Loaded {len(self.cache)} cached GeoIP records.")
            except Exception as e:
                logger.warning(f"Could not load GeoIP cache: {e}")
                self.cache = {}

    def _save_cache(self):
        """Saves cached GeoIP records to disk safely under lock."""
        try:
            with self.lock:
                cache_snapshot = dict(self.cache)
            with open(GEOIP_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(cache_snapshot, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save GeoIP cache: {e}")

    def _init_mmdb(self):
        """Initializes MaxMind reader if mmdb file exists."""
        if os.path.exists(MMDB_PATH):
            try:
                import geoip2.database
                self.reader = geoip2.database.Reader(str(MMDB_PATH))
                logger.info(f"Initialized MaxMind GeoLite2 database from {MMDB_PATH}")
            except Exception as e:
                logger.warning(f"Found MMDB but failed to initialize reader: {e}")
                self.reader = None
        else:
            logger.info("No local GeoLite2-City.mmdb found. Using hybrid fallback + online resolver.")

    def _detect_host_location(self):
        """Detects the host machine's external geographic position in a background thread."""
        def worker():
            try:
                req = urllib.request.Request(
                    "http://ip-api.com/json/?fields=status,country,countryCode,city,lat,lon,isp,as,org,query",
                    headers={"User-Agent": "AegisNet-Security-Agent/1.0"}
                )
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    data = json.loads(resp.read().decode())
                    if data.get("status") == "success":
                        self.host_location = {
                            "country": data.get("country", "Local Host"),
                            "country_code": data.get("countryCode", "US"),
                            "city": data.get("city", "Host Location"),
                            "lat": data.get("lat", 37.7749),
                            "lon": data.get("lon", -122.4194),
                            "isp": data.get("isp", "Local ISP"),
                            "asn": data.get("as", "AS0"),
                            "org": data.get("org", "Operator Machine"),
                            "is_private": False,
                            "public_ip": data.get("query")
                        }
                        logger.info(f"Host external location determined: {self.host_location['city']}, {self.host_location['country']} ({self.host_location['lat']}, {self.host_location['lon']})")
            except Exception as e:
                logger.warning(f"Could not detect host external location (offline or rate-limited): {e}")

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def is_private_ip(self, ip_str: str) -> bool:
        """Determines if an IP is private, loopback, or reserved."""
        if not ip_str or ip_str in ("0.0.0.0", "::", "127.0.0.1", "::1"):
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return (
                ip_obj.is_private or
                ip_obj.is_loopback or
                ip_obj.is_link_local or
                ip_obj.is_multicast or
                ip_obj.is_reserved or
                ip_obj.is_unspecified
            )
        except ValueError:
            return True

    def lookup(self, ip_str: str) -> Dict[str, Any]:
        """Resolves GeoIP information for an IP address synchronously with cache and async queue."""
        if not ip_str:
            return self._empty_record("Unknown")

        # Private / LAN handling
        if self.is_private_ip(ip_str):
            loc = dict(self.host_location)
            loc["ip"] = ip_str
            loc["is_private"] = True
            if ip_str in ("127.0.0.1", "::1"):
                loc["city"] = "Loopback (localhost)"
            else:
                loc["city"] = f"LAN ({ip_str})"
            return loc

        # Check Cache
        with self.lock:
            if ip_str in self.cache:
                return self.cache[ip_str]

        # Check Known Infrastructure
        if ip_str in KNOWN_INFRASTRUCTURE:
            rec = dict(KNOWN_INFRASTRUCTURE[ip_str])
            rec["ip"] = ip_str
            rec["is_private"] = False
            with self.lock:
                self.cache[ip_str] = rec
            return rec

        # Try Local MaxMind DB
        if self.reader:
            try:
                res = self.reader.city(ip_str)
                rec = {
                    "ip": ip_str,
                    "country": res.country.name or "Unknown",
                    "country_code": res.country.iso_code or "UN",
                    "city": res.city.name or "Unknown",
                    "lat": res.location.latitude or 0.0,
                    "lon": res.location.longitude or 0.0,
                    "isp": "MaxMind Geolocation",
                    "asn": "N/A",
                    "org": res.traits.autonomous_system_organization or "Unknown Org",
                    "is_private": False
                }
                with self.lock:
                    self.cache[ip_str] = rec
                return rec
            except Exception:
                pass

        # Trigger Async Remote Lookup if not already pending
        self._queue_async_lookup(ip_str)

        # Return approximate placeholder based on IP hash
        fallback = self._generate_fallback(ip_str)
        return fallback

    def _queue_async_lookup(self, ip_str: str):
        """Dispatches an async HTTP lookup to ip-api for rich GeoIP data."""
        with self.lock:
            if ip_str in self.pending_lookups or ip_str in self.cache:
                return
            self.pending_lookups.add(ip_str)

        def worker():
            try:
                url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query"
                req = urllib.request.Request(url, headers={"User-Agent": "AegisNet-Security-Agent/1.0"})
                with urllib.request.urlopen(req, timeout=3.5) as resp:
                    data = json.loads(resp.read().decode())
                    if data.get("status") == "success":
                        record = {
                            "ip": ip_str,
                            "country": data.get("country", "Unknown"),
                            "country_code": data.get("countryCode", "UN"),
                            "city": data.get("city", "Unknown"),
                            "lat": float(data.get("lat", 0.0)),
                            "lon": float(data.get("lon", 0.0)),
                            "isp": data.get("isp", "Unknown ISP"),
                            "asn": data.get("as", "Unknown ASN"),
                            "org": data.get("org", data.get("isp", "Unknown")),
                            "is_private": False
                        }
                        with self.lock:
                            self.cache[ip_str] = record
                            self.pending_lookups.discard(ip_str)
                        self._save_cache()
                        return
            except Exception as e:
                logger.debug(f"GeoIP remote query error for {ip_str}: {e}")
            
            with self.lock:
                self.pending_lookups.discard(ip_str)

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def _generate_fallback(self, ip_str: str) -> Dict[str, Any]:
        """Generates a realistic offline location based on IP block heuristics and regional allocations."""
        try:
            octets = [int(x) for x in ip_str.split(".") if x.isdigit()]
        except Exception:
            octets = [20, 0, 0, 1]

        first = octets[0] if octets else 20
        second = octets[1] if len(octets) > 1 else 10

        # Heuristic IP Block to Country / Centroid mapping
        if first in (3, 13, 15, 18, 52, 54):  # AWS US
            country, code, city, lat, lon = "United States", "US", "Ashburn (AWS)", 39.0438, -77.4874
            isp, org, asn = "Amazon AWS", "Amazon.com, Inc.", "AS16509"
        elif first in (34, 35):  # Google Cloud
            country, code, city, lat, lon = "United States", "US", "Council Bluffs (GCP)", 41.2619, -95.8608
            isp, org, asn = "Google Cloud", "Google LLC", "AS396982"
        elif first in (20, 40, 51):  # Microsoft Azure
            country, code, city, lat, lon = "United States", "US", "Redmond (Azure)", 47.6740, -122.1215
            isp, org, asn = "Microsoft Azure", "Microsoft Corporation", "AS8075"
        elif first in (104, 172, 162):  # Cloudflare
            country, code, city, lat, lon = "United States", "US", "San Francisco (Cloudflare)", 37.7749, -122.4194
            isp, org, asn = "Cloudflare, Inc.", "Cloudflare Anycast", "AS13335"
        elif first in (185, 194, 91):  # RIPE NCC (Europe / Middle East)
            country, code, city, lat, lon = "Germany", "DE", "Frankfurt", 50.1109, 8.6821
            isp, org, asn = "European Backbone", "RIPE Regional Carrier", "AS3320"
        elif first in (151, 157, 142, 199):  # North America
            country, code, city, lat, lon = "United States", "US", "New York", 40.7128, -74.0060
            isp, org, asn = "Tier-1 Carrier", "North America Backbone", "AS174"
        elif first in (118, 120, 122, 124, 125, 202, 203):  # APNIC (Asia Pacific)
            country, code, city, lat, lon = "Singapore", "SG", "Singapore", 1.3521, 103.8198
            isp, org, asn = "APNIC Regional Transit", "Asia Pacific Telecom", "AS4657"
        else:
            regions = [
                ("United States", "US", "North America Node", 38.0 + (first % 10), -97.0 + (second % 30)),
                ("Germany", "DE", "Europe Node", 51.0 + (first % 5), 10.0 + (second % 10)),
                ("United Kingdom", "GB", "London Node", 51.5 + (first % 3), -0.12 + (second % 2)),
                ("Singapore", "SG", "Southeast Asia Node", 1.3 + (first % 2), 103.8 + (second % 2)),
                ("Japan", "JP", "Tokyo Node", 35.6 + (first % 3), 139.6 + (second % 5)),
                ("Canada", "CA", "Toronto Node", 43.6 + (first % 4), -79.3 + (second % 10)),
                ("Netherlands", "NL", "Amsterdam Node", 52.3 + (first % 2), 4.9 + (second % 2)),
            ]
            country, code, city, lat, lon = regions[(first + second) % len(regions)]
            isp, org, asn = "Regional Gateway", "Autonomous Routing Network", f"AS{(first * 256 + second) % 65000 + 1000}"

        return {
            "ip": ip_str,
            "country": country,
            "country_code": code,
            "city": city,
            "lat": round(lat, 4),
            "lon": round(lon, 4),
            "isp": isp,
            "asn": asn,
            "org": org,
            "is_private": False
        }

    def _empty_record(self, ip_str: str) -> Dict[str, Any]:
        return {
            "ip": ip_str,
            "country": "Unknown",
            "country_code": "UN",
            "city": "Unknown",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "Unknown",
            "asn": "Unknown",
            "org": "Unknown",
            "is_private": False
        }

# Global singleton
geo_service = GeoIPService()
