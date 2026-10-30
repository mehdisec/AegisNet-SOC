import time
import socket
import logging
from typing import Dict, Any, List, Optional
from collections import Counter

import psutil
from backend.geoip_service import geo_service
from backend.threat_intel import threat_intel
from backend.config import MAX_STREAM_CONNECTIONS

logger = logging.getLogger("aegis.monitor")

PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 194: "IRC",
    443: "HTTPS", 465: "SMTPS", 514: "Syslog", 587: "SMTP-Sub",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5060: "SIP",
    5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "Sonar/PHP",
    27017: "MongoDB"
}

class NetworkMonitor:
    def __init__(self):
        self.last_io_time = time.time()
        self.last_io_counters = psutil.net_io_counters()
        self.proc_cache: Dict[int, Dict[str, Any]] = {}
        self.proc_cache_time: Dict[int, float] = {}
        self.CACHE_TTL = 3.0  # seconds

    def _get_process_info(self, pid: Optional[int]) -> Dict[str, Any]:
        """Retrieves process metadata with caching for high performance."""
        if not pid or pid <= 0:
            return {
                "pid": None,
                "name": "System / Kernel",
                "exe": "System",
                "username": "SYSTEM",
                "cpu_percent": 0.0,
                "memory_percent": 0.0
            }

        now = time.time()
        if pid in self.proc_cache and (now - self.proc_cache_time.get(pid, 0)) < self.CACHE_TTL:
            return self.proc_cache[pid]

        try:
            p = psutil.Process(pid)
            info = {
                "pid": pid,
                "name": p.name(),
                "exe": p.exe() if hasattr(p, "exe") else "N/A",
                "username": p.username() if hasattr(p, "username") else "N/A",
                "cpu_percent": 0.0,
                "memory_percent": round(p.memory_percent(), 2) if hasattr(p, "memory_percent") else 0.0
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            info = {
                "pid": pid,
                "name": f"PID {pid}",
                "exe": "Restricted Access",
                "username": "N/A",
                "cpu_percent": 0.0,
                "memory_percent": 0.0
            }

        self.proc_cache[pid] = info
        self.proc_cache_time[pid] = now
        return info

    def _determine_protocol(self, sock_type: int, lport: int, rport: Optional[int]) -> str:
        """Determines high-level application protocol based on ports and socket type."""
        proto = "TCP" if sock_type == socket.SOCK_STREAM else "UDP"
        
        # Check target or local port for service name
        if rport and rport in PORT_SERVICES:
            return PORT_SERVICES[rport]
        if lport in PORT_SERVICES:
            return PORT_SERVICES[lport]
        
        return proto

    def get_bandwidth_stats(self) -> Dict[str, Any]:
        """Calculates instantaneous network I/O throughput in KB/s and Mbps."""
        now = time.time()
        curr_counters = psutil.net_io_counters()
        dt = max(0.001, now - self.last_io_time)

        bytes_sent_delta = curr_counters.bytes_sent - self.last_io_counters.bytes_sent
        bytes_recv_delta = curr_counters.bytes_recv - self.last_io_counters.bytes_recv
        packets_sent_delta = curr_counters.packets_sent - self.last_io_counters.packets_sent
        packets_recv_delta = curr_counters.packets_recv - self.last_io_counters.packets_recv

        self.last_io_time = now
        self.last_io_counters = curr_counters

        tx_kbps = round((bytes_sent_delta / dt) / 1024.0, 2)
        rx_kbps = round((bytes_recv_delta / dt) / 1024.0, 2)
        tx_mbps = round((bytes_sent_delta * 8 / dt) / (1024.0 * 1024.0), 2)
        rx_mbps = round((bytes_recv_delta * 8 / dt) / (1024.0 * 1024.0), 2)

        return {
            "tx_kbps": tx_kbps,
            "rx_kbps": rx_kbps,
            "tx_mbps": tx_mbps,
            "rx_mbps": rx_mbps,
            "total_sent_mb": round(curr_counters.bytes_sent / (1024 * 1024), 1),
            "total_recv_mb": round(curr_counters.bytes_recv / (1024 * 1024), 1),
            "packets_sent_sec": round(packets_sent_delta / dt, 1),
            "packets_recv_sec": round(packets_recv_delta / dt, 1)
        }

    def capture_connections(self) -> Dict[str, Any]:
        """Captures active sockets, parses process data, resolves GeoIP, and computes analytics."""
        raw_conns = []
        try:
            raw_conns = psutil.net_connections(kind="inet")
        except Exception as e:
            logger.error(f"Error reading net_connections: {e}")

        conns_list: List[Dict[str, Any]] = []
        countries_counter = Counter()
        process_counter = Counter()
        protocol_counter = Counter()
        status_counter = Counter()

        # Unique ID counter
        for idx, c in enumerate(raw_conns):
            status = c.status if c.status else "NONE"
            status_counter[status] += 1

            l_ip = c.laddr.ip if c.laddr else ""
            l_port = c.laddr.port if c.laddr else 0
            r_ip = c.raddr.ip if c.raddr else ""
            r_port = c.raddr.port if c.raddr else None

            # Skip uninformative 0.0.0.0:0 listening without remote if not active
            is_active_session = bool(r_ip and r_ip != "0.0.0.0")
            
            proc_info = self._get_process_info(c.pid)
            process_counter[proc_info["name"]] += 1

            protocol = self._determine_protocol(c.type, l_port, r_port)
            protocol_counter[protocol] += 1

            # Direction detection
            if not r_ip:
                direction = "Listening"
            elif l_port in (80, 443, 8000, 8080, 22, 3389, 21):
                direction = "Inbound"
            else:
                direction = "Outbound"

            # GeoIP resolution
            src_geo = geo_service.lookup(l_ip)
            dst_geo = geo_service.lookup(r_ip) if r_ip else None

            # Threat Intelligence Reputation Scoring
            threat_info = None
            if r_ip:
                threat_info = threat_intel.evaluate_ip(
                    r_ip,
                    org=dst_geo.get("org", "") if dst_geo else "",
                    asn=dst_geo.get("asn", "") if dst_geo else ""
                )

            if dst_geo and dst_geo.get("country"):
                countries_counter[dst_geo["country"]] += 1
            elif src_geo and src_geo.get("country"):
                countries_counter[src_geo["country"]] += 1

            # Unique key for frontend tracking
            conn_id = f"{c.pid}_{l_ip}_{l_port}_{r_ip}_{r_port}_{c.type}"

            conn_obj = {
                "id": conn_id,
                "pid": c.pid,
                "process": proc_info["name"],
                "process_exe": proc_info["exe"],
                "process_user": proc_info["username"],
                "memory_percent": proc_info["memory_percent"],
                "socket_type": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                "protocol": protocol,
                "status": status,
                "direction": direction,
                "is_active_remote": is_active_session,
                "threat_intel": threat_info,
                "source": {
                    "ip": l_ip,
                    "port": l_port,
                    "geo": src_geo
                },
                "destination": {
                    "ip": r_ip,
                    "port": r_port,
                    "geo": dst_geo
                } if r_ip else None
            }

            conns_list.append(conn_obj)

        # Sort: priorize active threats first, then remote external WAN, then established, then listening
        def sort_priority(item):
            t_intel = item.get("threat_intel") or {}
            is_threat = 1 if t_intel.get("is_threat") else 0
            is_suspicious = 1 if t_intel.get("verdict") == "SUSPICIOUS" else 0
            has_remote = 1 if item["destination"] and not item["destination"]["geo"]["is_private"] else 0
            is_established = 1 if item["status"] == "ESTABLISHED" else 0
            has_any_remote = 1 if item["destination"] else 0
            return (is_threat, is_suspicious, has_remote, is_established, has_any_remote)

        sorted_conns = sorted(conns_list, key=sort_priority, reverse=True)
        stream_conns = sorted_conns[:MAX_STREAM_CONNECTIONS]

        bandwidth = self.get_bandwidth_stats()

        threat_count = sum(1 for c in conns_list if (c.get("threat_intel") or {}).get("is_threat"))
        suspicious_count = sum(1 for c in conns_list if (c.get("threat_intel") or {}).get("verdict") == "SUSPICIOUS")

        # Format Top Summaries
        top_countries = [
            {"country": country, "count": count, "percentage": round((count / max(1, len(conns_list))) * 100, 1)}
            for country, count in countries_counter.most_common(6)
        ]
        top_processes = [
            {"name": name, "count": count}
            for name, count in process_counter.most_common(6)
        ]
        top_protocols = [
            {"protocol": proto, "count": count}
            for proto, count in protocol_counter.most_common(6)
        ]

        return {
            "timestamp": time.time(),
            "total_connections": len(conns_list),
            "established_count": status_counter.get("ESTABLISHED", 0),
            "listen_count": status_counter.get("LISTEN", 0),
            "active_remote_count": sum(1 for c in conns_list if c["is_active_remote"]),
            "threat_count": threat_count,
            "suspicious_count": suspicious_count,
            "bandwidth": bandwidth,
            "connections": stream_conns,
            "telemetry": {
                "top_countries": top_countries,
                "top_processes": top_processes,
                "top_protocols": top_protocols,
                "status_breakdown": dict(status_counter.most_common(5))
            }
        }

# Global singleton
network_monitor = NetworkMonitor()
