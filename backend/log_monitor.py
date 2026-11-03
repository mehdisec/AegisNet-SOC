import os
import re
import json
import time
import socket
import logging
import platform
import threading
import datetime
import subprocess
from typing import Dict, Any, List, Optional
from collections import deque

import psutil
from backend.config import (
    SECURITY_LOGS_FILE,
    LOGIN_ATTEMPTS_FILE,
    MAX_LOG_EVENTS
)
from backend.geoip_service import geo_service
from backend.os_detector import get_system_info
from backend.log_threat_detector import log_threat_detector

logger = logging.getLogger("aegis.log_monitor")

# Windows Event Log helper availability
HAS_WIN32EVTLOG = False
if platform.system() == "Windows":
    try:
        import win32evtlog
        import win32evtlogutil
        import xml.etree.ElementTree as ET
        HAS_WIN32EVTLOG = True
    except ImportError:
        HAS_WIN32EVTLOG = False


def decode_log_value(val) -> str:
    """Safely decodes log values (handles systemd byte arrays, None, and integers)."""
    if val is None:
        return ""
    if isinstance(val, list):
        try:
            return bytes(val).decode("utf-8", errors="replace").strip()
        except Exception:
            return " ".join(str(x) for x in val)
    return str(val).strip()


class LogMonitor:
    def __init__(self):
        self.lock = threading.Lock()
        self.system_info = get_system_info()
        self.is_windows = (platform.system() == "Windows")
        self.is_linux = (platform.system() == "Linux")

        # Rolling in-memory caches
        self.security_logs: List[Dict[str, Any]] = []
        self.login_attempts: List[Dict[str, Any]] = []
        self.system_logs_cache: List[Dict[str, Any]] = []
        self.last_system_read_time: float = 0.0

        # Load persisted logs
        self._load_persisted_logs()

        # Seed initial authentications from OS if empty
        self._bootstrap_initial_data()

    def _load_persisted_logs(self):
        """Loads persisted security and login logs from disk."""
        if os.path.exists(SECURITY_LOGS_FILE):
            try:
                with open(SECURITY_LOGS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Filter out any old simulated incidents
                    self.security_logs = [x for x in data if "SIMULATE" not in x.get("id", "")]
            except Exception as e:
                logger.warning(f"Could not load security logs: {e}")
                self.security_logs = []

        if os.path.exists(LOGIN_ATTEMPTS_FILE):
            try:
                with open(LOGIN_ATTEMPTS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Filter out any old simulated logins
                    self.login_attempts = [x for x in data if "SIMULATE" not in x.get("id", "")]
            except Exception as e:
                logger.warning(f"Could not load login attempts: {e}")
                self.login_attempts = []

    def _save_persisted_logs(self):
        """Saves logs safely to disk."""
        try:
            with self.lock:
                sec_copy = list(self.security_logs[:MAX_LOG_EVENTS])
                login_copy = list(self.login_attempts[:MAX_LOG_EVENTS])

            with open(SECURITY_LOGS_FILE, "w", encoding="utf-8") as f:
                json.dump(sec_copy, f, indent=2)

            with open(LOGIN_ATTEMPTS_FILE, "w", encoding="utf-8") as f:
                json.dump(login_copy, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to persist log data: {e}")

    def _bootstrap_initial_data(self):
        """Pulls genuine historical records from OS event streams."""
        if not self.login_attempts:
            self._harvest_os_logins()

        if self.is_windows and HAS_WIN32EVTLOG:
            self._harvest_windows_security_channel()
        elif self.is_linux:
            self._harvest_linux_security_logs()

    # =========================================================================
    # 1. LIVE SYSTEM LOG MONITOR (MULTI-SOURCE LINUX & WINDOWS)
    # =========================================================================
    def get_system_logs(self, limit: int = 100, level: Optional[str] = None, source: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves live system event logs from OS kernel/subsystems and runs real-time threat detection."""
        limit = min(max(10, limit), 300)
        now = time.time()

        # Cache live reads for 2.0 seconds to prevent hammering the event log subsystem
        if (now - self.last_system_read_time) > 2.0 or not self.system_logs_cache:
            if self.is_windows:
                self.system_logs_cache = self._read_windows_system_logs(limit=250)
            elif self.is_linux:
                self.system_logs_cache = self._read_linux_system_logs(limit=250)
            else:
                self.system_logs_cache = []

            self.last_system_read_time = now

            # Automated threat analysis across newly harvested system events
            if self.system_logs_cache:
                os_mode = "windows" if self.is_windows else "linux"
                discovered_threats = log_threat_detector.scan_log_batch(self.system_logs_cache[:100], os_type=os_mode)
                for threat in discovered_threats:
                    self.add_security_event(threat)

        events = list(self.system_logs_cache)

        # Filters
        if level and level != "ALL":
            events = [e for e in events if e.get("level", "").upper() == level.upper()]

        if source and source != "ALL":
            source_lower = source.lower()
            events = [e for e in events if source_lower in e.get("source", "").lower()]

        if search:
            s_lower = search.lower()
            events = [
                e for e in events
                if s_lower in str(e.get("message", "")).lower()
                or s_lower in str(e.get("source", "")).lower()
                or s_lower in str(e.get("event_id", ""))
            ]

        return events[:limit]

    def _read_windows_system_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Reads real records from the Windows 'System' event log channel."""
        records = []
        if HAS_WIN32EVTLOG:
            try:
                import win32evtlog
                import win32evtlogutil

                h = win32evtlog.OpenEventLog(None, "System")
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                
                while len(records) < limit:
                    batch = win32evtlog.ReadEventLog(h, flags, 0)
                    if not batch:
                        break

                    for e in batch:
                        if e.EventType == win32evtlog.EVENTLOG_ERROR_TYPE:
                            lvl = "ERROR"
                        elif e.EventType == win32evtlog.EVENTLOG_WARNING_TYPE:
                            lvl = "WARNING"
                        elif e.EventType == win32evtlog.EVENTLOG_AUDIT_FAILURE:
                            lvl = "CRITICAL"
                        elif e.EventType == win32evtlog.EVENTLOG_AUDIT_SUCCESS:
                            lvl = "AUDIT"
                        else:
                            lvl = "INFO"

                        event_id = e.EventID & 0xFFFF

                        try:
                            msg = win32evtlogutil.SafeFormatMessage(e, "System").strip()
                            if not msg or msg.startswith("The description for Event ID"):
                                if e.StringInserts:
                                    msg = " ".join(str(s) for s in e.StringInserts)
                                else:
                                    msg = f"System event {event_id} from {e.SourceName}"
                        except Exception:
                            if e.StringInserts:
                                msg = " ".join(str(s) for s in e.StringInserts)
                            else:
                                msg = f"System event {event_id} from {e.SourceName}"

                        t_gen = e.TimeGenerated
                        time_str = t_gen.strftime("%Y-%m-%d %H:%M:%S") if hasattr(t_gen, "strftime") else str(t_gen)

                        records.append({
                            "id": f"SYS-{e.RecordNumber}",
                            "timestamp": time_str,
                            "source": e.SourceName or "Kernel",
                            "event_id": event_id,
                            "level": lvl,
                            "category": e.EventCategory,
                            "message": msg,
                            "computer": e.ComputerName or socket.gethostname()
                        })

                        if len(records) >= limit:
                            break

                win32evtlog.CloseEventLog(h)
            except Exception as ex:
                logger.warning(f"Error querying Windows System event log via pywin32: {ex}")

        # PowerShell fallback if pywin32 failed or produced 0 records
        if not records:
            try:
                ps_cmd = f"Get-WinEvent -LogName System -MaxEvents {min(limit, 50)} | Select-Object RecordId, TimeCreated, ProviderName, Id, LevelDisplayName, Message | ConvertTo-Json -Compress"
                proc = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3.5)
                if proc.returncode == 0 and proc.stdout.strip():
                    parsed = json.loads(proc.stdout)
                    items = parsed if isinstance(parsed, list) else [parsed]
                    for item in items:
                        lvl_name = str(item.get("LevelDisplayName") or "Info").upper()
                        if "ERR" in lvl_name:
                            lvl = "ERROR"
                        elif "WARN" in lvl_name:
                            lvl = "WARNING"
                        elif "CRIT" in lvl_name:
                            lvl = "CRITICAL"
                        else:
                            lvl = "INFO"

                        # Extract timestamp
                        t_raw = item.get("TimeCreated")
                        t_str = str(t_raw) if t_raw else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                        records.append({
                            "id": f"SYS-{item.get('RecordId', len(records)+1)}",
                            "timestamp": t_str,
                            "source": item.get("ProviderName") or "Kernel",
                            "event_id": item.get("Id", 0),
                            "level": lvl,
                            "category": 0,
                            "message": str(item.get("Message") or f"System event {item.get('Id')}").strip(),
                            "computer": socket.gethostname()
                        })
            except Exception as ps_err:
                logger.debug(f"PowerShell system log fallback error: {ps_err}")

        return records

    def _read_linux_system_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        """
        Multi-Source Linux System Log Reader:
        1. systemd journalctl JSON output (with safe byte-array string decoding)
        2. systemd journalctl plain-text output
        3. /var/log/syslog and /var/log/messages files
        4. dmesg -T kernel ring buffer (universal across all Linux kernels)
        5. /var/log/dmesg & /var/log/kern.log
        """
        records = []
        host = socket.gethostname()

        # ---------------------------------------------------------------------
        # Source 1: journalctl JSON
        # ---------------------------------------------------------------------
        try:
            cmd = ["journalctl", "-n", str(limit), "-o", "json", "--no-pager"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=4.5)
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                        prio = int(item.get("PRIORITY", 6))
                        if prio <= 2:
                            lvl = "CRITICAL"
                        elif prio == 3:
                            lvl = "ERROR"
                        elif prio == 4:
                            lvl = "WARNING"
                        else:
                            lvl = "INFO"

                        usec = int(item.get("__REALTIME_TIMESTAMP") or item.get("_SOURCE_REALTIME_TIMESTAMP") or (time.time() * 1000000))
                        dt = datetime.datetime.fromtimestamp(usec / 1000000.0)

                        # Decode message cleanly (handles byte lists from binary journal records)
                        msg_clean = decode_log_value(item.get("MESSAGE"))
                        if not msg_clean:
                            continue

                        src_clean = decode_log_value(item.get("_COMM") or item.get("SYSLOG_IDENTIFIER") or item.get("UNIT") or "kernel")
                        hostname_clean = decode_log_value(item.get("_HOSTNAME") or host)
                        msg_id = item.get("MESSAGE_ID") or 1000

                        records.append({
                            "id": f"LNX-{usec}",
                            "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
                            "source": src_clean,
                            "event_id": str(msg_id)[:12],
                            "level": lvl,
                            "category": item.get("SYSLOG_FACILITY", 0),
                            "message": msg_clean,
                            "computer": hostname_clean
                        })
                    except Exception:
                        continue
                if records:
                    records.reverse()
                    return records
        except Exception as e:
            logger.debug(f"Linux journalctl JSON query failed: {e}")

        # ---------------------------------------------------------------------
        # Source 2: journalctl Plain Text
        # ---------------------------------------------------------------------
        if not records:
            try:
                cmd = ["journalctl", "-n", str(limit), "--no-pager"]
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=4.0)
                if proc.returncode == 0 and proc.stdout:
                    lines = proc.stdout.splitlines()
                    for idx, line in enumerate(reversed(lines)):
                        parsed = self._parse_syslog_line(line, f"LNX-JNL-{idx}", host)
                        if parsed:
                            records.append(parsed)
                        if len(records) >= limit:
                            break
                    if records:
                        return records
            except Exception as e:
                logger.debug(f"Linux journalctl text query failed: {e}")

        # ---------------------------------------------------------------------
        # Source 3: /var/log/syslog & /var/log/messages
        # ---------------------------------------------------------------------
        if not records:
            for sys_path in ("/var/log/syslog", "/var/log/messages"):
                if os.path.exists(sys_path) and os.access(sys_path, os.R_OK):
                    try:
                        with open(sys_path, "r", encoding="utf-8", errors="ignore") as f:
                            raw_lines = deque(f, maxlen=limit)
                        for idx, line in enumerate(reversed(raw_lines)):
                            parsed = self._parse_syslog_line(line, f"LNX-FILE-{idx}", host)
                            if parsed:
                                records.append(parsed)
                        if records:
                            return records
                    except Exception as e:
                        logger.debug(f"Could not read {sys_path}: {e}")

        # ---------------------------------------------------------------------
        # Source 4: dmesg -T (Kernel Ring Buffer)
        # ---------------------------------------------------------------------
        if not records:
            try:
                proc = subprocess.run(["dmesg", "-T"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3.0)
                if proc.returncode == 0 and proc.stdout:
                    lines = proc.stdout.splitlines()
                    for idx, line in enumerate(reversed(lines[-limit:])):
                        # dmesg line format: [Mon Nov  3 15:10:02 2026] <message>
                        m = re.match(r"^\[([^\]]+)\]\s*(.*)$", line)
                        if m:
                            t_str = m.group(1).strip()
                            msg_str = m.group(2).strip()
                            lvl = "INFO"
                            m_lower = msg_str.lower()
                            if "error" in m_lower or "failed" in m_lower or "critical" in m_lower or "segfault" in m_lower:
                                lvl = "ERROR"
                            elif "warning" in m_lower or "warn" in m_lower:
                                lvl = "WARNING"

                            records.append({
                                "id": f"LNX-DMESG-{idx}",
                                "timestamp": t_str,
                                "source": "kernel",
                                "event_id": "DMESG",
                                "level": lvl,
                                "category": 0,
                                "message": msg_str,
                                "computer": host
                            })
                    if records:
                        return records
            except Exception as e:
                logger.debug(f"dmesg read failed: {e}")

        # ---------------------------------------------------------------------
        # Source 5: /var/log/kern.log & /var/log/dmesg
        # ---------------------------------------------------------------------
        if not records:
            for kpath in ("/var/log/kern.log", "/var/log/dmesg"):
                if os.path.exists(kpath) and os.access(kpath, os.R_OK):
                    try:
                        with open(kpath, "r", encoding="utf-8", errors="ignore") as f:
                            raw_lines = deque(f, maxlen=limit)
                        for idx, line in enumerate(reversed(raw_lines)):
                            parsed = self._parse_syslog_line(line, f"LNX-KERN-{idx}", host)
                            if parsed:
                                records.append(parsed)
                        if records:
                            return records
                    except Exception:
                        pass

        # If system logs are restricted by permissions, provide genuine system guidance notice
        if not records:
            records.append({
                "id": f"LNX-PERM-NOTICE-{int(time.time())}",
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source": "AegisNet-SystemAudit",
                "event_id": "PERM_NOTICE",
                "level": "WARNING",
                "category": 0,
                "message": "Linux system log access restricted: Run AegisNet with root (sudo) or add user to 'systemd-journal' and 'adm' groups: sudo usermod -aG systemd-journal,adm $USER",
                "computer": host
            })

        return records

    def _parse_syslog_line(self, line: str, record_id: str, default_host: str) -> Optional[Dict[str, Any]]:
        """Parses standard Linux RFC 3164 / 5424 syslog format."""
        line = line.strip()
        if not line:
            return None

        # Pattern: Month Day HH:MM:SS host process[pid]: message
        # Or: ISO8601 host process[pid]: message
        match = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\d+:\d+:\d+[^\s]*)\s+([^\s:]+)\s+([^:\[]+)(?:\[\d+\])?:?\s*(.*)$", line)
        if match:
            t_str = match.group(1)
            h_str = match.group(2)
            src_str = match.group(3)
            msg_str = match.group(4)
        else:
            t_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            h_str = default_host
            src_str = "system"
            msg_str = line

        lvl = "INFO"
        m_lower = msg_str.lower()
        if any(w in m_lower for w in ("error", "failed", "critical", "segfault", "panic", "fatal", "denied")):
            lvl = "ERROR"
        elif any(w in m_lower for w in ("warn", "warning", "rejected")):
            lvl = "WARNING"

        return {
            "id": record_id,
            "timestamp": t_str,
            "source": src_str or "system",
            "event_id": 1000,
            "level": lvl,
            "category": 0,
            "message": msg_str,
            "computer": h_str or default_host
        }

    # =========================================================================
    # 2. SECURITY LOG MONITOR & THREAT AUDIT
    # =========================================================================
    def get_security_logs(self, limit: int = 100, category: Optional[str] = None, severity: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves threat audit, policy changes, and security incident logs."""
        limit = min(max(10, limit), 300)

        # Harvest fresh events from Windows Security Channel, Defender, System or Linux auth logs
        if self.is_windows and HAS_WIN32EVTLOG:
            self._harvest_windows_security_channel()
        elif self.is_linux:
            self._harvest_linux_security_logs()

        with self.lock:
            logs = list(self.security_logs)

        # Apply Filters
        if category and category != "ALL":
            logs = [l for l in logs if l.get("category", "").upper() == category.upper()]

        if severity and severity != "ALL":
            logs = [l for l in logs if l.get("severity", "").upper() == severity.upper()]

        if search:
            s_lower = search.lower()
            logs = [
                l for l in logs
                if s_lower in str(l.get("title", "")).lower()
                or s_lower in str(l.get("description", "")).lower()
                or s_lower in str(l.get("source_ip", "")).lower()
                or s_lower in str(l.get("user", "")).lower()
            ]

        return logs[:limit]

    def add_security_event(self, event: Dict[str, Any]):
        """Adds a genuine security audit incident to the log stream."""
        if not event:
            return

        if "id" not in event:
            event["id"] = f"SEC-{int(time.time()*1000)}-{len(self.security_logs)+1}"
        if "timestamp" not in event:
            event["timestamp"] = datetime.datetime.now().isoformat()
        if "geo" not in event and event.get("source_ip"):
            src = event["source_ip"]
            event["geo"] = geo_service.lookup(src) if src not in ("127.0.0.1", "LOCAL", "::1") else geo_service.host_location

        with self.lock:
            # Check duplicate by ID
            if any(x.get("id") == event["id"] for x in self.security_logs):
                return
            self.security_logs.insert(0, event)
            if len(self.security_logs) > MAX_LOG_EVENTS:
                self.security_logs = self.security_logs[:MAX_LOG_EVENTS]

        self._save_persisted_logs()

    def _harvest_windows_security_channel(self):
        """Polls Windows Security, Defender, System, and PowerShell channels for security incidents."""
        if not HAS_WIN32EVTLOG:
            return

        import win32evtlog
        import xml.etree.ElementTree as ET

        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        new_events = []

        # 1. Direct Security Channel (Admin or Event Log Readers privilege)
        try:
            query = "*[System[(EventID=4688 or EventID=4720 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4740 or EventID=1102 or EventID=104 or EventID=4672 or EventID=5157)]]"
            q = win32evtlog.EvtQuery("Security", win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, query)
            events = win32evtlog.EvtNext(q, 25)

            for e in events:
                xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                root = ET.fromstring(xml_str)
                eid = root.find('.//ns:EventID', ns).text
                time_created = root.find('.//ns:TimeCreated', ns).attrib.get('SystemTime', '')
                rec_id = root.find('.//ns:EventRecordID', ns)
                rec_str = rec_id.text if rec_id is not None else str(int(time.time()))

                event_key = f"WIN-SEC-{rec_str}"
                if any(x.get("id") == event_key for x in self.security_logs):
                    continue

                event_data = root.find('.//ns:EventData', ns)
                data_dict = {}
                if event_data is not None:
                    for d in event_data.findall('ns:Data', ns):
                        name = d.attrib.get('Name')
                        if name:
                            data_dict[name] = d.text

                sec_item = {
                    "id": event_key,
                    "event_id": eid,
                    "timestamp": time_created,
                    "category": "AUDIT",
                    "severity": "INFO",
                    "title": f"Security Event {eid}",
                    "description": f"Windows Security Audit Event ID {eid}",
                    "source_ip": data_dict.get("IpAddress", "127.0.0.1"),
                    "user": data_dict.get("TargetUserName") or data_dict.get("SubjectUserName") or "SYSTEM",
                    "action": f"EVENT_{eid}",
                    "message": json.dumps(data_dict)
                }

                # Run through the Threat Detector
                detected_threat = log_threat_detector.analyze_event(sec_item, os_type="windows")
                if detected_threat:
                    new_events.append(detected_threat)
                else:
                    if eid == "4688":
                        sec_item["category"] = "PROCESS"
                        sec_item["title"] = "New Process Created"
                        proc = data_dict.get("NewProcessName", "Unknown")
                        sec_item["description"] = f"Created: {proc} by {sec_item['user']}"
                    elif eid == "4672":
                        sec_item["category"] = "PRIVILEGE"
                        sec_item["severity"] = "MEDIUM"
                        sec_item["title"] = "Special Privileges Assigned to Logon"
                        sec_item["description"] = f"Administrator privileges granted to {sec_item['user']}"
                    elif eid == "4720":
                        sec_item["category"] = "ACCOUNT"
                        sec_item["severity"] = "HIGH"
                        sec_item["title"] = "User Account Created"
                        sec_item["description"] = f"New user account {data_dict.get('TargetUserName')} was provisioned."
                    elif eid == "5157":
                        sec_item["category"] = "FIREWALL"
                        sec_item["severity"] = "HIGH"
                        sec_item["title"] = "Windows Filtering Platform Blocked Connection"
                        sec_item["description"] = f"WFP dropped packet to {data_dict.get('DestAddress')}:{data_dict.get('DestPort')}"

                    new_events.append(sec_item)
        except Exception:
            pass

        # 2. Windows Defender Operational Channel (Malware detections, tampering, configuration)
        try:
            q_def = win32evtlog.EvtQuery("Microsoft-Windows-Windows Defender/Operational", win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, "*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5004 or EventID=5007)]]")
            def_events = win32evtlog.EvtNext(q_def, 15)
            for e in def_events:
                xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                root = ET.fromstring(xml_str)
                eid = root.find('.//ns:EventID', ns).text
                time_created = root.find('.//ns:TimeCreated', ns).attrib.get('SystemTime', '')
                rec_id = root.find('.//ns:EventRecordID', ns)
                rec_str = rec_id.text if rec_id is not None else str(int(time.time()))

                event_key = f"WIN-DEF-{rec_str}"
                if any(x.get("id") == event_key for x in self.security_logs):
                    continue

                event_data = root.find('.//ns:EventData', ns)
                data_dict = {}
                if event_data is not None:
                    for d in event_data.findall('ns:Data', ns):
                        name = d.attrib.get('Name')
                        if name:
                            data_dict[name] = d.text

                threat_name = data_dict.get("Threat Name") or data_dict.get("Product Name") or f"Defender Event {eid}"
                sev = "CRITICAL" if eid in ("1116", "5001") else ("HIGH" if eid == "1117" else "INFO")
                cat = "MALWARE" if eid in ("1116", "1117") else "DEFENSE_EVASION"

                def_item = {
                    "id": event_key,
                    "event_id": eid,
                    "timestamp": time_created,
                    "category": cat,
                    "severity": sev,
                    "title": f"Defender: {threat_name}",
                    "description": f"Windows Defender Event {eid}: {threat_name}",
                    "source_ip": "127.0.0.1",
                    "user": "SYSTEM",
                    "action": f"DEFENDER_{eid}",
                    "message": json.dumps(data_dict)
                }
                new_events.append(def_item)
        except Exception:
            pass

        # 3. System Security Events (Service Installations Event 7045 & Audit Cleared Event 104)
        try:
            q_sys = win32evtlog.EvtQuery("System", win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, "*[System[(EventID=7045 or EventID=104)]]")
            sys_events = win32evtlog.EvtNext(q_sys, 15)
            for e in sys_events:
                xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                root = ET.fromstring(xml_str)
                eid = root.find('.//ns:EventID', ns).text
                time_created = root.find('.//ns:TimeCreated', ns).attrib.get('SystemTime', '')
                rec_id = root.find('.//ns:EventRecordID', ns)
                rec_str = rec_id.text if rec_id is not None else str(int(time.time()))

                event_key = f"WIN-SYSSEC-{rec_str}"
                if any(x.get("id") == event_key for x in self.security_logs):
                    continue

                event_data = root.find('.//ns:EventData', ns)
                data_dict = {}
                if event_data is not None:
                    for d in event_data.findall('ns:Data', ns):
                        name = d.attrib.get('Name')
                        if name:
                            data_dict[name] = d.text

                if eid == "7045":
                    svc_name = data_dict.get("ServiceName", "Unknown Service")
                    img_path = data_dict.get("ImagePath", "Unknown")
                    acct = data_dict.get("AccountName", "SYSTEM")
                    sys_item = {
                        "id": event_key,
                        "event_id": "7045",
                        "timestamp": time_created,
                        "category": "PERSISTENCE",
                        "severity": "MEDIUM",
                        "title": f"Service Installed: {svc_name}",
                        "description": f"Binary: {img_path} (Account: {acct})",
                        "source_ip": "127.0.0.1",
                        "user": acct,
                        "action": "SERVICE_INSTALLED",
                        "message": json.dumps(data_dict)
                    }
                    new_events.append(sys_item)
                elif eid == "104":
                    sys_item = {
                        "id": event_key,
                        "event_id": "104",
                        "timestamp": time_created,
                        "category": "DEFENSE_EVASION",
                        "severity": "HIGH",
                        "title": "System Audit Log Cleared",
                        "description": "The event log was cleared by an administrator or intruder.",
                        "source_ip": "127.0.0.1",
                        "user": "SYSTEM",
                        "action": "LOG_CLEARED",
                        "message": json.dumps(data_dict)
                    }
                    new_events.append(sys_item)
        except Exception:
            pass

        # 4. PowerShell Operational Channel (ScriptBlock Logging - Event 4104)
        try:
            q_ps = win32evtlog.EvtQuery("Microsoft-Windows-PowerShell/Operational", win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, "*[System[(EventID=4104)]]")
            ps_events = win32evtlog.EvtNext(q_ps, 15)
            for e in ps_events:
                xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                root = ET.fromstring(xml_str)
                time_created = root.find('.//ns:TimeCreated', ns).attrib.get('SystemTime', '')
                rec_id = root.find('.//ns:EventRecordID', ns)
                rec_str = rec_id.text if rec_id is not None else str(int(time.time()))

                event_key = f"WIN-PS-{rec_str}"
                if any(x.get("id") == event_key for x in self.security_logs):
                    continue

                event_data = root.find('.//ns:EventData', ns)
                data_dict = {}
                if event_data is not None:
                    for d in event_data.findall('ns:Data', ns):
                        name = d.attrib.get('Name')
                        if name:
                            data_dict[name] = d.text

                script_text = data_dict.get("ScriptBlockText", "")
                # Only log if suspicious or threat detected
                ps_item = {
                    "id": event_key,
                    "event_id": "4104",
                    "timestamp": time_created,
                    "category": "EXECUTION",
                    "severity": "INFO",
                    "title": "PowerShell ScriptBlock Executed",
                    "description": script_text[:120].strip() or "ScriptBlock executed",
                    "source_ip": "127.0.0.1",
                    "user": "SYSTEM",
                    "action": "POWERSHELL_SCRIPT",
                    "message": script_text
                }
                threat = log_threat_detector.analyze_event(ps_item, os_type="windows")
                if threat:
                    new_events.append(threat)
        except Exception:
            pass

        if new_events:
            with self.lock:
                for item in reversed(new_events):
                    self.security_logs.insert(0, item)
                self.security_logs = self.security_logs[:MAX_LOG_EVENTS]
            self._save_persisted_logs()

    def _harvest_linux_security_logs(self):
        """Discovers security incidents from Linux auth logs, journalctl, and systemd units."""
        if not self.is_linux:
            return

        new_events = []
        # 1. Query journalctl specifically for security units
        try:
            cmd = ["journalctl", "-n", "80", "-o", "json", "--no-pager", "-u", "ssh", "-u", "sshd", "-u", "sudo", "-u", "systemd-logind", "-u", "polkit"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3.5)
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                        msg = decode_log_value(item.get("MESSAGE"))
                        comm = decode_log_value(item.get("_COMM") or item.get("SYSLOG_IDENTIFIER") or "system")
                        usec = int(item.get("__REALTIME_TIMESTAMP") or (time.time() * 1000000))
                        event_key = f"LNX-SEC-{usec}"
                        if any(x.get("id") == event_key for x in self.security_logs):
                            continue

                        raw_event = {
                            "id": event_key,
                            "timestamp": datetime.datetime.fromtimestamp(usec / 1000000.0).isoformat(),
                            "source": comm,
                            "message": msg,
                            "user": item.get("_AUDIT_LOGINUID") or "root"
                        }

                        # Feed into LogThreatDetector
                        threat = log_threat_detector.analyze_event(raw_event, os_type="linux")
                        if threat:
                            new_events.append(threat)
                    except Exception:
                        continue
        except Exception as e:
            logger.debug(f"Linux security journalctl error: {e}")

        # 2. Check /var/log/auth.log, /var/log/secure, and /var/log/audit/audit.log
        for auth_file in ("/var/log/auth.log", "/var/log/secure", "/var/log/audit/audit.log"):
            if os.path.exists(auth_file) and os.access(auth_file, os.R_OK):
                try:
                    with open(auth_file, "r", encoding="utf-8", errors="ignore") as f:
                        lines = deque(f, maxlen=60)
                    for line in lines:
                        l_clean = line.strip()
                        if not l_clean:
                            continue
                        event_key = f"LNX-AUTH-{hash(l_clean)}"
                        if any(x.get("id") == event_key for x in self.security_logs):
                            continue

                        raw_event = {
                            "id": event_key,
                            "timestamp": datetime.datetime.now().isoformat(),
                            "source": "auth-log",
                            "message": l_clean
                        }
                        threat = log_threat_detector.analyze_event(raw_event, os_type="linux")
                        if threat:
                            new_events.append(threat)
                except Exception:
                    pass

        if new_events:
            with self.lock:
                for item in reversed(new_events):
                    self.security_logs.insert(0, item)
                self.security_logs = self.security_logs[:MAX_LOG_EVENTS]
            self._save_persisted_logs()

    # =========================================================================
    # 3. LOGIN ATTEMPTS MONITOR
    # =========================================================================
    def get_login_attempts(self, limit: int = 100, status: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves logon events, failed authentications, and session histories."""
        limit = min(max(10, limit), 300)

        # Refresh with current OS events
        self._harvest_os_logins()

        with self.lock:
            attempts = list(self.login_attempts)

        # Filters
        if status and status != "ALL":
            attempts = [a for a in attempts if a.get("status", "").upper() == status.upper()]

        if search:
            s_lower = search.lower()
            attempts = [
                a for a in attempts
                if s_lower in str(a.get("username", "")).lower()
                or s_lower in str(a.get("source_ip", "")).lower()
                or s_lower in str(a.get("logon_type", "")).lower()
                or s_lower in str(a.get("failure_reason", "")).lower()
            ]

        return attempts[:limit]

    def record_login_attempt(self, username: str, status: str, logon_type: str = "Interactive", source_ip: str = "127.0.0.1", failure_reason: str = "") -> Dict[str, Any]:
        """Records a real authentication attempt and evaluates brute-force threat scoring."""
        status = status.upper()
        if status not in ("SUCCESS", "FAILED", "LOGOFF", "DISCONNECTED"):
            status = "INFO"

        record_id = f"AUTH-{int(time.time()*1000)}-{len(self.login_attempts)+1}"
        geo = geo_service.lookup(source_ip) if source_ip != "LOCAL" else geo_service.host_location

        record = {
            "id": record_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "username": username,
            "status": status,
            "logon_type": logon_type,
            "source_ip": source_ip,
            "failure_reason": failure_reason if status == "FAILED" else "Authenticated successfully",
            "geo": geo,
            "severity": "HIGH" if status == "FAILED" else "INFO"
        }

        with self.lock:
            self.login_attempts.insert(0, record)
            if len(self.login_attempts) > MAX_LOG_EVENTS:
                self.login_attempts = self.login_attempts[:MAX_LOG_EVENTS]

        # Feed to Log Threat Detector if failed
        if status == "FAILED":
            raw_event = {
                "message": f"Authentication failed for user {username} from {source_ip}: {failure_reason}",
                "source": "LogonAuth",
                "user": username,
                "source_ip": source_ip
            }
            threat = log_threat_detector.analyze_event(raw_event)
            if threat:
                self.add_security_event(threat)

        self._save_persisted_logs()
        return record

    def _harvest_os_logins(self):
        """Harvests authentications from Windows TerminalServices & Security or Linux."""
        if self.is_linux:
            self._harvest_linux_logins()
            return

        if not self.is_windows or not HAS_WIN32EVTLOG:
            return

        import win32evtlog
        import xml.etree.ElementTree as ET

        # 1. Harvest from TerminalServices
        try:
            query = "*[System[(EventID=21 or EventID=22 or EventID=23 or EventID=24 or EventID=25)]]"
            q = win32evtlog.EvtQuery("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, query)
            events = win32evtlog.EvtNext(q, 30)

            ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event', 'e': 'Event_NS'}
            new_logins = []

            for e in events:
                xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                root = ET.fromstring(xml_str)
                eid = root.find('.//ns:EventID', ns).text
                time_created = root.find('.//ns:TimeCreated', ns).attrib.get('SystemTime', '')
                rec_id = root.find('.//ns:EventRecordID', ns)
                rec_str = rec_id.text if rec_id is not None else str(int(time.time()))

                event_id_key = f"OS-AUTH-{rec_str}"
                if any(x.get("id") == event_id_key for x in self.login_attempts):
                    continue

                user = root.find('.//e:User', ns)
                u_str = user.text if user is not None and user.text else "Console User"
                addr = root.find('.//e:Address', ns)
                a_str = addr.text if addr is not None and addr.text else "LOCAL"

                status = "SUCCESS"
                logon_type = "Interactive Console"
                reason = "Console Session Logon Succeeded"

                if eid == "21":
                    status = "SUCCESS"
                    logon_type = "Remote Desktop (RDP)" if a_str != "LOCAL" else "Interactive Console"
                    reason = "Session Logon Succeeded"
                elif eid == "22":
                    status = "SUCCESS"
                    logon_type = "Shell Start"
                    reason = "User Desktop Shell Initialized"
                elif eid == "23":
                    status = "LOGOFF"
                    logon_type = "Session Logoff"
                    reason = "User Logged Off Session"
                elif eid == "24":
                    status = "DISCONNECTED"
                    logon_type = "Session Disconnected"
                    reason = "Session Disconnected from Console"
                elif eid == "25":
                    status = "SUCCESS"
                    logon_type = "Session Reconnection"
                    reason = "Session Reconnected"

                geo = geo_service.lookup(a_str) if a_str != "LOCAL" else geo_service.host_location

                new_logins.append({
                    "id": event_id_key,
                    "timestamp": time_created,
                    "username": u_str,
                    "status": status,
                    "logon_type": logon_type,
                    "source_ip": a_str,
                    "failure_reason": reason,
                    "geo": geo,
                    "severity": "INFO" if status in ("SUCCESS", "LOGOFF") else "MEDIUM"
                })

            if new_logins:
                with self.lock:
                    for item in reversed(new_logins):
                        self.login_attempts.insert(0, item)
                    self.login_attempts = self.login_attempts[:MAX_LOG_EVENTS]
                self._save_persisted_logs()
        except Exception as e:
            logger.debug(f"TerminalServices harvest error: {e}")

        # 2. Harvest from Windows Security Channel (Events 4624 & 4625)
        if self.system_info.get("is_admin", False):
            try:
                query = "*[System[(EventID=4624 or EventID=4625)]]"
                q = win32evtlog.EvtQuery("Security", win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, query)
                events = win32evtlog.EvtNext(q, 25)
                
                ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                new_sec_logins = []

                for e in events:
                    xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                    root = ET.fromstring(xml_str)
                    eid = root.find('.//ns:EventID', ns).text
                    time_created = root.find('.//ns:TimeCreated', ns).attrib.get('SystemTime', '')
                    rec_id = root.find('.//ns:EventRecordID', ns)
                    rec_str = rec_id.text if rec_id is not None else str(int(time.time()))

                    event_id_key = f"SEC-LOGON-{rec_str}"
                    if any(x.get("id") == event_id_key for x in self.login_attempts):
                        continue

                    event_data = root.find('.//ns:EventData', ns)
                    d = {}
                    if event_data is not None:
                        for item in event_data.findall('ns:Data', ns):
                            name = item.attrib.get('Name')
                            if name:
                                d[name] = item.text

                    u_str = d.get("TargetUserName") or d.get("SubjectUserName") or "Unknown"
                    if u_str.endswith("$"):
                        continue

                    ip_str = d.get("IpAddress", "127.0.0.1")
                    if ip_str in ("-", "::1"):
                        ip_str = "LOCAL"

                    ltype_code = d.get("LogonType", "2")
                    ltype_map = {
                        "2": "Interactive Console",
                        "3": "Network Auth",
                        "4": "Batch Process",
                        "5": "Service Account",
                        "7": "Unlock Workstation",
                        "10": "Remote Desktop (RDP)",
                        "11": "Cached Credentials"
                    }
                    logon_type = ltype_map.get(ltype_code, f"Type {ltype_code}")

                    if eid == "4624":
                        status = "SUCCESS"
                        reason = "Logon Succeeded (Event 4624)"
                        sev = "INFO"
                    else:
                        status = "FAILED"
                        sub_status = d.get("SubStatus", "0xC000006A")
                        fail_map = {
                            "0xc000006a": "Bad Password / Invalid Credentials",
                            "0xc0000064": "Account Does Not Exist",
                            "0xc0000234": "Account Locked Out",
                            "0xc0000072": "Account Disabled",
                            "0xc0000193": "Account Expired"
                        }
                        reason = fail_map.get(sub_status.lower(), f"Logon Failed ({sub_status})")
                        sev = "HIGH"

                    geo = geo_service.lookup(ip_str) if ip_str != "LOCAL" else geo_service.host_location

                    new_sec_logins.append({
                        "id": event_id_key,
                        "timestamp": time_created,
                        "username": u_str,
                        "status": status,
                        "logon_type": logon_type,
                        "source_ip": ip_str,
                        "failure_reason": reason,
                        "geo": geo,
                        "severity": sev
                    })

                if new_sec_logins:
                    with self.lock:
                        for item in reversed(new_sec_logins):
                            self.login_attempts.insert(0, item)
                        self.login_attempts = self.login_attempts[:MAX_LOG_EVENTS]
                    self._save_persisted_logs()
            except Exception as ex:
                logger.debug(f"Windows Security logon read error: {ex}")

    def _harvest_linux_logins(self):
        """Harvests authentications on Linux from last, lastb, journalctl, and auth logs."""
        if not self.is_linux:
            return

        new_logins = []

        # 1. Successful logins via `last -n 30`
        try:
            proc = subprocess.run(["last", "-n", "30"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.5)
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] not in ("reboot", "wtmp", ""):
                        user = parts[0]
                        terminal = parts[1]
                        ip_or_host = parts[2]
                        event_key = f"LNX-LAST-{hash(line.strip())}"
                        if any(x.get("id") == event_key for x in self.login_attempts):
                            continue
                        
                        is_remote = (ip_or_host not in (":0", "tty1", "tty2", "LOCAL") and not ip_or_host.startswith(":"))
                        ltype = "Remote SSH" if "pts" in terminal or is_remote else "Console (tty)"
                        geo = geo_service.lookup(ip_or_host) if is_remote else geo_service.host_location

                        new_logins.append({
                            "id": event_key,
                            "timestamp": datetime.datetime.now().isoformat(),
                            "username": user,
                            "status": "SUCCESS",
                            "logon_type": ltype,
                            "source_ip": ip_or_host if is_remote else "LOCAL",
                            "failure_reason": "Logon Session Recorded (last)",
                            "geo": geo,
                            "severity": "INFO"
                        })
        except Exception:
            pass

        # 2. Failed logins via `lastb -n 30`
        try:
            proc = subprocess.run(["lastb", "-n", "30"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.5)
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] not in ("btmp", ""):
                        user = parts[0]
                        terminal = parts[1]
                        ip_or_host = parts[2]
                        event_key = f"LNX-LASTB-{hash(line.strip())}"
                        if any(x.get("id") == event_key for x in self.login_attempts):
                            continue

                        is_remote = (ip_or_host not in (":0", "tty1", "LOCAL") and not ip_or_host.startswith(":"))
                        geo = geo_service.lookup(ip_or_host) if is_remote else geo_service.host_location

                        new_logins.append({
                            "id": event_key,
                            "timestamp": datetime.datetime.now().isoformat(),
                            "username": user,
                            "status": "FAILED",
                            "logon_type": "Remote SSH" if "pts" in terminal or is_remote else "Console",
                            "source_ip": ip_or_host if is_remote else "LOCAL",
                            "failure_reason": "Invalid Credentials (lastb)",
                            "geo": geo,
                            "severity": "HIGH"
                        })
        except Exception:
            pass

        # 3. Journalctl SSH and PAM login harvest
        try:
            cmd = ["journalctl", "-u", "ssh", "-u", "sshd", "-u", "systemd-logind", "-n", "50", "-o", "json", "--no-pager"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3.0)
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                        msg = decode_log_value(item.get("MESSAGE"))
                        usec = int(item.get("__REALTIME_TIMESTAMP") or (time.time() * 1000000))
                        event_key = f"LNX-JNL-AUTH-{usec}"
                        if any(x.get("id") == event_key for x in self.login_attempts):
                            continue

                        # Check Accepted / Failed
                        m_acc = re.search(r"Accepted (?:password|publickey) for ([a-zA-Z0-9_\-\.]+) from ([0-9a-fA-F\.:]+)", msg)
                        m_fail = re.search(r"Failed password for (?:invalid user )?([a-zA-Z0-9_\-\.]+) from ([0-9a-fA-F\.:]+)", msg)

                        if m_acc:
                            u = m_acc.group(1)
                            ip = m_acc.group(2)
                            new_logins.append({
                                "id": event_key,
                                "timestamp": datetime.datetime.fromtimestamp(usec / 1000000.0).isoformat(),
                                "username": u,
                                "status": "SUCCESS",
                                "logon_type": "Remote SSH (Port 22)",
                                "source_ip": ip,
                                "failure_reason": "SSH Authentication Accepted",
                                "geo": geo_service.lookup(ip),
                                "severity": "INFO"
                            })
                        elif m_fail:
                            u = m_fail.group(1)
                            ip = m_fail.group(2)
                            new_logins.append({
                                "id": event_key,
                                "timestamp": datetime.datetime.fromtimestamp(usec / 1000000.0).isoformat(),
                                "username": u,
                                "status": "FAILED",
                                "logon_type": "Remote SSH (Port 22)",
                                "source_ip": ip,
                                "failure_reason": "SSH Bad Password / Credentials",
                                "geo": geo_service.lookup(ip),
                                "severity": "HIGH"
                            })
                    except Exception:
                        continue
        except Exception:
            pass

        if new_logins:
            with self.lock:
                for item in reversed(new_logins):
                    self.login_attempts.insert(0, item)
                self.login_attempts = self.login_attempts[:MAX_LOG_EVENTS]
            self._save_persisted_logs()

    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Retrieves currently logged-in host sessions via psutil and system tables."""
        sessions = []
        try:
            users = psutil.users()
            for u in users:
                t_str = datetime.datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M:%S") if u.started else "N/A"
                sessions.append({
                    "username": u.name,
                    "terminal": u.terminal or "Console",
                    "host": u.host or "Local Station",
                    "started": t_str,
                    "pid": u.pid,
                    "status": "ACTIVE"
                })
        except Exception as e:
            logger.debug(f"Failed to query active sessions: {e}")

        if not sessions:
            curr_user = os.getenv("USERNAME") or os.getenv("USER") or "Operator"
            sessions.append({
                "username": curr_user,
                "terminal": "Console (Interactive)",
                "host": socket.gethostname(),
                "started": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "pid": os.getpid(),
                "status": "ACTIVE"
            })

        return sessions

    def scan_all_logs_for_threats(self) -> Dict[str, Any]:
        """Triggers an active comprehensive threat analysis across all system and security logs."""
        # 1. Fetch fresh system logs
        sys_logs = self.get_system_logs(limit=200)

        # 2. Harvest security channels
        if self.is_windows and HAS_WIN32EVTLOG:
            self._harvest_windows_security_channel()
        elif self.is_linux:
            self._harvest_linux_security_logs()

        # 3. Harvest logins
        self._harvest_os_logins()

        # 4. Scan all records with LogThreatDetector
        os_mode = "windows" if self.is_windows else "linux"
        new_threats = log_threat_detector.scan_log_batch(sys_logs, os_type=os_mode)
        for t in new_threats:
            self.add_security_event(t)

        all_threats = log_threat_detector.get_detected_threats(limit=50)
        stats = self.get_summary_stats()

        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "os": self.system_info.get("os"),
            "scanned_system_events": len(sys_logs),
            "threats_discovered_now": len(new_threats),
            "total_active_threats": len(all_threats),
            "threats": all_threats,
            "stats": stats
        }

    def get_summary_stats(self) -> Dict[str, Any]:
        """Calculates fast real-time KPI counts across system, security, and authentication."""
        sys_logs = self.system_logs_cache or []
        err_count = sum(1 for e in sys_logs if e.get("level") in ("ERROR", "CRITICAL"))
        warn_count = sum(1 for e in sys_logs if e.get("level") == "WARNING")

        with self.lock:
            sec_incidents = sum(1 for s in self.security_logs if s.get("severity") in ("HIGH", "CRITICAL"))
            total_logins = len(self.login_attempts)
            failed_logins = sum(1 for a in self.login_attempts if a.get("status") == "FAILED")
            successful_logins = sum(1 for a in self.login_attempts if a.get("status") == "SUCCESS")

        active_sessions = len(self.get_active_sessions())

        # Brute-force risk calculation
        brute_force_active = any(
            s.get("action") in ("BRUTE_FORCE_SUSPECTED", "SSH_BRUTE_FORCE", "SUDO_BRUTE_FORCE") for s in self.security_logs[:15]
        ) or (failed_logins >= 3)

        return {
            "system_errors": err_count,
            "system_warnings": warn_count,
            "security_incidents": sec_incidents,
            "total_logins_24h": total_logins,
            "failed_logins_24h": failed_logins,
            "successful_logins_24h": successful_logins,
            "active_sessions": active_sessions,
            "brute_force_risk": "HIGH_ALERT" if brute_force_active else ("ELEVATED" if failed_logins > 0 else "NORMAL")
        }


# Global singleton instance
log_monitor = LogMonitor()
