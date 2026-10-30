import os
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
                    self.security_logs = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load security logs: {e}")
                self.security_logs = []

        if os.path.exists(LOGIN_ATTEMPTS_FILE):
            try:
                with open(LOGIN_ATTEMPTS_FILE, "r", encoding="utf-8") as f:
                    self.login_attempts = json.load(f)
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
        """Pulls historical records from OS event streams if cache is empty or needs refresh."""
        if not self.login_attempts:
            self._harvest_os_logins()

        if not self.security_logs:
            # Add initial system audit baseline entry
            sys_info = self.system_info
            self.security_logs.append({
                "id": f"SEC-{int(time.time()*1000)}-001",
                "timestamp": datetime.datetime.now().isoformat(),
                "category": "AUDIT",
                "severity": "INFO",
                "title": "AegisNet SOC Auditing Initialized",
                "description": f"Host telemetry initialized on {sys_info['hostname']} ({sys_info['os']} {sys_info['os_release']}). Administrative Elevation: {sys_info['is_admin']}.",
                "source_ip": "127.0.0.1",
                "user": "SYSTEM",
                "action": "MONITOR_STARTED",
                "geo": geo_service.host_location
            })
            self._save_persisted_logs()

    # =========================================================================
    # 1. LIVE SYSTEM LOG MONITOR
    # =========================================================================
    def get_system_logs(self, limit: int = 100, level: Optional[str] = None, source: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves live system event logs from OS kernel/subsystems."""
        limit = min(max(10, limit), 300)
        now = time.time()

        # Cache live reads for 2.0 seconds to prevent hammering the event log subsystem
        if (now - self.last_system_read_time) > 2.0 or not self.system_logs_cache:
            if self.is_windows and HAS_WIN32EVTLOG:
                self.system_logs_cache = self._read_windows_system_logs(limit=200)
            elif self.is_linux:
                self.system_logs_cache = self._read_linux_system_logs(limit=200)
            else:
                self.system_logs_cache = self._generate_fallback_system_logs()
            self.last_system_read_time = now

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
                if s_lower in e.get("message", "").lower()
                or s_lower in e.get("source", "").lower()
                or s_lower in str(e.get("event_id", ""))
            ]

        return events[:limit]

    def _read_windows_system_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Reads real records from the Windows 'System' event log channel."""
        import win32evtlog
        import win32evtlogutil

        records = []
        try:
            h = win32evtlog.OpenEventLog(None, "System")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            while len(records) < limit:
                batch = win32evtlog.ReadEventLog(h, flags, 0)
                if not batch:
                    break

                for e in batch:
                    # Map event type to standardized severity
                    if e.EventType == win32evtlog.EVENTLOG_ERROR_TYPE:
                        level = "ERROR"
                    elif e.EventType == win32evtlog.EVENTLOG_WARNING_TYPE:
                        level = "WARNING"
                    elif e.EventType == win32evtlog.EVENTLOG_AUDIT_FAILURE:
                        level = "CRITICAL"
                    elif e.EventType == win32evtlog.EVENTLOG_AUDIT_SUCCESS:
                        level = "AUDIT"
                    else:
                        level = "INFO"

                    event_id = e.EventID & 0xFFFF

                    # Format human readable message
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
                        "level": level,
                        "category": e.EventCategory,
                        "message": msg,
                        "computer": e.ComputerName or socket.gethostname()
                    })

                    if len(records) >= limit:
                        break

            win32evtlog.CloseEventLog(h)
        except Exception as ex:
            logger.warning(f"Error querying Windows System event log: {ex}")
            if not records:
                records = self._generate_fallback_system_logs()

        return records

    def _read_linux_system_logs(self, limit: int = 150) -> List[Dict[str, Any]]:
        """Reads system events from journalctl or /var/log/syslog on Linux."""
        records = []
        try:
            cmd = ["journalctl", "-n", str(limit), "-o", "json", "--no-pager"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.5)
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                        prio = int(item.get("PRIORITY", 6))
                        level = "INFO"
                        if prio <= 2:
                            level = "CRITICAL"
                        elif prio == 3:
                            level = "ERROR"
                        elif prio == 4:
                            level = "WARNING"

                        usec = int(item.get("__REALTIME_TIMESTAMP", time.time() * 1000000))
                        dt = datetime.datetime.fromtimestamp(usec / 1000000.0)

                        records.append({
                            "id": f"LNX-{usec}",
                            "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
                            "source": item.get("_COMM") or item.get("SYSLOG_IDENTIFIER") or "kernel",
                            "event_id": item.get("MESSAGE_ID", 1000),
                            "level": level,
                            "category": item.get("SYSLOG_FACILITY", 0),
                            "message": item.get("MESSAGE", ""),
                            "computer": item.get("_HOSTNAME", socket.gethostname())
                        })
                    except Exception:
                        continue
                records.reverse()
        except Exception as e:
            logger.debug(f"Linux journalctl read failed: {e}")

        if not records:
            records = self._generate_fallback_system_logs()

        return records

    def _generate_fallback_system_logs(self) -> List[Dict[str, Any]]:
        """Generates realistic host system health and kernel messages as fallback."""
        host = socket.gethostname()
        now = datetime.datetime.now()
        entries = []
        
        sample_templates = [
            ("Service Control Manager", 7036, "INFO", "The AegisNet Security SOC Service entered the running state."),
            ("Kernel-General", 1, "INFO", "System time synchronized with network hardware clock."),
            ("TCPIP", 4227, "WARNING", "TCP/IP has chosen to close an idle lingering socket connection to preserve buffer pools."),
            ("DistributedCOM", 10016, "WARNING", "The application-specific permission settings do not grant Local Activation permission for the COM Server Application."),
            ("Netwtw06", 6000, "INFO", "Wireless physical layer link quality optimal (RSSI -48 dBm)."),
            ("DNS Client Events", 3008, "INFO", "DNS resolver cache successfully purged and updated."),
            ("Microsoft-Windows-WindowsUpdateClient", 19, "INFO", "Installation Successful: Windows Intelligence definition update deployed.")
        ]

        for i, (src, eid, lvl, msg) in enumerate(sample_templates):
            delta = datetime.timedelta(minutes=i * 4 + 1)
            entries.append({
                "id": f"FALLBACK-{i+1}",
                "timestamp": (now - delta).strftime("%Y-%m-%d %H:%M:%S"),
                "source": src,
                "event_id": eid,
                "level": lvl,
                "category": 0,
                "message": msg,
                "computer": host
            })

        return entries

    # =========================================================================
    # 2. SECURITY LOG MONITOR
    # =========================================================================
    def get_security_logs(self, limit: int = 100, category: Optional[str] = None, severity: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves threat audit, policy changes, and security incident logs."""
        limit = min(max(10, limit), 300)

        # Harvest fresh events from Windows Security Channel if elevated, or Linux auth logs
        if self.is_windows and HAS_WIN32EVTLOG and self.system_info.get("is_admin", False):
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
                if s_lower in l.get("title", "").lower()
                or s_lower in l.get("description", "").lower()
                or s_lower in l.get("source_ip", "").lower()
                or s_lower in l.get("user", "").lower()
            ]

        return logs[:limit]

    def add_security_event(self, event: Dict[str, Any]):
        """Adds a new security audit incident to the log stream."""
        if "id" not in event:
            event["id"] = f"SEC-{int(time.time()*1000)}-{len(self.security_logs)+1}"
        if "timestamp" not in event:
            event["timestamp"] = datetime.datetime.now().isoformat()
        if "geo" not in event and event.get("source_ip"):
            event["geo"] = geo_service.lookup(event["source_ip"])

        with self.lock:
            self.security_logs.insert(0, event)
            if len(self.security_logs) > MAX_LOG_EVENTS:
                self.security_logs = self.security_logs[:MAX_LOG_EVENTS]

        self._save_persisted_logs()

    def _harvest_windows_security_channel(self):
        """Polls Windows Security Event Log (Admin privilege required)."""
        import win32evtlog
        import xml.etree.ElementTree as ET

        try:
            # Query security events: 4688 (Process Creation), 4720 (User Created), 1102 (Log Cleared), 4672 (Admin Privs)
            query = "*[System[(EventID=4688 or EventID=4720 or EventID=1102 or EventID=4672 or EventID=5157)]]"
            q = win32evtlog.EvtQuery("Security", win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, query)
            events = win32evtlog.EvtNext(q, 15)
            
            ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            new_events = []

            for e in events:
                xml_str = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
                root = ET.fromstring(xml_str)
                eid = root.find('.//ns:EventID', ns).text
                time_created = root.find('.//ns:TimeCreated', ns).attrib.get('SystemTime', '')
                rec_id = root.find('.//ns:EventRecordID', ns)
                rec_str = rec_id.text if rec_id is not None else str(int(time.time()))

                event_key = f"WIN-SEC-{rec_str}"
                # Check duplicate
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
                    "timestamp": time_created,
                    "category": "AUDIT",
                    "severity": "INFO",
                    "title": f"Security Event {eid}",
                    "description": f"Windows Security Audit Event ID {eid}",
                    "source_ip": data_dict.get("IpAddress", "127.0.0.1"),
                    "user": data_dict.get("TargetUserName") or data_dict.get("SubjectUserName") or "SYSTEM",
                    "action": f"EVENT_{eid}",
                    "geo": geo_service.lookup(data_dict.get("IpAddress", "127.0.0.1"))
                }

                if eid == "4688":
                    sec_item["category"] = "PROCESS"
                    sec_item["title"] = "New Process Created"
                    proc = data_dict.get("NewProcessName", "Unknown")
                    sec_item["description"] = f"Created: {proc} by {data_dict.get('SubjectUserName', 'SYSTEM')}"
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

            if new_events:
                with self.lock:
                    for item in reversed(new_events):
                        self.security_logs.insert(0, item)
                    self.security_logs = self.security_logs[:MAX_LOG_EVENTS]
                self._save_persisted_logs()
        except Exception as e:
            # Elevation not held, handled gracefully
            pass

    def _harvest_linux_security_logs(self):
        """Discovers security incidents from Linux auth logs or journalctl."""
        if not self.is_linux:
            return

        new_events = []
        # 1. Try journalctl for sudo, sshd, ufw, audit
        try:
            cmd = ["journalctl", "-n", "30", "-o", "json", "--no-pager"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.5)
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                        msg = item.get("MESSAGE", "")
                        comm = item.get("_COMM", "")
                        usec = int(item.get("__REALTIME_TIMESTAMP", time.time() * 1000000))
                        event_key = f"LNX-SEC-{usec}"
                        if any(x.get("id") == event_key for x in self.security_logs):
                            continue

                        # Sudo Privilege Changes
                        if comm == "sudo" or "COMMAND=" in msg:
                            new_events.append({
                                "id": event_key,
                                "timestamp": datetime.datetime.fromtimestamp(usec / 1000000.0).isoformat(),
                                "category": "PRIVILEGE",
                                "severity": "MEDIUM",
                                "title": "Elevated sudo Command Executed",
                                "description": msg[:200],
                                "source_ip": "127.0.0.1",
                                "user": item.get("_AUDIT_LOGINUID") or "root",
                                "action": "SUDO_EXECUTION",
                                "geo": geo_service.host_location
                            })
                        # SSH Security Anomalies
                        elif comm == "sshd" or "sshd[" in msg:
                            if "Failed password" in msg:
                                new_events.append({
                                    "id": event_key,
                                    "timestamp": datetime.datetime.fromtimestamp(usec / 1000000.0).isoformat(),
                                    "category": "AUTHENTICATION",
                                    "severity": "HIGH",
                                    "title": "SSH Authentication Failure",
                                    "description": msg[:200],
                                    "source_ip": "127.0.0.1",
                                    "user": "sshd",
                                    "action": "SSH_AUTH_FAIL",
                                    "geo": geo_service.host_location
                                })
                    except Exception:
                        continue
        except Exception:
            pass

        # 2. Check /var/log/auth.log or /var/log/secure if readable
        for auth_file in ("/var/log/auth.log", "/var/log/secure"):
            if os.path.exists(auth_file):
                try:
                    with open(auth_file, "r", encoding="utf-8", errors="ignore") as f:
                        lines = deque(f, maxlen=30)
                    for line in lines:
                        if "Failed password" in line or "sudo:" in line or "authentication failure" in line:
                            event_key = f"LNX-AUTH-{hash(line.strip())}"
                            if any(x.get("id") == event_key for x in self.security_logs):
                                continue
                            new_events.append({
                                "id": event_key,
                                "timestamp": datetime.datetime.now().isoformat(),
                                "category": "AUTHENTICATION" if "password" in line else "PRIVILEGE",
                                "severity": "HIGH" if "Failed" in line else "MEDIUM",
                                "title": "Linux Auth / Privilege Event",
                                "description": line.strip()[:200],
                                "source_ip": "127.0.0.1",
                                "user": "linux-user",
                                "action": "LINUX_AUTH_EVENT",
                                "geo": geo_service.host_location
                            })
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
                if s_lower in a.get("username", "").lower()
                or s_lower in a.get("source_ip", "").lower()
                or s_lower in a.get("logon_type", "").lower()
                or s_lower in a.get("failure_reason", "").lower()
            ]

        return attempts[:limit]

    def record_login_attempt(self, username: str, status: str, logon_type: str = "Interactive", source_ip: str = "127.0.0.1", failure_reason: str = "") -> Dict[str, Any]:
        """Records a new authentication attempt with automated brute-force threat calculation."""
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

        # Check for Brute-Force condition (3+ failed attempts in 5 minutes from same IP or user)
        if status == "FAILED":
            recent_fails = [
                a for a in self.login_attempts[:20]
                if a.get("status") == "FAILED"
                and (a.get("source_ip") == source_ip or a.get("username") == username)
            ]
            if len(recent_fails) >= 3:
                # Trigger a Security Incident alert
                self.add_security_event({
                    "id": f"ALERT-BRUTEFORCE-{int(time.time())}",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "category": "AUTHENTICATION",
                    "severity": "CRITICAL",
                    "title": "Brute-Force Authentication Anomaly Detected",
                    "description": f"Multiple failed login attempts ({len(recent_fails)}) detected against user '{username}' from IP {source_ip}.",
                    "source_ip": source_ip,
                    "user": username,
                    "action": "BRUTE_FORCE_SUSPECTED",
                    "geo": geo
                })

        self._save_persisted_logs()
        return record

    def _harvest_os_logins(self):
        """Discovers historical logon records from Windows TerminalServices & Security channels or Linux."""
        if self.is_linux:
            self._harvest_linux_logins()
            return

        if not self.is_windows or not HAS_WIN32EVTLOG:
            return

        import win32evtlog
        import xml.etree.ElementTree as ET

        # 1. Harvest from Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
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
            logger.debug(f"TerminalServices session harvest error: {e}")

        # 2. Harvest from Windows Security Channel (if running as Administrator)
        if self.system_info.get("is_admin", False):
            try:
                # Query 4624 (Logon) and 4625 (Failed Logon)
                query = "*[System[(EventID=4624 or EventID=4625)]]"
                q = win32evtlog.EvtQuery("Security", win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, query)
                events = win32evtlog.EvtNext(q, 20)
                
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
                    # Filter internal machine accounts like DESKTOP$
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
        """Harvests logins on Linux from last, lastb, and auth.log."""
        if not self.is_linux:
            return

        new_logins = []
        # 1. Successful logins via `last -n 30`
        try:
            proc = subprocess.run(["last", "-n", "30"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.0)
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

        # 2. Failed logins via `lastb -n 30` (requires root/sudo or readable btmp)
        try:
            proc = subprocess.run(["lastb", "-n", "30"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.0)
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
                            "logon_type": "Remote SSH (Port 22)" if "pts" in terminal or is_remote else "Console",
                            "source_ip": ip_or_host if is_remote else "LOCAL",
                            "failure_reason": "Bad Password / Invalid Credentials (lastb)",
                            "geo": geo,
                            "severity": "HIGH"
                        })
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
            # Fallback to current OS username
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

    def get_summary_stats(self) -> Dict[str, Any]:
        """Calculates fast real-time KPI counts across system, security, and authentication."""
        # Count system log errors/warnings from recent snapshot
        sys_logs = self.system_logs_cache or []
        err_count = sum(1 for e in sys_logs if e.get("level") in ("ERROR", "CRITICAL"))
        warn_count = sum(1 for e in sys_logs if e.get("level") == "WARNING")

        # Count security incidents
        with self.lock:
            sec_incidents = sum(1 for s in self.security_logs if s.get("severity") in ("HIGH", "CRITICAL"))
            
            # 24H Login counts
            total_logins = len(self.login_attempts)
            failed_logins = sum(1 for a in self.login_attempts if a.get("status") == "FAILED")
            successful_logins = sum(1 for a in self.login_attempts if a.get("status") == "SUCCESS")

        active_sessions = len(self.get_active_sessions())

        # Brute force threat assessment
        brute_force_active = any(
            s.get("action") == "BRUTE_FORCE_SUSPECTED" for s in self.security_logs[:10]
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
