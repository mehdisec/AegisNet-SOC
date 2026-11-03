"""
AegisNet SOC - Unified System Log Threat Detection Engine (Windows & Linux)
Real-time behavioral and signature-based log analysis for detecting:
- Brute-Force & Credential Stuffing (SSH, RDP, Sudo, Console)
- Privilege Escalation & Unauthorized Elevation (Sudoers, Admin Groups, Polkit)
- Defense Evasion & Log Tampering (Audit logs cleared, Firewall flushed, Services stopped)
- Malicious & Living-off-the-Land (LotL) Execution (PowerShell bypass, vssadmin, reverse shells)
- Memory Corruption & Exploit Crashes (Kernel segfaults, OOM Killer, Kernel tainting)
- Firewall & Network Drop Anomalies
"""

import re
import time
import socket
import logging
import datetime
from typing import Dict, Any, List, Optional, Tuple
from collections import deque, defaultdict

from backend.geoip_service import geo_service

logger = logging.getLogger("aegis.log_threat_detector")

# Threat Categories
CAT_AUTH = "AUTHENTICATION"
CAT_PRIV = "PRIVILEGE"
CAT_EVASION = "DEFENSE_EVASION"
CAT_EXEC = "PROCESS"
CAT_EXPLOIT = "EXPLOIT"
CAT_FIREWALL = "FIREWALL"
CAT_AUDIT = "AUDIT"

# Severities
SEV_CRITICAL = "CRITICAL"
SEV_HIGH = "HIGH"
SEV_MEDIUM = "MEDIUM"
SEV_LOW = "LOW"
SEV_INFO = "INFO"


class ThreatRule:
    def __init__(
        self,
        rule_id: str,
        name: str,
        category: str,
        severity: str,
        mitre_id: str,
        description_template: str,
        action_tag: str
    ):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.mitre_id = mitre_id
        self.description_template = description_template
        self.action_tag = action_tag


class LogThreatDetector:
    def __init__(self):
        # Rolling failure tracker for brute-force rate calculations: key -> deque of timestamps
        # Key is typically (ip, username, protocol/service)
        self.failed_logins: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self.detected_threats: List[Dict[str, Any]] = []
        self.seen_signatures = set()

        # Compile regex patterns for fast analysis
        self._init_regex_rules()

    def _init_regex_rules(self):
        """Compiles regexes for signature and heuristic detection across Windows & Linux logs."""
        # 1. Linux Sudo & Privilege Escalation
        self.re_linux_sudo_fail = re.compile(r"sudo:\s+([a-zA-Z0-9_\-\.]+)\s+:\s+(\d+)\s+incorrect password attempts", re.IGNORECASE)
        self.re_linux_sudo_not_sudoers = re.compile(r"sudo:\s+([a-zA-Z0-9_\-\.]+)\s+:\s+user NOT in sudoers", re.IGNORECASE)
        self.re_linux_sudo_shell = re.compile(r"sudo:\s+.*COMMAND=.*(/bin/(ba)?sh|/bin/zsh|/usr/bin/python|su\s+-?|/bin/dash)", re.IGNORECASE)
        self.re_linux_failed_su = re.compile(r"FAILED SU \(to root\) ([a-zA-Z0-9_\-\.]+)", re.IGNORECASE)
        self.re_linux_polkit_fail = re.compile(r"polkit.*(?:action.*rejected|authorization failed)", re.IGNORECASE)

        # 2. Linux SSH & Auth
        self.re_linux_ssh_failed = re.compile(r"Failed password for (?:invalid user )?([a-zA-Z0-9_\-\.]+) from ([0-9a-fA-F\.:]+)", re.IGNORECASE)
        self.re_linux_ssh_invalid_user = re.compile(r"Invalid user ([a-zA-Z0-9_\-\.]+) from ([0-9a-fA-F\.:]+)", re.IGNORECASE)
        self.re_linux_ssh_max_attempts = re.compile(r"error: maximum authentication attempts exceeded for (?:invalid user )?([a-zA-Z0-9_\-\.]+) from ([0-9a-fA-F\.:]+)", re.IGNORECASE)
        self.re_linux_ssh_disconnect_preauth = re.compile(r"Received disconnect from ([0-9a-fA-F\.:]+).*:.*\[preauth\]", re.IGNORECASE)

        # 3. Defense Evasion & Service Tampering (Linux & Windows)
        self.re_firewall_tamper = re.compile(r"(iptables\s+-F|ufw\s+disable|systemctl\s+(stop|disable)\s+(ufw|firewalld|iptables|fail2ban|auditd|apparmor))", re.IGNORECASE)
        self.re_log_tamper = re.compile(r"(rm\s+-rf\s+/var/log|truncate\s+.*(/var/log/|wtmp|btmp)|log\s+cleared)", re.IGNORECASE)

        # 4. Code Injections & Reverse Shells (Linux & Windows)
        self.re_reverse_shell = re.compile(r"(bash\s+-i\s+>&|nc\s+-e\s+/bin/|python.*pty\.spawn|socat\s+exec:)", re.IGNORECASE)
        self.re_pipe_to_shell = re.compile(r"(curl|wget)\s+.*\|\s*(ba)?sh", re.IGNORECASE)

        # 5. Windows PowerShell / LotL Execution
        self.re_win_ps_bypass = re.compile(r"(powershell|pwsh).*(?:-enc|-encodedcommand|-w\s+hidden|-executionpolicy\s+bypass|-nop|-noni)", re.IGNORECASE)
        self.re_win_shadow_copy = re.compile(r"(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled\s+No)", re.IGNORECASE)
        self.re_win_cred_dump = re.compile(r"(mimikatz|procdump.*lsass|comsvcs\.dll.*minidump|nanodump|sekurlsa)", re.IGNORECASE)
        self.re_win_recon = re.compile(r"(whoami\s+/priv|nltest\s+/dclist|net\s+localgroup\s+administrators\s+/add|net\s+user\s+.*\/add)", re.IGNORECASE)
        self.re_win_remote_dl = re.compile(r"(certutil.*-urlcache|bitsadmin.*/transfer)", re.IGNORECASE)

        # 6. Kernel Exploits & Crashes (Linux)
        self.re_linux_segfault = re.compile(r"kernel:.*\[\s*\d+\.\d+\]?\s*([a-zA-Z0-9_\-\.]+).*segfault at ([0-9a-fA-Fx]+)", re.IGNORECASE)
        self.re_linux_oom = re.compile(r"kernel:.*Out of memory:\s*Killed process\s*(\d+)\s*\(([^)]+)\)", re.IGNORECASE)
        self.re_linux_tainted = re.compile(r"kernel:.*(?:tainted.*module|module verification failed)", re.IGNORECASE)

        # 7. Firewall Drops
        self.re_ufw_drop = re.compile(r"\[UFW BLOCK\]\s+IN=.*SRC=([0-9a-fA-F\.:]+)\s+DST=([0-9a-fA-F\.:]+).*PROTO=([A-Z]+)\s+SPT=(\d+)\s+DPT=(\d+)", re.IGNORECASE)
        self.re_iptables_drop = re.compile(r"iptables.*DROP.*SRC=([0-9a-fA-F\.:]+).*DPT=(\d+)", re.IGNORECASE)

    def analyze_event(self, event: Dict[str, Any], os_type: str = "auto") -> Optional[Dict[str, Any]]:
        """
        Inspects an individual system, security, or authentication log record.
        Returns a structured Security Threat incident dict if malicious activity is identified.
        """
        if not event:
            return None

        msg = str(event.get("message") or "")
        source = str(event.get("source") or "")
        event_id = event.get("event_id")
        level = str(event.get("level") or "INFO").upper()
        now = time.time()
        timestamp = event.get("timestamp") or datetime.datetime.now().isoformat()

        # =====================================================================
        # 1. WINDOWS THREAT LOGIC
        # =====================================================================
        # Event ID 1102 / 104: Audit/System Log Cleared
        if event_id in (1102, "1102"):
            return self._build_incident(
                rule_id="WIN-DEF-001",
                name="Security Audit Log Cleared (Tampering Detected)",
                category=CAT_EVASION,
                severity=SEV_CRITICAL,
                mitre_id="T1070.001",
                description="The Windows Security Audit Log was cleared. This is a high-confidence indicator of attacker anti-forensics / defense evasion.",
                source_ip=event.get("computer") or "127.0.0.1",
                user=event.get("user") or "SYSTEM",
                action="AUDIT_LOG_CLEARED",
                raw_evidence=msg
            )

        if event_id in (104, "104"):
            return self._build_incident(
                rule_id="WIN-DEF-002",
                name="System Event Log Cleared",
                category=CAT_EVASION,
                severity=SEV_HIGH,
                mitre_id="T1070.001",
                description="The Windows System Event Log was cleared. Potential log destruction by attacker.",
                source_ip=event.get("computer") or "127.0.0.1",
                user=event.get("user") or "SYSTEM",
                action="SYSTEM_LOG_CLEARED",
                raw_evidence=msg
            )

        # Event ID 4740: Account Locked Out
        if event_id in (4740, "4740"):
            target_user = event.get("user") or self._extract_field(msg, "Target Account Name") or "Target Account"
            return self._build_incident(
                rule_id="WIN-AUTH-002",
                name=f"User Account Locked Out: {target_user}",
                category=CAT_AUTH,
                severity=SEV_HIGH,
                mitre_id="T1110.001",
                description=f"Account '{target_user}' was locked out after reaching the maximum failed password attempt threshold.",
                source_ip="127.0.0.1",
                user=target_user,
                action="ACCOUNT_LOCKOUT",
                raw_evidence=msg
            )

        # Event ID 4728 / 4732 / 4756: Member added to privileged local group
        if event_id in (4728, 4732, 4756, "4728", "4732", "4756"):
            return self._build_incident(
                rule_id="WIN-PRIV-001",
                name="Member Added to Privileged Security Group",
                category=CAT_PRIV,
                severity=SEV_HIGH,
                mitre_id="T1078.002",
                description=f"Privilege escalation event: A member was added to an administrative or security-enabled group: {msg[:180]}",
                source_ip="127.0.0.1",
                user=event.get("user") or "SYSTEM",
                action="ADMIN_GROUP_MEMBER_ADDED",
                raw_evidence=msg
            )

        # Event ID 7036 / 7045: Critical Security Service Stopped / Modified
        if "Service Control Manager" in source or event_id in (7036, 7045, "7036", "7045"):
            m_lower = msg.lower()
            if any(svc in m_lower for svc in ("windefend", "mpssvc", "sense", "wuauserv", "security center", "firewall")):
                if "stopped" in m_lower or "disabled" in m_lower or event_id in (7045, "7045"):
                    return self._build_incident(
                        rule_id="WIN-DEF-003",
                        name="Core Security Service Stopped or Modified",
                        category=CAT_EVASION,
                        severity=SEV_HIGH,
                        mitre_id="T1562.001",
                        description=f"Core security subsystem service modification: {msg[:200]}",
                        source_ip="127.0.0.1",
                        user="SYSTEM",
                        action="SECURITY_SERVICE_STOPPED",
                        raw_evidence=msg
                    )

        # Windows Process Creation (Event 4688) & Command Line Inspections
        if event_id in (4688, "4688") or "powershell" in msg.lower() or "cmd.exe" in msg.lower():
            if self.re_win_ps_bypass.search(msg):
                return self._build_incident(
                    rule_id="WIN-EXEC-001",
                    name="Obfuscated PowerShell Execution Policy Bypass",
                    category=CAT_EXEC,
                    severity=SEV_HIGH,
                    mitre_id="T1059.001",
                    description=f"Suspicious PowerShell process spawned with encoded command or execution policy bypass: {msg[:220]}",
                    source_ip="127.0.0.1",
                    user=event.get("user") or "SYSTEM",
                    action="POWERSHELL_BYPASS",
                    raw_evidence=msg
                )

            if self.re_win_shadow_copy.search(msg):
                return self._build_incident(
                    rule_id="WIN-RANSOM-001",
                    name="Volume Shadow Copy Deletion (Ransomware Tactic)",
                    category=CAT_EVASION,
                    severity=SEV_CRITICAL,
                    mitre_id="T1490",
                    description=f"Inhibition of system recovery: Execution detected attempting to purge Volume Shadow Copies: {msg[:220]}",
                    source_ip="127.0.0.1",
                    user=event.get("user") or "SYSTEM",
                    action="SHADOW_COPY_DELETION",
                    raw_evidence=msg
                )

            if self.re_win_cred_dump.search(msg):
                return self._build_incident(
                    rule_id="WIN-CRED-001",
                    name="LSASS Memory Credential Dumping Attempt",
                    category=CAT_AUTH,
                    severity=SEV_CRITICAL,
                    mitre_id="T1003.001",
                    description=f"Known credential dumping pattern detected targeting LSASS process memory: {msg[:220]}",
                    source_ip="127.0.0.1",
                    user=event.get("user") or "SYSTEM",
                    action="CREDENTIAL_DUMPING_ATTEMPT",
                    raw_evidence=msg
                )

            if self.re_win_remote_dl.search(msg):
                return self._build_incident(
                    rule_id="WIN-LOTL-001",
                    name="Living-off-the-Land Ingress Tool Execution (certutil/bitsadmin)",
                    category=CAT_EXEC,
                    severity=SEV_MEDIUM,
                    mitre_id="T1105",
                    description=f"Native binary utilized for remote artifact staging or download: {msg[:220]}",
                    source_ip="127.0.0.1",
                    user=event.get("user") or "SYSTEM",
                    action="LOLBIN_REMOTE_STAGING",
                    raw_evidence=msg
                )

        # =====================================================================
        # 2. LINUX THREAT LOGIC
        # =====================================================================
        # Sudo Abuse & Privilege Escalation
        m_sudo_fail = self.re_linux_sudo_fail.search(msg)
        if m_sudo_fail:
            user = m_sudo_fail.group(1)
            count = m_sudo_fail.group(2)
            return self._build_incident(
                rule_id="LNX-PRIV-001",
                name=f"Repeated Sudo Password Failures: {user}",
                category=CAT_PRIV,
                severity=SEV_HIGH,
                mitre_id="T1548.003",
                description=f"User '{user}' failed sudo authentication {count} times. Possible privilege escalation brute force.",
                source_ip="127.0.0.1",
                user=user,
                action="SUDO_BRUTE_FORCE",
                raw_evidence=msg
            )

        m_not_sudoers = self.re_linux_sudo_not_sudoers.search(msg)
        if m_not_sudoers:
            user = m_not_sudoers.group(1)
            return self._build_incident(
                rule_id="LNX-PRIV-002",
                name=f"Unauthorized Sudo Elevation Attempt by {user}",
                category=CAT_PRIV,
                severity=SEV_HIGH,
                mitre_id="T1548.003",
                description=f"User '{user}' is not in sudoers but attempted executing privileged commands.",
                source_ip="127.0.0.1",
                user=user,
                action="UNAUTHORIZED_SUDO_ATTEMPT",
                raw_evidence=msg
            )

        m_sudo_shell = self.re_linux_sudo_shell.search(msg)
        if m_sudo_shell and ("root" in msg or "sudo" in source):
            return self._build_incident(
                rule_id="LNX-PRIV-003",
                name="Root Interactive Shell Invoked via Sudo",
                category=CAT_PRIV,
                severity=SEV_MEDIUM,
                mitre_id="T1548.003",
                description=f"Interactive privileged shell was spawned: {msg[:180]}",
                source_ip="127.0.0.1",
                user=event.get("user") or "root",
                action="ROOT_SHELL_SPAWNED",
                raw_evidence=msg
            )

        m_failed_su = self.re_linux_failed_su.search(msg)
        if m_failed_su:
            user = m_failed_su.group(1)
            return self._build_incident(
                rule_id="LNX-PRIV-004",
                name=f"Failed 'su' to Root by User {user}",
                category=CAT_PRIV,
                severity=SEV_HIGH,
                mitre_id="T1548.003",
                description=f"User '{user}' attempted switching to the root superuser account with an invalid password.",
                source_ip="127.0.0.1",
                user=user,
                action="FAILED_SU_ROOT",
                raw_evidence=msg
            )

        if self.re_linux_polkit_fail.search(msg):
            return self._build_incident(
                rule_id="LNX-PRIV-005",
                name="Polkit Authorization Failure / Privilege Rejection",
                category=CAT_PRIV,
                severity=SEV_MEDIUM,
                mitre_id="T1078.003",
                description=f"Polkit policy authority rejected privilege grant request: {msg[:180]}",
                source_ip="127.0.0.1",
                user=event.get("user") or "unknown",
                action="POLKIT_AUTH_REJECTED",
                raw_evidence=msg
            )

        # Linux SSH Brute-Force & Credential Attacks
        m_ssh_fail = self.re_linux_ssh_failed.search(msg)
        if m_ssh_fail:
            user = m_ssh_fail.group(1)
            src_ip = m_ssh_fail.group(2)
            key = f"ssh-fail:{src_ip}"
            self.failed_logins[key].append(now)

            # Filter window to last 300 seconds (5 mins)
            cutoff = now - 300
            recent = [t for t in self.failed_logins[key] if t > cutoff]

            if len(recent) >= 3:
                return self._build_incident(
                    rule_id="LNX-SSH-BRUTE-001",
                    name=f"SSH Brute-Force Attack from {src_ip}",
                    category=CAT_AUTH,
                    severity=SEV_CRITICAL,
                    mitre_id="T1110.001",
                    description=f"High-frequency SSH credential attack: {len(recent)} failed authentications detected against account '{user}' from {src_ip}.",
                    source_ip=src_ip,
                    user=user,
                    action="SSH_BRUTE_FORCE",
                    raw_evidence=msg
                )

        m_invalid_user = self.re_linux_ssh_invalid_user.search(msg)
        if m_invalid_user:
            user = m_invalid_user.group(1)
            src_ip = m_invalid_user.group(2)
            return self._build_incident(
                rule_id="LNX-SSH-ENUM-001",
                name=f"SSH Account Enumeration Scan from {src_ip}",
                category=CAT_AUTH,
                severity=SEV_HIGH,
                mitre_id="T1589.002",
                description=f"Remote host {src_ip} attempted authentication using non-existent username '{user}'.",
                source_ip=src_ip,
                user=user,
                action="SSH_USER_ENUMERATION",
                raw_evidence=msg
            )

        # Linux Firewall & Log Tampering
        if self.re_firewall_tamper.search(msg):
            return self._build_incident(
                rule_id="LNX-DEF-001",
                name="Firewall Rules Flushed or Disabled",
                category=CAT_EVASION,
                severity=SEV_CRITICAL,
                mitre_id="T1562.004",
                description=f"Defense evasion command detected disabling or flushing host firewall policies: {msg[:200]}",
                source_ip="127.0.0.1",
                user="root",
                action="FIREWALL_POLICY_TAMPERED",
                raw_evidence=msg
            )

        if self.re_log_tamper.search(msg):
            return self._build_incident(
                rule_id="LNX-DEF-002",
                name="System Audit Logs Truncated or Purged",
                category=CAT_EVASION,
                severity=SEV_CRITICAL,
                mitre_id="T1070.002",
                description=f"Host log files under /var/log or accounting databases were wiped: {msg[:200]}",
                source_ip="127.0.0.1",
                user="root",
                action="LINUX_LOGS_PURGED",
                raw_evidence=msg
            )

        # Code Injections & Reverse Shells
        if self.re_reverse_shell.search(msg):
            return self._build_incident(
                rule_id="UNIX-REV-001",
                name="Interactive Reverse Shell Spawning Pattern",
                category=CAT_EXEC,
                severity=SEV_CRITICAL,
                mitre_id="T1059.004",
                description=f"Command line contains classic reverse TCP shell payload syntax: {msg[:220]}",
                source_ip="127.0.0.1",
                user=event.get("user") or "unknown",
                action="REVERSE_SHELL_DETECTED",
                raw_evidence=msg
            )

        if self.re_pipe_to_shell.search(msg):
            return self._build_incident(
                rule_id="UNIX-EXEC-002",
                name="Remote Script Piped Directly into Shell Interpreter",
                category=CAT_EXEC,
                severity=SEV_HIGH,
                mitre_id="T1105",
                description=f"Insecure remote content downloaded and piped straight into shell: {msg[:220]}",
                source_ip="127.0.0.1",
                user=event.get("user") or "unknown",
                action="REMOTE_PIPE_TO_SHELL",
                raw_evidence=msg
            )

        # Linux Kernel Segfaults / Exploits / OOM
        m_seg = self.re_linux_segfault.search(msg)
        if m_seg:
            proc_name = m_seg.group(1)
            address = m_seg.group(2)
            return self._build_incident(
                rule_id="LNX-EXPLOIT-001",
                name=f"Process Segmentation Fault / Memory Crash: {proc_name}",
                category=CAT_EXPLOIT,
                severity=SEV_HIGH,
                mitre_id="T1203",
                description=f"Kernel logged segmentation fault in process '{proc_name}' at address {address}. Possible buffer overflow or memory corruption exploit.",
                source_ip="127.0.0.1",
                user="kernel",
                action="KERNEL_SEGFAULT_CRASH",
                raw_evidence=msg
            )

        m_oom = self.re_linux_oom.search(msg)
        if m_oom:
            pid = m_oom.group(1)
            name = m_oom.group(2)
            return self._build_incident(
                rule_id="LNX-EXPLOIT-002",
                name=f"OOM Killer Triggered: Terminated Process {name}",
                category=CAT_EXPLOIT,
                severity=SEV_MEDIUM,
                mitre_id="T1499",
                description=f"Out of Memory Killer terminated process {name} (PID {pid}) to prevent system exhaustion.",
                source_ip="127.0.0.1",
                user="kernel",
                action="OOM_KILLER_INVOKED",
                raw_evidence=msg
            )

        if self.re_linux_tainted.search(msg):
            return self._build_incident(
                rule_id="LNX-KERNEL-001",
                name="Kernel Tainted / Unsigned Kernel Module Loaded",
                category=CAT_PRIV,
                severity=SEV_HIGH,
                mitre_id="T1547.006",
                description=f"Kernel taint flag set. An out-of-tree, proprietary or unsigned kernel module was loaded: {msg[:180]}",
                source_ip="127.0.0.1",
                user="kernel",
                action="KERNEL_TAINT_WARNING",
                raw_evidence=msg
            )

        # Firewall Inbound Scan Blocks
        m_ufw = self.re_ufw_drop.search(msg)
        if m_ufw:
            src_ip = m_ufw.group(1)
            dpt = m_ufw.group(5)
            proto = m_ufw.group(3)
            return self._build_incident(
                rule_id="LNX-FW-001",
                name=f"Inbound Connection Dropped by Firewall: {src_ip}:{dpt}",
                category=CAT_FIREWALL,
                severity=SEV_MEDIUM,
                mitre_id="T1046",
                description=f"UFW / iptables dropped unsolicited inbound {proto} packet from {src_ip} targeting port {dpt}.",
                source_ip=src_ip,
                user="firewall",
                action="FIREWALL_PACKET_DROPPED",
                raw_evidence=msg
            )

        return None

    def _build_incident(
        self,
        rule_id: str,
        name: str,
        category: str,
        severity: str,
        mitre_id: str,
        description: str,
        source_ip: str,
        user: str,
        action: str,
        raw_evidence: str
    ) -> Dict[str, Any]:
        """Formats and registers a standard Security Incident with GeoIP intelligence."""
        sig_key = f"{rule_id}:{source_ip}:{user}:{action}"
        
        # Check if already triggered in current runtime window
        if sig_key in self.seen_signatures:
            return None
        self.seen_signatures.add(sig_key)

        now_ms = int(time.time() * 1000)
        incident_id = f"THREAT-{rule_id}-{now_ms % 1000000}"

        geo = geo_service.lookup(source_ip) if source_ip not in ("127.0.0.1", "LOCAL", "::1") else geo_service.host_location

        incident = {
            "id": incident_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "category": category,
            "severity": severity,
            "title": name,
            "description": description,
            "source_ip": source_ip,
            "user": user,
            "action": action,
            "mitre_id": mitre_id,
            "geo": geo,
            "evidence": raw_evidence[:280] if raw_evidence else ""
        }

        self.detected_threats.insert(0, incident)
        if len(self.detected_threats) > 200:
            self.detected_threats = self.detected_threats[:200]

        logger.info(f"[THREAT DETECTED] [{severity}] {name} (User: {user}, IP: {source_ip})")
        return incident

    def _extract_field(self, text: str, field_name: str) -> Optional[str]:
        """Extracts field values from Windows event XML or formatted messages."""
        m = re.search(rf"{field_name}[:=]\s*([^\r\n]+)", text, re.IGNORECASE)
        return m.group(1).strip() if m else None

    def scan_log_batch(self, logs: List[Dict[str, Any]], os_type: str = "auto") -> List[Dict[str, Any]]:
        """Scans a batch of log records and returns all newly discovered security threats."""
        discovered = []
        for event in logs:
            threat = self.analyze_event(event, os_type=os_type)
            if threat:
                discovered.append(threat)
        return discovered

    def get_detected_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns detected threat records."""
        return self.detected_threats[:limit]


# Global singleton instance
log_threat_detector = LogThreatDetector()

