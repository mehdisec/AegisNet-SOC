import io
import csv
import json
import time
import socket
import datetime
from typing import Dict, Any, List, Optional

from backend.os_detector import get_system_info
from backend.threat_intel import threat_intel

class ReportGenerator:
    def __init__(self, log_monitor, connection_monitor, firewall_manager):
        self.log_monitor = log_monitor
        self.conn_monitor = connection_monitor
        self.firewall = firewall_manager

    def generate_summary_data(self) -> Dict[str, Any]:
        """Gathers unified telemetry for executive reports."""
        sys_info = get_system_info()
        stats = self.log_monitor.get_summary_stats()
        intel_stats = threat_intel.get_stats()
        recent_incidents = self.log_monitor.get_security_logs(limit=50)
        recent_logins = self.log_monitor.get_login_attempts(limit=50)
        active_sessions = self.log_monitor.get_active_sessions()
        firewall_rules = self.firewall.get_blocked_list()
        current_conns = self.conn_monitor.capture_connections()

        # Count threat classifications
        malicious_conns = [
            c for c in current_conns.get("connections", [])
            if (c.get("threat_intel") or {}).get("verdict") == "MALICIOUS"
        ]
        suspicious_conns = [
            c for c in current_conns.get("connections", [])
            if (c.get("threat_intel") or {}).get("verdict") == "SUSPICIOUS"
        ]

        return {
            "metadata": {
                "report_id": f"REP-{int(time.time()*1000)}",
                "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "generator": "AegisNet SOC Intelligence Suite v1.5",
                "host": sys_info.get("hostname", socket.gethostname()),
                "os": f"{sys_info.get('os')} {sys_info.get('os_release')} ({sys_info.get('os_arch')})",
                "is_elevated": sys_info.get("is_admin", False)
            },
            "kpis": {
                "active_sockets": current_conns.get("active_count", 0),
                "established_sockets": current_conns.get("established_count", 0),
                "security_incidents_total": stats.get("security_incidents", 0),
                "system_errors": stats.get("system_errors", 0),
                "system_warnings": stats.get("system_warnings", 0),
                "total_logins_24h": stats.get("total_logins_24h", 0),
                "failed_logins_24h": stats.get("failed_logins_24h", 0),
                "brute_force_status": stats.get("brute_force_risk", "NORMAL"),
                "firewall_rules_active": len(firewall_rules),
                "threat_queries_total": intel_stats.get("total_queries", 0),
                "tor_nodes_indexed": intel_stats.get("tor_nodes_loaded", 0),
                "live_malicious_conns": len(malicious_conns),
                "live_suspicious_conns": len(suspicious_conns)
            },
            "recent_incidents": recent_incidents[:15],
            "recent_logins": recent_logins[:15],
            "active_sessions": active_sessions,
            "firewall_rules": firewall_rules[:15],
            "top_geographies": current_conns.get("top_countries", [])
        }

    # =========================================================================
    # 1. STANDALONE HTML EXECUTIVE / PRINT-READY PDF REPORT
    # =========================================================================
    def generate_executive_html(self) -> str:
        """Generates a high-fidelity, printable executive cybersecurity brief."""
        data = self.generate_summary_data()
        meta = data["metadata"]
        kpi = data["kpis"]
        incidents = data["recent_incidents"]
        logins = data["recent_logins"]
        sessions = data["active_sessions"]
        rules = data["firewall_rules"]
        top_geo = data["top_geographies"]

        incidents_rows = ""
        for inc in incidents:
            sev_color = "#e11d48" if inc.get("severity") in ("CRITICAL", "HIGH") else "#f59e0b"
            incidents_rows += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
              <td style="padding: 8px; font-family: monospace; font-size: 11px; color: #94a3b8;">{inc.get('timestamp','N/A')[:19]}</td>
              <td style="padding: 8px;"><span style="background: {sev_color}20; color: {sev_color}; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 10px; border: 1px solid {sev_color}40;">{inc.get('severity','INFO')}</span></td>
              <td style="padding: 8px; font-weight: bold; color: #f8fafc;">{inc.get('title','Incident')}</td>
              <td style="padding: 8px; font-size: 12px; color: #cbd5e1;">{inc.get('description','')}</td>
              <td style="padding: 8px; font-family: monospace; font-size: 11px; color: #38bdf8;">{inc.get('source_ip','N/A')}</td>
            </tr>
            """

        logins_rows = ""
        for log in logins:
            status_color = "#10b981" if log.get("status") == "SUCCESS" else "#f43f5e"
            logins_rows += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
              <td style="padding: 8px; font-family: monospace; font-size: 11px; color: #94a3b8;">{log.get('timestamp','N/A')[:19]}</td>
              <td style="padding: 8px; font-weight: bold; color: #f8fafc;">{log.get('username','Unknown')}</td>
              <td style="padding: 8px;"><span style="background: {status_color}20; color: {status_color}; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 10px; border: 1px solid {status_color}40;">{log.get('status','N/A')}</span></td>
              <td style="padding: 8px; font-size: 11px; color: #cbd5e1;">{log.get('logon_type','Interactive')}</td>
              <td style="padding: 8px; font-family: monospace; font-size: 11px; color: #38bdf8;">{log.get('source_ip','LOCAL')}</td>
              <td style="padding: 8px; font-size: 11px; color: #94a3b8;">{log.get('failure_reason','')}</td>
            </tr>
            """

        geo_items = "".join([
            f"<div style='display:inline-block; margin-right: 15px; margin-bottom: 8px; font-family: monospace; font-size: 12px;'><span style='color: #38bdf8;'>{g.get('country')}:</span> <strong style='color:#f8fafc;'>{g.get('count')} conns</strong> ({g.get('percentage')}%)</div>"
            for g in top_geo
        ]) or "<span style='color: #64748b;'>No remote WAN connections mapped.</span>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AegisNet SOC - Executive Incident & Threat Briefing ({meta['report_id']})</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      margin: 0;
      padding: 30px;
    }}
    .container {{
      max-width: 1050px;
      margin: 0 auto;
      background: #1e293b;
      padding: 35px;
      border-radius: 12px;
      border: 1px solid #334155;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid #06b6d4;
      padding-bottom: 20px;
      margin-bottom: 25px;
    }}
    .title-box h1 {{
      margin: 0;
      font-size: 26px;
      letter-spacing: 1px;
      color: #ffffff;
      font-family: monospace;
    }}
    .title-box h1 span {{ color: #22d3ee; }}
    .title-box p {{
      margin: 4px 0 0 0;
      color: #94a3b8;
      font-size: 12px;
      font-family: monospace;
    }}
    .meta-box {{
      text-align: right;
      font-size: 11px;
      font-family: monospace;
      color: #cbd5e1;
      line-height: 1.6;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 15px;
      margin-bottom: 30px;
    }}
    .kpi-card {{
      background: #0f172a;
      padding: 16px;
      border-radius: 8px;
      border: 1px solid #334155;
    }}
    .kpi-card .label {{
      font-size: 10px;
      font-family: monospace;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .kpi-card .value {{
      font-size: 24px;
      font-weight: bold;
      font-family: monospace;
      color: #f8fafc;
      margin-top: 5px;
    }}
    .section-title {{
      font-size: 16px;
      font-weight: bold;
      color: #22d3ee;
      font-family: monospace;
      margin-top: 30px;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      border-bottom: 1px solid #334155;
      padding-bottom: 6px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 12px;
    }}
    th {{
      background: #0f172a;
      color: #94a3b8;
      padding: 10px 8px;
      font-family: monospace;
      font-size: 11px;
      text-transform: uppercase;
    }}
    .print-btn {{
      background: #06b6d4;
      color: #0f172a;
      border: none;
      padding: 8px 16px;
      font-family: monospace;
      font-weight: bold;
      border-radius: 6px;
      cursor: pointer;
      font-size: 12px;
      transition: background 0.2s;
    }}
    .print-btn:hover {{
      background: #22d3ee;
    }}
    @media print {{
      body {{ background: #ffffff; color: #000000; padding: 0; }}
      .container {{ border: none; box-shadow: none; background: #ffffff; padding: 0; width: 100%; }}
      .print-btn {{ display: none; }}
      th, .kpi-card {{ background: #f1f5f9; border: 1px solid #cbd5e1; color: #000; }}
      .kpi-card .value, tr td {{ color: #000 !important; }}
      tr {{ border-bottom: 1px solid #e2e8f0 !important; }}
      .section-title {{ color: #0284c7; border-bottom: 1px solid #0284c7; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="title-box">
        <h1>AEGIS<span>NET</span> SOC EXECUTIVE BRIEFING</h1>
        <p>REAL-TIME HOST SECURITY AUDIT, THREAT INTELLIGENCE & INCIDENT SUMMARY</p>
      </div>
      <div class="meta-box">
        <div><strong>REPORT ID:</strong> {meta['report_id']}</div>
        <div><strong>HOST:</strong> {meta['host']} ({meta['os']})</div>
        <div><strong>ELEVATION:</strong> {'ADMINISTRATOR (Privileged)' if meta['is_elevated'] else 'STANDARD USER'}</div>
        <div><strong>DATE:</strong> {meta['generated_at']}</div>
        <div style="margin-top: 8px;"><button class="print-btn" onclick="window.print()">PRINT / SAVE AS PDF</button></div>
      </div>
    </div>

    <!-- KPI SUMMARY -->
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="label">Active Network Sockets</div>
        <div class="value" style="color: #38bdf8;">{kpi['active_sockets']} <span style="font-size:12px; color:#94a3b8;">({kpi['established_sockets']} est)</span></div>
      </div>
      <div class="kpi-card">
        <div class="label">Security Threats Audited</div>
        <div class="value" style="color: {'#f43f5e' if kpi['security_incidents_total'] > 0 else '#10b981'};">{kpi['security_incidents_total']}</div>
      </div>
      <div class="kpi-card">
        <div class="label">Brute-Force Risk Level</div>
        <div class="value" style="color: {'#f43f5e' if kpi['brute_force_status'] == 'HIGH_ALERT' else '#10b981'};">{kpi['brute_force_status']}</div>
      </div>
      <div class="kpi-card">
        <div class="label">Active Firewall Rules</div>
        <div class="value" style="color: #a855f7;">{kpi['firewall_rules_active']} Rules</div>
      </div>
    </div>

    <!-- GEOGRAPHY SUMMARY -->
    <div class="section-title">TOP CONNECTED GEOGRAPHIES & REMOTE WAN ENDPOINTS</div>
    <div style="background: #0f172a; padding: 12px 16px; border-radius: 8px; border: 1px solid #334155; margin-bottom: 20px;">
      {geo_items}
    </div>

    <!-- THREAT INCIDENTS -->
    <div class="section-title">CRITICAL SECURITY INCIDENTS & THREAT AUDIT ({len(incidents)})</div>
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Severity</th>
          <th>Title</th>
          <th>Description</th>
          <th>Source IP</th>
        </tr>
      </thead>
      <tbody>
        {incidents_rows or '<tr><td colspan="5" style="padding:15px; text-align:center; color:#64748b;">No high-severity security incidents recorded.</td></tr>'}
      </tbody>
    </table>

    <!-- AUTHENTICATION LOGS -->
    <div class="section-title">AUTHENTICATION & ACCESS LOGS ({len(logins)})</div>
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>User Account</th>
          <th>Status</th>
          <th>Logon Type</th>
          <th>Source IP</th>
          <th>Reason / Notes</th>
        </tr>
      </thead>
      <tbody>
        {logins_rows or '<tr><td colspan="6" style="padding:15px; text-align:center; color:#64748b;">No logon attempt records available.</td></tr>'}
      </tbody>
    </table>

    <div style="margin-top: 40px; padding-top: 15px; border-top: 1px solid #334155; text-align: center; font-size: 11px; font-family: monospace; color: #64748b;">
      AegisNet Security Operations Center &bull; Generated automatically on {meta['host']} &bull; Confidential Cyber Audit Briefing
    </div>
  </div>
</body>
</html>
"""
        return html

    # =========================================================================
    # 2. CSV EXPORT
    # =========================================================================
    def generate_csv(self, export_type: str = "incidents") -> str:
        """Generates RFC 4180 compliant CSV stream for spreadsheets or analysis."""
        output = io.StringIO()
        writer = csv.writer(output)

        if export_type == "incidents":
            writer.writerow(["Incident_ID", "Timestamp", "Category", "Severity", "Title", "Description", "Source_IP", "User", "Action", "Geo_Country"])
            incidents = self.log_monitor.get_security_logs(limit=250)
            for inc in incidents:
                geo = inc.get("geo") or {}
                writer.writerow([
                    inc.get("id", ""),
                    inc.get("timestamp", ""),
                    inc.get("category", ""),
                    inc.get("severity", ""),
                    inc.get("title", ""),
                    inc.get("description", ""),
                    inc.get("source_ip", ""),
                    inc.get("user", ""),
                    inc.get("action", ""),
                    geo.get("country", "")
                ])

        elif export_type == "logins":
            writer.writerow(["Record_ID", "Timestamp", "Username", "Status", "Logon_Type", "Source_IP", "Failure_Reason", "Country", "City"])
            logins = self.log_monitor.get_login_attempts(limit=250)
            for log in logins:
                geo = log.get("geo") or {}
                writer.writerow([
                    log.get("id", ""),
                    log.get("timestamp", ""),
                    log.get("username", ""),
                    log.get("status", ""),
                    log.get("logon_type", ""),
                    log.get("source_ip", ""),
                    log.get("failure_reason", ""),
                    geo.get("country", ""),
                    geo.get("city", "")
                ])

        elif export_type == "connections":
            writer.writerow(["Connection_ID", "PID", "Process", "Socket_Type", "Protocol", "Status", "Direction", "Local_IP", "Local_Port", "Remote_IP", "Remote_Port", "Remote_Country", "Threat_Verdict", "Threat_Score"])
            conns = self.conn_monitor.capture_connections().get("connections", [])
            for c in conns:
                dst = c.get("destination") or {}
                dst_geo = dst.get("geo") or {}
                threat = c.get("threat_intel") or {}
                writer.writerow([
                    c.get("id", ""),
                    c.get("pid", ""),
                    c.get("process", ""),
                    c.get("socket_type", ""),
                    c.get("protocol", ""),
                    c.get("status", ""),
                    c.get("direction", ""),
                    c.get("source", {}).get("ip", ""),
                    c.get("source", {}).get("port", ""),
                    dst.get("ip", ""),
                    dst.get("port", ""),
                    dst_geo.get("country", ""),
                    threat.get("verdict", "CLEAN"),
                    threat.get("score", 0)
                ])

        elif export_type == "firewall":
            writer.writerow(["Rule_ID", "IP_Address", "Reason", "Blocked_At", "Rule_Name", "Country"])
            rules = self.firewall.get_blocked_list()
            for r in rules:
                writer.writerow([
                    r.get("id", ""),
                    r.get("ip", ""),
                    r.get("reason", ""),
                    r.get("created_at", ""),
                    r.get("rule_name", ""),
                    r.get("geo", {}).get("country", "") if isinstance(r.get("geo"), dict) else ""
                ])

        return output.getvalue()

    # =========================================================================
    # 3. SIEM ARCSIGHT CEF & SYSLOG EXPORT
    # =========================================================================
    def generate_siem_cef(self) -> str:
        """Generates ArcSight Common Event Format (CEF) log file for Splunk, QRadar, Elastic."""
        incidents = self.log_monitor.get_security_logs(limit=150)
        lines = []
        host = socket.gethostname()

        for inc in incidents:
            # CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
            sev_num = 1
            if inc.get("severity") == "CRITICAL": sev_num = 10
            elif inc.get("severity") == "HIGH": sev_num = 8
            elif inc.get("severity") == "MEDIUM": sev_num = 5

            eid = inc.get("id", "SEC-001")
            name = inc.get("title", "Security Incident")
            src = inc.get("source_ip", "127.0.0.1")
            usr = inc.get("user", "SYSTEM")
            msg = inc.get("description", "").replace("|", "-")
            act = inc.get("action", "ALERT")

            cef_line = f"CEF:0|AegisNet|SOC-Defender|1.5|{act}|{name}|{sev_num}|src={src} suser={usr} msg={msg} dhost={host} externalId={eid}"
            lines.append(cef_line)

        return "\n".join(lines)
