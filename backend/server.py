import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import Set, Optional, List, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel, Field

from backend.config import SERVER_HOST, SERVER_PORT, WS_BROADCAST_INTERVAL, FRONTEND_DIR
from backend.os_detector import get_system_info
from backend.network_monitor import network_monitor
from backend.firewall_manager import firewall_manager
from backend.geoip_service import geo_service
from backend.log_monitor import log_monitor
from backend.threat_intel import threat_intel
from backend.report_generator import ReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("aegis.server")

# Active WebSocket Connections Pool
class ConnectionHub:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        
        json_str = json.dumps(message)
        dead_connections = set()
        for conn in self.active_connections:
            try:
                await conn.send_text(json_str)
            except Exception:
                dead_connections.add(conn)

        for dead in dead_connections:
            self.active_connections.discard(dead)

hub = ConnectionHub()

# Background broadcast loop
async def broadcast_loop():
    logger.info("Starting background network telemetry and log broadcast loop...")
    while True:
        try:
            if hub.active_connections:
                # Capture connection and telemetry snapshot
                data = network_monitor.capture_connections()
                log_stats = log_monitor.get_summary_stats()
                payload = {
                    "type": "TELEMETRY_UPDATE",
                    "data": data,
                    "log_stats": log_stats
                }
                await hub.broadcast(payload)
        except Exception as e:
            logger.error(f"Error in broadcast loop: {e}", exc_info=True)

        await asyncio.sleep(WS_BROADCAST_INTERVAL)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("AegisNet Security Monitor starting up...")
    sys_info = get_system_info()
    logger.info(f"Host OS: {sys_info['os']} ({sys_info['os_release']}) | Admin Privileges: {sys_info['is_admin']}")
    logger.info(f"Firewall Backend: {sys_info['firewall_tool']}")
    
    # Start background broadcast task
    task = asyncio.create_task(broadcast_loop())
    yield
    # Shutdown
    task.cancel()
    logger.info("AegisNet Server shutting down...")

app = FastAPI(
    title="AegisNet Real-Time Threat & Network Security Monitor",
    description="Production-grade real-time network connection tracker, dynamic world map visualizer, and firewall control platform.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for API consumers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic Request Models
class TerminateRequest(BaseModel):
    pid: int = Field(..., description="Process ID to terminate")

class BlockIPRequest(BaseModel):
    ip: str = Field(..., description="IP address to block permanently")
    reason: str = Field(default="Security Operator Action", description="Audit note/reason for block")

class UnblockIPRequest(BaseModel):
    ip: str = Field(..., description="IP address to unblock")

class ThreatScanResponse(BaseModel):
    timestamp: str
    os: Optional[str] = None
    scanned_system_events: int
    threats_discovered_now: int
    total_active_threats: int

# REST Endpoints
@app.get("/api/system/status")
async def api_system_status():
    """Returns comprehensive host OS and network agent status."""
    info = get_system_info()
    info["host_location"] = geo_service.host_location
    return info

@app.get("/api/connections/active")
async def api_active_connections():
    """Returns a single snapshot of active connections and telemetry."""
    return network_monitor.capture_connections()

@app.get("/api/geoip/lookup/{ip}")
async def api_geoip_lookup(ip: str):
    """Inspects detailed GeoIP, ASN, and organizational data for a specific IP."""
    rec = geo_service.lookup(ip)
    return rec

@app.get("/api/firewall/rules")
async def api_get_firewall_rules():
    """Retrieves all registered firewall block rules."""
    return {
        "rules": firewall_manager.get_blocked_list()
    }

@app.post("/api/actions/terminate")
async def api_terminate_process(req: TerminateRequest):
    """Terminates a process by PID."""
    result = firewall_manager.terminate_process(req.pid)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to terminate process"))
    
    # Audit process kill in security logs
    log_monitor.add_security_event({
        "category": "PROCESS",
        "severity": "WARNING",
        "title": "Process Terminated by SOC Operator",
        "description": f"Process PID {req.pid} was terminated via AegisNet dashboard.",
        "source_ip": "127.0.0.1",
        "user": "SOC_OPERATOR",
        "action": "PROCESS_TERMINATE"
    })
    return result

@app.post("/api/actions/block-ip")
async def api_block_ip(req: BlockIPRequest):
    """Applies native OS firewall block rules against an IP."""
    result = firewall_manager.block_ip(req.ip, req.reason)
    if not result.get("success") and not result.get("requires_admin"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to block IP"))
    
    # Audit firewall block in security logs
    log_monitor.add_security_event({
        "category": "FIREWALL",
        "severity": "HIGH",
        "title": f"Firewall Rule Enforced for {req.ip}",
        "description": f"IP {req.ip} permanently blocked in OS firewall: {req.reason}",
        "source_ip": req.ip,
        "user": "SOC_OPERATOR",
        "action": "FIREWALL_BLOCK"
    })
    return result

@app.post("/api/actions/unblock-ip")
async def api_unblock_ip(req: UnblockIPRequest):
    """Removes native OS firewall block rules for an IP."""
    result = firewall_manager.unblock_ip(req.ip)
    
    # Audit unblock in security logs
    log_monitor.add_security_event({
        "category": "FIREWALL",
        "severity": "INFO",
        "title": f"Firewall Rule Removed for {req.ip}",
        "description": f"IP {req.ip} was unblocked in OS firewall.",
        "source_ip": req.ip,
        "user": "SOC_OPERATOR",
        "action": "FIREWALL_UNBLOCK"
    })
    return result

# =========================================================================
# LOGS & AUTHENTICATION ENDPOINTS
# =========================================================================
@app.get("/api/logs/system")
async def api_get_system_logs(limit: int = 100, level: Optional[str] = None, source: Optional[str] = None, search: Optional[str] = None):
    """Retrieves live system event logs from OS kernel and subsystems."""
    logs = log_monitor.get_system_logs(limit=limit, level=level, source=source, search=search)
    return {
        "count": len(logs),
        "logs": logs
    }

@app.get("/api/logs/security")
async def api_get_security_logs(limit: int = 100, category: Optional[str] = None, severity: Optional[str] = None, search: Optional[str] = None):
    """Retrieves threat audit, policy changes, and security incident logs."""
    logs = log_monitor.get_security_logs(limit=limit, category=category, severity=severity, search=search)
    return {
        "count": len(logs),
        "logs": logs
    }

@app.get("/api/logs/logins")
async def api_get_login_attempts(limit: int = 100, status: Optional[str] = None, search: Optional[str] = None):
    """Retrieves logon attempts, authentication failures, and historical sessions."""
    attempts = log_monitor.get_login_attempts(limit=limit, status=status, search=search)
    return {
        "count": len(attempts),
        "attempts": attempts
    }

@app.get("/api/logs/sessions")
async def api_get_active_sessions():
    """Retrieves currently logged-in host sessions."""
    return {
        "sessions": log_monitor.get_active_sessions()
    }

@app.get("/api/logs/stats")
async def api_get_log_stats():
    """Returns aggregated real-time counts across system, security, and authentication."""
    return log_monitor.get_summary_stats()

@app.post("/api/logs/scan-threats")
async def api_scan_threats():
    """Triggers an active comprehensive threat analysis across all system and security logs."""
    result = log_monitor.scan_all_logs_for_threats()
    return result

# WebSocket Streaming Endpoint
@app.websocket("/ws/live")
async def websocket_live_stream(websocket: WebSocket):
    """Real-time bidirectional WebSocket stream for network telemetry & logs."""
    await hub.connect(websocket)
    try:
        # Send immediate initial state
        initial_data = network_monitor.capture_connections()
        initial_stats = log_monitor.get_summary_stats()
        await websocket.send_text(json.dumps({
            "type": "INITIAL_STATE",
            "system": get_system_info(),
            "data": initial_data,
            "log_stats": initial_stats
        }))

        while True:
            # Listen for client requests (e.g. ping, refresh, filter commands)
            text = await websocket.receive_text()
            try:
                cmd = json.loads(text)
                action = cmd.get("action")
                if action == "PING":
                    await websocket.send_text(json.dumps({"type": "PONG", "timestamp": cmd.get("timestamp")}))
                elif action == "REFRESH":
                    fresh_data = network_monitor.capture_connections()
                    fresh_stats = log_monitor.get_summary_stats()
                    await websocket.send_text(json.dumps({
                        "type": "TELEMETRY_UPDATE",
                        "data": fresh_data,
                        "log_stats": fresh_stats
                    }))
                elif action == "GET_SYSTEM_LOGS":
                    logs = log_monitor.get_system_logs(
                        limit=cmd.get("limit", 100),
                        level=cmd.get("level"),
                        source=cmd.get("source"),
                        search=cmd.get("search")
                    )
                    await websocket.send_text(json.dumps({"type": "SYSTEM_LOGS_DATA", "logs": logs}))
                elif action == "GET_SECURITY_LOGS":
                    logs = log_monitor.get_security_logs(
                        limit=cmd.get("limit", 100),
                        category=cmd.get("category"),
                        severity=cmd.get("severity"),
                        search=cmd.get("search")
                    )
                    await websocket.send_text(json.dumps({"type": "SECURITY_LOGS_DATA", "logs": logs}))
                elif action == "GET_LOGIN_LOGS":
                    logins = log_monitor.get_login_attempts(
                        limit=cmd.get("limit", 100),
                        status=cmd.get("status"),
                        search=cmd.get("search")
                    )
                    sessions = log_monitor.get_active_sessions()
                    stats = log_monitor.get_summary_stats()
                    await websocket.send_text(json.dumps({
                        "type": "LOGIN_LOGS_DATA",
                        "logins": logins,
                        "sessions": sessions,
                        "stats": stats
                    }))
                elif action == "SCAN_THREATS":
                    scan_res = log_monitor.scan_all_logs_for_threats()
                    await websocket.send_text(json.dumps({
                        "type": "THREAT_SCAN_RESULT",
                        "data": scan_res
                    }))
            except Exception:
                pass
    except WebSocketDisconnect:
        hub.disconnect(websocket)
    except Exception as e:
        logger.debug(f"WebSocket connection error: {e}")
        hub.disconnect(websocket)

# =============================================================================
# THREAT INTELLIGENCE & REPUTATION API
# =============================================================================
@app.get("/api/intel/lookup")
async def threat_intel_lookup(ip: str):
    """Evaluates an IP address against threat feeds, Tor exit nodes, and reputation scoring."""
    if not ip:
        raise HTTPException(status_code=400, detail="Missing ip parameter")
    return threat_intel.evaluate_ip(ip)

@app.get("/api/intel/stats")
async def threat_intel_stats():
    """Returns threat intelligence database and cache statistics."""
    return threat_intel.get_stats()

# =============================================================================
# SECURITY INCIDENT REPORTS & SIEM EXPORT API
# =============================================================================
report_generator = ReportGenerator(log_monitor, network_monitor, firewall_manager)

@app.get("/api/reports/summary")
async def report_summary():
    """Returns comprehensive JSON security audit data."""
    return report_generator.generate_summary_data()

@app.get("/api/reports/executive-html")
async def report_executive_html():
    """Returns printable/standalone HTML Executive Briefing."""
    html_content = report_generator.generate_executive_html()
    return HTMLResponse(content=html_content, status_code=200)

@app.get("/api/reports/download")
async def report_download(format: str = "csv", type: str = "incidents"):
    """Downloads CSV, CEF, or Syslog formatted security logs."""
    fmt = format.lower()
    if fmt == "cef":
        content = report_generator.generate_siem_cef()
        return Response(
            content=content,
            media_type="text/plain",
            headers={"Content-Disposition": 'attachment; filename="aegisnet-siem-audit.cef"'}
        )
    elif fmt == "csv":
        content = report_generator.generate_csv(export_type=type)
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="aegisnet-{type}-report.csv"'}
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format '{format}'. Use 'csv' or 'cef'.")

# Serve Frontend Static Assets
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/")
async def serve_index():
    """Serves the main single-page cyber dashboard."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"message": "AegisNet API is running. Frontend index.html not yet built."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.server:app", host=SERVER_HOST, port=SERVER_PORT, reload=False)
