import os
import json
import subprocess
import platform
import logging
import ipaddress
import time
from typing import Dict, Any, List

import psutil
from backend.config import BLOCKED_IPS_FILE
from backend.os_detector import is_admin

logger = logging.getLogger("aegis.firewall")

class FirewallManager:
    def __init__(self):
        self.os_type = platform.system()
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self._load_blocked_ips()

    def _load_blocked_ips(self):
        """Loads persistent record of blocked IPs."""
        if os.path.exists(BLOCKED_IPS_FILE):
            try:
                with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
                    self.blocked_ips = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load blocked IPs file: {e}")
                self.blocked_ips = {}
        else:
            self.blocked_ips = {}

    def _save_blocked_ips(self):
        """Persists blocked IPs to disk."""
        try:
            with open(BLOCKED_IPS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.blocked_ips, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save blocked IPs file: {e}")

    def is_safe_to_block(self, ip: str) -> bool:
        """Sanity check to prevent operators from blocking loopback, broadcast, or wildcard."""
        if not ip:
            return False
        if ip in ("127.0.0.1", "::1", "0.0.0.0", "255.255.255.255"):
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
                return False
        except ValueError:
            return False
        return True

    def block_ip(self, ip: str, reason: str = "Operator Action") -> Dict[str, Any]:
        """Adds native OS firewall rules to block traffic to and from the specified IP."""
        if not self.is_safe_to_block(ip):
            return {
                "success": False,
                "ip": ip,
                "error": "Cannot block loopback, broadcast, or invalid IP addresses."
            }

        rule_name_in = f"AEGIS_BLOCK_{ip}_IN"
        rule_name_out = f"AEGIS_BLOCK_{ip}_OUT"

        commands = []
        if self.os_type == "Windows":
            commands.append([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name_in}",
                "dir=in", "action=block",
                f"remoteip={ip}"
            ])
            commands.append([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name_out}",
                "dir=out", "action=block",
                f"remoteip={ip}"
            ])
        elif self.os_type == "Linux":
            commands.append(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
            commands.append(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"])
        else:
            return {
                "success": False,
                "ip": ip,
                "error": f"Firewall manipulation not implemented for OS: {self.os_type}"
            }

        executed_commands = []
        for cmd in commands:
            cmd_str = " ".join(cmd)
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                executed_commands.append({
                    "command": cmd_str,
                    "returncode": result.returncode,
                    "stdout": result.stdout.strip(),
                    "stderr": result.stderr.strip()
                })
                if result.returncode != 0:
                    logger.warning(f"Firewall command failed ({result.returncode}): {result.stderr.strip() or result.stdout.strip()}")
            except Exception as e:
                logger.error(f"Execution error on '{cmd_str}': {e}")
                return {
                    "success": False,
                    "ip": ip,
                    "error": str(e),
                    "details": executed_commands
                }

        # Check if commands succeeded (returncode 0)
        all_succeeded = all(c["returncode"] == 0 for c in executed_commands)
        if all_succeeded or not is_admin():
            # If not admin, report command details so user knows to run elevated or we simulate/record
            note = "" if is_admin() else " (Warning: Host is not running with Administrator privileges. Command may require elevation.)"
            self.blocked_ips[ip] = {
                "ip": ip,
                "timestamp": time.time(),
                "formatted_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "reason": reason,
                "os": self.os_type,
                "status": "Active" if all_succeeded else "Elevation Required",
                "rules": [rule_name_in, rule_name_out]
            }
            self._save_blocked_ips()

            return {
                "success": all_succeeded,
                "ip": ip,
                "message": f"Firewall block rules configured for {ip}.{note}",
                "details": executed_commands,
                "requires_admin": not is_admin()
            }
        else:
            return {
                "success": False,
                "ip": ip,
                "error": "Firewall commands failed. Administrator/Root privileges required.",
                "details": executed_commands
            }

    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """Removes OS firewall rules for the specified IP."""
        rule_name_in = f"AEGIS_BLOCK_{ip}_IN"
        rule_name_out = f"AEGIS_BLOCK_{ip}_OUT"

        commands = []
        if self.os_type == "Windows":
            commands.append(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_in}"])
            commands.append(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name_out}"])
        elif self.os_type == "Linux":
            commands.append(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            commands.append(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
        else:
            return {"success": False, "ip": ip, "error": f"Unsupported OS: {self.os_type}"}

        executed_commands = []
        for cmd in commands:
            cmd_str = " ".join(cmd)
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, check=False)
                executed_commands.append({
                    "command": cmd_str,
                    "returncode": res.returncode,
                    "stdout": res.stdout.strip(),
                    "stderr": res.stderr.strip()
                })
            except Exception as e:
                logger.error(f"Error unblocking IP {ip}: {e}")

        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            self._save_blocked_ips()

        return {
            "success": True,
            "ip": ip,
            "message": f"Firewall rules removed for {ip}",
            "details": executed_commands
        }

    def get_blocked_list(self) -> List[Dict[str, Any]]:
        """Returns list of currently registered blocked IPs."""
        return list(self.blocked_ips.values())

    def terminate_process(self, pid: int) -> Dict[str, Any]:
        """Kills an active process by PID."""
        if pid <= 4:
            return {
                "success": False,
                "pid": pid,
                "error": "Cannot terminate critical system process (PID <= 4)."
            }

        proc_name = "Unknown"
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.terminate()
            gone, alive = psutil.wait_procs([proc], timeout=1.5)
            if alive:
                proc.kill()
            return {
                "success": True,
                "pid": pid,
                "process_name": proc_name,
                "message": f"Process '{proc_name}' (PID: {pid}) terminated successfully."
            }
        except psutil.NoSuchProcess:
            return {
                "success": True,
                "pid": pid,
                "process_name": proc_name,
                "message": f"Process {pid} had already exited."
            }
        except psutil.AccessDenied:
            # Try OS fallback command
            try:
                if self.os_type == "Windows":
                    res = subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True)
                    if res.returncode == 0:
                        return {"success": True, "pid": pid, "process_name": proc_name, "message": f"Killed PID {pid} via taskkill"}
                else:
                    res = subprocess.run(["kill", "-9", str(pid)], capture_output=True, text=True)
                    if res.returncode == 0:
                        return {"success": True, "pid": pid, "process_name": proc_name, "message": f"Killed PID {pid} via kill -9"}
            except Exception:
                pass
            return {
                "success": False,
                "pid": pid,
                "process_name": proc_name,
                "error": "Access Denied. Elevated (Administrator/Root) privileges required."
            }
        except Exception as e:
            return {
                "success": False,
                "pid": pid,
                "process_name": proc_name,
                "error": str(e)
            }

# Global singleton
firewall_manager = FirewallManager()
