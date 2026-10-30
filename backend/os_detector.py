import os
import platform
import socket
import shutil
import sys
import logging

logger = logging.getLogger("aegis.os_detector")

def is_admin() -> bool:
    """Checks whether the application is running with administrative/root privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception as e:
        logger.warning(f"Failed to check administrative privileges: {e}")
        return False

def detect_firewall_backend(os_name: str) -> str:
    """Detects which firewall CLI tool is available on the host system."""
    if os_name == "Windows":
        if shutil.which("netsh"):
            return "netsh"
        return "powershell"
    elif os_name == "Linux":
        if shutil.which("nft"):
            return "nftables"
        elif shutil.which("iptables"):
            return "iptables"
        elif shutil.which("ufw"):
            return "ufw"
        return "none"
    elif os_name == "Darwin":
        if shutil.which("pfctl"):
            return "pfctl"
        return "none"
    return "unknown"

def get_system_info() -> dict:
    """Returns a comprehensive diagnostic report of the host operating system."""
    os_name = platform.system()
    has_privileges = is_admin()
    firewall_tool = detect_firewall_backend(os_name)
    hostname = socket.gethostname()
    
    try:
        primary_ip = socket.gethostbyname(hostname)
    except Exception:
        primary_ip = "127.0.0.1"

    info = {
        "os": os_name,
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version.split()[0],
        "hostname": hostname,
        "primary_ip": primary_ip,
        "is_admin": has_privileges,
        "firewall_tool": firewall_tool,
        "monitoring_backend": "psutil_windows" if os_name == "Windows" else "psutil_linux"
    }
    return info

if __name__ == "__main__":
    import json
    print(json.dumps(get_system_info(), indent=2))
