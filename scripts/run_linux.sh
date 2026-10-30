#!/usr/bin/env bash
# AegisNet SOC Linux Multi-Mode Launcher
# Author: Mehdi Mirzaei (Mehdisec@gmail.com)

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ -f "$ROOT_DIR/.venv/bin/python" ]; then
    PYTHON_EXE="$ROOT_DIR/.venv/bin/python"
else
    PYTHON_EXE="python3"
fi

# Check for root privileges (for firewall rules)
if [ "$EUID" -ne 0 ]; then
    IS_ROOT=0
else
    IS_ROOT=1
fi

MODE="${1:-}"

if [ "$MODE" == "--desktop" ] || [ "$MODE" == "-d" ]; then
    echo "[*] Launching AegisNet Native Desktop Client..."
    exec "$PYTHON_EXE" "$ROOT_DIR/desktop_app.py"
elif [ "$MODE" == "--server" ] || [ "$MODE" == "-s" ]; then
    echo "[*] Launching AegisNet Server on http://0.0.0.0:8080 ..."
    exec "$PYTHON_EXE" -m uvicorn backend.server:app --host 0.0.0.0 --port 8080
elif [ "$MODE" == "--install" ] || [ "$MODE" == "-i" ]; then
    exec "$ROOT_DIR/install_linux.sh"
fi

# Interactive menu if no argument given
echo "=============================================================="
echo "      AEGISNET REAL-TIME NETWORK SECURITY SOC PLATFORM        "
echo "                  Author: Mehdi Mirzaei                       "
echo "=============================================================="
if [ "$IS_ROOT" -eq 1 ]; then
    echo "[OK] Running with root privileges (Firewall active)."
else
    echo "[NOTICE] Not running as root. (iptables/nftables requires sudo)"
fi
echo ""
echo "Select launch mode:"
echo "  [1] Native Desktop Window (Recommended)"
echo "  [2] Headless Server Mode (Web Browser on port 8080)"
echo "  [3] Run Linux Installer / Setup Wizard"
echo ""
read -r -p "Enter choice [1-3, default=1]: " CHOICE
CHOICE="${CHOICE:-1}"

case "$CHOICE" in
    2)
        echo "[*] Starting server on http://0.0.0.0:8080 ..."
        exec "$PYTHON_EXE" -m uvicorn backend.server:app --host 0.0.0.0 --port 8080
        ;;
    3)
        exec "$ROOT_DIR/install_linux.sh"
        ;;
    *)
        echo "[*] Starting native desktop client..."
        exec "$PYTHON_EXE" "$ROOT_DIR/desktop_app.py"
        ;;
esac
