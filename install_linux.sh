#!/usr/bin/env bash
# ==============================================================================
# AegisNet SOC v1.5 - Automated Linux Installer & Desktop Setup
# Lead Architect: Mehdi Mirzaei (Mehdisec)
# Email: Mehdisec@gmail.com
# GitHub: https://github.com/mehdisec
# Portfolio: https://github.io/mehdisec
# License: MIT
# ==============================================================================

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}============================================================================${NC}"
echo -e "${CYAN}        AEGISNET SOC v1.5 - AUTOMATED LINUX INSTALLER & SETUP               ${NC}"
echo -e "${CYAN}                  Lead Architect: Mehdi Mirzaei (Mehdisec)                  ${NC}"
echo -e "${CYAN}                  Contact: Mehdisec@gmail.com                               ${NC}"
echo -e "${CYAN}============================================================================${NC}"
echo ""

# Get script root directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# 1. Detect Package Manager and advise on WebKitGTK if needed
echo -e "${CYAN}[*] Checking Linux distribution and GUI webview dependencies...${NC}"

if command -v apt-get &> /dev/null; then
    echo -e "${GREEN}[OK] Debian/Ubuntu based distribution detected.${NC}"
    echo "    To ensure native desktop window support (pywebview):"
    echo "    sudo apt-get install -y python3-venv python3-pip libwebkit2gtk-4.0-37 gir1.2-webkit2-4.0 || true"
elif command -v pacman &> /dev/null; then
    echo -e "${GREEN}[OK] Arch Linux based distribution detected.${NC}"
    echo "    To ensure native desktop window support (pywebview):"
    echo "    sudo pacman -S --needed python-pip webkit2gtk || true"
elif command -v dnf &> /dev/null; then
    echo -e "${GREEN}[OK] Fedora/RedHat based distribution detected.${NC}"
    echo "    To ensure native desktop window support (pywebview):"
    echo "    sudo dnf install -y python3-pip webkit2gtk4.0 || true"
fi

# 2. Check Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR] python3 is not installed. Please install Python 3.10+ first.${NC}"
    exit 1
fi

PY_VER=$(python3 --version)
echo -e "${GREEN}[OK] Detected: ${PY_VER}${NC}"

# 3. Virtual Environment Setup
if [ ! -d ".venv" ]; then
    echo -e "${CYAN}[*] Creating virtual environment (.venv)...${NC}"
    python3 -m venv .venv || {
        echo -e "${YELLOW}[WARNING] python3-venv package might be missing. Installing globally or continuing...${NC}"
    }
fi

if [ -f ".venv/bin/python" ]; then
    PYTHON_EXE="$ROOT_DIR/.venv/bin/python"
    PIP_EXE="$ROOT_DIR/.venv/bin/pip"
else
    PYTHON_EXE="python3"
    PIP_EXE="pip3"
fi

# 4. Install Dependencies
echo -e "${CYAN}[*] Installing dependencies from requirements.txt...${NC}"
"$PIP_EXE" install --upgrade pip --quiet || true
"$PIP_EXE" install -r requirements.txt

# 5. Generate Project Icons
echo -e "${CYAN}[*] Generating high-resolution icons...${NC}"
"$PYTHON_EXE" scripts/generate_icons.py || true

# 6. Verify GeoIP Database
echo -e "${CYAN}[*] Checking GeoIP database...${NC}"
if [ ! -f "data/GeoLite2-City.mmdb" ]; then
    echo -e "${CYAN}[*] Downloading MaxMind GeoIP City Database...${NC}"
    "$PYTHON_EXE" scripts/download_geoip.py || true
else
    echo -e "${GREEN}[OK] GeoIP database already present.${NC}"
fi

# 7. Create Linux Desktop Entry (.desktop)
echo -e "${CYAN}[*] Configuring Linux Desktop application launcher...${NC}"
ICON_PATH="$ROOT_DIR/frontend/static/img/icon.png"
DESKTOP_ENTRY_DIR="$HOME/.local/share/applications"
mkdir -p "$DESKTOP_ENTRY_DIR"

DESKTOP_FILE="$DESKTOP_ENTRY_DIR/aegisnet.desktop"
cat <<EOF > "$DESKTOP_FILE"
[Desktop Entry]
Version=1.5
Type=Application
Name=AegisNet SOC
GenericName=Real-Time Threat & Network Security SOC
Comment=Autonomous Cyber Defense SOC, Real-Time GeoIP Telemetry, and Connection Interceptor
Exec=$ROOT_DIR/scripts/run_linux.sh --desktop
Icon=$ICON_PATH
Terminal=false
Categories=Network;Security;System;Monitor;
StartupNotify=true
StartupWMClass=aegisnet
EOF

chmod +x "$DESKTOP_FILE"
chmod +x "$ROOT_DIR/scripts/run_linux.sh"
chmod +x "$ROOT_DIR/desktop_app.py"

echo -e "${GREEN}[OK] Desktop launcher created: $DESKTOP_FILE${NC}"

# 8. Create Command Line Alias / Symlink
CLI_BIN_DIR="$HOME/.local/bin"
mkdir -p "$CLI_BIN_DIR"
CLI_LAUNCHER="$CLI_BIN_DIR/aegisnet"

cat <<EOF > "$CLI_LAUNCHER"
#!/usr/bin/env bash
exec "$ROOT_DIR/scripts/run_linux.sh" "\$@"
EOF

chmod +x "$CLI_LAUNCHER"
echo -e "${GREEN}[OK] CLI command installed: $CLI_LAUNCHER (Run 'aegisnet' from terminal)${NC}"

# If running with sudo, optionally install system-wide
if [ "$EUID" -eq 0 ]; then
    cp "$DESKTOP_FILE" /usr/share/applications/aegisnet.desktop 2>/dev/null || true
    ln -sf "$ROOT_DIR/scripts/run_linux.sh" /usr/local/bin/aegisnet 2>/dev/null || true
    echo -e "${GREEN}[OK] System-wide launcher created in /usr/share/applications and /usr/local/bin/aegisnet${NC}"
fi

echo ""
echo -e "${GREEN}============================================================================${NC}"
echo -e "${GREEN}[SUCCESS] AegisNet SOC Installation Complete!                               ${NC}"
echo -e "${GREEN}          Author: Mehdi Mirzaei <Mehdisec@gmail.com>                        ${NC}"
echo -e "${GREEN}          GitHub: https://github.com/mehdisec                               ${NC}"
echo -e "${GREEN}============================================================================${NC}"
echo ""
echo "To run the desktop app:"
echo "  1. Search 'AegisNet SOC' in your application menu, OR"
echo "  2. Run: ./scripts/run_linux.sh --desktop, OR"
echo "  3. Run: aegisnet"
echo ""
