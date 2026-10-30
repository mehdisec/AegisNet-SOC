"""
AegisNet SOC - Windows Automated Setup & Installer
===================================================
Installs AegisNet Desktop to %LOCALAPPDATA%\\Programs\\AegisNet-SOC,
generates Desktop and Start Menu shortcuts, and registers uninstaller.

Author: Mehdi Mirzaei (Mehdisec@gmail.com)
License: MIT
"""

import sys
import os
import shutil
import winreg
import subprocess
import ctypes
from pathlib import Path


APP_NAME = "AegisNet SOC"
APP_EXE = "AegisNet-SOC.exe"
PUBLISHER = "Mehdi Mirzaei"
VERSION = "1.5.0"
CONTACT = "Mehdisec@gmail.com"
URL = "https://github.com/mehdisec/AegisNet-SOC"


def get_install_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
    return Path(local_app_data) / "Programs" / "AegisNet-SOC"


def create_shortcut(target: Path, shortcut_path: Path, icon_path: Path, description: str):
    powershell_cmd = (
        f"$WshShell = New-Object -ComObject WScript.Shell; "
        f"$Shortcut = $WshShell.CreateShortcut('{str(shortcut_path)}'); "
        f"$Shortcut.TargetPath = '{str(target)}'; "
        f"$Shortcut.WorkingDirectory = '{str(target.parent)}'; "
        f"$Shortcut.IconLocation = '{str(icon_path)}, 0'; "
        f"$Shortcut.Description = '{description}'; "
        f"$Shortcut.Save();"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", powershell_cmd], capture_output=True)


def register_uninstaller(install_dir: Path, target_exe: Path, icon_path: Path):
    reg_path = rf"Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNetSOC"
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "AegisNet SOC - Cyber Defense Platform")
            winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, VERSION)
            winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, PUBLISHER)
            winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, str(icon_path))
            winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(install_dir))
            winreg.SetValueEx(key, "HelpLink", 0, winreg.REG_SZ, URL)
            winreg.SetValueEx(key, "URLInfoAbout", 0, winreg.REG_SZ, URL)
            uninstall_cmd = f'powershell -Command "Remove-Item -Recurse -Force \'{str(install_dir)}\'; Remove-Item \'$([Environment]::GetFolderPath(\'Desktop\'))\\AegisNet SOC.lnk\' -Force -ErrorAction SilentlyContinue; Remove-Item \'$([Environment]::GetFolderPath(\'StartMenu\'))\\Programs\\AegisNet SOC\' -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -Path \'HKCU:\\{reg_path}\' -Force -ErrorAction SilentlyContinue; [System.Windows.Forms.MessageBox]::Show(\'AegisNet SOC has been successfully uninstalled.\', \'AegisNet Uninstall\')"'
            winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, uninstall_cmd)
            winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
    except Exception as e:
        print(f"[Notice] Could not register uninstaller in Registry: {e}")


def main():
    print("=" * 68)
    print("      AEGISNET SOC v1.5 - WINDOWS SETUP & INSTALLER")
    print(f"      Lead Architect: {PUBLISHER} ({CONTACT})")
    print("=" * 68)
    print()

    # Determine source directory where payload files are bundled
    if getattr(sys, 'frozen', False):
        payload_dir = Path(sys._MEIPASS)
    else:
        payload_dir = Path(__file__).resolve().parent.parent / "dist"

    source_exe = payload_dir / APP_EXE
    if not source_exe.exists():
        # Check adjacent directory
        alt_exe = Path(sys.executable).parent / APP_EXE
        if alt_exe.exists():
            source_exe = alt_exe

    install_dir = get_install_dir()
    print(f"[*] Target Installation Directory: {install_dir}")

    try:
        install_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"[Error] Failed to create installation folder: {e}")
        input("Press Enter to exit...")
        return

    # Copy files
    dest_exe = install_dir / APP_EXE
    dest_icon = install_dir / "icon.ico"

    print("[*] Copying AegisNet application binaries...")
    if source_exe.exists():
        shutil.copy2(source_exe, dest_exe)
    else:
        print(f"[Error] Payload {APP_EXE} not found.")
        input("Press Enter to exit...")
        return

    source_icon = payload_dir / "icon.ico"
    if source_icon.exists():
        shutil.copy2(source_icon, dest_icon)
    elif (payload_dir / "frontend" / "static" / "img" / "icon.ico").exists():
        shutil.copy2(payload_dir / "frontend" / "static" / "img" / "icon.ico", dest_icon)

    # Copy data directory if present
    source_data = payload_dir / "data"
    if source_data.exists():
        dest_data = install_dir / "data"
        dest_data.mkdir(exist_ok=True)
        for item in source_data.glob("*"):
            if item.is_file():
                try:
                    shutil.copy2(item, dest_data / item.name)
                except Exception:
                    pass

    # Create Desktop Shortcut
    desktop_path = Path(os.environ.get("USERPROFILE", os.path.expanduser("~"))) / "Desktop" / "AegisNet SOC.lnk"
    print(f"[*] Creating Desktop shortcut: {desktop_path}")
    create_shortcut(dest_exe, desktop_path, dest_icon, "AegisNet SOC - Real-Time Cyber Threat Monitor")

    # Create Start Menu Shortcut
    start_menu = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "AegisNet SOC"
    start_menu.mkdir(parents=True, exist_ok=True)
    start_lnk = start_menu / "AegisNet SOC.lnk"
    print(f"[*] Creating Start Menu shortcut: {start_lnk}")
    create_shortcut(dest_exe, start_lnk, dest_icon, "AegisNet SOC - Real-Time Cyber Threat Monitor")

    # Register in Windows Registry
    register_uninstaller(install_dir, dest_exe, dest_icon)

    print()
    print("=" * 68)
    print(" [SUCCESS] AegisNet SOC Installation Finished Successfully!")
    print(f"           Author: {PUBLISHER} <{CONTACT}>")
    print(f"           GitHub: {URL}")
    print("=" * 68)
    print()

    # Ask to launch
    try:
        launch = input("Launch AegisNet SOC now? (Y/n): ").strip().lower()
        if launch != 'n':
            subprocess.Popen([str(dest_exe)], cwd=str(install_dir))
    except Exception:
        pass


if __name__ == "__main__":
    main()
