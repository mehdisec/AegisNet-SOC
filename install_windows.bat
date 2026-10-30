@echo off
setlocal enabledelayedexpansion
title AegisNet SOC - Windows Installer & Setup Wizard

echo ============================================================================
echo        AEGISNET SOC v1.5 - AUTOMATED WINDOWS INSTALLER ^& SETUP
echo                  Lead Architect: Mehdi Mirzaei (Mehdisec)
echo                  Contact: Mehdisec@gmail.com
echo ============================================================================
echo.

:: Step 0: Check Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [NOTICE] Running without elevated Administrator privileges.
    echo          Installer will set up user shortcuts and python environment.
    echo          (To grant firewall blocking netsh capability, run as Administrator)
    echo.
) else (
    echo [OK] Running with elevated Administrator privileges.
    echo.
)

:: Step 1: Change to project root directory
cd /d "%~dp0"
set "ROOT_DIR=%cd%"

:: Step 2: Verify Python 3
echo [*] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found in your system PATH!
    echo         Please download and install Python 3.10+ from https://www.python.org/
    echo         Ensure "Add Python to PATH" is checked during installation.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('python --version 2^>^&1') do set "PY_VER=%%v"
echo [OK] Detected: %PY_VER%

:: Step 3: Virtual Environment Setup
if not exist ".venv" (
    echo.
    echo [*] Creating virtual environment (.venv)...
    python -m venv .venv
    if %errorlevel% neq 0 (
        echo [WARNING] Could not create virtual environment. Falling back to global Python.
        set "PYTHON_EXE=python"
        set "PYTHONW_EXE=pythonw"
    ) else (
        echo [OK] Virtual environment created successfully.
        set "PYTHON_EXE=%ROOT_DIR%\.venv\Scripts\python.exe"
        set "PYTHONW_EXE=%ROOT_DIR%\.venv\Scripts\pythonw.exe"
    )
) else (
    echo [OK] Existing virtual environment found (.venv).
    set "PYTHON_EXE=%ROOT_DIR%\.venv\Scripts\python.exe"
    set "PYTHONW_EXE=%ROOT_DIR%\.venv\Scripts\pythonw.exe"
)

:: Step 4: Install Dependencies
echo.
echo [*] Installing / updating dependencies from requirements.txt...
"%PYTHON_EXE%" -m pip install --upgrade pip --quiet
"%PYTHON_EXE%" -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install one or more dependencies.
    pause
    exit /b 1
)
echo [OK] All dependencies satisfied (FastAPI, uvicorn, psutil, pywebview, Pillow).

:: Step 5: Generate Icons & Assets
echo.
echo [*] Generating high-resolution project icons...
"%PYTHON_EXE%" scripts/generate_icons.py
if exist "frontend\static\img\icon.ico" (
    copy /y "frontend\static\img\icon.ico" "%ROOT_DIR%\icon.ico" >nul 2>&1
)

:: Step 6: Verify GeoIP Database
echo.
echo [*] Checking GeoIP database...
if not exist "data\GeoLite2-City.mmdb" (
    echo [*] Downloading MaxMind GeoIP City Database...
    "%PYTHON_EXE%" scripts/download_geoip.py
) else (
    echo [OK] GeoIP database already present.
)

:: Step 7: Create Windows Desktop & Start Menu Shortcuts
echo.
echo [*] Creating Desktop and Start Menu shortcuts...

set "ICON_FILE=%ROOT_DIR%\icon.ico"
set "TARGET_BAT=%ROOT_DIR%\scripts\run_windows.bat"
set "DESKTOP_DIR=%USERPROFILE%\Desktop"
set "START_MENU_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\AegisNet SOC"

if not exist "%START_MENU_DIR%" mkdir "%START_MENU_DIR%"

:: PowerShell script to create .lnk shortcuts
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$WshShell = New-Object -ComObject WScript.Shell; " ^
    "$Shortcut = $WshShell.CreateShortcut('%DESKTOP_DIR%\AegisNet SOC.lnk'); " ^
    "$Shortcut.TargetPath = '%TARGET_BAT%'; " ^
    "$Shortcut.Arguments = '--desktop'; " ^
    "$Shortcut.WorkingDirectory = '%ROOT_DIR%'; " ^
    "$Shortcut.IconLocation = '%ICON_FILE%, 0'; " ^
    "$Shortcut.Description = 'AegisNet SOC - Real-Time Threat & Connection Monitor'; " ^
    "$Shortcut.Save(); " ^
    "$StartShortcut = $WshShell.CreateShortcut('%START_MENU_DIR%\AegisNet SOC.lnk'); " ^
    "$StartShortcut.TargetPath = '%TARGET_BAT%'; " ^
    "$StartShortcut.Arguments = '--desktop'; " ^
    "$StartShortcut.WorkingDirectory = '%ROOT_DIR%'; " ^
    "$StartShortcut.IconLocation = '%ICON_FILE%, 0'; " ^
    "$StartShortcut.Description = 'AegisNet SOC - Real-Time Threat & Connection Monitor'; " ^
    "$StartShortcut.Save();"

echo [OK] Shortcut created on Desktop: "%DESKTOP_DIR%\AegisNet SOC.lnk"
echo [OK] Shortcut created in Start Menu: "%START_MENU_DIR%\AegisNet SOC.lnk"

:: Step 8: Done!
echo.
echo ============================================================================
echo [SUCCESS] AegisNet SOC Installation Complete!
echo           Author: Mehdi Mirzaei ^<Mehdisec@gmail.com^>
echo           GitHub: https://github.com/mehdisec
echo ============================================================================
echo.
set /p LAUNCH_CHOICE="Do you want to launch AegisNet Desktop now? (Y/N): "
if /i "%LAUNCH_CHOICE%"=="Y" (
    start "" "%PYTHONW_EXE%" "%ROOT_DIR%\desktop_app.py"
)

exit /b 0
