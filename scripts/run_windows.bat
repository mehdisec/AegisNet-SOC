@echo off
setlocal enabledelayedexpansion
title AegisNet SOC Launcher

cd /d "%~dp0\.."
set "ROOT_DIR=%cd%"

:: Check for virtual environment python
if exist "%ROOT_DIR%\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%ROOT_DIR%\.venv\Scripts\python.exe"
    set "PYTHONW_EXE=%ROOT_DIR%\.venv\Scripts\pythonw.exe"
) else (
    set "PYTHON_EXE=python"
    set "PYTHONW_EXE=pythonw"
)

:: Check for Admin rights
net session >nul 2>&1
if %errorlevel% == 0 (
    set "IS_ADMIN=1"
) else (
    set "IS_ADMIN=0"
)

:: Parse Command-Line Arguments
if "%1"=="--desktop" goto run_desktop
if "%1"=="-d" goto run_desktop
if "%1"=="--server" goto run_server
if "%1"=="-s" goto run_server

:: Default interactive menu
echo ============================================================================
echo       AEGISNET REAL-TIME NETWORK SECURITY SOC PLATFORM v1.5
echo                  Lead Architect: Mehdi Mirzaei (Mehdisec)
echo ============================================================================
if "%IS_ADMIN%"=="1" (
    echo [OK] Running with Elevated Administrator Privileges.
) else (
    echo [NOTICE] Running without Administrator privileges.
    echo          (Netsh firewall blocks require Administrator rights)
)
echo.
echo Choose launch mode:
echo   [1] Native Desktop Window (Recommended)
echo   [2] Headless Server Mode (Accessible via Web Browser on port 8080)
echo   [3] Run Windows Installer / Setup Wizard
echo.
set /p MODE="Enter selection (1-3, default=1): "
if "%MODE%"=="2" goto run_server
if "%MODE%"=="3" goto run_installer
goto run_desktop

:run_desktop
echo.
echo [*] Launching AegisNet Native Desktop Client...
"%PYTHON_EXE%" "%ROOT_DIR%\desktop_app.py"
goto end

:run_server
echo.
echo [*] Launching AegisNet Server on http://0.0.0.0:8080 ...
start "" http://localhost:8080
"%PYTHON_EXE%" -m uvicorn backend.server:app --host 0.0.0.0 --port 8080
goto end

:run_installer
call "%ROOT_DIR%\install_windows.bat"
goto end

:end
