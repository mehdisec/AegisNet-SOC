#!/usr/bin/env python3
"""
AegisNet SOC - Native Desktop Application (Windows & Linux)
=============================================================
Zero-bloat native desktop window powered by pywebview (Edge WebView2 / WebKitGTK).
Integrates real-time connection interceptor, threat intelligence radar, and 
system telemetry with hardware-accelerated rendering.

Author: Mehdi Mirzaei
Email: Mehdisec@gmail.com
GitHub: https://github.com/mehdisec
Portfolio: https://github.io/mehdisec
License: MIT
"""

import sys
import os
import time
import socket
import threading
import webbrowser
import logging

# Ensure project root is in sys.path (supports PyInstaller frozen executable)
if getattr(sys, 'frozen', False):
    PROJECT_ROOT = sys._MEIPASS
    RUNTIME_ROOT = os.path.dirname(sys.executable)
else:
    PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
    RUNTIME_ROOT = PROJECT_ROOT

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("AegisNetDesktop")

DEFAULT_PORT = 8080
DEFAULT_HOST = "127.0.0.1"


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Check if the target port is currently bound and listening."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def start_uvicorn_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
    """Start uvicorn server in a background thread if not already running."""
    import uvicorn
    from backend.server import app

    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False
    )
    server = uvicorn.Server(config)
    server.run()


class DesktopApi:
    """JavaScript API bridge exposed to the Webview window as `window.pywebview.api`."""

    def __init__(self, window_ref=None):
        self._window = window_ref
        self.is_closing = False

    def set_window(self, window_ref):
        self._window = window_ref

    def exit_app(self):
        """Cleanly trigger app shutdown from within JavaScript without blocking after 3s animation."""
        logger.info("[DesktopApi] Exit requested from UI after 3s animation. Destroying window...")
        self.is_closing = True
        def _terminate():
            time.sleep(0.05)
            if self._window:
                try:
                    self._window.destroy()
                except Exception:
                    pass
            os._exit(0)

        threading.Thread(target=_terminate, daemon=True).start()
        return {"status": "closing"}

    def get_author(self):
        return {
            "name": "Mehdi Mirzaei",
            "email": "Mehdisec@gmail.com",
            "github": "https://github.com/mehdisec",
            "website": "https://github.io/mehdisec",
            "version": "1.5.0",
            "license": "MIT"
        }

    def open_external(self, url: str):
        """Open an external link in system's default browser."""
        if url.startswith(("http://", "https://", "mailto:")):
            webbrowser.open(url)
            return True
        return False


def main():
    logger.info("Initializing AegisNet SOC Desktop Client...")
    logger.info("Lead Architect: Mehdi Mirzaei (Mehdisec@gmail.com)")

    # 1. Check if backend is already running on port 8080
    if not is_port_in_use(DEFAULT_PORT, DEFAULT_HOST):
        logger.info(f"Starting embedded backend server on http://{DEFAULT_HOST}:{DEFAULT_PORT}...")
        server_thread = threading.Thread(
            target=start_uvicorn_server,
            args=(DEFAULT_HOST, DEFAULT_PORT),
            daemon=True
        )
        server_thread.start()

        # Wait for server to become responsive
        for _ in range(30):
            if is_port_in_use(DEFAULT_PORT, DEFAULT_HOST):
                logger.info("Backend server is UP and accepting connections.")
                break
            time.sleep(0.2)
    else:
        logger.info(f"AegisNet backend is already active on port {DEFAULT_PORT}.")

    app_url = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"

    # Determine icon path
    icon_path = os.path.join(PROJECT_ROOT, "frontend", "static", "img", "icon.ico")
    if not os.path.exists(icon_path):
        icon_path = os.path.join(PROJECT_ROOT, "icon.ico")
    if not os.path.exists(icon_path):
        icon_path = None

    # 2. Launch Native Window with pywebview
    try:
        import webview

        api_instance = DesktopApi(None)

        window = webview.create_window(
            title="AEGISNET SOC // Real-Time Threat & Connection Monitor",
            url=app_url,
            width=1440,
            height=900,
            min_size=(1024, 680),
            resizable=True,
            fullscreen=False,
            frameless=False,
            easy_drag=False,
            background_color="#07090e",
            js_api=api_instance
        )
        api_instance.set_window(window)

        # Clean, non-blocking window closing handler with 3-second shutdown animation
        def _perform_graceful_exit():
            try:
                window.evaluate_js("if (window.triggerAppShutdown) window.triggerAppShutdown();")
            except Exception:
                pass
            time.sleep(3.0)
            try:
                window.destroy()
            except Exception:
                pass
            os._exit(0)

        def on_closing():
            if api_instance.is_closing:
                return True
            api_instance.is_closing = True
            logger.info("AegisNet title bar close requested. Displaying exit animation for 3.0 seconds...")
            threading.Thread(target=_perform_graceful_exit, daemon=True).start()
            return False

        window.events.closing += on_closing

        logger.info("Launching native hardware-accelerated GUI window...")
        webview.start(
            debug=False,
            private_mode=False,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisNetDesktop/1.5"
        )
        logger.info("AegisNet desktop session terminated gracefully.")

    except ImportError:
        logger.warning("pywebview is not installed in the current environment.")
        logger.info(f"Opening AegisNet SOC in default web browser: {app_url}")
        webbrowser.open(app_url)
    except Exception as e:
        logger.error(f"Failed to initialize native desktop window: {e}")
        logger.info(f"Falling back to system browser: {app_url}")
        webbrowser.open(app_url)


if __name__ == "__main__":
    main()
