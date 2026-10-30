# -*- mode: python ; coding: utf-8 -*-
import sys
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

hidden_imports = [
    'uvicorn',
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.loops.asyncio',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.http.h11_impl',
    'uvicorn.protocols.http.httptools_impl',
    'uvicorn.protocols.websockets',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.protocols.websockets.websockets_impl',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',
    'uvicorn.lifespan.off',
    'fastapi',
    'fastapi.staticfiles',
    'fastapi.responses',
    'starlette',
    'starlette.routing',
    'starlette.middleware',
    'pydantic',
    'psutil',
    'webview',
    'webview.platforms.winforms',
    'webview.platforms.edgechromium',
    'email',
    'email.parser',
    'email.message',
    'pkg_resources',
    'PIL',
    'PIL.Image',
    'requests',
    'backend',
    'backend.server',
    'backend.config',
    'backend.os_detector',
    'backend.network_monitor',
    'backend.threat_intel',
    'backend.geoip_service',
    'backend.log_monitor',
    'backend.firewall_manager',
    'backend.report_generator',
]

try:
    hidden_imports += collect_submodules('uvicorn')
except Exception:
    pass

try:
    hidden_imports += collect_submodules('webview')
except Exception:
    pass

datas = [
    ('frontend', 'frontend'),
    ('data', 'data'),
    ('icon.ico', '.'),
]

a = Analysis(
    ['desktop_app.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy', 'pandas'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='AegisNet-SOC',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',
)
