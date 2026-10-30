# -*- mode: python ; coding: utf-8 -*-
block_cipher = None

datas = [
    ('dist/AegisNet-SOC.exe', '.'),
    ('icon.ico', '.'),
    ('data', 'data'),
]

a = Analysis(
    ['scripts/installer_template.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=['winreg', 'ctypes', 'subprocess', 'shutil', 'pathlib'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'scipy'],
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
    name='AegisNet-Setup',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Console wizard so user sees installation steps and progress
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',
)
