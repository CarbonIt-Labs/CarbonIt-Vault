# -*- mode: python ; coding: utf-8 -*-

import os
from PyInstaller.utils.hooks import collect_all, copy_metadata
from PyInstaller.utils.win32.versioninfo import (
    VSVersionInfo, FixedFileInfo, StringFileInfo, StringTable, StringStruct, VarFileInfo, VarStruct
)

# 1. Site-packages and QuantCrypt path definition
site_packages_path = r'C:\Users\USER\AppData\Local\Programs\Python\Python313\Lib\site-packages'
quantcrypt_path = os.path.join(site_packages_path, 'quantcrypt')

datas = [
    ('templates', 'templates'), 
    ('static', 'static')
]
binaries = []
hiddenimports = [
    'cffi',
    '_cffi_backend',
    'argon2',
    '_argon2_cffi_bindings',
    'quantcrypt',
    'webview',
    'flask'
]

# Collect argon2 binaries & modules
tmp_argon2 = collect_all('argon2')
datas += tmp_argon2[0]
binaries += tmp_argon2[1]
hiddenimports += tmp_argon2[2]

# Collect quantcrypt binaries & modules
tmp_qc = collect_all('quantcrypt')
datas += tmp_qc[0]
binaries += tmp_qc[1]
hiddenimports += tmp_qc[2]

# Copy package metadata for runtime package-version lookups
datas += copy_metadata('quantcrypt')
# FIX: The pip package is named 'argon2-cffi', not 'argon2'. 
# PyInstaller needs the pip distribution name to extract the metadata.
datas += copy_metadata('argon2-cffi')

# FIX: quantcrypt relies on relative folder paths to load precompiled PQClean CFFI binaries.
# PyInstaller flattens .dll files to root (_MEIPASS) by default, breaking internal lookups.
# Copying the raw quantcrypt folder into datas preserves its required internal directory tree.
if os.path.exists(quantcrypt_path):
    datas.append((quantcrypt_path, 'quantcrypt'))

# 2. Embed Windows Executable Version Info & Copyright
version_info = VSVersionInfo(
    ffi=FixedFileInfo(
        filevers=(1, 0, 0, 0),
        prodvers=(1, 0, 0, 0),
        mask=0x3f,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0)
    ),
    kids=[
        StringFileInfo(
            [
                StringTable(
                    '040904B0',
                    [
                        StringStruct('CompanyName', 'CarbonIt Labs'),
                        StringStruct('FileDescription', 'CarbonIt Vault - Post-Quantum Desktop Password Manager'),
                        StringStruct('FileVersion', '1.0.0.0'),
                        StringStruct('InternalName', 'CarbonIt Vault'),
                        StringStruct('LegalCopyright', '(c) 2026 CarbonIt Labs.'),
                        StringStruct('OriginalFilename', 'app.exe'),
                        StringStruct('ProductName', 'CarbonIt Vault'),
                        StringStruct('ProductVersion', '1.0.0.0'),
                    ]
                )
            ]
        ),
        VarFileInfo([VarStruct('Translation', [1033, 1200])])
    ]
)

a = Analysis(
    ['app.py'],
    pathex=[site_packages_path],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='app',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['logo.ico'],
    version=version_info,
)