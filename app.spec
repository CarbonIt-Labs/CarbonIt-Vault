# -*- mode: python ; coding: utf-8 -*-

import os
import sys
import importlib.util
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, copy_metadata
from PyInstaller.utils.win32.versioninfo import (
    VSVersionInfo, FixedFileInfo, StringFileInfo, StringTable,
    StringStruct, VarFileInfo, VarStruct
)

# Project root
project_root = Path(__file__).resolve().parent

# Locate QuantCrypt dynamically
quantcrypt_spec = importlib.util.find_spec("quantcrypt")

if quantcrypt_spec is None or not quantcrypt_spec.submodule_search_locations:
    raise RuntimeError("Could not locate the quantcrypt package.")

quantcrypt_path = Path(
    next(iter(quantcrypt_spec.submodule_search_locations))
)

datas = [
    (str(project_root / "templates"), "templates"),
    (str(project_root / "static"), "static"),
]

binaries = []

hiddenimports = [
    "cffi",
    "_cffi_backend",
    "argon2",
    "_argon2_cffi_bindings",
    "quantcrypt",
    "webview",
    "flask",
]

# Collect argon2
tmp_argon2 = collect_all("argon2")
datas += tmp_argon2[0]
binaries += tmp_argon2[1]
hiddenimports += tmp_argon2[2]

# Collect quantcrypt
tmp_qc = collect_all("quantcrypt")
datas += tmp_qc[0]
binaries += tmp_qc[1]
hiddenimports += tmp_qc[2]

# Package metadata
datas += copy_metadata("quantcrypt")
datas += copy_metadata("argon2-cffi")

# Preserve QuantCrypt's internal directory structure
if quantcrypt_path.exists():
    datas.append((str(quantcrypt_path), "quantcrypt"))

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
                    "040904B0",
                    [
                        StringStruct("CompanyName", "CarbonIt Labs"),
                        StringStruct(
                            "FileDescription",
                            "CarbonIt Vault - Post-Quantum Desktop Password Manager"
                        ),
                        StringStruct("FileVersion", "1.0.0.0"),
                        StringStruct("InternalName", "CarbonIt Vault"),
                        StringStruct(
                            "LegalCopyright",
                            "(c) 2026 CarbonIt Labs."
                        ),
                        StringStruct("OriginalFilename", "app.exe"),
                        StringStruct("ProductName", "CarbonIt Vault"),
                        StringStruct("ProductVersion", "1.0.0.0"),
                    ]
                )
            ]
        ),
        VarFileInfo([
            VarStruct("Translation", [1033, 1200])
        ])
    ]
)

a = Analysis(
    [str(project_root / "app.py")],
    pathex=[str(project_root)],
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
    name="app",
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
    icon=[str(project_root / "logo.ico")],
    version=version_info,
)
