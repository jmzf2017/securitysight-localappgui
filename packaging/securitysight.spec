# PyInstaller spec for the securitysight desktop app.
#
# Build from the REPO ROOT so the relative data paths resolve:
#   .venv/bin/python -m PyInstaller --noconfirm --clean packaging/securitysight.spec
#
# Produces dist/securitysight.app on macOS, dist/securitysight/ (with
# securitysight.exe) on Windows. Unsigned — see packaging/README.md.

import os
import sys
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))   # repo root (spec is in packaging/)

# Flask needs the templates + static trees at runtime; web.py looks for them at
# the unpack root (sys._MEIPASS) when frozen.
datas = [(os.path.join(ROOT, "templates"), "templates"),
         (os.path.join(ROOT, "static"), "static")]
datas += collect_data_files("webview")

# seed_demo is imported by string at runtime; keyring resolves backends
# dynamically; pcrm collectors are imported via the registry — pin them all.
hiddenimports = ["seed_demo"]
hiddenimports += collect_submodules("keyring")
hiddenimports += collect_submodules("pcrm")

a = Analysis(
    [os.path.join(ROOT, "main.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="securitysight",
    debug=False, strip=False, upx=False,
    console=False,            # GUI app — no console window
)
coll = COLLECT(exe, a.binaries, a.zipfiles, a.datas,
               strip=False, upx=False, name="securitysight")

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="securitysight.app",
        icon=None,
        bundle_identifier="com.securitysight.app",
        info_plist={"NSHighResolutionCapable": True,
                    "LSApplicationCategoryType": "public.app-category.utilities"},
    )
