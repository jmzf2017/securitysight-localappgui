# Packaging securitysight as a desktop app

Builds a self-contained desktop app (native window via pywebview, Python +
the local server bundled) with PyInstaller. **v1 bundles are unsigned** — see
the warnings below. Build on the target OS (PyInstaller does not cross-compile).

## Prerequisites
```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt   # includes pyinstaller
```

## Build

**macOS**
```bash
packaging/build_macos.sh            # -> dist/securitysight.app
open dist/securitysight.app
```

**Windows** (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1   # -> dist\securitysight\securitysight.exe
```

The data lake, settings and KEV cache live in the OS per-user dir
(`~/Library/Application Support/securitysight` on macOS,
`%LOCALAPPDATA%\securitysight` on Windows). API keys go in the OS keychain.

## Headless / server mode

The same binary can run as a local server with no window — handy for a smoke
test or for power users:
```bash
dist/securitysight.app/Contents/MacOS/securitysight --server     # prints the URL
```

## Windows: WebView2 runtime

pywebview renders via **Edge WebView2** on Windows. It's preinstalled on current
Windows 10/11, but on older builds the window will be blank until the user
installs the **Evergreen WebView2 Runtime** (free, from Microsoft). Bundle the
runtime installer alongside the `.exe`, or document the one-time download.

## Unsigned bundles (v1)

These builds are **not code-signed**, so the OS will warn on first launch:

- **macOS (Gatekeeper):** right-click the app → **Open** → **Open**, or
  `xattr -dr com.apple.quarantine dist/securitysight.app`.
- **Windows (SmartScreen):** **More info** → **Run anyway**.

Before any external/wide release, add signing:
- macOS: Developer ID signing + notarization (`codesign` + `notarytool`).
- Windows: Authenticode signing (`signtool`) with an OV/EV certificate.
