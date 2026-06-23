#!/usr/bin/env python3
"""securitysight desktop entry point.

Runs the Flask app in a background thread on an ephemeral localhost port and
shows it in a native window (pywebview / OS webview). Single-user, single
instance. Data + secrets live in the OS per-user locations.

  python main.py
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time

APP_NAME = "securitysight"
_LOCK_PORT = 49517          # fixed port held for the process lifetime as a mutex


def data_dir() -> str:
    """Per-user data directory (created if missing). Uses platformdirs so it's
    correct on macOS (~/Library/Application Support) and Windows (%LOCALAPPDATA%)."""
    import platformdirs
    d = platformdirs.user_data_dir(APP_NAME, APP_NAME)
    os.makedirs(d, exist_ok=True)
    return d


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def single_instance_lock(port: int = _LOCK_PORT):
    """Bind a fixed loopback port as a mutex. Returns the held socket if we're
    the only instance, else None (another instance already holds it)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        s.listen(1)
        return s
    except OSError:
        s.close()
        return None


def wait_until_up(port: int, timeout: float = 12.0) -> bool:
    import urllib.request
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/version", timeout=1)
            return True
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    return False


def _serve(app, port: int) -> None:
    app.run(host="127.0.0.1", port=port, threaded=True, use_reloader=False)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    headless = "--server" in argv          # run the server only, no native window

    if not headless:
        lock = single_instance_lock()
        if lock is None:
            print(f"{APP_NAME} is already running.", file=sys.stderr)
            return 1

    os.environ.setdefault("PCRM_DATA", data_dir())
    from pcrm.web import create_app

    app = create_app(data_root=os.environ["PCRM_DATA"])

    if headless:
        # Foreground server, no window — useful for power users and for smoke-
        # testing the packaged bundle.
        port = int(os.environ.get("PCRM_PORT", "0")) or free_port()
        print(f"securitysight serving on http://127.0.0.1:{port}  (Ctrl+C to stop)")
        _serve(app, port)
        return 0

    port = free_port()
    threading.Thread(target=_serve, args=(app, port), daemon=True).start()
    if not wait_until_up(port):
        print("server failed to start", file=sys.stderr)
        return 1

    import webview
    webview.create_window(APP_NAME, f"http://127.0.0.1:{port}",
                          width=1180, height=820, min_size=(900, 600))
    webview.start()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
