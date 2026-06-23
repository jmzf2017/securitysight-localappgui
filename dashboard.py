#!/usr/bin/env python3
"""Triage dashboard + local API.

  python dashboard.py            # http://localhost:8000

The Flask app (routes, REST API) now lives in pcrm/web.py; this is just the
entry point so `python dashboard.py` and WSGI `dashboard:app` keep working.
Reads the lake's state, serves the ranked queue, and writes triage decisions
back to the lake.
"""

from __future__ import annotations

import os

from pcrm.web import create_app

app = create_app(data_root=os.environ.get("PCRM_DATA", "data"))


if __name__ == "__main__":
    host = os.environ.get("PCRM_HOST", "127.0.0.1")
    port = int(os.environ.get("PCRM_PORT", "8000"))
    app.run(host=host, port=port, debug=False)
