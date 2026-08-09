"""Injected via PYTHONPATH into every sandboxed Python process.

Python imports ``sitecustomize`` automatically at startup, so the guard is
armed before any user code runs. Fails closed: if the sandbox cannot be
armed, the process exits instead of running unguarded.
"""

import os
import sys

if os.environ.get("AGENTBOX_POLICY"):
    try:
        from agentbox.guard import install_from_env

        install_from_env()
    except Exception as exc:  # noqa: BLE001 - anything here means "not sandboxed"
        sys.stderr.write(f"agentbox: failed to arm sandbox, refusing to run: {exc!r}\n")
        os._exit(70)
