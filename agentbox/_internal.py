"""Thread-local re-entrancy flag shared by the guard, trace, and client.

While the flag is raised, the audit-hook guard ignores events — used for
agentbox's own bookkeeping IO (trace appends, file hashing, sanctioned
effects) so it is neither blocked nor double-logged.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager

_tl = threading.local()


def is_quiet() -> bool:
    return getattr(_tl, "depth", 0) > 0


@contextmanager
def quiet():
    _tl.depth = getattr(_tl, "depth", 0) + 1
    try:
        yield
    finally:
        _tl.depth -= 1
