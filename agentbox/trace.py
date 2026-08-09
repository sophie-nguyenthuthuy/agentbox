"""Tamper-evident run traces: hash-chained JSONL.

Every entry carries ``prev`` (the previous entry's sha) and ``sha``
(sha256 over prev + the canonical JSON of the entry body), so any edit,
deletion, or reordering breaks the chain and is detected by
:func:`verify_chain`.

Entry kinds:

* ``meta``    — run header/footer written by the runner
* ``effect``  — an SDK effect with its recorded result (replayable)
* ``observe`` — a guard-witnessed side effect (verified on replay)
* ``deny``    — a policy violation (blocked, or logged in observe mode)
"""

from __future__ import annotations

import hashlib
import json
import os
import time

from ._internal import quiet

GENESIS = "0" * 64

__all__ = ["GENESIS", "TraceTampered", "TraceWriter", "canonical_json", "read_trace", "verify_chain"]


class TraceTampered(RuntimeError):
    """Raised when a trace's hash chain does not verify."""


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_sha(entry: dict, prev: str) -> str:
    body = {k: v for k, v in entry.items() if k != "sha"}
    return hashlib.sha256((prev + canonical_json(body)).encode()).hexdigest()


class TraceWriter:
    """Appends chained entries; continues an existing chain unless fresh=True."""

    def __init__(self, path: str, fresh: bool = False):
        self.path = path
        self._prev, self._i = GENESIS, 0
        with quiet():
            if fresh and os.path.exists(path):
                os.remove(path)
            elif os.path.exists(path) and os.path.getsize(path):
                last = read_trace(path)[-1]
                self._prev, self._i = last["sha"], last["i"] + 1

    def append(self, kind: str, op: str, args: dict, result=None) -> dict:
        entry: dict = {"i": self._i, "ts": round(time.time(), 6), "kind": kind, "op": op, "args": args}
        if result is not None:
            entry["result"] = result
        entry["prev"] = self._prev
        entry["sha"] = entry_sha(entry, self._prev)
        with quiet():
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(canonical_json(entry) + "\n")
        self._prev = entry["sha"]
        self._i += 1
        return entry


def read_trace(path: str) -> list[dict]:
    with quiet():
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]


def verify_chain(entries: list[dict]):
    """Return (True, None) if the chain verifies, else (False, first_bad_index)."""
    prev = GENESIS
    for idx, e in enumerate(entries):
        if e.get("i") != idx or e.get("prev") != prev or e.get("sha") != entry_sha(e, prev):
            return False, idx
        prev = e["sha"]
    return True, None
