"""In-agent SDK: effects that are recorded once and replayed deterministically.

Inside a sandboxed process::

    import agentbox.client as box

    text = box.read_text("data/notes.txt")
    resp = box.get("https://api.github.com/repos/x/y")
    out  = box.run(["git", "status"])
    t    = box.now()
    r    = box.random()
    box.write_text("out/report.md", text.upper())

In **record** mode each call performs the real effect (after a policy
check) and appends it to the trace. In **replay** mode no real effect
happens: the next recorded entry must match the call (op + args), and its
recorded result is returned. Any mismatch raises :class:`ReplayDivergence`.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import random as _random
import subprocess
import time
import urllib.parse
import urllib.request

from ._internal import quiet
from .policy import Policy
from .trace import TraceWriter, read_trace

__all__ = ["CheckpointError", "PolicyViolation", "ReplayDivergence", "Session", "session"]


class ReplayDivergence(RuntimeError):
    """The live run issued a different effect sequence than the recording."""


class CheckpointError(RuntimeError):
    """A requested pre-mutation checkpoint could not be taken.

    Fails closed: the mutating effect that triggered the checkpoint is
    blocked — a run that was promised to be undoable never half-happens.
    """


class PolicyViolation(PermissionError):
    """An effect was requested that the policy does not allow."""


def _key(args: dict) -> str:
    return json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(data) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


class Session:
    def __init__(
        self,
        policy: Policy,
        trace_path: str,
        mode: str = "record",
        report_path=None,
        checkpoint: bool = False,
    ):
        if mode not in ("record", "replay"):
            raise ValueError(f"unknown mode {mode!r}")
        self.policy = policy
        self.mode = mode
        self.diverged = None
        self.report_path = report_path
        self.checkpoint = checkpoint
        self._checkpointed = False
        if mode == "record":
            self.writer = TraceWriter(trace_path)
        else:
            # hook.* effects are runner infrastructure (e.g. --checkpoint), not
            # agent behavior — replay compares agent-issued effects only.
            self.entries = [
                e
                for e in read_trace(trace_path)
                if e["kind"] in ("effect", "observe") and not e["op"].startswith("hook.")
            ]
            self.cursor = 0
            if report_path:
                atexit.register(self._write_report)

    @classmethod
    def from_env(cls) -> "Session":
        policy = Policy.load(
            os.environ["AGENTBOX_POLICY"],
            root=os.environ.get("AGENTBOX_ROOT") or os.getcwd(),
        )
        return cls(
            policy,
            os.environ["AGENTBOX_TRACE"],
            mode=os.environ.get("AGENTBOX_MODE", "record"),
            report_path=os.environ.get("AGENTBOX_REPORT"),
            checkpoint=os.environ.get("AGENTBOX_CHECKPOINT") == "1",
        )

    def _write_report(self):
        with quiet():
            with open(self.report_path, "w", encoding="utf-8") as f:
                json.dump(
                    {"consumed": self.cursor, "total": len(self.entries), "diverged": self.diverged},
                    f,
                )

    # -- core ------------------------------------------------------------

    def record(self, kind: str, op: str, args: dict, result=None) -> dict:
        return self.writer.append(kind, op, args, result)

    def expect(self, kind: str, op: str, args: dict) -> dict:
        if self.cursor >= len(self.entries):
            self._diverge(
                f"live run issued {op} {_key(args)} but the recording ended "
                f"after {len(self.entries)} steps"
            )
        e = self.entries[self.cursor]
        if e["kind"] != kind or e["op"] != op or _key(e["args"]) != _key(args):
            self._diverge(
                f"step {e['i']}: recorded {e['kind']} {e['op']} {_key(e['args'])}, "
                f"but live run issued {kind} {op} {_key(args)}"
            )
        self.cursor += 1
        return e

    def _diverge(self, msg: str):
        self.diverged = msg
        raise ReplayDivergence(msg)

    def effect(self, op: str, args: dict, do):
        if self.mode == "record":
            with quiet():
                result = do()
            self.record("effect", op, args, result)
            return result
        return self.expect("effect", op, args).get("result")

    def observe(self, op: str, args: dict):
        if self.mode == "record":
            self.record("observe", op, args)
        else:
            self.expect("observe", op, args)

    # -- pre-mutation checkpoint (snapback) -------------------------------

    def _pre_mutation(self, tool: str, detail: str):
        """Take one snapback snapshot before the first mutating effect.

        Lazy: runs that never mutate cost nothing. Recorded as a ``hook.*``
        effect so the checkpoint id lives inside the hash-chained trace; on
        replay nothing runs (hook effects are filtered from expectations).
        The snapback subprocess gets a scrubbed environment — without it, the
        injected sitecustomize shim would arm a sandbox inside snapback and
        deny its own snapshot IO.
        """
        if not self.checkpoint or self.mode != "record" or self._checkpointed:
            return

        def do():
            env = {
                k: v
                for k, v in os.environ.items()
                if k not in ("PYTHONPATH", "NODE_OPTIONS") and not k.startswith("AGENTBOX")
            }
            try:
                p = subprocess.run(
                    ["snapback", "snap", "-m", f"agentbox: before {tool} {detail}"],
                    capture_output=True,
                    text=True,
                    env=env,
                )
            except FileNotFoundError:
                raise CheckpointError(
                    "checkpoint requested but snapback is not on PATH "
                    "(pip install snapback-cli)"
                ) from None
            if p.returncode != 0:
                raise CheckpointError(
                    f"snapback checkpoint failed: {p.stderr.strip() or p.stdout.strip()}"
                )
            return {"snapshot": p.stdout.strip().rsplit(" ", 1)[-1], "undo": "snapback undo"}

        self.effect("hook.checkpoint", {"tool": tool, "detail": detail}, do)
        self._checkpointed = True

    # -- effects ---------------------------------------------------------

    def read_text(self, path) -> str:
        if not self.policy.allows_read(os.path.abspath(path)):
            raise PolicyViolation(f"policy denies read {path}")

        def do():
            with open(path, encoding="utf-8") as f:
                return f.read()

        return self.effect("fs.read_text", {"path": str(path)}, do)

    def write_text(self, path, text: str) -> dict:
        if not self.policy.allows_write(os.path.abspath(path)):
            raise PolicyViolation(f"policy denies write {path}")
        self._pre_mutation("fs.write_text", str(path))

        def do():
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            return {"bytes": len(text.encode())}

        return self.effect("fs.write_text", {"path": str(path), "sha256": _sha(text)}, do)

    def get(self, url: str, headers=None) -> dict:
        parts = urllib.parse.urlsplit(url)
        if not self.policy.allows_net(parts.hostname, parts.port):
            raise PolicyViolation(f"policy denies net {parts.hostname}")

        def do():
            req = urllib.request.Request(url, headers=headers or {}, method="GET")
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read()
            return {
                "status": resp.status,
                "body": body.decode("utf-8", "replace"),
                "sha256": _sha(body),
            }

        return self.effect("net.get", {"url": url}, do)

    def run(self, argv) -> dict:
        argv = [str(a) for a in argv]
        if not self.policy.allows_exec(argv):
            raise PolicyViolation(f"policy denies exec {argv[0]}")
        self._pre_mutation("proc.run", argv[0])

        def do():
            p = subprocess.run(argv, capture_output=True, text=True)
            return {"code": p.returncode, "stdout": p.stdout, "stderr": p.stderr}

        return self.effect("proc.run", {"argv": argv}, do)

    def now(self) -> float:
        return self.effect("clock.now", {}, time.time)

    def random(self) -> float:
        return self.effect("rand.random", {}, _random.random)


# -- module-level convenience (configured from AGENTBOX_* env) ------------

_session: Session | None = None


def session() -> Session:
    global _session
    if _session is None:
        _session = Session.from_env()
    return _session


def read_text(path):
    return session().read_text(path)


def write_text(path, text):
    return session().write_text(path, text)


def get(url, headers=None):
    return session().get(url, headers=headers)


def run(argv):
    return session().run(argv)


def now():
    return session().now()


def random():
    return session().random()
