"""Spawn a command inside the sandbox, in record or replay mode.

The child gets a scrubbed environment (only ``env:``-allowed variables
plus a small safe set pass through), ``PYTHONPATH`` prepended with the
injection shim so any Python process arms the guard before user code
runs, and ``AGENTBOX_*`` variables describing the policy, trace, and mode.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

from . import __version__
from .policy import Policy
from .trace import TraceTampered, TraceWriter, read_trace, verify_chain

__all__ = ["RunResult", "run"]

_SAFE_ENV = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR", "SYSTEMROOT", "COMSPEC")


@dataclass
class RunResult:
    returncode: int
    mode: str
    stdout: str | None = None
    stderr: str | None = None
    report: dict | None = None
    problems: list = field(default_factory=list)

    @property
    def replay_ok(self) -> bool:
        return self.mode == "replay" and self.returncode == 0 and not self.problems


def _pkg_dir() -> str:
    return os.path.dirname(os.path.realpath(__file__))


def build_env(policy, policy_path, trace_path, mode, enforce, report_path, root) -> dict:
    env = {k: os.environ[k] for k in _SAFE_ENV if k in os.environ}
    for k, v in os.environ.items():
        if policy.allows_env(k):
            env[k] = v
    if "HOME" not in env:
        home = os.path.join(tempfile.gettempdir(), "agentbox-home")
        os.makedirs(home, exist_ok=True)
        env["HOME"] = home
    parts = [os.path.join(_pkg_dir(), "_inject"), os.path.dirname(_pkg_dir())]
    if os.environ.get("PYTHONPATH"):
        parts.append(os.environ["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(parts)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    env["AGENTBOX_POLICY"] = os.path.abspath(policy_path)
    env["AGENTBOX_TRACE"] = os.path.abspath(trace_path)
    env["AGENTBOX_MODE"] = mode
    env["AGENTBOX_ENFORCE"] = "1" if enforce else "0"
    env["AGENTBOX_ROOT"] = root
    if report_path:
        env["AGENTBOX_REPORT"] = os.path.abspath(report_path)
    return env


def run(
    argv,
    policy_path,
    trace_path="trace.jsonl",
    mode="record",
    enforce=True,
    cwd=None,
    capture=False,
) -> RunResult:
    if mode not in ("record", "replay"):
        raise ValueError(f"unknown mode {mode!r}")
    root = os.path.abspath(cwd or os.getcwd())
    policy = Policy.load(policy_path, root=root)

    report_path = None
    if mode == "record":
        writer = TraceWriter(trace_path, fresh=True)
        writer.append(
            "meta",
            "run.start",
            {
                "argv": list(argv),
                "policy_sha256": policy.sha256,
                "agentbox": __version__,
                "python": sys.version.split()[0],
            },
        )
    else:
        entries = read_trace(trace_path)
        ok, bad = verify_chain(entries)
        if not ok:
            raise TraceTampered(f"trace hash chain breaks at entry {bad}")
        meta = next((e for e in entries if e["kind"] == "meta"), None)
        recorded_sha = meta["args"].get("policy_sha256") if meta else None
        if recorded_sha and recorded_sha != policy.sha256:
            sys.stderr.write("agentbox: warning: policy differs from the one used at record time\n")
        fd, report_path = tempfile.mkstemp(prefix="agentbox-report-", suffix=".json")
        os.close(fd)

    env = build_env(policy, policy_path, trace_path, mode, enforce, report_path, root)
    proc = subprocess.run(list(argv), env=env, cwd=root, capture_output=capture, text=True)

    result = RunResult(
        returncode=proc.returncode,
        mode=mode,
        stdout=proc.stdout if capture else None,
        stderr=proc.stderr if capture else None,
    )

    if mode == "record":
        TraceWriter(trace_path).append("meta", "run.end", {"returncode": proc.returncode})
    else:
        report = None
        try:
            if os.path.getsize(report_path):
                with open(report_path, encoding="utf-8") as f:
                    report = json.load(f)
        except OSError:
            pass
        finally:
            try:
                os.remove(report_path)
            except OSError:
                pass
        result.report = report
        if proc.returncode != 0:
            result.problems.append(f"process exited with code {proc.returncode}")
        if report is None:
            result.problems.append("no replay report written (process died before exit hooks?)")
        else:
            if report.get("diverged"):
                result.problems.append(f"diverged: {report['diverged']}")
            elif report.get("consumed", 0) < report.get("total", 0):
                result.problems.append(
                    f"incomplete replay: only {report['consumed']} of {report['total']} "
                    f"recorded steps happened"
                )
        if result.problems and result.returncode == 0:
            result.returncode = 1
    return result
