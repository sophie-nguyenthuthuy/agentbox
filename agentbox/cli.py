"""agentbox CLI: run / replay / show / verify / init."""

from __future__ import annotations

import argparse
import collections
import json
import sys

from . import __version__
from .runtime import run as _run
from .trace import TraceTampered, read_trace, verify_chain

_STARTER_POLICY = """\
# agentbox policy — everything not allowed here is denied.
# Docs: https://github.com/sophie-nguyenthuthuy/agentbox

allow: read ./src
allow: write ./out

# net:  api.github.com
# net:  127.0.0.1
# exec: git status
# env:  HOME
"""


def _command(ns) -> list[str]:
    cmd = list(ns.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        sys.stderr.write("agentbox: no command given (use: agentbox run -p policy -- cmd ...)\n")
        raise SystemExit(2)
    return cmd


def _brief(entry) -> str:
    args = entry.get("args", {})
    for k in ("path", "url", "argv", "host", "target"):
        if k in args:
            v = args[k]
            return " ".join(v) if isinstance(v, list) else str(v)
    return json.dumps(args, ensure_ascii=False)[:60]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="agentbox",
        description="Policy-sandboxed runtime for agent processes: "
        "enforce a policy, capture a trace, replay a run deterministically.",
    )
    p.add_argument("--version", action="version", version=f"agentbox {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("run", help="run a command under policy, recording a trace")
    sp.add_argument("-p", "--policy", default="agentbox.policy")
    sp.add_argument("-t", "--trace", default="trace.jsonl")
    sp.add_argument("--observe", action="store_true", help="log violations instead of blocking")
    sp.add_argument(
        "--checkpoint",
        action="store_true",
        help="take a snapback snapshot before the agent's first mutating effect, "
        "so `snapback undo` reverts the run (needs: pip install snapback-cli)",
    )
    sp.add_argument("command", nargs=argparse.REMAINDER)

    sp = sub.add_parser("replay", help="deterministically replay a recorded trace")
    sp.add_argument("-p", "--policy", default="agentbox.policy")
    sp.add_argument("-t", "--trace", default="trace.jsonl")
    sp.add_argument("command", nargs=argparse.REMAINDER)

    sp = sub.add_parser("show", help="pretty-print a trace")
    sp.add_argument("-t", "--trace", default="trace.jsonl")
    sp.add_argument("--json", action="store_true", help="emit raw JSONL")

    sp = sub.add_parser("verify", help="verify a trace's hash chain")
    sp.add_argument("-t", "--trace", default="trace.jsonl")

    sub.add_parser("init", help="write a starter agentbox.policy")

    ns = p.parse_args(argv)

    if ns.cmd == "init":
        with open("agentbox.policy", "x", encoding="utf-8") as f:
            f.write(_STARTER_POLICY)
        print("wrote agentbox.policy")
        return 0

    if ns.cmd == "run":
        res = _run(
            _command(ns),
            ns.policy,
            ns.trace,
            mode="record",
            enforce=not ns.observe,
            checkpoint=ns.checkpoint,
        )
        entries = read_trace(ns.trace)
        counts = collections.Counter(e["kind"] for e in entries)
        print(
            f"agentbox: recorded {counts.get('effect', 0)} effects, "
            f"{counts.get('observe', 0)} observations, {counts.get('deny', 0)} denials "
            f"-> {ns.trace}"
        )
        snap = next(
            (e for e in entries if e["kind"] == "effect" and e["op"] == "hook.checkpoint"), None
        )
        if snap and snap.get("result"):
            print(
                f"agentbox: checkpoint {snap['result']['snapshot']} taken before first "
                f"mutation — `snapback undo` reverts this run"
            )
        return res.returncode

    if ns.cmd == "replay":
        try:
            res = _run(_command(ns), ns.policy, ns.trace, mode="replay")
        except TraceTampered as exc:
            print(f"agentbox: TAMPERED trace: {exc}")
            return 1
        if res.replay_ok:
            print(
                f"agentbox: replay ok — {res.report['consumed']}/{res.report['total']} "
                f"recorded steps matched"
            )
            return 0
        print("agentbox: replay FAILED")
        for prob in res.problems:
            print(f"  - {prob}")
        return res.returncode or 1

    entries = read_trace(ns.trace)

    if ns.cmd == "verify":
        ok, bad = verify_chain(entries)
        if ok:
            print(f"agentbox: trace ok — {len(entries)} entries, hash chain verified")
            return 0
        print(f"agentbox: TAMPERED — hash chain breaks at entry {bad}")
        return 1

    if ns.cmd == "show":
        for e in entries:
            if ns.json:
                print(json.dumps(e, ensure_ascii=False))
            else:
                print(f"{e['i']:>4}  {e['kind']:<8} {e['op']:<15} {_brief(e)}")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
