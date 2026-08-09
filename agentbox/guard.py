"""Process-level enforcement via ``sys.addaudithook``.

Installed automatically inside sandboxed children (see
``_inject/sitecustomize.py``). CPython audit hooks cannot be removed once
added, so the agent's own code cannot disarm the guard. The hook:

* blocks file opens outside the policy's read/write roots
  (stdlib and ``sys.path`` ``.py`` imports are allowed silently),
* blocks DNS/socket connects to hosts the policy doesn't allow,
* blocks subprocess spawns whose argv doesn't match an ``exec:`` rule,
* blocks ``ctypes`` dlopen/dlsym (the classic audit-hook bypass),
* records every *allowed* side effect into the trace as an ``observe``
  entry (reads carry a content sha256, so replay detects changed inputs),
* records every denial as a ``deny`` entry.

In replay mode all live network and subprocess spawns are blocked —
replayable effects must go through :mod:`agentbox.client`.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import sys

from ._internal import is_quiet, quiet

__all__ = ["GuardError", "install", "install_from_env"]

_HASH_CAP = 1_000_000  # hash file contents up to 1 MB; log size above
_installed = False


class GuardError(PermissionError):
    """Raised (from inside the triggering call) when the policy denies an action."""


def install_from_env():
    from . import client

    sess = client.session()
    enforce = os.environ.get("AGENTBOX_ENFORCE", "1") != "0"
    install(sess.policy, session=sess, mode=sess.mode, enforce=enforce)


def install(policy, session=None, mode="record", enforce=True):
    global _installed
    if _installed:
        return
    _installed = True

    pkg_dir = os.path.dirname(os.path.realpath(__file__))
    silent_roots = tuple(
        {os.path.realpath(p) for p in (sys.prefix, sys.base_prefix, sys.exec_prefix, pkg_dir)}
    )

    def in_syspath(rp):
        # Checked live, not snapshotted: the script's own directory lands on
        # sys.path only after site processing (i.e. after we are installed).
        return any(
            contains(os.path.realpath(p), rp) for p in sys.path if p
        )

    def _env_path(name):
        v = os.environ.get(name)
        return os.path.realpath(v) if v else None

    trace_path = _env_path("AGENTBOX_TRACE")
    policy_path = _env_path("AGENTBOX_POLICY")
    report_path = _env_path("AGENTBOX_REPORT")
    allowed_ips: set = set()

    def contains(root, p):
        return p == root or p.startswith(root.rstrip(os.sep) + os.sep)

    def deny(op, target):
        if session is not None and session.mode == "record":
            try:
                session.record("deny", op, {"target": str(target), "enforced": bool(enforce)})
            except Exception:
                pass
        if enforce:
            raise GuardError(f"agentbox: policy denies {op} {target}")
        with quiet():
            sys.stderr.write(f"agentbox[observe]: would deny {op} {target}\n")

    def observe(op, args):
        if session is not None:
            session.observe(op, args)

    def _is_write(mode_s, flags):
        if isinstance(mode_s, str):
            return any(c in mode_s for c in "wax+")
        f = flags or 0
        return bool(f & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC))

    def on_open(args):
        path, mode_s, flags = (tuple(args) + (None, None, None))[:3]
        if path is None or isinstance(path, int):
            return
        try:
            p = os.fsdecode(path)
        except Exception:
            return
        rp = os.path.realpath(p)
        if rp in (trace_path, report_path) or rp == os.devnull:
            return
        writing = _is_write(mode_s, flags)
        if not writing:
            if rp == policy_path:
                return
            if any(contains(r, rp) for r in silent_roots):
                return
            if rp.endswith((".py", ".pyc", ".pth", ".pyi")) and in_syspath(rp):
                return
        if writing:
            if policy.allows_write(rp):
                observe("fs.open_write", {"path": p})
                return
            deny("write", p)
            return
        if policy.allows_read(rp):
            info = {"path": p}
            with quiet():
                try:
                    st = os.stat(rp)
                    if os.path.isfile(rp) and st.st_size <= _HASH_CAP:
                        with open(rp, "rb") as f:
                            info["sha256"] = hashlib.sha256(f.read()).hexdigest()
                    else:
                        info["size"] = st.st_size
                except OSError:
                    info["exists"] = False
            observe("fs.open_read", info)
            return
        deny("read", p)

    def on_getaddrinfo(args):
        host, port = args[0], args[1]
        if mode == "replay":
            deny("net", f"{host!r} (replay mode blocks all live network; use agentbox.client)")
            return
        if policy.allows_net(host, port):
            with quiet():
                try:
                    import socket

                    for info in socket.getaddrinfo(os.fsdecode(host) if host else None, port):
                        allowed_ips.add(info[4][0])
                except OSError:
                    pass
            observe("net.resolve", {"host": os.fsdecode(host) if host is not None else None})
            return
        deny("net", os.fsdecode(host) if host is not None else "<none>")

    def on_connect(args):
        addr = args[1]
        if isinstance(addr, tuple) and len(addr) >= 2:
            host, port = addr[0], addr[1]
            if mode == "replay":
                deny("net", f"{host}:{port} (replay mode blocks all live network)")
                return
            if host in allowed_ips or policy.allows_net(host, port):
                return
            deny("net", f"{host}:{port}")
        elif isinstance(addr, (str, bytes)):
            p = os.fsdecode(addr)
            if not policy.allows_unix(p):
                deny("net", f"unix:{p}")

    def on_spawn(argv, label):
        argv = [os.fsdecode(a) for a in argv if a is not None]
        if not argv:
            deny("exec", label)
            return
        if mode == "replay":
            deny("exec", f"{argv[0]} (replay mode blocks spawns; use agentbox.client.run)")
            return
        if policy.allows_exec(argv):
            observe("proc.spawn", {"argv": argv})
            return
        deny("exec", shlex.join(argv))

    def hook(event, args):
        if is_quiet():
            return
        try:
            if event == "open":
                on_open(args)
            elif event == "socket.getaddrinfo":
                on_getaddrinfo(args)
            elif event == "socket.connect":
                on_connect(args)
            elif event == "subprocess.Popen":
                executable, cmd = args[0], args[1]
                argv = cmd if isinstance(cmd, (list, tuple)) else [cmd or executable]
                on_spawn(argv, "subprocess.Popen")
            elif event == "os.system":
                on_spawn(shlex.split(os.fsdecode(args[0])), "os.system")
            elif event == "os.posix_spawn":
                on_spawn(args[1] or [args[0]], "os.posix_spawn")
            elif event == "os.exec":
                on_spawn(args[1] or [args[0]], "os.exec")
            elif event == "os.spawn":
                on_spawn(args[2] or [args[1]], "os.spawn")
            elif event in ("ctypes.dlopen", "ctypes.dlsym"):
                deny("ctypes", args[0] if args else event)
            elif event in ("os.remove", "os.rmdir", "os.truncate", "shutil.rmtree", "os.mkdir"):
                p = os.path.realpath(os.fsdecode(args[0]))
                if p not in (trace_path, report_path) and not policy.allows_write(p):
                    deny("write", os.fsdecode(args[0]))
            elif event == "os.rename":
                for a in args[:2]:
                    if not policy.allows_write(os.path.realpath(os.fsdecode(a))):
                        deny("write", os.fsdecode(a))
        except Exception as exc:
            if isinstance(exc, PermissionError) or exc.__class__.__name__ == "ReplayDivergence":
                raise
            # A guard bug must not brick unrelated stdlib calls: warn, allow.
            with quiet():
                sys.stderr.write(f"agentbox: guard error on {event}: {exc!r}\n")

    sys.addaudithook(hook)
