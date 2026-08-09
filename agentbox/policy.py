"""Policy files: what an agent process may touch.

Format — one rule per line, ``#`` comments, comma-separated rules allowed
on a single line::

    allow: read ./src, net: api.github.com

    read:  ./data
    write: ./out
    net:   *.githubusercontent.com
    net:   127.0.0.1:8080
    net:   unix:/tmp/some.sock
    exec:  git status          # argv-prefix match
    exec:  echo                # any args
    env:   HOME
    env:   AWS_*

Rule keys: ``read``, ``write``, ``net``, ``exec``, ``env``. The prefix
``allow: <key> <value>`` is an accepted alias for ``<key>: <value>``.
A bare comma-separated continuation reuses the previous key
(``env: HOME, PATH``). Everything not allowed is denied.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import shlex

__all__ = ["Policy", "PolicyError"]

_KEYS = ("read", "write", "net", "exec", "env")


class PolicyError(ValueError):
    """Raised when a policy file cannot be parsed."""


class Policy:
    def __init__(self, root=".", reads=(), writes=(), nets=(), execs=(), envs=()):
        self.root = os.path.realpath(root)
        self.reads = [self._resolve(p) for p in reads]
        self.writes = [self._resolve(p) for p in writes]
        self.nets = [str(n) for n in nets]
        self.execs = [str(e) for e in execs]
        self.envs = [str(e) for e in envs]

    def _resolve(self, path: str) -> str:
        path = os.path.expanduser(path)
        if not os.path.isabs(path):
            path = os.path.join(self.root, path)
        return os.path.realpath(path)

    # -- parsing ---------------------------------------------------------

    @classmethod
    def parse(cls, text: str, root: str = ".") -> "Policy":
        rules: dict[str, list[str]] = {k: [] for k in _KEYS}
        key: str | None = None
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                key = None
                continue
            for seg in line.split(","):
                seg = seg.strip()
                if not seg:
                    continue
                head = seg.split(":", 1)[0].strip().lower()
                if ":" in seg and head in ("allow", *_KEYS):
                    _, _, value = seg.partition(":")
                    value = value.strip()
                    if head == "allow":
                        verb, _, rest = value.partition(" ")
                        head, value = verb.strip().lower(), rest.strip()
                        if head not in _KEYS:
                            raise PolicyError(
                                f"line {lineno}: unknown verb {head!r} after 'allow:'"
                            )
                    key = head
                else:
                    value = seg
                if key is None:
                    raise PolicyError(f"line {lineno}: value {seg!r} appears before any rule key")
                if not value:
                    raise PolicyError(f"line {lineno}: empty value for {key!r}")
                rules[key].append(value)
        return cls(
            root=root,
            reads=rules["read"],
            writes=rules["write"],
            nets=rules["net"],
            execs=rules["exec"],
            envs=rules["env"],
        )

    @classmethod
    def load(cls, path: str, root: str | None = None) -> "Policy":
        with open(path, encoding="utf-8") as f:
            return cls.parse(f.read(), root=root or os.getcwd())

    # -- decisions -------------------------------------------------------

    @staticmethod
    def _contains(root: str, path: str) -> bool:
        return path == root or path.startswith(root.rstrip(os.sep) + os.sep)

    def allows_read(self, path) -> bool:
        p = os.path.realpath(os.fsdecode(path))
        return any(self._contains(r, p) for r in (*self.reads, *self.writes))

    def allows_write(self, path) -> bool:
        p = os.path.realpath(os.fsdecode(path))
        return any(self._contains(r, p) for r in self.writes)

    def allows_net(self, host, port=None) -> bool:
        if host is None:
            host = "localhost"
        host = os.fsdecode(host).lower().rstrip(".")
        for rule in self.nets:
            if rule.startswith("unix:"):
                continue
            rhost, rport = rule, None
            head, _, tail = rule.rpartition(":")
            if head and tail.isdigit():
                rhost, rport = head, int(tail)
            if fnmatch.fnmatchcase(host, rhost.lower()):
                if rport is None or port is None or int(port) == rport:
                    return True
        return False

    def allows_unix(self, path) -> bool:
        p = os.fsdecode(path)
        return any(
            fnmatch.fnmatchcase(p, rule[5:]) for rule in self.nets if rule.startswith("unix:")
        )

    def allows_exec(self, argv) -> bool:
        if not argv:
            return False
        argv = [os.fsdecode(a) for a in argv]
        for rule in self.execs:
            want = shlex.split(rule)
            if not want:
                continue
            prog = argv[0]
            if prog != want[0] and os.path.basename(prog) != want[0]:
                continue
            if argv[1:len(want)] == want[1:]:
                return True
        return False

    def allows_env(self, name: str) -> bool:
        return any(fnmatch.fnmatchcase(name, rule) for rule in self.envs)

    # -- identity --------------------------------------------------------

    def canonical(self) -> str:
        lines = []
        for k, vals in (
            ("read", self.reads),
            ("write", self.writes),
            ("net", self.nets),
            ("exec", self.execs),
            ("env", self.envs),
        ):
            lines.extend(f"{k}: {v}" for v in sorted(vals))
        return "\n".join(lines) + "\n"

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical().encode()).hexdigest()

    def __repr__(self) -> str:
        return (
            f"Policy(reads={len(self.reads)}, writes={len(self.writes)}, "
            f"nets={len(self.nets)}, execs={len(self.execs)}, envs={len(self.envs)})"
        )
