"""End-to-end guard tests: real sandboxed subprocesses via runtime.run."""

import json

import pytest

from agentbox.trace import read_trace, verify_chain

BASE_POLICY = """
read:  ./data
write: ./out
"""


@pytest.fixture(autouse=True)
def workdir(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "out").mkdir()
    (tmp_path / "data" / "in.txt").write_text("hello guard")
    (tmp_path / "secret.txt").write_text("do not read me")
    return tmp_path


def test_allowed_read_write_and_observed(sandbox_run, tmp_path):
    res = sandbox_run(
        BASE_POLICY,
        """
        data = open("data/in.txt").read()
        with open("out/result.txt", "w") as f:
            f.write(data.upper())
        print("ok")
        """,
    )
    assert res.returncode == 0, res.stderr
    assert (tmp_path / "out" / "result.txt").read_text() == "HELLO GUARD"
    entries = read_trace(str(tmp_path / "trace.jsonl"))
    assert verify_chain(entries) == (True, None)
    ops = [(e["kind"], e["op"]) for e in entries]
    assert ("observe", "fs.open_read") in ops
    assert ("observe", "fs.open_write") in ops
    read = next(e for e in entries if e["op"] == "fs.open_read")
    assert "sha256" in read["args"]


def test_denied_read_blocks(sandbox_run):
    res = sandbox_run(BASE_POLICY, 'open("secret.txt").read()\n')
    assert res.returncode != 0
    assert "policy denies read" in res.stderr


def test_denied_write_blocks(sandbox_run, tmp_path):
    res = sandbox_run(BASE_POLICY, 'open("data/evil.txt", "w").write("x")\n')
    assert res.returncode != 0
    assert "policy denies write" in res.stderr
    assert not (tmp_path / "data" / "evil.txt").exists()


def test_observe_mode_logs_but_allows(sandbox_run, tmp_path):
    res = sandbox_run(BASE_POLICY, 'print(open("secret.txt").read())\n', enforce=False)
    assert res.returncode == 0
    assert "would deny read" in res.stderr
    denies = [e for e in read_trace(str(tmp_path / "trace.jsonl")) if e["kind"] == "deny"]
    assert denies and denies[0]["args"]["enforced"] is False


def test_net_denied_by_default(sandbox_run):
    res = sandbox_run(
        BASE_POLICY,
        """
        import socket
        socket.create_connection(("127.0.0.1", 9), timeout=1)
        """,
    )
    assert res.returncode != 0
    assert "policy denies net" in res.stderr


def test_net_allowed_host_works(sandbox_run, http_server):
    res = sandbox_run(
        BASE_POLICY + "net: 127.0.0.1\n",
        """
        import sys, urllib.request
        body = urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/").read()
        assert body == b"hello from server", body
        print("net ok")
        """,
        args=[http_server],
    )
    assert res.returncode == 0, res.stderr
    assert "net ok" in res.stdout


def test_exec_allowlist(sandbox_run):
    ok = sandbox_run(
        BASE_POLICY + "exec: echo\n",
        """
        import subprocess
        print(subprocess.run(["echo", "spawned"], capture_output=True, text=True).stdout)
        """,
    )
    assert ok.returncode == 0, ok.stderr
    assert "spawned" in ok.stdout

    denied = sandbox_run(
        BASE_POLICY + "exec: echo\n",
        'import subprocess; subprocess.run(["ls", "-la"])\n',
    )
    assert denied.returncode != 0
    assert "policy denies exec" in denied.stderr


def test_os_system_respects_exec_rules(sandbox_run):
    denied = sandbox_run(BASE_POLICY, 'import os; os.system("ls -la")\n')
    assert denied.returncode != 0
    assert "policy denies exec" in denied.stderr


def test_ctypes_dlopen_denied(sandbox_run):
    res = sandbox_run(
        BASE_POLICY,
        """
        import ctypes
        ctypes.CDLL(None)
        """,
    )
    assert res.returncode != 0
    assert "ctypes" in res.stderr


def test_env_is_scrubbed(sandbox_run, monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "leaky")
    monkeypatch.setenv("MY_ALLOWED", "visible")
    res = sandbox_run(
        BASE_POLICY + "env: MY_ALLOWED\n",
        """
        import os
        assert "SECRET_TOKEN" not in os.environ, "secret leaked"
        assert os.environ["MY_ALLOWED"] == "visible"
        print("env ok")
        """,
    )
    assert res.returncode == 0, res.stderr
    assert "env ok" in res.stdout


def test_delete_outside_write_roots_denied(sandbox_run, tmp_path):
    res = sandbox_run(BASE_POLICY, 'import os; os.remove("secret.txt")\n')
    assert res.returncode != 0
    assert "policy denies write" in res.stderr
    assert (tmp_path / "secret.txt").exists()
