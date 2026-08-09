"""Node runtime shim tests: real `node` children under the Python runner.

Also the cross-language compatibility proof: entries appended by the JS shim
must extend the hash chain started by the Python runner, and verify with the
Python `verify_chain`.
"""

import shutil
import sys
import textwrap

import pytest

from agentbox import runtime
from agentbox.trace import read_trace, verify_chain

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

POLICY = """
read:  ./data
write: ./out
"""

SDK_AGENT = """
const box = globalThis.agentbox;
const n = Number(process.argv[2]);
const text = box.readText("data/in.txt");
for (let i = 0; i < n; i++) box.writeText(`out/r${i}.txt`, text.toUpperCase());
console.log("done", box.now(), box.random());
"""


@pytest.fixture(autouse=True)
def workdir(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "out").mkdir()
    (tmp_path / "data" / "in.txt").write_text("hello node")
    (tmp_path / "secret.txt").write_text("do not read me")
    return tmp_path


@pytest.fixture
def node_run(tmp_path):
    def _run(policy_text, agent_code, mode="record", enforce=True, args=()):
        (tmp_path / "agent.js").write_text(textwrap.dedent(agent_code))
        (tmp_path / "agentbox.policy").write_text(textwrap.dedent(policy_text))
        return runtime.run(
            ["node", "agent.js", *[str(a) for a in args]],
            policy_path=str(tmp_path / "agentbox.policy"),
            trace_path=str(tmp_path / "trace.jsonl"),
            mode=mode,
            enforce=enforce,
            cwd=str(tmp_path),
            capture=True,
        )

    return _run


def test_direct_fs_guarded_and_cross_language_chain(node_run, tmp_path):
    res = node_run(
        POLICY,
        """
        const fs = require("fs");
        const data = fs.readFileSync("data/in.txt", "utf8");
        fs.writeFileSync("out/result.txt", data.toUpperCase());
        console.log("ok");
        """,
    )
    assert res.returncode == 0, res.stderr
    assert (tmp_path / "out" / "result.txt").read_text() == "HELLO NODE"
    entries = read_trace(str(tmp_path / "trace.jsonl"))
    # JS-written entries extend the Python-written meta and verify in Python
    assert verify_chain(entries) == (True, None)
    ops = [(e["kind"], e["op"]) for e in entries]
    assert ("meta", "run.start") in ops
    assert ("observe", "fs.open_read") in ops
    assert ("observe", "fs.open_write") in ops
    read = next(e for e in entries if e["op"] == "fs.open_read")
    assert "sha256" in read["args"]


def test_denied_read_blocks(node_run):
    res = node_run(POLICY, 'require("fs").readFileSync("secret.txt", "utf8");\n')
    assert res.returncode != 0
    assert "policy denies read" in res.stderr


def test_denied_write_blocks(node_run, tmp_path):
    res = node_run(POLICY, 'require("fs").writeFileSync("data/evil.txt", "x");\n')
    assert res.returncode != 0
    assert "policy denies write" in res.stderr
    assert not (tmp_path / "data" / "evil.txt").exists()


def test_net_denied_by_default(node_run):
    res = node_run(
        POLICY,
        """
        const net = require("net");
        net.createConnection({ host: "127.0.0.1", port: 9 });
        """,
    )
    assert res.returncode != 0
    assert "policy denies net" in res.stderr


def test_net_allowed_host_works(node_run, http_server):
    res = node_run(
        POLICY + "net: 127.0.0.1\n",
        """
        const http = require("http");
        http.get(`http://127.0.0.1:${process.argv[2]}/`, (r) => {
          const chunks = [];
          r.on("data", (c) => chunks.push(c));
          r.on("end", () => console.log("got:", Buffer.concat(chunks).toString()));
        });
        """,
        args=[http_server],
    )
    assert res.returncode == 0, res.stderr
    assert "got: hello from server" in res.stdout


def test_exec_allowlist(node_run):
    ok = node_run(
        POLICY + "exec: echo\n",
        'console.log(require("child_process").execFileSync("echo", ["spawned"], {encoding: "utf8"}));\n',
    )
    assert ok.returncode == 0, ok.stderr
    assert "spawned" in ok.stdout

    denied = node_run(
        POLICY + "exec: echo\n",
        'require("child_process").execFileSync("ls", ["-la"]);\n',
    )
    assert denied.returncode != 0
    assert "policy denies exec" in denied.stderr


def test_env_is_scrubbed(node_run, monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "leaky")
    monkeypatch.setenv("MY_ALLOWED", "visible")
    res = node_run(
        POLICY + "env: MY_ALLOWED\n",
        """
        if (process.env.SECRET_TOKEN) throw new Error("secret leaked");
        if (process.env.MY_ALLOWED !== "visible") throw new Error("allowed var missing");
        console.log("env ok");
        """,
    )
    assert res.returncode == 0, res.stderr
    assert "env ok" in res.stdout


def test_sdk_record_then_deterministic_replay(node_run, tmp_path):
    rec = node_run(POLICY, SDK_AGENT, args=[2])
    assert rec.returncode == 0, rec.stderr
    assert (tmp_path / "out" / "r1.txt").read_text() == "HELLO NODE"

    (tmp_path / "data" / "in.txt").unlink()
    (tmp_path / "out" / "r0.txt").unlink()
    (tmp_path / "out" / "r1.txt").unlink()

    rep = node_run(POLICY, SDK_AGENT, mode="replay", args=[2])
    assert rep.replay_ok, (rep.problems, rep.stderr)
    # read + 2 writes + clock + random
    assert rep.report["consumed"] == rep.report["total"] == 5
    assert not (tmp_path / "out" / "r0.txt").exists(), "replay must not re-execute writes"
    assert rep.stdout == rec.stdout, "clock + random must replay bit-identically"


def test_changed_input_diverges(node_run, tmp_path):
    agent = """
    const fs = require("fs");
    const data = fs.readFileSync("data/in.txt", "utf8");   // guard-observed sha256
    globalThis.agentbox.writeText("out/copy.txt", data);
    """
    rec = node_run(POLICY, agent)
    assert rec.returncode == 0, rec.stderr

    (tmp_path / "data" / "in.txt").write_text("tampered input")
    rep = node_run(POLICY, agent, mode="replay")
    assert not rep.replay_ok
    assert any("diverged" in p and "fs.open_read" in p for p in rep.problems), rep.problems


def test_replay_blocks_live_network(node_run, http_server):
    node_run(POLICY + "net: 127.0.0.1\n", "globalThis.agentbox.now();\n")
    rep = node_run(
        POLICY + "net: 127.0.0.1\n",
        """
        globalThis.agentbox.now();
        require("net").createConnection({ host: "127.0.0.1", port: Number(process.argv[2]) });
        """,
        mode="replay",
        args=[http_server],
    )
    assert not rep.replay_ok
    assert "replay mode blocks all live network" in rep.stderr
