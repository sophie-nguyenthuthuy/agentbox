"""--checkpoint: snapback snapshot before the first mutating effect."""

import os
import shutil
import stat
import subprocess
import sys
import textwrap

import pytest

from agentbox.client import CheckpointError, Session
from agentbox.policy import Policy
from agentbox.trace import read_trace, verify_chain

FAKE_SNAP_ID = "20260809-999999"


@pytest.fixture
def fake_snapback(tmp_path, monkeypatch):
    """A `snapback` shim on PATH that logs calls and mimics `snap` output."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "snapback-calls.log"
    script = bindir / "snapback"
    script.write_text(
        textwrap.dedent(
            f"""\
            #!/bin/sh
            if [ -n "$AGENTBOX_POLICY" ] || [ -n "$PYTHONPATH" ]; then
                echo "leaked sandbox env into snapback" >&2
                exit 9
            fi
            echo "$@" >> {log}
            echo "snapback: snapshot {FAKE_SNAP_ID}"
            """
        )
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return log


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "in.txt").write_text("hello")
    policy = Policy(root=str(tmp_path), reads=["data"], writes=["out"], execs=["echo"])
    return policy, tmp_path


def calls(log):
    return log.read_text().splitlines() if log.exists() else []


def test_checkpoint_recorded_once_before_first_mutation(env, fake_snapback):
    policy, tmp = env
    s = Session(policy, str(tmp / "t.jsonl"), "record", checkpoint=True)
    s.read_text(str(tmp / "data" / "in.txt"))  # read-only: no checkpoint yet
    assert calls(fake_snapback) == []

    s.write_text(str(tmp / "out" / "a.txt"), "one")
    s.write_text(str(tmp / "out" / "b.txt"), "two")
    s.run(["echo", "hi"])

    assert len(calls(fake_snapback)) == 1
    assert "before fs.write_text" in calls(fake_snapback)[0]

    ops = [e["op"] for e in read_trace(str(tmp / "t.jsonl")) if e["kind"] == "effect"]
    assert ops.index("hook.checkpoint") < ops.index("fs.write_text")
    assert ops.count("hook.checkpoint") == 1

    snap = next(
        e for e in read_trace(str(tmp / "t.jsonl")) if e["op"] == "hook.checkpoint"
    )
    assert snap["result"]["snapshot"] == FAKE_SNAP_ID
    assert verify_chain(read_trace(str(tmp / "t.jsonl")))[0]


def test_no_mutation_no_checkpoint(env, fake_snapback):
    policy, tmp = env
    s = Session(policy, str(tmp / "t.jsonl"), "record", checkpoint=True)
    s.read_text(str(tmp / "data" / "in.txt"))
    s.now()
    assert calls(fake_snapback) == []
    assert not any(e["op"] == "hook.checkpoint" for e in read_trace(str(tmp / "t.jsonl")))


def test_checkpoint_off_by_default(env, fake_snapback):
    policy, tmp = env
    s = Session(policy, str(tmp / "t.jsonl"), "record")
    s.write_text(str(tmp / "out" / "a.txt"), "x")
    assert calls(fake_snapback) == []


def test_checkpoint_failure_blocks_the_write(env, tmp_path, monkeypatch):
    policy, tmp = env
    bindir = tmp_path / "failbin"
    bindir.mkdir()
    bad = bindir / "snapback"
    bad.write_text("#!/bin/sh\necho boom >&2\nexit 1\n")
    bad.chmod(bad.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")

    s = Session(policy, str(tmp / "t.jsonl"), "record", checkpoint=True)
    with pytest.raises(CheckpointError, match="boom"):
        s.write_text(str(tmp / "out" / "a.txt"), "x")
    assert not (tmp / "out" / "a.txt").exists()  # fail closed

    # not sticky: the next mutation attempt retries the checkpoint
    with pytest.raises(CheckpointError):
        s.write_text(str(tmp / "out" / "a.txt"), "x")


def test_snapback_missing_is_actionable(env, tmp_path, monkeypatch):
    policy, tmp = env
    empty = tmp_path / "emptybin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    s = Session(policy, str(tmp / "t.jsonl"), "record", checkpoint=True)
    with pytest.raises(CheckpointError, match="pip install snapback-cli"):
        s.write_text(str(tmp / "out" / "a.txt"), "x")


def test_replay_skips_checkpoint_and_matches(env, fake_snapback):
    policy, tmp = env
    trace = str(tmp / "t.jsonl")
    s = Session(policy, trace, "record", checkpoint=True)
    s.write_text(str(tmp / "out" / "a.txt"), "one")
    assert len(calls(fake_snapback)) == 1

    # replay must consume every agent effect, never invoke snapback —
    # with or without checkpoint enabled on the replay session
    for ck in (False, True):
        r = Session(policy, trace, "replay", checkpoint=ck)
        r.write_text(str(tmp / "out" / "a.txt"), "one")
        assert r.cursor == len(r.entries)
    assert len(calls(fake_snapback)) == 1


def test_end_to_end_sandboxed_run(tmp_path, fake_snapback):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "in.txt").write_text("hello")
    import agentbox.runtime as runtime

    (tmp_path / "agent.py").write_text(
        textwrap.dedent(
            """\
            import agentbox.client as box
            text = box.read_text("data/in.txt")
            box.write_text("out/r.txt", text.upper())
            """
        )
    )
    (tmp_path / "agentbox.policy").write_text("read: ./data\nwrite: ./out\n")
    res = runtime.run(
        [sys.executable, "agent.py"],
        policy_path=str(tmp_path / "agentbox.policy"),
        trace_path=str(tmp_path / "trace.jsonl"),
        cwd=str(tmp_path),
        capture=True,
        checkpoint=True,
    )
    assert res.returncode == 0, res.stderr
    entries = read_trace(str(tmp_path / "trace.jsonl"))
    assert any(e["op"] == "hook.checkpoint" for e in entries)
    meta = next(e for e in entries if e["op"] == "run.start")
    assert meta["args"]["checkpoint"] is True
    assert len(calls(fake_snapback)) == 1

    # and the recorded run replays clean
    res = runtime.run(
        [sys.executable, "agent.py"],
        policy_path=str(tmp_path / "agentbox.policy"),
        trace_path=str(tmp_path / "trace.jsonl"),
        mode="replay",
        cwd=str(tmp_path),
        capture=True,
    )
    assert res.replay_ok, (res.problems, res.stderr)
    assert len(calls(fake_snapback)) == 1  # replay never snapshots


@pytest.mark.skipif(shutil.which("snapback") is None, reason="snapback-cli not installed")
def test_real_snapback_undo_reverts_the_agent(tmp_path, monkeypatch):
    """Full integration: agentbox --checkpoint + real snapback undo."""
    import agentbox.runtime as runtime

    monkeypatch.chdir(tmp_path)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "notes.txt").write_text("original notes")
    (tmp_path / "agent.py").write_text(
        textwrap.dedent(
            """\
            import agentbox.client as box
            notes = box.read_text("data/notes.txt")
            box.write_text("data/notes.txt", notes.upper())   # clobbers in place
            box.write_text("out/summary.txt", str(len(notes)))
            """
        )
    )
    (tmp_path / "agentbox.policy").write_text("read: ./data\nwrite: ./data\nwrite: ./out\n")
    # keep the audit trail out of the rollback: undo reverts the agent's
    # writes but must not truncate the hash-chained trace
    (tmp_path / "snapback.toml").write_text('[snapshot]\nignore = ["trace.jsonl"]\n')
    res = runtime.run(
        [sys.executable, "agent.py"],
        policy_path=str(tmp_path / "agentbox.policy"),
        trace_path=str(tmp_path / "trace.jsonl"),
        cwd=str(tmp_path),
        capture=True,
        checkpoint=True,
    )
    assert res.returncode == 0, res.stderr
    assert (tmp_path / "data" / "notes.txt").read_text() == "ORIGINAL NOTES"
    assert (tmp_path / "out" / "summary.txt").exists()

    undo = subprocess.run(
        ["snapback", "undo"], cwd=tmp_path, capture_output=True, text=True
    )
    assert undo.returncode == 0, undo.stderr
    assert (tmp_path / "data" / "notes.txt").read_text() == "original notes"
    assert not (tmp_path / "out" / "summary.txt").exists()
    # the full audit trail survives the rollback
    entries = read_trace(str(tmp_path / "trace.jsonl"))
    assert verify_chain(entries)[0]
    assert any(e["op"] == "hook.checkpoint" for e in entries)
    assert any(e["op"] == "run.end" for e in entries)
