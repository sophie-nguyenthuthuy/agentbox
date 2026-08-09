"""Deterministic replay of full sandboxed runs."""

import json

import pytest

from agentbox.trace import TraceTampered, read_trace

SDK_AGENT = """
import sys
import agentbox.client as box

n = int(sys.argv[1])
text = box.read_text("data/in.txt")
for i in range(n):
    box.write_text(f"out/r{i}.txt", text.upper())
stamp = box.now()
noise = box.random()
print("done", stamp, noise)
"""

POLICY = """
read:  ./data
write: ./out
"""


@pytest.fixture(autouse=True)
def workdir(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "out").mkdir()
    (tmp_path / "data" / "in.txt").write_text("replay me")
    return tmp_path


def test_replay_without_touching_the_world(sandbox_run, tmp_path):
    rec = sandbox_run(POLICY, SDK_AGENT, args=[2])
    assert rec.returncode == 0, rec.stderr
    assert (tmp_path / "out" / "r1.txt").read_text() == "REPLAY ME"

    # burn the world down: input gone, outputs gone
    (tmp_path / "data" / "in.txt").unlink()
    (tmp_path / "out" / "r0.txt").unlink()
    (tmp_path / "out" / "r1.txt").unlink()

    rep = sandbox_run(POLICY, SDK_AGENT, mode="replay", args=[2])
    assert rep.replay_ok, (rep.problems, rep.stderr)
    # read + 2 writes + clock + random
    assert rep.report["consumed"] == rep.report["total"] == 5
    assert not (tmp_path / "out" / "r0.txt").exists(), "replay must not re-execute writes"
    assert "done" in rep.stdout


def test_replay_output_is_bit_identical(sandbox_run):
    rec = sandbox_run(POLICY, SDK_AGENT, args=[1])
    rep = sandbox_run(POLICY, SDK_AGENT, mode="replay", args=[1])
    assert rep.replay_ok, (rep.problems, rep.stderr)
    assert rep.stdout == rec.stdout  # same clock + random values, replayed


def test_divergent_behavior_detected(sandbox_run):
    rec = sandbox_run(POLICY, SDK_AGENT, args=[1])
    assert rec.returncode == 0
    rep = sandbox_run(POLICY, SDK_AGENT, mode="replay", args=[3])
    assert not rep.replay_ok
    assert any("diverged" in p for p in rep.problems), rep.problems


def test_changed_input_file_diverges(sandbox_run, tmp_path):
    agent = """
    import agentbox.client as box
    data = open("data/in.txt").read()          # direct read -> guard observes sha256
    box.write_text("out/copy.txt", data)
    """
    rec = sandbox_run(POLICY, agent)
    assert rec.returncode == 0, rec.stderr

    (tmp_path / "data" / "in.txt").write_text("tampered input")
    rep = sandbox_run(POLICY, agent, mode="replay")
    assert not rep.replay_ok
    assert any("diverged" in p and "fs.open_read" in p for p in rep.problems), rep.problems


def test_incomplete_replay_detected(sandbox_run):
    agent = """
    import sys
    import agentbox.client as box
    for _ in range(int(sys.argv[1])):
        box.now()
    """
    sandbox_run(POLICY, agent, args=[3])
    rep = sandbox_run(POLICY, agent, mode="replay", args=[2])
    assert not rep.replay_ok
    assert any("incomplete replay" in p and "2 of 3" in p for p in rep.problems), rep.problems


def test_tampered_trace_refuses_replay(sandbox_run, tmp_path):
    from agentbox import runtime
    import sys as _sys

    sandbox_run(POLICY, SDK_AGENT, args=[1])
    trace = tmp_path / "trace.jsonl"
    lines = trace.read_text().splitlines()
    doctored = json.loads(lines[1])
    doctored["result"] = "forged"
    lines[1] = json.dumps(doctored, sort_keys=True, separators=(",", ":"))
    trace.write_text("\n".join(lines) + "\n")

    with pytest.raises(TraceTampered):
        runtime.run(
            [_sys.executable, "agent.py", "1"],
            policy_path=str(tmp_path / "agentbox.policy"),
            trace_path=str(trace),
            mode="replay",
            cwd=str(tmp_path),
            capture=True,
        )
