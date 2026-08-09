import pytest

from agentbox.client import PolicyViolation, ReplayDivergence, Session
from agentbox.policy import Policy
from agentbox.trace import read_trace, verify_chain


@pytest.fixture
def env(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "in.txt").write_text("xin chào")
    policy = Policy(
        root=str(tmp_path),
        reads=["data"],
        writes=["out"],
        nets=["127.0.0.1"],
        execs=["echo"],
    )
    return policy, tmp_path


def test_record_then_replay_fs(env):
    policy, tmp = env
    trace = str(tmp / "t.jsonl")
    s = Session(policy, trace, "record")
    text = s.read_text(str(tmp / "data" / "in.txt"))
    assert text == "xin chào"
    s.write_text(str(tmp / "out" / "r.txt"), text.upper())
    assert (tmp / "out" / "r.txt").read_text() == "XIN CHÀO"
    assert verify_chain(read_trace(trace)) == (True, None)

    # replay with the input deleted and output removed: nothing touches disk
    (tmp / "data" / "in.txt").unlink()
    (tmp / "out" / "r.txt").unlink()
    r = Session(policy, trace, "replay")
    assert r.read_text(str(tmp / "data" / "in.txt")) == "xin chào"
    r.write_text(str(tmp / "out" / "r.txt"), "XIN CHÀO")
    assert not (tmp / "out" / "r.txt").exists()
    assert r.cursor == len(r.entries)


def test_policy_violation_raised(env):
    policy, tmp = env
    s = Session(policy, str(tmp / "t.jsonl"), "record")
    with pytest.raises(PolicyViolation):
        s.read_text("/etc/passwd")
    with pytest.raises(PolicyViolation):
        s.write_text(str(tmp / "data" / "nope.txt"), "x")
    with pytest.raises(PolicyViolation):
        s.get("https://evil.example.com/")
    with pytest.raises(PolicyViolation):
        s.run(["rm", "-rf", "/"])


def test_clock_and_random_replay_deterministically(env):
    policy, tmp = env
    trace = str(tmp / "t.jsonl")
    s = Session(policy, trace, "record")
    t1, r1 = s.now(), s.random()
    replay = Session(policy, trace, "replay")
    assert replay.now() == t1
    assert replay.random() == r1


def test_exec_effect_records_output(env):
    policy, tmp = env
    trace = str(tmp / "t.jsonl")
    s = Session(policy, trace, "record")
    out = s.run(["echo", "hi"])
    assert out["code"] == 0 and out["stdout"].strip() == "hi"
    replay = Session(policy, trace, "replay")
    assert replay.run(["echo", "hi"]) == out


def test_net_get_records_and_replays(env, http_server):
    policy, tmp = env
    trace = str(tmp / "t.jsonl")
    url = f"http://127.0.0.1:{http_server}/x"
    s = Session(policy, trace, "record")
    resp = s.get(url)
    assert resp["status"] == 200 and resp["body"] == "hello from server"
    replay = Session(policy, trace, "replay")
    assert replay.get(url)["body"] == "hello from server"


def test_divergence_on_different_args(env):
    policy, tmp = env
    trace = str(tmp / "t.jsonl")
    s = Session(policy, trace, "record")
    s.read_text(str(tmp / "data" / "in.txt"))
    replay = Session(policy, trace, "replay")
    with pytest.raises(ReplayDivergence, match="fs.read_text"):
        replay.now()
    assert replay.diverged


def test_divergence_on_exhausted_trace(env):
    policy, tmp = env
    trace = str(tmp / "t.jsonl")
    Session(policy, trace, "record").now()
    replay = Session(policy, trace, "replay")
    replay.now()
    with pytest.raises(ReplayDivergence, match="recording ended"):
        replay.now()


def test_write_content_change_diverges(env):
    policy, tmp = env
    trace = str(tmp / "t.jsonl")
    Session(policy, trace, "record").write_text(str(tmp / "out" / "r.txt"), "version 1")
    replay = Session(policy, trace, "replay")
    with pytest.raises(ReplayDivergence):
        replay.write_text(str(tmp / "out" / "r.txt"), "version 2")
