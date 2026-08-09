import os
import subprocess
import sys
import textwrap

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cli(args, cwd):
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    return subprocess.run(
        [sys.executable, "-m", "agentbox", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def project(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "out").mkdir()
    (tmp_path / "data" / "in.txt").write_text("cli test")
    (tmp_path / "agent.py").write_text(
        textwrap.dedent(
            """
            import agentbox.client as box
            box.write_text("out/r.txt", box.read_text("data/in.txt").upper())
            print("agent ran")
            """
        )
    )
    (tmp_path / "agentbox.policy").write_text("read: ./data\nwrite: ./out\n")
    return tmp_path


def test_version():
    res = cli(["--version"], cwd=".")
    assert res.returncode == 0 and "agentbox" in res.stdout


def test_init(tmp_path):
    res = cli(["init"], cwd=str(tmp_path))
    assert res.returncode == 0
    assert (tmp_path / "agentbox.policy").exists()


def test_run_show_verify_replay_roundtrip(project):
    run = cli(["run", "--", sys.executable, "agent.py"], cwd=str(project))
    assert run.returncode == 0, run.stderr
    assert "agent ran" in run.stdout
    assert "recorded" in run.stdout

    show = cli(["show"], cwd=str(project))
    assert show.returncode == 0
    assert "fs.read_text" in show.stdout and "fs.write_text" in show.stdout

    verify = cli(["verify"], cwd=str(project))
    assert verify.returncode == 0 and "hash chain verified" in verify.stdout

    replay = cli(["replay", "--", sys.executable, "agent.py"], cwd=str(project))
    assert replay.returncode == 0, replay.stdout + replay.stderr
    assert "replay ok" in replay.stdout


def test_run_records_denials_and_fails(project):
    (project / "agent.py").write_text('open("agentbox.policy", "w").write("boom")\n')
    run = cli(["run", "--", sys.executable, "agent.py"], cwd=str(project))
    assert run.returncode != 0
    assert "policy denies write" in run.stderr
    show = cli(["show"], cwd=str(project))
    assert "deny" in show.stdout


def test_no_command_errors(project):
    res = cli(["run"], cwd=str(project))
    assert res.returncode == 2
    assert "no command" in res.stderr
