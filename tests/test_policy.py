import pytest

from agentbox.policy import Policy, PolicyError


def test_parse_one_liner_from_readme(tmp_path):
    p = Policy.parse("allow: read ./src, net: api.github.com", root=str(tmp_path))
    assert p.allows_read(tmp_path / "src" / "main.py")
    assert p.allows_net("api.github.com")
    assert not p.allows_read(tmp_path / "etc" / "passwd")
    assert not p.allows_net("evil.example.com")


def test_parse_full_form(tmp_path):
    p = Policy.parse(
        """
        # comment
        read:  ./data          # trailing comment
        write: ./out
        net:   *.github.com
        exec:  git status
        env:   HOME, AWS_*
        """,
        root=str(tmp_path),
    )
    assert p.allows_read(tmp_path / "data" / "x")
    assert p.allows_write(tmp_path / "out" / "y")
    assert p.allows_net("api.github.com")
    assert p.allows_exec(["git", "status"])
    assert p.allows_env("HOME") and p.allows_env("AWS_SECRET_ACCESS_KEY")
    assert not p.allows_env("HOMEBREW_PREFIX")


def test_comma_continuation_reuses_key(tmp_path):
    p = Policy.parse("env: HOME, PATH, LANG", root=str(tmp_path))
    assert p.allows_env("PATH") and p.allows_env("LANG")


def test_write_implies_read(tmp_path):
    p = Policy.parse("write: ./out", root=str(tmp_path))
    assert p.allows_read(tmp_path / "out" / "f")
    assert not p.allows_write(tmp_path / "elsewhere")


def test_dotdot_escape_is_denied(tmp_path):
    p = Policy.parse("read: ./data", root=str(tmp_path / "proj"))
    assert not p.allows_read(str(tmp_path / "proj" / "data" / ".." / ".." / "secret"))


def test_symlink_escape_is_denied(tmp_path):
    (tmp_path / "proj" / "data").mkdir(parents=True)
    (tmp_path / "secret").write_text("s")
    (tmp_path / "proj" / "data" / "link").symlink_to(tmp_path / "secret")
    p = Policy.parse("read: ./data", root=str(tmp_path / "proj"))
    assert not p.allows_read(tmp_path / "proj" / "data" / "link")


def test_prefix_is_directory_boundary(tmp_path):
    p = Policy.parse("read: ./data", root=str(tmp_path))
    assert not p.allows_read(tmp_path / "database" / "f")


def test_net_wildcard_and_port():
    p = Policy.parse("net: *.github.com\nnet: 127.0.0.1:8080")
    assert p.allows_net("raw.github.com")
    assert not p.allows_net("github.com.evil.io")
    assert p.allows_net("127.0.0.1", 8080)
    assert not p.allows_net("127.0.0.1", 9999)


def test_net_unix_socket():
    p = Policy.parse("net: unix:/tmp/agent.sock")
    assert p.allows_unix("/tmp/agent.sock")
    assert not p.allows_unix("/var/run/docker.sock")
    assert not p.allows_net("unix")


def test_exec_prefix_match():
    p = Policy.parse("exec: git status\nexec: echo")
    assert p.allows_exec(["git", "status"])
    assert p.allows_exec(["/usr/bin/git", "status", "--short"])
    assert not p.allows_exec(["git", "push"])
    assert p.allows_exec(["echo", "anything", "at", "all"])
    assert not p.allows_exec(["rm", "-rf", "/"])
    assert not p.allows_exec([])


def test_parse_errors():
    with pytest.raises(PolicyError):
        Policy.parse("allow: frobnicate ./x")
    with pytest.raises(PolicyError):
        Policy.parse("just a bare value")
    with pytest.raises(PolicyError):
        Policy.parse("read:")


def test_sha256_stable_and_order_independent(tmp_path):
    a = Policy.parse("read: ./a\nnet: x.com\nnet: y.com", root=str(tmp_path))
    b = Policy.parse("net: y.com\nnet: x.com\nread: ./a", root=str(tmp_path))
    assert a.sha256 == b.sha256
    c = Policy.parse("read: ./a\nnet: x.com", root=str(tmp_path))
    assert a.sha256 != c.sha256


def test_default_deny(tmp_path):
    p = Policy.parse("", root=str(tmp_path))
    assert not p.allows_read(tmp_path / "f")
    assert not p.allows_net("localhost")
    assert not p.allows_exec(["true"])
    assert not p.allows_env("PATH")
