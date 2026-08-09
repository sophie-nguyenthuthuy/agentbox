import sys
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agentbox import runtime


@pytest.fixture
def http_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"hello from server"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture
def sandbox_run(tmp_path):
    """Write an agent script + policy into tmp_path and run it sandboxed."""

    def _run(policy_text, agent_code, mode="record", enforce=True, args=()):
        (tmp_path / "agent.py").write_text(textwrap.dedent(agent_code))
        (tmp_path / "agentbox.policy").write_text(textwrap.dedent(policy_text))
        return runtime.run(
            [sys.executable, "agent.py", *[str(a) for a in args]],
            policy_path=str(tmp_path / "agentbox.policy"),
            trace_path=str(tmp_path / "trace.jsonl"),
            mode=mode,
            enforce=enforce,
            cwd=str(tmp_path),
            capture=True,
        )

    return _run
