# agentbox

**A sandbox runtime for AI agent processes.** One policy file says what the
agent may touch; agentbox wraps the process, enforces the policy at the
interpreter level, captures a tamper-evident trace of every side effect, and
can deterministically replay any recorded run.

```
allow: read ./src, net: api.github.com
```

Zero dependencies. Pure Python stdlib. Python 3.11+.

## Why

Agents run with your whole user account: your SSH keys, your `~/.aws`, your
network. Reviewing what an agent *did* after the fact means scrolling logs
that the agent itself could have written. agentbox gives you three properties
that compose:

1. **Policy** — default-deny capability file for filesystem, network,
   subprocesses, and environment variables.
2. **Trace** — every allowed effect and every denial is appended to a
   hash-chained JSONL log. Edit, delete, or reorder one line and
   `agentbox verify` catches it.
3. **Replay** — re-run the same command against the trace: recorded effects
   are served back (network never touched, clock and RNG frozen, writes
   skipped), and any behavioral divergence — including an input file whose
   content changed — fails the replay with the exact step that differed.

## Quickstart

```bash
pip install agentbox-runtime

agentbox init                                   # writes a starter agentbox.policy
agentbox run    -p agentbox.policy -- python agent.py    # record
agentbox show                                   # inspect the trace
agentbox verify                                 # check the hash chain
agentbox replay -p agentbox.policy -- python agent.py    # deterministic re-run
```

A run looks like this:

```
$ agentbox run -p agentbox.policy -- python demo_agent.py
wrote out/summary.txt at 1786243519.9181929
blocked as expected: agentbox: policy denies read /etc/passwd
agentbox: recorded 4 effects, 1 observations, 1 denials -> trace.jsonl

$ agentbox replay -p agentbox.policy -- python demo_agent.py
wrote out/summary.txt at 1786243519.9181929        # same clock value, replayed
agentbox: replay ok — 5/5 recorded steps matched
```

## Policy file

One rule per line, `#` comments, everything not allowed is denied:

```
read:  ./data              # file reads under this root
write: ./out               # writes (implies read) under this root
net:   api.github.com      # DNS + connect to this host
net:   *.githubusercontent.com
net:   127.0.0.1:8080      # optional port pin
net:   unix:/tmp/app.sock  # unix sockets
exec:  git status          # argv prefix match
exec:  echo                # bare program name: any args
env:   HOME                # env vars passed into the sandbox
env:   AWS_*               # globs work everywhere
```

`allow: read ./src` is an alias for `read: ./src`, and rules can share a line:
`allow: read ./src, net: api.github.com`.

## How enforcement works

`agentbox run` spawns your command with a scrubbed environment (only
`env:`-allowed variables survive) and injects a `sitecustomize` shim via
`PYTHONPATH`. Before any user code runs, the shim installs a
[`sys.addaudithook`](https://docs.python.org/3/library/audit_events.html)
guard — CPython audit hooks **cannot be removed once installed**, so the
agent's own code can't disarm it. The guard:

- blocks `open()` outside the policy roots (stdlib and `sys.path` imports
  are exempt), and records allowed reads with a content sha256;
- blocks DNS resolution and socket connects to non-allowed hosts;
- blocks `subprocess`/`os.system`/`os.exec*` spawns that don't match an
  `exec:` rule, plus deletes/renames outside write roots;
- blocks `ctypes` dlopen/dlsym — the classic audit-hook bypass;
- fails closed: if the sandbox can't arm, the process refuses to start.

For replayable effects, agents use the SDK (anything outside it is still
guarded and observed):

```python
import agentbox.client as box

text = box.read_text("data/notes.txt")
resp = box.get("https://api.github.com/repos/x/y")   # {"status", "body", "sha256"}
out  = box.run(["git", "status"])                    # {"code", "stdout", "stderr"}
t    = box.now()      # frozen on replay
r    = box.random()   # frozen on replay
box.write_text("out/report.md", text.upper())
```

## Threat model, honestly

agentbox is an **interpreter-level** sandbox for Python processes, not a
kernel one. What that means in practice:

| Stops | Doesn't stop |
|---|---|
| An agent (or its prompt-injected tool call) reading `~/.ssh`, posting to an unapproved host, spawning `rm -rf` | A malicious C extension making raw syscalls |
| Secret env vars leaking into the process at all | Bugs in CPython itself |
| Post-hoc log tampering (hash chain) | A hostile *human* with local root |
| Silent behavioral drift between runs (replay divergence) | Non-Python child processes (their spawn is policy-checked; their own IO is not yet guarded) |

Kernel backends (Landlock on Linux, Seatbelt on macOS) are on the roadmap as
defense-in-depth; the policy file and trace format won't change.

## Replay semantics

- SDK effects are matched in order by `(op, args)` and served from the trace.
- Guard-observed direct IO is verified: a read whose file content changed
  since recording is a divergence, with the sha256 diff in the report.
- Live network and subprocess spawns are blocked during replay — replayable
  effects must go through the SDK.
- Replay from the same working directory; relative paths are part of the match.

## Roadmap — contributions are deliberately bite-sized

Each of these is a single focused PR:

- **One policy rule per PR** — `net: cidr/…`, rate limits (`net: api.x.com @10/min`),
  `read-once:`, size caps on `write:`.
- **One language runtime per PR** — Node (`--require` shim), Deno
  (permissions bridge), Bun; the policy/trace/replay core is
  runtime-agnostic.
- **One trace exporter per PR** — OTLP spans, SQLite, `agentbox show --html`
  timeline.
- Kernel backends: Landlock, Seatbelt, seccomp-bpf.
- Adapters: LangGraph / OpenAI Agents / Claude Agent SDK tool-call wrappers.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Development

```bash
python -m pytest        # 49 tests, all stdlib + pytest
```

MIT © Sophie Nguyen Thu Thuy
