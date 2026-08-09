"""Demo agent. Run it sandboxed from the examples/ directory:

    agentbox run -p agentbox.policy -- python demo_agent.py
    agentbox replay -p agentbox.policy -- python demo_agent.py
    agentbox show
"""

import agentbox.client as box

notes = box.read_text("data/notes.txt")          # replayable effect
raw = open("data/notes.txt").read()              # direct IO: guard-observed
stamp = box.now()                                # frozen on replay
echoed = box.run(["echo", "sandboxed subprocess"])

box.write_text(
    "out/summary.txt",
    f"[{stamp}] {len(notes)} bytes of notes\n{echoed['stdout']}",
)
print("wrote out/summary.txt at", stamp)

try:
    open("/etc/passwd").read()
except PermissionError as exc:
    print("blocked as expected:", exc)
