"""Demo: an agent that mangles a file in place — and one command that undoes it.

    pip install agentbox-runtime snapback-cli
    cd examples
    mkdir -p data && echo "original notes" > data/notes.txt
    agentbox run --checkpoint -p checkpoint.policy -- python checkpoint_agent.py
    snapback diff          # see exactly what the agent changed
    snapback undo          # put it all back
    agentbox show          # the checkpoint id is step N of the hash chain

The snapshot is taken lazily, right before the agent's FIRST mutating effect,
and is recorded in the trace itself (`hook.checkpoint`), so "what can I roll
back to" is part of the same tamper-evident record as "what did it do".
"""

import agentbox.client as box

notes = box.read_text("data/notes.txt")

# a "helpful" rewrite that clobbers the original in place
box.write_text("data/notes.txt", notes.upper().replace(" ", "_"))
box.write_text("out/report.md", f"# Agent report\n\nProcessed {len(notes)} chars.\n")

print("agent done: rewrote data/notes.txt, wrote out/report.md")
print("regret it? -> snapback undo")
