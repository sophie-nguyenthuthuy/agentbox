# Changelog

## 0.2.0 — 2026-08-09

- **Node runtime shim** (`agentbox run -- node agent.js` just works): a
  zero-dependency CommonJS guard injected via `NODE_OPTIONS --require` that
  enforces the same policy file (fs / net / child_process / env scrub),
  appends to the **same hash chain** the Python runner starts (cross-language
  chain verifies with `agentbox verify`), and exposes the effects SDK as
  `globalThis.agentbox` with full deterministic replay. Honest caveat: the
  Node guard is monkeypatch-based, weaker than CPython's irremovable audit
  hooks; JS `now()`/`random()` return integers so traced values round-trip
  byte-identically through Python's canonical JSON.
- Python guard: exempt the entry script from read policy (spurious deny of
  the agent's own script in venv installs).

## 0.1.0 — 2026-08-09

Initial release.

- Default-deny policy file: `read:` / `write:` / `net:` / `exec:` / `env:`
  rules with globs, port pins, unix sockets, and argv-prefix exec matching.
- Interpreter-level enforcement via an irremovable `sys.addaudithook` guard,
  injected through a `sitecustomize` shim; fails closed, scrubs the
  environment, blocks the `ctypes` dlopen bypass.
- Hash-chained JSONL trace of every effect, observation, and denial;
  `agentbox verify` detects edits, deletions, and reordering.
- Deterministic replay: SDK effects served from the trace (clock and RNG
  frozen, writes skipped, live network/exec blocked), guard-observed reads
  verified by content sha256, per-step divergence reporting.
- CLI: `agentbox run | replay | show | verify | init`.
