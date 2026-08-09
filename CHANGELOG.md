# Changelog

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
