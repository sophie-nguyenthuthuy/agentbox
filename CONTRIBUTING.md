# Contributing to agentbox

The project is structured so most contributions are one small, self-contained
PR. Pick a lane:

## One policy rule per PR

Add a rule kind in `agentbox/policy.py` (parse + an `allows_*` method), wire
its enforcement point in `agentbox/guard.py`, and add tests in
`tests/test_policy.py` + `tests/test_guard.py`. Ideas: CIDR ranges for
`net:`, per-host rate limits, `read-once:`, byte caps on `write:`.

## One language runtime per PR

The policy file, trace format, and replay engine are runtime-agnostic; only
the in-process guard + SDK are Python today. A new runtime needs:

1. an injection mechanism (Node: `NODE_OPTIONS=--require`, Deno: permission
   flags computed from the policy),
2. an effects SDK that appends to the same hash-chained JSONL trace,
3. the replay cursor (match `(op, args)` in order, serve recorded results).

Put it under `runtimes/<lang>/` with its own test suite.

## One trace exporter per PR

Consume `trace.jsonl` (see `agentbox/trace.py` for the entry schema) and emit
another format: OTLP spans, SQLite, an HTML timeline for `agentbox show
--html`. Exporters live in `agentbox/export/` and must not add hard
dependencies — import optional libs lazily.

## Ground rules

- Stdlib only in the core; `pytest` is the only dev dependency.
- Every behavior change comes with a test that fails without it.
- The guard must fail closed; anything that weakens that needs a very good
  argument in the PR description.
- Run `python -m pytest` before pushing.
