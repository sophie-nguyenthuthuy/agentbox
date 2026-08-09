"""agentbox — policy-sandboxed runtime for AI agent processes.

A policy file declares what an agent process may touch (files, network
hosts, subprocesses, env vars). agentbox wraps the process, enforces the
policy at the interpreter level via audit hooks, captures a tamper-evident
trace of every effect, and can deterministically replay a recorded run.
"""

__version__ = "0.2.0"

from .client import PolicyViolation, ReplayDivergence, Session
from .policy import Policy, PolicyError
from .trace import TraceTampered

__all__ = [
    "Policy",
    "PolicyError",
    "PolicyViolation",
    "ReplayDivergence",
    "Session",
    "TraceTampered",
    "__version__",
]
