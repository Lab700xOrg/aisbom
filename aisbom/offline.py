"""The single switch for "this run must not touch the network" (#129).

`--offline` on `scan`/`score`, or ``AISBOM_OFFLINE=1`` for any command. Every
code path that can reach a server consults :func:`is_offline`: the PyPI
license lookup, the OSV lookup, telemetry and the update check, while remote
targets and ``--share`` are refused outright because they *are* network
operations. A narrower flag named "offline" that still phoned home would
mislead exactly the air-gapped users it exists for.

The flag is process state because telemetry and the update check are called
from many places; each command that accepts ``--offline`` sets it on entry,
so one invocation's choice never carries into the next.
"""

from __future__ import annotations

import os
from typing import Mapping

ENV_VAR = "AISBOM_OFFLINE"

_forced = False


def enable(flag: bool) -> None:
    """Set this invocation's ``--offline`` choice (False clears a prior one)."""
    global _forced
    _forced = bool(flag)


def is_offline(environ: Mapping[str, str] = os.environ) -> bool:
    return _forced or bool(environ.get(ENV_VAR))
