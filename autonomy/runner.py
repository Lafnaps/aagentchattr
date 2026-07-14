"""Trusted consumer for the pinned night-autonomy bootstrap.

The scheduler pins this module and :mod:`autonomy.supervisor_tick`; the
bootstrap verifies those exact bytes and loads them with its private in-memory
loader.  Manifest-listed Python is therefore part of the trusted computing
base.  The loader gives integrity and deterministic ordinary imports -- it is
not an in-process sandbox for hostile pinned Python.

There is deliberately no public ``arm`` API and no public caller-constructible
bootstrap context.  The private loader injects a fresh one-shot handoff before
executing this module.  That handoff catches accidental direct use and replay
inside the fresh runner process; it is a misuse guard, not cryptographic
provenance and not a defence against Python code already executing in-process.

The current supervisor tick is readiness-only and deterministic: it performs no
queue, process, scheduler, network, SVN, or product mutation.
"""

from __future__ import annotations

from dataclasses import dataclass

import autonomy.supervisor_tick


class RunnerError(Exception):
    """Stable, output-free refusal raised inside the trusted runner."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class _DependencyPin:
    """One verified dependency, exactly as the bootstrap validated it."""

    relative_path: str
    path: str
    sha256: str
    device: int
    inode: int
    size: int
    mtime_ns: int


@dataclass(frozen=True)
class _BootstrapContext:
    """Private immutable hand-off from the bootstrap to the trusted runner."""

    _handoff: object
    task_id: str = ""
    attempt: int = 0
    nonce: str = ""
    profile: str = ""
    model: str = ""
    repo: str = ""
    root: str = ""
    attempt_dir: str = ""
    config: str = ""
    config_sha256: str = ""
    bootstrap: str = ""
    python: str = ""
    dependency_manifest: str = ""
    task_spec: str = ""
    task_spec_sha256: str = ""
    principal_sid: str = ""
    dependencies: tuple = ()


# ``_PinnedLoader`` injects this name before executing the verified runner
# bytes.  A normal import leaves it ``None``.  Keeping the fallback in source
# makes direct imports fail predictably without exposing an arming function.
try:
    _BOOTSTRAP_HANDOFF
except NameError:
    _BOOTSTRAP_HANDOFF = None

_BOOTSTRAP_HANDOFF_CONSUMED = False


def _main_from_bootstrap(context: object) -> int:
    """Consume the loader-injected handoff once and run the trusted tick.

    The stable checks are sequencing/misuse checks only.  Python code already
    running in this interpreter could mutate private module state and is outside
    this boundary's threat model.
    """

    global _BOOTSTRAP_HANDOFF, _BOOTSTRAP_HANDOFF_CONSUMED

    handoff = _BOOTSTRAP_HANDOFF
    if _BOOTSTRAP_HANDOFF_CONSUMED:
        raise RunnerError("runner-already-consumed")
    if handoff is None:
        raise RunnerError("runner-not-armed")

    # Consume before inspecting or invoking caller-controlled objects.  A
    # failed invocation cannot be replayed in the same runner process.
    _BOOTSTRAP_HANDOFF_CONSUMED = True
    _BOOTSTRAP_HANDOFF = None

    if type(context) is not _BootstrapContext:
        raise RunnerError("runner-context-invalid")
    if context._handoff is not handoff:
        raise RunnerError("runner-token-mismatch")

    outcome = autonomy.supervisor_tick.run(context)
    if type(outcome) is not int or type(outcome) is bool:
        raise RunnerError("supervisor-tick-result-invalid")
    if outcome < 0 or outcome > 125:
        raise RunnerError("supervisor-tick-result-invalid")
    return outcome
