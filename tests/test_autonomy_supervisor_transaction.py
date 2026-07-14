from __future__ import annotations

import ast
import errno
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import tokenize
import types
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

import autonomy.control_state as control_state
import autonomy.supervisor_transaction as supervisor_transaction
from autonomy.control_state import (
    HALT_FILENAME,
    ROOT_MARKER,
    SUPERVISOR_LOCK_FILENAME,
    LockIntegrityError,
    LockUnavailableError,
    PermanentFileLock,
    create_halt,
)
from autonomy.supervisor_transaction import (
    FenceContentionError,
    FenceUsageError,
    HaltActive,
    HaltEvidenceError,
    TransactionCompleted,
    run_halt_first_transaction,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "autonomy" / "supervisor_transaction.py"
CANONICAL_ROOT_MARKER = b'{"name":"agentchattr-autonomy-queue","version":1}\n'
NONCE = "c" * 32
STAMP = "2026-07-13T12:34:56.789Z"
IS_WINDOWS = os.name == "nt"


def subprocess_environment():
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def collect_name_tokens(source_text):
    """Every exact Python NAME token in ``source_text``, NFKC-normalized.

    This matches Python's own identifier normalization, so an
    NFKC-equivalent hostile identifier cannot slip past an ASCII
    comparison.  String and comment contents are never NAME tokens.
    Tokenization errors propagate to the caller.
    """

    names = set()
    for token in tokenize.generate_tokens(io.StringIO(source_text).readline):
        if token.type == tokenize.NAME:
            names.add(unicodedata.normalize("NFKC", token.string))
    return names


DRIVER_NAME = "run_halt_first_transaction"
DRIVER_MODULE = "autonomy.supervisor_transaction"
DRIVER_CALL_SITE = "observe_night_tick"


def driver_binding_violations(source_text):
    """Closed AST binding audit of the night-tick driver consumer.

    Returns a sorted list of violation codes for one consumer module's
    source text.  An empty list proves exactly: the module has exactly one
    module-level unaliased
    ``from autonomy.supervisor_transaction import run_halt_first_transaction``
    binding, exactly one module-level ``observe_night_tick`` definition,
    and the only other occurrence of the driver identifier is exactly one
    direct ``ast.Name`` call of that imported binding directly inside
    ``observe_night_tick``.  Every other binding or use is a violation:
    alias import, aliased binding of the name, plain ``import`` binding,
    non-module-level or wrong-module import, attribute use, keyword
    argument name, bare load, store, delete, function/class definition,
    parameter (including lambda), exception alias, global/nonlocal
    declaration, match capture (``case name``/``*name``/``**name``), and
    PEP 695 type parameters.  Identifiers are compared NFKC-normalized on
    top of the parser's own normalization, so an NFKC-equivalent hostile
    spelling cannot slip past.  String and comment contents are never
    identifiers and stay ignored.  A source that does not parse raises
    ``SyntaxError`` to the caller: hard failure, never a skip.
    """

    tree = ast.parse(source_text)
    module_statements = list(tree.body)
    violations = []
    counters = {"unaliased_imports": 0, "direct_calls": 0}

    def normalized(identifier):
        return unicodedata.normalize("NFKC", identifier)

    def is_driver(identifier):
        return identifier is not None and normalized(identifier) == DRIVER_NAME

    observer_definitions = sum(
        1
        for statement in module_statements
        if isinstance(statement, ast.FunctionDef)
        and normalized(statement.name) == DRIVER_CALL_SITE
    )

    class Auditor(ast.NodeVisitor):
        def __init__(self):
            self.scopes = []

        def visit_ImportFrom(self, node):
            module = normalized(node.module) if node.module is not None else None
            for alias in node.names:
                if is_driver(alias.asname):
                    violations.append("aliased-binding-of-driver-name")
                if not is_driver(alias.name):
                    continue
                if alias.asname is not None:
                    violations.append("driver-imported-under-alias")
                elif module != DRIVER_MODULE or node.level != 0:
                    violations.append("driver-imported-from-wrong-module")
                elif not any(node is statement for statement in module_statements):
                    violations.append("driver-import-not-module-level")
                else:
                    counters["unaliased_imports"] += 1
            self.generic_visit(node)

        def visit_Import(self, node):
            for alias in node.names:
                if alias.asname is not None:
                    bound = alias.asname
                else:
                    bound = alias.name.partition(".")[0]
                if is_driver(bound):
                    violations.append("driver-name-bound-by-import")
            self.generic_visit(node)

        def _audit_scope(self, node, violation):
            if is_driver(node.name):
                violations.append(violation)
            self.scopes.append(normalized(node.name))
            self.generic_visit(node)
            self.scopes.pop()

        def visit_FunctionDef(self, node):
            self._audit_scope(node, "driver-name-used-as-function-definition")

        def visit_AsyncFunctionDef(self, node):
            self._audit_scope(node, "driver-name-used-as-function-definition")

        def visit_ClassDef(self, node):
            self._audit_scope(node, "driver-name-used-as-class-definition")

        def visit_Lambda(self, node):
            self.scopes.append("<lambda>")
            self.generic_visit(node)
            self.scopes.pop()

        def visit_arg(self, node):
            if is_driver(node.arg):
                violations.append("driver-name-used-as-parameter")
            self.generic_visit(node)

        def visit_ExceptHandler(self, node):
            if is_driver(node.name):
                violations.append("driver-name-used-as-exception-alias")
            self.generic_visit(node)

        def visit_Global(self, node):
            if any(is_driver(name) for name in node.names):
                violations.append("driver-name-declared-global")

        def visit_Nonlocal(self, node):
            if any(is_driver(name) for name in node.names):
                violations.append("driver-name-declared-nonlocal")

        def visit_MatchAs(self, node):
            if is_driver(node.name):
                violations.append("driver-name-used-as-match-capture")
            self.generic_visit(node)

        def visit_MatchStar(self, node):
            if is_driver(node.name):
                violations.append("driver-name-used-as-match-capture")
            self.generic_visit(node)

        def visit_MatchMapping(self, node):
            if is_driver(node.rest):
                violations.append("driver-name-used-as-match-capture")
            self.generic_visit(node)

        def visit_Attribute(self, node):
            if is_driver(node.attr):
                violations.append("driver-name-used-as-attribute")
            self.generic_visit(node)

        def visit_keyword(self, node):
            if is_driver(node.arg):
                violations.append("driver-name-used-as-keyword-argument")
            self.generic_visit(node)

        def visit_TypeVar(self, node):
            if is_driver(node.name):
                violations.append("driver-name-used-as-type-parameter")
            self.generic_visit(node)

        def visit_ParamSpec(self, node):
            if is_driver(node.name):
                violations.append("driver-name-used-as-type-parameter")
            self.generic_visit(node)

        def visit_TypeVarTuple(self, node):
            if is_driver(node.name):
                violations.append("driver-name-used-as-type-parameter")
            self.generic_visit(node)

        def visit_Call(self, node):
            func = node.func
            if isinstance(func, ast.Name) and is_driver(func.id):
                if self.scopes == [DRIVER_CALL_SITE]:
                    counters["direct_calls"] += 1
                else:
                    violations.append("driver-call-outside-observe-night-tick")
                # The sanctioned call-func Name is fully classified here;
                # arguments and keywords are still audited independently.
                for child in node.args:
                    self.visit(child)
                for child in node.keywords:
                    self.visit(child)
                return
            self.generic_visit(node)

        def visit_Name(self, node):
            if is_driver(node.id):
                if isinstance(node.ctx, ast.Load):
                    violations.append("driver-name-loaded-outside-direct-call")
                elif isinstance(node.ctx, ast.Del):
                    violations.append("driver-name-deleted")
                else:
                    violations.append("driver-name-stored")

    Auditor().visit(tree)
    if counters["unaliased_imports"] != 1:
        violations.append("driver-unaliased-import-count-not-one")
    if counters["direct_calls"] != 1:
        violations.append("driver-direct-call-count-not-one")
    if observer_definitions != 1:
        violations.append("observe-night-tick-definition-count-not-one")
    return sorted(violations)


class FenceFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / ROOT_MARKER).write_bytes(CANONICAL_ROOT_MARKER)

    def make_second_root(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        (root / ROOT_MARKER).write_bytes(CANONICAL_ROOT_MARKER)
        return root


@unittest.skipUnless(IS_WINDOWS, "the supervisor fence is Windows-only")
class HaltFirstTests(FenceFixture):
    def test_valid_halt_returns_halt_active_without_body_or_clock(self):
        create_halt(self.root, nonce=NONCE, created_utc=STAMP)
        with mock.patch(
            "autonomy.control_state._utc_now",
            side_effect=AssertionError("clock sentinel: the fence sampled a clock"),
        ):
            outcome = run_halt_first_transaction(self.root, None)
        self.assertIsInstance(outcome, HaltActive)
        self.assertEqual(NONCE, outcome.halt["nonce"])
        with self.assertRaises(TypeError):
            outcome.halt["nonce"] = "tampered"

        calls = []
        second = run_halt_first_transaction(self.root, lambda: calls.append(1))
        self.assertIsInstance(second, HaltActive)
        self.assertEqual([], calls)

    def test_missing_halt_runs_body_exactly_once_with_zero_arguments(self):
        invocations = []

        def body(*args, **kwargs):
            invocations.append((args, kwargs))
            return "body-result"

        outcome = run_halt_first_transaction(self.root, body)
        self.assertIsInstance(outcome, TransactionCompleted)
        self.assertEqual("body-result", outcome.result)
        self.assertEqual([((), {})], invocations)

    def test_driver_emits_no_framework_authority_object(self):
        self.assertFalse(hasattr(supervisor_transaction, "FenceCapability"))
        self.assertFalse(hasattr(supervisor_transaction, "CapabilityError"))
        self.assertNotIn("FenceCapability", supervisor_transaction.__all__)
        self.assertNotIn("CapabilityError", supervisor_transaction.__all__)
        token = object()
        outcome = run_halt_first_transaction(self.root, lambda: token)
        self.assertIsInstance(outcome, TransactionCompleted)
        # The arbitrary trusted business value passes through unchanged; it
        # is not an authority object and no framework object accompanies it.
        self.assertIs(token, outcome.result)

    def test_noncallable_body_is_rejected_only_after_halt_check(self):
        with self.assertRaises(FenceUsageError):
            run_halt_first_transaction(self.root, None)
        outcome = run_halt_first_transaction(self.root, lambda: "ok")
        self.assertEqual("ok", outcome.result)

    def test_noncallable_rejection_is_constant_and_never_evaluates_hooks(self):
        class HostileMeta(type):
            def __repr__(cls):
                raise KeyboardInterrupt("metaclass repr evaluated")

            def __str__(cls):
                raise KeyboardInterrupt("metaclass str evaluated")

        class HostileBody(metaclass=HostileMeta):
            def __repr__(self):
                raise KeyboardInterrupt("repr evaluated")

            def __str__(self):
                raise KeyboardInterrupt("str evaluated")

            def __format__(self, specification):
                raise KeyboardInterrupt("format evaluated")

        for hostile in (None, HostileBody()):
            with self.subTest(hostile=type(hostile).__name__):
                with self.assertRaises(FenceUsageError) as trap:
                    run_halt_first_transaction(self.root, hostile)
                self.assertEqual(
                    "transaction body must be callable", str(trap.exception)
                )
        outcome = run_halt_first_transaction(self.root, lambda: "after")
        self.assertEqual("after", outcome.result)


@unittest.skipUnless(IS_WINDOWS, "the supervisor fence is Windows-only")
class HaltEvidenceTests(FenceFixture):
    def sentinel_body(self):
        def body():  # pragma: no cover - must never run
            self.fail("transaction body ran despite unsafe HALT state")

        return body

    def halt_path(self):
        return self.root / HALT_FILENAME

    def test_corrupt_noncanonical_and_oversized_halt_prevent_body(self):
        wrong_kind = dict(
            attempt=0,
            created_utc=STAMP,
            kind="stop-request",
            nonce=NONCE,
            task_id="root",
            version=1,
        )
        extra_key = dict(wrong_kind, kind="halt", extra="forbidden")
        corruptions = (
            b"",
            b"garbage\n",
            b'{ "kind": "halt" }\n',
            json.dumps(wrong_kind, sort_keys=True, separators=(",", ":")).encode()
            + b"\n",
            json.dumps(extra_key, sort_keys=True, separators=(",", ":")).encode()
            + b"\n",
            b"{" + b" " * 3000,
        )
        for raw in corruptions:
            with self.subTest(raw=raw[:40]):
                self.halt_path().write_bytes(raw)
                with self.assertRaises(HaltEvidenceError):
                    run_halt_first_transaction(self.root, self.sentinel_body())
                self.halt_path().unlink()

    def test_hardlinked_halt_prevents_body(self):
        create_halt(self.root, nonce=NONCE, created_utc=STAMP)
        os.link(self.halt_path(), self.root / "halt-alias")
        with self.assertRaises(HaltEvidenceError):
            run_halt_first_transaction(self.root, self.sentinel_body())

    def test_reparse_halt_prevents_body_when_supported(self):
        target = self.root / "halt-target"
        target.write_bytes(b"{}\n")
        try:
            os.symlink(target, self.halt_path())
        except OSError as exc:
            self.skipTest(f"file symlinks denied by platform without privilege: {exc}")
        with self.assertRaises(HaltEvidenceError):
            run_halt_first_transaction(self.root, self.sentinel_body())

    def test_identity_swapped_halt_prevents_body(self):
        create_halt(self.root, nonce=NONCE, created_utc=STAMP)
        path = self.halt_path()
        valid_bytes = path.read_bytes()

        def swap(seen_path):
            os.unlink(path)
            path.write_bytes(valid_bytes)

        with mock.patch(
            "autonomy.supervisor_transaction._halt_open_seam", side_effect=swap
        ):
            with self.assertRaises(HaltEvidenceError):
                run_halt_first_transaction(self.root, self.sentinel_body())


@unittest.skipUnless(IS_WINDOWS, "the supervisor fence is Windows-only")
class FenceExclusionTests(FenceFixture):
    def lock_path(self):
        return self.root / SUPERVISOR_LOCK_FILENAME

    def test_held_fence_yields_bounded_contention_and_zero_body(self):
        calls = []
        holder = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        try:
            started = time.monotonic()
            with self.assertRaises(FenceContentionError):
                run_halt_first_transaction(self.root, lambda: calls.append(1))
            elapsed = time.monotonic() - started
        finally:
            holder.close()
        self.assertEqual([], calls)
        self.assertLess(elapsed, 10.0)
        outcome = run_halt_first_transaction(self.root, lambda: "after")
        self.assertEqual("after", outcome.result)

    def test_different_authenticated_roots_do_not_contend(self):
        other_root = self.make_second_root()
        holder = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        try:
            outcome = run_halt_first_transaction(other_root, lambda: "ok")
        finally:
            holder.close()
        self.assertEqual("ok", outcome.result)

    def test_nested_same_root_transaction_is_exact_contention(self):
        inner_calls = []

        def body():
            with self.assertRaises(FenceContentionError):
                run_halt_first_transaction(self.root, lambda: inner_calls.append(1))
            return "outer"

        outcome = run_halt_first_transaction(self.root, body)
        self.assertEqual("outer", outcome.result)
        self.assertEqual([], inner_calls)
        again = run_halt_first_transaction(self.root, lambda: "again")
        self.assertEqual("again", again.result)

    def test_rename_and_delete_while_held_cannot_split_brain(self):
        decoy = self.root / "decoy"
        decoy.write_bytes(b"\0")
        marker = self.root / ROOT_MARKER

        def body():
            with self.assertRaises(OSError):
                os.unlink(self.lock_path())
            with self.assertRaises(OSError):
                os.replace(decoy, self.lock_path())
            with self.assertRaises(OSError):
                os.unlink(marker)
            with self.assertRaises(OSError):
                os.replace(decoy, marker)
            with self.assertRaises(OSError):
                marker.open("wb")
            with self.assertRaises(OSError):
                os.rename(self.root, Path(os.fspath(self.root) + "-moved"))
            return "held"

        outcome = run_halt_first_transaction(self.root, body)
        self.assertEqual("held", outcome.result)
        self.assertEqual(b"\0", self.lock_path().read_bytes())
        self.assertEqual(1, os.lstat(self.lock_path()).st_nlink)
        self.assertEqual(CANONICAL_ROOT_MARKER, marker.read_bytes())

    def test_marker_invalidation_during_body_is_prevented_or_fails_closed(self):
        marker = self.root / ROOT_MARKER
        alias = self.root / "marker-alias"

        def body():
            os.link(marker, alias)
            return "alias-created"

        with self.assertRaises(LockIntegrityError):
            run_halt_first_transaction(self.root, body)
        os.unlink(alias)
        outcome = run_halt_first_transaction(self.root, lambda: "clean")
        self.assertEqual("clean", outcome.result)

    def test_body_exception_and_base_exception_propagate_unchanged(self):
        for hostile in (ValueError("body failed"), KeyboardInterrupt()):
            with self.subTest(hostile=type(hostile).__name__):
                invocations = []

                def body():
                    invocations.append(1)
                    raise hostile

                with self.assertRaises(type(hostile)) as trap:
                    run_halt_first_transaction(self.root, body)
                self.assertIs(hostile, trap.exception)
                self.assertEqual([1], invocations)
                outcome = run_halt_first_transaction(self.root, lambda: "recovered")
                self.assertEqual("recovered", outcome.result)

    def test_first_use_race_has_one_initializer_and_serialized_bodies(self):
        completions = []
        errors = []

        def contender(index):
            deadline = time.monotonic() + 120.0
            while True:
                try:
                    outcome = run_halt_first_transaction(
                        self.root, lambda: completions.append(index)
                    )
                except FenceContentionError:
                    if time.monotonic() >= deadline:
                        errors.append(TimeoutError(f"contender {index} starved"))
                        return
                    time.sleep(0.001)
                    continue
                except LockIntegrityError as exc:
                    if getattr(exc.__cause__, "winerror", None) == 32:
                        # Fail-closed publisher-drain sharing window; retry as
                        # a fresh independent invocation.
                        if time.monotonic() >= deadline:
                            errors.append(TimeoutError(f"contender {index} starved"))
                            return
                        time.sleep(0.001)
                        continue
                    errors.append(exc)
                    return
                except Exception as exc:  # pragma: no cover - diagnostic only
                    errors.append(exc)
                    return
                self.assertIsInstance(outcome, TransactionCompleted)
                return

        workers = [
            threading.Thread(target=contender, args=(index,)) for index in range(8)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=180)
        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual([], errors)
        self.assertEqual(8, len(completions))
        self.assertEqual(b"\0", self.lock_path().read_bytes())
        self.assertEqual(1, os.lstat(self.lock_path()).st_nlink)
        self.assertEqual(
            [], list(self.root.glob(f".{SUPERVISOR_LOCK_FILENAME}.*.tmp"))
        )

    def test_contention_with_rollback_failure_is_preserved_group_not_retryable(self):
        holder = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        released = []

        def release_holder():
            if not released:
                released.append(True)
                holder.close()

        self.addCleanup(release_holder)
        body_calls = []
        retained = []
        closes = []
        # Closed Win32 handle values are recycled, so close bookkeeping for a
        # retained handle only considers closes recorded from its own open.
        close_start = []
        real_create = control_state._win_create_file

        def create_spy(path, access, share, disposition, flags):
            handle = real_create(path, access, share, disposition, flags)
            if access != control_state._FILE_READ_ATTRIBUTES:
                close_start.append(len(closes))
                retained.append(handle)
            return handle

        injected = OSError(errno.EBADF, "injected rollback close failure", None, 6)
        real_close = control_state._win_close

        def close_spy(handle):
            # The real kernel close always runs first, and the injected
            # failure targets only the contender's retained lock handle.
            real_close(handle)
            closes.append(handle)
            if len(retained) == 3 and handle == retained[2]:
                raise injected

        with mock.patch(
            "autonomy.control_state._win_create_file", side_effect=create_spy
        ), mock.patch(
            "autonomy.control_state._win_close", side_effect=close_spy
        ):
            with self.assertRaises(BaseExceptionGroup) as trap:
                run_halt_first_transaction(
                    self.root, lambda: body_calls.append(1)
                )
        group = trap.exception
        # The compounded failure is preserved as the constructor's own group
        # and is never mapped to retryable FenceContentionError.
        self.assertNotIsInstance(group, FenceContentionError)
        self.assertEqual("lock acquisition and rollback both failed", group.message)
        self.assertEqual(2, len(group.exceptions))
        self.assertIsInstance(group.exceptions[0], LockUnavailableError)
        self.assertEqual(33, group.exceptions[0].__cause__.winerror)
        self.assertIsInstance(group.exceptions[1], LockIntegrityError)
        self.assertNotIsInstance(group.exceptions[1], LockUnavailableError)
        self.assertIs(injected, group.exceptions[1].__cause__)
        self.assertEqual([], body_calls)
        # Complete rollback: every retained handle the contender opened was
        # really closed exactly once.
        self.assertEqual(3, len(retained))
        for index, handle in enumerate(retained):
            self.assertEqual(1, closes[close_start[index]:].count(handle))
        release_holder()
        outcome = run_halt_first_transaction(self.root, lambda: "recovered")
        self.assertEqual("recovered", outcome.result)


@unittest.skipUnless(IS_WINDOWS, "the supervisor fence is Windows-only")
class ReleaseFailureMatrixTests(FenceFixture):
    """Exact primary-versus-release precedence for the transaction driver.

    Release failures are injected at the true offset-one unlock: the wrapper
    first performs the real kernel unlock and only then raises, so the fence
    is genuinely released while the driver observes a close failure.  The
    injected WinError is exactly 33 to prove that 33 outside the one
    ownership ``LockFileEx`` acquisition is integrity, never contention.
    """

    def release_failure_patch(self):
        real_unlock = control_state._win_unlock

        def unlock_fail(handle, offset):
            real_unlock(handle, offset)
            raise OSError(errno.EACCES, "injected release failure", None, 33)

        return mock.patch(
            "autonomy.control_state._win_unlock", side_effect=unlock_fail
        )

    def assert_recovered(self):
        outcome = run_halt_first_transaction(self.root, lambda: "recovered")
        self.assertEqual("recovered", outcome.result)

    def test_valid_halt_with_close_failure_raises_close_failure(self):
        create_halt(self.root, nonce=NONCE, created_utc=STAMP)
        with self.release_failure_patch():
            with self.assertRaises(LockIntegrityError) as trap:
                run_halt_first_transaction(self.root, None)
        self.assertNotIsInstance(trap.exception, FenceContentionError)
        self.assertEqual(33, trap.exception.__cause__.winerror)

    def test_corrupt_halt_with_close_failure_raises_ordered_group(self):
        (self.root / HALT_FILENAME).write_bytes(b"garbage\n")
        with self.release_failure_patch():
            with self.assertRaises(BaseExceptionGroup) as trap:
                run_halt_first_transaction(self.root, self.fail)
        group = trap.exception
        self.assertEqual("transaction and fence release both failed", group.message)
        self.assertEqual(2, len(group.exceptions))
        self.assertIsInstance(group.exceptions[0], HaltEvidenceError)
        self.assertIsInstance(group.exceptions[1], LockIntegrityError)

    def test_noncallable_body_with_close_failure_raises_ordered_group(self):
        with self.release_failure_patch():
            with self.assertRaises(BaseExceptionGroup) as trap:
                run_halt_first_transaction(self.root, None)
        group = trap.exception
        self.assertEqual("transaction and fence release both failed", group.message)
        self.assertEqual(2, len(group.exceptions))
        self.assertIsInstance(group.exceptions[0], FenceUsageError)
        self.assertIsInstance(group.exceptions[1], LockIntegrityError)
        self.assert_recovered()

    def test_successful_body_with_close_failure_raises_close_failure(self):
        invocations = []
        with self.release_failure_patch():
            with self.assertRaises(LockIntegrityError) as trap:
                run_halt_first_transaction(self.root, lambda: invocations.append(1))
        self.assertEqual([1], invocations)
        self.assertEqual(33, trap.exception.__cause__.winerror)
        self.assert_recovered()

    def test_body_exception_with_close_failure_preserves_both_in_order(self):
        hostile = ValueError("body failed")

        def body():
            raise hostile

        with self.release_failure_patch():
            with self.assertRaises(BaseExceptionGroup) as trap:
                run_halt_first_transaction(self.root, body)
        group = trap.exception
        self.assertEqual("transaction and fence release both failed", group.message)
        self.assertEqual(2, len(group.exceptions))
        self.assertIs(hostile, group.exceptions[0])
        self.assertIsInstance(group.exceptions[1], LockIntegrityError)
        self.assert_recovered()

    def test_body_base_exception_with_close_failure_preserves_both_in_order(self):
        hostile = KeyboardInterrupt("body interrupted")

        def body():
            raise hostile

        with self.release_failure_patch():
            with self.assertRaises(BaseExceptionGroup) as trap:
                run_halt_first_transaction(self.root, body)
        group = trap.exception
        self.assertEqual("transaction and fence release both failed", group.message)
        self.assertEqual(2, len(group.exceptions))
        self.assertIs(hostile, group.exceptions[0])
        self.assertIsInstance(group.exceptions[1], LockIntegrityError)
        self.assert_recovered()


@unittest.skipUnless(IS_WINDOWS, "the supervisor fence is Windows-only")
class HaltDescriptorCloseTests(FenceFixture):
    """Primary/close aggregation for the pinned durable-HALT descriptor."""

    def halt_path(self):
        return self.root / HALT_FILENAME

    def descriptor_capture(self, captured):
        real_open = os.open
        halt = os.fspath(self.halt_path())

        def open_spy(path, flags, *args, **kwargs):
            descriptor = real_open(path, flags, *args, **kwargs)
            if isinstance(path, (str, os.PathLike)) and os.fspath(path) == halt:
                captured.append(descriptor)
            return descriptor

        return mock.patch("os.open", side_effect=open_spy)

    def close_capture(self, captured, closes, injected):
        real_close = os.close

        def close_spy(descriptor):
            # The real kernel close always runs first, and the injected
            # failure targets only the captured HALT descriptor.
            real_close(descriptor)
            if captured and descriptor == captured[0]:
                closes.append(descriptor)
                if injected is not None:
                    raise injected

        return mock.patch("os.close", side_effect=close_spy)

    def parse_capture(self, calls, raised):
        real_parse = control_state.parse_halt_document

        def parse_spy(raw):
            calls.append(raw)
            try:
                return real_parse(raw)
            except BaseException as exc:
                raised.append(exc)
                raise

        return mock.patch(
            "autonomy.supervisor_transaction.parse_halt_document",
            side_effect=parse_spy,
        )

    def assert_descriptor_terminal(self, captured, closes):
        self.assertEqual(1, len(captured))
        self.assertEqual([captured[0]], closes)
        with self.assertRaises(OSError):
            os.fstat(captured[0])

    def assert_fence_released(self):
        follow_up = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        follow_up.close()

    def test_primary_only_with_close_success_reraises_same_primary(self):
        self.halt_path().write_bytes(b"garbage\n")
        captured, closes, parse_calls, parse_raised = [], [], [], []
        body_calls = []
        with self.descriptor_capture(captured), self.close_capture(
            captured, closes, None
        ), self.parse_capture(parse_calls, parse_raised):
            with self.assertRaises(HaltEvidenceError) as trap:
                run_halt_first_transaction(self.root, lambda: body_calls.append(1))
        self.assertEqual(1, len(parse_calls))
        self.assertEqual(1, len(parse_raised))
        self.assertIs(parse_raised[0], trap.exception.__cause__)
        self.assertEqual([], body_calls)
        self.assert_descriptor_terminal(captured, closes)
        self.assert_fence_released()

    def test_close_only_failure_is_typed_evidence_error_and_no_success(self):
        create_halt(self.root, nonce=NONCE, created_utc=STAMP)
        captured, closes, body_calls = [], [], []
        injected = OSError(errno.EBADF, "injected descriptor close failure")
        with self.descriptor_capture(captured), self.close_capture(
            captured, closes, injected
        ):
            with self.assertRaises(HaltEvidenceError) as trap:
                run_halt_first_transaction(self.root, lambda: body_calls.append(1))
        self.assertIs(injected, trap.exception.__cause__)
        self.assertEqual([], body_calls)
        self.assert_descriptor_terminal(captured, closes)
        self.assert_fence_released()

    def test_primary_plus_close_failure_preserves_both_in_order(self):
        self.halt_path().write_bytes(b"garbage\n")
        captured, closes, parse_calls, parse_raised = [], [], [], []
        body_calls = []
        injected = OSError(errno.EBADF, "injected descriptor close failure")
        with self.descriptor_capture(captured), self.close_capture(
            captured, closes, injected
        ), self.parse_capture(parse_calls, parse_raised):
            with self.assertRaises(BaseExceptionGroup) as trap:
                run_halt_first_transaction(self.root, lambda: body_calls.append(1))
        group = trap.exception
        self.assertEqual(
            "durable HALT read and descriptor close both failed", group.message
        )
        self.assertEqual(2, len(group.exceptions))
        self.assertIsInstance(group.exceptions[0], HaltEvidenceError)
        self.assertIs(parse_raised[0], group.exceptions[0].__cause__)
        self.assertIsInstance(group.exceptions[1], HaltEvidenceError)
        self.assertIs(injected, group.exceptions[1].__cause__)
        self.assertEqual(1, len(parse_calls))
        self.assertEqual([], body_calls)
        self.assert_descriptor_terminal(captured, closes)
        self.assert_fence_released()

    def test_close_only_keyboard_interrupt_is_preserved(self):
        create_halt(self.root, nonce=NONCE, created_utc=STAMP)
        captured, closes, body_calls = [], [], []
        injected = KeyboardInterrupt("injected close interrupt")
        with self.descriptor_capture(captured), self.close_capture(
            captured, closes, injected
        ):
            with self.assertRaises(KeyboardInterrupt) as trap:
                run_halt_first_transaction(self.root, lambda: body_calls.append(1))
        self.assertIs(injected, trap.exception)
        self.assertEqual([], body_calls)
        self.assert_descriptor_terminal(captured, closes)
        self.assert_fence_released()

    def test_primary_plus_keyboard_interrupt_close_is_ordered_group(self):
        self.halt_path().write_bytes(b"garbage\n")
        captured, closes, parse_calls, parse_raised = [], [], [], []
        body_calls = []
        injected = KeyboardInterrupt("injected close interrupt")
        with self.descriptor_capture(captured), self.close_capture(
            captured, closes, injected
        ), self.parse_capture(parse_calls, parse_raised):
            with self.assertRaises(BaseExceptionGroup) as trap:
                run_halt_first_transaction(self.root, lambda: body_calls.append(1))
        group = trap.exception
        self.assertEqual(2, len(group.exceptions))
        self.assertIsInstance(group.exceptions[0], HaltEvidenceError)
        self.assertIs(parse_raised[0], group.exceptions[0].__cause__)
        self.assertIs(injected, group.exceptions[1])
        self.assertEqual([], body_calls)
        self.assert_descriptor_terminal(captured, closes)
        self.assert_fence_released()


@unittest.skipUnless(IS_WINDOWS, "the supervisor fence is Windows-only")
class HaltCheckpointMatrixTests(FenceFixture):
    """Same-identity directory/symlink/reparse matrices at every checkpoint."""

    STAGES = ("opened-fstat", "post-read-fstat", "post-read-lstat")
    CORRUPTIONS = ("directory", "symlink", "reparse")

    def halt_path(self):
        return self.root / HALT_FILENAME

    @staticmethod
    def corrupt_stat(info, corruption):
        values = {
            "st_mode": info.st_mode,
            "st_nlink": info.st_nlink,
            "st_size": info.st_size,
            "st_dev": info.st_dev,
            "st_ino": info.st_ino,
            "st_file_attributes": getattr(info, "st_file_attributes", 0),
        }
        if corruption == "directory":
            values["st_mode"] = stat.S_IFDIR | 0o555
        elif corruption == "symlink":
            values["st_mode"] = stat.S_IFLNK | 0o777
        elif corruption == "reparse":
            values["st_file_attributes"] |= supervisor_transaction._REPARSE_FLAG
        else:  # pragma: no cover - matrix definition error
            raise AssertionError(corruption)
        return types.SimpleNamespace(**values)

    def run_matrix_case(self, stage, corruption):
        create_halt(self.root, nonce=NONCE, created_utc=STAMP)
        halt = os.fspath(self.halt_path())
        captured = []
        real_open = os.open

        def open_spy(path, flags, *args, **kwargs):
            descriptor = real_open(path, flags, *args, **kwargs)
            if isinstance(path, (str, os.PathLike)) and os.fspath(path) == halt:
                captured.append(descriptor)
            return descriptor

        fstat_calls = [0]
        real_fstat = os.fstat

        def fstat_spy(descriptor):
            info = real_fstat(descriptor)
            if captured and descriptor == captured[0]:
                fstat_calls[0] += 1
                if stage == "opened-fstat" and fstat_calls[0] == 1:
                    return self.corrupt_stat(info, corruption)
                if stage == "post-read-fstat" and fstat_calls[0] == 2:
                    return self.corrupt_stat(info, corruption)
            return info

        lstat_calls = [0]
        real_lstat = os.lstat

        def lstat_spy(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            if isinstance(path, (str, os.PathLike)) and os.fspath(path) == halt:
                lstat_calls[0] += 1
                if stage == "post-read-lstat" and lstat_calls[0] == 2:
                    return self.corrupt_stat(info, corruption)
            return info

        parse_calls = []

        def parse_spy(raw):
            parse_calls.append(raw)
            return control_state.parse_halt_document(raw)

        body_calls = []
        with mock.patch("os.open", side_effect=open_spy), mock.patch(
            "os.fstat", side_effect=fstat_spy
        ), mock.patch("os.lstat", side_effect=lstat_spy), mock.patch(
            "autonomy.supervisor_transaction.parse_halt_document",
            side_effect=parse_spy,
        ):
            with self.assertRaises(HaltEvidenceError):
                run_halt_first_transaction(self.root, lambda: body_calls.append(1))
        self.assertEqual([], parse_calls)
        self.assertEqual([], body_calls)
        self.assertEqual(1, len(captured))
        with self.assertRaises(OSError):
            os.fstat(captured[0])
        follow_up = PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME)
        follow_up.close()
        self.halt_path().unlink()

    def test_same_identity_corruption_matrix_fails_closed_at_every_checkpoint(self):
        for stage in self.STAGES:
            for corruption in self.CORRUPTIONS:
                with self.subTest(stage=stage, corruption=corruption):
                    self.run_matrix_case(stage, corruption)


@unittest.skipUnless(IS_WINDOWS, "the supervisor fence is Windows-only")
class SubprocessFenceTests(FenceFixture):
    def test_two_subprocess_transactions_on_one_root_never_overlap(self):
        script = textwrap.dedent(
            """
            import os
            import sys
            import time

            import autonomy.control_state as control_state
            from autonomy.control_state import LockIntegrityError
            from autonomy.supervisor_transaction import (
                FenceContentionError,
                run_halt_first_transaction,
            )

            root, log_path, index = sys.argv[1], sys.argv[2], sys.argv[3]
            busy = os.path.join(root, "busy-flag")

            def append(event):
                record = f"{event} {index} {time.perf_counter():.9f}\\n".encode()
                descriptor = os.open(log_path, os.O_APPEND | os.O_WRONLY | os.O_CREAT)
                try:
                    os.write(descriptor, record)
                finally:
                    os.close(descriptor)

            def tail_seam(path):
                append("tail")

            control_state._pre_unlock_seam = tail_seam

            real_unlock = control_state._win_unlock

            def unlock_logger(handle, offset):
                if offset == control_state._LOCK_OWNERSHIP_OFFSET:
                    # Stamp the instant immediately before the real kernel
                    # unlock so a competitor can only start strictly later.
                    append("unlock")
                real_unlock(handle, offset)

            control_state._win_unlock = unlock_logger

            def body():
                descriptor = os.open(busy, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                append("start")
                try:
                    time.sleep(0.2)
                finally:
                    append("end")
                    os.close(descriptor)
                    os.unlink(busy)
                return None

            deadline = time.monotonic() + 60.0
            while True:
                try:
                    run_halt_first_transaction(root, body)
                    raise SystemExit(0)
                except FenceContentionError:
                    pass
                except LockIntegrityError as exc:
                    if getattr(exc.__cause__, "winerror", None) != 32:
                        raise
                if time.monotonic() >= deadline:
                    raise SystemExit(7)
                time.sleep(0.01)
            """
        )
        log_path = self.root / "overlap-log.txt"
        children = [
            subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    script,
                    os.fspath(self.root),
                    os.fspath(log_path),
                    str(index),
                ],
                cwd=REPO_ROOT,
                env=subprocess_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for index in range(2)
        ]
        for child in children:
            self.addCleanup(child.kill)
        for child in children:
            stdout, stderr = child.communicate(timeout=120)
            self.assertEqual(0, child.returncode, stdout + stderr)
        self.assertFalse((self.root / "busy-flag").exists())
        events = {}
        for line in log_path.read_text().splitlines():
            kind, index, stamp = line.split()
            events.setdefault(index, {})[kind] = float(stamp)
        self.assertEqual(2, len(events))
        intervals = []
        for index, marks in events.items():
            self.assertEqual({"start", "end", "tail", "unlock"}, set(marks), marks)
            self.assertLessEqual(marks["start"], marks["end"])
            self.assertLessEqual(marks["end"], marks["tail"])
            self.assertLessEqual(marks["tail"], marks["unlock"])
            intervals.append((marks["start"], marks["unlock"], index))
        intervals.sort()
        # The second body must start strictly after the first transaction has
        # reached its final pre-unlock instant: exclusion holds through the
        # body tail, the final checkpoint, and the final unlock.
        self.assertLess(intervals[0][1], intervals[1][0], intervals)
        lock_path = self.root / SUPERVISOR_LOCK_FILENAME
        self.assertEqual(b"\0", lock_path.read_bytes())
        self.assertEqual(1, os.lstat(lock_path).st_nlink)

    def test_killing_holder_releases_kernel_lock_and_preserves_file(self):
        PermanentFileLock(self.root, SUPERVISOR_LOCK_FILENAME).close()
        lock_path = self.root / SUPERVISOR_LOCK_FILENAME
        ready_path = self.root / "holder-ready"
        probe_hold = self.root / "probe-held-file"
        holder_script = textwrap.dedent(
            """
            import os
            import subprocess
            import sys
            import time

            from autonomy.supervisor_transaction import run_halt_first_transaction

            root, ready_path, probe_hold = sys.argv[1:4]

            def body():
                probe = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        "import os, sys, time\\n"
                        "descriptor = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR)\\n"
                        "time.sleep(120)\\n",
                        probe_hold,
                    ],
                    close_fds=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                with open(ready_path + ".tmp", "w") as handle:
                    handle.write(str(probe.pid))
                os.replace(ready_path + ".tmp", ready_path)
                time.sleep(120)

            run_halt_first_transaction(root, body)
            """
        )
        holder_log = self.root / "holder-log.txt"
        with holder_log.open("w") as log_handle:
            holder = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    holder_script,
                    os.fspath(self.root),
                    os.fspath(ready_path),
                    os.fspath(probe_hold),
                ],
                cwd=REPO_ROOT,
                env=subprocess_environment(),
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
            )
        self.addCleanup(holder.kill)
        deadline = time.monotonic() + 30.0
        while not (ready_path.exists() and probe_hold.exists()):
            if holder.poll() is not None:
                self.fail(f"holder exited early: {holder_log.read_text()}")
            if time.monotonic() >= deadline:
                self.fail("holder never acquired the fence")
            time.sleep(0.05)
        probe_pid = int(ready_path.read_text())
        probe_terminated = False
        try:
            with self.assertRaises(FenceContentionError):
                run_halt_first_transaction(self.root, lambda: "denied")
            holder.kill()
            holder.wait(timeout=30)
            self.assertIsNotNone(holder.returncode)

            with self.assertRaises(PermissionError):
                os.unlink(probe_hold)

            outcome = None
            deadline = time.monotonic() + 15.0
            while True:
                try:
                    outcome = run_halt_first_transaction(
                        self.root, lambda: "acquired-after-kill"
                    )
                    break
                except FenceContentionError:
                    if time.monotonic() >= deadline:
                        self.fail("kernel lock was not released by holder death")
                    time.sleep(0.05)
            self.assertEqual("acquired-after-kill", outcome.result)
            self.assertEqual(b"\0", lock_path.read_bytes())
            self.assertEqual(1, os.lstat(lock_path).st_nlink)
        finally:
            try:
                os.kill(probe_pid, signal.SIGTERM)
            except OSError:
                probe_terminated = True
            deadline = time.monotonic() + 15.0
            while not probe_terminated:
                try:
                    os.unlink(probe_hold)
                    probe_terminated = True
                except OSError:
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
        self.assertTrue(probe_terminated, "probe child did not reach terminal state")


class StaticGateTests(unittest.TestCase):
    FORBIDDEN_IMPORT_FRAGMENTS = (
        "boot_clock",
        "tick_core",
        "tick_state",
        "queue_cli",
        "checkpoint",
        "scheduler",
        "runner",
        "supervisor_tick",
        "supervisor",
        "winjob",
        "canary_worker",
        "quota_capacity",
        "heartbeat",
        "subprocess",
        "socket",
        "ssl",
        "http",
        "urllib",
        "asyncio",
        "ctypes",
        "time",
        "datetime",
        "threading",
        "app",
        "store",
        "router",
        "jobs",
        "wrapper",
    )

    # The exact identifiers of the removed Python token-as-authority surface.
    FORBIDDEN_AUTHORITY_IDENTIFIERS = (
        "FenceCapability",
        "CapabilityError",
        "require_active",
    )
    FORBIDDEN_TRANSACTION_IDENTIFIERS = (
        "live_records",
        "generation_counter",
        "_build_fence_transaction_system",
    )

    def module_tree(self):
        return ast.parse(MODULE_PATH.read_text(encoding="utf-8"))

    def production_sources(self):
        """One finite production source set, reused by every NAME-token gate.

        Tests and any ``.venv`` are excluded by construction: only repo-root
        ``*.py`` and recursive ``autonomy/**/*.py`` are ever globbed.
        """

        sources = sorted(REPO_ROOT.glob("*.py")) + sorted(
            (REPO_ROOT / "autonomy").rglob("*.py")
        )
        self.assertTrue(sources)
        resolved = {source.resolve() for source in sources}
        self.assertIn(MODULE_PATH.resolve(), resolved)
        self.assertIn(
            (REPO_ROOT / "autonomy" / "control_state.py").resolve(), resolved
        )
        return sources

    def name_tokens_or_fail(self, source_path):
        """NAME tokens of one production source; any failure is a test failure."""

        try:
            text = source_path.read_text(encoding="utf-8")
            return collect_name_tokens(text)
        except (
            tokenize.TokenError,
            IndentationError,
            SyntaxError,
            UnicodeDecodeError,
            ValueError,
        ) as exc:
            self.fail(f"tokenization failed for {source_path}: {exc!r}")

    def test_import_surface_is_closed_and_forbidden_modules_are_absent(self):
        allowed = {
            "__future__",
            "os",
            "stat",
            "dataclasses",
            "pathlib",
            "types",
            "typing",
            "autonomy.control_state",
        }
        imported = set()
        for node in ast.walk(self.module_tree()):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(0, node.level, "relative imports are forbidden")
                self.assertIsNotNone(node.module)
                imported.add(node.module)
        self.assertLessEqual(imported, allowed, imported - allowed)
        for name in imported:
            parts = set(name.split("."))
            for fragment in self.FORBIDDEN_IMPORT_FRAGMENTS:
                self.assertNotIn(
                    fragment,
                    parts - {"control_state"},
                    f"forbidden import {fragment!r} via {name!r}",
                )

    # The gates below are deliberately conservative finite NAME-token rules,
    # not general runtime alias analysis: any future production import,
    # alias, assignment, or direct call of a gated name requires an explicit
    # reviewed test change.  String-based lookup such as getattr/importlib is
    # an intentionally recorded residual, not a covered case.

    def assert_name_token_confined(self, forbidden, defining_path):
        offenders = []
        for source_path in self.production_sources():
            if source_path.resolve() == defining_path.resolve():
                continue
            if forbidden in self.name_tokens_or_fail(source_path):
                offenders.append(str(source_path))
        self.assertEqual([], offenders, forbidden)

    def assert_name_token_consumer_set(self, forbidden, expected_paths):
        """The exact production sources whose NAME tokens include ``forbidden``.

        Unlike :meth:`assert_name_token_confined` this is a closed equality:
        a missing expected consumer fails exactly like an extra hostile one,
        and detection reuses the same NFKC-normalized NAME-token collector,
        so alias imports, attribute calls, stores, definitions, parameters,
        exception aliases, global/nonlocal statements, match captures, and
        NFKC-equivalent identifiers are all counted as consumption.
        """

        expected = sorted(str(path.resolve()) for path in expected_paths)
        consumers = []
        for source_path in self.production_sources():
            if forbidden in self.name_tokens_or_fail(source_path):
                consumers.append(str(source_path.resolve()))
        self.assertEqual(expected, sorted(consumers), forbidden)

    def test_run_halt_first_transaction_name_token_is_confined(self):
        self.assert_name_token_consumer_set(
            "run_halt_first_transaction",
            (MODULE_PATH, REPO_ROOT / "autonomy" / "night_tick.py"),
        )

    def test_create_halt_name_token_is_confined(self):
        self.assert_name_token_confined(
            "create_halt", REPO_ROOT / "autonomy" / "control_state.py"
        )

    def test_removed_authority_name_tokens_are_absent_from_autonomy(self):
        autonomy_dir = (REPO_ROOT / "autonomy").resolve()
        checked = 0
        for source_path in self.production_sources():
            if autonomy_dir not in source_path.resolve().parents:
                continue
            checked += 1
            tokens = self.name_tokens_or_fail(source_path)
            for forbidden in self.FORBIDDEN_AUTHORITY_IDENTIFIERS:
                self.assertNotIn(
                    forbidden,
                    tokens,
                    f"authority identifier {forbidden!r} in {source_path}",
                )
        self.assertGreater(checked, 5)

    def test_transaction_module_has_no_registry_generation_or_capability_name(self):
        tokens = self.name_tokens_or_fail(MODULE_PATH)
        for forbidden in (
            self.FORBIDDEN_AUTHORITY_IDENTIFIERS
            + self.FORBIDDEN_TRANSACTION_IDENTIFIERS
            + ("capability", "create_halt")
        ):
            self.assertNotIn(forbidden, tokens, forbidden)

    def test_collector_sees_every_identifier_binding_construct(self):
        source = textwrap.dedent(
            """
            import os as alias_import
            from pathlib import Path as alias_from

            def defined_function(parameter_name):
                global global_name
                stored_name = loaded_name
                try:
                    pass
                except ValueError as handler_name:
                    pass

                def inner_function():
                    nonlocal stored_name

                match subject_name:
                    case [first_capture, *star_capture]:
                        pass
                    case captured_as_name:
                        pass

            class DefinedClass:
                pass
            """
        )
        names = collect_name_tokens(source)
        for expected in (
            "os",
            "alias_import",
            "pathlib",
            "Path",
            "alias_from",
            "defined_function",
            "parameter_name",
            "global_name",
            "stored_name",
            "loaded_name",
            "handler_name",
            "inner_function",
            "subject_name",
            "first_capture",
            "star_capture",
            "captured_as_name",
            "DefinedClass",
        ):
            self.assertIn(expected, names)

    def test_collector_sees_aliased_imports_calls_and_stores(self):
        cases = (
            "from autonomy.supervisor_transaction import "
            "run_halt_first_transaction as fenced\n",
            "import autonomy.supervisor_transaction as st\n"
            "st.run_halt_first_transaction(root, body)\n",
            "fenced = run_halt_first_transaction\n",
            "try:\n    pass\nexcept ValueError as run_halt_first_transaction:\n"
            "    pass\n",
            "def helper(run_halt_first_transaction):\n    pass\n",
            "def helper():\n    global run_halt_first_transaction\n",
            "match value:\n    case run_halt_first_transaction:\n        pass\n",
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertIn(
                    "run_halt_first_transaction", collect_name_tokens(source)
                )

    def test_collector_normalizes_nfkc_equivalent_hostile_identifiers(self):
        hostile_name = "x = create_hal\N{MATHEMATICAL SANS-SERIF SMALL T}()\n"
        self.assertIn("create_halt", collect_name_tokens(hostile_name))
        hostile_attribute = (
            "module.run_halt_first_transactio"
            "\N{MATHEMATICAL SANS-SERIF SMALL N}(root, body)\n"
        )
        self.assertIn(
            "run_halt_first_transaction", collect_name_tokens(hostile_attribute)
        )

    def test_collector_ignores_string_and_comment_occurrences(self):
        source = (
            "# create_halt mentioned in a comment only\n"
            'text = "run_halt_first_transaction and create_halt"\n'
            "documented = '''FenceCapability CapabilityError require_active'''\n"
        )
        names = collect_name_tokens(source)
        for absent in (
            "create_halt",
            "run_halt_first_transaction",
            "FenceCapability",
            "CapabilityError",
            "require_active",
        ):
            self.assertNotIn(absent, names)

    def test_tokenization_failure_is_a_test_failure_never_a_skip(self):
        with tempfile.TemporaryDirectory() as scratch:
            broken = Path(scratch) / "broken.py"
            broken.write_bytes(b"def broken(:\n\xff\xfe (")
            with self.assertRaises(self.failureException):
                self.name_tokens_or_fail(broken)


class DriverBindingDisciplineTests(unittest.TestCase):
    """AST binding discipline for the one importing driver consumer.

    Boolean NAME-token presence proves which production files consume
    ``run_halt_first_transaction`` but cannot see hostile bindings inside
    the already expected consumer.  This gate therefore additionally
    requires that ``autonomy/night_tick.py`` passes
    :func:`driver_binding_violations` with zero violations: exactly one
    module-level unaliased import of the driver from the frozen module and
    exactly one direct Name call to that imported binding directly inside
    ``observe_night_tick``, with every other binding or use rejected.  The
    validator itself is exercised against every hostile fixture class the
    S1 R4 independent review demonstrated or required.
    """

    NIGHT_TICK_PATH = REPO_ROOT / "autonomy" / "night_tick.py"

    VALID_CONSUMER = textwrap.dedent(
        """
        from autonomy.supervisor_transaction import run_halt_first_transaction


        def _tick_body():
            return None


        def observe_night_tick(queue_root):
            return run_halt_first_transaction(queue_root, _tick_body)
        """
    )

    def test_real_night_tick_module_has_no_binding_violations(self):
        source = self.NIGHT_TICK_PATH.read_text(encoding="utf-8")
        self.assertEqual([], driver_binding_violations(source))

    def test_minimal_valid_consumer_is_accepted(self):
        self.assertEqual([], driver_binding_violations(self.VALID_CONSUMER))

    def test_hostile_constructs_added_to_a_valid_consumer_are_rejected(self):
        # Each fixture appends exactly one hostile construct to an
        # otherwise valid consumer, so the expected violation list is
        # exact, not a membership check.
        cases = (
            (
                "store",
                "run_halt_first_transaction = observe_night_tick\n",
                ["driver-name-stored"],
            ),
            (
                "type-alias-store",
                "type run_halt_first_transaction = int\n",
                ["driver-name-stored"],
            ),
            (
                "delete",
                "del run_halt_first_transaction\n",
                ["driver-name-deleted"],
            ),
            (
                "bare-load",
                "probe = run_halt_first_transaction\n",
                ["driver-name-loaded-outside-direct-call"],
            ),
            (
                "load-as-argument",
                "probe = repr(run_halt_first_transaction)\n",
                ["driver-name-loaded-outside-direct-call"],
            ),
            (
                "function-definition",
                "def run_halt_first_transaction():\n    pass\n",
                ["driver-name-used-as-function-definition"],
            ),
            (
                "async-function-definition",
                "async def run_halt_first_transaction():\n    pass\n",
                ["driver-name-used-as-function-definition"],
            ),
            (
                "class-definition",
                "class run_halt_first_transaction:\n    pass\n",
                ["driver-name-used-as-class-definition"],
            ),
            (
                "parameter",
                "def helper(run_halt_first_transaction):\n    pass\n",
                ["driver-name-used-as-parameter"],
            ),
            (
                "lambda-parameter",
                "helper = lambda run_halt_first_transaction: None\n",
                ["driver-name-used-as-parameter"],
            ),
            (
                "exception-alias",
                "try:\n    pass\n"
                "except ValueError as run_halt_first_transaction:\n    pass\n",
                ["driver-name-used-as-exception-alias"],
            ),
            (
                "global-declaration",
                "def helper():\n    global run_halt_first_transaction\n",
                ["driver-name-declared-global"],
            ),
            (
                "nonlocal-declaration",
                "def outer():\n"
                "    run_halt_first_transaction = None\n"
                "    def inner():\n"
                "        nonlocal run_halt_first_transaction\n",
                ["driver-name-declared-nonlocal", "driver-name-stored"],
            ),
            (
                "match-capture",
                "def helper(value):\n"
                "    match value:\n"
                "        case run_halt_first_transaction:\n"
                "            pass\n",
                ["driver-name-used-as-match-capture"],
            ),
            (
                "match-star-capture",
                "def helper(value):\n"
                "    match value:\n"
                "        case [*run_halt_first_transaction]:\n"
                "            pass\n",
                ["driver-name-used-as-match-capture"],
            ),
            (
                "match-mapping-rest-capture",
                "def helper(value):\n"
                "    match value:\n"
                "        case {**run_halt_first_transaction}:\n"
                "            pass\n",
                ["driver-name-used-as-match-capture"],
            ),
            (
                "attribute-use",
                "def helper(module):\n"
                "    return module.run_halt_first_transaction\n",
                ["driver-name-used-as-attribute"],
            ),
            (
                "attribute-call",
                "import autonomy.supervisor_transaction\n"
                "def helper(root, body):\n"
                "    return autonomy.supervisor_transaction."
                "run_halt_first_transaction(root, body)\n",
                ["driver-name-used-as-attribute"],
            ),
            (
                "keyword-argument-name",
                "def helper(callback):\n"
                "    return callback(run_halt_first_transaction=1)\n",
                ["driver-name-used-as-keyword-argument"],
            ),
            (
                "type-parameter",
                "def helper[run_halt_first_transaction]():\n    pass\n",
                ["driver-name-used-as-type-parameter"],
            ),
            (
                "nfkc-equivalent-store",
                "run_halt_first_transactio"
                "\N{MATHEMATICAL SANS-SERIF SMALL N} = 1\n",
                ["driver-name-stored"],
            ),
            (
                "aliased-binding-of-other-import",
                "from autonomy.supervisor_transaction import "
                "HaltActive as run_halt_first_transaction\n",
                ["aliased-binding-of-driver-name"],
            ),
            (
                "nfkc-equivalent-aliased-binding",
                "from autonomy.supervisor_transaction import "
                "run_halt_first_transaction as run_halt_first_transactio"
                "\N{MATHEMATICAL SANS-SERIF SMALL N}\n",
                ["aliased-binding-of-driver-name", "driver-imported-under-alias"],
            ),
            (
                "plain-import-binding",
                "import run_halt_first_transaction\n",
                ["driver-name-bound-by-import"],
            ),
            (
                "plain-import-alias-binding",
                "import os as run_halt_first_transaction\n",
                ["driver-name-bound-by-import"],
            ),
            (
                "duplicate-unaliased-import",
                "from autonomy.supervisor_transaction import "
                "run_halt_first_transaction\n",
                ["driver-unaliased-import-count-not-one"],
            ),
            (
                "module-level-call",
                "outcome = run_halt_first_transaction(None, None)\n",
                ["driver-call-outside-observe-night-tick"],
            ),
            (
                "call-in-other-function",
                "def helper(root):\n"
                "    return run_halt_first_transaction(root, None)\n",
                ["driver-call-outside-observe-night-tick"],
            ),
            (
                "observe-night-tick-redefinition",
                "def observe_night_tick(queue_root):\n    return None\n",
                ["observe-night-tick-definition-count-not-one"],
            ),
        )
        for label, suffix, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(
                    expected,
                    driver_binding_violations(self.VALID_CONSUMER + suffix),
                )

    def test_standalone_hostile_consumers_are_rejected(self):
        cases = (
            (
                "aliased-import-with-alias-call",
                "from autonomy.supervisor_transaction import "
                "run_halt_first_transaction as fenced\n"
                "def observe_night_tick(queue_root):\n"
                "    return fenced(queue_root, None)\n",
                "driver-imported-under-alias",
            ),
            (
                "wrong-module-import",
                "from autonomy.control_state import "
                "run_halt_first_transaction\n"
                "def observe_night_tick(queue_root):\n"
                "    return run_halt_first_transaction(queue_root, None)\n",
                "driver-imported-from-wrong-module",
            ),
            (
                "relative-import",
                "from .supervisor_transaction import "
                "run_halt_first_transaction\n"
                "def observe_night_tick(queue_root):\n"
                "    return run_halt_first_transaction(queue_root, None)\n",
                "driver-imported-from-wrong-module",
            ),
            (
                "function-level-import",
                "def observe_night_tick(queue_root):\n"
                "    from autonomy.supervisor_transaction import "
                "run_halt_first_transaction\n"
                "    return run_halt_first_transaction(queue_root, None)\n",
                "driver-import-not-module-level",
            ),
            (
                "missing-import",
                "def observe_night_tick(queue_root):\n"
                "    return run_halt_first_transaction(queue_root, None)\n",
                "driver-unaliased-import-count-not-one",
            ),
            (
                "call-nested-inside-observe-night-tick",
                "from autonomy.supervisor_transaction import "
                "run_halt_first_transaction\n"
                "def observe_night_tick(queue_root):\n"
                "    def inner():\n"
                "        return run_halt_first_transaction(queue_root, None)\n"
                "    return inner()\n",
                "driver-call-outside-observe-night-tick",
            ),
            (
                "two-direct-calls",
                "from autonomy.supervisor_transaction import "
                "run_halt_first_transaction\n"
                "def observe_night_tick(queue_root):\n"
                "    run_halt_first_transaction(queue_root, None)\n"
                "    return run_halt_first_transaction(queue_root, None)\n",
                "driver-direct-call-count-not-one",
            ),
            (
                "zero-direct-calls",
                "from autonomy.supervisor_transaction import "
                "run_halt_first_transaction\n"
                "def observe_night_tick(queue_root):\n"
                "    return None\n",
                "driver-direct-call-count-not-one",
            ),
            (
                "observe-night-tick-inside-class",
                "from autonomy.supervisor_transaction import "
                "run_halt_first_transaction\n"
                "class Holder:\n"
                "    def observe_night_tick(self, queue_root):\n"
                "        return run_halt_first_transaction(queue_root, None)\n",
                "driver-call-outside-observe-night-tick",
            ),
        )
        for label, source, expected_code in cases:
            with self.subTest(label=label):
                violations = driver_binding_violations(source)
                self.assertNotEqual([], violations)
                self.assertIn(expected_code, violations)

    def test_alias_preserving_redefinition_mutant_is_rejected(self):
        # The exact bypass the independent review demonstrated: the
        # imported driver survives under an alias, a local function
        # redefines the driver name, and the observer delegates through
        # the local redefinition.  Token presence still sees the name, so
        # only binding analysis can reject it.
        mutant = textwrap.dedent(
            """
            from autonomy.supervisor_transaction import (
                run_halt_first_transaction as _fenced_driver,
            )


            def _tick_body():
                return None


            def run_halt_first_transaction(queue_root, body):
                return _fenced_driver(queue_root, body)


            def observe_night_tick(queue_root):
                return run_halt_first_transaction(queue_root, _tick_body)
            """
        )
        self.assertIn(DRIVER_NAME, collect_name_tokens(mutant))
        violations = driver_binding_violations(mutant)
        self.assertIn("driver-imported-under-alias", violations)
        self.assertIn("driver-name-used-as-function-definition", violations)
        self.assertIn("driver-unaliased-import-count-not-one", violations)

    def test_validator_syntax_failure_is_hard_never_a_skip(self):
        with self.assertRaises(SyntaxError):
            driver_binding_violations("def broken(:\n")


if __name__ == "__main__":
    unittest.main()
