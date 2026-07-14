"""Deterministic tests for the pinned autonomy bootstrap boundary.

These tests never touch the real Task Scheduler, live agentchattr data or any
production process.  Every scenario is built inside a private temporary repo:

* a runnable ``.venv/Scripts/python.exe`` (a copy of the test interpreter, plus
  its ``pyvenv.cfg``) so an end-to-end subprocess run exercises the real
  ``-I -S`` launch and the real ``sys.executable`` binding, and
* copies of the *actual* ``autonomy/__init__.py``, ``autonomy/runner.py``,
  ``autonomy/supervisor_tick.py``, ``autonomy/boot_clock.py`` and
  ``autonomy/runner_bootstrap.py`` under test.  Individual tests may replace
  the trusted supervisor with a tiny manifest-listed fixture.

The sealed ``task-spec.json`` is produced with the scheduler's own canonical
serializer and pin format, so it is byte-faithful to what
``autonomy.scheduler`` emits (a dedicated test proves the equivalence).
"""

from __future__ import annotations

import copy
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import autonomy.runner as runner
import autonomy.runner_bootstrap as boot
import autonomy.scheduler as sched

NONCE = "0123456789abcdef0123456789abcdef"
REAL_PYTHON = Path(sys.executable)
REAL_PYVENV = REAL_PYTHON.parent.parent / "pyvenv.cfg"
REAL_AUTONOMY = Path(boot.__file__).parent
IS_WINDOWS = os.name == "nt"

def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _fs(path) -> str:
    return os.fspath(Path(path))


def _junctions_supported() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        root = Path(os.path.realpath(tempfile.mkdtemp()))
        target = root / "target"
        target.mkdir()
        link = root / "link"
        outcome = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
        )
        ok = outcome.returncode == 0 and link.exists()
        shutil.rmtree(root, ignore_errors=True)
        return ok
    except OSError:
        return False


JUNCTIONS = _junctions_supported()


class Sealed:
    """A fully materialised sealed attempt directory plus its launch argv."""

    def __init__(self, **fields) -> None:
        self.__dict__.update(fields)

    def finalize(self, *, mutate_doc=None, mutate_bytes=None):
        document = copy.deepcopy(self.doc)
        if mutate_doc is not None:
            mutate_doc(document)
        spec_bytes = sched._canonical_json(document)
        if mutate_bytes is not None:
            spec_bytes = mutate_bytes(spec_bytes)
        self.spec_bytes = spec_bytes
        self.spec_sha = hashlib.sha256(spec_bytes).hexdigest()
        Path(self.spec_path).write_bytes(spec_bytes)
        # argv as the bootstrap sees it (Python consumes the -I -S prefix).
        self.argv = list(self.base_args[2:]) + ["--task-spec-sha256", self.spec_sha]
        self.cmd = [_fs(self.python), "-I", "-S"] + self.argv
        return self


class BootstrapFixture(unittest.TestCase):
    def build(
        self,
        *,
        include_supervisor: bool = True,
        include_boot_clock: bool = True,
        boot_clock_package: bool = False,
        boot_clock_package_src: str | None = None,
        supervisor_src: str | None = None,
        extra_files: dict | None = None,
        task_id: str = "night-canary",
        attempt: int = 2,
        profile: str = "claude-work",
        model: str = "fable-5",
        nonce: str = NONCE,
        sid: str | None = None,
        finalize: bool = True,
    ) -> Sealed:
        base = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        repo = base / "repo"
        repo.mkdir()

        scripts = repo / ".venv" / "Scripts"
        scripts.mkdir(parents=True)
        python = scripts / "python.exe"
        shutil.copy2(REAL_PYTHON, python)
        if REAL_PYVENV.exists():
            shutil.copy2(REAL_PYVENV, repo / ".venv" / "pyvenv.cfg")

        autonomy_dir = repo / "autonomy"
        autonomy_dir.mkdir()
        for name in ("__init__.py", "runner.py", "runner_bootstrap.py"):
            shutil.copy2(REAL_AUTONOMY / name, autonomy_dir / name)

        dep_rel = ["autonomy/__init__.py", "autonomy/runner.py"]
        if include_supervisor:
            supervisor_path = autonomy_dir / "supervisor_tick.py"
            if supervisor_src is None:
                shutil.copy2(REAL_AUTONOMY / "supervisor_tick.py", supervisor_path)
            else:
                supervisor_path.write_text(supervisor_src, encoding="utf-8")
            dep_rel.append("autonomy/supervisor_tick.py")
        if include_boot_clock:
            shutil.copy2(
                REAL_AUTONOMY / "boot_clock.py", autonomy_dir / "boot_clock.py"
            )
            dep_rel.append("autonomy/boot_clock.py")
        if boot_clock_package:
            # A pinned package autonomy/boot_clock/__init__.py maps to the same
            # module name as the mandatory exact file autonomy/boot_clock.py.
            package_dir = autonomy_dir / "boot_clock"
            package_dir.mkdir()
            package_src = (
                boot_clock_package_src
                if boot_clock_package_src is not None
                else (REAL_AUTONOMY / "boot_clock.py").read_text(encoding="utf-8")
            )
            (package_dir / "__init__.py").write_text(package_src, encoding="utf-8")
            dep_rel.append("autonomy/boot_clock/__init__.py")
        for relpath, content in (extra_files or {}).items():
            target = repo / relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        root = repo / "data" / "autonomy-v1"
        root.mkdir(parents=True)
        config = root / "runner-config.json"
        config.write_text('{"safe":true}\n', encoding="utf-8")
        attempt_dir = root / "attempts" / task_id / ("a%d" % attempt)
        attempt_dir.mkdir(parents=True)
        manifest = root / "dependencies.json"

        dep_entries = sorted(
            ({"path": rel, "sha256": _sha256(repo / rel)} for rel in dep_rel),
            key=lambda entry: entry["path"].casefold(),
        )
        manifest.write_text(
            json.dumps(
                {"version": 1, "dependencies": dep_entries},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="ascii",
        )

        bootstrap = autonomy_dir / "runner_bootstrap.py"
        spec_path = attempt_dir / "task-spec.json"
        principal = sid if sid is not None else boot._current_user_sid()

        base_args = [
            "-I",
            "-S",
            _fs(bootstrap),
            "--root",
            _fs(root),
            "--task-id",
            task_id,
            "--attempt",
            str(attempt),
            "--nonce",
            nonce,
            "--profile",
            profile,
            "--model",
            model,
            "--config",
            _fs(config),
            "--dependency-manifest",
            _fs(manifest),
            "--task-spec",
            _fs(spec_path),
        ]

        def pin(path) -> dict:
            return sched._PinnedFile.capture_current(Path(path)).mapping()

        dependency_pins = sorted(
            ({"relative_path": rel, **pin(repo / rel)} for rel in dep_rel),
            key=lambda entry: entry["relative_path"].casefold(),
        )

        document = {
            "version": 1,
            "identity": {
                "task_id": task_id,
                "attempt": attempt,
                "nonce": nonce,
                "profile": profile,
                "model": model,
            },
            "paths": {
                "approved_repo_root": _fs(repo),
                "repo": _fs(repo),
                "root": _fs(root),
                "attempt": _fs(attempt_dir),
                "config": _fs(config),
                "bootstrap": _fs(bootstrap),
                "dependency_manifest": _fs(manifest),
                "task_spec": _fs(spec_path),
                "task_xml": _fs(attempt_dir / "runner-task.xml"),
            },
            "pins": {
                "python": pin(python),
                "config": pin(config),
                "bootstrap": pin(bootstrap),
                "dependency_manifest": pin(manifest),
                "dependencies": dependency_pins,
            },
            "launch": {
                "command": _fs(python),
                "arguments_before_task_spec_sha256": list(base_args),
                "task_spec_sha256_argument": "--task-spec-sha256",
                "working_directory": _fs(repo),
            },
            "scheduler_policy": {
                "folder": sched.TASK_FOLDER,
                "principal_user_sid": principal,
                "logon_type": "InteractiveToken",
                "run_level": "LeastPrivilege",
                "settings": dict(sched._SECURITY_SETTINGS),
                "idle_settings": dict(sched._IDLE_SETTINGS),
                "triggers": [{"type": "RegistrationTrigger", "enabled": True}],
            },
        }

        sealed = Sealed(
            base=base,
            repo=repo,
            root=root,
            attempt_dir=attempt_dir,
            config=config,
            manifest=manifest,
            spec_path=spec_path,
            bootstrap=bootstrap,
            python=python,
            dep_rel=dep_rel,
            base_args=base_args,
            doc=document,
        )
        if finalize:
            sealed.finalize()
        return sealed

    # -- in-process helpers -------------------------------------------------- #

    def validate_valid(self, sealed: Sealed, **kwargs):
        plan = boot._validate(
            sealed.argv, executable=_fs(sealed.python), isolated_ok=True, **kwargs
        )
        self.addCleanup(plan.close)
        return plan

    def expect_reject(self, sealed: Sealed, *, argv=None, **kwargs) -> str:
        try:
            plan = boot._validate(
                argv if argv is not None else sealed.argv,
                executable=_fs(sealed.python),
                isolated_ok=True,
                **kwargs,
            )
        except boot._BootstrapError as error:
            return error.code
        plan.close()
        self.fail("expected a fail-closed rejection, got a valid plan")

    # -- subprocess helpers -------------------------------------------------- #

    def run_bootstrap(self, sealed: Sealed, *, cmd=None):
        return subprocess.run(
            cmd if cmd is not None else sealed.cmd,
            cwd=_fs(sealed.repo),
            capture_output=True,
            timeout=120,
        )

    def assert_fail_closed(self, result, *, code=None, codes=None) -> str:
        self.assertEqual(result.returncode, boot._EXIT_FAILCLOSED)
        self.assertEqual(result.stdout, b"")
        stderr = result.stderr
        self.assertTrue(stderr.endswith(b"\n"))
        line = stderr.strip()
        self.assertNotIn(b"\n", line)
        self.assertNotIn(b"Traceback", stderr)
        line.decode("ascii")  # must be pure ASCII
        self.assertLessEqual(len(stderr), 256)
        obj = json.loads(line)
        self.assertEqual(set(obj), {"ok", "error"})
        self.assertIs(obj["ok"], False)
        if code is not None:
            self.assertEqual(obj["error"], code)
        if codes is not None:
            self.assertIn(obj["error"], codes)
        return obj["error"]


# --------------------------------------------------------------------------- #
# End-to-end subprocess behaviour.                                             #
# --------------------------------------------------------------------------- #


@unittest.skipUnless(IS_WINDOWS, "bootstrap boundary targets Windows")
class SubprocessTests(BootstrapFixture):
    def test_valid_sealed_fixture_runs_and_exits_zero(self) -> None:
        sealed = self.build(include_supervisor=True)
        result = self.run_bootstrap(sealed)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_supervisor_exit_code_is_propagated(self) -> None:
        sealed = self.build(
            include_supervisor=True,
            supervisor_src="def run(context):\n    return 7\n",
        )
        result = self.run_bootstrap(sealed)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b"")

    def test_missing_required_supervisor_fails_closed(self) -> None:
        # A runnable production manifest always includes the statically required
        # readiness supervisor.  Omitting it is rejected before trusted code can
        # execute.  This is also the bounded-output check.
        sealed = self.build(include_supervisor=False)
        result = self.run_bootstrap(sealed)
        self.assert_fail_closed(result, code="manifest-missing-supervisor")

    def test_missing_required_boot_clock_fails_closed(self) -> None:
        # The isolated boot-clock producer is a mandatory pinned dependency
        # root; a manifest without it is refused before any trusted runner
        # code executes, even though boot_clock.py exists on disk.
        sealed = self.build(include_boot_clock=False)
        (sealed.repo / "autonomy" / "boot_clock.py").write_text(
            "MAX_NS = (2 ** 63) - 1\n", encoding="utf-8"
        )
        result = self.run_bootstrap(sealed)
        self.assert_fail_closed(result, code="manifest-missing-boot-clock")

    def test_boot_clock_package_substitute_fails_closed_without_execution(self) -> None:
        # A fully self-consistent spec/manifest that pins the package
        # autonomy/boot_clock/__init__.py (same module name, wrong file) must be
        # refused with the established missing-boot-clock code before ANY pinned
        # dependency or trusted runner code executes.  Both sentinel files would
        # be written at module-execution time if that guarantee were broken.
        package_src = (
            "import pathlib\n"
            "pathlib.Path('boot-clock-package-executed.txt').write_text('x')\n"
            "MAX_NS = (2 ** 63) - 1\n"
        )
        supervisor_src = (
            "import pathlib\n"
            "pathlib.Path('supervisor-executed.txt').write_text('x')\n"
            "\n"
            "def run(context):\n"
            "    return 0\n"
        )
        sealed = self.build(
            include_boot_clock=False,
            boot_clock_package=True,
            boot_clock_package_src=package_src,
            supervisor_src=supervisor_src,
        )
        result = self.run_bootstrap(sealed)
        self.assert_fail_closed(result, code="manifest-missing-boot-clock")
        # cwd of the launch is the repo: neither sentinel may exist anywhere.
        self.assertFalse((sealed.repo / "boot-clock-package-executed.txt").exists())
        self.assertFalse((sealed.repo / "supervisor-executed.txt").exists())

    def test_unlisted_autonomy_import_has_no_filesystem_fallback(self) -> None:
        # supervisor_tick imports autonomy.helper, which exists on disk under
        # the repo but is NOT in the manifest.  The private loader must reject
        # it rather than fall back to the filesystem.
        sealed = self.build(
            include_supervisor=True,
            supervisor_src="import autonomy.helper\n\ndef run(context):\n    return 0\n",
            extra_files={"autonomy/helper.py": "VALUE = 1\n"},
        )
        self.assertTrue((sealed.repo / "autonomy" / "helper.py").exists())
        result = self.run_bootstrap(sealed)
        self.assert_fail_closed(result, code="unlisted-autonomy-import")

    def test_interpreter_not_isolated_is_rejected(self) -> None:
        sealed = self.build(include_supervisor=True)
        # Launch with -S only (no -I): isolation is incomplete, so refuse.
        cmd = [_fs(sealed.python), "-S"] + list(sealed.argv)
        result = self.run_bootstrap(sealed, cmd=cmd)
        self.assert_fail_closed(result, code="interpreter-not-isolated")

    def test_task_spec_byte_tamper_between_launch_and_read(self) -> None:
        # Digest is carried in argv; if the file's bytes differ, refuse.
        sealed = self.build(include_supervisor=True)
        Path(sealed.spec_path).write_bytes(sealed.spec_bytes + b" ")
        result = self.run_bootstrap(sealed)
        self.assert_fail_closed(result, code="task-spec-digest-mismatch")


# --------------------------------------------------------------------------- #
# In-process validation (fast, deterministic, no global import mutation).      #
# --------------------------------------------------------------------------- #


@unittest.skipUnless(IS_WINDOWS, "path/handle checks are Windows-specific here")
class ValidationTests(BootstrapFixture):
    def test_valid_fixture_validates(self) -> None:
        sealed = self.build(include_supervisor=True)
        plan = self.validate_valid(sealed)
        self.assertIn("autonomy.runner", plan.finder_modules)
        self.assertIn("autonomy.supervisor_tick", plan.finder_modules)
        self.assertIn("autonomy.boot_clock", plan.finder_modules)

    def test_exact_boot_clock_is_compiled_and_pinned(self) -> None:
        import types as types_module

        sealed = self.build()
        plan = self.validate_valid(sealed)
        code, is_package, origin = plan.finder_modules["autonomy.boot_clock"]
        self.assertIsInstance(code, types_module.CodeType)
        self.assertFalse(is_package)
        self.assertEqual(
            _fs(sealed.repo / "autonomy" / "boot_clock.py"), origin
        )
        pinned = {
            rel: sha for rel, _, sha, _ in plan.context_data["deps"]
        }
        self.assertEqual(
            _sha256(REAL_AUTONOMY / "boot_clock.py"),
            pinned["autonomy/boot_clock.py"],
        )

    def test_missing_boot_clock_manifest_entry_is_rejected(self) -> None:
        sealed = self.build(include_boot_clock=False)
        self.assertEqual(
            self.expect_reject(sealed), "manifest-missing-boot-clock"
        )

    def test_boot_clock_package_substitute_is_rejected(self) -> None:
        # The exact normalized relative file autonomy/boot_clock.py is
        # mandatory; a same-module-name package pin is not a substitute.
        sealed = self.build(include_boot_clock=False, boot_clock_package=True)
        self.assertEqual(
            self.expect_reject(sealed), "manifest-missing-boot-clock"
        )

    def test_boot_clock_file_and_package_together_are_rejected(self) -> None:
        # Pinning both the exact file and the package collides on the module
        # name and must be refused as a duplicate, never silently resolved.
        sealed = self.build(include_boot_clock=True, boot_clock_package=True)
        self.assertEqual(
            self.expect_reject(sealed), "dependency-module-duplicate"
        )

    def test_task_spec_byte_tamper(self) -> None:
        sealed = self.build()
        Path(sealed.spec_path).write_bytes(sealed.spec_bytes + b"\n")
        self.assertEqual(
            self.expect_reject(sealed), "task-spec-digest-mismatch"
        )

    def test_wrong_digest_in_argv(self) -> None:
        sealed = self.build()
        argv = list(sealed.argv)
        argv[-1] = "0" * 64
        self.assertEqual(
            self.expect_reject(sealed, argv=argv), "task-spec-digest-mismatch"
        )

    def test_spec_argv_identity_mismatch(self) -> None:
        sealed = self.build()
        argv = list(sealed.argv)
        argv[argv.index("--profile") + 1] = "claude-test2"
        self.assertIn(
            self.expect_reject(sealed, argv=argv),
            {"argv-spec-identity-mismatch", "launch-arguments-mismatch"},
        )

    def test_duplicate_json_keys(self) -> None:
        sealed = self.build(
            finalize=False,
        )
        sealed.finalize(
            mutate_bytes=lambda b: b.replace(
                b'"version":1}', b'"version":1,"version":1}'
            )
        )
        self.assertEqual(self.expect_reject(sealed), "json-duplicate-key")

    def test_extra_top_level_field(self) -> None:
        sealed = self.build(finalize=False)
        sealed.finalize(mutate_doc=lambda d: d.__setitem__("extra", "x"))
        self.assertEqual(self.expect_reject(sealed), "task-spec-schema")

    def test_nan_constant_is_rejected(self) -> None:
        sealed = self.build(finalize=False)
        # allow_nan defaults to True for a hand-rolled dumps, so inject NaN.
        sealed.finalize(
            mutate_bytes=lambda b: b.replace(b'"version":1', b'"version":NaN')
        )
        self.assertEqual(self.expect_reject(sealed), "json-constant-forbidden")

    def test_python_hash_drift(self) -> None:
        sealed = self.build(finalize=False)
        sealed.finalize(
            mutate_doc=lambda d: d["pins"]["python"].__setitem__("sha256", "0" * 64)
        )
        self.assertEqual(self.expect_reject(sealed), "file-hash-mismatch")

    def test_config_hash_drift(self) -> None:
        sealed = self.build(finalize=False)
        sealed.finalize(
            mutate_doc=lambda d: d["pins"]["config"].__setitem__("sha256", "1" * 64)
        )
        self.assertEqual(self.expect_reject(sealed), "file-hash-mismatch")

    def test_manifest_hash_drift(self) -> None:
        sealed = self.build(finalize=False)
        sealed.finalize(
            mutate_doc=lambda d: d["pins"]["dependency_manifest"].__setitem__(
                "sha256", "2" * 64
            )
        )
        self.assertEqual(self.expect_reject(sealed), "file-hash-mismatch")

    def test_bootstrap_identity_drift(self) -> None:
        sealed = self.build(finalize=False)

        def mutate(document):
            identity = document["pins"]["bootstrap"]["identity"]
            identity["mtime_ns"] = int(identity["mtime_ns"]) + 1

        sealed.finalize(mutate_doc=mutate)
        self.assertEqual(self.expect_reject(sealed), "file-identity-mismatch")

    def test_dependency_identity_drift(self) -> None:
        sealed = self.build(finalize=False)

        def mutate(document):
            identity = document["pins"]["dependencies"][0]["identity"]
            identity["mtime_ns"] = int(identity["mtime_ns"]) + 1

        sealed.finalize(mutate_doc=mutate)
        self.assertEqual(self.expect_reject(sealed), "file-identity-mismatch")

    def test_dependency_hash_drift_on_disk(self) -> None:
        sealed = self.build()
        # Overwrite a pinned dependency after sealing: identity + hash both move.
        (sealed.repo / "autonomy" / "runner.py").write_text(
            "def changed():\n    return 1\n", encoding="utf-8"
        )
        self.assertIn(
            self.expect_reject(sealed),
            {"file-identity-mismatch", "file-hash-mismatch"},
        )

    def test_manifest_dependency_set_mismatch(self) -> None:
        sealed = self.build(finalize=False)
        # Change only the spec pin sha for a dependency: the manifest still
        # lists the true sha, so the two authorities disagree.
        sealed.finalize(
            mutate_doc=lambda d: d["pins"]["dependencies"][0].__setitem__(
                "sha256", "3" * 64
            )
        )
        self.assertEqual(self.expect_reject(sealed), "manifest-spec-mismatch")

    def test_launch_arguments_tamper(self) -> None:
        sealed = self.build(finalize=False)
        sealed.finalize(
            mutate_doc=lambda d: d["launch"].__setitem__(
                "arguments_before_task_spec_sha256",
                d["launch"]["arguments_before_task_spec_sha256"] + ["--rogue"],
            )
        )
        self.assertEqual(self.expect_reject(sealed), "launch-arguments-mismatch")

    def test_scheduler_policy_settings_tamper(self) -> None:
        sealed = self.build(finalize=False)
        sealed.finalize(
            mutate_doc=lambda d: d["scheduler_policy"]["settings"].__setitem__(
                "AllowStartOnDemand", "true"
            )
        )
        self.assertEqual(self.expect_reject(sealed), "policy-settings")

    def test_principal_sid_mismatch(self) -> None:
        sealed = self.build(
            finalize=False,
            sid="S-1-5-21-9999999999-8888888888-7777777777-1002",
        )
        sealed.finalize()
        self.assertEqual(self.expect_reject(sealed), "policy-sid-mismatch")

    def test_manifest_missing_runner_entry(self) -> None:
        # A manifest/spec that omits autonomy/runner.py must be refused.
        sealed = self.build(finalize=False)

        def drop_runner(document):
            document["pins"]["dependencies"] = [
                entry
                for entry in document["pins"]["dependencies"]
                if entry["relative_path"] != "autonomy/runner.py"
            ]

        # Also drop it from the on-disk manifest so the two agree.
        manifest_doc = json.loads(Path(sealed.manifest).read_text("ascii"))
        manifest_doc["dependencies"] = [
            entry
            for entry in manifest_doc["dependencies"]
            if entry["path"] != "autonomy/runner.py"
        ]
        Path(sealed.manifest).write_text(
            json.dumps(
                manifest_doc, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            )
            + "\n",
            encoding="ascii",
        )
        # Re-pin the manifest to its new bytes so only the runner-entry rule fires.
        new_manifest_pin = sched._PinnedFile.capture_current(
            Path(sealed.manifest)
        ).mapping()

        def mutate(document):
            drop_runner(document)
            document["pins"]["dependency_manifest"] = new_manifest_pin

        sealed.finalize(mutate_doc=mutate)
        self.assertEqual(self.expect_reject(sealed), "manifest-missing-runner")


# --------------------------------------------------------------------------- #
# Lexical paths, reparse points, and identity-stable handles.                  #
# --------------------------------------------------------------------------- #


@unittest.skipUnless(IS_WINDOWS, "lexical path grammar is Windows-specific here")
class PathAndHandleTests(BootstrapFixture):
    def test_strict_lexical_rejections(self) -> None:
        cases = {
            r"relative\path": "path-not-drive-absolute",
            r"\\server\share\x": "path-unc-or-device",
            r"\\?\C:\x": "path-unc-or-device",
            "C:/forward/slash": "path-separator-invalid",
            r"C:\a\..\b": "path-dot-segment",
            r"C:\a\\b": "path-empty-component",
            "C:\\a\\b\\": "path-empty-component",
            r"C:\a\nul\b": "path-reserved-name",
            r"C:\a\trail \b": "path-trailing-space-or-dot",
            r"C:": "path-not-absolute",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                try:
                    boot._strict_lexical(raw)
                except boot._BootstrapError as error:
                    self.assertEqual(error.code, expected)
                else:
                    self.fail("expected rejection for %r" % raw)

    @unittest.skipUnless(JUNCTIONS, "directory junction creation not permitted here")
    def test_reparse_component_is_rejected(self) -> None:
        sealed = self.build()
        # Move data/ aside and replace it with a junction: every path under
        # root now traverses a reparse point.
        real_data = sealed.repo / "data"
        moved = sealed.repo / "data_real"
        real_data.rename(moved)
        outcome = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(real_data), str(moved)],
            capture_output=True,
        )
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        self.assertIn(
            self.expect_reject(sealed),
            {"path-reparse-forbidden", "path-resolution-ambiguous"},
        )

    def test_deny_delete_handle_blocks_swap(self) -> None:
        base = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        target = base / "trusted.bin"
        target.write_bytes(b"trusted-bytes")
        attacker = base / "attacker.bin"
        attacker.write_bytes(b"attacker-bytes")

        handle = boot._open_pinned(_fs(target))
        try:
            with self.assertRaises(PermissionError):
                os.replace(attacker, target)
            with self.assertRaises(PermissionError):
                target.write_bytes(b"attacker-bytes")
            data, _ = handle.read_verified(1024)
            self.assertEqual(data, b"trusted-bytes")
        finally:
            handle.close()
        # Once released, a legitimate replace succeeds.
        os.replace(attacker, target)
        self.assertEqual(target.read_bytes(), b"attacker-bytes")

    def test_held_files_block_ancestor_directory_renames(self) -> None:
        # On the Windows-only production path every trusted directory contains
        # at least one file held without FILE_SHARE_DELETE for the whole runner
        # execution.  Windows therefore also denies renaming those ancestors.
        for target_name in ("attempt_dir", "root", "repo"):
            with self.subTest(target=target_name):
                sealed = self.build()
                plan = boot._validate(
                    sealed.argv,
                    executable=_fs(sealed.python),
                    isolated_ok=True,
                )
                target = Path(getattr(sealed, target_name))
                moved = target.with_name(target.name + ".moved")
                try:
                    with self.assertRaises(PermissionError) as captured:
                        target.rename(moved)
                    self.assertEqual(captured.exception.winerror, 5)
                    self.assertTrue(target.is_dir())
                    self.assertFalse(moved.exists())
                finally:
                    plan.close()

    def test_final_path_mismatch_via_symlink_is_rejected(self) -> None:
        # A pinned open through a symlink must fail: the OS-reported final path
        # differs from the lexically-validated path.
        base = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        real = base / "real.bin"
        real.write_bytes(b"real")
        link = base / "link.bin"
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("symlink creation not permitted here")
        with self.assertRaises(boot._BootstrapError) as captured:
            boot._resolve_existing(_fs(link), "file")
        self.assertIn(
            captured.exception.code,
            {"path-reparse-forbidden", "path-resolution-ambiguous"},
        )

    def test_sanitize_sys_path_removes_repo_and_cwd(self) -> None:
        sealed = self.build()
        repo = _fs(sealed.repo)
        stdlib = os.path.dirname(os.__file__)
        saved = list(sys.path)
        try:
            sys.path[:] = [
                repo,
                os.path.join(repo, "autonomy"),
                _fs(sealed.root),
                "",
                stdlib,
            ]
            boot._sanitize_sys_path(repo, _fs(sealed.root))
            repo_real = os.path.normcase(os.path.realpath(repo))
            for entry in sys.path:
                self.assertNotEqual(entry, "")
                self.assertFalse(
                    os.path.normcase(os.path.realpath(entry)).startswith(repo_real)
                )
            self.assertIn(stdlib, sys.path)
        finally:
            sys.path[:] = saved


# --------------------------------------------------------------------------- #
# Runner contract + faithfulness to the scheduler.                             #
# --------------------------------------------------------------------------- #


class RunnerContractTests(BootstrapFixture):
    def test_direct_runner_invocation_fails_closed(self) -> None:
        self.assertFalse(hasattr(runner, "arm_bootstrap"))
        self.assertFalse(hasattr(runner, "BootstrapContext"))
        self.assertFalse(hasattr(runner, "main_from_bootstrap"))
        self.assertIsNone(runner._BOOTSTRAP_HANDOFF)
        with self.assertRaises(runner.RunnerError) as none_ctx:
            runner._main_from_bootstrap(None)
        self.assertEqual(none_ctx.exception.code, "runner-not-armed")
        # A direct import remains unarmed; there is no public mutation API.
        self.assertIsNone(runner._BOOTSTRAP_HANDOFF)

    def test_loader_injected_handoff_is_one_shot(self) -> None:
        origin = Path(runner.__file__)
        code = compile(origin.read_text(encoding="utf-8"), _fs(origin), "exec")
        handoff = object()
        loader = boot._PinnedLoader(code, _fs(origin), False, handoff)
        name = "autonomy._runner_handoff_fixture"
        spec = importlib.machinery.ModuleSpec(name, loader, origin=_fs(origin))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            loader.exec_module(module)
            context = module._BootstrapContext(_handoff=handoff)
            self.assertEqual(module._main_from_bootstrap(context), 0)
            with self.assertRaises(module.RunnerError) as replay:
                module._main_from_bootstrap(context)
            self.assertEqual(replay.exception.code, "runner-already-consumed")
        finally:
            sys.modules.pop(name, None)

    def test_runner_survives_scheduler_import_scanner(self) -> None:
        # Proves autonomy/runner.py is free of dynamic-import/capability
        # constructs and is reachable from a {__init__, runner} manifest, i.e.
        # the scheduler would accept it as a pinned dependency.
        sealed = self.build()
        paths = sched.RunnerPaths.validate(
            approved_repo_root=_fs(sealed.repo),
            python=_fs(sealed.python),
            repo=_fs(sealed.repo),
            root=_fs(sealed.root),
            config=_fs(sealed.config),
            dependency_manifest=_fs(sealed.manifest),
            python_sha256=_sha256(sealed.python),
            config_sha256=_sha256(sealed.config),
            bootstrap_sha256=_sha256(sealed.bootstrap),
            dependency_manifest_sha256=_sha256(sealed.manifest),
        )
        self.assertIsInstance(paths, sched.RunnerPaths)

    def test_builder_is_byte_faithful_to_scheduler_spec(self) -> None:
        # The hand-built task-spec used by these tests must be byte-identical to
        # what autonomy.scheduler emits for the same {__init__, runner} attempt.
        sealed = self.build()
        identity = sched.TaskIdentity(
            "night-canary", 2, NONCE, "claude-work", "fable-5"
        )
        paths = sched.RunnerPaths.validate(
            approved_repo_root=_fs(sealed.repo),
            python=_fs(sealed.python),
            repo=_fs(sealed.repo),
            root=_fs(sealed.root),
            config=_fs(sealed.config),
            dependency_manifest=_fs(sealed.manifest),
            python_sha256=_sha256(sealed.python),
            config_sha256=_sha256(sealed.config),
            bootstrap_sha256=_sha256(sealed.bootstrap),
            dependency_manifest_sha256=_sha256(sealed.manifest),
        )
        expected = sched._expected_task(identity, paths)
        self.assertEqual(sched._canonical_json(sealed.doc), expected.spec_bytes)
        # And the scheduler's argv equals the bootstrap's expected launch argv.
        self.assertEqual(
            list(expected.arguments),
            list(sealed.base_args) + ["--task-spec-sha256", expected.spec_sha256],
        )

    @unittest.skipUnless(IS_WINDOWS, "bootstrap boundary targets Windows")
    def test_scheduler_produced_spec_executes_readiness_tick(self) -> None:
        # Unlike the earlier hand-built happy path, this publishes the exact
        # scheduler-produced authority files and launches its exact argv.
        sealed = self.build(finalize=False)
        identity = sched.TaskIdentity(
            "night-canary", 2, NONCE, "claude-work", "fable-5"
        )
        paths = sched.RunnerPaths.validate(
            approved_repo_root=_fs(sealed.repo),
            python=_fs(sealed.python),
            repo=_fs(sealed.repo),
            root=_fs(sealed.root),
            config=_fs(sealed.config),
            dependency_manifest=_fs(sealed.manifest),
            python_sha256=_sha256(sealed.python),
            config_sha256=_sha256(sealed.config),
            bootstrap_sha256=_sha256(sealed.bootstrap),
            dependency_manifest_sha256=_sha256(sealed.manifest),
        )
        expected = sched._expected_task(identity, paths)
        sched._publish_task(expected, paths)

        result = subprocess.run(
            [_fs(sealed.python), *expected.arguments],
            cwd=_fs(sealed.repo),
            capture_output=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()
