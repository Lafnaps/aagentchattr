from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

import autonomy.scheduler as scheduler_module
from autonomy.scheduler import (
    SPEC_PREFIX_HEX,
    TASK_FOLDER,
    PathValidationError,
    RunnerPaths,
    SchedulerError,
    TaskIdentity,
    TaskObservation,
    TaskPresence,
    TaskProbe,
    TaskProbeStatus,
    TaskSchedulerAdapter,
    _encode_bstr_task_xml,
    _lock_xml_readonly,
    _semantic_projection,
    _xml_fingerprint,
    build_runner_arguments,
    build_task_name,
    build_task_xml,
)


NONCE = "0123456789abcdef0123456789abcdef"
TEST_SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
ATTACKER_SID = "S-1-5-21-9999999999-8888888888-7777777777-1002"
NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_manifest(path: Path, dependencies: list[dict[str, str]]) -> None:
    path.write_text(
        json.dumps(
            {"version": 1, "dependencies": dependencies},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )


class TrackingTestLocker:
    """Portable model of the production deny-write/delete XML handle."""

    def __init__(self) -> None:
        self.active = False
        self.path: Path | None = None

    @contextlib.contextmanager
    def __call__(self, path: Path):
        if self.active:
            raise AssertionError("nested XML lock")
        with path.open("rb") as stream:
            self.active = True
            self.path = path
            try:
                yield stream
            finally:
                self.path = None
                self.active = False

    def replace(self, source: Path, destination: Path) -> None:
        if self.active and destination == self.path:
            raise PermissionError("test model: destination is share-locked")
        os.replace(source, destination)


class SchedulerFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.sid_patch = mock.patch(
            "autonomy.scheduler._current_user_sid", return_value=TEST_SID
        )
        self.sid_patch.start()
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.repo = base / "repo & source"
        self.root = self.repo / "data" / "autonomy-v1"
        self.attempt = self.root / "attempts" / "night-canary" / "a2"
        self.attempt.mkdir(parents=True)

        self.python = self.repo / ".venv" / "Scripts" / "python.exe"
        self.python.parent.mkdir(parents=True)
        self.python.write_bytes(b"pinned-python")

        autonomy = self.repo / "autonomy"
        autonomy.mkdir()
        self.package_init = autonomy / "__init__.py"
        self.package_init.write_text("# closed package\n", encoding="utf-8")
        self.bootstrap = autonomy / "runner_bootstrap.py"
        self.bootstrap.write_text("# pinned bootstrap\n", encoding="utf-8")
        self.runner = autonomy / "runner.py"
        self.runner.write_text(
            "import autonomy.supervisor_tick\n\ndef main():\n    return 0\n",
            encoding="utf-8",
        )
        self.supervisor = autonomy / "supervisor_tick.py"
        self.supervisor.write_text(
            "def run(context):\n    return 0\n", encoding="utf-8"
        )

        self.config = self.root / "runner-config.json"
        self.config.write_text('{"safe":true}\n', encoding="utf-8")
        self.manifest = self.root / "dependencies.json"
        self.write_manifest_for(self.package_init, self.runner)

        self.schtasks = base / "Windows" / "System32" / "schtasks.exe"
        self.schtasks.parent.mkdir(parents=True)
        self.schtasks.write_bytes(b"pinned-schtasks")
        self.identity = TaskIdentity(
            "night-canary", 2, NONCE, "claude-work", "fable-5"
        )
        self.locker = TrackingTestLocker()
        self.paths = self.make_paths()

    def tearDown(self) -> None:
        self.sid_patch.stop()
        self.temp.cleanup()

    def relative(self, path: Path) -> str:
        return path.relative_to(self.repo).as_posix()

    def write_manifest_for(self, *paths: Path) -> None:
        selected = list(paths)
        if self.supervisor not in selected:
            selected.append(self.supervisor)
        write_manifest(
            self.manifest,
            [
                {"path": self.relative(path), "sha256": sha256(path)}
                for path in selected
            ],
        )

    def make_paths(self, **changes: object) -> RunnerPaths:
        values: dict[str, object] = {
            "approved_repo_root": self.repo,
            "python": self.python,
            "repo": self.repo,
            "root": self.root,
            "config": self.config,
            "dependency_manifest": self.manifest,
        }
        values.update(changes)
        values.setdefault("python_sha256", sha256(self.python))
        values.setdefault("config_sha256", sha256(self.config))
        values.setdefault("bootstrap_sha256", sha256(self.bootstrap))
        values.setdefault("dependency_manifest_sha256", sha256(self.manifest))
        return RunnerPaths.validate(**values)  # type: ignore[arg-type]

    def adapter(
        self, *, locker: TrackingTestLocker | None = None
    ) -> TaskSchedulerAdapter:
        return TaskSchedulerAdapter(
            test_only_schtasks_path=self.schtasks,
            test_only_schtasks_sha256=sha256(self.schtasks),
            test_only_xml_locker=locker or self.locker,
        )

    @staticmethod
    def completed(
        returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], returncode, stdout, stderr)

    def register(self, adapter: TaskSchedulerAdapter | None = None) -> str:
        with mock.patch(
            "autonomy.scheduler.subprocess.run", return_value=self.completed()
        ):
            return (adapter or self.adapter()).register(self.identity, self.paths)


class IdentityAndXmlTests(SchedulerFixture):
    def test_task_name_includes_nonce_and_full_spec_digest(self) -> None:
        name = self.register()
        digest = sha256(self.attempt / "task-spec.json")
        self.assertEqual(64, SPEC_PREFIX_HEX)
        self.assertEqual(
            build_task_name("night-canary", 2, NONCE, digest), name
        )
        self.assertTrue(name.endswith(digest))
        self.assertIn(NONCE, name)
        self.assertTrue(name.startswith(rf"{TASK_FOLDER}\night-canary-a2-"))

    def test_bootstrap_argv_binds_exact_task_spec_hash(self) -> None:
        name = self.register()
        argv = build_runner_arguments(self.identity, self.paths)
        digest = sha256(self.attempt / "task-spec.json")
        self.assertEqual(("-I", "-S", os.fspath(self.bootstrap)), argv[:3])
        self.assertNotIn("-m", argv)
        for value in (
            "--profile",
            "claude-work",
            "--model",
            "fable-5",
            "--dependency-manifest",
            os.fspath(self.manifest),
            "--task-spec",
            os.fspath(self.attempt / "task-spec.json"),
        ):
            self.assertIn(value, argv)
        index = argv.index("--task-spec-sha256")
        self.assertEqual(digest, argv[index + 1])
        self.assertTrue(name.endswith(argv[index + 1]))

    def test_xml_has_exact_registration_trigger_principal_and_exec(self) -> None:
        root = ET.fromstring(build_task_xml(self.identity, self.paths))
        triggers = root.findall("t:Triggers/t:RegistrationTrigger", NS)
        self.assertEqual(1, len(triggers))
        self.assertEqual(
            ["{http://schemas.microsoft.com/windows/2004/02/mit/task}Enabled"],
            [child.tag for child in triggers[0]],
        )
        self.assertEqual("true", triggers[0].findtext("t:Enabled", namespaces=NS))
        principal = root.find("t:Principals/t:Principal", NS)
        assert principal is not None
        self.assertEqual(
            ["UserId", "LogonType", "RunLevel"],
            [child.tag.rsplit("}", 1)[-1] for child in principal],
        )
        self.assertEqual(TEST_SID, principal.findtext("t:UserId", namespaces=NS))
        self.assertEqual(
            "InteractiveToken", principal.findtext("t:LogonType", namespaces=NS)
        )
        self.assertEqual(
            "LeastPrivilege", principal.findtext("t:RunLevel", namespaces=NS)
        )
        self.assertEqual(
            "false", root.findtext("t:Settings/t:AllowStartOnDemand", namespaces=NS)
        )
        self.assertEqual(1, len(root.findall("t:Actions/t:Exec", NS)))
        self.assertEqual(
            os.fspath(self.python),
            root.findtext("t:Actions/t:Exec/t:Command", namespaces=NS),
        )
        self.assertEqual(
            os.fspath(self.repo),
            root.findtext("t:Actions/t:Exec/t:WorkingDirectory", namespaces=NS),
        )

    def test_user_id_is_fingerprinted_and_no_principal_child_is_ignored(self) -> None:
        original = build_task_xml(self.identity, self.paths).encode("utf-8")
        substituted = original.replace(TEST_SID.encode(), ATTACKER_SID.encode())
        self.assertNotEqual(
            _xml_fingerprint(original), _xml_fingerprint(substituted)
        )
        unexpected = original.replace(
            b"<LogonType>", b"<DisplayName>ignored-before</DisplayName><LogonType>"
        )
        with self.assertRaises(SchedulerError):
            _xml_fingerprint(unexpected)

        builder = scheduler_module._task_xml

        def wrong_user(**kwargs: object) -> str:
            return builder(**kwargs).replace(TEST_SID, ATTACKER_SID)  # type: ignore[arg-type]

        with mock.patch("autonomy.scheduler._task_xml", side_effect=wrong_user):
            with self.assertRaises(SchedulerError) as captured:
                build_task_xml(self.identity, self.paths)
        self.assertEqual("task-xml-invalid", captured.exception.code)

    def test_identity_profile_model_are_strict(self) -> None:
        bad = [
            ("../x", 1, NONCE, "claude-work", "fable-5"),
            ("ok", 3, NONCE, "claude-work", "fable-5"),
            ("ok", 1, NONCE.upper(), "claude-work", "fable-5"),
            ("ok", 1, NONCE, "Bad Profile", "fable-5"),
            ("ok", 1, NONCE, "claude-work", "fable..5"),
        ]
        for values in bad:
            with self.subTest(values=values), self.assertRaises(SchedulerError):
                TaskIdentity(*values)


class AtomicRegistrationTests(SchedulerFixture):
    def test_create_is_the_only_launch_command_and_lock_spans_subprocess(self) -> None:
        adapter = self.adapter()

        def launched(command: list[str], **kwargs: object):
            self.assertTrue(self.locker.active)
            self.assertIs(kwargs["shell"], False)
            return self.completed()

        with mock.patch(
            "autonomy.scheduler.subprocess.run", side_effect=launched
        ) as run:
            name = adapter.register(self.identity, self.paths)
        self.assertEqual(1, run.call_count)
        self.assertEqual(
            [
                os.fspath(self.schtasks),
                "/Create",
                "/TN",
                name,
                "/XML",
                os.fspath(self.attempt / "runner-task.xml"),
            ],
            run.call_args.args[0],
        )
        self.assertNotIn("/F", run.call_args.args[0])
        self.assertNotIn("/Run", run.call_args.args[0])
        self.assertNotIn("/Query", run.call_args.args[0])
        self.assertFalse(hasattr(adapter, "run"))

    def test_duplicate_registration_is_create_only_and_never_overwrites(self) -> None:
        name = self.register()
        spec_before = (self.attempt / "task-spec.json").read_bytes()
        xml_before = (self.attempt / "runner-task.xml").read_bytes()
        with mock.patch(
            "autonomy.scheduler.subprocess.run", return_value=self.completed(1)
        ) as run:
            with self.assertRaises(SchedulerError) as captured:
                self.adapter().register(self.identity, self.paths)
        self.assertEqual("schtasks-create-nonzero", captured.exception.code)
        self.assertEqual("/Create", run.call_args.args[0][1])
        self.assertNotIn("/F", run.call_args.args[0])
        self.assertIn(name, run.call_args.args[0])
        self.assertEqual(spec_before, (self.attempt / "task-spec.json").read_bytes())
        self.assertEqual(xml_before, (self.attempt / "runner-task.xml").read_bytes())

    def test_xml_swap_at_subprocess_boundary_is_denied_by_lock(self) -> None:
        original: bytes | None = None

        def launched(_command: list[str], **_kwargs: object):
            nonlocal original
            xml = self.attempt / "runner-task.xml"
            original = xml.read_bytes()
            attacker = self.attempt / "attacker.xml"
            attacker.write_bytes(original.replace(b"<Hidden>true", b"<Hidden>false"))
            with self.assertRaises(PermissionError):
                self.locker.replace(attacker, xml)
            return self.completed()

        with mock.patch(
            "autonomy.scheduler.subprocess.run", side_effect=launched
        ):
            self.adapter().register(self.identity, self.paths)
        self.assertIsNotNone(original)
        self.assertEqual(original, (self.attempt / "runner-task.xml").read_bytes())

    @unittest.skipUnless(os.name == "nt", "native share-mode check is Windows-only")
    def test_native_xml_lock_denies_replace(self) -> None:
        xml = self.attempt / "native.xml"
        replacement = self.attempt / "replacement.xml"
        xml.write_bytes(b"trusted")
        replacement.write_bytes(b"attacker")
        with _lock_xml_readonly(xml):
            with self.assertRaises(PermissionError):
                xml.write_bytes(b"attacker")
            with self.assertRaises(PermissionError):
                os.replace(replacement, xml)
        os.replace(replacement, xml)

    def test_swap_before_locked_identity_check_blocks_create(self) -> None:
        class SwappingLocker:
            @contextlib.contextmanager
            def __call__(_self, path: Path):
                path.write_bytes(b"attacker")
                with path.open("rb") as stream:
                    yield stream

        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            with self.assertRaises(PathValidationError) as captured:
                self.adapter(locker=SwappingLocker()).register(  # type: ignore[arg-type]
                    self.identity, self.paths
                )
        run.assert_not_called()
        self.assertIn(
            captured.exception.code,
            {"file-identity-mismatch", "file-hash-mismatch"},
        )

    def test_task_spec_tamper_is_bound_to_pre_tamper_digest(self) -> None:
        observed_digest: str | None = None

        def launched(_command: list[str], **_kwargs: object):
            nonlocal observed_digest
            spec = self.attempt / "task-spec.json"
            xml = ET.fromstring((self.attempt / "runner-task.xml").read_bytes())
            arguments = xml.findtext("t:Actions/t:Exec/t:Arguments", namespaces=NS)
            assert arguments is not None
            expected = sha256(spec)
            self.assertIn(f"--task-spec-sha256 {expected}", arguments)
            observed_digest = expected
            spec.write_bytes(b"tampered-after-preflight")
            self.assertNotEqual(expected, sha256(spec))
            return self.completed()

        with mock.patch(
            "autonomy.scheduler.subprocess.run", side_effect=launched
        ):
            name = self.adapter().register(self.identity, self.paths)
        self.assertIsNotNone(observed_digest)
        self.assertTrue(name.endswith(observed_digest or ""))

    def test_task_spec_tamper_before_create_is_revalidated(self) -> None:
        fixture = self

        class SpecTamperingLocker:
            @contextlib.contextmanager
            def __call__(_self, path: Path):
                with path.open("rb") as stream:
                    fixture.attempt.joinpath("task-spec.json").write_bytes(b"tampered")
                    yield stream

        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            with self.assertRaises(PathValidationError):
                self.adapter(locker=SpecTamperingLocker()).register(  # type: ignore[arg-type]
                    self.identity, self.paths
                )
        run.assert_not_called()


class DurableAuthorityTests(SchedulerFixture):
    def test_conflicting_or_preexisting_spec_is_rejected_before_create(self) -> None:
        self.register()
        conflicting = TaskIdentity(
            "night-canary", 2, NONCE, "claude-test2", "fable-5"
        )
        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            with self.assertRaises(SchedulerError) as captured:
                self.adapter().register(conflicting, self.paths)
        run.assert_not_called()
        self.assertEqual("durable-spec-conflict", captured.exception.code)

        (self.attempt / "task-spec.json").write_bytes(b"attacker\n")
        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            with self.assertRaises(SchedulerError) as captured:
                self.adapter().register(self.identity, self.paths)
        run.assert_not_called()
        self.assertEqual("durable-spec-conflict", captured.exception.code)

    def test_spec_binds_principal_identity_paths_and_all_file_pins(self) -> None:
        self.register()
        document = json.loads((self.attempt / "task-spec.json").read_text("ascii"))
        self.assertEqual("claude-work", document["identity"]["profile"])
        self.assertEqual("fable-5", document["identity"]["model"])
        self.assertEqual(TEST_SID, document["scheduler_policy"]["principal_user_sid"])
        self.assertEqual(
            [{"enabled": True, "type": "RegistrationTrigger"}],
            document["scheduler_policy"]["triggers"],
        )
        self.assertEqual(os.fspath(self.bootstrap), document["paths"]["bootstrap"])
        for key, path in (
            ("python", self.python),
            ("config", self.config),
            ("bootstrap", self.bootstrap),
            ("dependency_manifest", self.manifest),
        ):
            self.assertEqual(sha256(path), document["pins"][key]["sha256"])
            self.assertEqual(
                {"device", "inode", "size", "mtime_ns"},
                set(document["pins"][key]["identity"]),
            )
        dependencies = {
            item["relative_path"]: item for item in document["pins"]["dependencies"]
        }
        self.assertEqual(
            {
                "autonomy/__init__.py",
                "autonomy/runner.py",
                "autonomy/supervisor_tick.py",
            },
            set(dependencies),
        )
        self.assertEqual(sha256(self.runner), dependencies["autonomy/runner.py"]["sha256"])

    def test_dependency_drift_fails_before_create(self) -> None:
        paths = self.make_paths()
        self.runner.write_text("def changed(): pass\n", encoding="utf-8")
        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            with self.assertRaises(PathValidationError):
                self.adapter().register(self.identity, paths)
        run.assert_not_called()


class DependencyManifestTests(SchedulerFixture):
    def test_empty_and_missing_required_entries_are_rejected(self) -> None:
        write_manifest(self.manifest, [])
        with self.assertRaises(PathValidationError):
            self.make_paths()

        self.write_manifest_for(self.runner)
        with self.assertRaises(PathValidationError) as captured:
            self.make_paths()
        self.assertEqual("manifest-required-entry-missing", captured.exception.code)

    def test_missing_direct_autonomy_import_is_rejected(self) -> None:
        self.runner.write_text("import autonomy.helper\n", encoding="utf-8")
        self.write_manifest_for(self.package_init, self.runner)
        with self.assertRaises(PathValidationError) as captured:
            self.make_paths()
        self.assertEqual("manifest-import-missing", captured.exception.code)

    def test_missing_transitive_autonomy_import_is_rejected(self) -> None:
        helper = self.runner.parent / "helper.py"
        self.runner.write_text("import autonomy.helper\n", encoding="utf-8")
        helper.write_text("import autonomy.leaf\n", encoding="utf-8")
        self.write_manifest_for(self.package_init, self.runner, helper)
        with self.assertRaises(PathValidationError) as captured:
            self.make_paths()
        self.assertEqual("manifest-import-missing", captured.exception.code)

    def test_dynamic_and_relative_imports_are_rejected(self) -> None:
        cases = (
            (
                "import importlib\nimportlib.import_module('autonomy.helper')\n",
                "manifest-dynamic-import-forbidden",
            ),
            (
                "def load():\n    return dynamic('autonomy.helper')\n"
                "from importlib import import_module as dynamic\n",
                "manifest-dynamic-import-forbidden",
            ),
            ("from . import helper\n", "manifest-relative-import-forbidden"),
        )
        for source, code in cases:
            with self.subTest(code=code):
                self.runner.write_text(source, encoding="utf-8")
                self.write_manifest_for(self.package_init, self.runner)
                with self.assertRaises(PathValidationError) as captured:
                    self.make_paths()
                self.assertEqual(code, captured.exception.code)

    def test_dynamic_alias_and_subscript_bypasses_are_rejected(self) -> None:
        cases = {
            "builtin-alias": (
                "load = __import__\nload('autonomy.helper')\n"
            ),
            "getattr-importlib": (
                "import importlib\n"
                "load = getattr(importlib, 'import_module')\n"
                "load('autonomy.helper')\n"
            ),
            "builtins-subscript": (
                "__builtins__['__import__']('autonomy.helper')\n"
            ),
            "builtins-import-alias": (
                "from builtins import __import__ as load\n"
                "load('autonomy.helper')\n"
            ),
            "builtins-dict": (
                "import builtins as safe\n"
                "load = safe.__dict__['__import__']\n"
                "load('autonomy.helper')\n"
            ),
            "importlib-from-alias": (
                "from importlib import import_module as load\n"
                "load('autonomy.helper')\n"
            ),
            "importlib-attribute-alias": (
                "import importlib as support\n"
                "load = support.import_module\n"
                "load('autonomy.helper')\n"
            ),
            "sys-modules-alias": (
                "import sys as system\n"
                "load = system.modules['importlib'].import_module\n"
                "load('autonomy.helper')\n"
            ),
            "arbitrary-registry-subscript": (
                "registry = {}\n"
                "registry['import_module']('autonomy.helper')\n"
            ),
        }
        for case, source in cases.items():
            with self.subTest(case=case):
                self.runner.write_text(source, encoding="utf-8")
                self.write_manifest_for(self.package_init, self.runner)
                with self.assertRaises(PathValidationError) as captured:
                    self.make_paths()
                self.assertEqual(
                    "manifest-dynamic-import-forbidden", captured.exception.code
                )

    def test_eval_style_capabilities_and_aliases_are_rejected(self) -> None:
        cases = {
            "eval": "run = eval\nrun(\"'safe'\")\n",
            "exec": "run = exec\nrun('pass')\n",
            "compile": "build = compile\nbuild('pass', '<x>', 'exec')\n",
            "globals": "namespace = globals\nnamespace()['__builtins__']\n",
            "locals": "namespace = locals\nnamespace()\n",
            "getattr-alias": "lookup = getattr\nlookup(object(), 'value')\n",
            "vars-alias": "namespace = vars\nnamespace()\n",
        }
        for case, source in cases.items():
            with self.subTest(case=case):
                self.runner.write_text(source, encoding="utf-8")
                self.write_manifest_for(self.package_init, self.runner)
                with self.assertRaises(PathValidationError) as captured:
                    self.make_paths()
                self.assertEqual(
                    "manifest-dynamic-import-forbidden", captured.exception.code
                )

    def test_dynamic_loader_module_drift_is_rejected(self) -> None:
        for module in ("builtins", "importlib", "pkgutil", "runpy", "zipimport"):
            with self.subTest(module=module):
                self.runner.write_text(f"import {module} as support\n", encoding="utf-8")
                self.write_manifest_for(self.package_init, self.runner)
                with self.assertRaises(PathValidationError) as captured:
                    self.make_paths()
                self.assertEqual(
                    "manifest-dynamic-import-forbidden", captured.exception.code
                )

    def test_unreachable_or_arbitrary_manifest_entry_is_rejected(self) -> None:
        helper = self.runner.parent / "helper.py"
        helper.write_text("VALUE = 1\n", encoding="utf-8")
        self.write_manifest_for(self.package_init, self.runner, helper)
        with self.assertRaises(PathValidationError) as captured:
            self.make_paths()
        self.assertEqual("manifest-entry-not-required", captured.exception.code)

        arbitrary = self.runner.parent / "payload.txt"
        arbitrary.write_text("payload\n", encoding="utf-8")
        self.write_manifest_for(self.package_init, self.runner, arbitrary)
        with self.assertRaises(PathValidationError) as captured:
            self.make_paths()
        self.assertEqual("manifest-entry-not-python-module", captured.exception.code)

    def test_valid_recursive_closure_is_accepted(self) -> None:
        helper = self.runner.parent / "helper.py"
        self.runner.write_text("import autonomy.helper\n", encoding="utf-8")
        helper.write_text("from autonomy.runner import main\n", encoding="utf-8")
        self.write_manifest_for(self.package_init, self.runner, helper)
        paths = self.make_paths()
        self.assertIsInstance(paths, RunnerPaths)

    def test_traversal_duplicate_and_duplicate_json_key_are_rejected(self) -> None:
        cases = [
            [{"path": "../escape.py", "sha256": "0" * 64}],
            [
                {"path": "autonomy/runner.py", "sha256": sha256(self.runner)},
                {"path": "AUTONOMY/RUNNER.PY", "sha256": sha256(self.runner)},
            ],
            [{"path": r"autonomy\runner.py", "sha256": sha256(self.runner)}],
        ]
        for entries in cases:
            with self.subTest(entries=entries):
                write_manifest(self.manifest, entries)
                with self.assertRaises(PathValidationError):
                    self.make_paths()

        self.manifest.write_text(
            '{"version":1,"version":1,"dependencies":[]}\n', encoding="ascii"
        )
        with self.assertRaises(PathValidationError) as captured:
            self.make_paths()
        self.assertEqual("json-duplicate-key", captured.exception.code)


class TrustAndCommandTests(SchedulerFixture):
    def test_getsystemdirectory_ignores_environment_spoof(self) -> None:
        spoof = Path(self.temp.name) / "attacker-windows"
        spoof.mkdir()
        with mock.patch.dict(os.environ, {"SystemRoot": os.fspath(spoof)}), mock.patch(
            "autonomy.scheduler._get_system_directory", return_value=self.schtasks.parent
        ):
            adapter = TaskSchedulerAdapter()
        self.assertEqual(self.schtasks, adapter.executable)

    def test_test_binary_and_locker_are_explicitly_test_only(self) -> None:
        with self.assertRaises(SchedulerError):
            TaskSchedulerAdapter(test_only_schtasks_path=self.schtasks)
        with self.assertRaises(PathValidationError):
            TaskSchedulerAdapter(
                test_only_schtasks_path=self.schtasks,
                test_only_schtasks_sha256="0" * 64,
            )
        with self.assertRaises(SchedulerError):
            TaskSchedulerAdapter(test_only_xml_locker=self.locker)

    def test_non_windows_default_xml_locker_fails_closed(self) -> None:
        xml = self.attempt / "probe.xml"
        xml.write_bytes(b"probe")
        with mock.patch("autonomy.scheduler.os.name", "posix"):
            with self.assertRaises(SchedulerError) as captured:
                with _lock_xml_readonly(xml):
                    pass
        self.assertEqual("xml-lock-unsupported-platform", captured.exception.code)

    def test_nonzero_create_and_delete_are_fail_closed(self) -> None:
        with mock.patch(
            "autonomy.scheduler.subprocess.run", return_value=self.completed(1)
        ):
            with self.assertRaises(SchedulerError) as captured:
                self.adapter().register(self.identity, self.paths)
        self.assertEqual("schtasks-create-nonzero", captured.exception.code)

        name = build_task_name("night-canary", 2, NONCE, "0" * 64)
        with mock.patch(
            "autonomy.scheduler.subprocess.run", return_value=self.completed(1)
        ):
            with self.assertRaises(SchedulerError) as captured:
                self.adapter().delete(name)
        self.assertEqual("schtasks-delete-nonzero", captured.exception.code)

    def test_query_has_no_false_absence_state(self) -> None:
        adapter = self.adapter()
        name = build_task_name("night-canary", 2, NONCE, "0" * 64)
        with mock.patch(
            "autonomy.scheduler.subprocess.run", return_value=self.completed()
        ):
            self.assertIs(adapter.query(name), TaskPresence.PRESENT)
        with mock.patch(
            "autonomy.scheduler.subprocess.run", return_value=self.completed(1)
        ):
            self.assertIs(adapter.query(name), TaskPresence.UNKNOWN)

    def test_timeout_and_spawn_errors_are_stable_and_secret_free(self) -> None:
        adapter = self.adapter()
        name = build_task_name("night-canary", 2, NONCE, "0" * 64)
        for failure, code in (
            (
                subprocess.TimeoutExpired(
                    ["SECRET"], 1, output=b"SECRET", stderr=b"SECRET"
                ),
                "schtasks-timeout",
            ),
            (OSError("SECRET"), "schtasks-exec-failed"),
        ):
            with self.subTest(code=code), mock.patch(
                "autonomy.scheduler.subprocess.run", side_effect=failure
            ):
                with self.assertRaises(SchedulerError) as captured:
                    adapter.query(name)
                self.assertEqual(code, str(captured.exception))
                self.assertNotIn("SECRET", str(captured.exception))


TASK_NS_URI = NS["t"]


def q(tag: str) -> str:
    return f"{{{TASK_NS_URI}}}{tag}"


def rewrite(xml_bytes: bytes, mutate) -> bytes:
    root = ET.fromstring(xml_bytes)
    mutate(root)
    ET.register_namespace("", TASK_NS_URI)
    return ET.tostring(root, encoding="utf-8")


def service_normalized(xml_bytes: bytes) -> bytes:
    """Model documented store normalization that must stay PRESENT_EXACT."""

    def mutate(root: ET.Element) -> None:
        info = root.find(q("RegistrationInfo"))
        assert info is not None
        ET.SubElement(info, q("Date")).text = "2026-07-13T03:14:15"
        ET.SubElement(info, q("Author")).text = "EMU\\operator"
        trigger = root.find(f"{q('Triggers')}/{q('RegistrationTrigger')}")
        assert trigger is not None
        enabled = trigger.find(q("Enabled"))
        assert enabled is not None
        trigger.remove(enabled)
        principal = root.find(f"{q('Principals')}/{q('Principal')}")
        assert principal is not None
        run_level = principal.find(q("RunLevel"))
        assert run_level is not None
        principal.remove(run_level)
        settings = root.find(q("Settings"))
        assert settings is not None
        settings.find(q("Hidden")).text = "1"
        settings.find(q("DisallowStartIfOnBatteries")).text = "0"
        idle = settings.find(q("IdleSettings"))
        assert idle is not None
        ET.SubElement(idle, q("Duration")).text = "PT10M"
        ET.SubElement(idle, q("WaitTimeout")).text = "PT1H"
        children = list(settings)
        for child in children:
            settings.remove(child)
        for child in reversed(children):
            settings.append(child)

    return rewrite(xml_bytes, mutate)


def prefixed_serialization(xml_bytes: bytes) -> bytes:
    root = ET.fromstring(xml_bytes)
    try:
        ET.register_namespace("task", TASK_NS_URI)
        return ET.tostring(root, encoding="utf-8")
    finally:
        ET.register_namespace("", TASK_NS_URI)


class ScriptedQueryPort:
    """Deterministic hermetic stand-in for the narrow COM query port."""

    def __init__(self, *script: object) -> None:
        self.script = list(script)
        self.calls: list[str] = []

    def __call__(self, task_name: str) -> TaskProbe:
        self.calls.append(task_name)
        if not self.script:
            raise AssertionError("query port script exhausted")
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item  # type: ignore[return-value]


class ExactBoundaryFixture(SchedulerFixture):
    @staticmethod
    def present(xml: bytes | None) -> TaskProbe:
        return TaskProbe(TaskProbeStatus.PRESENT, xml)

    @staticmethod
    def absent() -> TaskProbe:
        return TaskProbe(TaskProbeStatus.ABSENT)

    @staticmethod
    def unknown() -> TaskProbe:
        return TaskProbe(TaskProbeStatus.UNKNOWN)

    def exact_xml(self) -> bytes:
        return build_task_xml(self.identity, self.paths).encode("utf-8")

    def service_bstr_xml(self) -> bytes:
        text = build_task_xml(self.identity, self.paths).replace(
            'encoding="UTF-8"', 'encoding="UTF-16"', 1
        )
        return _encode_bstr_task_xml(text)

    def conflicting_xml(self) -> bytes:
        return rewrite(
            self.exact_xml(),
            lambda root: setattr(
                root.find(f"{q('Principals')}/{q('Principal')}/{q('UserId')}"),
                "text",
                ATTACKER_SID,
            ),
        )

    def expected_name(self) -> str:
        name = ET.fromstring(self.exact_xml()).findtext(
            "t:RegistrationInfo/t:URI", namespaces=NS
        )
        assert name is not None
        return name

    def port_adapter(self, port: object) -> TaskSchedulerAdapter:
        return TaskSchedulerAdapter(
            test_only_schtasks_path=self.schtasks,
            test_only_schtasks_sha256=sha256(self.schtasks),
            test_only_xml_locker=self.locker,
            test_only_query_port=port,  # type: ignore[arg-type]
        )

    def observe(self, *script: object) -> tuple[TaskObservation, ScriptedQueryPort]:
        port = ScriptedQueryPort(*script)
        adapter = self.port_adapter(port)
        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            observation = adapter.observe_exact(self.identity, self.paths)
        run.assert_not_called()
        return observation, port


class SemanticProjectionTests(ExactBoundaryFixture):
    def test_projection_is_deterministic_and_normalization_insensitive(self) -> None:
        exact = self.exact_xml()
        base = _semantic_projection(exact)
        self.assertEqual(base, _semantic_projection(exact))
        self.assertEqual(base, _semantic_projection(service_normalized(exact)))
        self.assertEqual(base, _semantic_projection(prefixed_serialization(exact)))

    def test_projection_refuses_doctype_garbage_and_oversized(self) -> None:
        cases = (
            b"",
            b"\xff\xfe",
            b"<!DOCTYPE Task []><Task/>",
            b"<!ENTITY x 'y'>",
            b"<Task version='1.2'/>",
            b"<x>" + b"a" * (1024 * 1024) + b"</x>",
        )
        for raw in cases:
            with self.subTest(raw=raw[:24]):
                with self.assertRaises(SchedulerError) as captured:
                    _semantic_projection(raw)
                self.assertEqual(
                    "task-xml-unprojectable", captured.exception.code
                )

    def test_decoded_bstr_utf16_declaration_is_reencoded_consistently(self) -> None:
        exact_text = build_task_xml(self.identity, self.paths)
        service_text = exact_text.replace(
            'encoding="UTF-8"', 'encoding="UTF-16"', 1
        )
        self.assertNotEqual(exact_text, service_text)

        raw = _encode_bstr_task_xml(service_text)

        self.assertTrue(raw.startswith(b'<?xml version="1.0" encoding="UTF-8"?>'))
        self.assertEqual(
            _semantic_projection(exact_text.encode("utf-8")),
            _semantic_projection(raw),
        )
        observation, _ = self.observe(self.present(raw))
        self.assertIs(TaskObservation.PRESENT_EXACT, observation)

    def test_bstr_reencoding_does_not_parse_or_erase_forbidden_xml(self) -> None:
        exact_text = build_task_xml(self.identity, self.paths).replace(
            'encoding="UTF-8"', "encoding='UTF-16'", 1
        )
        hostile = exact_text.replace(
            "<Task ", '<!DOCTYPE Task [<!ENTITY x "y">]>\n<Task ', 1
        )

        raw = _encode_bstr_task_xml(hostile)

        self.assertIn(b"<!DOCTYPE", raw)
        self.assertIn(b"<!ENTITY", raw)
        self.assertTrue(raw.startswith(b"<?xml version=\"1.0\" encoding='UTF-8'?>"))
        with self.assertRaises(SchedulerError) as captured:
            _semantic_projection(raw)
        self.assertEqual("task-xml-unprojectable", captured.exception.code)

    def test_bstr_reencoding_rejects_ambiguous_or_unencodable_text(self) -> None:
        for text in (
            '<?xml version="1.0" encoding="UTF-16" encoding="UTF-8"?><Task/>',
            '<?xml version="1.0" encoding="UTF-16"<Task/>',
            "\ud800",
        ):
            with self.subTest(text=repr(text)):
                with self.assertRaises(SchedulerError) as captured:
                    _encode_bstr_task_xml(text)
                self.assertEqual("task-xml-unreadable", captured.exception.code)


class ExactObservationTests(ExactBoundaryFixture):
    def test_exact_definition_is_present_exact_and_name_bound(self) -> None:
        observation, port = self.observe(self.present(self.exact_xml()))
        self.assertIs(TaskObservation.PRESENT_EXACT, observation)
        self.assertEqual([self.expected_name()], port.calls)

    def test_durable_registered_definition_is_present_exact(self) -> None:
        self.register()
        durable_xml = (self.attempt / "runner-task.xml").read_bytes()
        observation, _ = self.observe(self.present(durable_xml))
        self.assertIs(TaskObservation.PRESENT_EXACT, observation)

    def test_scheduler_normalized_definition_is_present_exact(self) -> None:
        for variant in (service_normalized, prefixed_serialization):
            with self.subTest(variant=variant.__name__):
                observation, _ = self.observe(
                    self.present(variant(self.exact_xml()))
                )
                self.assertIs(TaskObservation.PRESENT_EXACT, observation)

    def test_absence_and_unknown_are_distinct_typed_observations(self) -> None:
        observation, _ = self.observe(self.absent())
        self.assertIs(TaskObservation.ABSENT, observation)
        observation, _ = self.observe(self.unknown())
        self.assertIs(TaskObservation.UNKNOWN, observation)

    def test_malformed_localized_or_oversized_definition_is_conflict(self) -> None:
        exact = self.exact_xml()
        cases: dict[str, bytes | None] = {
            "unreadable-definition": None,
            "empty": b"",
            "truncated": exact[: len(exact) // 2],
            "localized-error-text": (
                "ERREUR : la tâche spécifiée est introuvable.".encode("cp1252")
            ),
            "wrong-namespace": b"<Task version='1.2'/>",
            "doctype": b"<!DOCTYPE Task []>" + exact,
            "oversized": b"<x>" + b"a" * (1024 * 1024) + b"</x>",
        }
        for case, raw in cases.items():
            with self.subTest(case=case):
                observation, _ = self.observe(self.present(raw))
                self.assertIs(TaskObservation.PRESENT_CONFLICT, observation)

    def test_semantic_drift_is_conflict_never_exact(self) -> None:
        temp_dir = os.fspath(Path(self.temp.name))

        def set_text(path: str, value: str):
            def mutate(root: ET.Element) -> None:
                node = root.find(path)
                assert node is not None
                node.text = value

            return mutate

        def second_exec(root: ET.Element) -> None:
            actions = root.find(q("Actions"))
            assert actions is not None
            extra = ET.SubElement(actions, q("Exec"))
            ET.SubElement(extra, q("Command")).text = r"C:\Windows\System32\cmd.exe"

        def time_trigger(root: ET.Element) -> None:
            triggers = root.find(q("Triggers"))
            assert triggers is not None
            for child in list(triggers):
                triggers.remove(child)
            trigger = ET.SubElement(triggers, q("TimeTrigger"))
            ET.SubElement(trigger, q("StartBoundary")).text = "2026-07-13T00:00:00"

        def second_trigger(root: ET.Element) -> None:
            triggers = root.find(q("Triggers"))
            assert triggers is not None
            extra = ET.SubElement(triggers, q("RegistrationTrigger"))
            ET.SubElement(extra, q("Enabled")).text = "true"

        def extra_simple_setting(root: ET.Element) -> None:
            settings = root.find(q("Settings"))
            assert settings is not None
            ET.SubElement(settings, q("UseUnifiedSchedulingEngine")).text = "true"

        def extra_complex_setting(root: ET.Element) -> None:
            settings = root.find(q("Settings"))
            assert settings is not None
            restart = ET.SubElement(settings, q("RestartOnFailure"))
            ET.SubElement(restart, q("Interval")).text = "PT1M"

        def security_descriptor(root: ET.Element) -> None:
            info = root.find(q("RegistrationInfo"))
            assert info is not None
            ET.SubElement(info, q("SecurityDescriptor")).text = "D:P"

        def group_principal(root: ET.Element) -> None:
            principal = root.find(f"{q('Principals')}/{q('Principal')}")
            assert principal is not None
            user = principal.find(q("UserId"))
            assert user is not None
            principal.remove(user)
            ET.SubElement(principal, q("GroupId")).text = "S-1-5-32-544"

        def second_principal(root: ET.Element) -> None:
            principals = root.find(q("Principals"))
            assert principals is not None
            extra = ET.SubElement(principals, q("Principal"), id="Other")
            ET.SubElement(extra, q("UserId")).text = ATTACKER_SID
            ET.SubElement(extra, q("LogonType")).text = "InteractiveToken"

        principal_path = f"{q('Principals')}/{q('Principal')}"
        exec_path = f"{q('Actions')}/{q('Exec')}"
        cases = {
            "principal-sid": set_text(f"{principal_path}/{q('UserId')}", ATTACKER_SID),
            "logon-type": set_text(f"{principal_path}/{q('LogonType')}", "Password"),
            "run-level": set_text(
                f"{principal_path}/{q('RunLevel')}", "HighestAvailable"
            ),
            "command": set_text(
                f"{exec_path}/{q('Command')}", r"C:\Windows\System32\cmd.exe"
            ),
            "working-directory": set_text(
                f"{exec_path}/{q('WorkingDirectory')}", temp_dir
            ),
            "hidden": set_text(f"{q('Settings')}/{q('Hidden')}", "false"),
            "on-demand": set_text(
                f"{q('Settings')}/{q('AllowStartOnDemand')}", "true"
            ),
            "time-limit": set_text(
                f"{q('Settings')}/{q('ExecutionTimeLimit')}", "PT9H"
            ),
            "priority": set_text(f"{q('Settings')}/{q('Priority')}", "4"),
            "idle-drift": set_text(
                f"{q('Settings')}/{q('IdleSettings')}/{q('StopOnIdleEnd')}", "true"
            ),
            "trigger-disabled": set_text(
                f"{q('Triggers')}/{q('RegistrationTrigger')}/{q('Enabled')}", "false"
            ),
            "version": lambda root: root.set("version", "1.3"),
            "second-exec-action": second_exec,
            "time-trigger": time_trigger,
            "second-trigger": second_trigger,
            "extra-simple-setting": extra_simple_setting,
            "extra-complex-setting": extra_complex_setting,
            "security-descriptor": security_descriptor,
            "group-principal": group_principal,
            "second-principal": second_principal,
        }

        exact = self.exact_xml()
        arguments = ET.fromstring(exact).findtext(
            "t:Actions/t:Exec/t:Arguments", namespaces=NS
        )
        assert arguments is not None
        cases["arguments"] = set_text(
            f"{exec_path}/{q('Arguments')}", arguments + " --unpinned"
        )
        for case, mutate in cases.items():
            with self.subTest(case=case):
                observation, _ = self.observe(
                    self.present(rewrite(exact, mutate))
                )
                self.assertIs(TaskObservation.PRESENT_CONFLICT, observation)

    def test_task_name_mismatch_is_conflict(self) -> None:
        sibling = self.expected_name().replace("-a2-", "-a1-")
        drifted = rewrite(
            self.exact_xml(),
            lambda root: setattr(
                root.find(f"{q('RegistrationInfo')}/{q('URI')}"), "text", sibling
            ),
        )
        observation, port = self.observe(self.present(drifted))
        self.assertIs(TaskObservation.PRESENT_CONFLICT, observation)
        self.assertEqual([self.expected_name()], port.calls)

    def test_probe_failure_is_stable_and_secret_free(self) -> None:
        port = ScriptedQueryPort(RuntimeError("SECRET"))
        adapter = self.port_adapter(port)
        with self.assertRaises(SchedulerError) as captured:
            adapter.observe_exact(self.identity, self.paths)
        self.assertEqual("task-probe-failed", str(captured.exception))
        self.assertNotIn("SECRET", str(captured.exception))

    def test_probe_result_ambiguity_fails_closed(self) -> None:
        cases = {
            "localized-string": "PRÉSENTE",
            "plain-status": TaskProbe("present", None),  # type: ignore[arg-type]
            "xml-on-absent": TaskProbe(TaskProbeStatus.ABSENT, b"<Task/>"),
            "xml-on-unknown": TaskProbe(TaskProbeStatus.UNKNOWN, b""),
            "text-xml": TaskProbe(TaskProbeStatus.PRESENT, "<Task/>"),  # type: ignore[arg-type]
        }
        for case, probe in cases.items():
            with self.subTest(case=case):
                adapter = self.port_adapter(ScriptedQueryPort(probe))
                with self.assertRaises(SchedulerError) as captured:
                    adapter.observe_exact(self.identity, self.paths)
                self.assertEqual(
                    "probe-result-invalid", captured.exception.code
                )

    def test_observe_requires_types_and_port(self) -> None:
        adapter = self.port_adapter(ScriptedQueryPort())
        with self.assertRaises(SchedulerError) as captured:
            adapter.observe_exact("night-canary", self.paths)  # type: ignore[arg-type]
        self.assertEqual("task-spec-invalid", captured.exception.code)
        portless = self.adapter()
        with self.assertRaises(SchedulerError) as captured:
            portless.observe_exact(self.identity, self.paths)
        self.assertEqual("query-port-unavailable", captured.exception.code)


class EnsureRegisteredTests(ExactBoundaryFixture):
    def test_exact_existing_replay_succeeds_without_create(self) -> None:
        port = ScriptedQueryPort(self.present(self.exact_xml()))
        adapter = self.port_adapter(port)
        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            name = adapter.ensure_registered(self.identity, self.paths)
        run.assert_not_called()
        self.assertEqual(self.expected_name(), name)
        self.assertEqual([name], port.calls)
        self.assertTrue((self.attempt / "task-spec.json").exists())
        self.assertTrue((self.attempt / "runner-task.xml").exists())

    def test_service_bstr_existing_replay_succeeds_without_create(self) -> None:
        port = ScriptedQueryPort(self.present(self.service_bstr_xml()))
        adapter = self.port_adapter(port)
        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            name = adapter.ensure_registered(self.identity, self.paths)
        run.assert_not_called()
        self.assertEqual(self.expected_name(), name)
        self.assertEqual([name], port.calls)

    def test_conflicting_same_name_task_fails_closed_without_create(self) -> None:
        port = ScriptedQueryPort(self.present(self.conflicting_xml()))
        adapter = self.port_adapter(port)
        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            with self.assertRaises(SchedulerError) as captured:
                adapter.ensure_registered(self.identity, self.paths)
        run.assert_not_called()
        self.assertEqual("task-conflict", captured.exception.code)

    def test_unknown_observation_fails_closed_without_create(self) -> None:
        adapter = self.port_adapter(ScriptedQueryPort(self.unknown()))
        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            with self.assertRaises(SchedulerError) as captured:
                adapter.ensure_registered(self.identity, self.paths)
        run.assert_not_called()
        self.assertEqual("task-observation-unknown", captured.exception.code)

    def test_fresh_create_registers_confirms_and_never_overwrites(self) -> None:
        port = ScriptedQueryPort(self.absent(), self.present(self.exact_xml()))
        adapter = self.port_adapter(port)

        def launched(command: list[str], **kwargs: object):
            self.assertTrue(self.locker.active)
            self.assertIs(kwargs["shell"], False)
            return self.completed()

        with mock.patch(
            "autonomy.scheduler.subprocess.run", side_effect=launched
        ) as run:
            name = adapter.ensure_registered(self.identity, self.paths)
        self.assertEqual(1, run.call_count)
        self.assertEqual(
            [
                os.fspath(self.schtasks),
                "/Create",
                "/TN",
                name,
                "/XML",
                os.fspath(self.attempt / "runner-task.xml"),
            ],
            run.call_args.args[0],
        )
        self.assertNotIn("/F", run.call_args.args[0])
        self.assertEqual([name, name], port.calls)

    def test_create_response_loss_resolved_only_by_exact_inspection(self) -> None:
        localized = self.completed(
            1, stderr="ERREUR : la tâche existe déjà.".encode("cp1252")
        )
        failures: dict[str, object] = {
            "nonzero-localized": localized,
            "timeout": subprocess.TimeoutExpired(["SECRET"], 1),
            "spawn-failure": OSError("SECRET"),
        }
        for case, failure in failures.items():
            with self.subTest(case=case):
                port = ScriptedQueryPort(
                    self.absent(), self.present(self.exact_xml())
                )
                adapter = self.port_adapter(port)
                patch_kwargs = (
                    {"side_effect": failure}
                    if isinstance(failure, BaseException)
                    else {"return_value": failure}
                )
                with mock.patch(
                    "autonomy.scheduler.subprocess.run", **patch_kwargs
                ):
                    name = adapter.ensure_registered(self.identity, self.paths)
                self.assertEqual(self.expected_name(), name)
                self.assertEqual([name, name], port.calls)

    def test_create_response_loss_without_exact_recovery_fails_closed(self) -> None:
        cases = {
            "still-absent": (self.absent(), "schtasks-create-nonzero"),
            "conflict": (self.present(self.conflicting_xml()), "task-conflict"),
            "unknown": (self.unknown(), "schtasks-create-nonzero"),
        }
        for case, (recovery, code) in cases.items():
            with self.subTest(case=case):
                adapter = self.port_adapter(
                    ScriptedQueryPort(self.absent(), recovery)
                )
                with mock.patch(
                    "autonomy.scheduler.subprocess.run",
                    return_value=self.completed(1, stderr=b"garbled \xff output"),
                ):
                    with self.assertRaises(SchedulerError) as captured:
                        adapter.ensure_registered(self.identity, self.paths)
                self.assertEqual(code, captured.exception.code)

    def test_create_success_still_requires_exact_confirmation(self) -> None:
        cases = {
            "absent-after-create": (self.absent(), "task-create-unconfirmed"),
            "unknown-after-create": (self.unknown(), "task-create-unconfirmed"),
            "conflict-after-create": (
                self.present(self.conflicting_xml()),
                "task-conflict",
            ),
        }
        for case, (confirmation, code) in cases.items():
            with self.subTest(case=case):
                adapter = self.port_adapter(
                    ScriptedQueryPort(self.absent(), confirmation)
                )
                with mock.patch(
                    "autonomy.scheduler.subprocess.run",
                    return_value=self.completed(),
                ):
                    with self.assertRaises(SchedulerError) as captured:
                        adapter.ensure_registered(self.identity, self.paths)
                self.assertEqual(code, captured.exception.code)

    def test_replay_after_successful_create_is_idempotent(self) -> None:
        first = ScriptedQueryPort(self.absent(), self.present(self.exact_xml()))
        with mock.patch(
            "autonomy.scheduler.subprocess.run", return_value=self.completed()
        ) as run:
            name = self.port_adapter(first).ensure_registered(
                self.identity, self.paths
            )
        self.assertEqual(1, run.call_count)
        replay = ScriptedQueryPort(self.present(self.exact_xml()))
        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            self.assertEqual(
                name,
                self.port_adapter(replay).ensure_registered(
                    self.identity, self.paths
                ),
            )
        run.assert_not_called()

    def test_missing_port_fails_before_any_effect(self) -> None:
        adapter = self.adapter()
        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            with self.assertRaises(SchedulerError) as captured:
                adapter.ensure_registered(self.identity, self.paths)
        run.assert_not_called()
        self.assertEqual("query-port-unavailable", captured.exception.code)
        self.assertFalse((self.attempt / "task-spec.json").exists())
        self.assertFalse((self.attempt / "runner-task.xml").exists())


class EnsureAbsentTests(ExactBoundaryFixture):
    def test_absent_replay_succeeds_without_delete(self) -> None:
        port = ScriptedQueryPort(self.absent())
        adapter = self.port_adapter(port)
        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            self.assertIsNone(adapter.ensure_absent(self.identity, self.paths))
        run.assert_not_called()
        self.assertEqual([self.expected_name()], port.calls)

    def test_never_deletes_conflicting_or_unobserved_task(self) -> None:
        cases = {
            "conflict": (
                self.present(self.conflicting_xml()),
                "task-conflict",
            ),
            "unreadable-definition": (self.present(None), "task-conflict"),
            "unknown": (self.unknown(), "task-observation-unknown"),
        }
        for case, (probe, code) in cases.items():
            with self.subTest(case=case):
                adapter = self.port_adapter(ScriptedQueryPort(probe))
                with mock.patch("autonomy.scheduler.subprocess.run") as run:
                    with self.assertRaises(SchedulerError) as captured:
                        adapter.ensure_absent(self.identity, self.paths)
                run.assert_not_called()
                self.assertEqual(code, captured.exception.code)

    def test_exact_task_is_deleted_and_absence_confirmed(self) -> None:
        port = ScriptedQueryPort(self.present(self.exact_xml()), self.absent())
        adapter = self.port_adapter(port)
        with mock.patch(
            "autonomy.scheduler.subprocess.run", return_value=self.completed()
        ) as run:
            adapter.ensure_absent(self.identity, self.paths)
        name = self.expected_name()
        self.assertEqual(
            [os.fspath(self.schtasks), "/Delete", "/TN", name, "/F"],
            run.call_args.args[0],
        )
        self.assertEqual([name, name], port.calls)

    def test_service_bstr_exact_task_reaches_delete_and_confirms_absent(self) -> None:
        port = ScriptedQueryPort(self.present(self.service_bstr_xml()), self.absent())
        adapter = self.port_adapter(port)
        with mock.patch(
            "autonomy.scheduler.subprocess.run", return_value=self.completed()
        ) as run:
            adapter.ensure_absent(self.identity, self.paths)
        name = self.expected_name()
        self.assertEqual(
            [os.fspath(self.schtasks), "/Delete", "/TN", name, "/F"],
            run.call_args.args[0],
        )
        self.assertEqual([name, name], port.calls)

    def test_delete_response_loss_resolved_by_reinspection(self) -> None:
        localized = self.completed(
            1, stderr="ERREUR : la tâche spécifiée est introuvable.".encode("cp1252")
        )
        failures: dict[str, object] = {
            "nonzero-localized": localized,
            "timeout": subprocess.TimeoutExpired(["SECRET"], 1),
            "spawn-failure": OSError("SECRET"),
        }
        for case, failure in failures.items():
            with self.subTest(case=case):
                port = ScriptedQueryPort(
                    self.present(self.exact_xml()), self.absent()
                )
                adapter = self.port_adapter(port)
                patch_kwargs = (
                    {"side_effect": failure}
                    if isinstance(failure, BaseException)
                    else {"return_value": failure}
                )
                with mock.patch(
                    "autonomy.scheduler.subprocess.run", **patch_kwargs
                ):
                    adapter.ensure_absent(self.identity, self.paths)
                self.assertEqual(2, len(port.calls))

    def test_delete_response_loss_without_absence_fails_closed(self) -> None:
        cases = {
            "still-present": (
                self.completed(1, stderr=b"localized \xa0 refusal"),
                self.present(self.exact_xml()),
                "schtasks-delete-nonzero",
            ),
            "unknown-after-timeout": (
                subprocess.TimeoutExpired(["SECRET"], 1),
                self.unknown(),
                "schtasks-timeout",
            ),
        }
        for case, (failure, final, code) in cases.items():
            with self.subTest(case=case):
                adapter = self.port_adapter(
                    ScriptedQueryPort(self.present(self.exact_xml()), final)
                )
                patch_kwargs = (
                    {"side_effect": failure}
                    if isinstance(failure, BaseException)
                    else {"return_value": failure}
                )
                with mock.patch(
                    "autonomy.scheduler.subprocess.run", **patch_kwargs
                ):
                    with self.assertRaises(SchedulerError) as captured:
                        adapter.ensure_absent(self.identity, self.paths)
                self.assertEqual(code, captured.exception.code)
                self.assertNotIn("SECRET", str(captured.exception))

    def test_delete_success_still_requires_trustworthy_absence(self) -> None:
        cases = {
            "still-exact": (
                self.present(self.exact_xml()),
                "task-delete-unconfirmed",
            ),
            "unknown": (self.unknown(), "task-observation-unknown"),
            "conflict": (
                self.present(self.conflicting_xml()),
                "task-conflict",
            ),
        }
        for case, (final, code) in cases.items():
            with self.subTest(case=case):
                adapter = self.port_adapter(
                    ScriptedQueryPort(self.present(self.exact_xml()), final)
                )
                with mock.patch(
                    "autonomy.scheduler.subprocess.run",
                    return_value=self.completed(),
                ):
                    with self.assertRaises(SchedulerError) as captured:
                        adapter.ensure_absent(self.identity, self.paths)
                self.assertEqual(code, captured.exception.code)

    def test_durable_conflict_blocks_teardown_before_probe_or_delete(self) -> None:
        for filename, code in (
            ("task-spec.json", "durable-spec-conflict"),
            ("runner-task.xml", "durable-xml-conflict"),
        ):
            with self.subTest(filename=filename):
                target = self.attempt / filename
                target.write_bytes(b"attacker\n")
                try:
                    port = ScriptedQueryPort()
                    adapter = self.port_adapter(port)
                    with mock.patch("autonomy.scheduler.subprocess.run") as run:
                        with self.assertRaises(SchedulerError) as captured:
                            adapter.ensure_absent(self.identity, self.paths)
                    run.assert_not_called()
                    self.assertEqual([], port.calls)
                    self.assertEqual(code, captured.exception.code)
                finally:
                    target.unlink()

    def test_ensure_absent_requires_types_and_port(self) -> None:
        adapter = self.port_adapter(ScriptedQueryPort())
        with self.assertRaises(SchedulerError) as captured:
            adapter.ensure_absent(self.identity, object())  # type: ignore[arg-type]
        self.assertEqual("task-spec-invalid", captured.exception.code)
        with mock.patch("autonomy.scheduler.subprocess.run") as run:
            with self.assertRaises(SchedulerError) as captured:
                self.adapter().ensure_absent(self.identity, self.paths)
        run.assert_not_called()
        self.assertEqual("query-port-unavailable", captured.exception.code)


class QueryPortBoundaryTests(ExactBoundaryFixture):
    def test_query_port_is_explicitly_test_only_and_validated(self) -> None:
        with self.assertRaises(SchedulerError) as captured:
            TaskSchedulerAdapter(test_only_query_port=ScriptedQueryPort())
        self.assertEqual("test-query-port-forbidden", captured.exception.code)
        with self.assertRaises(SchedulerError) as captured:
            TaskSchedulerAdapter(
                test_only_schtasks_path=self.schtasks,
                test_only_schtasks_sha256=sha256(self.schtasks),
                test_only_query_port="not-callable",  # type: ignore[arg-type]
            )
        self.assertEqual("test-query-port-invalid", captured.exception.code)

    def test_production_default_port_is_narrow_com_adapter(self) -> None:
        with mock.patch(
            "autonomy.scheduler._get_system_directory",
            return_value=self.schtasks.parent,
        ):
            adapter = TaskSchedulerAdapter()
        self.assertIsInstance(
            adapter._query_port, scheduler_module._ComTaskQueryPort
        )

    def test_com_port_fails_closed_off_windows(self) -> None:
        port = scheduler_module._ComTaskQueryPort()
        name = build_task_name("night-canary", 2, NONCE, "0" * 64)
        with mock.patch("autonomy.scheduler.os.name", "posix"):
            probe = port(name)
        self.assertEqual(TaskProbe(TaskProbeStatus.UNKNOWN), probe)

    def test_com_port_validates_task_name_before_any_com_use(self) -> None:
        port = scheduler_module._ComTaskQueryPort()
        for name in ("evil", r"\other-folder\task", ""):
            with self.subTest(name=name):
                with self.assertRaises(SchedulerError) as captured:
                    port(name)
                self.assertEqual("task-name-invalid", captured.exception.code)


if __name__ == "__main__":
    unittest.main()
