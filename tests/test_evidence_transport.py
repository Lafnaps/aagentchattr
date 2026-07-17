from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from autonomy import evidence_transport as transport


def canonical_line(document: object) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def documents(bundle: bytes) -> list[dict]:
    return [json.loads(line) for line in bundle.splitlines()]


def rendered(items: list[dict]) -> bytes:
    return b"".join(canonical_line(item) for item in items)


class EvidenceTransportCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()

    def write(self, relative_path: str, data: bytes) -> Path:
        path = self.source.joinpath(*relative_path.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def error(self, code: str, function, *args, **kwargs) -> None:
        with self.assertRaises(transport.EvidenceTransportError) as caught:
            function(*args, **kwargs)
        self.assertEqual(code, caught.exception.code)

    def one_file_bundle(self, data: bytes = b"abcdef", *, chunk_bytes: int = 2) -> bytes:
        self.write("payload.bin", data)
        return transport.pack(
            self.source,
            ["payload.bin"],
            chunk_bytes=chunk_bytes,
        )

    def assert_no_stage(self, target: Path) -> None:
        self.assertEqual(
            [],
            list(target.parent.glob(f".{target.name}.evidence-*")),
        )


class RoundTripTests(EvidenceTransportCase):
    def test_deterministic_roundtrip_empty_binary_utf8_and_chunk_edges(self) -> None:
        expected = {
            "empty.bin": b"",
            "nested/binary.bin": bytes(range(256)) + b"\x00\xff",
            "nested/utf8.txt": "Привет, evidence.\n".encode(),
        }
        for path, data in expected.items():
            self.write(path, data)

        supplied = ["empty.bin", r"nested\binary.bin", "nested/utf8.txt"]
        first = transport.pack(self.source, supplied, chunk_bytes=7)
        second = transport.pack(self.source, supplied, chunk_bytes=7)
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))
        self.assertNotIn(b"\r", first)
        self.assertFalse(first.startswith(b"\xef\xbb\xbf"))
        for line in first.splitlines(keepends=True):
            self.assertEqual(canonical_line(json.loads(line)), line)

        manifest = transport.verify(first)
        self.assertEqual(transport.SCHEMA, manifest.schema)
        self.assertEqual(1, manifest.version)
        self.assertEqual(7, manifest.chunk_bytes)
        self.assertEqual(sum(map(len, expected.values())), manifest.total_bytes)
        self.assertEqual(tuple(expected), tuple(item.path for item in manifest.files))
        self.assertEqual(0, manifest.files[0].chunks)

        target = self.root / "unpacked"
        unpacked = transport.unpack(first, target)
        self.assertEqual(manifest, unpacked)
        for path, data in expected.items():
            self.assertEqual(data, target.joinpath(*path.split("/")).read_bytes())
        self.assert_no_stage(target)

    def test_declared_file_order_is_bound_by_bundle_hash(self) -> None:
        self.write("a.txt", b"a")
        self.write("b.txt", b"b")
        forward = transport.verify(
            transport.pack(self.source, ["a.txt", "b.txt"], chunk_bytes=1)
        )
        reverse = transport.verify(
            transport.pack(self.source, ["b.txt", "a.txt"], chunk_bytes=1)
        )
        self.assertNotEqual(forward.bundle_sha256, reverse.bundle_sha256)

    def test_verify_is_side_effect_free(self) -> None:
        bundle = self.one_file_bundle()
        with mock.patch.object(
            transport.tempfile,
            "mkdtemp",
            side_effect=AssertionError("verify attempted a write"),
        ):
            manifest = transport.verify(bundle)
        self.assertEqual(6, manifest.total_bytes)

    def test_cli_pack_verify_and_unpack(self) -> None:
        self.write("cli.txt", b"cli-evidence")
        repository = Path(__file__).resolve().parents[1]
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"

        packed = subprocess.run(
            [
                sys.executable,
                "-m",
                "autonomy.evidence_transport",
                "pack",
                "--source-root",
                os.fspath(self.source),
                "--chunk-bytes",
                "3",
                "cli.txt",
            ],
            cwd=repository,
            env=environment,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, packed.returncode, packed.stderr.decode(errors="replace"))
        bundle_path = self.root / "evidence.jsonl"
        bundle_path.write_bytes(packed.stdout)

        verified = subprocess.run(
            [
                sys.executable,
                "-m",
                "autonomy.evidence_transport",
                "verify",
                os.fspath(bundle_path),
            ],
            cwd=repository,
            env=environment,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, verified.returncode, verified.stderr.decode(errors="replace"))
        summary = json.loads(verified.stdout)
        self.assertEqual("cli.txt", summary["files"][0]["path"])

        target = self.root / "cli-target"
        unpacked = subprocess.run(
            [
                sys.executable,
                "-m",
                "autonomy.evidence_transport",
                "unpack",
                os.fspath(bundle_path),
                os.fspath(target),
            ],
            cwd=repository,
            env=environment,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, unpacked.returncode, unpacked.stderr.decode(errors="replace"))
        self.assertEqual(b"cli-evidence", (target / "cli.txt").read_bytes())


class PackRefusalTests(EvidenceTransportCase):
    def test_pack_requires_a_bounded_explicit_file_list(self) -> None:
        self.error("file-count-bound-invalid", transport.pack, self.source, [])
        self.error(
            "file-count-bound-invalid",
            transport.pack,
            self.source,
            [f"file-{index}" for index in range(transport.MAX_FILES + 1)],
        )
        self.error(
            "file-list-invalid",
            transport.pack,
            self.source,
            "payload.bin",
        )

    def test_pack_rejects_unsafe_windows_paths_before_filesystem_access(self) -> None:
        unsafe = [
            "",
            ".",
            "..",
            "../escape",
            "dir/../escape",
            "/absolute",
            "C:/drive",
            "//server/share",
            r"\\?\C:\device",
            "name:stream",
            "NUL",
            "con.txt",
            "dir/COM1.log",
            "trailing.",
            "trailing ",
            "two//components",
            "control\tname",
            "question?.txt",
        ]
        for path in unsafe:
            with self.subTest(path=path):
                with self.assertRaises(transport.EvidenceTransportError):
                    transport.pack(self.source, [path])

    def test_pack_rejects_duplicate_casefold_and_parent_collisions(self) -> None:
        self.write("one.txt", b"one")
        self.error(
            "path-collision",
            transport.pack,
            self.source,
            ["one.txt", "ONE.TXT"],
        )
        self.error(
            "path-collision",
            transport.pack,
            self.source,
            ["one.txt", "one.txt/child"],
        )

    def test_pack_rejects_directories_and_reparse_ancestors(self) -> None:
        directory = self.source / "directory"
        directory.mkdir()
        self.error(
            "source-not-file",
            transport.pack,
            self.source,
            ["directory"],
        )

        self.write("payload.bin", b"payload")
        original = transport._path_is_reparse

        def injected(path: Path) -> bool:
            if os.path.normcase(os.fspath(path)) == os.path.normcase(os.fspath(self.source)):
                return True
            return original(path)

        with mock.patch.object(transport, "_path_is_reparse", side_effect=injected):
            self.error(
                "reparse-path",
                transport.pack,
                self.source,
                ["payload.bin"],
            )

    def test_pack_enforces_chunk_and_file_bounds_before_read(self) -> None:
        self.write("payload.bin", b"x" * (transport.MAX_CHUNKS_PER_FILE + 1))
        self.error(
            "integer-bound-invalid",
            transport.pack,
            self.source,
            ["payload.bin"],
            chunk_bytes=0,
        )
        self.error(
            "integer-bound-invalid",
            transport.pack,
            self.source,
            ["payload.bin"],
            chunk_bytes=transport.MAX_CHUNK_BYTES + 1,
        )
        self.error(
            "chunk-count-bound-invalid",
            transport.pack,
            self.source,
            ["payload.bin"],
            chunk_bytes=1,
        )


class GrammarRefusalTests(EvidenceTransportCase):
    def test_rejects_noncanonical_encoding_and_trailing_data(self) -> None:
        bundle = self.one_file_bundle()
        cases = {
            "utf8-bom-invalid": b"\xef\xbb\xbf" + bundle,
            "utf8-invalid": b"\xff" + bundle[1:],
            "canonical-json-invalid": bundle.replace(b"\n", b"\r\n", 1),
            "trailing-bytes": bundle[:-1],
            "trailing-records": bundle + b"{}\n",
        }
        for code, candidate in cases.items():
            with self.subTest(code=code):
                self.error(code, transport.verify, candidate)

    def test_rejects_duplicate_json_keys_unknown_fields_and_wrong_types(self) -> None:
        bundle = self.one_file_bundle()
        lines = bundle.splitlines(keepends=True)
        duplicate = b'{"type":"header",' + lines[0][1:] + b"".join(lines[1:])
        self.error("duplicate-json-key", transport.verify, duplicate)

        items = documents(bundle)
        items[0]["unknown"] = 1
        self.error("schema-fields-invalid", transport.verify, rendered(items))

        items = documents(bundle)
        items[0]["chunk_bytes"] = True
        self.error("integer-bound-invalid", transport.verify, rendered(items))

        items = documents(bundle)
        items[0]["version"] = 1.0
        self.error("integer-bound-invalid", transport.verify, rendered(items))

    def test_rejects_strict_base64_and_chunk_hash_or_order_mismatch(self) -> None:
        bundle = self.one_file_bundle(b"abcd", chunk_bytes=2)
        items = documents(bundle)
        items[2]["data"] = "!!!!"
        self.error("base64-invalid", transport.verify, rendered(items))

        items = documents(bundle)
        items[2]["sha256"] = "0" * 64
        self.error("chunk-hash-mismatch", transport.verify, rendered(items))

        items = documents(bundle)
        items[2]["ordinal"] = 1
        self.error("record-order-invalid", transport.verify, rendered(items))

        items = documents(bundle)
        del items[2]
        self.error("record-order-invalid", transport.verify, rendered(items))

        items = documents(bundle)
        items.insert(3, dict(items[2]))
        self.error("record-order-invalid", transport.verify, rendered(items))

    def test_rejects_file_schema_summary_and_bundle_hash_mismatch(self) -> None:
        bundle = self.one_file_bundle()
        items = documents(bundle)
        items[1]["sha256"] = "0" * 64
        self.error("file-hash-mismatch", transport.verify, rendered(items))

        items = documents(bundle)
        items[-1]["total_bytes"] += 1
        self.error("bundle-summary-mismatch", transport.verify, rendered(items))

        items = documents(bundle)
        items[-1]["sha256"] = "0" * 64
        self.error("bundle-hash-mismatch", transport.verify, rendered(items))

        items = documents(bundle)
        items[0]["version"] = 2
        self.error("integer-bound-invalid", transport.verify, rendered(items))

    def test_rejects_all_declared_bounds_before_materialization(self) -> None:
        bundle = self.one_file_bundle(b"abcdef", chunk_bytes=2)

        items = documents(bundle)
        items[0]["chunk_bytes"] = transport.MAX_CHUNK_BYTES + 1
        self.error("integer-bound-invalid", transport.verify, rendered(items))

        items = documents(bundle)
        items[0]["file_count"] = transport.MAX_FILES + 1
        self.error("integer-bound-invalid", transport.verify, rendered(items))

        items = documents(bundle)
        items[1]["chunks"] = transport.MAX_CHUNKS_PER_FILE + 1
        self.error("integer-bound-invalid", transport.verify, rendered(items))

        items = documents(bundle)
        items[1]["bytes"] = transport.MAX_FILE_BYTES + 1
        self.error("integer-bound-invalid", transport.verify, rendered(items))

        items = documents(bundle)
        items[1]["path"] = "x" * (transport.MAX_RELATIVE_PATH_BYTES + 1)
        self.error("path-bound-invalid", transport.verify, rendered(items))

        with mock.patch.object(transport, "MAX_TOTAL_BYTES", 5):
            self.error("total-bytes-bound-invalid", transport.verify, bundle)

        with mock.patch.object(transport, "MAX_BUNDLE_BYTES", len(bundle) - 1):
            self.error("bundle-bound-invalid", transport.verify, bundle)

    def test_rejects_unsafe_or_colliding_paths_from_a_received_bundle(self) -> None:
        first = self.write("first.txt", b"a")
        second = self.write("second.txt", b"b")
        self.assertTrue(first.is_file() and second.is_file())
        bundle = transport.pack(
            self.source,
            ["first.txt", "second.txt"],
            chunk_bytes=1,
        )
        for unsafe in ("name:stream", "NUL.txt", "trailing.", "../escape"):
            items = documents(bundle)
            items[1]["path"] = unsafe
            with self.subTest(path=unsafe):
                self.error("unsafe-path", transport.verify, rendered(items))

        items = documents(bundle)
        items[3]["path"] = "FIRST.TXT"
        self.error("path-collision", transport.verify, rendered(items))

        items = documents(bundle)
        items[1]["path"] = "parent"
        items[3]["path"] = "parent/child"
        self.error("path-collision", transport.verify, rendered(items))

    def test_rejects_non_bytes_input(self) -> None:
        self.error("bundle-type-invalid", transport.verify, "not bytes")


class AtomicUnpackTests(EvidenceTransportCase):
    def test_existing_target_is_untouched_and_no_stage_is_created(self) -> None:
        bundle = self.one_file_bundle()
        target = self.root / "target"
        target.mkdir()
        sentinel = target / "owner.txt"
        sentinel.write_bytes(b"owner")

        self.error("target-exists", transport.unpack, bundle, target)
        self.assertEqual(b"owner", sentinel.read_bytes())
        self.assertEqual(["owner.txt"], [path.name for path in target.iterdir()])
        self.assert_no_stage(target)

    def test_target_created_during_publish_wins_without_overwrite(self) -> None:
        bundle = self.one_file_bundle()
        target = self.root / "race-target"
        publish = transport._publish_staging

        def race(stage: Path, destination: Path) -> None:
            destination.mkdir()
            (destination / "winner.txt").write_bytes(b"winner")
            publish(stage, destination)

        with mock.patch.object(transport, "_publish_staging", side_effect=race):
            self.error("target-exists", transport.unpack, bundle, target)
        self.assertEqual(b"winner", (target / "winner.txt").read_bytes())
        self.assertFalse((target / "payload.bin").exists())
        self.assert_no_stage(target)

    def test_injected_write_failure_removes_stage_and_leaves_no_target(self) -> None:
        bundle = self.one_file_bundle()
        target = self.root / "failed-target"
        with mock.patch.object(
            transport,
            "_write_file",
            side_effect=OSError("injected write failure"),
        ):
            self.error("unpack-io", transport.unpack, bundle, target)
        self.assertFalse(target.exists())
        self.assert_no_stage(target)

    def test_target_reparse_ancestor_is_refused_before_staging(self) -> None:
        bundle = self.one_file_bundle()
        allowed = self.root / "allowed"
        allowed.mkdir()
        target = allowed / "target"
        original = transport._path_is_reparse

        def injected(path: Path) -> bool:
            if os.path.normcase(os.fspath(path)) == os.path.normcase(os.fspath(allowed)):
                return True
            return original(path)

        with mock.patch.object(transport, "_path_is_reparse", side_effect=injected):
            self.error("reparse-path", transport.unpack, bundle, target)
        self.assertFalse(target.exists())
        self.assert_no_stage(target)

    def test_invalid_bundle_never_checks_or_creates_target(self) -> None:
        bundle = self.one_file_bundle() + b"{}\n"
        target = self.root / "never-touched"
        with mock.patch.object(
            transport,
            "_absolute_local_path",
            side_effect=AssertionError("target inspected before complete verification"),
        ):
            self.error("trailing-records", transport.unpack, bundle, target)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
