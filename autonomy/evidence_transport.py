"""Deterministic, bounded transport for small local evidence bundles.

The module deliberately has no network or agentchattr runtime integration.
Callers explicitly name files below a source root, transport the returned
JSONL bytes by a mechanism of their choice, then verify or atomically unpack
those bytes below a new target root.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import io
import json
import ntpath
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from typing import Any, Mapping, Sequence


SCHEMA = "agentchattr-evidence"
VERSION = 1

DEFAULT_CHUNK_BYTES = 64 * 1024
MAX_CHUNK_BYTES = 1024 * 1024
MAX_FILES = 32
MAX_CHUNKS_PER_FILE = 4096
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_RELATIVE_PATH_BYTES = 512
MAX_RECORD_BYTES = 4 * ((MAX_CHUNK_BYTES + 2) // 3) + 1024
MAX_BUNDLE_BYTES = 96 * 1024 * 1024

_HEADER_KEYS = frozenset(
    {"chunk_bytes", "file_count", "schema", "type", "version"}
)
_FILE_KEYS = frozenset(
    {"bytes", "chunks", "ordinal", "path", "sha256", "type"}
)
_CHUNK_KEYS = frozenset(
    {"data", "file", "ordinal", "sha256", "type"}
)
_BUNDLE_KEYS = frozenset({"file_count", "sha256", "total_bytes", "type"})
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_WINDOWS_INVALID = frozenset('<>:"\\|?*')
_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul", "clock$"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class EvidenceTransportError(ValueError):
    """A fail-closed refusal with a stable machine-readable code."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


@dataclass(frozen=True, slots=True)
class EvidenceFile:
    ordinal: int
    path: str
    size: int
    sha256: str
    chunks: int


@dataclass(frozen=True, slots=True)
class EvidenceManifest:
    schema: str
    version: int
    chunk_bytes: int
    total_bytes: int
    bundle_sha256: str
    files: tuple[EvidenceFile, ...]


@dataclass(frozen=True, slots=True)
class _SourceBinding:
    relative_path: str
    path: Path
    size: int
    chunks: int
    identity: tuple[int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _ParsedBundle:
    manifest: EvidenceManifest
    payloads: tuple[bytes, ...]


class _DuplicateJSONKey(ValueError):
    pass


def _fail(code: str, detail: str) -> None:
    raise EvidenceTransportError(code, detail)


def _canonical_document(document: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        _fail("json-value-invalid", str(exc))


def _canonical_line(document: Mapping[str, Any]) -> bytes:
    return _canonical_document(document) + b"\n"


def _pairs_to_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _exact_int(
    value: Any,
    field: str,
    *,
    minimum: int = 0,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(
            "integer-bound-invalid",
            f"{field} must be an integer in {minimum}..{maximum}",
        )
    return value


def _exact_string(value: Any, field: str) -> str:
    if type(value) is not str:
        _fail("type-invalid", f"{field} must be a string")
    return value


def _sha256(value: Any, field: str) -> str:
    text = _exact_string(value, field)
    if _SHA256_RE.fullmatch(text) is None:
        _fail("sha256-invalid", f"{field} must be lowercase SHA-256")
    return text


def _require_keys(
    document: Mapping[str, Any], expected: frozenset[str], record: str
) -> None:
    actual = frozenset(document)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        _fail(
            "schema-fields-invalid",
            f"{record} fields differ; missing={missing}, unknown={unknown}",
        )


def _normalise_pack_path(value: Any) -> str:
    if type(value) is not str:
        _fail("unsafe-path", "relative paths must be strings")
    return _validate_relative_path(value.replace("\\", "/"))


def _validate_relative_path(value: Any) -> str:
    path = _exact_string(value, "path")
    try:
        encoded = path.encode("utf-8", "strict")
    except UnicodeError as exc:
        _fail("unsafe-path", f"path is not valid UTF-8 text: {exc}")
    if not encoded or len(encoded) > MAX_RELATIVE_PATH_BYTES:
        _fail(
            "path-bound-invalid",
            f"path must occupy 1..{MAX_RELATIVE_PATH_BYTES} UTF-8 bytes",
        )
    drive, _ = ntpath.splitdrive(path)
    if drive or path.startswith(("/", "\\")) or ntpath.isabs(path):
        _fail("unsafe-path", f"absolute, drive, UNC, and device paths are refused: {path!r}")
    if "\\" in path:
        _fail("unsafe-path", "transport paths must use '/' separators")

    components = path.split("/")
    for component in components:
        if component in {"", ".", ".."}:
            _fail("unsafe-path", f"empty, dot, and parent components are refused: {path!r}")
        if component.endswith((".", " ")):
            _fail("unsafe-path", f"components may not end with dot or space: {path!r}")
        if any(ord(character) < 32 or ord(character) == 127 for character in component):
            _fail("unsafe-path", f"control characters are refused: {path!r}")
        if any(character in _WINDOWS_INVALID for character in component):
            _fail("unsafe-path", f"Windows-reserved punctuation is refused: {path!r}")
        device_stem = component.split(".", 1)[0].rstrip(" .").casefold()
        if device_stem in _WINDOWS_RESERVED:
            _fail("unsafe-path", f"reserved Windows device name: {component!r}")
    return path


def _validate_path_set(paths: Sequence[str]) -> None:
    folded: set[str] = set()
    folded_components: list[tuple[str, ...]] = []
    for path in paths:
        key = path.casefold()
        if key in folded:
            _fail("path-collision", f"duplicate or case-fold-equivalent path: {path!r}")
        folded.add(key)
        folded_components.append(tuple(part.casefold() for part in path.split("/")))

    for index, components in enumerate(folded_components):
        for other_index, other in enumerate(folded_components):
            if index == other_index:
                continue
            if len(components) < len(other) and other[: len(components)] == components:
                _fail(
                    "path-collision",
                    f"a file path is also a parent path: {paths[index]!r}",
                )


def _absolute_local_path(value: os.PathLike[str] | str, field: str) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        _fail("root-invalid", f"{field} is not path-like: {exc}")
    if type(raw) is not str or not raw or "\x00" in raw:
        _fail("root-invalid", f"{field} must be a non-empty text path")
    if any(ord(character) < 32 for character in raw):
        _fail("root-invalid", f"{field} contains a control character")
    if raw.startswith(("\\\\", "//")):
        _fail("root-invalid", f"{field} must be local, not UNC or device-backed")
    if not os.path.isabs(raw):
        _fail("root-invalid", f"{field} must be absolute")

    drive, tail = os.path.splitdrive(raw)
    separators = {os.sep}
    if os.altsep:
        separators.add(os.altsep)
    lexical_tail = tail
    for separator in separators:
        lexical_tail = lexical_tail.replace(separator, "/")
    if any(part in {".", ".."} for part in lexical_tail.split("/") if part):
        _fail("root-invalid", f"{field} may not contain dot or parent components")
    del drive
    return Path(os.path.abspath(os.path.normpath(raw)))


def _path_chain(path: Path) -> tuple[Path, ...]:
    chain = [path]
    while chain[-1].parent != chain[-1]:
        chain.append(chain[-1].parent)
    chain.reverse()
    return tuple(chain)


def _stat_is_reparse(info: os.stat_result) -> bool:
    attributes = int(getattr(info, "st_file_attributes", 0))
    return stat.S_ISLNK(info.st_mode) or bool(attributes & _REPARSE_POINT)


def _path_is_reparse(path: Path) -> bool:
    return _stat_is_reparse(os.lstat(path))


def _assert_existing_safe(path: Path, *, final_directory: bool | None = None) -> None:
    for component in _path_chain(path):
        if not os.path.lexists(component):
            _fail("path-missing", f"path component does not exist: {component}")
        try:
            if _path_is_reparse(component):
                _fail("reparse-path", f"symlink or reparse point refused: {component}")
        except OSError as exc:
            _fail("path-inspection-failed", f"cannot inspect {component}: {exc}")
    if final_directory is not None:
        try:
            mode = os.lstat(path).st_mode
        except OSError as exc:
            _fail("path-inspection-failed", f"cannot inspect {path}: {exc}")
        if final_directory and not stat.S_ISDIR(mode):
            _fail("root-invalid", f"path must be a directory: {path}")
        if not final_directory and not stat.S_ISREG(mode):
            _fail("source-not-file", f"source must be a regular file: {path}")


def _normal_real(path: Path) -> str:
    return os.path.normcase(os.path.realpath(os.fspath(path)))


def _assert_contained(path: Path, root: Path) -> None:
    candidate = _normal_real(path)
    boundary = _normal_real(root)
    try:
        common = os.path.commonpath([candidate, boundary])
    except ValueError:
        _fail("path-escape", f"path is not on the root volume: {path}")
    if os.path.normcase(common) != boundary:
        _fail("path-escape", f"path escapes declared root: {path}")


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(getattr(info, "st_file_attributes", 0)),
    )


def _source_bindings(
    source_root: os.PathLike[str] | str,
    relative_paths: Sequence[str],
    chunk_bytes: int,
) -> tuple[_SourceBinding, ...]:
    root = _absolute_local_path(source_root, "source_root")
    _assert_existing_safe(root, final_directory=True)

    bindings: list[_SourceBinding] = []
    total_bytes = 0
    for relative_path in relative_paths:
        candidate = root.joinpath(*relative_path.split("/"))
        _assert_contained(candidate, root)
        _assert_existing_safe(candidate, final_directory=False)
        try:
            info = os.lstat(candidate)
        except OSError as exc:
            _fail("source-io", f"cannot stat {candidate}: {exc}")
        size = _exact_int(
            info.st_size,
            f"bytes for {relative_path}",
            maximum=MAX_FILE_BYTES,
        )
        chunks = (size + chunk_bytes - 1) // chunk_bytes
        if chunks > MAX_CHUNKS_PER_FILE:
            _fail(
                "chunk-count-bound-invalid",
                f"{relative_path!r} needs {chunks} chunks; maximum is {MAX_CHUNKS_PER_FILE}",
            )
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            _fail(
                "total-bytes-bound-invalid",
                f"source total exceeds {MAX_TOTAL_BYTES} bytes",
            )
        bindings.append(
            _SourceBinding(
                relative_path=relative_path,
                path=candidate,
                size=size,
                chunks=chunks,
                identity=_identity(info),
            )
        )
    return tuple(bindings)


def _read_bound_source(binding: _SourceBinding) -> bytes:
    _assert_existing_safe(binding.path, final_directory=False)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(binding.path, flags)
    except OSError as exc:
        _fail("source-io", f"cannot open {binding.path}: {exc}")
    try:
        before = os.fstat(descriptor)
        if _stat_is_reparse(before) or not stat.S_ISREG(before.st_mode):
            _fail("source-not-file", f"source changed type: {binding.path}")
        if _identity(before) != binding.identity:
            _fail("source-changed", f"source changed before read: {binding.path}")

        chunks: list[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError as exc:
        _fail("source-io", f"cannot read {binding.path}: {exc}")
    finally:
        os.close(descriptor)

    try:
        current = os.lstat(binding.path)
    except OSError as exc:
        _fail("source-changed", f"source disappeared after read: {binding.path}: {exc}")
    if (
        len(data) != binding.size
        or _identity(after) != binding.identity
        or _identity(current) != binding.identity
        or _stat_is_reparse(current)
    ):
        _fail("source-changed", f"source changed while being read: {binding.path}")
    return data


def _bundle_digest(files: Sequence[EvidenceFile], chunk_bytes: int) -> str:
    binding = {
        "chunk_bytes": chunk_bytes,
        "files": [
            {
                "bytes": item.size,
                "ordinal": item.ordinal,
                "path": item.path,
                "sha256": item.sha256,
            }
            for item in files
        ],
        "schema": SCHEMA,
        "version": VERSION,
    }
    return hashlib.sha256(_canonical_document(binding)).hexdigest()


def pack(
    source_root: os.PathLike[str] | str,
    relative_paths: Sequence[str],
    *,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
) -> bytes:
    """Return one canonical schema-v1 JSONL bundle for explicit source files."""

    chunk_bytes = _exact_int(
        chunk_bytes,
        "chunk_bytes",
        minimum=1,
        maximum=MAX_CHUNK_BYTES,
    )
    if isinstance(relative_paths, (str, bytes)):
        _fail("file-list-invalid", "relative_paths must be a sequence of paths")
    try:
        supplied = tuple(relative_paths)
    except TypeError as exc:
        _fail("file-list-invalid", f"relative_paths is not iterable: {exc}")
    if not 1 <= len(supplied) <= MAX_FILES:
        _fail("file-count-bound-invalid", f"file count must be 1..{MAX_FILES}")
    paths = tuple(_normalise_pack_path(path) for path in supplied)
    _validate_path_set(paths)
    bindings = _source_bindings(source_root, paths, chunk_bytes)

    lines = [
        _canonical_line(
            {
                "chunk_bytes": chunk_bytes,
                "file_count": len(bindings),
                "schema": SCHEMA,
                "type": "header",
                "version": VERSION,
            }
        )
    ]
    files: list[EvidenceFile] = []
    total_bytes = 0
    for ordinal, binding in enumerate(bindings):
        data = _read_bound_source(binding)
        file_sha256 = hashlib.sha256(data).hexdigest()
        item = EvidenceFile(
            ordinal=ordinal,
            path=binding.relative_path,
            size=len(data),
            sha256=file_sha256,
            chunks=binding.chunks,
        )
        files.append(item)
        total_bytes += len(data)
        lines.append(
            _canonical_line(
                {
                    "bytes": item.size,
                    "chunks": item.chunks,
                    "ordinal": ordinal,
                    "path": item.path,
                    "sha256": item.sha256,
                    "type": "file",
                }
            )
        )
        for chunk_ordinal, offset in enumerate(range(0, len(data), chunk_bytes)):
            chunk = data[offset : offset + chunk_bytes]
            lines.append(
                _canonical_line(
                    {
                        "data": base64.b64encode(chunk).decode("ascii"),
                        "file": ordinal,
                        "ordinal": chunk_ordinal,
                        "sha256": hashlib.sha256(chunk).hexdigest(),
                        "type": "chunk",
                    }
                )
            )

    bundle_sha256 = _bundle_digest(files, chunk_bytes)
    lines.append(
        _canonical_line(
            {
                "file_count": len(files),
                "sha256": bundle_sha256,
                "total_bytes": total_bytes,
                "type": "bundle",
            }
        )
    )
    result = b"".join(lines)
    if len(result) > MAX_BUNDLE_BYTES:
        _fail("bundle-bound-invalid", f"encoded bundle exceeds {MAX_BUNDLE_BYTES} bytes")
    return result


class _BundleReader:
    def __init__(self, bundle: bytes) -> None:
        self._stream = io.BytesIO(bundle)
        self.records = 0

    def record(self, expected: str) -> dict[str, Any]:
        raw = self._stream.readline(MAX_RECORD_BYTES + 2)
        if not raw:
            _fail("record-missing", f"missing {expected} record")
        if len(raw) > MAX_RECORD_BYTES + 1:
            _fail("record-bound-invalid", f"{expected} record is too large")
        if not raw.endswith(b"\n"):
            _fail("trailing-bytes", f"{expected} record has no LF terminator")
        line = raw[:-1]
        if not line:
            _fail("canonical-json-invalid", "empty JSONL records are refused")
        if line.startswith(b"\xef\xbb\xbf"):
            _fail("utf8-bom-invalid", "UTF-8 BOM is refused")
        try:
            text = line.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            _fail("utf8-invalid", f"invalid UTF-8 in {expected}: {exc}")
        try:
            document = json.loads(
                text,
                object_pairs_hook=_pairs_to_object,
                parse_constant=_reject_constant,
            )
        except _DuplicateJSONKey as exc:
            _fail("duplicate-json-key", f"duplicate JSON key: {exc}")
        except (json.JSONDecodeError, ValueError) as exc:
            _fail("json-invalid", f"invalid {expected} JSON: {exc}")
        if type(document) is not dict:
            _fail("type-invalid", f"{expected} record must be an object")
        if _canonical_document(document) != line:
            _fail("canonical-json-invalid", f"{expected} record is not canonical JSON")
        self.records += 1
        if self.records > MAX_FILES * (MAX_CHUNKS_PER_FILE + 1) + 2:
            _fail("record-count-bound-invalid", "bundle has too many records")
        return document

    def finish(self) -> None:
        if self._stream.read(1):
            _fail("trailing-records", "records or bytes follow the bundle record")


def _parse_bundle(value: bytes | bytearray | memoryview) -> _ParsedBundle:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        _fail("bundle-type-invalid", "bundle must be bytes-like")
    bundle = bytes(value)
    if not bundle:
        _fail("bundle-empty", "bundle is empty")
    if len(bundle) > MAX_BUNDLE_BYTES:
        _fail("bundle-bound-invalid", f"encoded bundle exceeds {MAX_BUNDLE_BYTES} bytes")

    reader = _BundleReader(bundle)
    header = reader.record("header")
    _require_keys(header, _HEADER_KEYS, "header")
    record_type = _exact_string(header["type"], "header.type")
    schema = _exact_string(header["schema"], "header.schema")
    version = _exact_int(
        header["version"],
        "header.version",
        minimum=VERSION,
        maximum=VERSION,
    )
    if record_type != "header" or schema != SCHEMA or version != VERSION:
        _fail("schema-version-invalid", "header schema, version, or type is unsupported")
    chunk_bytes = _exact_int(
        header["chunk_bytes"],
        "header.chunk_bytes",
        minimum=1,
        maximum=MAX_CHUNK_BYTES,
    )
    file_count = _exact_int(
        header["file_count"],
        "header.file_count",
        minimum=1,
        maximum=MAX_FILES,
    )

    files: list[EvidenceFile] = []
    payloads: list[bytes] = []
    paths: list[str] = []
    total_bytes = 0
    for file_ordinal in range(file_count):
        document = reader.record(f"file {file_ordinal}")
        _require_keys(document, _FILE_KEYS, f"file {file_ordinal}")
        if document["type"] != "file":
            _fail("record-order-invalid", f"expected file record {file_ordinal}")
        ordinal = _exact_int(
            document["ordinal"],
            f"file {file_ordinal}.ordinal",
            maximum=MAX_FILES - 1,
        )
        if ordinal != file_ordinal:
            _fail("record-order-invalid", f"expected file ordinal {file_ordinal}, got {ordinal}")
        path = _validate_relative_path(document["path"])
        paths.append(path)
        _validate_path_set(paths)
        size = _exact_int(
            document["bytes"],
            f"file {file_ordinal}.bytes",
            maximum=MAX_FILE_BYTES,
        )
        chunks = _exact_int(
            document["chunks"],
            f"file {file_ordinal}.chunks",
            maximum=MAX_CHUNKS_PER_FILE,
        )
        expected_chunks = (size + chunk_bytes - 1) // chunk_bytes
        if chunks != expected_chunks:
            _fail(
                "chunk-count-invalid",
                f"file {file_ordinal} declares {chunks} chunks, expected {expected_chunks}",
            )
        declared_sha256 = _sha256(document["sha256"], f"file {file_ordinal}.sha256")
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            _fail(
                "total-bytes-bound-invalid",
                f"declared total exceeds {MAX_TOTAL_BYTES} bytes",
            )

        materialized = bytearray()
        for chunk_ordinal in range(chunks):
            chunk_document = reader.record(f"chunk {file_ordinal}/{chunk_ordinal}")
            _require_keys(
                chunk_document,
                _CHUNK_KEYS,
                f"chunk {file_ordinal}/{chunk_ordinal}",
            )
            if chunk_document["type"] != "chunk":
                _fail("record-order-invalid", "expected chunk record")
            chunk_file = _exact_int(
                chunk_document["file"],
                "chunk.file",
                maximum=MAX_FILES - 1,
            )
            actual_ordinal = _exact_int(
                chunk_document["ordinal"],
                "chunk.ordinal",
                maximum=MAX_CHUNKS_PER_FILE - 1,
            )
            if chunk_file != file_ordinal or actual_ordinal != chunk_ordinal:
                _fail(
                    "record-order-invalid",
                    f"expected chunk {file_ordinal}/{chunk_ordinal}",
                )
            encoded = _exact_string(chunk_document["data"], "chunk.data")
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as exc:
                _fail("base64-invalid", f"invalid strict Base64: {exc}")
            if base64.b64encode(decoded).decode("ascii") != encoded:
                _fail("base64-invalid", "Base64 is not in canonical padded form")
            expected_size = min(chunk_bytes, size - chunk_ordinal * chunk_bytes)
            if len(decoded) != expected_size:
                _fail(
                    "chunk-size-invalid",
                    f"chunk {file_ordinal}/{chunk_ordinal} has {len(decoded)} bytes, expected {expected_size}",
                )
            chunk_sha256 = _sha256(chunk_document["sha256"], "chunk.sha256")
            if hashlib.sha256(decoded).hexdigest() != chunk_sha256:
                _fail("chunk-hash-mismatch", f"chunk {file_ordinal}/{chunk_ordinal} hash differs")
            materialized.extend(decoded)

        data = bytes(materialized)
        if len(data) != size:
            _fail("file-size-mismatch", f"file {file_ordinal} size differs")
        if hashlib.sha256(data).hexdigest() != declared_sha256:
            _fail("file-hash-mismatch", f"file {file_ordinal} hash differs")
        files.append(
            EvidenceFile(
                ordinal=file_ordinal,
                path=path,
                size=size,
                sha256=declared_sha256,
                chunks=chunks,
            )
        )
        payloads.append(data)

    trailer = reader.record("bundle")
    _require_keys(trailer, _BUNDLE_KEYS, "bundle")
    if trailer["type"] != "bundle":
        _fail("record-order-invalid", "expected final bundle record")
    trailer_count = _exact_int(
        trailer["file_count"],
        "bundle.file_count",
        minimum=1,
        maximum=MAX_FILES,
    )
    trailer_total = _exact_int(
        trailer["total_bytes"],
        "bundle.total_bytes",
        maximum=MAX_TOTAL_BYTES,
    )
    trailer_sha256 = _sha256(trailer["sha256"], "bundle.sha256")
    if trailer_count != file_count or trailer_total != total_bytes:
        _fail("bundle-summary-mismatch", "bundle count or byte total differs")
    expected_bundle_sha256 = _bundle_digest(files, chunk_bytes)
    if trailer_sha256 != expected_bundle_sha256:
        _fail("bundle-hash-mismatch", "bundle binding hash differs")
    reader.finish()

    return _ParsedBundle(
        manifest=EvidenceManifest(
            schema=SCHEMA,
            version=VERSION,
            chunk_bytes=chunk_bytes,
            total_bytes=total_bytes,
            bundle_sha256=trailer_sha256,
            files=tuple(files),
        ),
        payloads=tuple(payloads),
    )


def verify(bundle: bytes | bytearray | memoryview) -> EvidenceManifest:
    """Validate a bundle without touching the filesystem."""

    return _parse_bundle(bundle).manifest


def _make_safe_parent(stage: Path, relative_path: str) -> Path:
    current = stage
    for component in relative_path.split("/")[:-1]:
        current = current / component
        if os.path.lexists(current):
            _assert_existing_safe(current, final_directory=True)
        else:
            try:
                os.mkdir(current)
            except OSError as exc:
                _fail("unpack-io", f"cannot create staging directory {current}: {exc}")
        _assert_contained(current, stage)
        _assert_existing_safe(current, final_directory=True)
    return current


def _write_file(path: Path, data: bytes) -> None:
    with open(path, "xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _publish_staging(stage: Path, target: Path) -> None:
    """Atomically rename one directory while refusing an existing target."""

    if os.name == "nt":
        os.rename(stage, target)
        return

    if sys.platform.startswith("linux"):
        library = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(library, "renameat2", None)
        if renameat2 is None:
            _fail("atomic-publish-unsupported", "renameat2 is unavailable")
        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100,
            os.fsencode(stage),
            -100,
            os.fsencode(target),
            1,
        )
        if result == 0:
            return
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(error, os.strerror(error), os.fspath(target))
        if error in {errno.ENOSYS, getattr(errno, "ENOTSUP", errno.ENOSYS)}:
            _fail("atomic-publish-unsupported", os.strerror(error))
        raise OSError(error, os.strerror(error), os.fspath(target))

    _fail("atomic-publish-unsupported", f"no no-replace directory rename for {sys.platform}")


def _cleanup_staging(stage: Path) -> None:
    if not os.path.lexists(stage):
        return
    if stage.is_symlink():
        stage.unlink()
    else:
        shutil.rmtree(stage)


def unpack(
    bundle: bytes | bytearray | memoryview,
    target_root: os.PathLike[str] | str,
) -> EvidenceManifest:
    """Verify fully, then publish all files under one new target directory."""

    parsed = _parse_bundle(bundle)
    target = _absolute_local_path(target_root, "target_root")
    if target.parent == target or not target.name:
        _fail("root-invalid", "target_root must name a child directory")
    parent = target.parent
    _assert_existing_safe(parent, final_directory=True)
    if os.path.lexists(target):
        _fail("target-exists", f"target root already exists: {target}")

    stage: Path | None = None
    published = False
    try:
        stage = Path(
            tempfile.mkdtemp(
                prefix=f".{target.name}.evidence-",
                dir=parent,
            )
        )
        _assert_contained(stage, parent)
        _assert_existing_safe(stage, final_directory=True)

        for item, data in zip(parsed.manifest.files, parsed.payloads, strict=True):
            destination = stage.joinpath(*item.path.split("/"))
            _assert_contained(destination, stage)
            destination_parent = _make_safe_parent(stage, item.path)
            _assert_existing_safe(destination_parent, final_directory=True)
            _assert_contained(destination_parent, stage)
            if os.path.lexists(destination):
                _fail("staging-collision", f"staging file already exists: {destination}")
            _write_file(destination, data)
            _assert_existing_safe(destination, final_directory=False)
            if os.lstat(destination).st_size != item.size:
                _fail("staging-write-mismatch", f"staging size differs: {destination}")

        _assert_existing_safe(parent, final_directory=True)
        _assert_existing_safe(stage, final_directory=True)
        if os.path.lexists(target):
            _fail("target-exists", f"target root appeared before publish: {target}")
        try:
            _publish_staging(stage, target)
        except FileExistsError:
            _fail("target-exists", f"target root won the publish race: {target}")
        published = True
        return parsed.manifest
    except Exception as exc:
        if stage is not None and not published and os.path.lexists(stage):
            try:
                _cleanup_staging(stage)
            except OSError as cleanup_error:
                raise EvidenceTransportError(
                    "staging-cleanup-failed",
                    f"cannot remove {stage}: {cleanup_error}",
                ) from exc
        if isinstance(exc, EvidenceTransportError):
            raise
        if isinstance(exc, OSError):
            raise EvidenceTransportError("unpack-io", str(exc)) from exc
        raise


def _read_bundle_path(value: str) -> bytes:
    if value == "-":
        data = sys.stdin.buffer.read(MAX_BUNDLE_BYTES + 1)
    else:
        try:
            with open(value, "rb") as stream:
                data = stream.read(MAX_BUNDLE_BYTES + 1)
        except OSError as exc:
            _fail("bundle-read-failed", f"cannot read {value}: {exc}")
    if len(data) > MAX_BUNDLE_BYTES:
        _fail("bundle-bound-invalid", f"encoded bundle exceeds {MAX_BUNDLE_BYTES} bytes")
    return data


def _manifest_line(manifest: EvidenceManifest) -> bytes:
    return _canonical_line(
        {
            "bundle_sha256": manifest.bundle_sha256,
            "chunk_bytes": manifest.chunk_bytes,
            "files": [
                {
                    "bytes": item.size,
                    "chunks": item.chunks,
                    "ordinal": item.ordinal,
                    "path": item.path,
                    "sha256": item.sha256,
                }
                for item in manifest.files
            ],
            "schema": manifest.schema,
            "total_bytes": manifest.total_bytes,
            "version": manifest.version,
        }
    )


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    pack_parser = commands.add_parser("pack", help="write a bundle to stdout")
    pack_parser.add_argument("--source-root", required=True)
    pack_parser.add_argument("--chunk-bytes", type=int, default=DEFAULT_CHUNK_BYTES)
    pack_parser.add_argument("files", nargs="+")

    verify_parser = commands.add_parser("verify", help="verify a bundle without writes")
    verify_parser.add_argument("bundle", help="bundle file, or '-' for stdin")

    unpack_parser = commands.add_parser("unpack", help="publish into an absent target root")
    unpack_parser.add_argument("bundle", help="bundle file, or '-' for stdin")
    unpack_parser.add_argument("target_root")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    try:
        if args.command == "pack":
            sys.stdout.buffer.write(
                pack(args.source_root, args.files, chunk_bytes=args.chunk_bytes)
            )
            sys.stdout.buffer.flush()
            return 0
        bundle = _read_bundle_path(args.bundle)
        if args.command == "verify":
            manifest = verify(bundle)
        else:
            manifest = unpack(bundle, args.target_root)
        sys.stdout.buffer.write(_manifest_line(manifest))
        sys.stdout.buffer.flush()
        return 0
    except EvidenceTransportError as exc:
        print(f"ERROR[{exc.code}]: {exc.detail}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
