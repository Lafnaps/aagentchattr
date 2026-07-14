"""Small crash-safe I/O primitives shared by queue producers and workers.

The lock is deliberately a separate, never-replaced file.  Every operation
which can replace/archive the active queue and every producer append takes the
same cross-process lock, so a startup maintenance pass cannot race an append.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
from pathlib import Path


class DeliveryBackpressureError(RuntimeError):
    """Durable delivery storage reached its fail-closed safety ceiling."""


def write_backpressure_marker(queue_file: Path, component: str,
                              current_bytes: int, limit_bytes: int) -> Path:
    """Publish an actionable durable marker without deleting queue data."""
    queue_file = Path(queue_file)
    marker = queue_file.with_name(queue_file.name + ".backpressure.json")
    payload = json.dumps({
        "version": 1,
        "state": "delivery-backpressure",
        "component": str(component),
        "queue": str(queue_file.resolve()),
        "current_bytes": int(current_bytes),
        "limit_bytes": int(limit_bytes),
        "at_ns": time.time_ns(),
        "action": (
            "manual reconciliation/archival required; no data was deleted"
        ),
    }, ensure_ascii=True, sort_keys=True).encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(
        prefix=marker.name + ".tmp-", dir=str(marker.parent)
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, marker)
        fsync_directory_best_effort(marker.parent)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return marker


def _fsync_directory(path: Path) -> None:
    """Best-effort durable directory metadata flush (POSIX and Windows)."""
    path = Path(path)
    if os.name != "nt":
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        fd = os.open(str(path), flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return

    # Python cannot os.open() a Windows directory.  FILE_FLAG_BACKUP_SEMANTICS
    # is the documented way to obtain a directory handle for FlushFileBuffers.
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path), 0x80000000, 0x00000007, None, 3, 0x02000000, None,
    )
    invalid = wintypes.HANDLE(-1).value
    if handle == invalid:
        raise OSError(ctypes.get_last_error(), "CreateFileW(directory) failed")
    try:
        if not kernel32.FlushFileBuffers(handle):
            raise OSError(ctypes.get_last_error(), "FlushFileBuffers(directory) failed")
    finally:
        kernel32.CloseHandle(handle)


def fsync_directory_best_effort(path: Path) -> None:
    """Flush directory metadata without turning unsupported FSes into loss."""
    try:
        _fsync_directory(Path(path))
    except OSError:
        # Some Windows/network filesystems reject directory flushes.  File
        # contents are still fsynced; callers cannot safely do more in stdlib.
        pass


def queue_lock_path(queue_file: Path) -> Path:
    return Path(queue_file).with_name(Path(queue_file).name + ".lock")


@contextlib.contextmanager
def _exclusive_file_lock(lock_path: Path, timeout: float):
    """Acquire one byte of *lock_path* as a bounded cross-process mutex."""
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    existed = lock_path.exists()
    stream = open(lock_path, "a+b")
    if not existed:
        fsync_directory_best_effort(lock_path.parent)
    deadline = time.monotonic() + max(0.0, float(timeout))
    acquired = False
    try:
        while not acquired:
            try:
                if os.name == "nt":
                    import msvcrt
                    stream.seek(0, os.SEEK_END)
                    if stream.tell() == 0:
                        stream.write(b"\0")
                        stream.flush()
                        os.fsync(stream.fileno())
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except (OSError, IOError):
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"timed out locking {lock_path.name}")
                time.sleep(0.01)
        yield
    finally:
        if acquired:
            try:
                if os.name == "nt":
                    import msvcrt
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            finally:
                stream.close()
        else:
            stream.close()


@contextlib.contextmanager
def queue_file_lock(queue_file: Path, timeout: float = 30.0):
    """Exclusive cross-process lock shared by producers and maintenance.

    A non-blocking OS primitive plus a bounded retry loop avoids an immortal
    process hang if a filesystem/lock implementation misbehaves.
    """
    lock_path = queue_lock_path(Path(queue_file))
    with _exclusive_file_lock(lock_path, timeout):
        yield


def queue_consumer_lease_path(queue_file: Path) -> Path:
    """Lock file used only by delivery consumers, never by producers."""
    queue_file = Path(queue_file)
    return queue_file.with_name(queue_file.name + ".consumer.lock")


@contextlib.contextmanager
def queue_consumer_lease(queue_file: Path, timeout: float = 0.0):
    """Single-consumer lease for one complete delivery transaction.

    This lock is deliberately separate from :func:`queue_file_lock`: queue
    producers may continue their short append/fsync critical sections while a
    consumer is waiting for or actively driving an interactive terminal.
    """
    with _exclusive_file_lock(queue_consumer_lease_path(queue_file), timeout):
        yield


def append_bytes_durable(path: Path, data: bytes) -> None:
    """Append and fsync bytes, including the parent entry on first create."""
    path = Path(path)
    existed = path.exists()
    with open(path, "ab") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if not existed:
        fsync_directory_best_effort(path.parent)


def write_unique_evidence(path: Path, data: bytes,
                          label: str = "quarantine") -> Path:
    """Create a durable evidence file without ever replacing an older one.

    ``mkstemp`` provides the O_EXCL name allocation needed when clocks are
    frozen, several corruptions happen in one tick, or multiple processes
    quarantine concurrently.  The caller may delete/move the source only
    after this function returns.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    prefix = (
        f"{path.name}.{label}-{time.strftime('%Y%m%dT%H%M%S')}-"
        f"{time.time_ns()}-{os.getpid()}-"
    )
    fd, target_name = tempfile.mkstemp(prefix=prefix, dir=str(path.parent))
    target = Path(target_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(bytes(data))
            stream.flush()
            os.fsync(stream.fileno())
        fsync_directory_best_effort(path.parent)
        return target
    except Exception:
        try:
            os.unlink(target)
        except OSError:
            pass
        raise
