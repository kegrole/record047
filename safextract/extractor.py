"""Atomic, policy-enforced extraction of zip and tar archives."""

from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import entries as entry_mod
from .events import (
    EVENT_UNSUPPORTED,
    Event,
    ExtractionError,
)
from .limits import (
    Limits,
    RatioTracker,
    file_count_event,
    single_file_event,
    total_size_event,
)
from .paths import (
    classify_unsafe_name,
    ensure_within,
    safe_destination,
    safe_symlink_destination,
)

_READ_CHUNK = 64 * 1024
SETUID_SETGID_MASK = 0o6000


@dataclass
class ExtractionResult:
    archive: str
    events: list[Event] = field(default_factory=list)
    written_files: int = 0
    aborted: bool = False
    destination: str | None = None

    def to_row(self) -> dict:
        return {
            "archive": self.archive,
            "events": [event.to_dict() for event in self.events],
            "written_files": self.written_files,
            "aborted": self.aborted,
        }


class _Counters:
    def __init__(self) -> None:
        self.bytes = 0
        self.files = 0


class _CountingReader:
    """File wrapper counting raw (compressed) bytes consumed by tarfile."""

    def __init__(self, handle) -> None:
        self._handle = handle
        self.bytes_read = 0

    def read(self, size: int = -1):
        data = self._handle.read(size)
        self.bytes_read += len(data)
        return data

    def close(self) -> None:
        self._handle.close()

    def seekable(self) -> bool:
        return False

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def extract_archive(
    archive_path: str | os.PathLike,
    dest_dir: str | os.PathLike,
    limits: Limits | None = None,
) -> ExtractionResult:
    """Extract one archive into ``dest_dir``; never leave a partial result.

    Extraction happens in a temporary sibling directory and the destination is
    swapped in atomically.  Any policy violation aborts and removes staging.
    """

    archive_path = Path(archive_path)
    dest_dir = Path(dest_dir)
    limits = limits or Limits()
    result = ExtractionResult(archive=str(archive_path))

    kind = entry_mod.detect_archive(archive_path)
    parent = dest_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{dest_dir.name}.stage-", dir=parent)
    )
    backup: Path | None = None

    try:
        if kind == "zip":
            with zipfile.ZipFile(archive_path) as archive:
                _extract_zip(archive, staging, limits, result)
        else:
            with archive_path.open("rb") as raw:
                reader = _CountingReader(raw)
                with tarfile.open(fileobj=reader, mode="r|*") as archive:
                    _extract_tar(archive, reader, staging, limits, result)
    except ExtractionError as exc:
        result.events.append(exc.event)
        result.aborted = True
    except Exception as exc:  # pragma: no cover - defensive safety net
        result.events.append(
            Event("extraction_error", "", f"解压失败: {exc}")
        )
        result.aborted = True

    if result.aborted:
        shutil.rmtree(staging, ignore_errors=True)
        return result

    try:
        if dest_dir.exists():
            backup = parent / f".{dest_dir.name}.old-{os.getpid()}-{id(staging)}"
            os.rename(dest_dir, backup)
        os.replace(staging, dest_dir)
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)
        result.destination = str(dest_dir)
    except OSError as exc:
        if backup is not None and backup.exists() and not dest_dir.exists():
            os.rename(backup, dest_dir)
        shutil.rmtree(staging, ignore_errors=True)
        result.events.append(Event("extraction_error", "", str(exc)))
        result.aborted = True
    return result


def _safe_mode(mode: int | None, default: int) -> int:
    if mode is None:
        return default
    return (mode & 0o7777) & ~SETUID_SETGID_MASK


def _prepare_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _check_file_limits(
    entry_name: str,
    entry_size: int,
    counters: _Counters,
    limits: Limits,
) -> None:
    if entry_size > limits.max_single_file_bytes:
        raise ExtractionError(
            single_file_event(
                entry_name, entry_size, limits.max_single_file_bytes
            )
        )
    if counters.files + 1 > limits.max_file_count:
        raise ExtractionError(
            file_count_event(
                entry_name, counters.files + 1, limits.max_file_count
            )
        )
    if counters.bytes + entry_size > limits.max_total_bytes:
        raise ExtractionError(
            total_size_event(
                entry_name,
                counters.bytes + entry_size,
                limits.max_total_bytes,
            )
        )


def _stream_to_file(
    stream,
    out_path: Path,
    entry_name: str,
    counters: _Counters,
    limits: Limits,
) -> int:
    written = 0
    with out_path.open("wb") as handle:
        while True:
            chunk = stream.read(_READ_CHUNK)
            if not chunk:
                break
            written += len(chunk)
            counters.bytes += len(chunk)
            if counters.bytes > limits.max_total_bytes:
                raise ExtractionError(
                    total_size_event(
                        entry_name,
                        counters.bytes,
                        limits.max_total_bytes,
                    )
                )
            handle.write(chunk)
    return written


def _apply_attrs(
    path: Path, mode: int | None, mtime: float | None, default_mode: int
) -> None:
    os.chmod(path, _safe_mode(mode, default_mode))
    if mtime is not None:
        os.utime(path, (mtime, mtime), follow_symlinks=False)


def _extract_zip(
    archive: zipfile.ZipFile,
    root: Path,
    limits: Limits,
    result: ExtractionResult,
) -> None:
    counters = _Counters()
    ratios = RatioTracker(limits.max_compression_ratio)
    dir_timestamps: list[tuple[Path, float]] = []

    for entry in entry_mod.zip_entries(archive):
        target = safe_destination(root, entry.name)

        if entry.kind == "dir":
            target.mkdir(parents=True, exist_ok=True)
            os.chmod(target, _safe_mode(entry.mode, 0o755))
            if entry.mtime is not None:
                dir_timestamps.append((target, entry.mtime))
            continue

        if entry.kind == "symlink":
            with archive.open(entry.source, "r") as stream:
                link_target = stream.read().decode("utf-8", "replace")
            event = safe_symlink_destination(root, entry.name, link_target)
            if event is not None:
                raise ExtractionError(event)
            _prepare_parent(target)
            os.symlink(link_target, target)
            continue

        if entry.kind != "file":
            raise ExtractionError(
                Event(
                    EVENT_UNSUPPORTED,
                    entry.name,
                    f"不支持的 zip 条目类型: {entry.kind}",
                )
            )

        _check_file_limits(entry.name, entry.size, counters, limits)
        _check_zip_ratio(entry, limits)
        _prepare_parent(target)
        with archive.open(entry.source, "r") as stream:
            _stream_to_file(
                stream, target, entry.name, counters, limits
            )
        counters.files += 1
        result.written_files += 1
        ratios.add(entry.size, max(entry.stored_size, 1))
        _apply_attrs(target, entry.mode, entry.mtime, 0o644)

    for path, mtime in sorted(
        dir_timestamps, key=lambda item: len(item[0].parts), reverse=True
    ):
        os.utime(path, (mtime, mtime), follow_symlinks=False)


def _check_zip_ratio(entry, limits: Limits) -> None:
    if entry.stored_size <= 0 or entry.size <= 0:
        return
    ratio = entry.size / entry.stored_size
    if ratio > limits.max_compression_ratio:
        from .limits import compression_ratio_event

        raise ExtractionError(
            compression_ratio_event(
                entry.name, ratio, limits.max_compression_ratio
            )
        )


def _extract_tar(
    archive: tarfile.TarFile,
    reader: _CountingReader,
    root: Path,
    limits: Limits,
    result: ExtractionResult,
) -> None:
    counters = _Counters()
    ratios = RatioTracker(limits.max_compression_ratio)
    dir_timestamps: list[tuple[Path, float]] = []

    for entry in entry_mod.tar_entries(archive):
        bytes_before = reader.bytes_read
        target = safe_destination(root, entry.name)

        if entry.kind == "dir":
            target.mkdir(parents=True, exist_ok=True)
            os.chmod(target, _safe_mode(entry.mode, 0o755))
            if entry.mtime is not None:
                dir_timestamps.append((target, entry.mtime))
            continue

        if entry.kind == "symlink":
            event = safe_symlink_destination(
                root, entry.name, entry.link_target or ""
            )
            if event is not None:
                raise ExtractionError(event)
            _prepare_parent(target)
            os.symlink(entry.link_target, target)
            continue

        if entry.kind == "hardlink":
            name_event = classify_unsafe_name(entry.link_target or "")
            if name_event is not None:
                raise ExtractionError(name_event)
            link_source = (root / entry.link_target).resolve(strict=False)
            if not ensure_within(root, link_source) or not link_source.exists():
                raise ExtractionError(
                    Event(
                        "unsafe_symlink",
                        entry.name,
                        (
                            f"硬链接目标 {entry.link_target!r} 不存在或越界，已拒绝该条目"
                        ),
                    )
                )
            _prepare_parent(target)
            os.link(link_source, target)
            continue

        if entry.kind != "file":
            raise ExtractionError(
                Event(
                    EVENT_UNSUPPORTED,
                    entry.name,
                    f"不支持的 tar 条目类型: {entry.kind}",
                )
            )

        _check_file_limits(entry.name, entry.size, counters, limits)
        _prepare_parent(target)
        stream = archive.extractfile(entry.source)
        if stream is None:
            raise ExtractionError(
                Event(EVENT_UNSUPPORTED, entry.name, "条目没有可读负载")
            )
        with stream:
            _stream_to_file(stream, target, entry.name, counters, limits)
        counters.files += 1
        result.written_files += 1
        stored_delta = max(reader.bytes_read - bytes_before, 1)
        ratios.add(entry.size, stored_delta)
        ratio_event = ratios.event(entry.name)
        if ratio_event is not None:
            raise ExtractionError(ratio_event)
        _apply_attrs(target, entry.mode, entry.mtime, 0o644)

    for path, mtime in sorted(
        dir_timestamps, key=lambda item: len(item[0].parts), reverse=True
    ):
        os.utime(path, (mtime, mtime), follow_symlinks=False)
