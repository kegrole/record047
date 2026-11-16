"""Uniform archive entry descriptors built from zipfile/tarfile metadata."""

from __future__ import annotations

import stat
import calendar
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass
class ArchiveEntry:
    name: str
    kind: str  # "file" | "dir" | "symlink" | "hardlink" | "other"
    size: int
    stored_size: int
    mode: int | None
    mtime: float | None
    link_target: str | None
    source: object

    @property
    def is_regular_file(self) -> bool:
        return self.kind == "file"


def zip_entries(archive: zipfile.ZipFile) -> Iterator[ArchiveEntry]:
    for info in archive.infolist():
        name = info.filename
        mode_attr = info.external_attr >> 16
        mode = mode_attr & 0o7777 if mode_attr else None
        unix = (
            info.create_system == 3
            and stat.S_ISLNK(info.external_attr >> 16)
        )
        if unix:
            kind = "symlink"
            link_target = None  # target bytes are the entry payload
        elif info.is_dir():
            kind = "dir"
            link_target = None
        else:
            kind = "file"
            link_target = None
        yield ArchiveEntry(
            name=name,
            kind=kind,
            size=info.file_size,
            stored_size=info.compress_size,
            mode=mode,
            mtime=calendar.timegm(info.date_time + (0, 0, -1)),
            link_target=link_target,
            source=info,
        )


def tar_entries(archive: tarfile.TarFile) -> Iterator[ArchiveEntry]:
    # Stream mode ("r|*") yields members in order; getmembers() would exhaust
    # the stream and make later extractfile() calls fail.
    for member in archive:
        if member.isdir():
            kind = "dir"
            link_target = None
        elif member.issym():
            kind = "symlink"
            link_target = member.linkname
        elif member.islnk():
            kind = "hardlink"
            link_target = member.linkname
        elif member.isfile():
            kind = "file"
            link_target = None
        else:
            kind = "other"
            link_target = member.linkname or None
        yield ArchiveEntry(
            name=member.name,
            kind=kind,
            size=member.size,
            stored_size=member.size,  # replaced with compressed stream totals
            mode=member.mode,
            mtime=float(member.mtime),
            link_target=link_target,
            source=member,
        )


def detect_archive(path: Path) -> str:
    """Return ``"zip"`` or ``"tar"`` based on magic bytes, then suffix."""

    with path.open("rb") as handle:
        signature = handle.read(262)
    if zipfile.is_zipfile(path):
        return "zip"
    if tarfile.is_tarfile(path):
        return "tar"
    if signature[:4] == b"PK\x03\x04":
        return "zip"
    raise ValueError(f"无法识别的归档格式: {path}")
