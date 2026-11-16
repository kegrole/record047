"""Path validation shared by zip and tar extraction.

Archive entry names use POSIX style, but archives crafted on (or for) Windows
may contain drive letters, backslashes or UNC prefixes.  Every entry name is
therefore checked before it is joined with the extraction directory.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .events import (
    EVENT_ABSOLUTE,
    EVENT_TRAVERSAL,
    EVENT_UNSUPPORTED,
    EVENT_WINDOWS,
    Event,
    ExtractionError,
)

_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_UNC_RE = re.compile(r"^[\\\\]{2}[^\\\\]")


def classify_unsafe_name(name: str) -> Event | None:
    """Return a security event for *name*, or ``None`` when it is safe.

    Rejected forms:
      * Windows drive paths such as ``C:\\evil.txt`` or ``C:/evil.txt``;
      * UNC / backslash rooted paths such as ``\\\\share\\x`` or ``\\evil``;
      * POSIX absolute paths such as ``/etc/passwd``;
      * any normalized ``..`` component (e.g. ``../evil.txt`` or ``a/../../b``).
    Backslashes are always treated as separators rather than literal bytes.
    """

    if not name or not name.strip():
        return Event(EVENT_TRAVERSAL, name, "空条目名属于非法路径")

    if _DRIVE_RE.match(name):
        return Event(
            EVENT_WINDOWS,
            name,
            f"路径穿越：Windows 盘符形式路径 {name!r} 不允许",
        )
    if _UNC_RE.match(name) or name.startswith("\\"):
        return Event(
            EVENT_WINDOWS,
            name,
            f"路径穿越：Windows UNC/反斜杠根路径 {name!r} 不允许",
        )
    if name.startswith("/"):
        return Event(
            EVENT_ABSOLUTE,
            name,
            f"绝对路径条目 {name!r} 不允许写入解包目录之外",
        )

    parts = re.split(r"[\\/]", name)
    if any(part == ".." for part in parts):
        return Event(
            EVENT_TRAVERSAL,
            name,
            f"路径穿越：条目名 {name!r} 包含 .. 组件",
        )

    if os.path.isabs(name) or Path(name).is_absolute():
        return Event(
            EVENT_ABSOLUTE,
            name,
            f"绝对路径条目 {name!r} 不允许写入解包目录之外",
        )
    return None


def safe_destination(dest_root: Path, name: str) -> Path:
    """Validate *name* and join it onto *dest_root* in strict mode."""

    event = classify_unsafe_name(name)
    if event is not None:
        raise ExtractionError(event)
    return (dest_root / name).resolve(strict=False)


def ensure_within(dest_root: Path, candidate: Path) -> bool:
    """Return whether *candidate* stays inside *dest_root*."""

    root = dest_root.resolve(strict=False)
    target = candidate.resolve(strict=False)
    try:
        target.relative_to(root)
    except ValueError:
        return False
    return True


def safe_symlink_destination(
    dest_root: Path, entry_name: str, link_target: str
) -> Event | None:
    """Validate a symbolic link's effective target against *dest_root*.

    Both the link target itself (absolute or containing ``..``) and the path
    reached after resolving existing parent links must remain inside the root.
    """

    name_event = classify_unsafe_name(entry_name)
    if name_event is not None:
        return name_event
    if not link_target or not link_target.strip():
        return Event(EVENT_UNSUPPORTED, entry_name, "符号链接目标为空")

    link_path = (dest_root / entry_name).resolve(strict=False)
    if os.path.isabs(link_target):
        effective = Path(link_target)
    else:
        effective = (link_path.parent / link_target)

    if not ensure_within(dest_root, effective):
        return Event(
            "unsafe_symlink",
            entry_name,
            (
                f"符号链接目标 {link_target!r} 解析后落在解包目录之外，已拒绝该条目"
            ),
        )
    return None
