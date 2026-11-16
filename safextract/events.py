"""Security events emitted while validating and extracting an archive."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


EVENT_TRAVERSAL = "path_traversal"
EVENT_ABSOLUTE = "absolute_path"
EVENT_WINDOWS = "windows_path"
EVENT_SYMLINK = "unsafe_symlink"
EVENT_LIMIT = "limit_exceeded"
EVENT_UNSUPPORTED = "unsupported_entry"


@dataclass(frozen=True)
class Event:
    """A single rejected entry or aborted extraction event."""

    type: str
    entry: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "entry": self.entry, "reason": self.reason}


class ExtractionError(Exception):
    """Raised when extraction must be aborted; carries the triggering event."""

    def __init__(self, event: Event) -> None:
        super().__init__(event.reason)
        self.event = event
