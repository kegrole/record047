"""Per-archive extraction report structures and JSON serialization."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .events import Event


@dataclass
class ReportRow:
    archive: str
    events: list[Event]
    written_files: int
    aborted: bool

    def to_dict(self) -> dict:
        return {
            "archive": self.archive,
            "events": [event.to_dict() for event in self.events],
            "written_files": self.written_files,
            "aborted": self.aborted,
        }


def build_report(results: Iterable) -> list[dict]:
    return [result.to_row() for result in results]


def write_report(rows: list[dict], out_path: str | Path) -> None:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        json.dump(rows, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def summarize(rows: list[dict]) -> tuple[int, int, int]:
    archive_count = len(rows)
    event_count = sum(len(row["events"]) for row in rows)
    rejected_entries = sum(
        1 for row in rows for event in row["events"]
    )
    return archive_count, event_count, rejected_entries
