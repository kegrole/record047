"""Safe archive extraction for zip and tar archives using only the stdlib."""

from .events import Event
from .extractor import ExtractionResult, extract_archive
from .limits import Limits
from .report import ReportRow, build_report, write_report

__all__ = [
    "Event",
    "ExtractionResult",
    "Limits",
    "ReportRow",
    "build_report",
    "extract_archive",
    "write_report",
]

__version__ = "1.0.0"
