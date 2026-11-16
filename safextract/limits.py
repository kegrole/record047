"""Configurable extraction limits and the events they produce."""

from __future__ import annotations

from dataclasses import dataclass

from .events import EVENT_LIMIT, Event


@dataclass(frozen=True)
class Limits:
    """Thresholds enforced while extracting a single archive.

    ``max_compression_ratio`` compares expanded bytes against compressed bytes
    (so 100 means the payload must not be more than 100x its stored size).
    """

    max_total_bytes: int = 100 * 1024 * 1024
    max_single_file_bytes: int = 50 * 1024 * 1024
    max_file_count: int = 10_000
    max_compression_ratio: float = 100.0


def single_file_event(entry: str, size: int, limit: int) -> Event:
    return Event(
        EVENT_LIMIT,
        entry,
        f"单文件大小 {size} 字节超过阈值 {limit} 字节，已中止解压",
    )


def total_size_event(entry: str, total: int, limit: int) -> Event:
    return Event(
        EVENT_LIMIT,
        entry,
        f"解压后总大小 {total} 字节超过阈值 {limit} 字节，已中止解压",
    )


def file_count_event(entry: str, count: int, limit: int) -> Event:
    return Event(
        EVENT_LIMIT,
        entry,
        f"文件数量 {count} 超过阈值 {limit}，已中止解压",
    )


def compression_ratio_event(
    entry: str, ratio: float, threshold: float
) -> Event:
    return Event(
        EVENT_LIMIT,
        entry,
        (
            f"压缩比 {ratio:.2f} 超过阈值 {threshold:.2f}，已中止解压"
        ),
    )


class RatioTracker:
    """Track expanded vs stored bytes for an entire archive."""

    def __init__(self, threshold: float) -> None:
        self.threshold = threshold
        self.expanded = 0
        self.stored = 0

    def add(self, expanded_bytes: int, stored_bytes: int) -> None:
        self.expanded += expanded_bytes
        self.stored += stored_bytes

    def ratio(self) -> float | None:
        if self.stored <= 0:
            return None
        return self.expanded / self.stored

    def event(self, entry: str) -> Event | None:
        ratio = self.ratio()
        if ratio is not None and ratio > self.threshold:
            return compression_ratio_event(entry, ratio, self.threshold)
        return None
