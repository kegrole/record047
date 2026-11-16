"""Command line entry point for batch safe extraction."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .extractor import extract_archive
from .limits import Limits
from .report import build_report, summarize, write_report

_ARCHIVE_SUFFIXES = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".tar.gz"}


def _find_archives(archives_path: Path) -> list[Path]:
    if archives_path.is_file():
        return [archives_path]
    if not archives_path.is_dir():
        raise FileNotFoundError(f"归档路径不存在: {archives_path}")
    found = sorted(
        path
        for path in archives_path.rglob("*")
        if path.is_file()
        and (
            path.suffix.lower() in _ARCHIVE_SUFFIXES
            or path.name.endswith((".tar.gz", ".tar.bz2", ".tar.xz"))
        )
    )
    return found


def _destination_for(dest_root: Path, archive: Path) -> Path:
    name = archive.name
    for suffix in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    else:
        name = archive.stem
    return dest_root / name


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m safextract.cli",
        description="安全解包 zip/tar 归档并输出 JSON 报告",
    )
    parser.add_argument(
        "--archives",
        required=True,
        type=Path,
        help="单个归档文件或存放归档的目录",
    )
    parser.add_argument(
        "--dest",
        required=True,
        type=Path,
        help="解包目标根目录，每个归档对应一个子目录",
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="JSON 报告输出路径",
    )
    parser.add_argument("--max-total-bytes", type=int, default=None)
    parser.add_argument("--max-single-file-bytes", type=int, default=None)
    parser.add_argument("--max-file-count", type=int, default=None)
    parser.add_argument(
        "--max-compression-ratio", type=float, default=None
    )
    return parser


def _limits_from_args(args: argparse.Namespace) -> Limits:
    defaults = Limits()
    return Limits(
        max_total_bytes=args.max_total_bytes
        if args.max_total_bytes is not None
        else defaults.max_total_bytes,
        max_single_file_bytes=args.max_single_file_bytes
        if args.max_single_file_bytes is not None
        else defaults.max_single_file_bytes,
        max_file_count=args.max_file_count
        if args.max_file_count is not None
        else defaults.max_file_count,
        max_compression_ratio=args.max_compression_ratio
        if args.max_compression_ratio is not None
        else defaults.max_compression_ratio,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    limits = _limits_from_args(args)
    archives = _find_archives(args.archives)
    if not archives:
        print("未找到任何归档文件", file=sys.stderr)
        return 2

    results = []
    for archive in archives:
        destination = _destination_for(args.dest, archive)
        results.append(extract_archive(archive, destination, limits))

    rows = build_report(results)
    write_report(rows, args.out)
    archive_count, event_count, rejected = summarize(rows)
    print(
        f"归档数: {archive_count}，事件数: {event_count}，拒绝条目数: {rejected}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
