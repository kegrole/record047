"""Behavior tests for safextract.

All archive fixtures are generated here from scratch with the standard
library, so the tests do not depend on the prebuilt demo archives.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from safextract.extractor import extract_archive  # noqa: E402
from safextract.limits import Limits  # noqa: E402
from safextract.report import build_report, summarize  # noqa: E402


def _make_zip(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)


def _make_zip_symlink(path: Path, link_name: str, target: str) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo(link_name)
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, target.encode("utf-8"))


def _make_tar(path: Path, regular: dict[str, bytes]) -> None:
    with tarfile.open(path, "w") as archive:
        for name, payload in regular.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))


def _make_tar_symlink(path: Path, link_name: str, target: str) -> None:
    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo(name=link_name)
        info.type = tarfile.SYMTYPE
        info.linkname = target
        info.mode = 0o777
        archive.addfile(info)


def _make_tar_setuid(path: Path, name: str, payload: bytes) -> None:
    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo(name=name)
        info.size = len(payload)
        info.mode = 0o4755
        info.mtime = 1_700_000_000
        archive.addfile(info, io.BytesIO(payload))


class SafextractFixtureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="safextract-test-"))
        self.archives = self.tmp / "archives"
        self.archives.mkdir()
        self.dest_root = self.tmp / "unpacked"
        self.dest_root.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def build_fixtures(self) -> dict[str, Path]:
        """Build the six fixtures required by criterion 1."""
        normal = self.archives / "normal.zip"
        _make_zip(
            normal,
            {
                "a.txt": b"alpha\n",
                "dir/b.txt": b"beta\n",
                "dir/c.txt": b"gamma\n",
            },
        )

        traversal = self.archives / "traversal.zip"
        _make_zip(
            traversal,
            {"../evil.txt": b"pwned\n", "ok.txt": b"ok\n"},
        )

        absolute = self.archives / "absolute.tar"
        _make_tar(
            absolute,
            {"/etc/passwd": b"root:x:0:0::/root:/bin/sh\n"},
        )

        symlink = self.archives / "symlink.tar"
        _make_tar_symlink(symlink, "escape.lnk", "../../../etc/passwd")

        high_ratio = self.archives / "high_ratio.zip"
        with zipfile.ZipFile(high_ratio, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("bomb.bin", b"0" * 500_000)

        windows = self.archives / "windows_path.zip"
        _make_zip(windows, {r"C:\evil.txt": b"drive-rooted\n"})

        return {
            "normal": normal,
            "traversal": traversal,
            "absolute": absolute,
            "symlink": symlink,
            "high_ratio": high_ratio,
            "windows": windows,
        }

    def _extract_all(self, fixtures: dict[str, Path]):
        results = [
            extract_archive(archive, self.dest_root / key, Limits())
            for key, archive in fixtures.items()
        ]
        return results, build_report(results)

    def _snapshot(self, directory: Path) -> set[str]:
        return {
            item.relative_to(directory).as_posix()
            for item in directory.rglob("*")
        }

    def test_01_six_archives_five_report_events_normal_clean(self):
        """Criteria 1 and 2."""
        fixtures = self.build_fixtures()
        self.assertEqual(len(fixtures), 6)
        _, rows = self._extract_all(fixtures)

        self.assertEqual(len([row for row in rows if row["events"]]), 5)
        normal_row = next(
            row
            for row in rows
            if row["archive"] == str(fixtures["normal"])
        )
        self.assertEqual(normal_row["events"], [])
        self.assertEqual(normal_row["written_files"], 3)
        self.assertFalse(normal_row["aborted"])
        for row in rows:
            if row is not normal_row:
                self.assertTrue(row["aborted"])

    def test_02_relative_traversal_entry_rejected_and_absent(self):
        """Criterion 3."""
        fixtures = self.build_fixtures()
        result = extract_archive(
            fixtures["traversal"], self.dest_root / "traversal"
        )
        self.assertTrue(result.aborted)
        event = result.events[0].to_dict()
        self.assertEqual(event["entry"], "../evil.txt")
        self.assertEqual(event["type"], "path_traversal")
        self.assertIn("路径穿越", event["reason"])
        self.assertFalse((self.dest_root / "traversal").exists())
        self.assertFalse((self.tmp / "evil.txt").exists())

    def test_03_absolute_path_entry_reported(self):
        """Criterion 4."""
        fixtures = self.build_fixtures()
        result = extract_archive(
            fixtures["absolute"], self.dest_root / "absolute"
        )
        self.assertTrue(result.aborted)
        event = result.events[0].to_dict()
        self.assertEqual(event["type"], "absolute_path")
        self.assertEqual(event["entry"], "/etc/passwd")
        self.assertFalse((self.dest_root / "absolute").exists())

    def test_04_escaping_symlink_rejected(self):
        """Criterion 5."""
        fixtures = self.build_fixtures()
        result = extract_archive(
            fixtures["symlink"], self.dest_root / "symlink"
        )
        self.assertTrue(result.aborted)
        event = result.events[0].to_dict()
        self.assertEqual(event["type"], "unsafe_symlink")
        self.assertEqual(event["entry"], "escape.lnk")
        self.assertIn("符号链接目标", event["reason"])
        self.assertIn("解包目录之外", event["reason"])
        self.assertFalse((self.dest_root / "symlink").exists())

        # An in-root symlink must remain supported for both formats.
        safe_tar = self.archives / "safe_symlink.tar"
        with tarfile.open(safe_tar, "w") as archive:
            payload = b"inside\n"
            file_info = tarfile.TarInfo("a.txt")
            file_info.size = len(payload)
            file_info.mode = 0o644
            archive.addfile(file_info, io.BytesIO(payload))
            link_info = tarfile.TarInfo("inside.lnk")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "a.txt"
            link_info.mode = 0o777
            archive.addfile(link_info)
        ok = extract_archive(safe_tar, self.dest_root / "safe_link")
        self.assertEqual(ok.events, [])
        link = self.dest_root / "safe_link" / "inside.lnk"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "a.txt")

        safe_zip = self.archives / "safe_symlink.zip"
        _make_zip(safe_zip, {"a.txt": b"inside\n"})
        with zipfile.ZipFile(safe_zip, "a") as archive:
            info = zipfile.ZipInfo("inside.lnk")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b"a.txt")
        ok_zip = extract_archive(safe_zip, self.dest_root / "safe_zip_link")
        self.assertEqual(ok_zip.events, [])
        zip_link = self.dest_root / "safe_zip_link" / "inside.lnk"
        self.assertTrue(zip_link.is_symlink())
        self.assertEqual(os.readlink(zip_link), "a.txt")

    def test_05_high_compression_ratio_reports_both_numbers(self):
        """Criterion 6: ratio and threshold both appear; default is 100."""
        fixtures = self.build_fixtures()
        result = extract_archive(
            fixtures["high_ratio"], self.dest_root / "bomb"
        )
        self.assertTrue(result.aborted)
        event = result.events[0].to_dict()
        self.assertEqual(event["type"], "limit_exceeded")
        numbers = re.findall(r"\d+(?:\.\d+)?", event["reason"])
        self.assertGreaterEqual(len(numbers), 2)
        ratio = float(numbers[0])
        threshold = float(numbers[1])
        self.assertGreater(ratio, 100.0)
        self.assertEqual(threshold, 100.0)

        custom_result = extract_archive(
            fixtures["high_ratio"],
            self.dest_root / "bomb_custom",
            Limits(max_compression_ratio=50.0),
        )
        self.assertTrue(custom_result.aborted)
        self.assertIn("50.00", custom_result.events[0].reason)

    def test_06_windows_path_treated_as_traversal(self):
        """Criterion 7."""
        fixtures = self.build_fixtures()
        result = extract_archive(
            fixtures["windows"], self.dest_root / "windows"
        )
        self.assertTrue(result.aborted)
        event = result.events[0].to_dict()
        self.assertEqual(event["entry"], r"C:\evil.txt")
        self.assertIn(event["type"], {"windows_path", "path_traversal"})
        self.assertIn("路径穿越", event["reason"])
        self.assertFalse((self.dest_root / "windows").exists())

        backslash = self.archives / "backslash.zip"
        _make_zip(backslash, {r"nested\..\escape.txt": b"x"})
        other = extract_archive(
            backslash, self.dest_root / "backslash"
        )
        self.assertTrue(other.aborted)
        self.assertIn("路径穿越", other.events[0].reason)

    def test_07_parent_directory_set_unchanged_for_all_outcomes(self):
        """Criterion 8: nothing appears outside the extraction target."""
        fixtures = self.build_fixtures()
        parent = self.tmp / "parent_watch"
        parent.mkdir()
        sentinel = parent / "sentinel.txt"
        sentinel.write_bytes(b"keep me")

        for key, archive in fixtures.items():
            destination = parent / f"out_{key}"
            destination.mkdir()
            before = self._snapshot(parent)
            result = extract_archive(archive, destination)
            after = self._snapshot(parent)
            if result.aborted:
                self.assertEqual(before, after)
            else:
                extra = after - before
                self.assertTrue(
                    all(item.startswith(f"out_{key}/") for item in extra)
                )
        self.assertEqual(sentinel.read_bytes(), b"keep me")
        self.assertFalse((self.tmp / "evil.txt").exists())

    def test_08_report_contains_required_fields(self):
        """Criterion 9."""
        fixtures = self.build_fixtures()
        _, rows = self._extract_all(fixtures)
        for row in rows:
            self.assertEqual(
                set(row.keys()),
                {"archive", "events", "written_files", "aborted"},
            )
            for event in row["events"]:
                self.assertEqual(
                    set(event.keys()), {"type", "entry", "reason"}
                )
        payload = json.loads(json.dumps(rows, ensure_ascii=False))
        self.assertEqual(len(payload), 6)
        archive_count, event_count, rejected = summarize(rows)
        self.assertEqual(archive_count, 6)
        self.assertEqual(event_count, rejected)
        self.assertGreaterEqual(event_count, 5)

    def test_09_setuid_setgid_bits_are_masked_but_mode_kept(self):
        archive_path = self.archives / "setuid.tar"
        _make_tar_setuid(archive_path, "tool.sh", b"#!/bin/sh\n")
        result = extract_archive(
            archive_path, self.dest_root / "setuid"
        )
        self.assertEqual(result.events, [])
        target = self.dest_root / "setuid" / "tool.sh"
        mode = stat.S_IMODE(target.stat().st_mode)
        self.assertEqual(mode & 0o6000, 0)
        self.assertEqual(mode & 0o755, 0o755)
        self.assertEqual(target.read_bytes(), b"#!/bin/sh\n")

    def test_10_tar_content_mode_and_mtime_are_preserved(self):
        archive_path = self.archives / "attrs.tar"
        payload = b"attribute check\n"
        with tarfile.open(archive_path, "w") as archive:
            info = tarfile.TarInfo("nested/file.txt")
            info.size = len(payload)
            info.mode = 0o640
            info.mtime = 1_700_000_123
            archive.addfile(info, io.BytesIO(payload))
        result = extract_archive(
            archive_path, self.dest_root / "attrs"
        )
        self.assertFalse(result.aborted)
        target = self.dest_root / "attrs" / "nested" / "file.txt"
        self.assertEqual(target.read_bytes(), payload)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
        self.assertEqual(int(target.stat().st_mtime), 1_700_000_123)

    def test_11_other_limits_and_compressed_tar_are_enforced(self):
        tiny = Limits(
            max_total_bytes=10,
            max_single_file_bytes=5,
            max_file_count=1,
            max_compression_ratio=100.0,
        )
        single = self.archives / "big.zip"
        _make_zip(single, {"big.bin": b"x" * 6})
        result = extract_archive(
            single, self.dest_root / "big", tiny
        )
        self.assertTrue(result.aborted)
        self.assertEqual(result.events[0].type, "limit_exceeded")
        self.assertFalse((self.dest_root / "big").exists())

        many = self.archives / "many.zip"
        _make_zip(many, {"a": b"a", "b": b"b"})
        many_result = extract_archive(
            many, self.dest_root / "many", Limits(max_file_count=1)
        )
        self.assertTrue(many_result.aborted)

        # gzip-compressed tar: aggregate ratio is computed from stream bytes.
        bomb_tar = self.archives / "bomb.tar.gz"
        with tarfile.open(bomb_tar, "w:gz") as archive:
            info = tarfile.TarInfo("bomb.bin")
            payload = b"0" * 500_000
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        gz_result = extract_archive(
            bomb_tar, self.dest_root / "gz_bomb"
        )
        self.assertTrue(gz_result.aborted)
        self.assertIn("压缩比", gz_result.events[0].reason)
        self.assertIn("100.00", gz_result.events[0].reason)

    def test_12_zip_symlink_traversal_is_not_format_specific(self):
        # The checks must work on freshly generated archives, not only demos.
        evil_zip = self.archives / "evil_link.zip"
        _make_zip_symlink(evil_zip, "link", "../../etc/passwd")
        result = extract_archive(
            evil_zip, self.dest_root / "evil_link"
        )
        self.assertTrue(result.aborted)
        self.assertEqual(result.events[0].type, "unsafe_symlink")

        absolute_zip = self.archives / "abs_link.zip"
        _make_zip_symlink(absolute_zip, "link", "/etc/passwd")
        abs_result = extract_archive(
            absolute_zip, self.dest_root / "abs_link"
        )
        self.assertTrue(abs_result.aborted)
        self.assertEqual(abs_result.events[0].type, "unsafe_symlink")


if __name__ == "__main__":
    unittest.main(verbosity=2)
