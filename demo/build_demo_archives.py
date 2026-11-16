"""Rebuild the six demo archives used by the README and CLI examples.

Run from the repository root:
    python demo/build_demo_archives.py
"""

from __future__ import annotations

import io
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent / "archives"


def _write_zip(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)


def build() -> None:
    if DEMO_DIR.exists():
        shutil.rmtree(DEMO_DIR)
    DEMO_DIR.mkdir(parents=True)

    # 1. Normal archive with exactly three regular files.
    _write_zip(
        DEMO_DIR / "01_normal.zip",
        {
            "docs/readme.txt": b"hello safextract\n",
            "docs/notes.txt": b"notes line\n",
            "data/values.bin": bytes(range(64)),
        },
    )

    # 2. Relative traversal entry.
    _write_zip(
        DEMO_DIR / "02_relative_traversal.zip",
        {"../evil.txt": b"this must never escape\n", "ok.txt": b"ok\n"},
    )

    # 3. Absolute path entry.
    with tarfile.open(DEMO_DIR / "03_absolute_path.tar", "w") as archive:
        payload = b"root:x:0:0::/root:/bin/sh\n"
        info = tarfile.TarInfo("/etc/passwd")
        info.size = len(payload)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(payload))

    # 4. Symbolic link whose target escapes the extraction root.
    with tarfile.open(DEMO_DIR / "04_escaping_symlink.tar", "w") as archive:
        info = tarfile.TarInfo("escape.lnk")
        info.type = tarfile.SYMTYPE
        info.linkname = "../../../etc/passwd"
        info.mode = stat.S_IMODE(0o777)
        archive.addfile(info)

    # 5. Highly compressible payload: ratio is far above 100.
    with zipfile.ZipFile(
        DEMO_DIR / "05_high_compression_ratio.zip", "w", zipfile.ZIP_DEFLATED
    ) as archive:
        archive.writestr("bomb.bin", b"0" * 500_000)

    # 6. Windows drive-letter path; backslash must count as a separator.
    _write_zip(
        DEMO_DIR / "06_windows_drive_path.zip",
        {r"C:\evil.txt": b"windows path must be rejected\n"},
    )


if __name__ == "__main__":
    build()
    print(f"demo archives written to {DEMO_DIR}")
