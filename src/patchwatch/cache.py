"""Content-addressable on-disk cache keyed by SHA256."""

from __future__ import annotations

import contextlib
import hashlib
import os
import tempfile
from pathlib import Path


class Cache:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir

    def binary_path(self, sha256_hex: str, filename: str) -> Path:
        # Two-char shard so a single dir doesn't accumulate thousands of files.
        return self.base_dir / "binaries" / sha256_hex[:2] / sha256_hex / filename

    @staticmethod
    def sha256_hex(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def write_atomic(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        # tempfile in the destination dir so the rename is atomic on the same FS.
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=path.suffix)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        except Exception:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
