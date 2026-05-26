"""Shared types + protocol for patch acquisition adapters."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol


class Arch(StrEnum):
    X64 = "x64"
    ARM64 = "arm64"
    X86 = "x86"


class Confidence(StrEnum):
    """Quality of a patched/previous pair selection."""

    EXACT_KB = "exact_kb"
    VERSION_FALLBACK = "version_fallback"
    APPROXIMATE = "approximate"


def strip_kb_prefix(kb_id: str) -> str:
    """Return just the digits of a KB identifier (case-insensitive prefix strip)."""
    s = kb_id.strip()
    if s[:2].upper() == "KB":
        s = s[2:]
    return s


@dataclass(frozen=True, slots=True)
class KbFile:
    """One file shipped by a KB."""

    filename: str
    version: str
    arch: Arch
    file_size: int | None = None
    date_stamp: str | None = None


@dataclass(frozen=True, slots=True)
class DownloadedBinary:
    path: Path
    sha256_hex: str
    size: int
    version: str | None
    source_url: str


@dataclass(frozen=True, slots=True)
class BinaryPair:
    """Pre/post-patch pair for one binary, ready to diff."""

    filename: str
    previous: DownloadedBinary
    patched: DownloadedBinary
    confidence: Confidence


class PatchAdapter(Protocol):
    """Family-specific patch acquisition.

    Each adapter knows how to enumerate the files shipped by a KB and how
    to acquire a (pre, post) binary pair for any given file. The diff stage
    is family-agnostic and operates on BinaryPair regardless of source.
    """

    family: str

    async def list_files(self, kb_id: str) -> list[KbFile]: ...

    async def acquire_pair(
        self,
        kb_id: str,
        file: KbFile,
    ) -> BinaryPair | None: ...
