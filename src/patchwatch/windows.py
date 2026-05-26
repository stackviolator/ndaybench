"""WindowsAdapter: Tier 1 (support page CSV) + Winbindex + MSDL."""

from __future__ import annotations

import csv
import io
import re

import httpx
from bs4 import BeautifulSoup

from .adapter import Arch, BinaryPair, KbFile, strip_kb_prefix
from .cache import Cache
from .catalog import CatalogClient
from .winbindex import WinbindexClient, select_pair
from .windows_msu import enumerate_via_msu


class Tier1Error(Exception):
    """Raised when the support page has no file-information CSV link."""


def extract_file_information_csv_links(html: str) -> list[str]:
    """Return the hrefs of "file information" anchors on a KB topic page.

    Microsoft's KB topic pages link to a per-update file-info CSV via text like
    "download the file information for cumulative update <KB>". The href is
    usually a `go.microsoft.com/fwlink/?linkid=NNN` redirector that 302s to a
    `download.microsoft.com/.../<kb>.csv` URL — so don't filter by extension.

    Skip SSU and hash links — they use the same surrounding phrasing.
    """
    soup = BeautifulSoup(html, "lxml")
    out: list[str] = []
    for a in soup.find_all("a", href=True):
        text = a.get_text(strip=False).lower()
        if "file information" not in text:
            continue
        if "hash" in text or "ssu" in text or "servicing stack" in text:
            continue
        out.append(a["href"])
    return out


def _arch_from_banner(banner: str) -> Arch | None:
    lower = banner.lower()
    if "arm64-based" in lower or "arm64 based" in lower:
        return Arch.ARM64
    if "x64-based" in lower or "x64 based" in lower:
        return Arch.X64
    if "x86-based" in lower or "x86 based" in lower:
        return Arch.X86
    return None


_DIGITS = re.compile(r"\d+")


def _parse_size(raw: str) -> int | None:
    digits = "".join(_DIGITS.findall(raw))
    return int(digits) if digits else None


def parse_kb_csv(text: str) -> list[KbFile]:
    """Parse a multi-section Microsoft "File information" CSV.

    Sections are preceded by a banner row encoding the arch
    ("Windows 11, version 24H2 LCU x64-based"), followed by a header row
    ("File name","File version","Date","Time","File size"), then data rows.
    """
    reader = csv.reader(io.StringIO(text))
    current_arch: Arch | None = None
    out: list[KbFile] = []
    for row in reader:
        # Strip empty trailing cells.
        row = [c.strip() for c in row]
        while row and row[-1] == "":
            row.pop()
        if not row:
            continue

        joined = ",".join(row)
        arch = _arch_from_banner(joined)
        if arch is not None:
            current_arch = arch
            continue

        first = row[0]
        if first.lower() == "file name":
            continue
        if not first or len(row) < 2 or current_arch is None:
            continue

        out.append(
            KbFile(
                filename=first,
                version=row[1],
                arch=current_arch,
                file_size=_parse_size(row[4]) if len(row) > 4 else None,
                date_stamp=row[2] if len(row) > 2 else None,
            )
        )
    return out


class WindowsAdapter:
    """Acquisition for Windows client + server KBs.

    Pipeline: Tier 1 support-page CSV → per-file Winbindex lookup → MSDL
    Symbol Server download → BinaryPair with content-addressable cache.
    """

    family: str = "windows"

    def __init__(
        self,
        cache: Cache,
        *,
        support_base_url: str = "https://support.microsoft.com",
        http: httpx.AsyncClient | None = None,
        winbindex: WinbindexClient | None = None,
        catalog: CatalogClient | None = None,
    ) -> None:
        self._support_base = support_base_url.rstrip("/")
        self._http = http or httpx.AsyncClient(
            timeout=120.0,
            follow_redirects=True,
            headers={"user-agent": "patchwatch/0.1"},
        )
        self._owns_http = http is None
        self._winbindex = winbindex or WinbindexClient(client=self._http)
        self._catalog = catalog or CatalogClient(client=self._http)
        self._cache = cache

    async def __aenter__(self) -> WindowsAdapter:
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def list_files(self, kb_id: str) -> list[KbFile]:
        """Try Tier 1 (support page CSV); fall through to Tier 2 (MSU)."""
        try:
            return await self._list_files_tier1(kb_id)
        except Tier1Error:
            return await enumerate_via_msu(self._catalog, kb_id, self._cache)

    async def _list_files_tier1(self, kb_id: str) -> list[KbFile]:
        bare = strip_kb_prefix(kb_id)
        topic_url = f"{self._support_base}/help/{bare}"
        topic = await self._http.get(topic_url)
        topic.raise_for_status()

        links = extract_file_information_csv_links(topic.text)
        if not links:
            raise Tier1Error(f"no file-information CSV link on {topic_url}")

        csv_url = links[0]
        csv_resp = await self._http.get(csv_url)
        csv_resp.raise_for_status()
        text = csv_resp.content.decode("utf-8", errors="replace")
        return parse_kb_csv(text)

    async def acquire_pair(self, kb_id: str, file: KbFile) -> BinaryPair | None:
        try:
            entries = await self._winbindex.fetch_file_data(file.filename)
        except httpx.HTTPStatusError:
            return None
        pair = select_pair(entries, kb_id, file.arch, fallback_version=file.version)
        if pair is None:
            return None
        # Short-circuit when Winbindex already reports identical SHA256s: the
        # binary didn't actually change between revisions, so there's nothing
        # to diff. Saves the two MSDL roundtrips per stale file.
        pre_sha = pair.previous.sha256
        post_sha = pair.patched.sha256
        if pre_sha and post_sha and pre_sha == post_sha:
            return None
        try:
            patched = await self._winbindex.download_entry(file.filename, pair.patched, self._cache)
            previous = await self._winbindex.download_entry(
                file.filename, pair.previous, self._cache
            )
        except httpx.HTTPStatusError:
            return None
        return BinaryPair(
            filename=file.filename,
            previous=previous,
            patched=patched,
            confidence=pair.confidence,
        )


__all__ = [
    "Tier1Error",
    "WindowsAdapter",
    "extract_file_information_csv_links",
    "parse_kb_csv",
]
