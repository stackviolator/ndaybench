"""Winbindex + Microsoft Symbol Server (MSDL) client.

Winbindex is a third-party index of every published version of every Windows
DLL Microsoft has ever shipped. It does not host the binaries itself — it just
records the (timestamp, virtual_size) pair from the PE header and the KB(s)
each version shipped in. The actual download is served by msdl.microsoft.com.
"""

from __future__ import annotations

import gzip
import json
import re
from dataclasses import dataclass
from typing import Any

import httpx

from .adapter import Arch, Confidence, DownloadedBinary, strip_kb_prefix
from .cache import Cache


@dataclass(frozen=True, slots=True)
class WinbindexEntry:
    """One historical version of a Windows DLL as recorded by Winbindex."""

    raw: dict[str, Any]

    @property
    def timestamp(self) -> int | None:
        v = self._fi().get("timestamp")
        return int(v) if v is not None else None

    @property
    def virtual_size(self) -> int | None:
        v = self._fi().get("virtualSize")
        return int(v) if v is not None else None

    @property
    def sha256(self) -> str | None:
        return self._fi().get("sha256")

    @property
    def version(self) -> str | None:
        return self._fi().get("version")

    @property
    def arch(self) -> Arch:
        m = self._fi().get("machineType")
        # PE IMAGE_FILE_HEADER.Machine
        if m == 0x8664:
            return Arch.X64
        if m == 0xAA64:
            return Arch.ARM64
        return Arch.X86

    @property
    def kb_list(self) -> list[str]:
        """KB IDs this binary version shipped in (e.g. ['KB5083631']).

        Winbindex schema: windowsVersions[os_version][kb_id] = {updateInfo, assemblies}.
        The kb_id is the inner dict key, not a field of updateInfo.
        """
        out: list[str] = []
        windows_info = self.raw.get("windowsVersions", {})
        if not isinstance(windows_info, dict):
            return out
        for kbs in windows_info.values():
            if isinstance(kbs, dict):
                out.extend(kbs.keys())
        return out

    def appears_in_kb(self, kb_id: str) -> bool:
        target = strip_kb_prefix(kb_id)
        return any(strip_kb_prefix(k) == target for k in self.kb_list)

    def _fi(self) -> dict[str, Any]:
        return self.raw.get("fileInfo", {}) or {}


class WinbindexClient:
    def __init__(
        self,
        base_url: str = "https://winbindex.m417z.com",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._http = client or httpx.AsyncClient(timeout=60.0, follow_redirects=True)
        self._owns_client = client is None

    async def __aenter__(self) -> WinbindexClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._owns_client:
            await self._http.aclose()

    async def fetch_file_data(self, filename: str) -> dict[str, WinbindexEntry]:
        """Returns map of pe-hash → WinbindexEntry for every known version."""
        url = f"{self._base}/data/by_filename_compressed/{filename.lower()}.json.gz"
        resp = await self._http.get(url)
        resp.raise_for_status()
        decompressed = gzip.decompress(resp.content)
        raw = json.loads(decompressed)
        return {k: WinbindexEntry(raw=v) for k, v in raw.items() if isinstance(v, dict)}

    async def download_entry(
        self,
        filename: str,
        entry: WinbindexEntry,
        cache: Cache,
    ) -> DownloadedBinary:
        ts, vs = entry.timestamp, entry.virtual_size
        if ts is None or vs is None:
            raise ValueError(f"winbindex entry for {filename} missing timestamp/virtual_size")
        url = msdl_url(filename, ts, vs)

        if entry.sha256:
            path = cache.binary_path(entry.sha256, filename)
            if path.exists():
                return DownloadedBinary(
                    path=path,
                    sha256_hex=entry.sha256,
                    size=path.stat().st_size,
                    version=entry.version,
                    source_url=url,
                )

        resp = await self._http.get(url)
        resp.raise_for_status()
        data = resp.content
        sha = Cache.sha256_hex(data)
        path = cache.binary_path(sha, filename)
        Cache.write_atomic(path, data)
        return DownloadedBinary(
            path=path,
            sha256_hex=sha,
            size=len(data),
            version=entry.version,
            source_url=url,
        )


def msdl_url(filename: str, timestamp: int, virtual_size: int) -> str:
    return f"https://msdl.microsoft.com/download/symbols/{filename}/{timestamp:08X}{virtual_size:X}/{filename}"


_REVISION_RE = re.compile(r"^\d+\.\d+\.(\d+)\.(\d+)")


def _parse_revision(version: str | None) -> int | None:
    """Encode (build << 32 | revision) so newer OS branches sort above older ones.

    Avoids "10.0.10240.21161 ranks above 10.0.28000.2113" due to a higher bare
    revision number on an older branch.
    """
    if not version:
        return None
    m = _REVISION_RE.match(version)
    if not m:
        return None
    build = int(m.group(1))
    rev = int(m.group(2))
    return (build << 32) | rev


@dataclass(frozen=True, slots=True)
class PatchPair:
    patched: WinbindexEntry
    previous: WinbindexEntry
    confidence: Confidence


def select_pair(
    entries: dict[str, WinbindexEntry],
    kb_id: str,
    arch: Arch,
    fallback_version: str | None,
) -> PatchPair | None:
    arch_entries = [e for e in entries.values() if e.arch == arch]

    # Level 1: an entry's kb_list contains this KB.
    patched = next((e for e in arch_entries if e.appears_in_kb(kb_id)), None)
    if patched:
        prev = _pick_previous(arch_entries, patched)
        if prev:
            return PatchPair(patched, prev, Confidence.EXACT_KB)

    # Level 2: match by exact version string from the KB CSV.
    if fallback_version:
        patched = next((e for e in arch_entries if e.version == fallback_version), None)
        if patched:
            prev = _pick_previous(arch_entries, patched)
            if prev:
                return PatchPair(patched, prev, Confidence.VERSION_FALLBACK)

    # Level 3: take the two highest revisions, treating the top as "patched".
    sorted_entries = sorted(
        ((_parse_revision(e.version), e) for e in arch_entries),
        key=lambda t: t[0] if t[0] is not None else -1,
        reverse=True,
    )
    sorted_entries = [t for t in sorted_entries if t[0] is not None]
    if len(sorted_entries) >= 2:
        return PatchPair(sorted_entries[0][1], sorted_entries[1][1], Confidence.APPROXIMATE)
    return None


def _pick_previous(
    arch_entries: list[WinbindexEntry], patched: WinbindexEntry
) -> WinbindexEntry | None:
    patched_rev = _parse_revision(patched.version)
    if patched_rev is None:
        return None
    older: list[tuple[int, WinbindexEntry]] = []
    for e in arch_entries:
        if e is patched:
            continue
        rev = _parse_revision(e.version)
        if rev is None or rev >= patched_rev:
            continue
        older.append((rev, e))
    if not older:
        return None
    return max(older, key=lambda t: t[0])[1]
