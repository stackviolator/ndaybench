"""MspAdapter: Microsoft Update Catalog → MSP → embedded DLL extraction.

Covers Office-family server products (SharePoint, Exchange, Office, Project,
Visio, Skype for Business). These ship patches as MSP files inside catalog
CAB downloads — there's no Symbol Server / Winbindex equivalent, so the
pre-patch DLL has to come from the previous KB's MSP.

`acquire_pair` requires `previous_kb_id` at construction time. Auto-discovery
of the prior KB (by walking SUG history for the same product) is a future
enhancement; for now the caller supplies it.
"""

from __future__ import annotations

from pathlib import Path

import httpx

from .adapter import Arch, BinaryPair, Confidence, DownloadedBinary, KbFile, strip_kb_prefix
from .cache import Cache
from .catalog import CatalogClient
from .msp import extract_artifact

_DEFAULT_LANGUAGE_TAG = "x-none"  # English / language-neutral artifact


class MspAdapterError(Exception):
    pass


class MspAdapter:
    """Acquisition for Office-family server products via Microsoft Update Catalog."""

    family: str = "msp"

    def __init__(
        self,
        cache: Cache,
        *,
        previous_kb_id: str | None = None,
        catalog: CatalogClient | None = None,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self._cache = cache
        self.previous_kb_id = previous_kb_id
        self._http = http or httpx.AsyncClient(
            timeout=600.0,
            follow_redirects=True,
            headers={"user-agent": "patchwatch/0.1"},
        )
        self._owns_http = http is None
        self._catalog = catalog or CatalogClient(client=self._http)

    async def __aenter__(self) -> MspAdapter:
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def list_files(self, kb_id: str) -> list[KbFile]:
        """Download, extract, and return a KbFile per binary in the KB.

        Version/arch are unknown without parsing the PE header — left as
        empty/X64 placeholders.  Downstream filters by `.dll/.exe/.sys`.
        """
        extracted = await self._extract_kb(kb_id)
        out: list[KbFile] = []
        for name in extracted:
            if name.lower().endswith((".dll", ".exe", ".sys")):
                out.append(KbFile(filename=name, version="", arch=Arch.X64))
        return out

    async def acquire_pair(self, kb_id: str, file: KbFile) -> BinaryPair | None:
        if self.previous_kb_id is None:
            raise MspAdapterError(
                "MspAdapter needs an explicit previous_kb_id "
                "(auto-discovery of prior KB not implemented)"
            )

        post = await self._extract_kb(kb_id)
        pre = await self._extract_kb(self.previous_kb_id)

        if file.filename not in post or file.filename not in pre:
            return None

        post_bin = self._stage_binary(post[file.filename], file.filename)
        pre_bin = self._stage_binary(pre[file.filename], file.filename)
        if post_bin.sha256_hex == pre_bin.sha256_hex:
            # Identical bytes — no real patch on this file. Skip.
            return None
        return BinaryPair(
            filename=file.filename,
            previous=pre_bin,
            patched=post_bin,
            confidence=Confidence.EXACT_KB,
        )

    # ─── internals

    async def _extract_kb(self, kb_id: str) -> dict[str, bytes]:
        """Acquire and extract all files for `kb_id`. Cached on disk per KB."""
        kb_cache = self._cache.base_dir / "msp_kb" / strip_kb_prefix(kb_id)
        if (kb_cache / ".done").exists():
            return {p.name: p.read_bytes() for p in kb_cache.iterdir() if p.is_file()}

        cab_bytes = await self._download_kb_artifact(kb_id)
        extracted = extract_artifact(cab_bytes)

        kb_cache.mkdir(parents=True, exist_ok=True)
        for name, data in extracted.items():
            (kb_cache / Path(name).name).write_bytes(data)
        (kb_cache / ".done").touch()
        return extracted

    async def _download_kb_artifact(self, kb_id: str) -> bytes:
        results = await self._catalog.search(kb_id)
        if not results:
            raise MspAdapterError(f"no catalog results for {kb_id}")

        urls = await self._catalog.resolve_download_urls(results[0].update_id)
        if not urls:
            raise MspAdapterError(f"no download URLs returned for {kb_id}")

        # Prefer the language-neutral (`x-none`) artifact — that's the one
        # holding the actual binary patch; everything else is per-locale
        # MUI resources we don't need.
        primary = next((u for u in urls if _DEFAULT_LANGUAGE_TAG in u.lower()), urls[0])

        # On-disk cache for the raw artifact (the .cab download).
        artifact_cache = self._cache.base_dir / "msp_artifacts" / f"{strip_kb_prefix(kb_id)}.cab"
        if artifact_cache.exists():
            return artifact_cache.read_bytes()
        data = await self._catalog.download(primary)
        artifact_cache.parent.mkdir(parents=True, exist_ok=True)
        Cache.write_atomic(artifact_cache, data)
        return data

    def _stage_binary(self, data: bytes, filename: str) -> DownloadedBinary:
        sha = Cache.sha256_hex(data)
        path = self._cache.binary_path(sha, filename)
        if not path.exists():
            Cache.write_atomic(path, data)
        return DownloadedBinary(
            path=path,
            sha256_hex=sha,
            size=len(data),
            version=None,
            source_url="msp:",
        )
