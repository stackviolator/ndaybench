"""Microsoft Update Catalog client.

Scrapes catalog.update.microsoft.com for KB downloads. Returns one or more
download URLs per KB — each result corresponds to a SKU/language variant.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
from bs4 import BeautifulSoup, Tag

from .adapter import strip_kb_prefix

_GUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
_DOWNLOAD_URL_RE = re.compile(
    r"""\.url\s*=\s*['"](https?://[^'"]+\.(?:msu|msp|cab|exe))['"]""",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class CatalogResult:
    update_id: str
    title: str
    products: str  # "products" column from the catalog table
    arch_hint: str  # extracted arch keyword if present in title/column


def _extract_arch(title: str, products: str) -> str:
    blob = f"{title} {products}".lower()
    if "arm64" in blob:
        return "arm64"
    if "x64" in blob or "amd64" in blob:
        return "x64"
    if "x86" in blob or "ia-32" in blob:
        return "x86"
    return ""


def parse_search_results(html: str) -> list[CatalogResult]:
    soup = BeautifulSoup(html, "lxml")
    table = soup.find("table", id="ctl00_catalogBody_updateMatches")
    if table is None or not isinstance(table, Tag):
        return []

    out: list[CatalogResult] = []
    for row in table.find_all("tr"):
        cells = row.find_all("td") if isinstance(row, Tag) else []
        if len(cells) < 6:
            continue
        # 8 cells: blank, Title, Products, Classification, LastUpdated, Version, Size, Download.
        title = cells[1].get_text(strip=True)
        products = cells[2].get_text(strip=True)
        # Last cell holds the Download <input class="flatBlueButtonDownload" id="<guid>">.
        # Earlier catalog versions encoded the GUID in an onclick="goToDetails(...)"
        # handler; the current UI stores it directly as the input id.
        last = cells[-1]
        update_id: str | None = None
        for inp in last.find_all("input"):
            if not isinstance(inp, Tag):
                continue
            classes = inp.get("class") or []
            if "flatBlueButtonDownload" in classes:
                candidate = inp.get("id") or ""
                if isinstance(candidate, str) and _GUID_RE.match(candidate):
                    update_id = candidate
                    break
        if update_id is None:
            continue
        out.append(
            CatalogResult(
                update_id=update_id,
                title=title,
                products=products,
                arch_hint=_extract_arch(title, products),
            )
        )
    return out


def parse_download_dialog(html: str) -> list[str]:
    """Extract download URLs from the DownloadDialog response."""
    return [m.group(1) for m in _DOWNLOAD_URL_RE.finditer(html)]


class CatalogClient:
    def __init__(
        self,
        base_url: str = "https://catalog.update.microsoft.com",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._http = client or httpx.AsyncClient(
            timeout=120.0,
            follow_redirects=True,
            headers={
                "user-agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/126.0.0.0 Safari/537.36"
                ),
            },
        )
        self._owns_http = client is None

    async def __aenter__(self) -> CatalogClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def search(self, kb_id: str) -> list[CatalogResult]:
        url = f"{self._base}/Search.aspx?q=KB{strip_kb_prefix(kb_id)}"
        resp = await self._http.get(url)
        resp.raise_for_status()
        return parse_search_results(resp.text)

    async def resolve_download_urls(self, update_id: str) -> list[str]:
        url = f"{self._base}/DownloadDialog.aspx"
        payload = f'[{{"size":0,"languages":"","uidInfo":"{update_id}","updateID":"{update_id}"}}]'
        resp = await self._http.post(
            url,
            content=urlencode({"updateIDs": payload}),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        return parse_download_dialog(resp.text)

    async def download(self, url: str) -> bytes:
        resp = await self._http.get(url)
        resp.raise_for_status()
        return resp.content
