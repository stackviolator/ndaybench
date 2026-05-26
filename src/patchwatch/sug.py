"""Microsoft Security Update Guide (SUG) v2 OData client and models."""

from __future__ import annotations

from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator


def _camel(s: str) -> str:
    head, *rest = s.split("_")
    return head + "".join(w.title() for w in rest)


class _SugModel(BaseModel):
    model_config = ConfigDict(alias_generator=_camel, populate_by_name=True, extra="ignore")


class KbArticle(_SugModel):
    article_name: str | None = None
    article_url: str | None = None
    fixed_build_number: str | None = None
    reboot_required: str | None = None


class AffectedProduct(_SugModel):
    cve_number: str
    product: str | None = None
    kb_articles: list[KbArticle] | None = None


class Vulnerability(_SugModel):
    cve_number: str
    cve_title: str | None = None
    base_score: float | None = None
    temporal_score: float | None = None
    vector_string: str | None = None
    severity: str | None = None
    impact: str | None = None
    issuing_cna: str | None = None
    tag: str | None = None
    exploited: str | None = None
    publicly_disclosed: str | None = None
    customer_action_required: bool | None = None
    is_mariner: bool | None = None
    release_number: str | None = None
    release_date: str | None = None
    revision_number: str | None = None
    description: str | None = None
    cwe_list: list[str] | None = None

    @field_validator("base_score", "temporal_score", mode="before")
    @classmethod
    def _parse_score(cls, v: Any) -> float | None:
        # SUG returns scores as either a JSON number or a string ("5.7"). Accept both.
        if v is None or v == "":
            return None
        if isinstance(v, str):
            return float(v)
        return float(v)

    @property
    def cwe_id(self) -> str | None:
        if not self.cwe_list:
            return None
        return self.cwe_list[0].split(":", 1)[0].strip()


class ReleaseNote(_SugModel):
    release_number: str
    release_date: str | None = None
    title: str | None = None


class OdataPage[T: BaseModel](BaseModel):
    value: list[T]
    next_link: str | None = Field(default=None, alias="@odata.nextLink")
    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class SugClient:
    """Async client for the MSRC SUG OData v2 endpoint."""

    def __init__(
        self,
        base_url: str = "https://api.msrc.microsoft.com/sug/v2.0",
        language: str = "en-US",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._root = f"{base_url.rstrip('/')}/{language}"
        self._client = client or httpx.AsyncClient(timeout=30.0)
        self._owns_client = client is None

    async def __aenter__(self) -> SugClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def list_releases(self) -> list[ReleaseNote]:
        page = await self._get(f"{self._root}/releaseNote", ReleaseNote)
        return page.value

    async def vulnerabilities_in_release(self, release_number: str) -> list[Vulnerability]:
        filt = (
            f"releaseNumber eq '{release_number}' and isMariner eq false "
            f"and issuingCna eq 'Microsoft'"
        )
        url = f"{self._root}/vulnerability"
        return await self._fetch_all(url, Vulnerability, params={"$filter": filt})

    async def vulnerability_detail(self, cve_id: str) -> Vulnerability | None:
        url = f"{self._root}/vulnerability"
        params = {"$filter": f"cveNumber eq '{cve_id}'"}
        rows = await self._fetch_all(url, Vulnerability, params=params)
        if not rows:
            return None
        # SUG can return one row per release the CVE appears in; later rows may
        # lack base_score. Pick the row with the highest score so callers see
        # the real severity rather than a score-less revision row.
        return max(rows, key=lambda v: v.base_score or 0.0)

    async def affected_products(self, cve_id: str) -> list[AffectedProduct]:
        url = f"{self._root}/affectedProduct"
        params = {"$filter": f"cveNumber eq '{cve_id}'"}
        return await self._fetch_all(url, AffectedProduct, params=params)

    async def _get[T: BaseModel](
        self,
        url: str,
        model: type[T],
        params: dict[str, str] | None = None,
    ) -> OdataPage[T]:
        resp = await self._client.get(url, params=params)
        resp.raise_for_status()
        return OdataPage[model].model_validate(resp.json())  # type: ignore[valid-type]

    async def _fetch_all[T: BaseModel](
        self,
        url: str,
        model: type[T],
        params: dict[str, str] | None = None,
    ) -> list[T]:
        out: list[T] = []
        next_url: str | None = url
        next_params = params
        while next_url:
            page = await self._get(next_url, model, params=next_params)
            out.extend(page.value)
            next_url = page.next_link
            next_params = None  # next_link already encodes the filter
        return out
