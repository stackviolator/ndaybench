"""CVE → KB resolution. Emits one target KB per distinct patch shipped by the CVE."""

from __future__ import annotations

import string
from collections.abc import Iterable
from dataclasses import dataclass

from .sug import AffectedProduct, KbArticle


@dataclass(frozen=True, slots=True)
class TargetKb:
    family: str
    product: str
    kb_id: str
    build: str | None


def _is_numeric_kb(name: str | None) -> bool:
    """True if `name` is a bare KB number (digits, optionally KB-prefixed).

    Rejects strings like "Release Notes" or "Click to Run" that show up in
    Office / ASP.NET affected-product rows and would otherwise produce bogus
    IDs like "KBRelease Notes".
    """
    if not name:
        return False
    digits = name.lstrip(string.ascii_letters)
    return bool(digits) and digits.isdigit()


def _has_non_x64_arch(name: str) -> bool:
    return (
        "arm64" in name
        or "arm-based" in name
        or "ia64" in name
        or "itanium" in name
        or " rt " in name
        or name.endswith(" rt")
    )


def _classify_family(product_name: str) -> str:
    n = product_name.lower()
    if "sharepoint" in n:
        return "sharepoint"
    if "exchange server" in n:
        return "exchange"
    if "sql server" in n:
        return "sql-server"
    if "windows server" in n:
        return "windows-server"
    if "windows 11" in n or "windows 10" in n:
        return "windows-client"
    if "office" in n or "365 apps" in n:
        return "office"
    if ".net" in n or "asp.net" in n:
        return "dotnet"
    if "visual studio" in n:
        return "visual-studio"
    return "other"


def _is_diffable(product_name: str | None) -> bool:
    """Filter out SKUs we can't realistically diff (non-x64, IoT, Mobile, RT)."""
    if not product_name:
        return False
    n = product_name.lower()
    if _has_non_x64_arch(n):
        return False
    if "iot" in n or "mobile" in n:
        return False
    # Client Windows SKUs tag the arch explicitly. Drop the row if the name
    # contains "windows 11"/"windows 10" but lacks "x64" — that's an arch
    # variant we filtered above, or a non-x64 listing we don't want.
    is_client_win = ("windows 11" in n or "windows 10" in n) and "server" not in n
    return not (is_client_win and "x64" not in n)


def _build_number(kbs: Iterable[KbArticle] | None) -> int:
    if not kbs:
        return 0
    for kb in kbs:
        if not kb.fixed_build_number:
            continue
        parts = kb.fixed_build_number.split(".")
        if len(parts) >= 3:
            try:
                return int(parts[2])
            except ValueError:
                continue
    return 0


def _first_numeric_kb(kbs: Iterable[KbArticle] | None) -> KbArticle | None:
    if not kbs:
        return None
    for kb in kbs:
        if _is_numeric_kb(kb.article_name):
            return kb
    return None


def _windows_priority(family: str) -> bool:
    """True for families where we want only the highest-build SKU, not all of them.

    Windows ships many supported SKU generations concurrently (Win11 23H2, 24H2,
    25H2, 26H1, Server 2025, etc.). Diffing all of them is rarely interesting —
    the newest is the canonical target. For non-Windows families (SharePoint,
    Exchange) every supported version is a separate codebase and we keep them all.
    """
    return family in {"windows-client", "windows-server"}


def pick_targets(products: list[AffectedProduct]) -> list[TargetKb]:
    """Build the list of target KBs to diff for a CVE.

    Rules:
    - Drop non-x64 / IoT / Mobile / RT product rows.
    - Drop rows without a numeric KB.
    - For Windows client and server: keep only the highest-build SKU per family.
    - For everything else (SharePoint, Exchange, ...): keep every distinct KB.
    - Dedupe by KB across all output rows.
    """
    eligible = [
        p
        for p in products
        if _is_diffable(p.product) and _first_numeric_kb(p.kb_articles) is not None
    ]

    # Bucket eligible products by family.
    by_family: dict[str, list[AffectedProduct]] = {}
    for p in eligible:
        fam = _classify_family(p.product or "")
        by_family.setdefault(fam, []).append(p)

    seen: set[str] = set()
    out: list[TargetKb] = []

    def emit(family: str, prod: AffectedProduct) -> None:
        kb = _first_numeric_kb(prod.kb_articles)
        if kb is None or kb.article_name is None:
            return
        kb_id = normalize_kb_id(kb.article_name)
        if kb_id in seen:
            return
        seen.add(kb_id)
        out.append(
            TargetKb(
                family=family,
                product=prod.product or "",
                kb_id=kb_id,
                build=kb.fixed_build_number,
            )
        )

    for family, prods in by_family.items():
        if _windows_priority(family):
            best = max(prods, key=lambda p: _build_number(p.kb_articles))
            emit(family, best)
        else:
            for p in prods:
                emit(family, p)
    return out


def normalize_kb_id(raw: str) -> str:
    """Return `KB<number>` form regardless of whether the input was prefixed."""
    return raw if raw.upper().startswith("KB") else f"KB{raw}"
