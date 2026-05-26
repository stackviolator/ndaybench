"""Tier 2 KB enumeration: Update Catalog → MSU download → manifest parsing.

Fires when the support page has no "file information" CSV link. Uses our
pure-Python CAB reader to peel MSU → inner CABs → `.manifest` XMLs, then
parses each manifest for assemblyIdentity (version+arch) and file entries.

Only x64 MSUs are fetched, so the result never includes ARM64 rows — that
matches the Rust implementation and downstream filters x64 anyway.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from .adapter import Arch, KbFile, strip_kb_prefix
from .cab import parse_cab
from .cache import Cache
from .catalog import CatalogClient


class Tier2Error(Exception):
    pass


_ARCH_BY_PROCESSOR = {
    "amd64": Arch.X64,
    "x86": Arch.X86,
    "arm64": Arch.ARM64,
    "wow64": Arch.X64,  # 32-bit binary running on x64 — still ships in the x64 MSU
    "msil": Arch.X64,  # .NET-language-neutral; group with x64
}


def parse_manifest(xml_bytes: bytes) -> list[KbFile]:
    """Parse a Component-Based Servicing manifest for assemblyIdentity + file entries.

    The schema uses an `urn:schemas-microsoft-com:asm.v3` namespace for the
    asmv3 elements; we strip namespaces and match by local tag name.
    """
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return []

    version = ""
    arch = Arch.X64
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag == "assemblyIdentity":
            version = el.attrib.get("version", version)
            proc = el.attrib.get("processorArchitecture", "").lower()
            arch = _ARCH_BY_PROCESSOR.get(proc, Arch.X64)
            break

    files: list[KbFile] = []
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag != "file":
            continue
        name = el.attrib.get("name") or el.attrib.get("sourceName")
        if not name:
            continue
        files.append(KbFile(filename=name, version=version, arch=arch))
    return files


def extract_msu_manifests(msu_bytes: bytes) -> list[KbFile]:
    """Extract every `.manifest` XML out of an MSU and parse each.

    MSU layout: outer CAB containing inner CAB(s). Manifests live inside the
    inner CABs. We dedupe across manifests by (filename, arch, version)
    since the same DLL can appear in multiple manifests.
    """
    outer = parse_cab(msu_bytes)
    by_key: dict[tuple[str, Arch, str], KbFile] = {}

    for inner_name, inner_data in outer.files.items():
        if not inner_name.lower().endswith(".cab"):
            # Some MSUs ship .manifest files at the top level.
            if inner_name.lower().endswith(".manifest"):
                for f in parse_manifest(inner_data):
                    by_key[(f.filename, f.arch, f.version)] = f
            continue
        try:
            inner = parse_cab(inner_data)
        except Exception:  # noqa: BLE001 — inner CABs occasionally use unsupported compression
            continue
        for fname, fdata in inner.files.items():
            if not fname.lower().endswith(".manifest"):
                continue
            for f in parse_manifest(fdata):
                by_key[(f.filename, f.arch, f.version)] = f
    return list(by_key.values())


async def enumerate_via_msu(
    catalog: CatalogClient,
    kb_id: str,
    cache: Cache,
) -> list[KbFile]:
    """Full Tier 2 path: catalog search → resolve x64 MSU URL → download → extract → parse."""
    results = await catalog.search(kb_id)
    pick = next((r for r in results if "x64" in r.arch_hint), None) or (
        results[0] if results else None
    )
    if pick is None:
        raise Tier2Error(f"no catalog results for {kb_id}")

    urls = await catalog.resolve_download_urls(pick.update_id)
    msu_url = next((u for u in urls if u.lower().endswith(".msu")), None)
    if msu_url is None:
        raise Tier2Error(f"no .msu URL for {kb_id}")

    msu_cache = cache.base_dir / "msu" / f"{strip_kb_prefix(kb_id)}.msu"
    if msu_cache.exists():
        data = msu_cache.read_bytes()
    else:
        data = await catalog.download(msu_url)
        msu_cache.parent.mkdir(parents=True, exist_ok=True)
        Cache.write_atomic(msu_cache, data)
    return extract_msu_manifests(data)
