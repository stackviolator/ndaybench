"""MSP / catalog-artifact extraction.

Microsoft Office-family patches (SharePoint, Exchange, Office, Project, Visio)
ship via the Microsoft Update Catalog as CABs containing one or more MSP files.
An MSP is an OLE Compound Document (Structured Storage) whose payload streams
are themselves CAB-format archives carrying the patched DLLs/EXEs.

This module unwraps that nested format with pure-Python deps:

    catalog .cab artifact
        └── .msp (OLE compound document)
            └── stream(s) starting with `MSCF` (CAB magic)
                └── *.dll / *.exe / *.sys / ...
"""

from __future__ import annotations

import io
from collections.abc import Iterable
from pathlib import Path

import olefile

from .cab import parse_cab

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_CAB_MAGIC = b"MSCF"


def _is_cab(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == _CAB_MAGIC


def _is_ole(data: bytes) -> bool:
    return len(data) >= 8 and data[:8] == _OLE_MAGIC


def _parse_cab_bytes(data: bytes) -> Iterable[tuple[str, bytes]]:
    """Yield (filename, bytes) from a CAB blob via our pure-Python CAB reader."""
    arc = parse_cab(data)
    yield from arc.files.items()


def _extract_msp_streams(msp_bytes: bytes) -> Iterable[tuple[str, bytes]]:
    """Yield (filename, bytes) for every file embedded in an MSP.

    Strategy: open the OLE compound doc, scan every stream for the CAB magic,
    parse any matching stream as a CAB, yield its members. Bypasses MSI's
    encoded-stream-name scheme — the magic-byte sniff identifies the payload
    directly so we don't need to decode names.
    """
    ole = olefile.OleFileIO(io.BytesIO(msp_bytes))
    try:
        for path in ole.listdir(streams=True, storages=False):
            stream = ole.openstream(path)
            head = stream.read(4)
            if head != _CAB_MAGIC:
                continue
            stream.seek(0)
            cab_data = stream.read()
            try:
                yield from _parse_cab_bytes(cab_data)
            except Exception:  # noqa: BLE001 - skip malformed CAB streams
                continue
    finally:
        ole.close()


def extract_artifact(data: bytes) -> dict[str, bytes]:
    """Recursively extract files from a catalog download artifact.

    Handles arbitrary nesting of CABs and MSPs. Returns a dict keyed by
    filename. Collisions overwrite — duplicate filenames inside a single
    patch are rare and usually identical.
    """
    out: dict[str, bytes] = {}
    _walk(data, out)
    return out


def _walk(data: bytes, out: dict[str, bytes]) -> None:
    if _is_cab(data):
        for fn, inner in _parse_cab_bytes(data):
            _walk_member(fn, inner, out)
    elif _is_ole(data):
        for fn, inner in _extract_msp_streams(data):
            _walk_member(fn, inner, out)


def _walk_member(filename: str, data: bytes, out: dict[str, bytes]) -> None:
    if _is_cab(data) or _is_ole(data):
        _walk(data, out)
    else:
        out[filename] = data


def write_extracted(files: dict[str, bytes], dest: Path) -> list[Path]:
    """Write extracted files to dest/ flat. Returns the written paths."""
    dest.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, data in files.items():
        # Strip any embedded path components for safety; we don't want an
        # archive entry like "../../etc/passwd" escaping dest.
        safe = Path(name).name
        if not safe:
            continue
        p = dest / safe
        p.write_bytes(data)
        written.append(p)
    return written
