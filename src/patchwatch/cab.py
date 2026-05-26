"""Minimal CAB v1.3 reader. Supports LZX and stored (no-compression) folders.

Microsoft's CAB v1.3 file format (also known as Cabinet). Spec:
- CFHEADER: 36+ bytes, then optional reserved area and prev/next-cabinet names.
- CFFOLDER[N]: 8+ bytes each.
- CFFILE[M]: variable, null-terminated filename.
- CFDATA[*]: per-folder compressed payload chunks.

This reader handles arbitrary CAB layouts produced by Microsoft Update Catalog
artifacts and MSU files. MSZIP / Quantum folders fall through to cabarchive
for now (cabarchive supports MSZIP but not LZX, complementary to us).
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass

from .lzx import LzxBitReader, LzxDecoder

# CFHEADER flags
_FLAG_PREV_CABINET = 0x01
_FLAG_NEXT_CABINET = 0x02
_FLAG_RESERVE_PRESENT = 0x04

# Compression method codes (low 8 bits of CFFOLDER.type_compress).
_COMP_NONE = 0
_COMP_MSZIP = 1
_COMP_QUANTUM = 2
_COMP_LZX = 3


@dataclass(frozen=True, slots=True)
class CabFile:
    name: str
    uncompressed_size: int
    folder_index: int
    offset_in_folder: int
    attribs: int


@dataclass(frozen=True, slots=True)
class CabFolder:
    coff_cab_start: int
    n_data_blocks: int
    type_compress: int  # raw u16; method = low 4 bits, lzx_window in high byte

    @property
    def compression_method(self) -> int:
        return self.type_compress & 0x0F

    @property
    def lzx_window_bits(self) -> int:
        return (self.type_compress >> 8) & 0x1F


@dataclass(slots=True)
class CabArchive:
    """Decoded CAB: filename → uncompressed bytes."""

    files: dict[str, bytes]


def _read_cstring(data: memoryview, start: int, *, utf8: bool) -> tuple[str, int]:
    end = start
    while end < len(data) and data[end] != 0:
        end += 1
    raw = bytes(data[start:end])
    end += 1  # consume terminator
    if utf8:
        return raw.decode("utf-8", errors="replace"), end
    return raw.decode("cp1252", errors="replace"), end


def parse_cab(data: bytes) -> CabArchive:
    """Parse a CAB file from a bytes buffer. Returns the in-memory archive."""
    mv = memoryview(data)
    if bytes(mv[:4]) != b"MSCF":
        raise ValueError("not a CAB (bad signature)")

    # --- CFHEADER ---
    coff_files = int.from_bytes(mv[16:20], "little")
    version_minor = mv[24]
    version_major = mv[25]
    if (version_major, version_minor) != (1, 3):
        # Most CABs in the wild are v1.3; reject anything else loudly so we
        # notice if Microsoft starts shipping something new.
        raise ValueError(f"unsupported CAB version {version_major}.{version_minor}")
    c_folders = int.from_bytes(mv[26:28], "little")
    c_files = int.from_bytes(mv[28:30], "little")
    flags = int.from_bytes(mv[30:32], "little")

    pos = 36
    cb_cf_folder_reserve = 0
    cb_cf_data_reserve = 0
    if flags & _FLAG_RESERVE_PRESENT:
        cb_cf_header_reserve = int.from_bytes(mv[pos : pos + 2], "little")
        cb_cf_folder_reserve = mv[pos + 2]
        cb_cf_data_reserve = mv[pos + 3]
        pos += 4 + cb_cf_header_reserve
    if flags & _FLAG_PREV_CABINET:
        _, pos = _read_cstring(mv, pos, utf8=False)  # prev cabinet name
        _, pos = _read_cstring(mv, pos, utf8=False)  # prev disk name
    if flags & _FLAG_NEXT_CABINET:
        _, pos = _read_cstring(mv, pos, utf8=False)
        _, pos = _read_cstring(mv, pos, utf8=False)

    # --- CFFOLDER[N] ---
    folders: list[CabFolder] = []
    for _ in range(c_folders):
        coff_cab_start = int.from_bytes(mv[pos : pos + 4], "little")
        n_data_blocks = int.from_bytes(mv[pos + 4 : pos + 6], "little")
        type_compress = int.from_bytes(mv[pos + 6 : pos + 8], "little")
        pos += 8 + cb_cf_folder_reserve
        folders.append(CabFolder(coff_cab_start, n_data_blocks, type_compress))

    # --- CFFILE[M] ---
    files: list[CabFile] = []
    p = coff_files
    for _ in range(c_files):
        cb_file = int.from_bytes(mv[p : p + 4], "little")
        uoff_folder_start = int.from_bytes(mv[p + 4 : p + 8], "little")
        i_folder = int.from_bytes(mv[p + 8 : p + 10], "little")
        # date[2], time[2], attribs[2]
        attribs = int.from_bytes(mv[p + 14 : p + 16], "little")
        p += 16
        # Filename: attrib bit 0x80 = UTF-8; otherwise cp1252-like.
        name, p = _read_cstring(mv, p, utf8=bool(attribs & 0x80))
        files.append(
            CabFile(
                name=name,
                uncompressed_size=cb_file,
                folder_index=i_folder,
                offset_in_folder=uoff_folder_start,
                attribs=attribs,
            )
        )

    # --- For each folder, decompress all CFDATA chunks ---
    folder_data: list[bytes] = []
    for f in folders:
        chunks = _read_folder_chunks(mv, f, cb_cf_data_reserve)
        method = f.compression_method
        if method == _COMP_LZX:
            folder_data.append(_decompress_lzx_folder(chunks, f.lzx_window_bits))
        elif method == _COMP_NONE:
            folder_data.append(b"".join(c for c, _ in chunks))
        elif method == _COMP_MSZIP:
            folder_data.append(_decompress_mszip_folder(chunks))
        elif method == _COMP_QUANTUM:
            raise NotImplementedError("Quantum compression not supported")
        else:
            raise ValueError(f"unknown CAB compression method {method}")

    # --- Slice each file out of its folder ---
    out: dict[str, bytes] = {}
    for f in files:
        fd = folder_data[f.folder_index]
        start = f.offset_in_folder
        end = start + f.uncompressed_size
        if end > len(fd):
            raise ValueError(
                f"CAB file {f.name!r}: offset {start}+{f.uncompressed_size} "
                f"exceeds folder size {len(fd)}"
            )
        out[f.name] = bytes(fd[start:end])
    return CabArchive(files=out)


def _read_folder_chunks(
    mv: memoryview, folder: CabFolder, cb_cf_data_reserve: int
) -> list[tuple[bytes, int]]:
    """Return list of (compressed_payload, uncompressed_size) per CFDATA."""
    p = folder.coff_cab_start
    chunks: list[tuple[bytes, int]] = []
    for _ in range(folder.n_data_blocks):
        # CFDATA: csum[4], cb_data[2], cb_uncomp[2], abReserve[cb_cf_data_reserve], ab[cb_data].
        _csum = int.from_bytes(mv[p : p + 4], "little")
        cb_data = int.from_bytes(mv[p + 4 : p + 6], "little")
        cb_uncomp = int.from_bytes(mv[p + 6 : p + 8], "little")
        p += 8 + cb_cf_data_reserve
        chunks.append((bytes(mv[p : p + cb_data]), cb_uncomp))
        p += cb_data
    return chunks


def _decompress_lzx_folder(chunks: list[tuple[bytes, int]], window_bits: int) -> bytes:
    """Decompress all LZX CFDATAs in a folder.

    The compressed payloads of every CFDATA in a folder form ONE continuous
    LZX bit stream — they are not independent. Only at every 32 KiB of *output*
    (one LZX frame) does the bit stream realign to a 16-bit word boundary,
    not at every CFDATA boundary. CAB-LZX just happens to align CFDATA = frame.
    """
    decoder = LzxDecoder(window_bits)
    # Concatenate every CFDATA's compressed payload into one buffer.
    concatenated = b"".join(c for c, _ in chunks)
    br = LzxBitReader(concatenated)

    out = bytearray()
    for _comp, uncomp_size in chunks:
        out.extend(decoder.decompress_chunk(br, uncomp_size))
    return bytes(out)


def _decompress_mszip_folder(chunks: list[tuple[bytes, int]]) -> bytes:
    """Decompress MSZIP CFDATAs.

    Each chunk starts with a 'CK' signature, then a raw deflate stream that
    may reference up to 32 KiB of the previous chunk's output via a preset
    sliding dictionary.
    """
    out = bytearray()
    for comp, _uncomp_size in chunks:
        if comp[:2] != b"CK":
            raise ValueError("MSZIP chunk missing CK signature")
        # The dictionary is the last 32 KiB of decoded output so far.
        dict_window = bytes(out[-(1 << 15) :])
        if dict_window:
            decobj = zlib.decompressobj(-zlib.MAX_WBITS, zdict=dict_window)
        else:
            decobj = zlib.decompressobj(-zlib.MAX_WBITS)
        out.extend(decobj.decompress(comp[2:]) + decobj.flush())
    return bytes(out)
