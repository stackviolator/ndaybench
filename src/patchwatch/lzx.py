"""Pure-Python LZX decompressor (CAB profile).

Implements LZX as used inside Microsoft CAB v1.3 folders. Based on Stuart
Caie's libmspack `lzxd.c` reference implementation.

Scope:
- Block types: verbatim (1), aligned-offset (2), uncompressed (3).
- Window sizes 2^15..2^21 (15..21 bits).
- x86 E8 jmp translation ("Intel preprocessing") — applied per 32 KiB frame.
- Multi-CFDATA decoding with 16-bit alignment between CAB chunks.

Reference: libmspack/mspack/lzxd.c.
"""

from __future__ import annotations

# ─── constants ──────────────────────────────────────────────────────────────

MIN_MATCH = 2
MAX_MATCH = 257
NUM_CHARS = 256

LZX_PRETREE_NUM_ELEMENTS = 20
LZX_ALIGNED_NUM_ELEMENTS = 8
LZX_NUM_PRIMARY_LENGTHS = 7
LZX_NUM_SECONDARY_LENGTHS = 249

LZX_BLOCKTYPE_INVALID = 0
LZX_BLOCKTYPE_VERBATIM = 1
LZX_BLOCKTYPE_ALIGNED = 2
LZX_BLOCKTYPE_UNCOMPRESSED = 3

LZX_FRAME_SIZE = 32768
LZX_E8_CUTOFF = 0x40000000  # E8 translation disabled past 1 GiB of output

_POSITION_SLOTS_PER_WINDOW = {15: 30, 16: 32, 17: 34, 18: 36, 19: 38, 20: 42, 21: 50}

_EXTRA_BITS = [
    0,
    0,
    0,
    0,
    1,
    1,
    2,
    2,
    3,
    3,
    4,
    4,
    5,
    5,
    6,
    6,
    7,
    7,
    8,
    8,
    9,
    9,
    10,
    10,
    11,
    11,
    12,
    12,
    13,
    13,
    14,
    14,
    15,
    15,
    16,
    16,
    17,
    17,
    17,
    17,
    17,
    17,
    17,
    17,
    17,
    17,
    17,
    17,
    17,
    17,
    17,
]


def _build_position_base() -> list[int]:
    base = [0] * 51
    acc = 0
    for i in range(1, 51):
        acc += 1 << _EXTRA_BITS[i - 1]
        base[i] = acc
    return base


_POSITION_BASE = _build_position_base()


# ─── bit reader ─────────────────────────────────────────────────────────────


class LzxBitReader:
    """LSB-byte / MSB-bit reader matching libmspack's INPUT/READ_BITS macros.

    Words are fetched 16 bits at a time, little-endian. Bits within an
    accumulator are consumed MSB-first.
    """

    __slots__ = ("data", "pos", "_bits", "_nbits")

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        self.data = memoryview(data) if not isinstance(data, memoryview) else data
        self.pos = 0
        self._bits = 0
        self._nbits = 0

    def _fill(self, need: int) -> None:
        while self._nbits < need:
            if self.pos + 1 < len(self.data):
                lo = self.data[self.pos]
                hi = self.data[self.pos + 1]
                self.pos += 2
                word = (hi << 8) | lo
            elif self.pos < len(self.data):
                lo = self.data[self.pos]
                self.pos += 1
                word = lo
            else:
                word = 0
            # Place word so its MSB lands at bit position (_nbits + 15).
            self._bits = (self._bits << 16) | word
            self._nbits += 16

    def peek(self, n: int) -> int:
        if n == 0:
            return 0
        self._fill(n)
        return (self._bits >> (self._nbits - n)) & ((1 << n) - 1)

    def read(self, n: int) -> int:
        if n == 0:
            return 0
        self._fill(n)
        result = (self._bits >> (self._nbits - n)) & ((1 << n) - 1)
        self._nbits -= n
        self._bits &= (1 << self._nbits) - 1
        return result

    def realign(self) -> None:
        drop = self._nbits & 15
        if drop:
            self._nbits -= drop
            self._bits &= (1 << self._nbits) - 1

    def align_for_uncompressed_block(self) -> None:
        """Drop 1..16 bits to byte-align per libmspack's UNCOMPRESSED block rule.

        - If the buffer is empty: read a full 16-bit word from input then drop
          it (= consume 2 padding bytes).
        - Otherwise: drop whatever's in the buffer (= 1..16 bits).
        """
        if self._nbits == 0:
            self._fill(16)
        self._nbits = 0
        self._bits = 0

    def read_uint32(self) -> int:
        """Read a 32-bit LE uint that's word-aligned in the bit stream.

        LZX stores 32-bit headers (E8 translation_size, R0/R1/R2 in uncompressed
        blocks) as two 16-bit words, *high word first* in bit-stream order
        (which inverts to "low byte first per word" once the words land in the
        accumulator).
        """
        hi = self.read(16)
        lo = self.read(16)
        return (hi << 16) | lo


# ─── canonical Huffman decoder ──────────────────────────────────────────────


def build_huffman_table(lengths: list[int]) -> tuple[list[int], list[int], list[int]]:
    """Build canonical-Huffman decode tables from per-symbol code lengths."""
    n = len(lengths)
    max_len = max(lengths) if lengths else 0

    counts = [0] * (max_len + 2)
    for ln in lengths:
        if ln > 0:
            counts[ln] += 1

    first = [0] * (max_len + 2)
    last = [0] * (max_len + 2)
    code = 0
    for L in range(1, max_len + 1):
        code <<= 1
        first[L] = code
        code += counts[L]
        last[L] = code
        if code > (1 << L):
            raise ValueError(f"Huffman lengths not prefix-free at len={L}: code={code}")

    offsets = [0] * (max_len + 2)
    for L in range(1, max_len + 1):
        offsets[L + 1] = offsets[L] + counts[L]
    table = [0] * n
    pos = list(offsets)  # mutable copy
    for sym, ln in enumerate(lengths):
        if ln == 0:
            continue
        table[pos[ln]] = sym
        pos[ln] += 1

    return table, first, last


def huff_decode(
    br: LzxBitReader,
    table: list[int],
    first: list[int],
    last: list[int],
) -> int:
    code = 0
    base = 0
    max_len = len(first) - 2
    for L in range(1, max_len + 1):
        code = (code << 1) | br.read(1)
        if code < last[L]:
            return table[base + (code - first[L])]
        base += last[L] - first[L]
    raise ValueError("Huffman decode: code exceeded maximum length")


# ─── pre-tree (delta-encoded code length decoding) ──────────────────────────


def _read_pretree_lengths(
    br: LzxBitReader,
    target: list[int],
    start: int,
    end: int,
) -> None:
    """Decode code lengths into target[start:end], updating target in place.

    LZX delta-encodes the new block's tree lengths relative to the previous
    block's. The pre-tree decodes:
        z in 0..16  -> new_length = (prev - z) mod 17
        z == 17     -> run of (4..19) zero lengths
        z == 18     -> run of (20..51) zero lengths
        z == 19     -> 1 extra bit + 4 copies of (prev - next_pretree_sym) mod 17
    """
    pre_lens = [br.read(4) for _ in range(LZX_PRETREE_NUM_ELEMENTS)]
    table, first, last = build_huffman_table(pre_lens)

    i = start
    while i < end:
        z = huff_decode(br, table, first, last)
        if z in (17, 18):
            run = (br.read(4) + 4) if z == 17 else (br.read(5) + 20)
            for _ in range(run):
                if i >= end:
                    break
                target[i] = 0
                i += 1
        elif z == 19:
            run = br.read(1) + 4
            y = huff_decode(br, table, first, last)
            new_len = (target[i] - y) % 17
            for _ in range(run):
                if i >= end:
                    break
                target[i] = new_len
                i += 1
        else:
            target[i] = (target[i] - z) % 17
            i += 1


# ─── E8 (x86 jmp) translation ───────────────────────────────────────────────


def _e8_translate_frame(
    buf: bytearray,
    frame_start_in_buf: int,
    frame_len: int,
    abs_output_pos: int,
    intel_filesize: int,
) -> None:
    """Reverse the encoder's E8 jmp/call relativization, in place, for one frame.

    The encoder converted PC-relative `call rel32` offsets to absolute file
    positions (rel + abs_pos) so they compress better across binaries with
    different load addresses. We reverse the operation.

    Per libmspack: only the first (LZX_E8_CUTOFF - 10) bytes of total output
    are eligible, and frames shorter than 10 bytes are skipped.
    """
    if intel_filesize == 0 or frame_len < 10:
        return
    if abs_output_pos >= LZX_E8_CUTOFF:
        return
    # Translate up to 10 bytes before the end of the frame.
    i = frame_start_in_buf
    end = frame_start_in_buf + frame_len - 10
    while i < end:
        if buf[i] == 0xE8:
            curpos = abs_output_pos + (i - frame_start_in_buf)
            rel = buf[i + 1] | (buf[i + 2] << 8) | (buf[i + 3] << 16) | (buf[i + 4] << 24)
            if rel & 0x80000000:
                rel -= 0x100000000
            # libmspack: if rel >= -curpos && rel < intel_filesize:
            #              if rel >= 0: out = rel - curpos
            #              else:        out = rel + intel_filesize - curpos
            if rel >= -curpos and rel < intel_filesize:
                # libmspack: rel_off = (abs >= 0) ? abs - curpos : abs + filesize.
                # The negative branch does NOT subtract curpos.
                new_rel = (rel - curpos if rel >= 0 else rel + intel_filesize) & 0xFFFFFFFF
                buf[i + 1] = new_rel & 0xFF
                buf[i + 2] = (new_rel >> 8) & 0xFF
                buf[i + 3] = (new_rel >> 16) & 0xFF
                buf[i + 4] = (new_rel >> 24) & 0xFF
            i += 5
        else:
            i += 1


# ─── main decoder ───────────────────────────────────────────────────────────


class LzxDecoder:
    """Stateful LZX decoder for CAB folders.

    Construct once per CAB folder; feed CFDATA payloads via decompress_chunk().
    The LZ window, recent-offset queue, and Huffman tree code-length arrays
    persist across CFDATA boundaries.
    """

    def __init__(self, window_bits: int) -> None:
        if window_bits not in _POSITION_SLOTS_PER_WINDOW:
            raise ValueError(f"unsupported LZX window bits: {window_bits}")
        self.window_size = 1 << window_bits
        self.window = bytearray(self.window_size)
        self.window_posn = 0
        num_position_slots = _POSITION_SLOTS_PER_WINDOW[window_bits]
        self.main_size = NUM_CHARS + 8 * num_position_slots

        self.r0 = 1
        self.r1 = 1
        self.r2 = 1

        self.main_lens = [0] * self.main_size
        self.length_lens = [0] * LZX_NUM_SECONDARY_LENGTHS

        self.main_table: list[int] = []
        self.main_first: list[int] = []
        self.main_last: list[int] = []
        self.length_table: list[int] = []
        self.length_first: list[int] = []
        self.length_last: list[int] = []
        self.aligned_table: list[int] = []
        self.aligned_first: list[int] = []
        self.aligned_last: list[int] = []

        self.header_read = False
        self.intel_filesize = 0
        self.intel_started = False

        self.output_pos = 0
        self.block_type = LZX_BLOCKTYPE_INVALID
        self.block_length = 0  # original size — needed for the odd-uncompressed pad check
        self.block_remaining = 0

    # ---------------- public

    def decompress(self, data: bytes, output_size: int) -> bytes:
        br = LzxBitReader(data)
        return self.decompress_chunk(br, output_size)

    def decompress_chunk(self, br: LzxBitReader, chunk_uncomp: int) -> bytes:
        """Decode one CAB chunk = one LZX frame.

        - chunk_uncomp is normally 32768 (LZX_FRAME_SIZE); the final CFDATA in
          a folder may be shorter.
        - On entry the bit reader is implicitly word-aligned (callers pass
          a fresh reader per CFDATA, since CAB realigns at every boundary).
        - After producing chunk_uncomp bytes, applies E8 translation to the
          whole frame if intel_started + intel_filesize say so.
        """
        if not self.header_read:
            self.header_read = True
            intel = br.read(1)
            if intel:
                self.intel_filesize = br.read_uint32()

        out = bytearray()
        target = chunk_uncomp
        while target > 0:
            if self.block_remaining == 0:
                # libmspack: if previous block was an odd-length UNCOMPRESSED
                # block, the encoder emitted exactly one padding byte. Skip it.
                # This MUST happen every time block_remaining transitions to 0,
                # not only at chunk boundaries.
                if self.block_type == LZX_BLOCKTYPE_UNCOMPRESSED and self.block_length & 1:
                    br.pos += 1
                self._read_block_header(br)

            n = min(self.block_remaining, target)

            if self.block_type == LZX_BLOCKTYPE_UNCOMPRESSED:
                self._decode_uncompressed(br, n, out)
            else:
                aligned = self.block_type == LZX_BLOCKTYPE_ALIGNED
                self._decode_compressed_block(br, n, aligned, out)

            self.block_remaining -= n
            target -= n

        # Per-frame E8 translation. libmspack semantics:
        #   if intel_started and intel_filesize and frame_index < 32768
        #      and frame_size > 10: scan E8 bytes in the frame buffer.
        if (
            self.intel_started
            and self.intel_filesize
            and self.output_pos < (32768 * LZX_FRAME_SIZE)
            and len(out) > 10
        ):
            _e8_translate_frame(
                out,
                frame_start_in_buf=0,
                frame_len=len(out),
                abs_output_pos=self.output_pos,
                intel_filesize=self.intel_filesize,
            )

        self.output_pos += len(out)

        # End-of-frame realign to a 16-bit word boundary (libmspack lzxd.c L696).
        if br._nbits > 0:
            br._fill(16)
        drop = br._nbits & 15
        if drop:
            br.read(drop)
        return bytes(out)

    # ---------------- internals

    def _read_block_header(self, br: LzxBitReader) -> None:
        self.block_type = br.read(3)
        if self.block_type not in (
            LZX_BLOCKTYPE_VERBATIM,
            LZX_BLOCKTYPE_ALIGNED,
            LZX_BLOCKTYPE_UNCOMPRESSED,
        ):
            raise ValueError(f"invalid LZX block type {self.block_type}")
        # Block length is 24 bits: high-16 then low-8 (libmspack lzxd.c L478).
        hi16 = br.read(16)
        lo8 = br.read(8)
        self.block_length = (hi16 << 8) | lo8
        self.block_remaining = self.block_length

        if self.block_type == LZX_BLOCKTYPE_ALIGNED:
            aligned_lens = [br.read(3) for _ in range(LZX_ALIGNED_NUM_ELEMENTS)]
            (
                self.aligned_table,
                self.aligned_first,
                self.aligned_last,
            ) = build_huffman_table(aligned_lens)

        if self.block_type in (LZX_BLOCKTYPE_VERBATIM, LZX_BLOCKTYPE_ALIGNED):
            _read_pretree_lengths(br, self.main_lens, 0, NUM_CHARS)
            _read_pretree_lengths(br, self.main_lens, NUM_CHARS, self.main_size)
            self.main_table, self.main_first, self.main_last = build_huffman_table(self.main_lens)
            # If literal byte 0xE8 has any code in this block's main tree, the
            # encoder may emit E8s — flip intel_started so the per-frame E8
            # translation kicks in for this and subsequent frames.
            if self.main_lens[0xE8] != 0:
                self.intel_started = True

            _read_pretree_lengths(br, self.length_lens, 0, LZX_NUM_SECONDARY_LENGTHS)
            self.length_table, self.length_first, self.length_last = build_huffman_table(
                self.length_lens
            )

        elif self.block_type == LZX_BLOCKTYPE_UNCOMPRESSED:
            # An uncompressed block can contain literal E8 bytes without
            # warning — assume worst case and enable E8 translation.
            self.intel_started = True
            # libmspack: drop 1..16 bits to byte-align (force-read 16 padding
            # bits if the bit buffer was already empty).
            br.align_for_uncompressed_block()
            if br.pos + 12 > len(br.data):
                raise ValueError("LZX uncompressed block: not enough input for R values")
            self.r0 = int.from_bytes(br.data[br.pos : br.pos + 4], "little")
            self.r1 = int.from_bytes(br.data[br.pos + 4 : br.pos + 8], "little")
            self.r2 = int.from_bytes(br.data[br.pos + 8 : br.pos + 12], "little")
            br.pos += 12

    def _decode_uncompressed(self, br: LzxBitReader, n: int, out: bytearray) -> None:
        # Bit accumulator is empty here (aligned in _read_block_header). The
        # odd-length pad byte is handled at the block boundary, not per-call —
        # `n` is the bytes-this-call, which can be odd even when the whole
        # block is even.
        end = br.pos + n
        if end > len(br.data):
            raise ValueError("LZX uncompressed block: not enough input bytes")
        chunk = bytes(br.data[br.pos : end])
        br.pos = end
        out.extend(chunk)
        self._mirror_to_window(chunk)

    def _mirror_to_window(self, chunk: bytes) -> None:
        """Copy `chunk` into the LZ window at window_posn, with wrap."""
        n = len(chunk)
        wsize = self.window_size
        posn = self.window_posn
        if posn + n <= wsize:
            self.window[posn : posn + n] = chunk
        else:
            first = wsize - posn
            self.window[posn:wsize] = chunk[:first]
            self.window[: n - first] = chunk[first:]
        self.window_posn = (posn + n) % wsize

    def _decode_compressed_block(
        self,
        br: LzxBitReader,
        n: int,
        aligned: bool,
        out: bytearray,
    ) -> None:
        # Hoist hot fields to locals — Python attribute access is ~3x slower.
        window = self.window
        wsize = self.window_size
        main_t, main_f, main_l = self.main_table, self.main_first, self.main_last
        len_t, len_f, len_l = self.length_table, self.length_first, self.length_last
        aln_t, aln_f, aln_l = self.aligned_table, self.aligned_first, self.aligned_last
        r0, r1, r2 = self.r0, self.r1, self.r2
        posn = self.window_posn
        target = len(out) + n

        while len(out) < target:
            main = huff_decode(br, main_t, main_f, main_l)
            if main < NUM_CHARS:
                out.append(main)
                window[posn] = main
                posn = (posn + 1) % wsize
                continue

            main -= NUM_CHARS
            length_header = main & LZX_NUM_PRIMARY_LENGTHS
            position_slot = main >> 3
            if length_header == LZX_NUM_PRIMARY_LENGTHS:
                match_length = (
                    MIN_MATCH + LZX_NUM_PRIMARY_LENGTHS + huff_decode(br, len_t, len_f, len_l)
                )
            else:
                match_length = MIN_MATCH + length_header

            if position_slot == 0:
                match_offset = r0
            elif position_slot == 1:
                match_offset = r1
                r1 = r0
                r0 = match_offset
            elif position_slot == 2:
                match_offset = r2
                r2 = r0
                r0 = match_offset
            else:
                extra = _EXTRA_BITS[position_slot]
                if aligned and extra >= 3:
                    verbatim = br.read(extra - 3) << 3
                    formatted_offset = (
                        _POSITION_BASE[position_slot]
                        + verbatim
                        + huff_decode(br, aln_t, aln_f, aln_l)
                    )
                elif extra > 0:
                    formatted_offset = _POSITION_BASE[position_slot] + br.read(extra)
                else:
                    formatted_offset = _POSITION_BASE[position_slot]
                match_offset = formatted_offset - 2
                r2 = r1
                r1 = r0
                r0 = match_offset

            src = (posn - match_offset) % wsize
            remaining = target - len(out)
            emit = min(match_length, remaining)
            if emit < match_length:
                raise ValueError(
                    "LZX match crossed block boundary — corrupt stream or our bookkeeping is wrong"
                )

            # Fast path: non-overlapping match (offset >= length) AND no window
            # wrap on either side. Slice-copy is much faster than byte-by-byte.
            if match_offset >= emit and src + emit <= wsize and posn + emit <= wsize:
                chunk = bytes(window[src : src + emit])
                out.extend(chunk)
                window[posn : posn + emit] = chunk
                posn += emit
            else:
                # Overlap / wrap: fall back to per-byte LZ77 expansion. This is
                # the only correct path when match_offset < emit (RLE-style).
                for _ in range(emit):
                    b = window[src]
                    out.append(b)
                    window[posn] = b
                    posn = (posn + 1) % wsize
                    src = (src + 1) % wsize

        self.r0, self.r1, self.r2 = r0, r1, r2
        self.window_posn = posn
