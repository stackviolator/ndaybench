# ndaybench

A benchmark for measuring whether AI agents can build working exploits from
n-day patches. This repository hosts the data-acquisition pipeline that feeds
the benchmark — **patchwatch** — along with the planning docs for the
benchmark harness itself.

The thesis: given a CVE, its public description, and the patched + previous
binaries, can an agent produce an exploit that triggers the vulnerability on
the unpatched target? Today the answer is mostly unknown because nobody has a
reproducible eval. This repo is the start of one.

## What's in here

```
.
├── src/patchwatch/      # patchwatch CLI — CVE → binary pair → ghidriff diff
├── docs/                # data-flow diagrams
├── Dockerfile.ghidriff  # pinned ghidriff image (Ghidra 11.3.1 compat)
├── pyproject.toml
└── uv.lock
```

`patchwatch` is the n-day acquisition pipeline:

1. Pull CVE metadata from Microsoft's Security Update Guide (SUG).
2. Pick the right KB(s) for the affected products (Windows, SharePoint,
   Exchange, Office MSPs).
3. Enumerate the files the patch changes.
4. Resolve and download the patched + previous binary versions from
   Winbindex / the Microsoft Symbol Server.
5. Run `ghidriff` (Ghidra-based binary differ) to produce structured
   function-level diffs and decompiler output.
6. Bundle the result as a "PoC kit" — pre/post binaries + diff +
   decompilation, ready to hand to an agent or analyst.

There are **no LLMs in the pipeline**. Every stage is deterministic.

## Install

Requires Python 3.12+ and [uv](https://github.com/astral-sh/uv).

```bash
git clone git@github.com:stackviolator/ndaybench.git
cd ndaybench
uv sync
```

You also need Docker for the `diff` stage. The first run builds the pinned
ghidriff image:

```bash
docker build -f Dockerfile.ghidriff -t ghidriff-fixed:latest .
```

> Why pinned? The upstream `ghidriff:latest` ships Ghidra 11.3.1 but `pyghidra
> 3.x` requires Ghidra 12.0+. This Dockerfile pins `pyghidra` back to the last
> 11.3-compatible release. See [clearbluejar/ghidriff#134](https://github.com/clearbluejar/ghidriff/issues/134).

## Quickstart

```bash
# 1. Look up a CVE and pick target KBs.
uv run patchwatch ingest CVE-2025-26633

# 2. List the binaries each KB ships.
uv run patchwatch list CVE-2025-26633

# 3. Acquire patched + previous binary pairs into the cache.
#    Filter by filename — agents/analysts pick which to download.
uv run patchwatch acquire CVE-2025-26633 --files mscms.dll --files msctf.dll

# 4. Run the diff. Writes ghidriff JSON + markdown into the cache.
uv run patchwatch diff ~/.cache/patchwatch/manifests/CVE-2025-26633.json

# 5. Bundle the artifacts as a PoC kit.
uv run patchwatch export-poc CVE-2025-26633 --workspace ./poc-CVE-2025-26633

# 6. Render a markdown narrative report.
uv run patchwatch report CVE-2025-26633
```

For SharePoint / Exchange / Office CVEs the patch ships as an MSP rather than
an MSU. patchwatch handles both — the MSP path needs a previous KB, which is
auto-discovered via SUG history but can be pinned explicitly:

```bash
uv run patchwatch acquire CVE-2025-XXXXX \
  --previous KB5002822:KB5002815 \
  --files some.dll
```

## Pipeline at a glance

```
SUG  ──►  pick targets (Windows MSU / SharePoint MSP / Exchange MSP / Office MSP)
              │
              ▼
       enumerate files per KB
       ├── Windows: support-page CSV (tier 1) → Update Catalog MSU (tier 2)
       └── MSP:     OLE compound doc → embedded CAB → manifest XML
              │
              ▼
       resolve pre/post versions
       ├── Winbindex (filename → list of (version, timestamp, virtual_size))
       └── Microsoft Symbol Server (msdl) — download by <ts><vsize>
              │
              ▼
       ghidriff (Ghidra under the hood, sibling Docker container)
              │
              ▼
       PoC bundle:  manifest.json + pre/ + post/ + ghidriff/ + report.md
```

Implementation details worth knowing:

- **CAB + LZX in pure Python.** Origin's Rust prototype shells out to
  `expand.exe`; this rewrite implements CAB v1.3 with LZX and MSZIP from
  scratch (`src/patchwatch/cab.py`, `src/patchwatch/lzx.py`). The LZX decoder
  is validated byte-perfect against `cabextract` on a 980 MB SharePoint CAB.
  Means patchwatch runs on macOS and Linux, not just Windows.
- **Forward-compat manifests.** Every artifact emits a schema version
  (`MANIFEST_SCHEMA_VERSION`, `DIFFS_SCHEMA_VERSION`,
  `POC_BUNDLE_SCHEMA_VERSION` in `_schema.py`) so downstream consumers can
  fail fast on incompatible inputs.
- **ghidriff is slow; we tune it.** `--no-bsim`, JVM heap bumped via
  `PATCHWATCH_GHIDRIFF_HEAP`, persistent project caches. A typical CVE diffs
  in 30-90s warm and 2-5min cold.
- **The cache is content-addressed.** Re-running `acquire` for the same CVE
  is a no-op.

## ndaybench (planning)

The benchmark itself is in design. The goal:

- **Input:** a CVE entry with CVSS, description, CWE, and the patchwatch
  bundle (pre/post binaries + decompiled diff).
- **Task:** the agent must produce an exploit script that, when run against
  the unpatched VM, triggers the vulnerability.
- **Oracle:** a deterministic ladder of signals — crash, hijacked
  control-flow, shell, full RCE on a labeled target. Closest analogue is
  ExploitBench's 16-flag scoring rubric.
- **Contamination defense:** time-windowed releases. `release_2026_06` only
  contains CVEs published after the model's cutoff, à la LiveCodeBench.

Plan and research notes live in the standalone `patchwatch-server` repo for
now and will be folded in once the harness lands.

## License

Apache 2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

The Python `patchwatch` CLI is a from-scratch reimplementation. The original
Rust prototype was built by [Origin](https://originhq.com); their patch
diffing pipeline writeup is at
<https://www.originhq.com/research/patch-diffing-pipeline>.
