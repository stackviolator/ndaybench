"""patchwatch CLI."""

from __future__ import annotations

import asyncio
import dataclasses
import json
from dataclasses import asdict
from importlib.metadata import version as _pkg_version
from pathlib import Path

import httpx
import typer

from ._schema import DIFFS_SCHEMA_VERSION, MANIFEST_SCHEMA_VERSION
from .adapter import Arch, KbFile
from .cache import Cache
from .diff import GhidriffError, run_ghidriff, staged_label
from .ingest import TargetKb, pick_targets
from .markdown_report import render_from_disk as _render_report_from_disk
from .msp_adapter import MspAdapter
from .poc_bundle import build_bundle
from .sug import SugClient, Vulnerability
from .windows import WindowsAdapter

PATCHWATCH_VERSION = _pkg_version("patchwatch")

app = typer.Typer(
    help="Patch Tuesday CVE ingestion + binary diff pipeline.",
    no_args_is_help=True,
)

_DEFAULT_CACHE = Path.home() / ".cache" / "patchwatch"


def _version_callback(value: bool) -> None:
    if value:
        print(PATCHWATCH_VERSION)
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(  # noqa: B008
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Print patchwatch version and exit.",
    ),
) -> None:
    """patchwatch — Patch Tuesday CVE → binary diff pipeline."""


@app.command()
def ingest(
    cve_id: str = typer.Argument(..., help="CVE identifier, e.g. CVE-2025-26633"),
    base_url: str = typer.Option("https://api.msrc.microsoft.com/sug/v2.0", help="SUG base URL"),
    language: str = typer.Option("en-US", help="SUG language"),
) -> None:
    """Fetch CVE detail from SUG and pick the target KBs. Prints JSON to stdout."""
    result = asyncio.run(_ingest(cve_id, base_url, language))
    print(json.dumps(result, indent=2))


@app.command(name="list")
def list_cmd(
    cve_id: str = typer.Argument(..., help="CVE identifier"),
) -> None:
    """List candidate binaries per target KB (no downloads).

    Returns JSON describing each target KB and the x64 PE files it ships.
    Use this to pick which filenames to feed into `acquire --files`.
    """
    result = asyncio.run(_list_candidates(cve_id))
    print(json.dumps(result, indent=2, default=_json_default))


@app.command()
def acquire(
    cve_id: str = typer.Argument(..., help="CVE identifier"),
    files: list[str] = typer.Option(  # noqa: B008
        [],
        "--files",
        help="Exact filenames to acquire (repeatable, case-insensitive). "
        "If omitted, acquires every x64 PE in the KB.",
    ),
    previous: list[str] = typer.Option(  # noqa: B008
        [],
        "--previous",
        help="Previous KB(s) for non-Windows families. Two forms accepted: "
        "explicit `--previous KB5002822:KB5002815` maps a target KB to its prior, "
        "or bare `--previous KB5002815` (positional, first non-Windows target). "
        "Omit entirely to auto-discover via SUG history.",
    ),
    cache_dir: Path = typer.Option(  # noqa: B008
        _DEFAULT_CACHE,
        help="Where to cache binaries + artifacts.",
    ),
    limit: int = typer.Option(
        0, help="Only acquire pairs for the first N files per target. 0 = all."
    ),
    name_filter: list[str] = typer.Option(  # noqa: B008
        [],
        "--name-filter",
        help="Substring filter on filename (case-insensitive). "
        "Repeat for OR semantics, e.g. --name-filter dns --name-filter rpc.",
    ),
) -> None:
    """Run the full pipeline for a CVE: pick targets → list files → acquire pairs.

    Writes a manifest.json to <cache_dir>/manifests/<CVE>.json describing every
    pair on disk, ready for the diff stage.

    Unchanged binaries (identical SHA256 in pre/post Winbindex entries) are
    skipped automatically — the actual count of changed binaries per KB is
    typically 1-2 orders of magnitude smaller than the raw KB file list.
    """
    result = asyncio.run(_acquire(cve_id, previous, cache_dir, limit, name_filter, files))
    print(json.dumps(result, indent=2, default=_json_default))


def _json_default(obj: object) -> object:
    if dataclasses.is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, Path):
        return str(obj)
    raise TypeError(f"not JSON serializable: {type(obj).__name__}")


async def _ingest(cve_id: str, base_url: str, language: str) -> dict[str, object]:
    async with SugClient(base_url=base_url, language=language) as sug:
        cve, targets, n_products = await _fetch_targets(sug, cve_id)
    return _ingest_payload(cve, targets, n_affected_products=n_products)


async def _find_previous_kb(sug: SugClient, current_release: str, product_name: str) -> str | None:
    """Walk back through SUG releases for the previous KB matching `product_name`.

    Returns None if nothing's found in a 6-month lookback window.
    """
    releases = await sug.list_releases()
    try:
        idx = next(i for i, r in enumerate(releases) if r.release_number == current_release)
    except StopIteration:
        return None
    target_product = product_name.lower()
    # CVE titles contain the product family name (e.g. "Microsoft SharePoint
    # ... Vulnerability"); use the first product word as a cheap pre-filter
    # so we don't fetch affectedProducts for unrelated CVEs.
    product_hint = next(
        (
            w
            for w in target_product.split()
            if w not in {"microsoft", "the", "and", "for", "server"}
        ),
        "",
    )
    for prior in releases[idx + 1 : idx + 7]:
        vulns = await sug.vulnerabilities_in_release(prior.release_number)
        candidates = [v for v in vulns if product_hint in (v.cve_title or "").lower()]
        for v in candidates:
            products = await sug.affected_products(v.cve_number)
            for p in products:
                if (p.product or "").lower() != target_product:
                    continue
                for kb in p.kb_articles or []:
                    name = kb.article_name
                    if not name:
                        continue
                    digits = name.removeprefix("KB").removeprefix("kb")
                    if digits.isdigit():
                        return f"KB{digits}"
    return None


def _parse_previous_flags(
    flags: list[str], non_win_targets: list[TargetKb]
) -> dict[str, str]:
    """Parse --previous values into a {target_kb -> previous_kb} map.

    Two accepted forms per flag value:
    - `KB_TGT:KB_PREV` — explicit mapping, order-independent.
    - bare `KB_PREV`   — positional; assigns to non_win_targets in order.

    Bare and explicit forms can be mixed.
    """
    explicit: dict[str, str] = {}
    positional: list[str] = []
    for raw in flags:
        if ":" in raw:
            tgt, _, prev = raw.partition(":")
            if not tgt or not prev:
                raise typer.BadParameter(f"--previous {raw!r}: expected KB_TGT:KB_PREV")
            explicit[tgt] = prev
        else:
            positional.append(raw)
    if len(positional) > len(non_win_targets):
        raise typer.BadParameter(
            f"got {len(positional)} positional --previous flags but only "
            f"{len(non_win_targets)} non-Windows targets in this CVE"
        )
    prev_map = dict(zip([t.kb_id for t in non_win_targets], positional, strict=False))
    unknown = explicit.keys() - {t.kb_id for t in non_win_targets}
    if unknown:
        raise typer.BadParameter(
            f"--previous targets not in CVE's non-Windows targets: {sorted(unknown)}"
        )
    prev_map.update(explicit)
    return prev_map


async def _fetch_targets(sug: SugClient, cve_id: str) -> tuple[Vulnerability, list[TargetKb], int]:
    cve = await sug.vulnerability_detail(cve_id)
    if cve is None:
        raise typer.BadParameter(f"CVE {cve_id} not found in SUG")
    products = await sug.affected_products(cve_id)
    targets = pick_targets(products)
    if not targets:
        raise typer.BadParameter(
            f"no Windows/SharePoint/Exchange x64 KB found in affectedProducts for {cve_id}"
        )
    return cve, targets, len(products)


def _ingest_payload(
    cve: Vulnerability, targets: list[TargetKb], *, n_affected_products: int
) -> dict[str, object]:
    return {
        "cve_id": cve.cve_number,
        "title": cve.cve_title,
        "description": cve.description,
        "cwe": cve.cwe_id,
        "cvss": cve.base_score,
        "severity": cve.severity,
        "exploited": cve.exploited,
        "publicly_disclosed": cve.publicly_disclosed,
        "release_number": cve.release_number,
        "release_date": cve.release_date,
        "revision_number": cve.revision_number,
        "n_affected_products": n_affected_products,
        "targets": [asdict(t) for t in targets],
    }


async def _list_candidates(cve_id: str) -> dict[str, object]:
    """Cheap KB enumeration. No Winbindex calls, no downloads."""
    async with httpx.AsyncClient(
        timeout=120.0,
        follow_redirects=True,
        headers={"user-agent": "patchwatch/0.1"},
    ) as http:
        sug = SugClient(client=http)
        cve, targets, n_products = await _fetch_targets(sug, cve_id)
        candidates_by_target: list[dict[str, object]] = []
        cache = Cache(_DEFAULT_CACHE)
        for t in targets:
            if t.family not in ("windows-client", "windows-server"):
                candidates_by_target.append(
                    {
                        "target": asdict(t),
                        "status": "not-listed",
                        "reason": "non-Windows families require an MSP extraction to list "
                        "(slow); use acquire with --files instead",
                    }
                )
                continue
            adapter = WindowsAdapter(cache, http=http)
            try:
                files = _filter_pe(await adapter.list_files(t.kb_id))
            except Exception as e:  # noqa: BLE001
                candidates_by_target.append(
                    {"target": asdict(t), "status": "failed", "error": str(e)}
                )
                continue
            candidates_by_target.append(
                {
                    "target": asdict(t),
                    "status": "ok",
                    "n_candidates": len(files),
                    "files": [
                        {
                            "filename": f.filename,
                            "version": f.version,
                            "arch": f.arch.value,
                            "file_size": f.file_size,
                        }
                        for f in files
                    ],
                }
            )

    payload = _ingest_payload(cve, targets, n_affected_products=n_products)
    payload["candidates"] = candidates_by_target
    return payload


async def _acquire(
    cve_id: str,
    previous: list[str],
    cache_dir: Path,
    limit: int,
    name_filter: list[str] | None = None,
    files: list[str] | None = None,
) -> dict[str, object]:
    """Run target selection + per-target acquisition. Returns a manifest dict."""
    cache = Cache(cache_dir)
    async with httpx.AsyncClient(
        timeout=600.0,
        follow_redirects=True,
        headers={"user-agent": "patchwatch/0.1"},
    ) as http:
        sug = SugClient(client=http)
        cve, targets, n_products = await _fetch_targets(sug, cve_id)

        non_win_targets = [
            t for t in targets if t.family not in ("windows-client", "windows-server")
        ]
        prev_map = _parse_previous_flags(previous, non_win_targets)
        if cve.release_number:
            for t in non_win_targets:
                if not prev_map.get(t.kb_id):
                    auto = await _find_previous_kb(sug, cve.release_number, t.product)
                    if auto:
                        prev_map[t.kb_id] = auto

        explicit_files = {f.lower() for f in (files or [])}
        manifest_targets: list[dict[str, object]] = []
        for target in targets:
            target_payload = await _acquire_one(
                target,
                prev_map,
                cache,
                http,
                limit,
                name_filter or [],
                explicit_files,
            )
            manifest_targets.append(target_payload)

    manifest: dict[str, object] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "patchwatch_version": PATCHWATCH_VERSION,
    }
    manifest.update(_ingest_payload(cve, targets, n_affected_products=n_products))
    manifest["acquisitions"] = manifest_targets

    manifests_dir = cache_dir / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    out_path = manifests_dir / f"{cve_id}.json"
    out_path.write_text(json.dumps(manifest, indent=2, default=_json_default))
    manifest["manifest_path"] = str(out_path)
    return manifest


_WIN_CONCURRENCY = 8  # parallel winbindex fetches; tuned to be polite


async def _acquire_one(
    target: TargetKb,
    prev_map: dict[str, str],
    cache: Cache,
    http: httpx.AsyncClient,
    limit: int,
    name_filter: list[str],
    explicit_files: set[str],
) -> dict[str, object]:
    if target.family in ("windows-client", "windows-server"):
        pairs, skipped = await _acquire_windows(
            target, cache, http, limit, name_filter, explicit_files
        )
    else:
        previous_kb = prev_map.get(target.kb_id)
        if previous_kb is None:
            return {
                "target": asdict(target),
                "status": "skipped",
                "reason": "no --previous KB supplied for non-Windows family",
            }
        pairs, skipped = await _acquire_msp(
            target, previous_kb, cache, http, limit, name_filter, explicit_files
        )

    return {
        "target": asdict(target),
        "status": "ok",
        "n_pairs": len(pairs),
        "n_skipped": len(skipped),
        "pairs": pairs,
        "skipped": skipped,
    }


async def _acquire_windows(
    target: TargetKb,
    cache: Cache,
    http: httpx.AsyncClient,
    limit: int,
    name_filter: list[str],
    explicit_files: set[str],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    adapter = WindowsAdapter(cache, http=http)
    files = _filter_pe(await adapter.list_files(target.kb_id))
    files = _select_files(files, name_filter, explicit_files)
    if limit:
        files = files[:limit]

    sem = asyncio.Semaphore(_WIN_CONCURRENCY)

    async def acquire(file: KbFile) -> tuple[KbFile, object]:
        async with sem:
            return file, await adapter.acquire_pair(target.kb_id, file)

    results = await asyncio.gather(*(acquire(f) for f in files))
    pairs: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    for file, pair in results:
        if pair is None:
            skipped.append({"filename": file.filename, "reason": "no winbindex pair"})
        else:
            pairs.append(_pair_payload(pair))
    return pairs, skipped


async def _acquire_msp(
    target: TargetKb,
    previous_kb: str,
    cache: Cache,
    http: httpx.AsyncClient,
    limit: int,
    name_filter: list[str],
    explicit_files: set[str],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    # MSP path is CPU-bound on LZX decode (the catalog + extract), not IO —
    # parallelism inside one KB extraction doesn't help. Run sequentially.
    pairs: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    async with MspAdapter(cache, previous_kb_id=previous_kb, http=http) as adapter:
        files = await adapter.list_files(target.kb_id)
        files = _select_files(files, name_filter, explicit_files)
        if limit:
            files = files[:limit]
        for file in files:
            pair = await adapter.acquire_pair(target.kb_id, file)
            if pair is None:
                skipped.append({"filename": file.filename, "reason": "no pair or unchanged"})
                continue
            pairs.append(_pair_payload(pair))
    return pairs, skipped


def _apply_name_filter(files: list[KbFile], substrings: list[str]) -> list[KbFile]:
    """Substring-OR filter on filename (case-insensitive). Empty list = passthrough."""
    if not substrings:
        return files
    needles = [s.lower() for s in substrings if s]
    return [f for f in files if any(n in f.filename.lower() for n in needles)]


def _select_files(
    files: list[KbFile], name_filter: list[str], explicit_files: set[str]
) -> list[KbFile]:
    """Apply --files (exact match) and --name-filter (substring), in that order.

    --files takes precedence: if the agent passed explicit names, those are
    the universe and --name-filter only narrows further. With no --files,
    --name-filter narrows the full PE set.
    """
    if explicit_files:
        files = [f for f in files if f.filename.lower() in explicit_files]
    return _apply_name_filter(files, name_filter)


def _filter_pe(files: list[KbFile]) -> list[KbFile]:
    """Restrict to x64 .dll/.exe/.sys files. Dedupe by filename (first wins)."""
    seen: set[str] = set()
    out: list[KbFile] = []
    for f in files:
        if f.arch != Arch.X64:
            continue
        ext = f.filename.lower().rsplit(".", 1)[-1] if "." in f.filename else ""
        if ext not in {"dll", "exe", "sys"}:
            continue
        if f.filename in seen:
            continue
        seen.add(f.filename)
        out.append(f)
    return out


def _pair_payload(pair: object) -> dict[str, object]:
    p = asdict(pair)  # BinaryPair → nested dict; Path/Confidence handled below
    for side in ("previous", "patched"):
        sub = p[side]
        if isinstance(sub.get("path"), Path):
            sub["path"] = str(sub["path"])
    # Confidence is a StrEnum; asdict leaves it as the enum instance.
    p["confidence"] = str(p["confidence"])
    return p


@app.command()
def diff(
    manifest: Path = typer.Argument(  # noqa: B008
        ..., help="Path to a manifest.json produced by `acquire`."
    ),
    output_dir: Path = typer.Option(  # noqa: B008
        _DEFAULT_CACHE / "diffs",
        help="Where to stage binaries + collect ghidriff JSON output.",
    ),
    diff_engine: str = typer.Option("docker", help="ghidriff execution mode: 'docker' or 'local'."),
    docker_image: str = typer.Option(
        "ghidriff-fixed:latest",
        help="Docker image to use in --diff-engine=docker mode.",
    ),
    ghidra_install_dir: str = typer.Option(
        "",
        help="GHIDRA_INSTALL_DIR for ghidriff (only used in --diff-engine=local).",
    ),
    limit: int = typer.Option(0, help="Diff at most N pairs per target. 0 = all."),
    no_report: bool = typer.Option(
        False,
        "--no-report",
        help="Skip rendering the per-CVE Markdown report next to the diffs JSON.",
    ),
) -> None:
    """Run ghidriff on every binary pair in the manifest. Writes diffs.json next to it."""
    result = asyncio.run(
        _diff(
            manifest,
            output_dir,
            ghidra_install_dir or None,
            limit,
            engine=diff_engine,
            docker_image=docker_image,
            write_report=not no_report,
        )
    )
    print(json.dumps(result, indent=2, default=_json_default))


@app.command()
def report(
    cve_id: str = typer.Argument(..., help="CVE identifier, e.g. CVE-2026-33824"),
    cache_dir: Path = typer.Option(  # noqa: B008
        _DEFAULT_CACHE,
        help="Cache root containing the manifests/ directory.",
    ),
    out: Path = typer.Option(  # noqa: B008
        None,
        "--out",
        help="Write Markdown here (default: <cache>/manifests/<CVE>.report.md). "
        "Use '-' for stdout.",
    ),
) -> None:
    """Re-render the per-CVE Markdown report from existing manifests on disk.

    Useful when the template has changed and you don't want to re-run `diff`.
    Reads `<cache>/manifests/<CVE>.json` + `<CVE>.diffs.json` (if present).
    """
    manifests_dir = cache_dir / "manifests"
    md = _render_report_from_disk(manifests_dir, cve_id)
    if out is not None and str(out) == "-":
        print(md, end="")
        return
    out_path = out or (manifests_dir / f"{cve_id}.report.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md)
    print(json.dumps({"cve_id": cve_id, "report_path": str(out_path)}, indent=2))


@app.command(name="export-poc")
def export_poc(
    cve_id: str = typer.Argument(..., help="CVE identifier, e.g. CVE-2026-33824"),
    workspace: Path = typer.Option(  # noqa: B008
        ...,
        "--workspace",
        help="Directory to populate with the PoC bundle (created if missing).",
    ),
    cache_dir: Path = typer.Option(  # noqa: B008
        _DEFAULT_CACHE,
        "--cache-dir",
        help="Cache root containing the manifests/ directory.",
    ),
) -> None:
    """Stage a hand-off PoC bundle for a CVE.

    Reads `<cache-dir>/manifests/<CVE>.json` (acquire manifest) and
    `<CVE>.diffs.json` (diff manifest), hard-links the pre/post binaries +
    ghidriff project tree into `<workspace>/`, and writes `context.json`
    plus `cve.md`. The workspace is fully self-contained — paths inside
    `context.json` are relative to its root.
    """
    manifests_dir = cache_dir / "manifests"
    manifest_path = manifests_dir / f"{cve_id}.json"
    diffs_path = manifests_dir / f"{cve_id}.diffs.json"
    if not manifest_path.exists():
        raise typer.BadParameter(
            f"manifest not found: {manifest_path} — run `patchwatch acquire {cve_id}` first"
        )
    if not diffs_path.exists():
        raise typer.BadParameter(
            f"diffs manifest not found: {diffs_path} — run `patchwatch diff` first"
        )
    bundle = build_bundle(manifest_path, diffs_path, workspace)
    print(
        json.dumps(
            {
                "cve_id": bundle.cve_id,
                "workspace": str(workspace.resolve()),
                "n_pre": len(bundle.prepatch_paths),
                "n_post": len(bundle.postpatch_paths),
                "n_findings": len(bundle.findings),
                "patched_build": bundle.patched_build,
                "context_path": str((workspace / "context.json").resolve()),
                "cve_md_path": str((workspace / "cve.md").resolve()),
            },
            indent=2,
        )
    )


async def _diff(
    manifest_path: Path,
    output_dir: Path,
    ghidra_install_dir: str | None,
    limit: int,
    *,
    engine: str = "docker",
    docker_image: str = "ghidriff-fixed:latest",
    write_report: bool = True,
) -> dict[str, object]:
    manifest = json.loads(manifest_path.read_text())
    cve_id = manifest["cve_id"]

    diff_targets: list[dict[str, object]] = []
    for acq in manifest.get("acquisitions", []):
        target = acq["target"]
        target_diffs: list[dict[str, object]] = []
        pairs = acq.get("pairs", [])
        if limit:
            pairs = pairs[:limit]
        for pair in pairs:
            pre_path = Path(pair["previous"]["path"])
            post_path = Path(pair["patched"]["path"])
            filename = pair["filename"]
            stem, dot, ext = filename.partition(".")
            ext = f".{ext}" if dot else ""
            pre_label = staged_label(
                stem, ext, pair["previous"].get("version"), pair["previous"]["sha256_hex"]
            )
            post_label = staged_label(
                stem, ext, pair["patched"].get("version"), pair["patched"]["sha256_hex"]
            )
            pair_dir = output_dir / cve_id / target["kb_id"] / stem
            try:
                result = await run_ghidriff(
                    pre_path,
                    post_path,
                    pair_dir,
                    engine=engine,
                    docker_image=docker_image,
                    docker_volume_root=output_dir,
                    ghidra_install_dir=ghidra_install_dir,
                    previous_label=pre_label,
                    patched_label=post_label,
                )
                target_diffs.append(
                    {
                        "filename": filename,
                        "status": "ok",
                        "json_path": str(result.json_path),
                        "output_dir": str(result.output_dir),
                    }
                )
            except GhidriffError as e:
                target_diffs.append({"filename": filename, "status": "failed", "error": str(e)})
        diff_targets.append(
            {
                "target": target,
                "n_pairs": len(pairs),
                "n_ok": sum(1 for d in target_diffs if d["status"] == "ok"),
                "n_failed": sum(1 for d in target_diffs if d["status"] == "failed"),
                "diffs": target_diffs,
            }
        )

    out: dict[str, object] = {
        "schema_version": DIFFS_SCHEMA_VERSION,
        "patchwatch_version": PATCHWATCH_VERSION,
        "cve_id": cve_id,
        "manifest_path": str(manifest_path),
        "diffs_dir": str(output_dir / cve_id),
        "targets": diff_targets,
    }
    diffs_path = manifest_path.parent / f"{cve_id}.diffs.json"
    diffs_path.write_text(json.dumps(out, indent=2, default=_json_default))
    out["diffs_manifest_path"] = str(diffs_path)

    if write_report:
        # Render the Markdown narrative alongside the diffs JSON. We render
        # from disk (rather than the in-memory dict) so a single code path
        # serves both `diff` and `report`.
        try:
            report_md = _render_report_from_disk(manifest_path.parent, cve_id)
            report_path = manifest_path.parent / f"{cve_id}.report.md"
            report_path.write_text(report_md)
            out["report_path"] = str(report_path)
        except Exception as e:  # noqa: BLE001
            # Don't fail the diff command just because the narrative blew up.
            out["report_error"] = str(e)
    return out


if __name__ == "__main__":
    app()
