"""Per-CVE Markdown narrative report.

Renders a human-readable summary of the diff pipeline output for one CVE:
header (title/CVSS/CWE/release) → targets table → per-binary diffed function
list with Before/After decompiled C blocks.

This is the Python port of `crates/patchwatch/src/report/render.rs`, minus the
LLM-derived sections (triage rankings, synthesis, deep analysis) since this
crate doesn't produce them.

Public entry point: `render_cve_report(manifest, diffs_manifest, ghidriff_jsons)`.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from html.parser import HTMLParser
from io import StringIO
from pathlib import Path
from typing import Any

from ._schema import DIFFS_SCHEMA_VERSION

# Diff-type tags that mark a function as *not* having a real code change.
# ghidriff sets these when only addresses shifted, ref counts moved, etc.
_NON_CODE_DIFF_TYPES: frozenset[str] = frozenset({"address", "refcount", "length"})

# Cap on per-binary function bodies so a runaway diff doesn't explode the doc.
_TOP_MODIFIED = 10


def render_cve_report(
    manifest: dict[str, Any],
    diffs_manifest: dict[str, Any] | None,
    ghidriff_jsons: dict[tuple[str, str], dict[str, Any]],
) -> str:
    """Build the Markdown narrative for one CVE.

    `manifest` is a parsed `<CVE>.json` (output of `patchwatch acquire`).
    `diffs_manifest` is the parsed `<CVE>.diffs.json` (may be None if diff
    hasn't run yet — in that case we render header + targets only).
    `ghidriff_jsons` is a mapping `(kb_id, filename) -> parsed ghidriff JSON`
    for the diffs that succeeded.
    """
    cve_id = manifest.get("cve_id") or "(unknown CVE)"
    out = StringIO()

    # ── Header ───────────────────────────────────────────────────────────────
    title = manifest.get("title") or "(no title)"
    out.write(f"# {cve_id} — {title}\n\n")

    cvss = manifest.get("cvss")
    severity = manifest.get("severity") or "—"
    cwe = manifest.get("cwe") or "—"
    exploited = manifest.get("exploited") or "No"
    bucket = _cvss_bucket(cvss)
    out.write("> ")
    out.write(f"`{bucket.upper()}` · ")
    out.write(f"CVSS **{cvss if cvss is not None else 'N/A'}** · ")
    out.write(f"severity **{severity}** · ")
    out.write(f"CWE **{cwe}** · ")
    out.write(f"exploited **{exploited}**\n\n")

    release = manifest.get("release_number") or "—"
    release_date = manifest.get("release_date") or "—"
    out.write(f"**Release:** {release}  \n")
    out.write(f"**Release date:** {release_date}  \n")
    if rev := manifest.get("revision_number"):
        out.write(f"**Revision:** {rev}  \n")
    out.write("\n")

    # ── Description (strip HTML, SUG returns rich text) ──────────────────────
    desc = manifest.get("description")
    if desc:
        out.write("## Description\n\n")
        out.write(_strip_html(desc).strip())
        out.write("\n\n")

    # ── Targets ──────────────────────────────────────────────────────────────
    targets = manifest.get("targets") or []
    if targets:
        out.write("## Targets\n\n")
        out.write("| Family | Product | KB | Build |\n")
        out.write("|---|---|---|---|\n")
        for t in targets:
            out.write(
                f"| {t.get('family', '—')} | {t.get('product', '—')} "
                f"| {t.get('kb_id', '—')} | {t.get('build') or '—'} |\n"
            )
        out.write("\n")

    # ── Per-target × per-binary diffs ────────────────────────────────────────
    diff_targets = (diffs_manifest or {}).get("targets") or []
    pair_index = _index_pairs(manifest)
    n_binaries = sum(len(t.get("diffs") or []) for t in diff_targets)
    if diff_targets:
        out.write(f"## Diffed binaries ({n_binaries} total)\n\n")
    for dt in diff_targets:
        target = dt.get("target") or {}
        kb_id = target.get("kb_id") or "—"
        for d in dt.get("diffs") or []:
            filename = d.get("filename") or "(unknown)"
            status = d.get("status")
            out.write(f"### {kb_id} · {filename}\n\n")
            pair = pair_index.get((kb_id, filename))
            if pair:
                pre_v = (pair.get("previous") or {}).get("version") or "?"
                post_v = (pair.get("patched") or {}).get("version") or "?"
                out.write(
                    f"`{pre_v}` → `{post_v}` · confidence "
                    f"`{pair.get('confidence', '?')}`\n\n"
                )
            if status != "ok":
                out.write(
                    f"_diff did not complete: {d.get('error') or status or 'unknown'}_\n\n"
                )
                continue
            gj = ghidriff_jsons.get((kb_id, filename))
            if gj is None:
                out.write("_ghidriff JSON not found on disk; nothing to render._\n\n")
                continue
            _render_binary_diff(out, gj)

    # ── Footer ───────────────────────────────────────────────────────────────
    pw_ver = (
        manifest.get("patchwatch_version")
        or (diffs_manifest or {}).get("patchwatch_version")
        or "?"
    )
    now = datetime.now(UTC).isoformat(timespec="seconds")
    out.write("---\n\n")
    out.write(
        f"_generated by patchwatch {pw_ver} · diffs schema v{DIFFS_SCHEMA_VERSION} · {now}_\n"
    )
    return out.getvalue()


# ── helpers ──────────────────────────────────────────────────────────────────


def _render_binary_diff(out: StringIO, gj: dict[str, Any]) -> None:
    funcs = (gj.get("functions") or {})
    modified = list(funcs.get("modified") or [])
    n_added = len(funcs.get("added") or [])
    n_deleted = len(funcs.get("deleted") or [])
    n_modified = len(modified)
    out.write(
        f"counts: **+{n_added}** added · **−{n_deleted}** deleted · "
        f"**~{n_modified}** modified\n\n"
    )

    # Drop functions whose only diff is address/refcount/length (no real code change),
    # then sort by ratio ascending (most-changed first).
    def _real_change(f: dict[str, Any]) -> bool:
        tags = set(f.get("diff_type") or f.get("diff_types") or [])
        if not tags:
            return True  # no metadata → don't filter out
        return bool(tags - _NON_CODE_DIFF_TYPES)

    real = [f for f in modified if _real_change(f)]
    real.sort(key=lambda f: f.get("ratio") if f.get("ratio") is not None else 1.0)
    shown = real[:_TOP_MODIFIED]
    for f in shown:
        name = f.get("name") or "(anon)"
        ratio = f.get("ratio")
        ratio_s = f"{ratio:.2f}" if isinstance(ratio, (int, float)) else "?"
        out.write(f"#### `{name}` (ratio {ratio_s})\n\n")
        old_code = ((f.get("old") or {}).get("code")) or ""
        new_code = ((f.get("new") or {}).get("code")) or ""
        if old_code:
            out.write("**Before:**\n\n```c\n")
            out.write(old_code.rstrip("\n"))
            out.write("\n```\n\n")
        if new_code:
            out.write("**After:**\n\n```c\n")
            out.write(new_code.rstrip("\n"))
            out.write("\n```\n\n")
    if len(real) > _TOP_MODIFIED:
        out.write(f"_+{len(real) - _TOP_MODIFIED} more not shown_\n\n")

    strings = gj.get("strings") or {}
    added_s = strings.get("added") or []
    deleted_s = strings.get("deleted") or []
    if added_s or deleted_s:
        out.write("**Strings**\n\n")
        for s in added_s:
            out.write(f"- `+ {s}`\n")
        for s in deleted_s:
            out.write(f"- `- {s}`\n")
        out.write("\n")


def _index_pairs(manifest: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for acq in manifest.get("acquisitions") or []:
        kb_id = (acq.get("target") or {}).get("kb_id")
        if not kb_id:
            continue
        for pair in acq.get("pairs") or []:
            fname = pair.get("filename")
            if fname:
                out[(kb_id, fname)] = pair
    return out


def _cvss_bucket(score: float | int | None) -> str:
    if score is None:
        return "none"
    s = float(score)
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "none"


class _TagStripper(HTMLParser):
    """Strip HTML tags while keeping inner text. SUG descriptions are short
    snippets of HTML; a full sanitizer would be overkill."""

    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        self._chunks.append(data)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("br", "p", "li", "div"):
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("p", "li", "div"):
            self._chunks.append("\n")

    @property
    def text(self) -> str:
        return "".join(self._chunks)


def _strip_html(s: str) -> str:
    if "<" not in s:
        return s
    parser = _TagStripper()
    try:
        parser.feed(s)
    except Exception:  # noqa: BLE001
        # Fall back to a crude regex if the parser chokes on malformed HTML.
        return re.sub(r"<[^>]+>", "", s)
    return re.sub(r"\n{3,}", "\n\n", parser.text).strip()


# ── on-disk wiring ────────────────────────────────────────────────────────────


def render_from_disk(manifests_dir: Path, cve_id: str) -> str:
    """Convenience: read `<CVE>.json` + `<CVE>.diffs.json` from a manifests dir
    and render. Used by the CLI's `report` subcommand."""
    manifest_path = manifests_dir / f"{cve_id}.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text())
    diffs_path = manifests_dir / f"{cve_id}.diffs.json"
    diffs_manifest: dict[str, Any] | None = None
    ghidriff_jsons: dict[tuple[str, str], dict[str, Any]] = {}
    if diffs_path.exists():
        diffs_manifest = json.loads(diffs_path.read_text())
        for dt in diffs_manifest.get("targets") or []:
            kb_id = (dt.get("target") or {}).get("kb_id")
            for d in dt.get("diffs") or []:
                if d.get("status") != "ok":
                    continue
                jp = d.get("json_path")
                if not jp:
                    continue
                p = Path(jp)
                if not p.exists():
                    continue
                try:
                    ghidriff_jsons[(kb_id, d.get("filename"))] = json.loads(p.read_text())
                except (OSError, json.JSONDecodeError):
                    continue
    return render_cve_report(manifest, diffs_manifest, ghidriff_jsons)
