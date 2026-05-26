"""PoC bundle export.

Mirrors the Rust `PocsmithContext` / `export_poc_context` flow: read the
acquire manifest + diff manifest off disk, stage the pre/post binaries plus
the ghidriff project tree into a self-contained workspace, and write a
machine-readable `context.json` alongside a human-readable `cve.md`.

This is strictly a hand-off artifact — we do NOT invoke any downstream
runner (Pocsmith / VM / KDNet). The bundle is what an exploit author
receives; they take it from there.

Paths inside `context.json` are RELATIVE to the workspace root so the
bundle can be moved/zipped without breaking.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._schema import POC_BUNDLE_SCHEMA_VERSION

# Ratio threshold for inclusion in findings: a ghidriff `ratio` of 1.0 means
# the function is byte-identical post-patch. Anything strictly less than
# 0.95 actually changed enough to be worth handing to an exploit author.
# (Matches the Rust impl's 0.3 relevance threshold in spirit; ours is the
# inverse signal — ratio is similarity, relevance is divergence.)
_RATIO_INCLUDE_MAX = 0.95


@dataclass
class PocFinding:
    """One modified function worth surfacing to the PoC author."""

    binary: str
    function: str
    ratio: float
    diff_type: list[str] = field(default_factory=list)
    old_address: str | None = None
    new_address: str | None = None
    before_code: str | None = None
    after_code: str | None = None


@dataclass
class PocBundle:
    """The on-disk PoC hand-off bundle.

    Field names match the Rust `PocsmithContext` where they overlap so a
    downstream consumer reading either representation sees the same keys.
    """

    schema_version: int
    cve_id: str
    kb: str
    title: str
    description: str
    primary_binaries: list[str]
    findings: list[PocFinding]
    prepatch_paths: dict[str, str]
    postpatch_paths: dict[str, str]
    ghidriff_dir: str
    cvss: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    exploited: str | None = None
    cwe: str | None = None
    release_number: str | None = None
    release_date: str | None = None
    patched_build: str | None = None
    patchwatch_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize, dropping `None`s on optionals so the JSON is tidy."""
        d: dict[str, Any] = {
            "schema_version": self.schema_version,
            "cve_id": self.cve_id,
            "kb": self.kb,
            "title": self.title,
            "description": self.description,
            "primary_binaries": list(self.primary_binaries),
            "findings": [
                {k: v for k, v in f.__dict__.items() if v is not None and v != []}
                for f in self.findings
            ],
            "prepatch_paths": dict(sorted(self.prepatch_paths.items())),
            "postpatch_paths": dict(sorted(self.postpatch_paths.items())),
            "ghidriff_dir": self.ghidriff_dir,
        }
        for k in (
            "cvss",
            "cvss_vector",
            "severity",
            "exploited",
            "cwe",
            "release_number",
            "release_date",
            "patched_build",
            "patchwatch_version",
        ):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


def parse_patched_build(version: str | None) -> str | None:
    """Extract the bare build number from a Windows `version` string.

    Microsoft's typical PE FileVersion looks like
    `"10.0.26100.1882 (WinBuild.160101.0800)"`; we just want the first token.
    """
    if not version:
        return None
    return version.split(" ", 1)[0].strip() or None


def _sha8(sha: str | None) -> str:
    """First 8 hex chars of a SHA256, or `"unknown"` when missing.

    Mirrors the Rust impl which derives the sha directory from the source
    path's parent (the Cache puts each binary under `<sha[:2]>/<sha>/`).
    """
    if sha and len(sha) >= 8:
        return sha[:8]
    return "unknown"


def _link_or_copy(src: Path, dst: Path) -> None:
    """Hard-link `src` into `dst`; fall back to a regular copy on OSError.

    OSError covers EXDEV (cross-device), filesystem refusal (NTFS-on-loop,
    some FUSE mounts), and racing-replace failures. Falling back keeps the
    bundle build robust on macOS/colima where the cache and workspace can
    sit on different volumes.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.unlink()
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def _copy_tree(src: Path, dst: Path) -> None:
    """Recursive copy that prefers hard links per-file.

    `shutil.copytree(..., copy_function=os.link)` would raise on cross-
    device errors and abort the whole tree, so we walk manually.
    """
    dst.mkdir(parents=True, exist_ok=True)
    for entry in src.iterdir():
        target = dst / entry.name
        if entry.is_dir():
            _copy_tree(entry, target)
        else:
            _link_or_copy(entry, target)


def _index_ghidriff_jsons(diffs: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """{(kb_id, filename) -> ghidriff diff entry} from diffs.json.

    Only entries with `status == "ok"` and a present `json_path` survive.
    """
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for t in diffs.get("targets", []):
        kb = (t.get("target") or {}).get("kb_id", "")
        for d in t.get("diffs", []):
            if d.get("status") != "ok":
                continue
            if not d.get("json_path"):
                continue
            out[(kb, d["filename"])] = d
    return out


def _load_findings_for(binary: str, ghidriff_json_path: Path) -> list[PocFinding]:
    """Filter the ghidriff `modified` list down to actually-changed funcs.

    ghidriff reports `ratio` ∈ [0.0, 1.0] — similarity, where 1.0 means
    byte-identical (purely a re-link). We keep ratios < 0.95.
    """
    try:
        gd = json.loads(ghidriff_json_path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    fns = (gd.get("functions") or {}).get("modified") or []
    out: list[PocFinding] = []
    for fn in fns:
        ratio = fn.get("ratio")
        if not isinstance(ratio, (int, float)):
            continue
        if ratio >= _RATIO_INCLUDE_MAX:
            continue
        old = fn.get("old") or {}
        new = fn.get("new") or {}
        name = old.get("name") or new.get("name") or "<anonymous>"
        out.append(
            PocFinding(
                binary=binary,
                function=name,
                ratio=float(ratio),
                diff_type=list(fn.get("diff_type") or []),
                old_address=old.get("address"),
                new_address=new.get("address"),
                before_code=old.get("code"),
                after_code=new.get("code"),
            )
        )
    # Sort lowest-ratio (most divergent) first — that's the exploit author's
    # natural reading order.
    out.sort(key=lambda f: f.ratio)
    return out


def _render_cve_md(bundle: PocBundle, findings_by_binary: dict[str, list[PocFinding]]) -> str:
    """Compact human-readable summary. Intentionally terse — the JSON is
    authoritative; this is just the at-a-glance view."""
    lines: list[str] = []
    lines.append(f"# {bundle.cve_id} — {bundle.title or '(no title)'}")
    lines.append("")
    lines.append(f"- **CVE:** {bundle.cve_id}")
    if bundle.cvss is not None:
        lines.append(f"- **CVSS:** {bundle.cvss:.1f}")
    if bundle.cvss_vector:
        lines.append(f"- **CVSS vector:** `{bundle.cvss_vector}`")
    if bundle.severity:
        lines.append(f"- **Severity:** {bundle.severity}")
    lines.append(f"- **KB:** {bundle.kb}")
    if bundle.cwe:
        lines.append(f"- **CWE:** {bundle.cwe}")
    if bundle.exploited:
        lines.append(f"- **Exploited:** {bundle.exploited}")
    if bundle.patched_build:
        lines.append(f"- **Patched build:** {bundle.patched_build}")
    if bundle.release_number:
        rel = bundle.release_number
        if bundle.release_date:
            rel = f"{rel} ({bundle.release_date})"
        lines.append(f"- **Release:** {rel}")
    lines.append("")
    if bundle.description:
        lines.append("## Description")
        lines.append("")
        lines.append(bundle.description.strip())
        lines.append("")
    if bundle.primary_binaries:
        lines.append("## Primary binaries")
        lines.append("")
        for b in bundle.primary_binaries:
            lines.append(f"- `{b}`")
        lines.append("")

    if findings_by_binary:
        lines.append("## Top modified functions")
        lines.append("")
        for binary, fns in sorted(findings_by_binary.items()):
            if not fns:
                continue
            lines.append(f"### `{binary}`")
            lines.append("")
            for f in fns[:10]:
                dtype = ", ".join(f.diff_type) if f.diff_type else "—"
                lines.append(f"- `{f.function}` — ratio {f.ratio:.2f} ({dtype})")
            if len(fns) > 10:
                lines.append(f"- … and {len(fns) - 10} more")
            lines.append("")

    lines.append("## Layout")
    lines.append("")
    lines.append("- `context.json` — full machine-readable bundle metadata")
    lines.append("- `pre-patch/` — pre-patch binaries, sharded by sha8")
    lines.append("- `post-patch/` — post-patch binaries, sharded by sha8")
    lines.append("- `ghidriff/` — full ghidriff project tree (json + markdown + side-by-side)")
    lines.append("")
    return "\n".join(lines)


def build_bundle(
    manifest_path: Path,
    diffs_manifest_path: Path,
    output_workspace: Path,
) -> PocBundle:
    """Read the manifest + diffs, stage everything into `output_workspace`,
    write `context.json` + `cve.md`, return the in-memory bundle.

    `output_workspace` is created if missing; existing contents are NOT
    purged (so re-runs are additive — overwrites individual files but
    leaves unrelated subdirs alone).
    """
    manifest_path = Path(manifest_path)
    diffs_manifest_path = Path(diffs_manifest_path)
    output_workspace = Path(output_workspace)

    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest not found: {manifest_path}")
    if not diffs_manifest_path.exists():
        raise FileNotFoundError(f"diffs manifest not found: {diffs_manifest_path}")

    manifest = json.loads(manifest_path.read_text())
    diffs = json.loads(diffs_manifest_path.read_text())

    cve_id = manifest.get("cve_id") or diffs.get("cve_id")
    if not cve_id:
        raise ValueError("manifest is missing cve_id")

    output_workspace.mkdir(parents=True, exist_ok=True)

    diff_index = _index_ghidriff_jsons(diffs)

    # We walk every acquired pair; if the same filename is acquired under
    # multiple KBs we just take the first one (the staged path will be
    # sha-sharded, so collisions can't shadow each other).
    prepatch_paths: dict[str, str] = {}
    postpatch_paths: dict[str, str] = {}
    findings: list[PocFinding] = []
    findings_by_binary: dict[str, list[PocFinding]] = {}
    primary_binaries: list[str] = []
    patched_build: str | None = None
    primary_kb: str | None = None

    for acq in manifest.get("acquisitions", []):
        target = acq.get("target") or {}
        kb_id = target.get("kb_id", "")
        if primary_kb is None and kb_id:
            primary_kb = kb_id
        for pair in acq.get("pairs", []) or []:
            filename = pair["filename"]
            if filename not in primary_binaries:
                primary_binaries.append(filename)
            prev = pair.get("previous") or {}
            post = pair.get("patched") or {}

            if patched_build is None:
                patched_build = parse_patched_build(post.get("version"))

            pre_rel = f"pre-patch/{_sha8(prev.get('sha256_hex'))}/{filename}"
            post_rel = f"post-patch/{_sha8(post.get('sha256_hex'))}/{filename}"

            if prev.get("path"):
                _link_or_copy(Path(prev["path"]), output_workspace / pre_rel)
                prepatch_paths[filename] = pre_rel
            if post.get("path"):
                _link_or_copy(Path(post["path"]), output_workspace / post_rel)
                postpatch_paths[filename] = post_rel

            diff_entry = diff_index.get((kb_id, filename))
            if diff_entry:
                fns = _load_findings_for(filename, Path(diff_entry["json_path"]))
                findings.extend(fns)
                findings_by_binary.setdefault(filename, []).extend(fns)

    # Stage ghidriff project tree(s). Each pair has its own `output_dir`
    # under `<diffs_dir>/<kb>/<stem>`. We mirror that layout under
    # `<workspace>/ghidriff/<kb>/<stem>/`.
    ghidriff_dir_rel = "ghidriff"
    ghidriff_root = output_workspace / ghidriff_dir_rel
    for t in diffs.get("targets", []):
        kb = (t.get("target") or {}).get("kb_id", "")
        for d in t.get("diffs", []):
            if d.get("status") != "ok":
                continue
            out_dir = d.get("output_dir")
            if not out_dir:
                continue
            src = Path(out_dir)
            if not src.exists():
                continue
            dst = ghidriff_root / kb / src.name
            _copy_tree(src, dst)

    bundle = PocBundle(
        schema_version=POC_BUNDLE_SCHEMA_VERSION,
        cve_id=cve_id,
        kb=primary_kb or "",
        title=manifest.get("title") or "",
        description=manifest.get("description") or "",
        primary_binaries=primary_binaries,
        findings=findings,
        prepatch_paths=prepatch_paths,
        postpatch_paths=postpatch_paths,
        ghidriff_dir=ghidriff_dir_rel + "/",
        cvss=manifest.get("cvss"),
        cvss_vector=manifest.get("cvss_vector"),
        severity=manifest.get("severity"),
        exploited=manifest.get("exploited"),
        cwe=manifest.get("cwe"),
        release_number=manifest.get("release_number"),
        release_date=manifest.get("release_date"),
        patched_build=patched_build,
        patchwatch_version=manifest.get("patchwatch_version"),
    )

    (output_workspace / "context.json").write_text(
        json.dumps(bundle.to_dict(), indent=2, sort_keys=False) + "\n"
    )
    (output_workspace / "cve.md").write_text(_render_cve_md(bundle, findings_by_binary))

    return bundle
