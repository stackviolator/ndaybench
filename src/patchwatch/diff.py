"""ghidriff invocation.

Two execution modes:
- `local`: assumes `ghidriff` is on PATH and Ghidra reachable via
  GHIDRA_INSTALL_DIR. Heavy install (JDK + Ghidra + ghidriff Python).
- `docker`: runs ghidriff inside the upstream image
  `ghcr.io/clearbluejar/ghidriff` (or a locally-built variant that pins
  pyghidra==2.2.1 for Ghidra 11.3 compatibility — see Dockerfile.ghidriff).

In `docker` mode patchwatch shells out to the docker CLI — this is the one
exception to the "no docker shellouts" rule we made for everything else,
because Ghidra has no SDK alternative and pulling Java + 1.5 GB of Ghidra
onto the host is a significantly worse experience than `docker run`.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path


class GhidriffError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class GhidriffResult:
    json_path: Path
    output_dir: Path
    exit_code: int


def staged_label(stem: str, ext: str, version: str | None, sha256_hex: str) -> str:
    """Build a unique on-disk label for a staged binary.

    ghidriff uses the input filename as the report title; we want both the pre
    and post copies to live in the same dir with distinct names so the report
    title carries the version (or, failing that, a SHA prefix).
    """
    # Drop any trailing parenthetical like " (WinBuild.160101.0800)".
    ident = version.split()[0] if version else sha256_hex[:8]
    return f"{stem}_{ident}{ext}"


async def run_ghidriff(
    previous_path: Path,
    patched_path: Path,
    output_dir: Path,
    *,
    engine: str = "local",
    ghidriff_bin: str = "ghidriff",
    ghidra_install_dir: str | None = None,
    docker_image: str = "ghidriff-fixed:latest",
    docker_volume_root: Path | None = None,
    previous_label: str | None = None,
    patched_label: str | None = None,
) -> GhidriffResult:
    """Diff `previous_path` vs `patched_path`. Returns the path of the JSON output.

    Idempotent: if the expected JSON already exists, returns immediately.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Stage both binaries into the output dir so ghidriff's report title encodes
    # the version. The container path below assumes this layout too.
    pre_label = previous_label or previous_path.name
    post_label = patched_label or patched_path.name
    pre_staged = output_dir / pre_label
    post_staged = output_dir / post_label
    if pre_staged.resolve() != previous_path.resolve():
        pre_staged.write_bytes(previous_path.read_bytes())
    if post_staged.resolve() != patched_path.resolve():
        post_staged.write_bytes(patched_path.read_bytes())

    json_path = _expected_json_path(output_dir, pre_label, post_label)
    if json_path.exists():
        return GhidriffResult(json_path=json_path, output_dir=output_dir, exit_code=0)

    if engine == "docker":
        await _run_docker(output_dir, pre_label, post_label, docker_image, docker_volume_root)
    elif engine == "local":
        await _run_local(pre_staged, post_staged, output_dir, ghidriff_bin, ghidra_install_dir)
    else:
        raise GhidriffError(f"unknown diff engine: {engine!r}")

    if not json_path.exists():
        # Fallback glob — ghidriff's filename convention can vary.
        candidates = list((output_dir / "json").glob("*.ghidriff.json"))
        if not candidates:
            raise GhidriffError(f"ghidriff produced no JSON output in {output_dir}")
        json_path = candidates[0]

    return GhidriffResult(json_path=json_path, output_dir=output_dir, exit_code=0)


async def _run_local(
    pre_staged: Path,
    post_staged: Path,
    output_dir: Path,
    ghidriff_bin: str,
    ghidra_install_dir: str | None,
) -> None:
    if shutil.which(ghidriff_bin) is None:
        raise GhidriffError(
            f"`{ghidriff_bin}` not found on PATH. Install with "
            f"`pip install ghidriff` and set GHIDRA_INSTALL_DIR, "
            f"or run with --diff-engine docker."
        )
    cmd = [ghidriff_bin, str(pre_staged), str(post_staged), "-o", str(output_dir)]
    env = None
    if ghidra_install_dir:
        env = {**os.environ, "GHIDRA_INSTALL_DIR": ghidra_install_dir}
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _out, err = await proc.communicate()
    if proc.returncode != 0:
        raise GhidriffError(
            f"ghidriff exited {proc.returncode}: {err.decode(errors='replace')[:500]}"
        )


async def _run_docker(
    output_dir: Path,
    pre_label: str,
    post_label: str,
    image: str,
    volume_root: Path | None,
) -> None:
    """Run ghidriff inside `image`, bind-mounting `volume_root` so the container
    sees the staged binaries at `/ghidriffs/<subdir>/<label>`.

    `volume_root` defaults to `output_dir.parent` so multiple per-binary
    `output_dir`s share one mount.

    When patchwatch itself runs inside a container (backend wrapper service),
    `volume_root` is a CONTAINER-internal path that the host docker daemon
    can't resolve. Set `PATCHWATCH_HOST_DATA_DIR` + `PATCHWATCH_CONTAINER_DATA_DIR`
    in the env to map a container path prefix to its host equivalent — the
    sibling ghidriff container then mounts the right host path.
    """
    if shutil.which("docker") is None:
        raise GhidriffError("`docker` not found on PATH (install Docker Desktop).")

    # Heap size is env-tunable so we can adjust per-container memory budget
    # from compose without code changes. Default 8G matches the previous
    # hard-coded value; lower (e.g. 5G) to fit more concurrent diffs into a
    # fixed-RAM colima VM.
    heap = os.environ.get("PATCHWATCH_GHIDRIFF_HEAP", "8G")

    root = (volume_root or output_dir.parent).resolve()
    try:
        subdir = output_dir.resolve().relative_to(root)
    except ValueError as e:
        raise GhidriffError(
            f"output_dir {output_dir} must be inside docker_volume_root {root}"
        ) from e

    # Persistent caches under the shared volume so subsequent runs skip
    # re-analysis when the project / symbols / packed-program dirs already
    # contain a hit. Pre-creating them on the host avoids permission issues
    # with whatever uid the ghidriff container runs as.
    for sub in ("_ghidra-projects", "_ghidra-symbols", "_ghidra-gzfs"):
        (root / sub).mkdir(parents=True, exist_ok=True)

    host_root = _translate_to_host_path(root)

    pre_ctr = f"/ghidriffs/{subdir.as_posix()}/{pre_label}"
    post_ctr = f"/ghidriffs/{subdir.as_posix()}/{post_label}"
    out_ctr = f"/ghidriffs/{subdir.as_posix()}"
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{host_root}:/ghidriffs",
        image,
        pre_ctr,
        post_ctr,
        "-o",
        out_ctr,
        # Performance knobs supported by ghidriff in the ghidra-11.3-compatible
        # image we ship (`--decompiler-timeout` only exists in newer builds).
        # - Bigger JVM heap: reduces GC pressure on >1 MB DLLs.
        # - Drop BSIM correlator: the slowest matcher; quality drop is
        #   negligible for monthly Patch Tuesday diffs.
        # - Persistent project / symbols / gzf caches: re-running the same
        #   pair becomes near-instant; new pairs still benefit from cached
        #   PDB downloads and cached per-binary GZFs.
        f"--jvm-args=-Xmx{heap}",
        "--max-ram-percent",
        "80",
        "--no-bsim",
        "--project-location",
        "/ghidriffs/_ghidra-projects",
        "--symbols-path",
        "/ghidriffs/_ghidra-symbols",
        "--gzfs-path",
        "/ghidriffs/_ghidra-gzfs",
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _out, err = await proc.communicate()
    if proc.returncode != 0:
        raise GhidriffError(
            f"docker run exited {proc.returncode}: {err.decode(errors='replace')[:500]}"
        )


def _translate_to_host_path(container_path: Path) -> Path:
    """Map a path the current process sees to its host equivalent.

    Returns `container_path` unchanged when both env vars are unset (running
    on the host directly). When both are set, rewrites paths under
    `PATCHWATCH_CONTAINER_DATA_DIR` to live under `PATCHWATCH_HOST_DATA_DIR`.
    """
    host = os.environ.get("PATCHWATCH_HOST_DATA_DIR")
    container = os.environ.get("PATCHWATCH_CONTAINER_DATA_DIR", "/data")
    if not host:
        return container_path
    try:
        rel = container_path.relative_to(container)
    except ValueError:
        return container_path
    return Path(host) / rel


def _expected_json_path(output_dir: Path, previous_label: str, patched_label: str) -> Path:
    """Where ghidriff writes its diff JSON.

    Format: `<output_dir>/json/<previous_label>-<patched_label>.ghidriff.json`.
    """
    return output_dir / "json" / f"{previous_label}-{patched_label}.ghidriff.json"


def parse_ghidriff_json(path: Path) -> dict:
    """Load a ghidriff JSON file."""
    with path.open() as f:
        return json.load(f)


def summarize_ghidriff(data: dict, *, top_modified: int = 10) -> dict:
    """Compact agent-friendly summary of a ghidriff diff JSON.

    Keeps function names + similarity ratios + change types, drops the
    decompiled C bodies (which are large). The full JSON is still on disk
    if the agent wants to dig into a specific function.
    """
    funcs = data.get("functions", {}) or {}
    added = [_func_name(f) for f in funcs.get("added", [])]
    deleted = [_func_name(f) for f in funcs.get("deleted", [])]
    modified = []
    for f in funcs.get("modified", []):
        modified.append(
            {
                "name": _func_name(f),
                "ratio": f.get("ratio") or f.get("similarity"),
                "diff_types": f.get("diff_type") or f.get("diff_types") or [],
            }
        )
    # Most-changed first (lowest ratio = most rewritten).
    modified.sort(key=lambda m: m["ratio"] if m["ratio"] is not None else 1.0)
    strings = data.get("strings", {}) or {}
    return {
        "n_added": len(added),
        "n_deleted": len(deleted),
        "n_modified": len(modified),
        "added_strings": (strings.get("added") or [])[:20],
        "deleted_strings": (strings.get("deleted") or [])[:20],
        "added_functions": added[:50],
        "deleted_functions": deleted[:50],
        "top_modified": modified[:top_modified],
    }


def _func_name(entry: object) -> str:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        # Modified entries have nested old/new objects with the name.
        for sub in (entry.get("old"), entry.get("new")):
            if isinstance(sub, dict) and sub.get("name"):
                return sub["name"]
        return entry.get("name") or entry.get("old_name") or entry.get("new_name") or "?"
    return "?"
