"""bakery CLI — recipe inspection and VM image builder."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from ._schema import RECIPE_SCHEMA_VERSION
from .builder import BuildConfig, Builder
from .recipe import Plan, load_task, walk_recipes

app = typer.Typer(
    help="Recipe-driven Windows VM image builder for ndaybench.",
    no_args_is_help=True,
)


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@app.command()
def show(
    task_path: Path = typer.Argument(  # noqa: B008
        ..., help="Path to a task YAML recipe file."
    ),
    recipes_dir: Path = typer.Option(  # noqa: B008
        None,
        "--recipes-dir",
        help="Root of the recipes tree. Defaults to <task_path>/../..",
    ),
) -> None:
    """Load and validate a task recipe, then print the fully resolved build plan."""
    search = [recipes_dir] if recipes_dir else [task_path.parent.parent]
    try:
        _raw, plan = load_task(task_path, search)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    _print_plan(plan)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@app.command(name="list")
def list_cmd(
    recipes_dir: Path = typer.Argument(  # noqa: B008
        ..., help="Root directory of the recipes tree."
    ),
    output_format: str = typer.Option(
        "text", "--format", help="Output format: text or json"
    ),
) -> None:
    """Walk a recipes directory and print every recipe with its hash."""
    try:
        catalog = walk_recipes(recipes_dir)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    if output_format == "json":
        typer.echo(
            json.dumps(
                {"schema_version": RECIPE_SCHEMA_VERSION, **catalog}, indent=2
            )
        )
        return

    for category, items in catalog.items():
        typer.echo(f"\n{'=' * 72}")
        typer.echo(f"  {category.upper()}")
        typer.echo("=" * 72)
        for item in items:
            if "error" in item:
                typer.echo(f"  ERROR  {item['path']}")
                typer.echo(f"         {item['error']}")
                continue
            item_id = item.get("id") or item.get("cve_id", "?")
            h = item.get("hash", "")
            typer.echo(f"  {item_id:<40}  {h[:16]}...")
            if category == "editions":
                typer.echo(
                    f"    {item['display_name']}  "
                    f"firmware={item['firmware']}  "
                    f"disk={item['disk_gb']} GB  "
                    f"secure_boot={item.get('secure_boot', False)}"
                )
            elif category == "baselines":
                typer.echo(
                    f"    edition={item['edition']}  "
                    f"patches={item['n_patches']}  build={item['target_build']}"
                )
            elif category == "customizations":
                typer.echo(
                    f"    {item['display_name']}  "
                    f"steps={item['n_steps']}  conflicts={item['conflicts_with']}"
                )
            elif category == "tasks":
                typer.echo(
                    f"    baseline={item['baseline']}  "
                    f"custs={item['customizations']}  conflicts={item['n_conflicts']}"
                )


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


@app.command()
def validate(
    recipes_dir: Path = typer.Argument(  # noqa: B008
        ..., help="Root directory of the recipes tree."
    ),
) -> None:
    """Load every recipe in the directory; exit 1 if any fail validation."""
    errors: list[str] = []
    ok: int = 0

    catalog = walk_recipes(recipes_dir)
    for category, items in catalog.items():
        for item in items:
            path = item.get("path", "?")
            if "error" in item:
                errors.append(f"{category}/{Path(path).name}: {item['error']}")
            else:
                ok += 1
                item_id = item.get("id") or item.get("cve_id", "?")
                typer.echo(f"  OK  {category}/{item_id}")

    # Check for conflict violations in tasks
    tasks_dir = recipes_dir / "tasks"
    if tasks_dir.is_dir():
        for task_file in sorted(tasks_dir.glob("*.yaml")):
            try:
                _raw, plan = load_task(task_file, [recipes_dir])
                for cv in plan.conflicts:
                    errors.append(
                        f"tasks/{task_file.name}: conflict {cv.a!r} vs {cv.b!r}"
                    )
            except Exception:  # noqa: BLE001
                pass  # already captured above

    typer.echo(f"\n{ok} recipes validated.")
    if errors:
        typer.echo(f"{len(errors)} error(s):", err=True)
        for e in errors:
            typer.echo(f"  ERROR: {e}", err=True)
        raise typer.Exit(1)
    else:
        typer.echo("All recipes valid.")


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


@app.command()
def build(
    task_path: Path = typer.Argument(  # noqa: B008
        ..., help="Path to a task YAML recipe file."
    ),
    recipes_dir: Path = typer.Option(  # noqa: B008
        None,
        "--recipes-dir",
        help="Root of the recipes tree. Defaults to <task_path>/../..",
    ),
    dry_run: bool = typer.Option(  # noqa: B008
        False,
        "--dry-run",
        help="Print the commands that would execute without running them.",
    ),
    proxmox_host: str = typer.Option("p620-1", "--host", help="Proxmox host name or IP"),
    proxmox_user: str = typer.Option("root", "--user", help="SSH user on the Proxmox host"),
    source_vmid: int = typer.Option(
        9000, "--source-vmid", help="Template VMID to clone from"
    ),
    vmid_start: int = typer.Option(
        9100, "--vmid-start", help="First VMID in the allocation range"
    ),
    vmid_end: int = typer.Option(
        9200, "--vmid-end", help="Last VMID (exclusive) in the allocation range"
    ),
    cache_root: Path = typer.Option(  # noqa: B008
        Path("~/.cache/ndaybench/images").expanduser(),
        "--cache-root",
        help="Local directory for cached raw images (on the Proxmox host).",
    ),
    bridge: str = typer.Option("vmbr1000", "--bridge", help="VM network bridge"),
) -> None:
    """Build a VM image from a task recipe.

    With --dry-run, prints the exact qm/ssh/qemu-img commands in order
    without executing them.  Use this to review the build plan before
    running against a real Proxmox host.

    Example (smoke test):

        bakery build --dry-run recipes/tasks/example-CVE-2026-XXXXX.yaml
    """
    search = [recipes_dir] if recipes_dir else [task_path.parent.parent]
    try:
        _raw, plan = load_task(task_path, search)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"ERROR loading recipe: {exc}", err=True)
        raise typer.Exit(1) from exc

    if not dry_run:
        _print_plan(plan)
        typer.echo()

    if plan.conflicts:
        typer.echo("ERROR: conflict violations detected — cannot build:", err=True)
        for cv in plan.conflicts:
            typer.echo(f"  {cv.a}  conflicts with  {cv.b}", err=True)
        raise typer.Exit(1)

    config = BuildConfig(
        proxmox_host=proxmox_host,
        proxmox_user=proxmox_user,
        source_vmid=source_vmid,
        vmid_range=range(vmid_start, vmid_end),
        cache_root=cache_root,
        bridge=bridge,
    )
    builder = Builder(config)

    try:
        raw_path = builder.build_plan(plan, dry_run=dry_run)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"ERROR: build failed: {exc}", err=True)
        raise typer.Exit(1) from exc

    if not dry_run:
        typer.echo(f"\nBuild complete: {raw_path}")
    else:
        typer.echo(f"\n[dry-run] Would produce: {raw_path}")


# ---------------------------------------------------------------------------
# Shared formatting
# ---------------------------------------------------------------------------


def _print_plan(plan: Plan) -> None:
    e = plan.edition
    t = plan.task
    typer.echo("=" * 72)
    typer.echo(f"  TASK       : {t.cve_id}")
    typer.echo(f"  CLASS      : {t.class_}")
    typer.echo(f"  EDITION    : {e.id}  ({e.display_name})")
    typer.echo(f"               ISO  {e.iso_url}")
    typer.echo(f"               sha256 {e.iso_sha256}")
    typer.echo(
        f"               WIM index {e.wim_index}  firmware={e.firmware}  "
        f"disk={e.disk_gb} GB  secure_boot={e.secure_boot}"
    )
    typer.echo("-" * 72)

    typer.echo("  PATCHES")
    if plan.patches:
        for i, p in enumerate(plan.patches, 1):
            typer.echo(f"    [{i}] {p.kb}  (catalog {p.catalog_guid})")
            typer.echo(f"         sha256 {p.sha256}")
            typer.echo(f"         {p.url}")
    else:
        typer.echo("    (none — bare edition, no patches applied)")

    typer.echo("-" * 72)
    typer.echo("  CUSTOMIZATIONS & STEPS")
    if plan.customizations:
        for cust in plan.customizations:
            typer.echo(f"    [{cust.id}]  {cust.display_name}")
            for j, step in enumerate(cust.steps, 1):
                d = step.model_dump()
                step_type = d.pop("type")
                detail = "  ".join(f"{k}={v!r}" for k, v in d.items() if v)
                typer.echo(f"      step {j}: {step_type}  {detail}")
    else:
        typer.echo("    (none)")

    typer.echo("-" * 72)
    if plan.conflicts:
        typer.echo("  CONFLICTS  *** VIOLATIONS DETECTED ***")
        for c in plan.conflicts:
            typer.echo(f"    ! {c.a}  conflicts with  {c.b}")
    else:
        typer.echo("  CONFLICTS  : none")

    typer.echo("-" * 72)

    # Task-level metadata (does not affect image hash)
    if t.flag:
        typer.echo(f"  FLAG       : profile={t.flag.profile}")
    if t.randomized:
        typer.echo(f"  RANDOMIZED : {', '.join(t.randomized)}")
    if t.agent_brief_path:
        typer.echo(f"  BRIEF      : {t.agent_brief_path}")
    if t.grader:
        g = t.grader
        typer.echo(
            f"  GRADER     : channel={g.submission_channel}  "
            f"success={g.success}  max={g.max_attempt_seconds}s"
        )
        typer.echo(f"               record={g.record}")
    if t.tags:
        for k, v in t.tags.items():
            typer.echo(f"  TAG        : {k}={v}")
    if t.references:
        typer.echo("  REFERENCES :")
        for ref in t.references:
            typer.echo(f"    {ref}")

    typer.echo("-" * 72)
    typer.echo(f"  SCHEMA VER : {RECIPE_SCHEMA_VERSION}")
    typer.echo(f"  HASH       : {plan.content_hash}")
    typer.echo("=" * 72)


if __name__ == "__main__":
    app()
