"""ndaybench CLI — run tasks, inspect the runs DB."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from . import db
from .runner import DEFAULT_DB, run_task

app = typer.Typer(help="ndaybench: Windows n-day exploit benchmark runner.", no_args_is_help=True)


@app.command()
def run(
    task: Path = typer.Argument(..., help="Path to a task recipe YAML."),
    agent: str = typer.Option("stub", help="Agent name (currently only 'stub')."),
    recipes_dir: Path = typer.Option(Path("recipes"), help="Directory of recipe YAMLs."),
    host: str = typer.Option("p620-1", help="OpenVMM host name or IP."),
    keep_vms: bool = typer.Option(False, help="Skip VM teardown (for debugging)."),
    budget_seconds: int | None = typer.Option(
        None, "--budget", help="Per-run wall-clock budget, seconds (default: task budget)."
    ),
) -> None:
    """Spawn a fresh VM for TASK, run AGENT against it, grade, record."""
    score = run_task(
        task,
        agent_name=agent,
        recipes_dir=recipes_dir,
        host=host,
        keep_vms=keep_vms,
        budget_seconds=budget_seconds,
    )
    typer.echo(json.dumps(score, indent=2))


@app.command()
def sweep(
    task: Path = typer.Argument(..., help="Path to a task recipe YAML."),
    runs: int = typer.Option(1, help="Total number of runs to launch."),
    parallelism: int = typer.Option(1, help="Max concurrent runs."),
    agent: str = typer.Option("stub", help="Agent name."),
    host: str = typer.Option("p620-1", help="OpenVMM host name or IP."),
    budget_seconds: int | None = typer.Option(None, "--budget"),
    recipes_dir: Path = typer.Option(Path("recipes"), help="Directory of recipe YAMLs."),
) -> None:
    """Run TASK multiple times in parallel (port-pool allocator)."""
    from .sweep import sweep as _sweep
    results = _sweep(
        task,
        agent_name=agent,
        runs=runs,
        parallelism=parallelism,
        budget_seconds=budget_seconds,
        host=host,
        recipes_dir=recipes_dir,
    )
    passed = sum(1 for r in results if r.get("status") == "passed")
    failed = sum(1 for r in results if r.get("status") == "failed")
    timeout = sum(1 for r in results if r.get("status") == "timeout")
    error = sum(1 for r in results if r.get("status") == "error")
    typer.echo(json.dumps(results, indent=2))
    typer.echo(
        f"\nsummary: total={len(results)}  passed={passed}  failed={failed}  "
        f"timeout={timeout}  error={error}",
        err=True,
    )


@app.command(name="list")
def list_runs(
    limit: int = typer.Option(10, help="Max rows to show."),
    db_path: Path = typer.Option(DEFAULT_DB, help="Path to the runs SQLite DB."),
) -> None:
    """List recent runs."""
    conn = db.connect(db_path)
    rows = db.list_runs(conn, limit=limit)
    if not rows:
        typer.echo("(no runs)")
        return
    for r in rows:
        typer.echo(
            f"{r['run_id']}  {r['cve_id']:<18}  {r['agent_id']:<8}  "
            f"{r['status']:<8}  started={r['started_at']}  "
            f"flag_correct={'yes' if r['submitted_flag'] == r['flag'] else 'no'}"
        )


@app.command()
def lint(
    recipes_dir: Path = typer.Option(Path("recipes"), help="Directory of recipe YAMLs."),
) -> None:
    """Validate every recipe under recipes_dir.  Exits 1 if any errors found."""
    from .lint import lint_recipes
    issues = lint_recipes(recipes_dir)
    if not issues:
        typer.echo("OK: all recipes clean")
        return

    errors = [i for i in issues if i.severity == "error"]
    warns = [i for i in issues if i.severity == "warn"]
    for i in issues:
        typer.echo(f"{i.severity.upper():<5} {i.recipe}: {i.message}")
    typer.echo(f"\n{len(errors)} error(s), {len(warns)} warning(s)")
    if errors:
        raise typer.Exit(1)


@app.command()
def show(
    run_id: str = typer.Argument(...),
    db_path: Path = typer.Option(DEFAULT_DB, help="Path to the runs SQLite DB."),
) -> None:
    """Show full details for a single run."""
    conn = db.connect(db_path)
    row = db.get_run(conn, run_id)
    if not row:
        typer.echo(f"no run {run_id!r}", err=True)
        raise typer.Exit(1)
    vms = db.vms_for_run(conn, run_id)
    typer.echo(json.dumps({"run": row, "vms": vms}, indent=2))


if __name__ == "__main__":
    app()
