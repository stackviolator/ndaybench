"""End-to-end integration tests for the runner.

Skipped by default; set NDAYBENCH_INTEGRATION=1 to enable.  Each test takes
~30-90s and creates+destroys real Proxmox VMs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ndaybench import db
from ndaybench.runner import run_task
from ndaybench.sweep import sweep
from ndaybench.vm import ProxmoxClient

REPO_ROOT = Path(__file__).resolve().parents[2]
TASK_RECIPE = REPO_ROOT / "recipes" / "tasks" / "CVE-2025-26633.yaml"
RECIPES_DIR = REPO_ROOT / "recipes"


def _assert_no_leaks(pm: ProxmoxClient) -> None:
    """Verify p620 has no ndaybench-named VMs or ISOs after a test."""
    out = pm.run("qm list", check=False).stdout
    leaked_vmids = [
        line.split()[0]
        for line in out.splitlines()[1:]
        if "ndaybench" in line.lower()
    ]
    assert not leaked_vmids, f"VMs leaked: {leaked_vmids}"

    iso_check = pm.run(
        "ls /var/lib/vz/template/iso/ndaybench-*.iso 2>/dev/null || true",
        check=False,
    ).stdout.strip()
    assert iso_check == "", f"ISOs leaked: {iso_check}"


@pytest.fixture
def pm() -> ProxmoxClient:
    return ProxmoxClient()


@pytest.fixture(autouse=True)
def _leak_guard(pm: ProxmoxClient):
    """Sanity-check no leftovers before AND after each integration test."""
    _assert_no_leaks(pm)
    yield
    _assert_no_leaks(pm)


@pytest.mark.integration
def test_stub_single_run(tmp_path: Path, pm: ProxmoxClient) -> None:
    """One end-to-end stub run lands cleanly in the DB with status=failed."""
    score = run_task(
        TASK_RECIPE,
        agent_name="stub",
        recipes_dir=RECIPES_DIR,
        runs_dir=tmp_path,
        db_path=tmp_path / "ndaybench.sqlite3",
    )
    assert score["status"] == "failed"  # stub deliberately submits wrong flag
    assert score["cve_id"] == "CVE-2025-26633"
    assert score["submitted_flag"] == "ndaybench{stub_does_not_actually_exploit}"
    assert score["expected_flag"].startswith("ndaybench{")

    # DB row + VM row written
    conn = db.connect(tmp_path / "ndaybench.sqlite3")
    row = db.get_run(conn, score["run_id"])
    assert row is not None
    assert row["status"] == "failed"
    assert row["flag"] == score["expected_flag"]
    vms = db.vms_for_run(conn, score["run_id"])
    assert len(vms) == 1
    assert vms[0]["role"] == "sole"


@pytest.mark.integration
def test_two_concurrent_runs_get_distinct_vmids(tmp_path: Path) -> None:
    """Sweep with parallelism=2 must give each run a distinct VMID + IP."""
    results = sweep(
        TASK_RECIPE,
        agent_name="stub",
        runs=2,
        parallelism=2,
        recipes_dir=RECIPES_DIR,
    )
    assert len(results) == 2
    assert all(r.get("status") == "failed" for r in results), results

    # Look up VMIDs assigned (different runs → different VMIDs).
    run_ids = [r["run_id"] for r in results]
    conn = db.connect(REPO_ROOT / "runs" / "ndaybench.sqlite3")
    vmids = []
    ips = []
    for rid in run_ids:
        vs = db.vms_for_run(conn, rid)
        assert len(vs) == 1
        vmids.append(vs[0]["vmid"])
        ips.append(vs[0]["ip"])
    assert len(set(vmids)) == 2, f"VMID collision: {vmids}"
    assert len(set(ips)) == 2, f"IP collision: {ips}"


@pytest.mark.integration
def test_tiny_budget_times_out(tmp_path: Path) -> None:
    """A 1-second budget should produce status=timeout, not error."""
    score = run_task(
        TASK_RECIPE,
        agent_name="stub",
        recipes_dir=RECIPES_DIR,
        runs_dir=tmp_path,
        db_path=tmp_path / "ndaybench.sqlite3",
        budget_seconds=1,  # impossible — spawn alone takes 35s
    )
    assert score["status"] == "timeout"
    assert score["error"] and "budget" in score["error"].lower()
    # Submission may be None (agent never got to submit).
    assert score["submitted_flag"] is None
