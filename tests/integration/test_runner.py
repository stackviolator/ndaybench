"""End-to-end integration tests for the runner (OpenVMM backend).

Skipped by default; set NDAYBENCH_INTEGRATION=1 to enable.  Each test spawns +
destroys real OpenVMM VMs on the host and takes a few minutes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ndaybench import db
from ndaybench.openvmm import OpenVmmClient
from ndaybench.runner import run_task
from ndaybench.sweep import sweep

REPO_ROOT = Path(__file__).resolve().parents[2]
TASK_RECIPE = REPO_ROOT / "recipes" / "tasks" / "CVE-2025-26633.yaml"
RECIPES_DIR = REPO_ROOT / "recipes"


def _assert_no_leaks(client: OpenVmmClient) -> None:
    """Verify the host has no leftover ndaybench units or taps after a test."""
    units = client._host_run(
        "systemctl list-units 'ndb-*' --all --no-legend --plain 2>/dev/null | wc -l",
        check=False,
    ).stdout.strip()
    assert units == "0", f"leaked systemd units: {units}"
    taps = client._host_run(
        "ip -br link show 2>/dev/null | grep -c '^ndb' || true", check=False
    ).stdout.strip()
    assert taps in ("0", ""), f"leaked taps: {taps}"


@pytest.fixture
def client() -> OpenVmmClient:
    return OpenVmmClient()


@pytest.fixture(autouse=True)
def _leak_guard(client: OpenVmmClient):
    _assert_no_leaks(client)
    yield
    _assert_no_leaks(client)


@pytest.mark.integration
def test_stub_single_run(tmp_path: Path) -> None:
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

    conn = db.connect(tmp_path / "ndaybench.sqlite3")
    row = db.get_run(conn, score["run_id"])
    assert row is not None and row["status"] == "failed"
    assert row["flag"] == score["expected_flag"]
    vms = db.vms_for_run(conn, score["run_id"])
    assert len(vms) == 1 and vms[0]["role"] == "sole"


@pytest.mark.integration
def test_two_concurrent_runs_get_distinct_ips(tmp_path: Path) -> None:
    """Sweep with parallelism=2 must give each run a distinct lease IP."""
    results = sweep(TASK_RECIPE, agent_name="stub", runs=2, parallelism=2,
                    recipes_dir=RECIPES_DIR)
    assert len(results) == 2
    assert all(r.get("status") == "failed" for r in results), results

    conn = db.connect(REPO_ROOT / "runs" / "ndaybench.sqlite3")
    ips = []
    for r in results:
        vs = db.vms_for_run(conn, r["run_id"])
        assert len(vs) == 1
        ips.append(vs[0]["ip"])
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
        budget_seconds=1,  # impossible — spawn alone takes ~25s
    )
    assert score["status"] == "timeout"
    assert score["error"] and "budget" in score["error"].lower()
    assert score["submitted_flag"] is None
