"""Unit tests for the runs SQLite layer."""

from pathlib import Path

from ndaybench import db


def test_create_and_get_run(tmp_path: Path) -> None:
    conn = db.connect(tmp_path / "test.sqlite3")
    db.create_run(
        conn,
        run_id="abc123",
        cve_id="CVE-2025-26633",
        task_recipe="recipes/tasks/CVE-2025-26633.yaml",
        agent_id="stub",
        flag="ndaybench{deadbeef}",
        agent_password="pw1!",
        flag_profile="admin",
        run_dir=tmp_path / "runs" / "abc123",
    )
    row = db.get_run(conn, "abc123")
    assert row is not None
    assert row["cve_id"] == "CVE-2025-26633"
    assert row["flag"] == "ndaybench{deadbeef}"
    assert row["agent_password"] == "pw1!"
    assert row["status"] == "running"


def test_record_and_list_vms(tmp_path: Path) -> None:
    conn = db.connect(tmp_path / "test.sqlite3")
    db.create_run(
        conn,
        run_id="r1",
        cve_id="CVE-X",
        task_recipe="r.yaml",
        agent_id="stub",
        flag="f",
        agent_password=None,
        flag_profile=None,
        run_dir=tmp_path,
    )
    db.record_vm(conn, run_id="r1", role="scoring", vmid=9200, ip="192.0.2.200")
    db.record_vm(conn, run_id="r1", role="scratch", vmid=9201, ip="192.0.2.201")
    vms = db.vms_for_run(conn, "r1")
    assert len(vms) == 2
    assert {v["role"] for v in vms} == {"scoring", "scratch"}
    assert {v["vmid"] for v in vms} == {9200, 9201}


def test_finalize_transitions(tmp_path: Path) -> None:
    conn = db.connect(tmp_path / "test.sqlite3")
    db.create_run(
        conn,
        run_id="r2",
        cve_id="CVE-X",
        task_recipe="r.yaml",
        agent_id="stub",
        flag="ndaybench{xyz}",
        agent_password=None,
        flag_profile="admin",
        run_dir=tmp_path,
    )
    # Pass case
    db.finalize_run(conn, run_id="r2", status="passed", submitted_flag="ndaybench{xyz}")
    row = db.get_run(conn, "r2")
    assert row["status"] == "passed"
    assert row["submitted_flag"] == "ndaybench{xyz}"
    assert row["ended_at"] is not None

    # Error case
    db.create_run(
        conn,
        run_id="r3",
        cve_id="CVE-X",
        task_recipe="r.yaml",
        agent_id="stub",
        flag="f",
        agent_password=None,
        flag_profile=None,
        run_dir=tmp_path,
    )
    db.finalize_run(conn, run_id="r3", status="error", error_message="boom")
    row = db.get_run(conn, "r3")
    assert row["status"] == "error"
    assert row["error_message"] == "boom"


def test_list_runs_order_and_limit(tmp_path: Path) -> None:
    conn = db.connect(tmp_path / "test.sqlite3")
    for i in range(5):
        db.create_run(
            conn,
            run_id=f"r{i}",
            cve_id="CVE-X",
            task_recipe="r.yaml",
            agent_id="stub",
            flag="f",
            agent_password=None,
            flag_profile=None,
            run_dir=tmp_path,
        )
    rows = db.list_runs(conn, limit=3)
    assert len(rows) == 3
