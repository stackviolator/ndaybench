"""SQLite store for ndaybench benchmark runs.

Schema:
  runs       — one row per attempt (run_id, cve, agent, ground-truth flag, status)
  run_vms    — one row per VM spawned for a run (role, proxmox vmid, ip)

The database is the ground-truth log of "what flag did we inject into which VM
for which run."  The oracle reads from here, not from the run dir, so that a
corrupted transcript can never be regraded into a false pass.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  run_id          TEXT PRIMARY KEY,
  cve_id          TEXT NOT NULL,
  task_recipe     TEXT NOT NULL,
  agent_id        TEXT NOT NULL,
  flag            TEXT NOT NULL,
  agent_password  TEXT,
  flag_profile    TEXT,
  status          TEXT NOT NULL DEFAULT 'running',
  submitted_flag  TEXT,
  started_at      TEXT NOT NULL,
  ended_at        TEXT,
  run_dir         TEXT NOT NULL,
  error_message   TEXT
);

CREATE TABLE IF NOT EXISTS run_vms (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id      TEXT NOT NULL REFERENCES runs(run_id),
  role        TEXT NOT NULL,          -- 'sole' | 'scoring' | 'scratch'
  vmid        INTEGER NOT NULL,
  ip          TEXT,
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_run_vms_run_id ON run_vms(run_id);
"""


def utcnow() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.row_factory = sqlite3.Row
    return conn


def create_run(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    cve_id: str,
    task_recipe: str,
    agent_id: str,
    flag: str,
    agent_password: str | None,
    flag_profile: str | None,
    run_dir: Path,
) -> None:
    conn.execute(
        "INSERT INTO runs "
        "(run_id, cve_id, task_recipe, agent_id, flag, agent_password, "
        "flag_profile, started_at, run_dir) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id,
            cve_id,
            task_recipe,
            agent_id,
            flag,
            agent_password,
            flag_profile,
            utcnow(),
            str(run_dir),
        ),
    )
    conn.commit()


def record_vm(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    role: str,
    vmid: int,
    ip: str | None,
) -> None:
    conn.execute(
        "INSERT INTO run_vms (run_id, role, vmid, ip, created_at) VALUES (?, ?, ?, ?, ?)",
        (run_id, role, vmid, ip, utcnow()),
    )
    conn.commit()


def update_vm_ip(conn: sqlite3.Connection, *, run_id: str, role: str, ip: str) -> None:
    conn.execute(
        "UPDATE run_vms SET ip=? WHERE run_id=? AND role=?",
        (ip, run_id, role),
    )
    conn.commit()


def finalize_run(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    status: str,
    submitted_flag: str | None = None,
    error_message: str | None = None,
) -> None:
    conn.execute(
        "UPDATE runs SET status=?, submitted_flag=?, ended_at=?, error_message=? WHERE run_id=?",
        (status, submitted_flag, utcnow(), error_message, run_id),
    )
    conn.commit()


def get_run(conn: sqlite3.Connection, run_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
    return dict(row) if row else None


def list_runs(conn: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def vms_for_run(conn: sqlite3.Connection, run_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM run_vms WHERE run_id=? ORDER BY id", (run_id,)
    ).fetchall()
    return [dict(r) for r in rows]
