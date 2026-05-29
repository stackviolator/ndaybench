"""Parallel sweep driver for ndaybench runs.

Owns VMID/IP allocation across a fleet of concurrent worker threads.  Each
worker drives one `run_task` invocation.  Threads are appropriate here because
nearly all time is spent in subprocess SSH calls (GIL not a bottleneck).
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .runner import run_task
from .vm import ProxmoxClient, VmError


@dataclass
class VmidPool:
    """Thread-safe VMID allocator for concurrent runs.

    On construction the pool is seeded with [lo..hi] minus whatever is already
    in `qm list` on the Proxmox host.  Workers `acquire()` to reserve and
    `release()` to return a VMID once their VM is destroyed.
    """

    lo: int = 9200
    hi: int = 9252
    _available: list[int] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @classmethod
    def from_proxmox(cls, pm: ProxmoxClient, lo: int = 9200, hi: int = 9252) -> "VmidPool":
        out = pm.run("qm list", check=False).stdout
        taken = set()
        for line in out.splitlines()[1:]:
            parts = line.split()
            if parts and parts[0].isdigit():
                taken.add(int(parts[0]))
        avail = [v for v in range(lo, hi + 1) if v not in taken]
        return cls(lo=lo, hi=hi, _available=avail)

    def acquire(self) -> int:
        with self._lock:
            if not self._available:
                raise VmError(f"VmidPool exhausted (range [{self.lo},{self.hi}])")
            return self._available.pop(0)

    def release(self, vmid: int) -> None:
        with self._lock:
            if vmid not in self._available:
                self._available.append(vmid)

    def size(self) -> int:
        with self._lock:
            return len(self._available)


def sweep(
    task_path: Path,
    *,
    agent_name: str = "stub",
    runs: int = 1,
    parallelism: int = 1,
    budget_seconds: int | None = None,
    proxmox_host: str = "p620-1",
    recipes_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Run `runs` attempts of `task` in parallel (up to `parallelism` at a time).

    Returns the list of score dicts (same shape `run_task` returns), in
    completion order.
    """
    pm = ProxmoxClient(host=proxmox_host)
    pool = VmidPool.from_proxmox(pm)
    if pool.size() < parallelism:
        raise VmError(
            f"VmidPool has {pool.size()} free VMIDs but parallelism={parallelism}"
        )

    def worker() -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "agent_name": agent_name,
            "proxmox_host": proxmox_host,
            "budget_seconds": budget_seconds,
            "vmid_pool": pool,
        }
        if recipes_dir is not None:
            kwargs["recipes_dir"] = recipes_dir
        return run_task(task_path, **kwargs)

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=parallelism) as ex:
        futures = [ex.submit(worker) for _ in range(runs)]
        for f in as_completed(futures):
            try:
                results.append(f.result())
            except Exception as exc:  # noqa: BLE001
                results.append({"status": "error", "error": f"{type(exc).__name__}: {exc}"})
    return results
