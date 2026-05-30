"""Parallel sweep driver for ndaybench runs (OpenVMM backend).

Runs many attempts of a task concurrently.  Each worker drives one `run_task`
with a unique (grpc_port, vnc_port) pair from a thread-safe pool; the run_id
already gives each VM a unique MAC + tap, so concurrent runs are isolated.
Threads are fine here — nearly all time is in subprocess SSH/gRPC calls.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .openvmm import OpenVmmClient, OpenVmmConfig
from .runner import run_task


class PoolExhausted(RuntimeError):
    pass


@dataclass
class PortPool:
    """Thread-safe allocator of (grpc_port, vnc_port) pairs for concurrent runs."""

    grpc_base: int = 18060
    vnc_base: int = 5930
    size: int = 16
    _free: list[tuple[int, int]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if not self._free:
            self._free = [
                (self.grpc_base + i, self.vnc_base + i) for i in range(self.size)
            ]

    def acquire(self) -> tuple[int, int]:
        with self._lock:
            if not self._free:
                raise PoolExhausted("port pool exhausted")
            return self._free.pop(0)

    def release(self, ports: tuple[int, int]) -> None:
        with self._lock:
            if ports not in self._free:
                self._free.append(ports)


def sweep(
    task_path: Path,
    *,
    agent_name: str = "stub",
    runs: int = 1,
    parallelism: int = 1,
    budget_seconds: int | None = None,
    host: str = "p620-1",
    recipes_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Run `runs` attempts of `task` in parallel (up to `parallelism` at once).

    Returns the list of score dicts (same shape `run_task` returns), in
    completion order.
    """
    pool = PortPool(size=max(parallelism, 1))

    # Bring up the shared bridge + CoW storage once, so concurrent workers don't
    # race on `ip link add` / `mount` / base-seed.
    client = OpenVmmClient(config=OpenVmmConfig(host=host))
    client.ensure_network()
    client.ensure_storage()

    def worker() -> dict[str, Any]:
        grpc_port, vnc_port = pool.acquire()
        try:
            kwargs: dict[str, Any] = {
                "agent_name": agent_name,
                "host": host,
                "budget_seconds": budget_seconds,
                "grpc_port": grpc_port,
                "vnc_port": vnc_port,
            }
            if recipes_dir is not None:
                kwargs["recipes_dir"] = recipes_dir
            return run_task(task_path, **kwargs)
        finally:
            pool.release((grpc_port, vnc_port))

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=parallelism) as ex:
        futures = [ex.submit(worker) for _ in range(runs)]
        for f in as_completed(futures):
            try:
                results.append(f.result())
            except Exception as exc:  # noqa: BLE001
                results.append({"status": "error", "error": f"{type(exc).__name__}: {exc}"})
    return results
