"""Unit tests for the sweep PortPool (no host required)."""

import threading

import pytest

from ndaybench.sweep import PoolExhausted, PortPool


def test_acquire_release_roundtrip() -> None:
    pool = PortPool(size=3)
    a = pool.acquire()
    b = pool.acquire()
    c = pool.acquire()
    assert len({a, b, c}) == 3
    with pytest.raises(PoolExhausted):
        pool.acquire()
    pool.release(b)
    assert pool.acquire() == b


def test_distinct_ports_under_threads() -> None:
    pool = PortPool(size=20)
    acquired: list[tuple[int, int]] = []
    lock = threading.Lock()

    def worker() -> None:
        p = pool.acquire()
        with lock:
            acquired.append(p)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # No duplicate (grpc, vnc) pairs handed out — the whole point of the pool.
    assert len(acquired) == len(set(acquired)) == 20


def test_double_release_is_idempotent() -> None:
    pool = PortPool(size=2)
    a = pool.acquire()
    pool.release(a)
    pool.release(a)  # must not duplicate
    assert len(pool._free) == 2
