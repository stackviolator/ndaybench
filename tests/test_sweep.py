"""Unit tests for VmidPool (no Proxmox required)."""

import threading

import pytest

from ndaybench.sweep import VmidPool
from ndaybench.vm import VmError


def test_acquire_release_roundtrip() -> None:
    pool = VmidPool(lo=9200, hi=9202)
    pool._available = [9200, 9201, 9202]
    a = pool.acquire()
    b = pool.acquire()
    c = pool.acquire()
    assert {a, b, c} == {9200, 9201, 9202}
    # Exhausted
    with pytest.raises(VmError):
        pool.acquire()
    # Return one and re-acquire
    pool.release(b)
    assert pool.acquire() == b


def test_distinct_ids_under_threads() -> None:
    pool = VmidPool(lo=9200, hi=9252)
    pool._available = list(range(9200, 9253))
    acquired: list[int] = []
    lock = threading.Lock()

    def worker() -> None:
        v = pool.acquire()
        with lock:
            acquired.append(v)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # No duplicates handed out — the whole point of the pool.
    assert len(acquired) == len(set(acquired)) == 20


def test_double_release_is_idempotent() -> None:
    pool = VmidPool(lo=9200, hi=9201)
    pool._available = [9200, 9201]
    v = pool.acquire()
    pool.release(v)
    pool.release(v)  # should not duplicate
    assert pool.size() == 2
