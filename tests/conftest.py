"""Shared pytest configuration for ndaybench tests."""

import os

import pytest


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless NDAYBENCH_INTEGRATION=1 is set."""
    if os.environ.get("NDAYBENCH_INTEGRATION") == "1":
        return
    skip_integration = pytest.mark.skip(
        reason="integration tests need real Proxmox; set NDAYBENCH_INTEGRATION=1"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)
