"""Schema tests for task recipes (no infra needed)."""

from pathlib import Path

import pytest
from bakery.recipe import TaskRecipe, load_task, recipe_hash

REPO_ROOT = Path(__file__).resolve().parents[1]
RECIPES = REPO_ROOT / "recipes"


def test_load_cve_2025_26633() -> None:
    task, plan = load_task(RECIPES / "tasks" / "CVE-2025-26633.yaml", [RECIPES])
    assert task.cve_id == "CVE-2025-26633"
    assert task.class_ == "lpe"
    assert task.flag is not None
    assert task.flag.profile == "admin"
    assert task.grader is not None
    assert task.grader.max_attempt_seconds == 7200
    assert "lpe-harness" in [c.id for c in plan.customizations]


def test_dual_vm_defaults_to_false() -> None:
    """dual_vm and scratch_extra_customizations are present and default off."""
    task = TaskRecipe.model_validate(
        {
            "cve_id": "CVE-2999-99999",
            "edition": "win11-22h2-enterprise",
            "baseline": "win11-22h2-2025-02",
        }
    )
    assert task.dual_vm is False
    assert task.scratch_extra_customizations == []


def test_dual_vm_fields_do_not_affect_image_hash() -> None:
    """Adding dual_vm metadata mustn't churn the cached image hash."""
    base = {
        "cve_id": "CVE-2999-99999",
        "edition": "win11-22h2-enterprise",
        "baseline": "win11-22h2-2025-02",
    }
    a = TaskRecipe.model_validate(base)
    b = TaskRecipe.model_validate(
        {**base, "dual_vm": True, "scratch_extra_customizations": ["kd-net-vmbus"]}
    )
    # recipe_hash on the TaskRecipe directly excludes class_/flag/dual_vm/etc.
    assert recipe_hash(a) == recipe_hash(b)


def test_all_recipes_parse_clean() -> None:
    """Every checked-in task recipe loads without error."""
    failures = []
    for p in (RECIPES / "tasks").glob("*.yaml"):
        try:
            load_task(p, [RECIPES])
        except Exception as exc:
            failures.append((p.name, str(exc)))
    assert not failures, f"task recipes failed to load: {failures}"
