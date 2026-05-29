"""Unit tests for the recipe linter."""

from pathlib import Path

import pytest

from ndaybench.lint import lint_recipes

REPO_ROOT = Path(__file__).resolve().parents[1]
RECIPES = REPO_ROOT / "recipes"


def test_real_catalog_lints_clean_of_errors() -> None:
    """The committed recipes/ tree should pass with zero errors.

    Warnings are tolerated — they're heuristic.
    """
    issues = lint_recipes(RECIPES)
    errors = [i for i in issues if i.severity == "error"]
    assert errors == [], "real catalog should have no errors: " + str(errors)


def _scaffold_minimal_recipes(tmp_path: Path) -> Path:
    """Build a tiny but valid recipes tree under tmp_path/recipes and return it."""
    base = tmp_path / "recipes"
    for sub in ("editions", "baselines", "customizations", "tasks"):
        (base / sub).mkdir(parents=True)

    (base / "editions" / "win.yaml").write_text(
        "schema_version: 1\nid: win\ndisplay_name: w\n"
        "iso_url: https://example/x.iso\n"
        "iso_sha256: " + "a" * 64 + "\n"
        "wim_index: 1\nfirmware: uefi\n"
    )
    (base / "baselines" / "base.yaml").write_text(
        "schema_version: 1\nid: base\ndisplay_name: b\nedition: win\n"
        "target_build: '22621.4890'\npatches: []\n"
    )
    (base / "customizations" / "lpe-harness.yaml").write_text(
        "schema_version: 1\nid: lpe-harness\ndisplay_name: lpe\nsteps: []\n"
    )
    return base


def test_detects_missing_brief(tmp_path: Path) -> None:
    base = _scaffold_minimal_recipes(tmp_path)
    (base / "tasks" / "bad.yaml").write_text(
        "schema_version: 1\ncve_id: CVE-9999-9999\nclass: lpe\n"
        "edition: win\nbaseline: base\ncustomizations: [lpe-harness]\n"
        "agent_brief_path: bench/does-not-exist/brief.md\n"
    )
    issues = lint_recipes(base)
    errs = [i for i in issues if i.severity == "error"]
    assert any("agent_brief_path" in i.message for i in errs), errs


def test_warns_when_lpe_task_missing_harness(tmp_path: Path) -> None:
    base = _scaffold_minimal_recipes(tmp_path)
    (base / "tasks" / "noharness.yaml").write_text(
        "schema_version: 1\ncve_id: CVE-9999-9999\nclass: lpe\n"
        "edition: win\nbaseline: base\ncustomizations: []\n"
    )
    issues = lint_recipes(base)
    warns = [i for i in issues if i.severity == "warn"]
    assert any("lpe-harness" in i.message for i in warns), warns


def test_detects_bad_patch_sha256(tmp_path: Path) -> None:
    base = _scaffold_minimal_recipes(tmp_path)
    # Overwrite baseline with a malformed patch hash
    (base / "baselines" / "base.yaml").write_text(
        "schema_version: 1\nid: base\ndisplay_name: b\nedition: win\n"
        "target_build: '22621.4890'\n"
        "patches:\n"
        "  - kb: KB1234567\n"
        "    sha256: NOTHEX\n"
        "    catalog_guid: 00000000-0000-0000-0000-000000000000\n"
        "    url: https://example/k.msu\n"
    )
    issues = lint_recipes(base)
    errs = [i for i in issues if i.severity == "error"]
    assert any("sha256" in i.message for i in errs), errs


def test_warns_on_nonhttps_patch_url(tmp_path: Path) -> None:
    base = _scaffold_minimal_recipes(tmp_path)
    (base / "baselines" / "base.yaml").write_text(
        "schema_version: 1\nid: base\ndisplay_name: b\nedition: win\n"
        "target_build: '22621.4890'\n"
        "patches:\n"
        "  - kb: KB1234567\n"
        "    sha256: " + "a" * 64 + "\n"
        "    catalog_guid: 00000000-0000-0000-0000-000000000000\n"
        "    url: http://insecure.example/k.msu\n"
    )
    issues = lint_recipes(base)
    warns = [i for i in issues if i.severity == "warn"]
    assert any("https" in i.message for i in warns), warns
