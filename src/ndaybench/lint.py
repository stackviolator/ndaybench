"""Recipe linter — validate baselines, customizations, and tasks under recipes/.

Errors (severity="error") break the build; warnings (severity="warn") are
heuristics that may or may not be intentional.

Run via the `ndaybench lint` CLI command.  Exits 1 if any errors are found.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from bakery.recipe import (
    load_baseline,
    load_customization,
    load_edition,
    load_task,
)

_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_BUILD_RE = re.compile(r"^\d+\.\d+$")


@dataclass
class LintIssue:
    severity: str   # "error" | "warn"
    recipe: str     # path
    message: str


def lint_recipes(recipes_dir: Path) -> list[LintIssue]:
    """Walk *recipes_dir* and return every issue found."""
    issues: list[LintIssue] = []
    recipes_dir = recipes_dir.resolve()

    # Editions — pure Pydantic validation.
    for p in sorted((recipes_dir / "editions").glob("*.yaml")):
        try:
            load_edition(p)
        except Exception as exc:  # noqa: BLE001
            issues.append(LintIssue("error", str(p), f"edition load failed: {exc}"))

    # Baselines — validate target_build format + each patch's sha256/url.
    for p in sorted((recipes_dir / "baselines").glob("*.yaml")):
        try:
            rb = load_baseline(p, [recipes_dir])
        except Exception as exc:  # noqa: BLE001
            issues.append(LintIssue("error", str(p), f"baseline load failed: {exc}"))
            continue

        if not _BUILD_RE.match(rb.target_build):
            issues.append(
                LintIssue(
                    "warn",
                    str(p),
                    f"target_build {rb.target_build!r} doesn't match 'major.minor' form",
                )
            )

        for patch in rb.patches:
            if not _HEX64.match(patch.sha256.lower()):
                issues.append(
                    LintIssue(
                        "error",
                        str(p),
                        f"patch {patch.kb} sha256 is not 64 lowercase hex chars",
                    )
                )
            if not patch.url.startswith("https://"):
                issues.append(
                    LintIssue(
                        "warn",
                        str(p),
                        f"patch {patch.kb} url is not https://",
                    )
                )

    # Customizations — load each.
    for p in sorted((recipes_dir / "customizations").glob("*.yaml")):
        try:
            load_customization(p)
        except Exception as exc:  # noqa: BLE001
            issues.append(LintIssue("error", str(p), f"customization load failed: {exc}"))

    # Tasks — load resolves the full plan; check conflicts, brief, class consistency.
    for p in sorted((recipes_dir / "tasks").glob("*.yaml")):
        try:
            task, plan = load_task(p, [recipes_dir])
        except Exception as exc:  # noqa: BLE001
            issues.append(LintIssue("error", str(p), f"task load failed: {exc}"))
            continue

        for cv in plan.conflicts:
            issues.append(
                LintIssue(
                    "error",
                    str(p),
                    f"customization conflict: {cv.a!r} conflicts_with {cv.b!r}",
                )
            )

        if task.agent_brief_path:
            brief = (recipes_dir.parent / task.agent_brief_path).resolve()
            if not brief.exists():
                issues.append(
                    LintIssue(
                        "error",
                        str(p),
                        f"agent_brief_path points to missing file: {task.agent_brief_path}",
                    )
                )

        cust_ids = {c.id for c in plan.customizations}
        if task.class_ == "lpe" and "lpe-harness" not in cust_ids:
            issues.append(
                LintIssue(
                    "warn",
                    str(p),
                    "class=lpe but lpe-harness is not in customizations",
                )
            )
        elif task.class_ == "rce" and "rce-harness" not in cust_ids:
            issues.append(
                LintIssue(
                    "warn",
                    str(p),
                    "class=rce but rce-harness is not in customizations",
                )
            )

        if task.dual_vm:
            for cid in task.scratch_extra_customizations:
                cust_path = recipes_dir / "customizations" / f"{cid}.yaml"
                if not cust_path.exists():
                    issues.append(
                        LintIssue(
                            "error",
                            str(p),
                            f"scratch_extra_customizations references missing {cid!r}",
                        )
                    )

    return issues
