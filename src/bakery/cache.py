"""Content-addressed image cache for baked VM snapshots.

Images are stored as ``<hash>.raw`` on the Proxmox host under ``cache_root``.
A sibling ``<hash>.manifest.json`` records build metadata.

The cache is keyed on the recipe content_hash (SHA-256 of the transitive
recipe closure).  Hits return early without rebuilding.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class ImageManifest:
    """Metadata written next to every cached raw image."""

    recipe_hash: str
    build_timestamp: float = field(default_factory=time.time)
    verified_ubr: int | None = None
    build_duration_seconds: float | None = None
    source_recipe_ids: list[str] = field(default_factory=list)
    proxmox_host: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, text: str) -> ImageManifest:
        return cls(**json.loads(text))


class ImageCache:
    """Manage the on-host raw image cache directory.

    The cache lives on the Proxmox host (accessed via SSH).  This class only
    knows about *local* paths — the builder is responsible for SSH transport.
    For dry-run mode the builder calls ``raw_path`` / ``manifest_path`` to
    construct the paths it *would* create.
    """

    def __init__(self, cache_root: Path) -> None:
        self.root = cache_root

    def raw_path(self, recipe_hash: str) -> Path:
        return self.root / f"{recipe_hash}.raw"

    def manifest_path(self, recipe_hash: str) -> Path:
        return self.root / f"{recipe_hash}.manifest.json"

    def is_cached(self, recipe_hash: str) -> bool:
        """Return True if both the .raw and .manifest.json exist."""
        return (
            self.raw_path(recipe_hash).exists()
            and self.manifest_path(recipe_hash).exists()
        )

    def write_manifest(self, manifest: ImageManifest) -> Path:
        """Write manifest to disk; return the path."""
        p = self.manifest_path(manifest.recipe_hash)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(manifest.to_json())
        return p

    def read_manifest(self, recipe_hash: str) -> ImageManifest:
        p = self.manifest_path(recipe_hash)
        return ImageManifest.from_json(p.read_text())
