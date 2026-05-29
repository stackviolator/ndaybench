"""Thin SSH/qm wrapper for Proxmox operations.

Each function returns a list[str] command suitable for subprocess.run().
The BuildConfig (ssh_command + host + user) is threaded through so callers
can swap in a dry-run print instead of actual execution.

All commands are designed to be unit-testable in isolation — they produce
deterministic command lists from their arguments.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Command builders — pure functions, no I/O
# ---------------------------------------------------------------------------


def cmd_qm_clone(src_vmid: int, new_vmid: int, *, linked: bool = True) -> list[str]:
    """Clone a VM, optionally as a linked clone."""
    args = ["qm", "clone", str(src_vmid), str(new_vmid)]
    if linked:
        args.append("--full=0")
    return args


def cmd_qm_create(
    vmid: int,
    *,
    name: str,
    memory_mb: int = 4096,
    cores: int = 4,
    bridge: str = "vmbr1000",
) -> list[str]:
    return [
        "qm",
        "create",
        str(vmid),
        "--name",
        name,
        "--memory",
        str(memory_mb),
        "--cores",
        str(cores),
        "--net0",
        f"virtio,bridge={bridge}",
        "--agent",
        "enabled=1",
        "--ostype",
        "win10",
    ]


def cmd_qm_set_efidisk(
    vmid: int,
    storage: str = "local",
    *,
    pre_enrolled_keys: int = 0,
    fmt: str = "qcow2",
) -> list[str]:
    """Allocate a fresh EFI variable store, optionally without pre-enrolled SB keys."""
    efi_spec = (
        f"{storage}:0,efitype=4m,pre-enrolled-keys={pre_enrolled_keys},format={fmt}"
    )
    return ["qm", "set", str(vmid), "--efidisk0", efi_spec]


def cmd_qm_set_cdrom(vmid: int, storage: str, iso_name: str) -> list[str]:
    """Attach an ISO as a cdrom device."""
    return [
        "qm",
        "set",
        str(vmid),
        "--ide0",
        f"{storage}:iso/{iso_name},media=cdrom",
    ]


def cmd_qm_eject_cdrom(vmid: int) -> list[str]:
    """Eject the cdrom (set to none)."""
    return ["qm", "set", str(vmid), "--ide0", "none,media=cdrom"]


def cmd_qm_start(vmid: int) -> list[str]:
    return ["qm", "start", str(vmid)]


def cmd_qm_shutdown(vmid: int) -> list[str]:
    return ["qm", "guest", "cmd", str(vmid), "shutdown"]


# Alias used by builder (more explicit name)
cmd_qm_guest_cmd_shutdown = cmd_qm_shutdown


def cmd_qm_status(vmid: int) -> list[str]:
    return ["qm", "status", str(vmid)]


def cmd_qm_guest_ping(vmid: int) -> list[str]:
    return ["qm", "guest", "cmd", str(vmid), "ping"]


def cmd_qm_guest_exec(
    vmid: int,
    *guest_args: str,
    timeout: int = 60,
) -> list[str]:
    return [
        "qm",
        "guest",
        "exec",
        "--timeout",
        str(timeout),
        str(vmid),
        "--",
        *guest_args,
    ]


def cmd_qm_guest_exec_powershell(
    vmid: int,
    ps_command: str,
    *,
    timeout: int = 60,
) -> list[str]:
    return cmd_qm_guest_exec(
        vmid,
        "powershell.exe",
        "-NoProfile",
        "-Command",
        ps_command,
        timeout=timeout,
    )


def cmd_qm_guest_exec_cmd(
    vmid: int,
    cmd_command: str,
    *,
    timeout: int = 60,
) -> list[str]:
    """Run a command via cmd.exe /c inside the guest.

    Use this for bcdedit calls — PowerShell mangles {default}/{current} braces.
    """
    return cmd_qm_guest_exec(
        vmid,
        "cmd.exe",
        "/c",
        cmd_command,
        timeout=timeout,
    )


def cmd_qm_destroy(vmid: int) -> list[str]:
    return ["qm", "destroy", str(vmid), "--purge", "1"]


def cmd_genisoimage(
    output_iso: str,
    volume_label: str,
    *source_files: str,
) -> list[str]:
    return [
        "genisoimage",
        "-o",
        output_iso,
        "-V",
        volume_label,
        "-J",
        "-r",
        *source_files,
    ]


def cmd_qemu_img_convert(src_qcow2: str, dst_raw: str) -> list[str]:
    return [
        "qemu-img",
        "convert",
        "-p",
        "-O",
        "raw",
        src_qcow2,
        dst_raw,
    ]


def cmd_rm(path: str) -> list[str]:
    return ["rm", "-f", path]


def cmd_find_disk(vmid: int, images_root: str = "/var/lib/vz/images") -> list[str]:
    """Find the main disk qcow2 for a given VMID (returns a find command)."""
    return [
        "find",
        f"{images_root}/{vmid}",
        "-name",
        f"vm-{vmid}-disk-*.qcow2",
        "-not",
        "-name",
        "*efidisk*",
    ]


# ---------------------------------------------------------------------------
# SSH wrapper
# ---------------------------------------------------------------------------


@dataclass
class SshConfig:
    """SSH connection parameters."""

    host: str = "p620-1"
    user: str = "root"
    ssh_command: list[str] = field(default_factory=lambda: ["ssh"])

    @property
    def target(self) -> str:
        return f"{self.user}@{self.host}"

    def wrap(self, remote_cmd: list[str]) -> list[str]:
        """Wrap *remote_cmd* in an SSH invocation.

        SSH joins everything after the destination with spaces and hands it
        to the user's login shell on the far side, which re-tokenizes — so
        PowerShell snippets with ``((`` or ``{}`` get mangled by remote bash
        before they ever reach qm/PowerShell.  Pass the remote command as a
        single shlex-quoted string instead.
        """
        quoted = " ".join(shlex.quote(arg) for arg in remote_cmd)
        return self.ssh_command + [self.target, quoted]
