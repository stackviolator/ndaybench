"""Builder: takes a Plan and executes it against a Proxmox host.

Canonical build loop (from empirical PoC, 2026-05-27):

  1.  qm clone <SRC> <NEW> (linked)
  2.  Replace efidisk: qm set <NEW> --efidisk0 local:0,efitype=4m,pre-enrolled-keys=0
  3.  Wrap MSU in ISO: genisoimage -o /var/lib/vz/template/iso/<id>-<kb>.iso ...
  4.  Attach ISO: qm set <NEW> --ide0 local:iso/<iso>,media=cdrom
  5.  qm start <NEW>; poll guest agent ping
  6.  Re-enable wuauserv (Ludus templates disable WU)
  7.  wusa.exe /quiet /norestart; expect exit 3010 (reboot needed) or 0
  8.  bcdedit via cmd.exe (NOT PowerShell — PS mangles {default} braces)
  9.  qm guest cmd <NEW> shutdown; poll until stopped
  10. Eject ISO; qm start <NEW>; wait agent (finalization boot)
  11. Verify UBR
  12. (Optional) sysprep
  13. qm guest cmd <NEW> shutdown; poll stopped
  14. qemu-img convert qcow2 -> raw -> cache
  15. qm destroy <NEW> --purge 1; rm ISO

Usage:

    config = BuildConfig(proxmox_host="p620-1")
    builder = Builder(config)
    raw_path = builder.build(task)          # real build
    raw_path = builder.build(task, dry_run=True)   # print commands only
"""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .cache import ImageCache, ImageManifest
from .proxmox import (
    SshConfig,
    cmd_find_disk,
    cmd_genisoimage,
    cmd_qemu_img_convert,
    cmd_qm_clone,
    cmd_qm_destroy,
    cmd_qm_eject_cdrom,
    cmd_qm_guest_cmd_shutdown,
    cmd_qm_guest_exec,
    cmd_qm_guest_exec_cmd,
    cmd_qm_guest_exec_powershell,
    cmd_qm_guest_ping,
    cmd_qm_set_cdrom,
    cmd_qm_set_efidisk,
    cmd_qm_start,
    cmd_qm_status,
    cmd_rm,
)
from .recipe import (
    ApplyMsuStep,
    BcdeditStep,
    Plan,
    PowershellInlineStep,
    QmConfigStep,
    RegistrySetStep,
    SysprepStep,
    TaskRecipe,
    VerifyBuildStep,
    WaitForRebootStep,
    load_task,
)

log = logging.getLogger(__name__)

# Path on the Proxmox host where MSU files are pre-staged.
MSU_HOST_DIR = "/root/ndaybench/msu"

# ISO template storage path on the Proxmox host.
ISO_TEMPLATE_DIR = "/var/lib/vz/template/iso"

# Path where Proxmox stores VM disk images.
VM_IMAGES_DIR = "/var/lib/vz/images"

# Guest-side path where the ISO is mounted (typically D:\ on Windows).
GUEST_ISO_DRIVE = "D:"

# Poll interval in seconds for agent-ping and VM-status checks.
_POLL_INTERVAL = 5

# Maximum seconds to wait for the guest agent after start.
_AGENT_TIMEOUT = 600

# Maximum seconds to wait for a VM to reach "stopped" state.
_STOP_TIMEOUT = 120


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class BuildConfig:
    """Configuration for a Builder instance."""

    proxmox_host: str = "p620-1"
    proxmox_user: str = "root"
    # VMID range to allocate from.  Builder picks the first unused one.
    vmid_range: range = field(default_factory=lambda: range(9100, 9200))
    # Source template VMID to clone from (must exist on the Proxmox host).
    source_vmid: int = 9000
    iso_storage: str = "local"
    disk_storage: str = "local"
    bridge: str = "vmbr1000"
    cache_root: Path = field(
        default_factory=lambda: Path("~/.cache/ndaybench/images").expanduser()
    )
    # Override to add -i <keyfile>, ProxyJump, etc.
    ssh_command: list[str] = field(default_factory=lambda: ["ssh"])


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class Builder:
    """Execute a Plan against a Proxmox host to produce a cached raw image."""

    def __init__(self, config: BuildConfig) -> None:
        self.config = config
        self._ssh = SshConfig(
            host=config.proxmox_host,
            user=config.proxmox_user,
            ssh_command=config.ssh_command,
        )
        self._cache = ImageCache(config.cache_root)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, task: TaskRecipe, *, dry_run: bool = False) -> Path:
        """Build the image for *task* and return the path to the cached .raw file.

        If dry_run=True, commands are printed but not executed.  The returned
        path is the would-be cache location (does not exist yet).
        """
        from pathlib import Path as _Path

        search = [_Path("recipes")]
        _raw, plan = load_task(
            # Re-resolve from disk so the Plan is always fresh.
            # If the caller already has a Plan they can pass it via build_plan().
            # This overload exists for CLI convenience.
            _find_task_path(task),
            search,
        )
        return self.build_plan(plan, dry_run=dry_run)

    def build_plan(self, plan: Plan, *, dry_run: bool = False) -> Path:
        """Execute *plan* and return the path to the cached .raw file."""
        h = plan.content_hash
        raw = self._cache.raw_path(h)

        if not dry_run and self._cache.is_cached(h):
            log.info("Cache hit for %s — skipping build.", h[:16])
            return raw

        if dry_run:
            print(f"[dry-run] Recipe hash: {h}")
            print(f"[dry-run] Cache path (would-be): {raw}")
            print()

        vmid = self._pick_vmid(dry_run=dry_run)
        iso_name, iso_path = self._iso_name(plan)
        t_start = time.monotonic()

        try:
            self._phase_clone_and_prepare(plan, vmid, iso_name, iso_path, dry_run)
            verified_ubr = self._phase_patch_and_configure(plan, vmid, iso_name, dry_run)
            self._phase_capture(plan, vmid, h, dry_run)
        except Exception:
            if not dry_run:
                log.exception("Build failed — attempting cleanup of VMID %d", vmid)
                self._cleanup(vmid, iso_path, dry_run=False)
            raise

        duration = time.monotonic() - t_start

        if not dry_run:
            manifest = ImageManifest(
                recipe_hash=h,
                build_timestamp=time.time(),
                verified_ubr=verified_ubr,
                build_duration_seconds=duration,
                source_recipe_ids=[
                    plan.task.edition,
                    plan.task.baseline,
                    *plan.task.customizations,
                ],
                proxmox_host=self.config.proxmox_host,
            )
            self._cache.write_manifest(manifest)
            log.info(
                "Build complete in %.1fs  hash=%s  raw=%s",
                duration,
                h[:16],
                raw,
            )

        return raw

    # ------------------------------------------------------------------
    # Build phases
    # ------------------------------------------------------------------

    def _phase_clone_and_prepare(
        self,
        plan: Plan,
        vmid: int,
        iso_name: str,
        iso_path: str,
        dry_run: bool,
    ) -> None:
        """Phase 1: clone source VM, replace EFI disk, wrap MSU in ISO, attach."""

        # Step 1: clone
        self._run(cmd_qm_clone(self.config.source_vmid, vmid), dry_run)

        # Step 2: replace EFI disk with fresh pre-enrolled-keys=0 allocation
        # (required for KDNET — bcdedit /set {default} debug on is blocked
        # when Secure Boot keys are enrolled).
        pre_enrolled = 1 if plan.edition.secure_boot else 0
        self._run(
            cmd_qm_set_efidisk(
                vmid,
                self.config.disk_storage,
                pre_enrolled_keys=pre_enrolled,
                fmt=plan.edition.efidisk_format,
            ),
            dry_run,
        )

        # Step 3 & 4: for each patch, wrap in ISO and attach.
        # (We handle patches in _phase_patch_and_configure; here we just
        # attach the first patch ISO so the VM boots with it available.)
        if plan.patches:
            first_kb = plan.patches[0].kb
            msu_src = f"{MSU_HOST_DIR}/{first_kb}.msu"
            iso_full = f"{ISO_TEMPLATE_DIR}/{iso_name}"
            self._run(
                cmd_genisoimage(iso_full, first_kb, msu_src),
                dry_run,
            )
            self._run(
                cmd_qm_set_cdrom(vmid, self.config.iso_storage, iso_name),
                dry_run,
            )

        # Step 5: start VM and wait for agent
        self._run(cmd_qm_start(vmid), dry_run)
        self._wait_for_agent(vmid, dry_run)

    def _phase_patch_and_configure(
        self,
        plan: Plan,
        vmid: int,
        iso_name: str,
        dry_run: bool,
    ) -> int | None:
        """Phase 2: apply patches, run customization steps.  Returns verified UBR."""
        verified_ubr: int | None = None

        # Apply each patch via wusa.exe
        for patch in plan.patches:
            self._apply_patch(vmid, patch.kb, dry_run)

        # After patches, reboot cycle so changes take effect
        if plan.patches:
            self._full_reboot_cycle(vmid, iso_name, dry_run, eject_first=True)

        # Run customization steps
        for cust in plan.customizations:
            for step in cust.steps:
                result = self._run_step(vmid, step, plan, dry_run)
                if result is not None:
                    verified_ubr = result

        return verified_ubr

    def _phase_capture(
        self,
        plan: Plan,
        vmid: int,
        recipe_hash: str,
        dry_run: bool,
    ) -> None:
        """Phase 3: optional sysprep, shutdown, convert qcow2 -> raw, cleanup."""

        # Shutdown for capture
        self._run(cmd_qm_guest_cmd_shutdown(vmid), dry_run)
        self._wait_stopped(vmid, dry_run)

        # Find the main disk
        find_cmd = cmd_find_disk(vmid, VM_IMAGES_DIR)
        if dry_run:
            print(f"[dry-run] $ (ssh) {' '.join(find_cmd)}")
            disk_path = f"{VM_IMAGES_DIR}/{vmid}/vm-{vmid}-disk-0.qcow2"
        else:
            out = self._ssh_output(find_cmd)
            disk_path = out.strip().splitlines()[0]

        raw_path = str(self._cache.raw_path(recipe_hash))
        tmp_raw = f"{raw_path}.tmp"

        # Convert qcow2 -> raw into a temp path, then mv into place
        self._run(cmd_qemu_img_convert(disk_path, tmp_raw), dry_run)

        mv_cmd = ["mv", tmp_raw, raw_path]
        self._run(mv_cmd, dry_run)

        # Cleanup: destroy VM and remove ISO
        iso_path = f"{ISO_TEMPLATE_DIR}/{_iso_name_for_plan(plan)}"
        self._cleanup(vmid, iso_path, dry_run=dry_run)

    # ------------------------------------------------------------------
    # Step executor
    # ------------------------------------------------------------------

    def _run_step(
        self, vmid: int, step: object, plan: Plan, dry_run: bool
    ) -> int | None:
        """Dispatch a RecipeStep to the appropriate handler.  Returns UBR if verify-build."""
        if isinstance(step, BcdeditStep):
            self._step_bcdedit(vmid, step, dry_run)
        elif isinstance(step, ApplyMsuStep):
            self._step_apply_msu(vmid, step, dry_run)
        elif isinstance(step, WaitForRebootStep):
            self._step_wait_for_reboot(vmid, plan, dry_run)
        elif isinstance(step, SysprepStep):
            self._step_sysprep(vmid, step, dry_run)
        elif isinstance(step, VerifyBuildStep):
            return self._step_verify_build(vmid, step, dry_run)
        elif isinstance(step, PowershellInlineStep):
            self._step_powershell_inline(vmid, step, dry_run)
        elif isinstance(step, RegistrySetStep):
            self._step_registry_set(vmid, step, dry_run)
        elif isinstance(step, QmConfigStep):
            self._step_qm_config(vmid, step, dry_run)
        else:
            log.warning("Unhandled step type: %s", type(step).__name__)
        return None

    def _step_bcdedit(self, vmid: int, step: BcdeditStep, dry_run: bool) -> None:
        """Run bcdedit via cmd.exe (default) or PowerShell.

        Always use cmd.exe for bcdedit.  PowerShell parses {default} and
        {current} as scriptblock/hashtable delimiters and corrupts the args.
        """
        if step.via == "cmd":
            cmd = cmd_qm_guest_exec_cmd(vmid, f"bcdedit {step.args}")
        else:
            cmd = cmd_qm_guest_exec_powershell(vmid, f"bcdedit {step.args}")
        self._run(cmd, dry_run)

    def _step_apply_msu(self, vmid: int, step: ApplyMsuStep, dry_run: bool) -> None:
        """Install an MSU via wusa.exe.

        Sequence:
        1. Re-enable wuauserv (Ludus templates leave it Disabled).
        2. Start-Process wusa.exe ... -Wait -PassThru; check ExitCode.
        3. Accept 0 (success, no reboot) or 3010 (success, reboot needed).
        """
        # Re-enable Windows Update service defensively
        enable_cmd = cmd_qm_guest_exec_powershell(
            vmid,
            (
                "if ((Get-Service wuauserv).StartType -eq 'Disabled') {"
                " Set-Service wuauserv -StartupType Manual };"
                " Start-Service wuauserv"
            ),
        )
        self._run(enable_cmd, dry_run)

        # Run wusa.exe via Start-Process so we can capture ExitCode
        expected = ",".join(str(c) for c in step.expected_exit_codes)
        ps = (
            f"$p = Start-Process wusa.exe "
            f"-ArgumentList '{step.msu_path_in_guest}','/quiet','/norestart' "
            f"-Wait -PassThru; "
            f"if ($p.ExitCode -notin @({expected})) "
            f"{{ exit $p.ExitCode }} else {{ Write-Output $p.ExitCode }}"
        )
        wusa_cmd = cmd_qm_guest_exec_powershell(
            vmid, ps, timeout=step.timeout_seconds
        )
        self._run(wusa_cmd, dry_run)

    def _step_wait_for_reboot(
        self, vmid: int, plan: Plan, dry_run: bool
    ) -> None:
        """Full shutdown + wait-stopped + start + wait-agent cycle."""
        iso_name = _iso_name_for_plan(plan)
        self._full_reboot_cycle(vmid, iso_name, dry_run, eject_first=False)

    def _step_sysprep(self, vmid: int, step: SysprepStep, dry_run: bool) -> None:
        shutdown_flag = "/shutdown" if step.shutdown else ""
        ps = (
            f"sysprep.exe /{step.mode} {shutdown_flag} /mode:vm /quiet"
        ).strip()
        # sysprep lives in System32\Sysprep; run from there to avoid path issues
        cmd = cmd_qm_guest_exec_cmd(
            vmid, f"cd %SystemRoot%\\System32\\Sysprep && {ps}"
        )
        if step.strict:
            self._run(cmd, dry_run)
        else:
            # Ignore non-zero exit
            try:
                self._run(cmd, dry_run)
            except subprocess.CalledProcessError as exc:
                log.warning(
                    "sysprep exited %d (strict=False — ignoring): %s",
                    exc.returncode,
                    exc,
                )

    def _step_verify_build(
        self, vmid: int, step: VerifyBuildStep, dry_run: bool
    ) -> int:
        """Read UBR from registry and assert it matches expected_ubr."""
        ps = (
            "(Get-ItemProperty "
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').UBR"
        )
        cmd = cmd_qm_guest_exec_powershell(vmid, ps)
        if dry_run:
            print(f"[dry-run] $ (ssh) {' '.join(self._ssh.wrap(cmd))}")
            print(f"[dry-run]   (would assert UBR == {step.expected_ubr})")
            return step.expected_ubr
        out = self._ssh_output(cmd)
        ubr = int(out.strip())
        if ubr != step.expected_ubr:
            raise RuntimeError(
                f"UBR mismatch: expected {step.expected_ubr}, got {ubr}"
            )
        log.info("UBR verified: %d", ubr)
        return ubr

    def _step_powershell_inline(
        self, vmid: int, step: PowershellInlineStep, dry_run: bool
    ) -> None:
        cmd = cmd_qm_guest_exec_powershell(vmid, step.script, timeout=step.timeout)
        self._run(cmd, dry_run)

    def _step_registry_set(
        self, vmid: int, step: RegistrySetStep, dry_run: bool
    ) -> None:
        ps = (
            f"Set-ItemProperty -Path '{step.hive}:\\{step.key}' "
            f"-Name '{step.name}' -Value {step.value} "
            f"-Type {step.kind.replace('REG_', '')}"
        )
        cmd = cmd_qm_guest_exec_powershell(vmid, ps)
        self._run(cmd, dry_run)

    def _step_qm_config(self, vmid: int, step: QmConfigStep, dry_run: bool) -> None:
        """Apply a qm set argument directly on the host (not inside the guest)."""
        parts = step.args.split(":", 1)
        if len(parts) == 2:
            key = parts[0].strip()
            val = parts[1].strip()
            host_cmd = ["qm", "set", str(vmid), f"--{key}", val]
        else:
            host_cmd = ["qm", "set", str(vmid)] + step.args.split()
        self._run_host(host_cmd, dry_run)

    # ------------------------------------------------------------------
    # Patch application
    # ------------------------------------------------------------------

    def _apply_patch(self, vmid: int, kb: str, dry_run: bool) -> None:
        """Apply a single MSU patch using wusa.exe."""
        # MSU is assumed to be available at GUEST_ISO_DRIVE\<kb>.msu
        # (mounted via the ISO we attached in _phase_clone_and_prepare).
        msu_guest_path = f"{GUEST_ISO_DRIVE}\\{kb}.msu"
        step = ApplyMsuStep(
            type="apply-msu",
            kb=kb,
            msu_path_in_guest=msu_guest_path,
            expected_exit_codes=[0, 3010],
            timeout_seconds=3600,
        )
        self._step_apply_msu(vmid, step, dry_run)

    # ------------------------------------------------------------------
    # VM lifecycle helpers
    # ------------------------------------------------------------------

    def _full_reboot_cycle(
        self,
        vmid: int,
        iso_name: str,
        dry_run: bool,
        *,
        eject_first: bool = False,
    ) -> None:
        """Shutdown -> wait stopped -> (optionally eject ISO) -> start -> wait agent."""
        self._run(cmd_qm_guest_cmd_shutdown(vmid), dry_run)
        self._wait_stopped(vmid, dry_run)
        if eject_first:
            self._run(cmd_qm_eject_cdrom(vmid), dry_run)
        self._run(cmd_qm_start(vmid), dry_run)
        self._wait_for_agent(vmid, dry_run)

    def _wait_for_agent(self, vmid: int, dry_run: bool) -> None:
        if dry_run:
            print(
                f"[dry-run] (poll) qm guest cmd {vmid} ping  "
                f"until {{}} (timeout {_AGENT_TIMEOUT}s)"
            )
            return
        deadline = time.monotonic() + _AGENT_TIMEOUT
        while time.monotonic() < deadline:
            try:
                # `qm guest cmd <vmid> ping` exits 0 (no exception) when the
                # agent is up — the response is an empty string, NOT "{}".
                # An exit code != 0 means the agent isn't responding yet;
                # subprocess.run raises CalledProcessError, which we swallow.
                self._ssh_output(cmd_qm_guest_ping(vmid))
                return
            except subprocess.CalledProcessError:
                pass
            time.sleep(_POLL_INTERVAL)
        raise TimeoutError(f"Guest agent did not respond within {_AGENT_TIMEOUT}s")

    def _wait_stopped(self, vmid: int, dry_run: bool) -> None:
        if dry_run:
            print(
                f"[dry-run] (poll) qm status {vmid}  "
                f"until status=stopped (timeout {_STOP_TIMEOUT}s)"
            )
            return
        deadline = time.monotonic() + _STOP_TIMEOUT
        while time.monotonic() < deadline:
            out = self._ssh_output(cmd_qm_status(vmid))
            if "stopped" in out:
                return
            time.sleep(_POLL_INTERVAL)
        raise TimeoutError(f"VM {vmid} did not stop within {_STOP_TIMEOUT}s")

    def _pick_vmid(self, *, dry_run: bool) -> int:
        if dry_run:
            vmid = self.config.vmid_range.start
            print(f"[dry-run] Allocated VMID: {vmid}  (first in range {self.config.vmid_range})")
            return vmid
        # Ask Proxmox which VMIDs are in use
        used_raw = self._ssh_output(["qm", "list"])
        used: set[int] = set()
        for line in used_raw.splitlines()[1:]:  # skip header
            parts = line.split()
            if parts:
                try:
                    used.add(int(parts[0]))
                except ValueError:
                    pass
        for vmid in self.config.vmid_range:
            if vmid not in used:
                return vmid
        raise RuntimeError(
            f"No free VMID in range {self.config.vmid_range}"
        )

    def _cleanup(self, vmid: int, iso_path: str, *, dry_run: bool) -> None:
        self._run(cmd_qm_destroy(vmid), dry_run)
        self._run(cmd_rm(iso_path), dry_run)

    # ------------------------------------------------------------------
    # Execution helpers
    # ------------------------------------------------------------------

    def _run(self, host_cmd: list[str], dry_run: bool) -> None:
        """Run *host_cmd* over SSH (or print if dry_run)."""
        full = self._ssh.wrap(host_cmd)
        if dry_run:
            print(f"[dry-run] $ ssh {self._ssh.target} {' '.join(host_cmd)}")
        else:
            log.debug("ssh %s %s", self._ssh.target, " ".join(host_cmd))
            subprocess.run(full, check=True)

    def _run_host(self, cmd: list[str], dry_run: bool) -> None:
        """Run *cmd* locally (for qm set calls that don't need SSH — e.g. on the host itself)."""
        full = self._ssh.wrap(cmd)
        if dry_run:
            print(f"[dry-run] $ ssh {self._ssh.target} {' '.join(cmd)}")
        else:
            log.debug("(host) %s", " ".join(cmd))
            subprocess.run(full, check=True)

    def _ssh_output(self, remote_cmd: list[str]) -> str:
        full = self._ssh.wrap(remote_cmd)
        result = subprocess.run(full, check=True, capture_output=True, text=True)
        return result.stdout

    # ------------------------------------------------------------------
    # ISO helpers
    # ------------------------------------------------------------------

    def _iso_name(self, plan: Plan) -> tuple[str, str]:
        name = _iso_name_for_plan(plan)
        path = f"{ISO_TEMPLATE_DIR}/{name}"
        return name, path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso_name_for_plan(plan: Plan) -> str:
    h_short = plan.content_hash[:12]
    kb = plan.patches[0].kb if plan.patches else "nopatch"
    return f"{plan.task.cve_id}-{kb}-{h_short}.iso"


def _find_task_path(task: TaskRecipe) -> Path:
    """Try to locate the task YAML by convention.  Fallback: current directory."""
    candidates = [
        Path("recipes") / "tasks" / f"{task.cve_id}.yaml",
        Path(f"{task.cve_id}.yaml"),
    ]
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError(
        f"Cannot locate task YAML for {task.cve_id}.  "
        "Pass the path explicitly via build_plan()."
    )
