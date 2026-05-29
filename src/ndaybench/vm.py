"""Proxmox VM lifecycle for ndaybench runs.

A `ProxmoxClient` shells out to `ssh root@<host> qm ...` and exposes the
subset of operations the runner needs: spawn a clone from a cached raw image,
attach a secrets ISO, configure a static IP via guest agent, snapshot, revert,
reboot, destroy.

We chain SSH to the guest via the Proxmox host using `sshpass` (vmbr1000 is
not routable from outside p620).
"""

from __future__ import annotations

import datetime as dt
import json
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


def utcnow_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


class VmError(RuntimeError):
    pass


@dataclass
class ProxmoxClient:
    host: str = "p620-1"
    storage: str = "local"
    bridge: str = "vmbr1000"
    cache_dir: str = "/root/ndaybench/cache"
    iso_dir: str = "/var/lib/vz/template/iso"
    ssh_opts: tuple[str, ...] = (
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
    )

    def _ssh_argv(self, remote_cmd: str) -> list[str]:
        return ["ssh", *self.ssh_opts, f"root@{self.host}", remote_cmd]

    def run(
        self, remote_cmd: str, *, timeout: int = 60, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        proc = subprocess.run(
            self._ssh_argv(remote_cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if check and proc.returncode != 0:
            raise VmError(
                f"proxmox cmd failed (rc={proc.returncode}): {remote_cmd!r}\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
            )
        return proc

    # --- inventory / status -----------------------------------------------

    def status(self, vmid: int) -> str:
        out = self.run(f"qm status {vmid}", check=False).stdout.strip()
        return out.split(":", 1)[1].strip() if ":" in out else out

    def exists(self, vmid: int) -> bool:
        return self.run(f"qm status {vmid}", check=False).returncode == 0

    def next_free_vmid(self, lo: int = 9200, hi: int = 9499) -> int:
        out = self.run("qm list", check=False).stdout
        taken = set()
        for line in out.splitlines()[1:]:
            parts = line.split()
            if parts and parts[0].isdigit():
                taken.add(int(parts[0]))
        for v in range(lo, hi + 1):
            if v not in taken:
                return v
        raise VmError(f"no free VMID in [{lo},{hi}]")

    # --- spawn / destroy --------------------------------------------------

    def upload_iso(self, local_path: Path, remote_name: str) -> str:
        """Upload an ISO to the Proxmox iso storage and return its full remote path."""
        remote_path = f"{self.iso_dir}/{remote_name}"
        subprocess.run(
            ["scp", *self.ssh_opts, str(local_path), f"root@{self.host}:{remote_path}"],
            check=True,
            capture_output=True,
        )
        return remote_path

    def build_secrets_iso(
        self, *, flag: str, password: str, profile: str, iso_name: str
    ) -> str:
        """Build a per-run secrets ISO on the Proxmox host.

        Returns the full remote path.  Uses genisoimage on the host so we don't
        depend on mkisofs being installed locally (macOS doesn't ship it).
        """
        remote_path = f"{self.iso_dir}/{iso_name}"
        payload = {"flag": flag, "password": password, "profile": profile}
        # Hand the secrets to a small Python one-liner over stdin to avoid
        # any quoting headaches with arbitrary password bytes.
        py = (
            "import json,sys,os,subprocess,tempfile; "
            "d=json.loads(sys.stdin.read()); "
            "td=tempfile.mkdtemp(); "
            "open(td+'/NDAYBENCH-SECRETS','w').write('v1\\n'); "
            "open(td+'/flag.txt','w').write(d['flag']); "
            "open(td+'/password.txt','w').write(d['password']); "
            "open(td+'/profile.txt','w').write(d['profile']); "
            f"subprocess.run(['genisoimage','-quiet','-o',{remote_path!r},"
            "'-V','NDAYBENCH','-J','-r',td], check=True); "
            "import shutil; shutil.rmtree(td)"
        )
        proc = subprocess.run(
            self._ssh_argv(f"python3 -c {shlex.quote(py)}"),
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if proc.returncode != 0:
            raise VmError(
                f"build_secrets_iso failed (rc={proc.returncode})\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
            )
        return remote_path

    def remove_iso(self, remote_name: str) -> None:
        self.run(f"rm -f {shlex.quote(f'{self.iso_dir}/{remote_name}')}", check=False)

    def spawn_from_cache(
        self,
        *,
        vmid: int,
        name: str,
        cache_image_sha: str,
        secrets_iso_name: str,
        memory_mb: int = 4096,
        cores: int = 2,
    ) -> None:
        """Create + start a VM whose virtio0 is a qcow2 overlay backed by a cached raw."""
        backing = f"{self.cache_dir}/{cache_image_sha}.raw"
        overlay_dir = f"/var/lib/vz/images/{vmid}"
        overlay_path = f"{overlay_dir}/vm-{vmid}-disk-overlay.qcow2"
        script = "; ".join(
            [
                # Create VM shell
                f"qm create {vmid} --name {shlex.quote(name)} "
                f"--memory {memory_mb} --cores {cores} --cpu host --kvm 1 "
                f"--bios ovmf --machine pc-i440fx-9.2+pve1 "
                f"--ostype win11 --scsihw virtio-scsi-single --agent 1 "
                f"--net0 virtio,bridge={self.bridge} "
                f"--efidisk0 {self.storage}:1,efitype=4m,pre-enrolled-keys=0,format=qcow2",
                # Overlay disk
                f"mkdir -p {overlay_dir}",
                f"qemu-img create -f qcow2 -F raw -b {backing} {overlay_path}",
                f"qm set {vmid} --virtio0 "
                f"{self.storage}:{vmid}/vm-{vmid}-disk-overlay.qcow2,"
                f"cache=none,discard=on,iothread=1",
                # Secrets ISO
                f"qm set {vmid} --ide0 "
                f"{self.storage}:iso/{secrets_iso_name},media=cdrom",
                # Boot order
                f"qm set {vmid} --boot order=virtio0\\;ide0\\;net0",
                # Start
                f"qm start {vmid}",
            ]
        )
        self.run(script, timeout=120)

    def destroy(self, vmid: int) -> None:
        self.run(f"qm stop {vmid}", check=False, timeout=60)
        # qm wait for stopped (best-effort)
        for _ in range(15):
            if self.status(vmid) == "stopped" or not self.exists(vmid):
                break
            time.sleep(1)
        self.run(f"qm destroy {vmid} --purge", check=False, timeout=120)

    # --- lifecycle controls ----------------------------------------------

    def stop(self, vmid: int) -> None:
        self.run(f"qm stop {vmid}", check=False, timeout=60)

    def start(self, vmid: int) -> None:
        self.run(f"qm start {vmid}", timeout=60)

    def reboot(self, vmid: int) -> None:
        """Power-cycle via qm shutdown (graceful, falls back to stop)."""
        self.run(f"qm shutdown {vmid} --timeout 30", check=False, timeout=60)
        for _ in range(20):
            if self.status(vmid) == "stopped":
                break
            time.sleep(2)
        else:
            self.stop(vmid)
            time.sleep(2)
        self.start(vmid)

    def snapshot(self, vmid: int, name: str) -> None:
        self.run(f"qm snapshot {vmid} {shlex.quote(name)} --vmstate 0", timeout=120)

    def rollback(self, vmid: int, name: str) -> None:
        # vmstate=0 snapshots cannot be rolled back into a running VM —
        # stop first, rollback, then start.
        if self.status(vmid) != "stopped":
            self.run(f"qm stop {vmid}", check=False, timeout=60)
            for _ in range(20):
                if self.status(vmid) == "stopped":
                    break
                time.sleep(1)
        self.run(f"qm rollback {vmid} {shlex.quote(name)} --start 1", timeout=180)

    # --- guest agent -----------------------------------------------------

    def wait_guest_agent(self, vmid: int, *, timeout: int = 180) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.run(f"qm guest cmd {vmid} ping", check=False, timeout=10).returncode == 0:
                return
            time.sleep(3)
        raise VmError(f"VM {vmid} guest agent did not come up in {timeout}s")

    def guest_exec(
        self, vmid: int, argv: list[str], *, timeout: int = 60
    ) -> dict:
        """Run a command in the guest via QEMU guest agent.  Returns parsed JSON."""
        quoted = " ".join(shlex.quote(a) for a in argv)
        proc = self.run(
            f"qm guest exec --timeout {timeout} {vmid} -- {quoted}",
            timeout=timeout + 30,
        )
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise VmError(f"guest-exec returned non-JSON: {proc.stdout!r}") from exc

    def configure_static_ip(
        self,
        vmid: int,
        *,
        ip: str,
        prefix: int = 24,
        gateway: str,
        interface: str = "Ethernet",
    ) -> None:
        mask = _prefix_to_mask(prefix)
        ps = (
            f"netsh interface ip set address name='{interface}' static {ip} {mask} {gateway}; "
            f"netsh interface ip set dns name='{interface}' static {gateway}"
        )
        self.guest_exec(vmid, ["powershell.exe", "-NoProfile", "-Command", ps], timeout=30)


# --- standalone VM SSH (chained via Proxmox host) ---------------------------


@dataclass
class GuestSsh:
    """SSH into a Windows guest via Proxmox host (vmbr1000 isn't routable)."""

    proxmox: ProxmoxClient
    vm_ip: str
    user: str = "agent"
    password: str = ""

    def exec(self, cmd: str, *, timeout: int = 60) -> dict[str, object]:
        inner = (
            f"sshpass -p {shlex.quote(self.password)} "
            f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o LogLevel=ERROR -o ConnectTimeout=10 "
            f"{shlex.quote(self.user)}@{self.vm_ip} {shlex.quote(cmd)}"
        )
        proc = subprocess.run(
            self.proxmox._ssh_argv(inner),
            capture_output=True,
            text=True,
            timeout=timeout + 15,
            check=False,
        )
        return {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "exit_code": proc.returncode,
        }

    def wait_ready(self, *, timeout: int = 120) -> None:
        deadline = time.monotonic() + timeout
        last_err = ""
        while time.monotonic() < deadline:
            r = self.exec("whoami", timeout=15)
            if r["exit_code"] == 0:
                return
            last_err = str(r.get("stderr") or "")
            time.sleep(3)
        raise VmError(f"SSH to {self.vm_ip} never came up in {timeout}s; last err: {last_err}")


def _prefix_to_mask(prefix: int) -> str:
    bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return ".".join(str((bits >> (8 * i)) & 0xFF) for i in (3, 2, 1, 0))
