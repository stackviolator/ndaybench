"""OpenVMM VM lifecycle for ndaybench runs (gRPC vmservice backend).

The OpenVMM-backed replacement for the Proxmox/qemu backend (``vm.py``).  It
drives Microsoft's upstream OpenVMM via its **gRPC vmservice control API**, with
**systemd** as the session/process supervisor and a **dedicated tap** for guest
networking.  Architecture proven empirically on the p620 host (2026-05-29):

* **Process / session** -- each VM is one ``openvmm --grpc <unix-sock>`` process
  run as a transient **systemd unit** ``ndb-<run_id>.service``.  systemd is the
  session registry the vmservice API lacks (list/status/stop by name, survives
  client disconnect, journald logs, no pty -- grpc mode has no repl).

* **Control** -- the base, upstream vmservice RPCs only:
  ``CreateVM`` (creates *paused*) / ``ResumeVM`` (boots) / ``PauseVM`` /
  ``TeardownVM`` (destroys the VM but keeps the process, so a later ``CreateVM``
  starts clean) / ``Quit`` (kills the process).  We deliberately do **not** use
  the co-tenant's uncommitted ``SaveSnapshot``/``AddDisk`` RPC additions.

* **Transport** -- the grpc socket is a unix socket on the host and the host's
  sshd forbids stream-local forwarding, so we bridge it: ``socat`` unix->TCP on
  the host + a standard ``ssh -L`` TCP forward, then a local grpc channel.

* **Disk** -- the gRPC disk path takes a monolithic file (no ``sqldiff``
  overlay), and ``/root`` is ext4 (no reflink), so each run gets a **full copy**
  of the read-only golden base.  That also makes snapshots trivial and
  bulletproof: an independent disk file.

* **Networking** -- a dedicated tap (``tap_ndb`` / ``192.168.252.0/24``) with
  dnsmasq DHCP + scoped MASQUERADE, isolated from the ntbench co-tenant
  (``tap_ovmm`` / 192.168.251.x).  Each VM gets a deterministic MAC so its DHCP
  lease is matched unambiguously (no guessing; concurrency-safe).  The guest is
  reached by its lease IP over SSH (consomme inbound hostfwd is broken here).

* **Snapshot / restore** -- disk-file based: ``TeardownVM`` (flushes+releases the
  disk, process stays up) -> copy the disk file -> ``CreateVM``+``ResumeVM``.
  Same semantics as the old Proxmox ``--vmstate 0`` (disk state only).

Isolation: per-run systemd unit, socket, disk, tap MAC, grpc + vnc ports; we
never broad-``pkill openvmm`` (that would kill ntbench) -- only our unit / pid.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import shlex
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

import grpc
from google.protobuf import empty_pb2

from ._vmservice import vmservice_pb2 as pb
from ._vmservice import vmservice_pb2_grpc as pbg


def utcnow_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


class OpenVmmError(RuntimeError):
    pass


# The golden base built once on ext4; seeded into the CoW mount on first use.
GOLDEN_BASE = (
    "/root/ndaybench/openvmm/images/ndaybench-win11-22h2-ent-base-20260529.img"
)
DEFAULT_UEFI_FD = (
    "/root/openvmm/.packages/hyperv.uefi.mscoreuefi.x64.RELEASE"
    "/MsvmX64/RELEASE_VS2022/FV/MSVM.fd"
)
# CoW root: an XFS-reflink loopback (ext4 has no reflink).  base image + all
# per-run disks + snapshots live here so cloning is an instant block-shared
# `cp --reflink`.  Self-contained (one file on ext4), isolated from co-tenants.
COW_MNT = "/root/ndaybench/openvmm/cow"
COW_FILE = "/root/ndaybench/openvmm/cow.xfs"
COW_SIZE = "400G"


@dataclass(frozen=True)
class OpenVmmConfig:
    host: str = "p620-1"
    ssh_user: str = "root"
    # phase5 fork binary: adds memory_backing_file + SaveSnapshot/RestoreSnapshot
    # over the gRPC API (enables resume-from-memory fast restore, no reboot).
    ovmm_bin: str = "/root/openvmm-phase5/target/release/openvmm"
    uefi_fd: str = DEFAULT_UEFI_FD
    golden_base: str = GOLDEN_BASE
    cow_mnt: str = COW_MNT
    cow_file: str = COW_FILE
    cow_size: str = COW_SIZE
    # one bridge shared by all runs; each VM gets its own tap enslaved to it
    # (a tap attaches to only one VM, so concurrent VMs need separate taps).
    bridge: str = "br_ndb"
    subnet: str = "192.168.252"
    dhcp_lo: int = 50
    dhcp_hi: int = 100
    leases_file: str = "/var/lib/misc/dnsmasq.leases"
    guest_user: str = "Administrator"
    guest_password: str = "password"
    ssh_opts: tuple[str, ...] = (
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
    )

    @property
    def base_image(self) -> str:
        """The base image inside the CoW mount (reflink source for run disks)."""
        return f"{self.cow_mnt}/base.img"

    @property
    def work_dir(self) -> str:
        return f"{self.cow_mnt}/runs"

    @property
    def host_ip(self) -> str:
        return f"{self.subnet}.1"

    def _ssh_base(self) -> list[str]:
        return ["ssh", *self.ssh_opts, f"{self.ssh_user}@{self.host}"]


@dataclass
class OpenVmmVm:
    run_id: str
    unit: str                 # systemd transient unit name
    rsock: str                # grpc unix socket path on host
    grpc_port: int            # host socat TCP port == local forwarded port
    disk: str                 # per-run disk image on host
    snapshot_dir: str
    mem_file: str             # file-backed guest RAM (required for mem snapshots)
    mac: str                  # "00-15-5d-52-xx-yy"
    tap: str                  # per-run tap device enslaved to the bridge
    vnc_port: int
    memory_mb: int = 4096
    cores: int = 4
    ip: str | None = None
    snapshot_name: str | None = None
    _fwd: subprocess.Popen | None = field(default=None, repr=False)

    @property
    def mac_colon(self) -> str:
        return self.mac.replace("-", ":").lower()


@dataclass
class OpenVmmClient:
    config: OpenVmmConfig = field(default_factory=OpenVmmConfig)

    # --- host plumbing ----------------------------------------------------

    def _host_run(self, cmd: str, *, timeout: int = 60, check: bool = True):
        proc = subprocess.run(
            [*self.config._ssh_base(), cmd],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if check and proc.returncode != 0:
            raise OpenVmmError(
                f"host cmd failed (rc={proc.returncode}): {cmd!r}\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
            )
        return proc

    def _host_script(self, script: str, *, timeout: int = 180, check: bool = True):
        proc = subprocess.run(
            [*self.config._ssh_base(), "bash", "-s"],
            input=script, capture_output=True, text=True, timeout=timeout, check=False,
        )
        if check and proc.returncode != 0:
            raise OpenVmmError(
                f"host script failed (rc={proc.returncode})\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
            )
        return proc

    # --- network ----------------------------------------------------------

    def ensure_network(self) -> None:
        """Idempotently bring up the shared bridge + dnsmasq + scoped NAT.

        Per-run taps are created in ``spawn`` and enslaved to this bridge, so
        many VMs share one subnet/dnsmasq while each owns its own tap device.
        """
        c = self.config
        self._host_script(f"""
set -euo pipefail
BR={shlex.quote(c.bridge)}; SUB={shlex.quote(c.subnet)}; HOSTIP={shlex.quote(c.host_ip)}
ip link show "$BR" >/dev/null 2>&1 || ip link add name "$BR" type bridge
ip addr replace "$HOSTIP"/24 dev "$BR"; ip link set "$BR" up
pgrep -f "dnsmasq.*$BR" >/dev/null 2>&1 || \
  ( nohup dnsmasq --interface="$BR" --bind-interfaces \
      --dhcp-range="$SUB".{c.dhcp_lo},"$SUB".{c.dhcp_hi},255.255.255.0,12h \
      --listen-address="$HOSTIP" --no-resolv --port=0 \
      >/tmp/dnsmasq-ndb.log 2>&1 & disown )
sysctl -q -w net.ipv4.ip_forward=1
iptables -t nat -C POSTROUTING -s "$SUB".0/24 -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "$SUB".0/24 -j MASQUERADE
""", timeout=30)

    def _ensure_tap(self, vm: OpenVmmVm) -> None:
        """Create this run's tap and enslave it to the shared bridge."""
        c = self.config
        self._host_script(
            f"set -e; ip link show {shlex.quote(vm.tap)} >/dev/null 2>&1 || "
            f"ip tuntap add dev {shlex.quote(vm.tap)} mode tap; "
            f"ip link set {shlex.quote(vm.tap)} master {shlex.quote(c.bridge)}; "
            f"ip link set {shlex.quote(vm.tap)} up",
            timeout=20,
        )

    # --- storage (XFS-reflink CoW loopback) -------------------------------

    def ensure_storage(self) -> None:
        """Idempotently mount the XFS-reflink CoW loopback and seed the base image.

        ext4 has no reflink, so per-run disks would each be a 25s/13GB full copy.
        We keep a single XFS-reflink loopback file and put base + runs + snapshots
        inside it, making every clone an instant, block-shared ``cp --reflink``.
        """
        c = self.config
        self._host_script(f"""
set -euo pipefail
F={shlex.quote(c.cow_file)}; M={shlex.quote(c.cow_mnt)}
mkdir -p "$M"
if ! mountpoint -q "$M"; then
  if [ ! -f "$F" ]; then
    truncate -s {shlex.quote(c.cow_size)} "$F"
    mkfs.xfs -m reflink=1 -q "$F"
  fi
  mount -o loop "$F" "$M"
fi
mkdir -p "$M"/runs
# seed the golden base into the CoW fs (reflink source must share the fs)
if [ ! -f {shlex.quote(c.base_image)} ]; then
  cp --sparse=always {shlex.quote(c.golden_base)} {shlex.quote(c.base_image)}
fi
""", timeout=120)

    # --- grpc transport ---------------------------------------------------

    @contextmanager
    def _stub(self, vm: OpenVmmVm, *, ready_timeout: int = 10):
        ch = grpc.insecure_channel(f"127.0.0.1:{vm.grpc_port}")
        try:
            grpc.channel_ready_future(ch).result(timeout=ready_timeout)
            yield pbg.VMStub(ch)
        finally:
            ch.close()

    def _bring_up_process(self, vm: OpenVmmVm) -> None:
        """Start the openvmm grpc server (systemd unit) + socat bridge + ssh -L."""
        c = self.config
        self._host_script(f"""
set -e
systemctl stop {shlex.quote(vm.unit)} 2>/dev/null || true
systemctl reset-failed {shlex.quote(vm.unit)} 2>/dev/null || true
pkill -f "socat.*TCP-LISTEN:{vm.grpc_port}," 2>/dev/null || true
rm -f {shlex.quote(vm.rsock)}
systemd-run --unit={shlex.quote(vm.unit)} --collect \
  {shlex.quote(c.ovmm_bin)} --grpc {shlex.quote(vm.rsock)} --hv
for i in $(seq 1 20); do [ -S {shlex.quote(vm.rsock)} ] && break; sleep 0.5; done
nohup socat TCP-LISTEN:{vm.grpc_port},reuseaddr,fork,bind=127.0.0.1 \
  UNIX-CONNECT:{shlex.quote(vm.rsock)} >/tmp/socat-{vm.run_id}.log 2>&1 & disown
sleep 1
""", timeout=40)
        # local TCP forward (kill any stale forward holding this port first, so
        # an orphan from a crashed prior run can't block the bind)
        if vm._fwd is not None:
            vm._fwd.terminate()
        subprocess.run(["pkill", "-f", f"ssh.*-L 127.0.0.1:{vm.grpc_port}:"],
                       capture_output=True)
        time.sleep(0.5)
        vm._fwd = subprocess.Popen(
            [*c._ssh_base()[:-1], "-N", "-T",
             "-L", f"127.0.0.1:{vm.grpc_port}:127.0.0.1:{vm.grpc_port}",
             f"{c.ssh_user}@{c.host}"]
        )
        time.sleep(3)

    def _teardown_process(self, vm: OpenVmmVm) -> None:
        if vm._fwd is not None:
            vm._fwd.terminate()
            vm._fwd = None
        self._host_script(
            f"pkill -f 'socat.*TCP-LISTEN:{vm.grpc_port},' 2>/dev/null || true; "
            f"systemctl stop {shlex.quote(vm.unit)} 2>/dev/null || true; "
            f"systemctl reset-failed {shlex.quote(vm.unit)} 2>/dev/null || true; "
            f"rm -f {shlex.quote(vm.rsock)}",
            timeout=40, check=False,
        )

    # --- vm config --------------------------------------------------------

    def _vm_config(self, vm: OpenVmmVm) -> pb.VMConfig:
        c = self.config
        return pb.VMConfig(
            memory_config=pb.MemoryConfig(memory_mb=vm.memory_mb),
            processor_config=pb.ProcessorConfig(processor_count=vm.cores),
            uefi=pb.UEFI(firmware_path=c.uefi_fd),
            # file-backed RAM on the CoW mount → enables SaveSnapshot and makes
            # memory.bin an instant hardlink/reflink on the same filesystem.
            memory_backing_file=vm.mem_file,
            devices_config=pb.DevicesConfig(
                scsi_disks=[pb.SCSIDisk(
                    controller=0, lun=0, host_path=vm.disk,
                    type=pb.SCSI_DISK_TYPE_VHD1)],
                nic_config=[pb.NICConfig(
                    nic_id="00000000-0000-0000-0000-0000000000db",
                    mac_address=vm.mac,
                    tap=pb.TapBackend(name=vm.tap))],
            ),
        )

    def _create_and_boot(self, vm: OpenVmmVm, *, lease_timeout: int = 120,
                         ssh_timeout: int = 180) -> None:
        with self._stub(vm) as stub:
            stub.CreateVM(pb.CreateVMRequest(config=self._vm_config(vm), log_id=vm.run_id),
                          timeout=30)
            stub.ResumeVM(empty_pb2.Empty(), timeout=30)
        vm.ip = self._wait_lease(vm, timeout=lease_timeout)
        self.wait_ssh(vm, timeout=ssh_timeout)

    # --- lifecycle --------------------------------------------------------

    def spawn(self, run_id: str, *, source: str | None = None,
              memory_mb: int = 4096, cores: int = 4,
              grpc_port: int = 18060, vnc_port: int = 5930,
              lease_timeout: int = 120, ssh_timeout: int = 180) -> OpenVmmVm:
        """Boot a fresh VM whose disk is an instant reflink clone of *source*.

        *source* defaults to the golden base.  Pass a snapshot's disk path
        (``snapshot_path(...)``) to stamp out many parallel VMs from one golden
        point -- each clone is instant and block-shared (the sweep pattern).
        """
        c = self.config
        src = source or c.base_image
        vm = OpenVmmVm(
            run_id=run_id, unit=f"ndb-{run_id}", rsock=f"/tmp/ndb-{run_id}.sock",
            grpc_port=grpc_port, disk=f"{c.work_dir}/{run_id}.img",
            snapshot_dir=f"{c.work_dir}/{run_id}.snapshots",
            mem_file=f"{c.work_dir}/{run_id}.mem",
            mac=self._mac_for(run_id), tap=self._tap_for(run_id), vnc_port=vnc_port,
            memory_mb=memory_mb, cores=cores,
        )
        self.ensure_network()
        self._ensure_tap(vm)
        self.ensure_storage()
        self._host_script(
            f"set -e; mkdir -p {shlex.quote(vm.snapshot_dir)}; "
            # instant block-shared CoW clone (XFS reflink)
            f"cp --reflink=always {shlex.quote(src)} {shlex.quote(vm.disk)}",
            timeout=120,
        )
        self._bring_up_process(vm)
        self._create_and_boot(vm, lease_timeout=lease_timeout, ssh_timeout=ssh_timeout)
        return vm

    def start(self, vm: OpenVmmVm, *, ssh_timeout: int = 180) -> None:
        """(Re)start a previously-stopped VM from its existing disk."""
        self.ensure_network()
        self._ensure_tap(vm)
        self._bring_up_process(vm)
        self._create_and_boot(vm, ssh_timeout=ssh_timeout)

    def stop(self, vm: OpenVmmVm, *, graceful: bool = True, timeout: int = 60) -> None:
        """Power off the guest and shut down the grpc process + supervisor."""
        if graceful and vm.ip:
            self.guest_exec(vm, "shutdown /s /t 0", timeout=20, check=False)
            time.sleep(5)
        try:
            with self._stub(vm, ready_timeout=5) as stub:
                stub.Quit(empty_pb2.Empty(), timeout=10)
        except Exception:  # noqa: BLE001  -- process may already be gone
            pass
        self._teardown_process(vm)

    def reboot(self, vm: OpenVmmVm, *, ssh_timeout: int = 180) -> None:
        """Power-cycle the guest (clean shutdown + fresh boot)."""
        self._quiesce(vm)
        self.start(vm, ssh_timeout=ssh_timeout)

    def _quiesce(self, vm: OpenVmmVm, *, halt_timeout: int = 120) -> None:
        """Cleanly power off the guest and stop the grpc process, releasing the disk.

        TeardownVM stalls on this build, so instead we shut the guest down from
        inside (Windows flushes), wait for it to halt, then stop the openvmm
        process (which closes the disk file).  Once the guest is off, the disk
        file is consistent and safe to copy.
        """
        if vm.ip:
            self.guest_exec(vm, "shutdown /s /t 0", timeout=20, check=False)
            self._wait_halted(vm, timeout=halt_timeout)
        self._teardown_process(vm)

    def _wait_halted(self, vm: OpenVmmVm, *, timeout: int) -> None:
        """Block until the guest stops answering SSH (powered off)."""
        if not vm.ip:
            return
        deadline = time.monotonic() + timeout
        fails = 0
        while time.monotonic() < deadline:
            fails = 0 if self._guest_ssh_ok(vm.ip) else fails + 1
            if fails >= 2:  # two consecutive misses == halted
                return
            time.sleep(5)

    def destroy(self, vm: OpenVmmVm) -> None:
        self.stop(vm, graceful=False)
        self._host_script(
            f"ip link del {shlex.quote(vm.tap)} 2>/dev/null || true; "
            f"rm -f {shlex.quote(vm.disk)} {shlex.quote(vm.mem_file)} "
            f"/tmp/socat-{vm.run_id}.log; "
            f"rm -rf {shlex.quote(vm.snapshot_dir)}",
            timeout=60, check=False,
        )

    # --- snapshot / restore (disk-file based) -----------------------------

    def snapshot(self, vm: OpenVmmVm, name: str) -> None:
        """Fast live snapshot: pause vCPUs, flush, reflink-clone the disk, resume.

        PauseVM stops the guest, ``sync`` flushes openvmm's buffered writes to the
        on-disk extents, and an XFS reflink clone captures them instantly
        (block-shared).  ResumeVM continues -- no reboot.  The snapshot is
        crash-consistent (NTFS is journaled); for ndaybench we snapshot the idle
        post-boot guest, so it's effectively clean.  ~a few seconds vs ~110s.
        """
        snap = self._snap_path(vm, name)
        # Flush the guest's NTFS write-back cache to the virtual disk first, so
        # recent in-guest writes are on-disk before we pause (host `sync` only
        # flushes openvmm's own buffer, not the guest's).
        if vm.ip:
            self.guest_powershell(vm, "Write-VolumeCache -DriveLetter C", check=False)
        with self._stub(vm) as stub:
            stub.PauseVM(empty_pb2.Empty(), timeout=30)
            try:
                self._host_script(
                    f"set -e; mkdir -p {shlex.quote(vm.snapshot_dir)}; sync; "
                    f"cp --reflink=always {shlex.quote(vm.disk)} {shlex.quote(snap)}",
                    timeout=60,
                )
            finally:
                stub.ResumeVM(empty_pb2.Empty(), timeout=30)
        vm.snapshot_name = name

    def restore(self, vm: OpenVmmVm, name: str, *, ssh_timeout: int = 180) -> None:
        """Restore disk to a snapshot: quiesce, reflink the snapshot back, re-boot.

        Restore needs the disk released (openvmm holds it) and the guest's memory
        is gone, so this is a clean stop + instant reflink swap + fresh boot.
        """
        snap = self._snap_path(vm, name)
        self._quiesce(vm)
        self._host_script(
            f"set -e; test -f {shlex.quote(snap)}; rm -f {shlex.quote(vm.disk)}; "
            f"cp --reflink=always {shlex.quote(snap)} {shlex.quote(vm.disk)}",
            timeout=120,
        )
        self.start(vm, ssh_timeout=ssh_timeout)

    def _snap_path(self, vm: OpenVmmVm, name: str) -> str:
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in name)
        return f"{vm.snapshot_dir}/{safe}.img"

    def snapshot_path(self, vm: OpenVmmVm, name: str) -> str:
        """Disk path of a snapshot -- pass to ``spawn(source=...)`` to duplicate it."""
        return self._snap_path(vm, name)

    # --- lease + guest exec ----------------------------------------------

    def _mac_for(self, run_id: str) -> str:
        h = hashlib.sha256(run_id.encode()).digest()
        return f"00-15-5d-52-{h[0]:02x}-{h[1]:02x}"

    def _tap_for(self, run_id: str) -> str:
        # IFNAMSIZ caps device names at 15 chars; keep it short + unique.
        h = hashlib.sha256(run_id.encode()).hexdigest()[:8]
        return f"ndb{h}"

    def _wait_lease(self, vm: OpenVmmVm, *, timeout: int, verify: bool = True) -> str:
        """Return the guest's current IP for our MAC.

        The lease file can hold MORE than one entry for a MAC (a stale pre-restore
        lease plus a fresh one after the guest re-DHCPs when netvsc re-inits on
        restore).  So take the *freshest* (highest dnsmasq expiry, field 1) and,
        when ``verify``, only return an IP that actually answers SSH -- never a
        stale address.  This is the bug that made fast-restore look broken.
        """
        c = self.config
        deadline = time.monotonic() + timeout
        last_seen: list[str] = []
        while time.monotonic() < deadline:
            # all IPs for our MAC, freshest expiry first
            out = self._host_run(
                f"awk '$2==\"{vm.mac_colon}\" {{print $1, $3}}' {shlex.quote(c.leases_file)} "
                f"2>/dev/null | sort -rn | awk '{{print $2}}'", check=False,
            ).stdout
            ips = [ln.strip() for ln in out.splitlines() if ln.strip()]
            last_seen = ips
            for ip in ips:
                if not verify or self._guest_ssh_ok(ip):
                    return ip
            time.sleep(4)
        raise OpenVmmError(
            f"VM {vm.run_id}: no SSH-reachable lease for {vm.mac} in {timeout}s "
            f"(leases seen: {last_seen or 'none'})"
        )

    def _guest_ssh_cmd(self, ip: str, remote: str) -> str:
        c = self.config
        return (
            f"sshpass -p {shlex.quote(c.guest_password)} "
            f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-o LogLevel=ERROR -o ConnectTimeout=10 "
            f"-o PreferredAuthentications=password -o PubkeyAuthentication=no "
            f"{shlex.quote(c.guest_user)}@{ip} {shlex.quote(remote)}"
        )

    def _guest_ssh_ok(self, ip: str) -> bool:
        """True if the guest answers SSH; a hang/timeout counts as not-up."""
        try:
            return self._host_run(self._guest_ssh_cmd(ip, "exit 0"),
                                  timeout=25, check=False).returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def wait_ssh(self, vm: OpenVmmVm, *, timeout: int = 180) -> None:
        if not vm.ip:
            raise OpenVmmError("vm has no IP")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._guest_ssh_ok(vm.ip):
                return
            time.sleep(4)
        raise OpenVmmError(f"SSH to {vm.ip} never came up in {timeout}s")

    def guest_exec(self, vm: OpenVmmVm, cmd: str, *, timeout: int = 60,
                   check: bool = True) -> dict[str, object]:
        if not vm.ip:
            raise OpenVmmError("vm has no IP")
        proc = self._host_run(self._guest_ssh_cmd(vm.ip, cmd),
                              timeout=timeout + 20, check=check)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "exit_code": proc.returncode}

    def guest_powershell(self, vm: OpenVmmVm, script: str, *, timeout: int = 60,
                         check: bool = True) -> dict[str, object]:
        enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        return self.guest_exec(vm, f"powershell -NoProfile -EncodedCommand {enc}",
                               timeout=timeout, check=check)


# ---------------------------------------------------------------------------
# Smoke: start -> run -> snapshot -> restore -> stop on the live host
# ---------------------------------------------------------------------------


def _smoke(run_id: str = "smoke") -> int:
    client = OpenVmmClient()
    vm = None
    try:
        print(f"[spawn] {run_id} ...")
        vm = client.spawn(run_id, grpc_port=18061, vnc_port=5932)
        print(f"[spawn] up ip={vm.ip} mac={vm.mac} unit={vm.unit}")

        r = client.guest_exec(vm, "hostname; whoami")
        print(f"[run]   {r['stdout'].strip()!r} rc={r['exit_code']}")

        marker = f"C:\\ndb-{run_id}.txt"
        client.guest_powershell(vm, f"Set-Content -Path '{marker}' -Value 'before'")
        print("[snap]  snapshot 'pre' ...")
        client.snapshot(vm, "pre")
        client.guest_powershell(vm, f"Remove-Item -Force '{marker}'")
        gone = client.guest_powershell(vm, f"Test-Path '{marker}'")
        print(f"[snap]  marker after delete: {gone['stdout'].strip()!r} (expect False)")

        print("[rest]  restore 'pre' ...")
        client.restore(vm, "pre")
        read = f"Get-Content '{marker}' -EA SilentlyContinue"
        back = client.guest_powershell(vm, read, check=False)
        print(f"[rest]  marker after restore: {back['stdout'].strip()!r} (expect 'before')")

        # duplicate: clone the 'pre' snapshot into a second, concurrent VM
        print("[dup]   spawning a 2nd VM from the 'pre' snapshot (reflink clone) ...")
        dup = client.spawn(f"{run_id}-dup", source=client.snapshot_path(vm, "pre"),
                           grpc_port=18062, vnc_port=5933)
        dmark = client.guest_powershell(dup, read, check=False)
        print(f"[dup]   clone ip={dup.ip}; marker on clone: {dmark['stdout'].strip()!r} "
              "(expect 'before' -- inherited from snapshot)")
        client.destroy(dup)

        print("[stop]  graceful stop ...")
        client.stop(vm, graceful=True)
        print("[stop]  done")
        return 0
    finally:
        if vm is not None:
            print("[teardown] destroy")
            client.destroy(vm)


if __name__ == "__main__":
    import sys
    raise SystemExit(_smoke(*(sys.argv[1:2] or ["smoke"])))
