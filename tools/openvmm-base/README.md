# OpenVMM base image — hands-off bake

Build assets for the golden Windows 11 base that the OpenVMM backend clones for
every run. The whole pipeline is **deterministic and zero-keypress** — no VNC,
no graphics, no "press any key" prompt, no timing hacks. A full bake takes
**~6–7 minutes**.

## Files

| File | Role |
|------|------|
| `autounattend.xml`     | The answer file. Victim is a **standard user** (`<Group>Users</Group>`) so the LPE barrier is real; Administrator autologon; OpenSSH enabled + firewall off; TPM/SecureBoot/RAM checks bypassed (`LabConfig`); ends with `shutdown /s` for auto-capture. No KDNET/debug settings. |
| `make-noprompt-iso.sh` | Re-masters a stock Win11 ISO to boot UEFI **without** the keypress prompt (swaps in `efisys_noprompt.bin`). One-time, cached. |
| `make-answer-iso.sh`   | Wraps `autounattend.xml` in a small data ISO Setup auto-discovers. |
| `build-base.sh`        | Orchestrates: no-prompt ISO → answer ISO → boot OpenVMM unattended → capture. |

## Why a no-prompt ISO

Stock Windows media boots `efi/microsoft/boot/efisys.bin`, which shows
*"Press any key to boot from CD or DVD…"* and, absent a keypress, falls through
to the next boot entry (an empty disk). The media also ships
`efisys_noprompt.bin`, which boots straight into Setup. We re-master the ISO to
use it, so the installer comes up hands-off every time.

(The naive `xorriso -osirrox` in-place extract can yield an empty tree — the
script uses mount + `cp -a`, which is reliable.)

## How completion is detected

`autounattend.xml`'s `FirstLogonCommands` end with `shutdown /s /t 10`. When the
guest powers off, the OpenVMM process exits — that's the "done" signal
(`build-base.sh` waits on the process). Guest *reboots* during Setup don't exit
OpenVMM; only the final power-off does.

Post-install the firmware boots the installed HDD first (Windows Boot Manager is
ordered ahead of the DVD), so the still-attached install ISO does **not** loop
back into Setup — nothing to detach.

## Usage

```bash
export STOCK_ISO=/path/to/Win11_22H2.iso
export NDAYBENCH_OPENVMM_BINARY=/root/openvmm-phase5/target/release/openvmm
export NDAYBENCH_UEFI_FIRMWARE=/root/openvmm/.packages/.../MSVM.fd
sudo -E ./build-base.sh
```

Output lands at `$NDB_ROOT/images/ndaybench-win11-22h2-base-clean-<stamp>.img`
(default `NDB_ROOT=/root/openvmm-ndb`). Point the runtime at it via
`GOLDEN_BASE` / `OpenVmmConfig(golden_base=...)`.

> Host layout: all bake artifacts live under `/root/openvmm-ndb/`, kept separate
> from `/root/ndaybench` (the main-branch checkout). See `src/ndaybench/openvmm.py`.

## Not done here (future per-task customization)

KDNET for WinDbg is intentionally **out** of the base — when we add it, it'll be
a per-task customization over serial/vmbus transport (no network adapter), not
baked into the golden image.
