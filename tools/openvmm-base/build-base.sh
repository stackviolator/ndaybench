#!/usr/bin/env bash
# Bake the golden Windows 11 base image on OpenVMM, fully hands-off (~6-7 min).
#
# Pipeline (each step is idempotent — re-mastered ISOs are cached and reused):
#   1. Re-master the stock Win11 ISO to a no-prompt UEFI boot ISO.
#   2. Build the autounattend answer ISO from autounattend.xml.
#   3. Boot OpenVMM with: empty target disk + no-prompt Win11 ISO (DVD) +
#      answer ISO (DVD), UEFI firmware, headless (no --gfx, no keypress).
#   4. Setup runs unattended; FirstLogonCommands end with `shutdown /s`, which
#      powers the guest off and exits the OpenVMM process -> that's our "done"
#      signal. The finished target disk IS the golden base.
#
# Post-install the firmware boots the installed HDD first (Windows Boot Manager
# is ordered ahead of the DVD), so the still-attached install ISO does NOT loop
# back into Setup and there's nothing to detach.
#
# All artifacts live under $NDB_ROOT (default /root/openvmm-ndb) — deliberately
# isolated from /root/ndaybench, which is the main-branch (Proxmox) checkout.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

NDB_ROOT="${NDB_ROOT:-/root/openvmm-ndb}"
STOCK_ISO="${STOCK_ISO:?set STOCK_ISO=/path/to/Win11_22H2.iso}"
OVMM="${NDAYBENCH_OPENVMM_BINARY:?set NDAYBENCH_OPENVMM_BINARY=/path/to/openvmm}"
UEFI="${NDAYBENCH_UEFI_FIRMWARE:?set NDAYBENCH_UEFI_FIRMWARE=/path/to/MSVM.fd}"

STAMP="${STAMP:-$(cat /proc/sys/kernel/random/uuid | cut -c1-8)}"
NOPROMPT_ISO="$NDB_ROOT/win11-22h2-noprompt.iso"
ANSWER_ISO="$NDB_ROOT/autounattend-clean.iso"
TARGET="${TARGET:-$NDB_ROOT/images/ndaybench-win11-22h2-base-clean-$STAMP.img}"
DISK_GB="${DISK_GB:-40}"
TIMEOUT="${TIMEOUT:-1800}"  # generous; a real bake powers off at ~360s

mkdir -p "$NDB_ROOT/images"

[ -f "$NOPROMPT_ISO" ] || { echo "[1/4] no-prompt ISO"; "$HERE/make-noprompt-iso.sh" "$STOCK_ISO" "$NOPROMPT_ISO"; }
echo "[2/4] answer ISO"; "$HERE/make-answer-iso.sh" "$HERE/autounattend.xml" "$ANSWER_ISO"

echo "[3/4] empty target disk ($DISK_GB GB): $TARGET"
truncate -s "${DISK_GB}G" "$TARGET"

echo "[4/4] booting OpenVMM unattended (timeout ${TIMEOUT}s; exits on guest shutdown /s)"
# `dvd` marks the disk read-only optical media so El Torito boot works.
timeout "$TIMEOUT" "$OVMM" \
  --uefi --uefi-firmware "$UEFI" \
  --hv \
  --disk "file:$TARGET" \
  --disk "file:$NOPROMPT_ISO,dvd" \
  --disk "file:$ANSWER_ISO,dvd" \
  --com1 none \
  -p 4 -m 4G \
  >"$NDB_ROOT/bake.log" 2>&1 || true

echo "[+] base built: $TARGET"
echo "[+] point OpenVmmClient at it via GOLDEN_BASE / OpenVmmConfig(golden_base=...)"
