#!/usr/bin/env bash
# Re-master a stock Windows 11 install ISO into a *no-prompt* UEFI boot ISO.
#
# Stock MS install media ships two El Torito UEFI boot images:
#   efi/microsoft/boot/efisys.bin           -> shows "Press any key to boot
#                                               from CD or DVD..." (needs a keypress)
#   efi/microsoft/boot/efisys_noprompt.bin  -> boots straight into Setup
#
# Stock ISOs boot the prompting one, so an unattended VM either hangs at the
# prompt or falls through to an empty disk. Re-mastering with the noprompt
# image makes the installer boot hands-off, every time, with no graphics and
# no timing-fragile keypress injection. This is a one-time artifact, reused
# for every base bake.
#
# NOTE: the `xorriso -osirrox` in-place extract is unreliable here (it can
# produce an empty tree); mount + copy is the path that actually works.
#
# Usage:
#   sudo ./make-noprompt-iso.sh /path/to/Win11_22H2.iso /root/openvmm-ndb/win11-22h2-noprompt.iso
set -euo pipefail

SRC_ISO="${1:?usage: make-noprompt-iso.sh <stock-win11.iso> <output-noprompt.iso>}"
OUT_ISO="${2:?usage: make-noprompt-iso.sh <stock-win11.iso> <output-noprompt.iso>}"

command -v xorriso >/dev/null || { echo "need xorriso (nix-shell -p xorriso)"; exit 1; }

MNT=$(mktemp -d)
SRC=$(mktemp -d)
cleanup() { mountpoint -q "$MNT" && umount "$MNT"; rm -rf "$MNT" "$SRC"; }
trap cleanup EXIT

echo "[+] mounting $SRC_ISO read-only"
mount -o loop,ro "$SRC_ISO" "$MNT"

echo "[+] verifying the no-prompt UEFI boot image is present"
test -f "$MNT/efi/microsoft/boot/efisys_noprompt.bin" \
  || { echo "efisys_noprompt.bin not in this ISO"; exit 1; }

echo "[+] copying ISO contents (mount+copy — reliable extract)"
cp -a "$MNT/." "$SRC/"
umount "$MNT"

echo "[+] re-mastering with efisys_noprompt.bin as the UEFI El Torito image"
# BIOS entry (etfsboot.com) kept for portability; OpenVMM boots the UEFI entry,
# which now points at the no-prompt image. Expect load-size 2880 sectors
# (= 1.4 MB efisys_noprompt.bin) in the resulting boot catalog.
xorriso -as mkisofs \
  -iso-level 4 -udf \
  -V "WIN11_NOPROMPT" \
  -b boot/etfsboot.com -no-emul-boot -boot-load-size 8 \
  -eltorito-alt-boot \
  -e efi/microsoft/boot/efisys_noprompt.bin -no-emul-boot \
  -o "$OUT_ISO" "$SRC"

echo "[+] done: $OUT_ISO"
echo "[+] boot catalog (expect a UEFI image, load-size 2880):"
xorriso -indev "$OUT_ISO" -report_el_torito plain 2>/dev/null | grep -iE "boot|emul|load" || true
