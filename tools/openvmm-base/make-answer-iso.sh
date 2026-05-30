#!/usr/bin/env bash
# Build a small data ISO carrying autounattend.xml. It is attached as a second
# DVD during install; Windows Setup auto-discovers autounattend.xml on removable
# media at the root, so no boot config is needed — it's just a data disc.
#
# Usage:
#   ./make-answer-iso.sh [autounattend.xml] [/root/openvmm-ndb/autounattend-clean.iso]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
XML="${1:-$HERE/autounattend.xml}"
OUT="${2:-/root/openvmm-ndb/autounattend-clean.iso}"

command -v genisoimage >/dev/null || { echo "need genisoimage (nix-shell -p cdrkit)"; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cp "$XML" "$TMP/autounattend.xml"
genisoimage -quiet -o "$OUT" -J -r -V "UNATTEND" "$TMP"
echo "[+] created $OUT"
