#!/usr/bin/env bash
# Boot a Torito ISO headless in QEMU and wait for a login prompt on the
# serial console (Torito images log to ttyS0 by default).
#
#   tools/boot-test.sh image.iso [bios|uefi] [timeout-seconds]
#
# Exit status 0 when "login:" appears, 1 otherwise. The serial log is kept
# next to the image as <image>.<mode>.serial.log.
set -euo pipefail

iso=${1:?usage: boot-test.sh image.iso [bios|uefi] [timeout]}
mode=${2:-bios}
limit=${3:-600}
log="${iso}.${mode}.serial.log"
rm -f "$log"

accel=(-accel tcg)
if [ -w /dev/kvm ]; then accel=(-accel kvm -cpu host); fi

firmware=()
if [ "$mode" = uefi ]; then
    code=""
    for c in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd \
             /usr/share/edk2/x64/OVMF_CODE.4m.fd /usr/share/edk2/ovmf/OVMF_CODE.fd \
             /usr/share/qemu/edk2-x86_64-code.fd; do
        [ -f "$c" ] && { code=$c; break; }
    done
    [ -n "$code" ] || { echo "no OVMF firmware found (install the ovmf package)"; exit 2; }
    vars_src="${code/CODE/VARS}"
    vars=$(mktemp)
    if [ -f "$vars_src" ]; then cp "$vars_src" "$vars"; else truncate -s "$(stat -c %s "$code")" "$vars"; fi
    firmware=(-drive "if=pflash,format=raw,readonly=on,file=$code" -drive "if=pflash,format=raw,file=$vars")
fi

qemu-system-x86_64 "${accel[@]}" -m 2048 -smp 2 "${firmware[@]}" \
    -drive "file=$iso,media=cdrom,readonly=on" -boot d \
    -display none -monitor none -serial "file:$log" -no-reboot &
qpid=$!
trap 'kill $qpid 2>/dev/null || true' EXIT

start=$(date +%s)
while kill -0 $qpid 2>/dev/null; do
    if grep -q "login:" "$log" 2>/dev/null; then
        echo "✓ $mode boot reached a login prompt in $(( $(date +%s) - start ))s"
        tail -n 5 "$log" | tr -cd '\11\12\15\40-\176'
        exit 0
    fi
    if [ $(( $(date +%s) - start )) -ge "$limit" ]; then break; fi
    sleep 2
done
echo "✗ $mode boot did not reach a login prompt within ${limit}s; serial log:"
tr -cd '\11\12\15\40-\176' < "$log" | tail -n 80 || true
exit 1
