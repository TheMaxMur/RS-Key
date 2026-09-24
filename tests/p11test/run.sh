#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# OpenSC's own PKCS#11 suite, p11test, against the attached device: the view of
# PIV and OpenPGP that ssh, a browser and a Linux desktop get through
# opensc-pkcs11.so, which no CI suite saw before. The keys are made the way
# OpenSC's CI makes them on its virtual cards (.github/test-piv.sh and
# test-openpgp.sh, OpenSC 0.27.1), and each result is diffed against the
# reference beside this script, as that CI diffs its own.
#
# The references are this device's. Against a YubiKey 5C NFC 5.8.0 made up the
# same way, p11test answers PIV identically, and OpenPGP in two places otherwise,
# both deliberate: RSA-1024 is offered, so old keys keep working, and MSE lets
# the authentication key decrypt.
#
# `scripts/usbip-guest.sh` runs this on the Yubico identity: `ykman --reader`
# refuses the default one's reader ("PID must be provided for non-NFC").
#
#   tests/p11test/run.sh <out-dir>   # the JSONs land there, references untouched
set -uo pipefail

out="$1"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"
# A PC/SC reader name carries the USB serial; the emulator's is fixed.
reader="${P11TEST_READER:-rs-key-emu}"
module="$(dirname "$(readlink -f "$(command -v p11test)")")/../lib/opensc-pkcs11.so"
mgm=010203040506070801020304050607080102030405060708
pin=123456
admin=12345678

step() { # <what> <command…>: the command's output only when it fails
  local what="$1" rc=0
  shift
  timeout 300 "$@" >"$out/step.log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "FAIL: $what (exit $rc$([ "$rc" -eq 124 ] && echo ", timed out"))"
    sed 's/^/      /' "$out/step.log"
    return 1
  fi
}

[ -f "$module" ] || { echo "FAIL: no opensc-pkcs11.so beside p11test ($module)"; exit 1; }
# Only ykman is told which reader to use; OpenSC's tools take the first card. With
# a second key plugged in, OpenPGP's admin PIN would be tried against that one.
readers="$(ykman list --readers)"
if [ "$(printf '%s\n' "$readers" | grep -c .)" -ne 1 ] || ! grep -qF "$reader" <<<"$readers"; then
  echo "FAIL: want exactly one PC/SC reader, and it '$reader'; found:"
  printf '%s\n' "$readers" | sed 's/^/      /'
  exit 1
fi

# PIV: two RSA-2048 and two P-256 keys, each with a self-signed certificate.
step "PIV reset" ykman -r "$reader" piv reset -f || exit 1
for slot in "9e RSA2048 barCard" "9a RSA2048 bar" "9c ECCP256 bar" "9d ECCP256 bar"; do
  set -- $slot
  step "PIV $1 key" ykman -r "$reader" piv keys generate -m "$mgm" -a "$2" "$1" "$out/$1.pem" || exit 1
  step "PIV $1 certificate" ykman -r "$reader" piv certificates generate -m "$mgm" -P "$pin" \
    -s "CN=$3,OU=test,O=example.com" "$1" "$out/$1.pem" || exit 1
done

# OpenPGP: all three keys generated on the card, the decryption key twice — the
# second time through pkcs15-init, as OpenSC's CI does it. The card carries PIV
# too, and OpenSC binds one driver per card, so name it.
step "OpenPGP reset" ykman -r "$reader" openpgp reset -f || exit 1
export OPENSC_DRIVER=openpgp
step "OpenPGP key 2" openpgp-tool --verify CHV3 --pin "$admin" --gen-key 2 || exit 1
step "OpenPGP key 2 again" pkcs15-init --verify --auth-id 3 --pin "$admin" \
  --delete-objects privkey,pubkey --id 2 --generate-key rsa/2048 || exit 1
step "pkcs11-tool --test" pkcs11-tool --module "$module" -l -t -p "$pin" || exit 1
step "OpenPGP key 1" openpgp-tool --verify CHV3 --pin "$admin" --gen-key 1 || exit 1
step "OpenPGP key 3" openpgp-tool --verify CHV3 --pin "$admin" --gen-key 3 || exit 1

rc=0
run() { # <name> <slot>
  if ! step "p11test $1" p11test -m "$module" -s "$2" -p "$pin" -o "$out/$1.json"; then
    rc=1
  elif ! diff -u3 "$here/$1_ref.json" "$out/$1.json"; then
    echo "FAIL: p11test $1 differs from tests/p11test/$1_ref.json (above)"
    rc=1
  fi
}
# The signature key is the second slot's, behind its own PIN reference.
run openpgp_s0 0
run openpgp_s1 1
unset OPENSC_DRIVER
run piv 0
[ "$rc" -eq 0 ] && echo "p11test: PIV and both OpenPGP slots match their references"
exit "$rc"
