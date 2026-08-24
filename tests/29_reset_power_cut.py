#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""HIL: cut real board power during authenticatorReset, then inspect the next boot.

    nix develop -c python tests/29_reset_power_cut.py

⚠ DESTRUCTIVE: wipes FIDO credentials/PIN and deliberately removes power during
a flash mutation. Use a throwaway key running the no-touch test image.

This is the runtime witness for `ResetNeverWeakensSurvivingState` and its three
clauses: `ResetKeepsThePinGate`, `ResetKeepsTheAlwaysUvGate`, and
`ResetKeepsTheBackupSeal`. It provisions one owner seed, seals its export window,
sets a PIN, enables alwaysUv, and creates a resident credential. While RESET is
in flight the operator unplugs the key. On the next boot:

* the old credential must not authorize without either gate;
* if the PIN or alwaysUv record disappeared, that refusal is mandatory;
* if the backup seal disappeared, the now-exportable seed must be a fresh seed,
  never the owner's pre-reset seed.

For a relay rig, set `RSK_POWER_CUT_CMD` to an argv-style command that removes USB
power long enough for the device to disappear and then restores it. Optional
`RSK_POWER_CUT_DELAY_MS` selects the delay after the RESET sender starts
(default 25 ms). Without it, the script asks the operator to yank and restore
the cable.
"""
import hashlib
import os
import shlex
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import replug  # noqa: E402
from ctaphid import Protocol2, client_pin, decode, enc, send_cbor  # noqa: E402
from rsk import backup  # noqa: E402

PIN = b"6482"
RP = "reset-power-cut.example"
PERM_MC, PERM_ACFG = 0x01, 0x20
MAKE_CREDENTIAL, GET_ASSERTION, GET_INFO, AUTH_CONFIG = 0x01, 0x02, 0x04, 0x0D
CTAP_RESET = 0x07
PUAT_PREFIX = b"\xff" * 32


def mac(token, data):
    from cryptography.hazmat.primitives import hashes, hmac as chmac

    h = chmac.HMAC(token, hashes.SHA256())
    h.update(data)
    return h.finalize()


def set_pin(dev, cid):
    ka = client_pin(dev, cid, {1: 2, 2: 2})
    assert ka[0] == 0, f"getKeyAgreement: {ka[0]:#x}"
    cose = decode(ka[1:])[1]
    proto = Protocol2(cose[-2], cose[-3])
    padded = PIN + b"\x00" * (64 - len(PIN))
    encrypted = proto.encrypt(padded)
    r = client_pin(
        dev,
        cid,
        {1: 2, 2: 3, 3: proto.cose(), 4: proto.authenticate(encrypted), 5: encrypted},
    )
    assert r[0] == 0, f"setPIN: {r[0]:#x}"


def token_for(dev, cid, permission, rp=None):
    ka = client_pin(dev, cid, {1: 2, 2: 2})
    assert ka[0] == 0, f"getKeyAgreement: {ka[0]:#x}"
    cose = decode(ka[1:])[1]
    proto = Protocol2(cose[-2], cose[-3])
    req = {
        1: 2,
        2: 9,
        3: proto.cose(),
        6: proto.encrypt(hashlib.sha256(PIN).digest()[:16]),
        9: permission,
    }
    if rp is not None:
        req[10] = rp
    r = client_pin(dev, cid, {k: req[k] for k in sorted(req)})
    assert r[0] == 0, f"getPinUvAuthToken: {r[0]:#x}"
    return proto.decrypt(decode(r[1:])[2])


def make_resident_credential(dev, cid):
    client_data_hash = hashlib.sha256(b"phase-6 reset power cut").digest()
    token = token_for(dev, cid, PERM_MC, RP)
    request = {
        1: client_data_hash,
        2: {"id": RP},
        3: {"id": b"\x29\x29\x29\x29", "name": "phase6"},
        4: [{"alg": -7, "type": "public-key"}],
        7: {"rk": True},
        8: mac(token, client_data_hash),
        9: 2,
    }
    r = send_cbor(dev, cid, bytes([MAKE_CREDENTIAL]) + enc(request))
    assert r[0] == 0, f"makeCredential: {r[0]:#x}"
    auth_data = decode(r[1:])[2]
    cred_len = int.from_bytes(auth_data[53:55], "big")
    credential_id = auth_data[55:55 + cred_len]
    assert credential_id, "makeCredential returned an empty credential id"
    return credential_id


def enable_always_uv(dev, cid):
    token = token_for(dev, cid, PERM_ACFG)
    verify = PUAT_PREFIX + bytes([AUTH_CONFIG, 0x02])
    request = {1: 0x02, 3: 2, 4: mac(token, verify)}
    r = send_cbor(dev, cid, bytes([AUTH_CONFIG]) + enc(request))
    assert r[0] == 0, f"toggleAlwaysUv: {r[0]:#x}"
    info = decode(send_cbor(dev, cid, bytes([GET_INFO]))[1:])
    assert info[4].get("alwaysUv") is True, "alwaysUv did not engage"


def old_credential_without_gates(dev, cid, credential_id):
    request = {
        1: RP,
        2: hashlib.sha256(b"post-cut assertion").digest(),
        3: [{"id": credential_id, "type": "public-key"}],
    }
    return send_cbor(dev, cid, bytes([GET_ASSERTION]) + enc(request))[0]


def cut_during_reset(dev, cid):
    outcome = {}

    def send_reset():
        try:
            outcome["response"] = send_cbor(dev, cid, bytes([CTAP_RESET]))
        except Exception as error:  # the expected path is a dead USB handle
            outcome["error"] = repr(error)
        finally:
            dev.close()

    worker = threading.Thread(target=send_reset, daemon=True)
    command = os.environ.get("RSK_POWER_CUT_CMD")
    if command:
        delay = int(os.environ.get("RSK_POWER_CUT_DELAY_MS", "25")) / 1000
        worker.start()
        time.sleep(delay)
        relay = subprocess.Popen(shlex.split(command))
        replug.wait_gone()
        if relay.wait() != 0:
            sys.exit(f"FAIL: RSK_POWER_CUT_CMD exited {relay.returncode}")
    else:
        input("Press Enter when your hand is on the cable; yank it at the CUT line… ")
        worker.start()
        print("\n>>> CUT POWER NOW — then plug the key back in once it disappears <<<")
        replug.wait_gone()
    fresh, fresh_cid, _ = replug.wait_back()
    worker.join(timeout=5)
    if worker.is_alive():
        fresh.close()
        sys.exit("INCONCLUSIVE: the RESET sender did not observe the power loss")
    response = outcome.get("response")
    if response and response[0] == 0:
        fresh.close()
        sys.exit("INCONCLUSIVE: RESET completed before power disappeared; cut earlier")
    print(f"reset interrupted as intended ({outcome.get('error', response)!s})")
    return fresh, fresh_cid


def main():
    print("Phase-6 HIL — use a throwaway key; this intentionally tears a flash wipe.")
    dev, cid = replug.reset(None, "the phase-6 clean-slate setup")
    try:
        owner_seed = backup.read_seed(dev, cid, None)
        status, _ = backup._vendor(dev, cid, {1: backup.FINALIZE})
        assert status == 0, f"backup finalize: {status:#x}"
        set_pin(dev, cid)
        credential_id = make_resident_credential(dev, cid)
        enable_always_uv(dev, cid)
        print("provisioned: sealed owner seed + PIN + alwaysUv + resident credential")

        dev, cid = cut_during_reset(dev, cid)
        info_response = send_cbor(dev, cid, bytes([GET_INFO]))
        assert info_response[0] == 0, f"getInfo after cut: {info_response[0]:#x}"
        options = decode(info_response[1:])[4]
        assertion_status = old_credential_without_gates(dev, cid, credential_id)
        assert assertion_status != 0, (
            "old credential authorized after the reset lost its protection "
            f"(clientPin={options.get('clientPin')}, alwaysUv={options.get('alwaysUv')})"
        )

        status, state = backup._vendor(dev, cid, {1: backup.STATE})
        assert status == 0, f"backup state after cut: {status:#x}"
        sealed = bool(state[1])
        if not sealed:
            current = backup.read_seed(dev, cid, PIN.decode() if options.get("clientPin") else None)
            assert current != owner_seed, "owner seed survived after its backup seal disappeared"

        print(
            "post-cut: "
            f"clientPin={options.get('clientPin')} alwaysUv={options.get('alwaysUv')} "
            f"sealed={sealed} old-assertion={assertion_status:#x}"
        )
        print("PASS — torn reset remained fail-closed across the real reboot")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
