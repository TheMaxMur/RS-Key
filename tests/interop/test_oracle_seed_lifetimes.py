# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Flash/RAM peers distinguish real reboot from host-interface reconnect."""
import hashlib
import hmac

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import oracle
from oracle_lib import binding, codec, seed_lifetimes
from oracle_lib.identity_chain import commitment
from oracle_lib.trace import Outcome, Reply, Trace, TransferError
from oracle_lib.runner import Options, Session
from oracle_lib.vendor_lifecycle import AUT_ENABLE, AUT_DISABLE
from test_oracle_expanded import apdu_parts
from test_oracle_seed_matrix import Peer as SeedPeer


class Peer(SeedPeer):
    layer = "hid_report"
    emulated = True

    def __init__(self, defect=None):
        super().__init__()
        self.fault = defect
        self.lock_key, self.unlocked = None, False
        self.org = self.chain = None
        self.app = None
        self.boots = []
        self.consent_mode = "accept"

    def assertion(self, fields):
        if self.lock_key is not None and not self.unlocked and self.fault != "locked-key-still-usable":
            return 0x7f, {}
        return super().assertion(fields)

    def control(self, action, deadline, observe):
        self.boots.append(action)
        if action == "power_cycle" and self.fault != "RAM-survives-power":
            self.unlocked = False
        if action == "power_cycle" and self.fault != "MSE-survives-reboot":
            self.vendor.channel = None
        if action in ("card_reset", "reconnect") and self.fault == "card-reset-erases-RAM":
            self.unlocked = False
        if action == "power_cycle" and self.fault == "boot-reopens-seal":
            self.sealed = False
        if action == "power_cycle" and self.fault == "boot-loses-identity":
            self.org = self.chain = None
        return Reply(b"offline ATR")

    def wait_disconnect(self, deadline, observe):
        raise TransferError("synthetic observed disconnect", Outcome.DISCONNECTED)

    def usb_reset(self, deadline, observe):
        self.boots.append("usb-reset")
        if self.fault == "USB-reset-erases-RAM":
            self.unlocked = False
        return Reply(b"")

    def mac_valid(self, command, fields):
        sub, params = fields[1], fields.get(2)
        if 3 in fields and fields[3] not in (1, 2):
            return 2
        if 4 not in fields:
            return 0x36
        if 3 not in fields:
            return 0x14
        message = b"\xff" * 32 + bytes([command, sub]) + (codec.encode(params) if params is not None else b"")
        expected = hmac.digest(self.token, message, "sha256")[:16 if fields[3] == 1 else 32]
        return 0 if fields[4] == expected and self.permissions & 32 else 0x33

    def open_blob(self, channel, blob):
        if channel is None or len(blob) != 60:
            return None
        key, aad = channel
        try:
            return ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], aad)
        except InvalidTag:
            return None

    def transfer(self, *args):
        if len(args) == 3:
            wire, deadline, observe = args
            ins, p1, p2, data = apdu_parts(wire)
            if ins == 0xa4:
                from oracle_lib.runner import AIDS
                if data == b"oracle-no-such-applet":
                    return Reply(b"\x6a\x82", "applet_error", 0x6a82)
                self.app = data
                return Reply(b"U2F_V2\x90\x00", status=0x9000)
            if ins == 0xfd:
                return Reply(b"\x05\x08\x00\x90\x00", status=0x9000)
            if ins == 0x1f:
                if self.fault != "RAM-survives-warm":
                    self.unlocked = False
                if self.fault != "MSE-survives-reboot":
                    self.vendor.channel = None
                self.boots.append("warm")
                return Reply(b"\x90\x00", status=0x9000)
            raise AssertionError("unprofiled synthetic card command")
        command, wire, deadline, observe = args
        if command == 3:
            if wire[1] == 3:
                return Reply(b"U2F_V2\x90\x00", status=0x9000)
            if wire[1] == 2:
                status = 0x6985 if self.u2f_seed == self.vendor.seed else 0x6a80
                return Reply(status.to_bytes(2, "big"), "applet_error", status)
            assert wire[1] == 1 and self.org is not None
            self.u2f_seed = self.vendor.seed
            body = wire[7:-2]
            challenge, application = body[:32], body[32:]
            point = ec.derive_private_key(19, ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            handle = b"owned fixture"
            signature = self.org.sign(b"\x00" + application + challenge + handle + point, ec.ECDSA(hashes.SHA256()))
            return Reply(b"\x05" + point + bytes([len(handle)]) + handle + self.chain + signature + b"\x90\x00", status=0x9000)
        if wire[0] == 7:
            records = self.records.copy()
            result = super().transfer(command, wire, deadline, observe)
            self.records = records
            self.vendor.seed = hashlib.sha256(self.vendor.seed + b"reset").digest()
            self.lock_key, self.unlocked = None, False
            self.sealed = False
            if self.fault == "reset-deletes-batch-identity":
                self.org = self.chain = None
            return result
        if wire[0] == 13:
            fields = codec.decode(wire[1:])
            params = fields[2]
            status = self.mac_valid(13, fields)
            if status:
                if self.fault == "unauthorized-CONFIG-spends-MSE":
                    self.vendor.channel = None
                return self.reply(wire, status, {}, observe)
            if params[1] == AUT_ENABLE:
                channel, self.vendor.channel = self.vendor.channel, None
                if self.lock_key is not None or channel is None:
                    status = 0x30
                else:
                    lock = self.open_blob(channel, params.get(2, b""))
                    if lock is None:
                        status = 2
                    elif not self.confirmed and self.fault != "ignores-lock-decline":
                        status = 0x27
                    else:
                        self.lock_key, self.unlocked = lock, False
            elif params[1] == AUT_DISABLE:
                if self.lock_key is None:
                    status = 0x30
                elif not self.unlocked:
                    status = 0x33
                elif not self.confirmed and self.fault != "ignores-lock-decline":
                    status = 0x2d if self.consent_mode == "panel-cancel" else 0x27
                else:
                    self.lock_key, self.unlocked = None, self.fault == "disable-leaves-RAM"
            else:
                raise AssertionError("unprofiled synthetic CONFIG")
            return self.reply(wire, status, {}, observe)
        if wire[0] != 0x41:
            return super().transfer(command, wire, deadline, observe)
        fields = codec.decode(wire[1:])
        sub, params = fields[1], fields.get(2, {})
        if sub == 5:
            return self.reply(wire, 0, {1: self.sealed, 2: self.lock_key is None, 3: self.lock_key is not None, 4: self.unlocked, 5: False}, observe)
        if sub == 11:
            return self.reply(wire, 0, {1: False} if self.org is None else {1: True, 2: commitment(self.chain)}, observe)
        if sub in (13, 14, 15):
            return self.reply(wire, 0, {1: False if sub == 14 else [] if sub == 15 else b""}, observe)
        if sub in (6, 9, 10):
            channel, self.vendor.channel = self.vendor.channel, None
            status = 0x30 if channel is None else 0
            if not status and sub == 6:
                key = self.open_blob(channel, params.get(1, b""))
                status = 2 if key is None or key != self.lock_key else 0
                if not status:
                    self.unlocked = True
            elif not status and sub == 9:
                scalar = self.open_blob(channel, params[1])
                self.org = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())
                self.chain = params[2]
            elif not status:
                self.org = self.chain = None
            return self.reply(wire, status, {}, observe)
        if sub == 2 and (self.sealed or self.lock_key is not None and not self.unlocked):
            self.vendor.channel = None
            return self.reply(wire, 0x30, {}, observe)
        if sub == 3 and self.lock_key is not None:
            self.vendor.channel = None
            return self.reply(wire, 0x30, {}, observe)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("locked-key-still-usable", "missing-seed cause"),
    ("RAM-survives-power", "RAM follows"), ("RAM-survives-warm", "RAM follows"),
    ("card-reset-erases-RAM", "RAM follows"), ("boot-reopens-seal", "seal survives"),
    ("boot-loses-identity", "packed-chain commitment"), ("reset-deletes-batch-identity", "packed-chain commitment"),
    ("disable-leaves-RAM", "erases the RAM copy"), ("unauthorized-CONFIG-spends-MSE", "CTAP success"),
    ("ignores-lock-decline", "distinct status"), ("MSE-survives-reboot", "prior channel"),
    ("USB-reset-erases-RAM", "RAM follows")])
def test_seed_lock_seal_and_identity_lifetime_table(tmp_path, monkeypatch, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "seed-lifetimes", {})
    session = Session(trace, hid=peer, card=peer, profile="rsk", options=Options(exercise=True, touch=True,
        pin="fixture-PIN", operator=True, features=("display",), timeout=140,
        allow_effects=("config_change", "seed_change", "replace_identity", "applet_reset", "pin_change", "reboot")))
    original = seed_lifetimes.cue
    def cue(session, mode):
        peer.confirmed, peer.consent_mode = mode == "accept", mode
        original(session, mode)
    monkeypatch.setattr(seed_lifetimes, "cue", cue)
    monkeypatch.setattr(binding, "check_pair", lambda session: session.values.update(same_instance_confirmed=True))
    session.values["same_instance_confirmed"] = True
    oracle.execute(session, ["seed-lifetimes"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:20]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:20]
        assert peer.lock_key is None and not peer.unlocked and not peer.sealed and peer.org is None
        assert peer.vendor.seed == bytes(range(32))
        assert {"power_cycle", "card_reset", "reconnect", "warm"}.issubset(peer.boots)
