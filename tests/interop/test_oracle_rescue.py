# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Rescue calendar and certificate wires are checked by an independent peer."""
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

import oracle
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts


class Card:
    layer = "pcsc_apdu"

    def __init__(self, defect):
        self.defect, self.seconds, self.certificate = defect, 0, None
        self.key = ec.derive_private_key(42, ec.SECP256K1())

    def transfer(self, request, deadline, observe):
        ins, p1, p2, data = apdu_parts(request)
        status, body = 0x9000, b""
        if ins == 0xA4:
            body = bytes(12)
        elif ins == 0x10:
            if p1 == 2:
                body = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            elif p1 == 1 and len(data) == 32:
                r, s = utils.decode_dss_signature(self.key.sign(data, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
                body = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            elif p1 == 3 and data:
                leaf = x509.load_der_x509_certificate(data)
                assert leaf.public_key().public_numbers() == self.key.public_key().public_numbers()
                self.certificate = leaf
            else:
                status = 0x6700
        elif ins == 0x1C and (p1, p2) == (2, 2):
            if len(data) != 4:
                status = 0x6700
            elif self.defect != "RTC-write-noop":
                self.seconds = int.from_bytes(data, "big")
        elif ins == 0x1E and p1 == 4:
            if p2 == 2:
                body = self.seconds.to_bytes(4, "big")
            else:
                date = datetime.fromtimestamp(self.seconds, timezone.utc)
                month = date.month if self.defect == "one-based-month" else date.month - 1
                body = date.year.to_bytes(2, "big") + bytes([month, date.day, (date.weekday() + 1) % 7, date.hour, date.minute, date.second])
        elif ins == 0x1E and p1 == 8:
            body = b"\x02\x01"
        elif ins == 0x1E and p1 == 3:
            body = bytes(3)
        elif ins == 0x20:
            status = 0x6985 if data in (b"INITV2", b"IMPORTV2") else 0x6A80
        elif ins == 0x1B:
            status = 0x6A86
        else:
            status = 0x6D00
        observe("tx", request)
        response = body + status.to_bytes(2, "big")
        observe("rx", response)
        return Reply(response, "success" if status == 0x9000 else "applet_error", status)


@pytest.mark.parametrize("defect,expected", [(None, None), ("one-based-month", "RTC civil calendar"),
                                           ("RTC-write-noop", "RTC epoch readback")])
def test_rescue_commands_through_dispatch(tmp_path, defect, expected):
    card = Card(defect)
    trace = Trace(tmp_path / "rescue", {})
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, allow_effects=("replace_identity",)))
    oracle.execute(session, ["rescue"])
    trace.finish()
    failed = [row for row in trace.cases if row["verdict"] == "fail"]
    if expected is None:
        assert not failed, failed
        assert all(row["verdict"] == "pass" for row in trace.cases if row["scenario_id"].startswith("rescue.RTC."))
    else:
        assert any(expected in row["reason"] for row in failed), failed
    assert card.certificate is not None


class RecoveryCard(Card):
    emulated = True

    def __init__(self, layout, defect):
        super().__init__(defect)
        self.layout, self.ready = layout, False

    def control(self, action, deadline, observe):
        assert action == "reconnect"
        return Reply(bytes(12))

    def transfer(self, request, deadline, observe):
        from oracle_lib.runner import AIDS
        ins, p1, p2, data = apdu_parts(request)
        if ins == 0x1E and p1 == 8:
            body, status = bytes([2, int(self.ready)]), 0x9000
        elif not self.ready and ins == 0xA4 and data != AIDS["rescue"]:
            body, status = b"", 0x6581
        elif ins == 0x20 and data in (b"INITV2", b"IMPORTV2"):
            body, status = b"", 0x6985
            if not self.ready and p1 == (0 if self.layout == "empty" else 1):
                status = 0x9000
                self.ready = self.defect != "setup-noop"
        else:
            return super().transfer(request, deadline, observe)
        observe("tx", request)
        response = body + status.to_bytes(2, "big")
        observe("rx", response)
        return Reply(response, "success" if status == 0x9000 else "applet_error", status)


@pytest.mark.parametrize("layout", ["empty", "legacy"])
@pytest.mark.parametrize("defect", [None, "setup-noop"])
def test_prepared_recovery_fixture_transitions_through_dispatch(tmp_path, layout, defect):
    card = RecoveryCard(layout, defect)
    trace = Trace(tmp_path / "recovery", {})
    session = Session(trace, card=card, profile="rsk", options=Options(exercise=True, touch=True, recovery_layout=layout,
                      allow_effects=("storage_setup", "reboot")))
    oracle.execute(session, ["rescue"])
    trace.finish()
    row = next(row for row in trace.cases if row["scenario_id"] == "rescue.storage-setup.recovery-to-active." + layout)
    if defect is None:
        assert row["verdict"] == "pass" and card.ready, row
        assert not [row for row in trace.cases if row["verdict"] == "fail"], trace.cases
    else:
        assert row["verdict"] == "fail" and "transitions to active v2" in row["reason"], row
