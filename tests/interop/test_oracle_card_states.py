# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""An ACL case cannot pass because a different input-validation guard refused it."""
import pytest

from oracle_lib import card_states, codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace


@pytest.mark.parametrize("refusal", [0x6982, 0x6A80])
def test_OpenPGP_DO_ACL_cases_require_the_intended_refusal(tmp_path, monkeypatch, refusal):
    from yubikit import openpgp
    from yubikit.core.smartcard import ApduError

    class Card:
        layer = "pcsc_apdu"
        authorized = False

        def __init__(self):
            self.values = {tag: b"9" if tag == 0x5F35 else b"en" if tag == 0x5F2D else b"original"
                           for tag, _ in card_states.PGP_PERSONAL_DOS}
            self.original = dict(self.values)

        def transfer(self, request, deadline, observe):
            observe("tx", request)
            ins, p1, p2 = request[1:4]
            tag, status, data = p1 * 256 + p2, 0x9000, b""
            if ins == 0x20:
                self.authorized = p1 != 0xFF
            elif ins == 0xCA:
                data = codec.tlv(0x65, b"".join(codec.tlv(key, self.values[key]) for key in (0x5B, 0x5F2D, 0x5F35))) if tag == 0x65 else self.values[tag]
            elif ins == 0xDA:
                value = request[5:5 + request[4]]
                if not self.authorized:
                    assert value == dict(card_states.PGP_PERSONAL_DOS)[tag]
                    status = refusal
                else:
                    self.values[tag] = value
            else:
                raise AssertionError("unexpected card request")
            data += status.to_bytes(2, "big")
            observe("rx", data)
            return Reply(data, "success" if status == 0x9000 else "applet_error", status)

    trace = Trace(tmp_path / "ACL", {})
    peer = Card()
    session = Session(trace, card=peer, options=Options(exercise=True, openpgp_admin="fixture-admin"))
    session.applet = "openpgp"

    class Sdk:
        def __init__(self, connection):
            pass

        def get_data(self, tag):
            return session.card_value(session.apdu(codec.apdu(0xCA, tag >> 8, tag & 255)))

        def verify_admin(self, secret):
            session.card_value(session.apdu(codec.apdu(0x20, p2=0x83, data=secret.encode())))

        def put_data(self, tag, value):
            response = session.apdu(codec.apdu(0xDA, tag >> 8, tag & 255, value))
            if response.status != 0x9000:
                raise ApduError(response.data[:-2], response.status)

    monkeypatch.setattr(openpgp, "OpenPgpSession", Sdk)
    card_states.pgp_objects(session)
    trace.finish()
    if refusal == 0x6982:
        assert all(row["verdict"] == "pass" for row in trace.cases), trace.cases
    else:
        assert all(row["verdict"] == "fail" and "refusal cause" in row["reason"] for row in trace.cases), trace.cases
    assert peer.values == peer.original
