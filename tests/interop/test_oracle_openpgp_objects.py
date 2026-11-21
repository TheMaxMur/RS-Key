# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""DO byte bounds, opaque text and the complete sex enum use private witnesses."""
import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_openpgp_catalog import Peer as Catalog
from test_oracle_openpgp_references import sdk_with_errors


class Peer(Catalog):
    def transfer(self, wire, deadline, observe):
        ins, p1, p2, body = apdu_parts(wire)
        tag = p1 * 256 + p2
        owner = 0x82 if tag in (0x101, 0x103) else 0x83
        if ins != 0xda or owner not in self.grants:
            return super().transfer(wire, deadline, observe)
        fixed = 20 if tag in (*range(0xc7, 0xcd), 0xdb, 0xdc) else 4 if tag in (*range(0xce, 0xd1), 0xdd) else None
        bound = {0x5b: 39, 0x5f2d: 8, 0x5f35: 1}.get(tag, 2048)
        accepted = len(body) == fixed if fixed is not None else len(body) <= bound
        if tag == 0x5f35 and body and body not in (b"1", b"2", b"9"):
            accepted = self.defect == "accept-sex-zero" and body == b"0"
        if self.defect == "text-must-be-UTF8" and tag in (0x5b, 0x5e, 0x5f2d, 0x5f50):
            try:
                body.decode()
            except UnicodeDecodeError:
                accepted = False
        if self.defect == "length-check-absent" and tag != 0x5f35:
            accepted = True
        if not accepted:
            observe("tx", wire)
            observe("rx", b"\x6a\x80")
            return Reply(b"\x6a\x80", "applet_error", 0x6a80)
        changed = body.partition(b"\x00")[0] if self.defect == "NUL-terminated-text" and tag in (0x5b, 0x5e, 0x5f2d, 0x5f50) else b"9" if tag == 0x5f35 and not body else body
        return super().transfer(codec.apdu(0xda, p1, p2, changed), deadline, observe)


@pytest.mark.parametrize("defect,needle", [(None, None), ("accept-sex-zero", "exactly its three profiled"),
    ("text-must-be-UTF8", "byte-bounded rather than Unicode"), ("NUL-terminated-text", "retains every opaque byte"),
    ("length-check-absent", "length boundary refusal")])
def test_actual_DO_bounds_binary_text_and_reserved_values(tmp_path, monkeypatch, defect, needle):
    from yubikit import openpgp
    peer = Peer(defect)
    trace = Trace(tmp_path / "OpenPGP-objects", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, touch=True,
        openpgp_pin="123456", openpgp_admin="12345678"))
    original = dict(peer.data)
    monkeypatch.setattr(openpgp, "OpenPgpSession", sdk_with_errors(session))
    oracle.execute(session, ["openpgp-objects"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for _, reason in failures), failures[:25]
    else:
        assert trace.cases and all(row["verdict"] == "pass" for row in trace.cases), failures[:25]
        assert peer.data == original and not peer.keys
