# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""OATH proof peers retain access grants independently of challenge freshness."""
import hmac

import pytest

import oracle
from oracle_lib import codec
from oracle_lib.runner import AIDS, Options, Session
from oracle_lib.trace import Reply, Trace
from test_oracle_expanded import apdu_parts
from test_oracle_oath_semantics import Peer as RecordPeer


class Peer(RecordPeer):
    def __init__(self, defect=None):
        super().__init__(defect)
        self.code, self.validated, self.applet, self.challenge_number = None, True, None, 0

    def transfer(self, wire, deadline, observe):
        ins, p1, p2, data = apdu_parts(wire)
        sw, output = 0x9000, b""
        if ins == 0xA4 and p1 == 4:
            same = self.applet == data
            self.applet = data
            self.validated = self.code is None or same and self.validated and self.defect != "reselect-drops-grant"
            if data == AIDS["oath"]:
                self.challenge_number += 1
                self.challenge = self.challenge_number.to_bytes(8, "big")
                output = codec.tlv(0x71, b"offline-id")
                if self.code:
                    output += codec.tlv(0x74, self.challenge) + codec.tlv(0x7B, b"\x01")
        elif ins in (3, 0xA3):
            try:
                items = codec.parse_tlv(data)
            except ValueError:
                items = []
            tags = [tag for tag, value in items]
            if ins == 3:
                if not self.validated:
                    sw = 0x6982
                elif items == [(0x73, b"")]:
                    self.code, self.validated = None, True
                elif tags != [0x73, 0x74, 0x75]:
                    sw = 0x6A80
                else:
                    key, challenge, proof = [value for tag, value in items]
                    if not 15 <= len(key) <= 65 or key[0] not in (1, 2, 3) or len(challenge) != 8:
                        sw = 0x6A80
                    else:
                        hash_name = {1: "sha1", 2: "sha256", 3: "sha512"}[key[0]]
                        if proof != hmac.digest(key[1:], challenge, hash_name) and self.defect != "accept-invalid-install-proof":
                            sw = 0x6984
                        else:
                            self.code, self.validated = (hash_name, key[1:]), False
            elif tags != [0x75, 0x74]:
                sw = 0x6A80
            elif self.code is None:
                sw = 0x6984
            else:
                proof, challenge = [value for tag, value in items]
                hash_name, secret = self.code
                if proof != hmac.digest(secret, self.challenge, hash_name) and self.defect != "bad-proof-opens-store":
                    sw = 0x6A80
                else:
                    self.validated = True
                    output = codec.tlv(0x75, hmac.digest(secret, challenge, hash_name))
        elif not self.validated:
            sw = 0x6982
        else:
            return super().transfer(wire, deadline, observe)
        observe("tx", wire)
        output += sw.to_bytes(2, "big")
        observe("rx", output)
        return Reply(output, "success" if sw == 0x9000 else "applet_error", sw)


@pytest.mark.parametrize("defect,needle", [(None, None), ("reselect-drops-grant", "APDU success"),
    ("bad-proof-opens-store", "invalid VALIDATE proof/grammar is refused"),
    ("accept-invalid-install-proof", "SET CODE validates grammar before proof")])
def test_access_algorithms_proof_grammar_and_grant_state(tmp_path, defect, needle):
    peer = Peer(defect)
    trace = Trace(tmp_path / "OATH-access", {})
    session = Session(trace, card=peer, profile="rsk", options=Options(exercise=True, allow_effects=("config_change",)))
    oracle.execute(session, ["oath-access"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if needle:
        assert any(needle in reason for name, reason in failures), failures
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases), [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] != "pass"]
        assert not peer.records and peer.code is None
