# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Foreign public fixtures need real origin signatures and a different serial."""
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import oracle
from oracle_lib import codec, foreign_references
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Trace
from test_oracle_token_matrix import Peer as Tokens
from test_oracle_u2f_semantics import Peer as U2f


def bundle(relation="distinct"):
    rp, challenge = "foreign-source.oracle.invalid", b"h" * 32
    key = ec.derive_private_key(777, ec.SECP256R1())
    public = key.public_key().public_numbers()
    cose = {1: 2, 3: -7, -1: 1, -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big")}
    signed = hashlib.sha256(rp.encode()).digest() + b"\x01" + bytes(4)
    signature = key.sign(signed + challenge, ec.ECDSA(hashes.SHA256()))
    fido = {"kind": "fido2", "source_serial": "source", "seed_relation": relation, "rp": rp,
        "credential_id": (b"foreign-key" * 4).hex(), "cose_key": codec.encode(cose).hex(), "auth_data": signed.hex(),
        "client_hash": challenge.hex(), "signature": signature.hex()}
    application, head = b"a" * 32, b"\x01\x00\x00\x00\x01"
    u2f = {"kind": "u2f", "source_serial": "source", "seed_relation": relation,
        "handle": (b"foreign-U2F" * 4).hex(), "public_key": key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex(),
        "application": application.hex(), "challenge": challenge.hex(), "auth_head": head.hex(),
        "signature": key.sign(application + head + challenge, ec.ECDSA(hashes.SHA256())).hex()}
    return [fido, u2f]


class Hid(Tokens):
    descriptor = {"serial_number": "target"}

    def __init__(self, accept=False):
        super().__init__()
        self.u2f_peer = U2f()
        if accept:
            key = ec.derive_private_key(777, ec.SECP256R1())
            entries = [foreign_references.validate(row) for row in bundle()]
            fido, u2f = entries
            self.records[fido["credential_id"]] = {"key": key, "rp": fido["rp"], "alg": -7, "resident": False, "user": {"id": b"origin"}, "ext": {}, "blob": b""}
            self.credential_counts[fido["credential_id"]] = 0
            self.u2f_peer.handles[u2f["handle"]] = {"key": key, "application": u2f["application"], "counter": 0}

    def transfer(self, command, wire, deadline, observe):
        if command == 3:
            return self.u2f_peer.transfer(command, wire, deadline, observe)
        return super().transfer(command, wire, deadline, observe)


@pytest.mark.parametrize("accept,relation", [(False, "distinct"), (True, "distinct"), (True, "same"), (True, "unknown")])
def test_foreign_reference_isolation_and_explicit_seed_portability(tmp_path, accept, relation):
    trace = Trace(tmp_path / "foreign-references", {})
    entries = tuple(foreign_references.validate(row) for row in bundle(relation))
    session = Session(trace, hid=Hid(accept), profile="rsk", options=Options(exercise=True, touch=True, pin="fixture-PIN", foreign_references=entries))
    oracle.execute(session, ["foreign-references"])
    trace.finish()
    failures = [(row["scenario_id"], row["reason"]) for row in trace.cases if row["verdict"] == "fail"]
    if accept and relation == "distinct":
        assert len(failures) == 2 and all("distinct source" in reason for _, reason in failures), failures
    else:
        assert len(trace.cases) == 2 and all(row["verdict"] == "pass" for row in trace.cases), failures


@pytest.mark.parametrize("mutation", ["signature", "RP", "serial", "kind", "shape", "size"])
def test_foreign_bundle_validation_precedes_discovery(tmp_path, monkeypatch, mutation):
    values = bundle()
    if mutation == "signature":
        values[0]["signature"] = "00" * 70
    elif mutation == "RP":
        values[0]["rp"] = "different.oracle.invalid"
    elif mutation == "serial":
        values[0]["source_serial"] = ""
    elif mutation == "kind":
        values[0]["kind"] = "wallet"
    elif mutation == "shape":
        values[0] = None
    else:
        values = "x" * (foreign_references.MAX_BUNDLE_BYTES + 1)
    source = tmp_path / "foreign.json"
    source.write_text(json.dumps(values))
    monkeypatch.setattr(oracle, "inventory", lambda: pytest.fail("invalid public reference attempted physical discovery"))
    assert oracle.main(["capture", "--hid", "never-open", "--out", str(tmp_path / "capture"), "--foreign-references", str(source)]) == 2


def test_same_device_serial_cannot_be_claimed_as_a_foreign_key(tmp_path):
    entries = bundle()
    for entry in entries:
        entry["source_serial"] = "target"
    trace = Trace(tmp_path / "same-device", {})
    session = Session(trace, hid=Hid(), profile="rsk", options=Options(exercise=True, touch=True,
        foreign_references=tuple(foreign_references.validate(entry) for entry in entries)))
    oracle.execute(session, ["foreign-references"])
    trace.finish()
    assert len(trace.cases) == 2 and not trace.exchanges
    assert all(row["applicability"] == "blocked_by_precondition" for row in trace.cases)


def test_offline_catalog_expands_every_supplied_reference_without_discovery(tmp_path, monkeypatch, capsys):
    entries = bundle() + bundle("same") + bundle("unknown")
    source, destination = tmp_path / "foreign.json", tmp_path / "catalog.json"
    source.write_text(json.dumps(entries))
    for name in ("inventory", "Hid", "Pcsc"):
        monkeypatch.setattr(oracle, name, lambda *args, **kwargs: pytest.fail("offline catalog attempted device access"))
    assert oracle.main(["plan", "--suite", "foreign-references", "--foreign-references", str(source), "--out", str(destination)]) == 0
    assert json.loads(capsys.readouterr().out)["cases"] == len(entries)
    cases = json.loads(destination.read_text())["cases"]
    assert len({row["scenario_id"] for row in cases}) == len(entries)
    assert not destination.with_name("events.jsonl").exists()
