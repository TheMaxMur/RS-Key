# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Drive stateful suite entry points with functional peers and directed defects."""
import hashlib
import hmac
import json

import pytest

import oracle
from oracle_lib import codec, management_cases, negative, oath_states, transport_cases
from oracle_lib.runner import Options, Session
from oracle_lib.trace import Reply, Trace, recover
from oracle_lib.transport import Hid


class OathStateCard:
    layer = "pcsc_apdu"

    def __init__(self, defect=None):
        self.defect = defect
        self.records = {}
        self.key = None
        self.authenticated = False
        self.counter = 0
        self.challenge = bytes(8)
        self.previous_challenge = bytes(8)
        self.requests = []

    def transfer(self, request, deadline, observe):
        self.requests.append(request)
        observe("tx", request)
        ins, p1, p2 = request[1:4]
        data = request[5:5 + request[4]] if len(request) > 4 else b""
        status, result = 0x9000, b""
        if ins == 0xA4:
            self.counter += 1
            self.previous_challenge, self.challenge = self.challenge, self.counter.to_bytes(8, "big")
            self.authenticated = False
            result = codec.tlv(0x79, b"\x05\x08\x00") + codec.tlv(0x71, b"oracleid")
            if self.key:
                result += codec.tlv(0x74, self.challenge) + codec.tlv(0x7B, b"\x01")
        elif self.key and not self.authenticated and ins not in (0xA3, 4) and self.defect != "ACL-bypass":
            status = 0x6982
        elif ins == 3:
            fields = dict(codec.parse_tlv(data))
            key = fields[0x73]
            if key:
                assert fields[0x75] == hmac.digest(key[1:], fields[0x74], "sha1")
            self.key, self.authenticated = key[1:] if key else None, False
        elif ins == 0xA3:
            fields = dict(codec.parse_tlv(data))
            good = self.key and fields[0x75] == hmac.digest(self.key, self.challenge, "sha1")
            stale = self.defect == "replay" and self.key and fields[0x75] == hmac.digest(self.key, self.previous_challenge, "sha1")
            if not (good or stale):
                self.authenticated, status = False, 0x6A80
            else:
                self.authenticated = True
                result = codec.tlv(0x75, hmac.digest(self.key, fields[0x74], "sha1"))
        elif ins == 1:
            increasing = data.endswith(b"\x78\x01")
            try:
                fields = dict(codec.parse_tlv(data[:-2] if increasing else data))
            except ValueError:
                fields = {}
            name, key = fields.get(0x71), fields.get(0x73)
            if not name or len(name) > 64 or not key or len(key) < 3 or key[0] != 0x21 or key[1] not in (6, 8):
                if self.defect == "delete-on-refusal" and name in self.records:
                    del self.records[name]
                status = 0x6A80
            else:
                self.records[name] = [key, increasing, -1]
        elif ins == 0xA1:
            result = b"".join(codec.tlv(0x72, entry[0][:1] + name) for name, entry in self.records.items())
        elif ins == 2:
            name = dict(codec.parse_tlv(data))[0x71]
            if name not in self.records:
                status = 0x6A82
            else:
                del self.records[name]
        elif ins == 5:
            fields = codec.parse_tlv(data)
            old, new = fields[0][1], fields[1][1]
            if old not in self.records or new in self.records:
                status = 0x6A80
            else:
                self.records[new] = self.records.pop(old)
        elif ins == 0xA2:
            fields = dict(codec.parse_tlv(data))
            entry = self.records.get(fields[0x71])
            if entry is None:
                status = 0x6A82
            else:
                key, increasing, previous = entry
                counter = int.from_bytes(fields[0x74], "big")
                if increasing and counter < previous and self.defect != "increasing-bypass":
                    status = 0x6985
                else:
                    digest = hmac.digest(key[2:], fields[0x74], "sha1")
                    offset = digest[-1] & 15
                    number = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % (10 ** key[1])
                    result = codec.tlv(0x76, key[1:2] + number.to_bytes(4, "big"))
                    entry[2] = max(previous, counter)
        elif ins == 4:
            if (p1, p2) != (0xDE, 0xAD):
                status = 0x6B00
            elif self.defect != "reset-noop":
                self.records.clear()
                self.key = None
        else:
            raise AssertionError(f"unexpected INS {ins:02x}")
        response = result + status.to_bytes(2, "big")
        observe("rx", response)
        return Reply(response, "success" if status == 0x9000 else "applet_error", status)


@pytest.mark.parametrize("defect,assertion", [(None, None), ("ACL-bypass", "locked-list refused"),
    ("replay", "stale-proof refused"), ("delete-on-refusal", "names preserved after refusal"),
    ("increasing-bypass", "decreasing-challenge refused"), ("reset-noop", "RESET empties records")])
def test_oath_state_cases_detect_the_intended_defect(tmp_path, defect, assertion):
    card = OathStateCard(defect)
    trace = Trace(tmp_path / "state", {"backend": "synthetic"})
    session = Session(trace, card=card, options=Options(exercise=True, allow_effects=("config_change", "applet_reset")))
    oracle.execute(session, ["oath-states"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if assertion is None:
        assert not failures
        assert len(trace.cases) > 1 and all(row["verdict"] == "pass" for row in trace.cases)
        assert card.key is None and not card.records
        transitions = [json.loads(line) for line in (tmp_path / "state/events.jsonl").read_text().splitlines()
                       if json.loads(line)["record_type"] == "state_transition"]
        witnessed = [row for row in transitions if row["basis"] == "explicit witness assertions"]
        assert witnessed and all(row["trigger"] in row["evidence"] for row in witnessed)
    else:
        assert any(assertion in " ".join([row["reason"], *row.get("causes", [])]) for row in failures), failures


def test_privileged_effect_gate_precedes_all_io(tmp_path):
    trace = Trace(tmp_path / "effects", {})
    card = OathStateCard()
    session = Session(trace, card=card, options=Options(exercise=True))
    oath_states.access(session)
    oath_states.reset(session)
    trace.finish()
    assert not card.requests
    assert all(row["applicability"] == "excluded_by_mode" for row in trace.cases)


@pytest.mark.parametrize("permitted", [False, True])
def test_effect_permissions_are_wired_through_capture_CLI(tmp_path, monkeypatch, capsys, permitted):
    class Card(OathStateCard):
        atr = b"synthetic"

        def transfer(self, request, deadline, observe):
            from oracle_lib.runner import AIDS
            if request[1] == 0xA4 and request[5:5 + request[4]] != AIDS["oath"]:
                self.requests.append(request)
                observe("tx", request)
                observe("rx", b"\x6a\x82")
                return Reply(b"\x6a\x82", "applet_error", 0x6A82)
            return super().transfer(request, deadline, observe)

        def initialize(self, trace, timeout):
            pass

        def close(self):
            pass

    card = Card()
    monkeypatch.setattr(oracle, "EmuCard", lambda *args: card)
    argv = ["capture", "--emu-card", "synthetic.invalid:1", "--out", str(tmp_path / "CLI"),
            "--suite", "oath-states", "--exercise"]
    if permitted:
        argv += ["--allow-effect", "config_change", "--allow-effect", "applet_reset"]
    assert oracle.main(argv) == 0
    operations = {request[1] for request in card.requests}
    if permitted:
        assert {3, 4} <= operations
    else:
        assert not {3, 4} & operations
    result = recover(tmp_path / "CLI")
    assert result["manifest"]["allowed_effects"] == (["config_change", "applet_reset"] if permitted else [])
    assert not card.records and card.key is None
    capsys.readouterr()


def test_catalog_uses_normal_dispatch_without_enumeration(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline catalog attempted device I/O")
    monkeypatch.setattr(oracle, "inventory", forbidden)
    monkeypatch.setattr(oracle, "Hid", forbidden)
    monkeypatch.setattr(oracle, "Pcsc", forbidden)
    monkeypatch.setattr(oracle, "OtpFeature", forbidden)
    destination = tmp_path / "catalog.json"
    assert oracle.main(["plan", "--out", str(destination)]) == 0
    result = json.loads(destination.read_text())
    names = {row["scenario_id"] for row in result["cases"]}
    assert {"oath.transition.access-code", "fido.transition.pin-change", "piv.transition.pin-policy.always",
            "transport.assembly.missing-continuation", "rsk.audit.checkpoint", "management.transition.lock.card"} <= names
    assert all(row["applicability"] == "not_run" for row in result["cases"])
    assert {row["coverage"] for row in result["coverage"]["families"]} == {"implemented_not_run"}
    assert all(row["executed"] == row["passed"] == 0 for row in result["coverage"]["families"])
    assert any(row["profile"] == "OnlyKey" and row["vendor_catalog_status"] == "unknown"
               for row in result["coverage"]["external_profiles"])
    assert not (tmp_path / "events.jsonl").exists()
    capsys.readouterr()


def test_wallet_catalog_excludes_card_vendor_and_raw_fault_suites(tmp_path, capsys):
    destination = tmp_path / "wallet.json"
    assert oracle.main(["plan", "--profile", "trezor", "--out", str(destination)]) == 0
    names = {row["scenario_id"] for row in json.loads(destination.read_text())["cases"]}
    assert "vendor.profile-exclusion" in names
    assert "transport.profile-exclusion" in names
    assert not any(name.startswith(("negative.piv.", "negative.oath.", "rsk.transition.", "card.selection.")) for name in names)
    capsys.readouterr()


class RejectingCtap:
    layer = "hid_report"

    def __init__(self, defect=False):
        self.defect = defect

    def transfer(self, command, data, deadline, observe):
        observe("tx", data)
        if data[0] == 4:
            body, status = codec.encode({1: ["FIDO_2_1"]}), 0
        else:
            body, status = b"", 0 if self.defect else 0x12
        response = bytes([status]) + body
        observe("rx", response)
        return Reply(response, "success" if status == 0 else "applet_error", status)


@pytest.mark.parametrize("accept_invalid", [False, True])
def test_structural_corpus_has_real_rejection_and_recovery_checks(tmp_path, accept_invalid):
    trace = Trace(tmp_path / "negative", {})
    session = Session(trace, hid=RejectingCtap(accept_invalid), options=Options(exercise=True))
    session.values["fido.info"] = {1: ["FIDO_2_1"]}
    negative.fido(session)
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if accept_invalid:
        assert failures and all("structurally invalid CTAP input refused" in row["reason"] for row in failures)
    else:
        assert not failures
        assert all(row["verdict"] == "pass" for row in trace.cases)
        assert all(exchange["timing"]["response_latency_ns"] is not None for exchange in recover(tmp_path / "negative")["exchanges"])


def test_recovery_check_does_not_insert_a_hidden_capability_probe(tmp_path):
    trace = Trace(tmp_path / "explicit-steps", {})
    session = Session(trace, hid=RejectingCtap(), options=Options(exercise=True))
    oracle.execute(session, ["negative"])
    trace.finish()
    first = trace.cases[0]
    exchanges = {row["exchange_id"]: row for row in trace.exchanges}
    assert [exchanges[key]["command"] for key in first["exchanges"]] == ["ctap.01", "ctap.04"]
    assert first["verdict"] == "pass"


def test_non_shortest_integer_probe_is_actually_noncanonical(tmp_path):
    trace = Trace(tmp_path / "encoding", {})
    session = Session(trace, hid=RejectingCtap())
    negative.fido(session)
    trace.finish()
    case = next(row for row in trace.cases if row["scenario_id"] == "encoding.getinfo.non-shortest-key")
    exchange = next(row for row in trace.exchanges if row["exchange_id"] == case["exchanges"][0])
    encoded = bytes.fromhex(exchange["request"]["hex"])[1:]
    assert codec.encode(codec.decode(encoded)) != encoded


class ReportPeer:
    def __init__(self, defect=False):
        self.pending, self.replies = None, []
        self.defect = defect

    def write(self, data):
        frame = data[1:]
        cid, marker = frame[:4], frame[4]
        error = None
        if marker & 0x80:
            command, total = marker & 127, int.from_bytes(frame[5:7], "big")
            if command == 6 and total != 8:
                error = 3
            elif total > 7609:
                error = 3
            else:
                self.pending = [cid, command, total, bytearray(frame[7:7 + min(total, 57)]), 0]
        elif self.pending:
            if marker != self.pending[4]:
                error = 4
            else:
                remaining = self.pending[2] - len(self.pending[3])
                self.pending[3].extend(frame[5:5 + min(remaining, 59)])
                self.pending[4] += 1
        if error is not None:
            self.replies += transport_cases.reports(cid, 0x3F, bytes([1 if self.defect else error]))
            self.pending = None
        elif self.pending and len(self.pending[3]) == self.pending[2]:
            cid, command, _, payload, _ = self.pending
            if command == 6:
                payload = payload + cid + b"\x02\x01\x00\x00\x04"
            self.replies += transport_cases.reports(cid, command, bytes(payload))
            self.pending = None
        return len(data)

    def read(self, length, timeout):
        if not self.replies and self.pending:
            cid = self.pending[0]
            self.pending = None
            self.replies += transport_cases.reports(cid, 0x3F, b"\x05")
        return self.replies.pop(0) if self.replies else b""


@pytest.mark.parametrize("wrong_error", [False, True])
def test_raw_report_faults_pass_through_real_adapter(tmp_path, wrong_error):
    trace = Trace(tmp_path / "reports", {})
    hid = Hid({}, trace.now, ReportPeer(wrong_error))
    hid.cid = b"\x00\x00\x00\x01"
    session = Session(trace, hid=hid, profile="rsk")
    oracle.execute(session, ["transport"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if wrong_error:
        assert failures and any("bad INIT length error" in row["reason"] for row in failures)
    else:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases)


def test_transition_cannot_cite_a_different_case(tmp_path):
    trace = Trace(tmp_path / "evidence", {})
    session = Session(trace, hid=RejectingCtap())
    with session.case("producer"):
        session.ctap_value(session.ctap(4))
    with session.case("unrelated"):
        session.transition("state", "before", "after", "exchange-1", ["exchange-1"])
    trace.finish()
    assert trace.cases[-1]["verdict"] == "fail"
    assert "current case" in trace.cases[-1]["reason"]


class ManagementPeer:
    layer = "pcsc_apdu"
    broken = False

    def __init__(self, bypass=None):
        self.bypass = bypass
        self.lock = None
        self.calls = []
        self.original = {1: b"\x02\x3b", 2: b"\x00\x00\x00\x01", 3: b"\x02\x3b", 4: b"\x01", 5: b"\x05\x08\x00"}

    def read(self):
        body = b"".join(codec.tlv(tag, value) for tag, value in {**self.original, 10: bytes([self.lock is not None])}.items())
        return bytes([len(body)]) + body

    def write(self, writer, fields):
        parsed = dict(codec.parse_tlv(fields))
        if self.lock and parsed.get(11) != self.lock and self.bypass != writer:
            return False
        if any(tag not in (10, 11) for tag in parsed):
            return False
        if 10 in parsed:
            if len(parsed[10]) != 16:
                return False
            self.lock = parsed[10] if any(parsed[10]) else None
        return True

    def transfer(self, *args):
        if len(args) == 3:
            request, _, observe = args
            writer = "card"
            ins = request[1]
            command, payload = ("select", b"") if ins == 0xA4 else ("read", b"") if ins == 0x1D else ("write", request[6:6 + request[5]])
        else:
            command, payload, _, observe = args
            writer = "hid"
            if command == 0x10:
                fields = codec.decode(payload[1:])
                assert payload[0] == 0x41 and fields[1] == 12
                writer, command, payload = "fido", "write", fields[2][2]
            else:
                command = "read" if command == 0x42 else "write"
                payload = payload[1:1 + payload[0]] if payload else b""
        return self.reply(writer, command, payload, observe)

    def reply(self, writer, command, payload, observe):
        self.calls.append((writer, command, payload))
        observe("tx", payload)
        accepted = command != "write" or self.write(writer, payload)
        body = self.read() if command == "read" else b""
        if writer == "card":
            status = 0x9000 if accepted else 0x6986
            body += status.to_bytes(2, "big")
        elif writer == "fido":
            status = 0 if accepted else 0x30
            body = bytes([status]) + body
        else:
            status = None if accepted else 1
        observe("rx", body)
        return Reply(body, "success" if accepted else "applet_error", status)


class ManagementOtp:
    layer = "hid_report"
    broken = False

    def __init__(self, peer):
        self.peer = peer

    def transfer(self, command, payload, expected, deadline, observe):
        if command == 0x13:
            return self.peer.reply("otp", "read", b"", observe)
        return self.peer.reply("otp", "write", payload[1:1 + payload[0]], observe)


@pytest.mark.parametrize("bypass", [None, "card", "hid", "otp", "fido"])
def test_configuration_lock_each_writer_detects_its_own_bypass(tmp_path, bypass):
    trace = Trace(tmp_path / "locks", {})
    peer = ManagementPeer(bypass)
    session = Session(trace, card=peer, hid=peer, otp_hid=ManagementOtp(peer), profile="rsk",
                      options=Options(exercise=True, touch=True, allow_effects=("config_change",)))
    session.values["fido.info"] = {4: {"clientPin": False}}
    oracle.execute(session, ["management-states"])
    trace.finish()
    failures = [row for row in trace.cases if row["verdict"] == "fail"]
    if bypass is None:
        assert not failures, failures
        assert all(row["verdict"] == "pass" for row in trace.cases)
    else:
        assert any(row["scenario_id"] == "management.transition.lock." + bypass and
                   "unlock cannot clear lock" in row["reason"] for row in failures), failures
    assert peer.lock is None


def test_new_PIN_change_case_cannot_touch_wallet(tmp_path):
    from oracle_lib import fido_states
    trace = Trace(tmp_path / "wallet-guard", {})
    peer = RejectingCtap()
    session = Session(trace, hid=peer, profile="trezor",
                      options=Options(exercise=True, touch=True, pin="fixture-pin", allow_effects=("pin_change",)))
    fido_states.pin_change(session)
    trace.finish()
    assert not trace.exchanges
    assert trace.cases[0]["applicability"] == "excluded_by_profile"


@pytest.mark.parametrize("applet,ins,reference,status", [("openpgp", 0x24, 0x81, 0x6982),
    ("piv", 0x24, 0x80, 0x63C2), ("piv", 0x2C, 0x80, 0x63C2), ("oath", 0xB2, 0, 0x63C2),
    ("oath", 0xB3, 0, 0x63C2)])
def test_refused_secret_change_and_OTP_PIN_stop_future_attempts(tmp_path, applet, ins, reference, status):
    class Refusing:
        layer = "pcsc_apdu"
        calls = 0

        def transfer(self, request, deadline, observe):
            self.calls += 1
            observe("tx", request)
            return Reply(status.to_bytes(2, "big"), "applet_error", status)

    trace = Trace(tmp_path / "retry-budget", {})
    card = Refusing()
    session = Session(trace, card=card)
    session.applet = applet
    for index in range(2):
        with session.case(f"attempt-{index}"):
            session.observe("status", session.apdu(codec.apdu(ins, p2=reference, data=b"fixture")).status)
    trace.finish()
    assert card.calls == 1
    assert trace.cases[1]["applicability"] == "blocked_by_precondition"
