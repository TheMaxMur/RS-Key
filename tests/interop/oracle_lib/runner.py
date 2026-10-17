# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Named Python scenarios share capture, policy, and assertion handling."""
import hashlib
import sys
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from enum import Enum

from . import codec
from .trace import CaptureError, Outcome, TransferError, json_value
from .transport import HID_CBOR, HID_INIT, HID_MSG, HID_PING

AIDS = {
    "fido": bytes.fromhex("a0000006472f0001"),
    "management": bytes.fromhex("a000000527471117"),
    "oath": bytes.fromhex("a000000527210101"),
    "otp": bytes.fromhex("a000000527200101"),
    "piv": bytes.fromhex("a000000308000010000100"),
    "openpgp": bytes.fromhex("d27600012401"),
    "rescue": bytes.fromhex("a0583fc19b7e4f21"),
    "vendor": bytes.fromhex("f000000001"),
    "canokey_admin": bytes.fromhex("f000000000"),
    "ndef": bytes.fromhex("d2760000850101"),
    "hsmauth": bytes.fromhex("a000000527210701"),
}

RESTRICTED_EFFECTS = ("pin_change", "pin_attempts", "applet_reset", "config_change", "otp_both_slots", "otp_extra_slots",
                      "replace_identity", "seed_change", "reboot", "capacity", "storage_setup")


class CtapRoute(Enum):
    HID = "hid"
    CARD = "card"


class SkipCase(Exception):
    def __init__(self, reason, applicability="blocked_by_precondition", expected_cause=None):
        super().__init__(reason)
        self.applicability = applicability
        self.expected_cause = expected_cause


@dataclass
class Options:
    exercise: bool = False
    touch: bool = False
    timeout: float = 15
    seed: str = "rs-key-oracle-v1"
    pin: str | None = None
    piv_pin: str | None = None
    openpgp_pin: str | None = None
    openpgp_admin: str | None = None
    management_key: bytes | None = None
    oath_password: str | None = None
    piv_puk: str | None = None
    oath_pin: str | None = None
    openpgp_reset_code: str | None = None
    operator: bool = False
    recovery_layout: str | None = None
    features: tuple = ()
    otp_slot: int = 2
    allow_effects: tuple = ()


class Case(AbstractContextManager):
    def __init__(self, session, name, families, effects, needs_touch, parameters=None, method="explicit"):
        self.session, self.name = session, name
        self.families, self.effects, self.needs_touch = list(families), list(effects), needs_touch
        self.parameters, self.method = parameters or {}, method

    def __enter__(self):
        session = self.session
        if session.trace.case is not None:
            raise ValueError("nested scenarios are not supported")
        session.trace.case = self.name
        session.current = self
        session.event_evidence = None
        self.assertions, self.observations = [], {}
        self.first_exchange = len(session.trace.exchanges)
        self.started_ns = session.trace.now()
        session.trace.emit("scenario_started", families=self.families, effects=self.effects,
                           parameters=self.parameters, coverage_method=self.method)
        if not session.planning and self.needs_touch and session.options.touch and (not self.effects or session.options.exercise):
            print(f"oracle: {self.name} — confirm on the selected device when requested", file=sys.stderr)
        return self

    def require(self):
        if self.session.planning:
            raise SkipCase("catalog only; no transport opened", "not_run")
        if self.effects and not self.session.options.exercise:
            raise SkipCase("fixture writes require --exercise", "excluded_by_mode")
        restricted = set(self.effects) & set(RESTRICTED_EFFECTS)
        missing = restricted - set(self.session.options.allow_effects)
        if missing:
            raise SkipCase("requires --allow-effect " + ", ".join(sorted(missing)), "excluded_by_mode")
        if self.needs_touch and not self.session.options.touch:
            raise SkipCase("operator interaction requires --touch", "excluded_by_mode")
        if self.session.broken and not self.session.recovering:
            raise SkipCase("a preceding transport failure left session state unknown")

    def __exit__(self, kind, error, traceback):
        session = self.session
        result = {"scenario_id": self.name, "sample": session.trace.sample,
                  "scenario_revision": 1,
                  "timing": {"start_ns": self.started_ns, "end_ns": session.trace.now()},
                  "families": self.families, "effects": self.effects,
                  "parameters": self.parameters, "coverage_method": self.method,
                  "assertions": self.assertions, "observations": self.observations,
                  "exchanges": [e["exchange_id"] for e in session.trace.exchanges[self.first_exchange:]],
                  "verdict": "pass", "applicability": "applicable", "reason": None}
        if isinstance(error, SkipCase):
            result.update(verdict="inconclusive", applicability=error.applicability, reason=str(error))
        elif error:
            result.update(verdict="fail", reason=f"{kind.__name__}: {error}")
            if isinstance(error, TransferError):
                session.broken |= error.outcome in (Outcome.DEADLINE, Outcome.DISCONNECTED)
        propagate = None
        if error:
            causes, context = [], error.__context__
            while context is not None and len(causes) < 8:
                causes.append(f"{type(context).__name__}: {context}")
                context = context.__context__
            result["causes"] = causes
            context = error.__context__
            while isinstance(error, SkipCase) and context is not None:
                if context is error.expected_cause:
                    context = context.__context__
                    continue
                if isinstance(context, (CaptureError, KeyboardInterrupt, SystemExit)):
                    propagate = context
                if not isinstance(context, SkipCase) and not (isinstance(context, TransferError) and context.outcome == Outcome.HOST_REJECTED):
                    result.update(verdict="fail", applicability="applicable",
                                  reason=f"{type(context).__name__}: {context}; cleanup/precondition: {error}")
                    break
                context = context.__context__
        elif not self.assertions and not self.observations:
            result.update(verdict="inconclusive", reason="no property was checked")
        try:
            session.trace.cases.append(result)
            session.trace.emit("scenario_finished", result=result)
            session.trace.flush()
        finally:
            session.trace.case = None
            session.current = None
            session.trace.phase = "probe"
        if propagate is not None:
            raise propagate
        return error is not None and not isinstance(error, (CaptureError, KeyboardInterrupt, SystemExit))


class Session:
    def __init__(self, trace, hid=None, card=None, profile="generic", options=None, otp_hid=None):
        self.trace, self.hid, self.card, self.profile = trace, hid, card, profile
        self.options = options or Options()
        self.initial_pin = self.options.pin
        self.otp_hid = otp_hid
        self.current = None
        self.broken = False
        self.values = {}
        self.failed_auth = set()
        self.applet = None
        self.states = {}
        self.planning = False
        self.attempt_budget = None
        self.event_evidence = None
        self.keyboard = None
        self.ctap_route = CtapRoute.HID
        self.recovering = False

    @contextmanager
    def route(self, route):
        if not isinstance(route, CtapRoute):
            raise ValueError("CTAP route must be typed")
        previous, self.ctap_route = self.ctap_route, route
        try:
            yield
        finally:
            self.ctap_route = previous

    @contextmanager
    def attempts(self, domain, limit):
        self._gate()
        self.require(self.profile != "trezor", "bounded PIN failures excluded on wallet device", "excluded_by_profile")
        self.require(self.current is not None and "pin_attempts" in self.current.effects,
                     "intentional failures require the pin_attempts case effect")
        if self.attempt_budget is not None or not 1 <= limit <= 32:
            raise ValueError("PIN attempt budget must be non-nested and between 1 and 32")
        self.require(domain not in self.failed_auth, "a preceding unplanned failure left this secret unverified")
        budget = {"domain": domain, "remaining": limit, "used": 0}
        self.attempt_budget = budget
        self.trace.emit("authorization_budget_started", domain=str(domain), limit=limit)
        try:
            yield
        finally:
            self.trace.emit("authorization_budget_finished", domain=str(domain), used=budget["used"], limit=limit)
            self.attempt_budget = None

    def _attempt(self, domain):
        budget = self.attempt_budget
        if budget is not None and budget["domain"] == domain:
            self.require(budget["remaining"] > 0, "explicit PIN attempt budget exhausted")
            budget["remaining"] -= 1
            budget["used"] += 1
            self.trace.emit("authorization_attempt", domain=str(domain), ordinal=budget["used"], remaining=budget["remaining"])
        else:
            self.require(domain not in self.failed_auth, "this PIN reference already refused a supplied secret; further attempts are blocked")

    def _auth_result(self, domain, failed, succeeded):
        if failed:
            self.failed_auth.add(domain)
            self.trace.emit("authorization_stopped", domain=str(domain))
        elif succeeded and self.attempt_budget is not None and self.attempt_budget["domain"] == domain:
            self.failed_auth.discard(domain)
            self.trace.emit("authorization_recovered", domain=str(domain))

    def case(self, name, families=(), effects=(), touch=False, parameters=None, method="explicit"):
        return Case(self, name, families, effects, touch, parameters, method)

    def require(self, condition, reason, applicability="blocked_by_precondition"):
        self._gate()
        if not condition:
            raise SkipCase(reason, applicability)

    def check(self, name, actual, expected=True):
        if self.current is None:
            raise ValueError("assertion outside a scenario")
        result = {"name": name, "actual": json_value(actual), "expected": json_value(expected),
                  "verdict": "pass" if actual == expected else "fail",
                  "evidence": self.event_evidence or (self.trace.exchanges[-1]["exchange_id"] if self.trace.exchanges else None)}
        self.current.assertions.append(result)
        self.trace.emit("assertion", **result)
        if actual != expected:
            raise AssertionError(f"{name}: got {repr(actual)[:160]}, expected {repr(expected)[:160]}")

    def observe(self, name, value, comparison="exact"):
        if self.current is None:
            raise ValueError("observation outside a scenario")
        observation = {"value": json_value(value), "comparison": comparison}
        self.current.observations[name] = observation
        self.trace.emit("observation", name=name, **observation)

    def bind(self, name, value):
        self.values[name] = value
        self.trace.emit("binding", name=name, value=value,
                        producer=self.trace.exchanges[-1]["exchange_id"] if self.trace.exchanges else None)
        return value

    def state(self, name, value):
        previous = self.states.get(name, "unknown")
        self.states[name] = value
        self.trace.emit("state_transition", state=name, previous=previous, current=value,
                        evidence=self.trace.exchanges[-1]["exchange_id"] if self.trace.exchanges else None,
                        basis="derived from the recorded exchange outcome; readback checks are separate")

    def transition(self, name, before, after, trigger, witnesses):
        """A witnessed transition must cite actual exchanges in this invocation."""
        available = {e["exchange_id"] for e in self.trace.exchanges[self.current.first_exchange:]}
        if not witnesses or not set(witnesses).issubset(available) or trigger not in available:
            raise ValueError("state transition requires exchange evidence from the current case")
        self.states[name] = after
        self.trace.emit("state_transition", state=name, previous=before, current=after,
                        trigger=trigger, evidence=list(witnesses), basis="explicit witness assertions")

    def evidence(self):
        return self.trace.exchanges[-1]["exchange_id"]

    def fixture(self, name, length=32):
        output, counter = b"", 0
        while len(output) < length:
            output += hashlib.sha256(f"{self.options.seed}:{name}:{counter}".encode()).digest()
            counter += 1
        return output[:length]

    def _gate(self):
        if self.current:
            self.current.require()

    def _exchange(self, *args):
        self.event_evidence = None
        try:
            return self.trace.exchange(*args)
        except TransferError as error:
            self.broken |= error.outcome != Outcome.HOST_REJECTED or error.transmitted
            raise

    def hid_call(self, command, data=b"", name=None):
        self._gate()
        self.require(self.hid is not None, "no selected HID transport", "excluded_by_mode")
        pin_attempt = False
        if command == HID_CBOR and data[:1] == b"\x06":
            try:
                fields = codec.decode(data[1:])
                pin_attempt = isinstance(fields, dict) and fields.get(2) in (4, 5, 9)
            except (ValueError, TypeError):
                pass
        if pin_attempt:
            self._attempt("fido.pin")

        def transfer(deadline, observe):
            if self.profile == "trezor":
                if command not in (HID_INIT, HID_PING, HID_CBOR, HID_MSG, 0x08, 0x11):
                    raise TransferError("Trezor profile permits FIDO/U2F commands only", Outcome.HOST_REJECTED)
                if command == HID_CBOR and (not data or data[0] not in (1, 2, 4, 6, 7, 8, 9, 10, 11, 12, 13)):
                    raise TransferError("Trezor vendor/wallet command refused", Outcome.HOST_REJECTED)
                if command == HID_CBOR and data[0] == 6:
                    try:
                        fields = codec.decode(data[1:])
                    except (ValueError, TypeError) as error:
                        raise TransferError("ambiguous clientPIN encoding excluded on wallet device", Outcome.HOST_REJECTED) from error
                    if isinstance(fields, dict) and fields.get(2) in (3, 4):
                        raise TransferError("host PIN changes are excluded on the wallet device", Outcome.HOST_REJECTED)
                if command == HID_MSG and (len(data) < 4 or data[0] != 0 or data[1] not in (1, 2, 3)):
                    raise TransferError("Trezor profile permits U2F APDUs only", Outcome.HOST_REJECTED)
            return self.hid.transfer(command, data, deadline, observe)

        reply = self._exchange("hid", self.hid.layer, name or f"ctaphid.{command:02x}", data,
                               self.options.timeout, transfer)
        if pin_attempt:
            self._auth_result("fido.pin", reply.status in (0x31, 0x32, 0x34, 0x35, 0x3F), reply.protocol == "success")
        return reply

    def ctap(self, command, fields=None, raw=None):
        data = bytes([command]) + (raw if raw is not None else codec.encode(fields) if fields is not None else b"")
        if self.ctap_route == CtapRoute.CARD:
            return self.ctap_card(data)
        name = f"ctap.{command:02x}"
        key = 2 if command == 6 else 1 if command in (10, 13, 0x41) else None
        if isinstance(fields, dict) and isinstance(fields.get(key), int):
            name += f".{fields[key]:02x}"
        reply = self.hid_call(HID_CBOR, data, name)
        if reply.protocol == "success" and len(reply.data) > 1:
            try:
                value = codec.decode(reply.data[1:], lossless=True)
                self.trace.emit("decoded", decoder="oracle.cbor.v1", value=value)
            except (ValueError, TypeError) as error:
                self.trace.emit("decode_error", decoder="oracle.cbor.v1", error=str(error))
        return reply

    def ctap_card(self, data):
        from .trace import Reply
        self._gate()
        self.require(self.profile != "trezor", "wallet profile excludes card FIDO transport", "excluded_by_profile")
        try:
            fields = codec.decode(data[1:]) if data[:1] == b"\x06" else None
        except (ValueError, TypeError):
            fields = None
        pin_attempt = isinstance(fields, dict) and fields.get(2) in (4, 5, 9)
        if pin_attempt:
            self._attempt("fido.pin")
        response = self.apdu(codec.apdu(0x10, data=data, cla=0x80), "ctap.card." + data[:1].hex())
        value = bytearray(response.data[:-2])
        for _ in range(256):
            if response.status >> 8 != 0x61:
                break
            response = self.apdu(codec.apdu(0xC0, le=response.status & 255 or 256), "ctap.card.GET-RESPONSE")
            value.extend(response.data[:-2])
        self.card_value(response)
        self.check("card CTAP response has status byte", len(value) > 0)
        result = Reply(bytes(value), "success" if value[0] == 0 else "applet_error", value[0])
        self.trace.emit("protocol_result", protocol="ctap", status=value[0], evidence=self.evidence(), transport="card")
        self.observe(f"ctap.card.{data[0]:02x}.step-{len(self.trace.exchanges)}.status", value[0])
        if pin_attempt:
            self._auth_result("fido.pin", result.status in (0x31, 0x32, 0x34, 0x35, 0x3F), result.status == 0)
        return result

    def ctap_value(self, reply):
        self.check("CTAP success", (reply.protocol, reply.status), ("success", 0))
        return codec.decode(reply.data[1:]) if len(reply.data) > 1 else {}

    def apdu(self, request, name=None):
        self._gate()
        self.require(self.card is not None, "no selected card transport", "excluded_by_mode")
        ins = request[1] if len(request) > 1 else None
        pin_attempt = len(request) > 5 and (ins in (0x20, 0x24, 0x2C) or self.applet == "oath" and ins in (0xB2, 0xB3))
        if self.applet == "openpgp" and ins == 0x2C and request[2] == 2:
            pin_attempt = False
        self.require(not pin_attempt or self.applet is not None, "select a known applet before submitting a PIN")
        auth_domain = (self.applet, request[3]) if pin_attempt else None
        if pin_attempt and self.applet == "piv" and ins == 0x2C:
            auth_domain = ("piv", 0x81)
        if pin_attempt and self.applet == "oath" and ins in (0xB2, 0xB3):
            auth_domain = ("oath", 0xB2)
        if pin_attempt and self.applet == "openpgp":
            if ins == 0x2C:
                auth_domain = ("openpgp", "reset_code")
            elif request[3] in (0x81, 0x82):
                auth_domain = ("openpgp", 0x81)
        if pin_attempt:
            self._attempt(auth_domain)

        def transfer(deadline, observe):
            if self.profile == "trezor":
                raise TransferError("card/vendor transport excluded on the wallet device", Outcome.HOST_REJECTED)
            return self.card.transfer(request, deadline, observe)

        reply = self._exchange("card", self.card.layer, name or f"apdu.{request[:4].hex()}", request,
                               self.options.timeout, transfer)
        if len(request) >= 5 and request[1:3] == b"\xa4\x04":
            selected = request[5:5 + request[4]]
            matches = [key for key, aid in AIDS.items() if len(selected) >= 5 and (aid.startswith(selected) or selected.startswith(aid))]
            self.applet = matches[0] if reply.status == 0x9000 and len(matches) == 1 else None
            self.state("selected_applet", self.applet if reply.status == 0x9000 else "unknown_after_refused_select")
        if pin_attempt:
            self._auth_result(auth_domain, reply.status & 0xFFF0 == 0x63C0 or reply.status in (0x6982, 0x6983), reply.protocol == "success")
        return reply

    def card_value(self, reply):
        self.check("APDU success", (reply.protocol, reply.status), ("success", 0x9000))
        return reply.data[:-2]

    def otp_call(self, slot, data=b"", expected_len=0):
        self._gate()
        self.require(self.otp_hid is not None, "no selected OTP HID interface", "excluded_by_mode")
        self.require(self.profile != "trezor", "wallet profile excludes OTP HID", "excluded_by_profile")
        self.require(not self.otp_hid.broken, "OTP worker stopped after a preceding API failure")
        request = bytes([slot]) + data if slot >= 0 else b""
        return self._exchange("otp", self.otp_hid.layer, f"otp.hid.{slot:02x}", request, self.options.timeout,
                              lambda deadline, observe: self.otp_hid.transfer(slot, data, expected_len, deadline, observe))

    def select(self, applet, required=False):
        previous = self.trace.phase
        self.trace.phase = previous if previous in ("cleanup", "verify") else "setup"
        try:
            reply = self.apdu(codec.apdu(0xA4, 4, data=AIDS[applet]), f"select.{applet}")
            if reply.protocol == "applet_error" and reply.status in (0x6A82, 0x6D00):
                if required:
                    self.check("previously available applet remains selectable", reply.status, 0x9000)
                raise SkipCase(f"{applet} selection refused: {reply.status:04x}", "unsupported_confirmed")
            return self.card_value(reply)
        finally:
            self.trace.phase = previous

    def close(self):
        for session_id, transport in (("hid", self.hid), ("card", self.card), ("otp", self.otp_hid), ("keyboard", self.keyboard)):
            if transport:
                try:
                    if session_id == "hid" and getattr(transport, "active", False):
                        try:
                            self.trace.exchange("hid", transport.layer, "ctaphid.cancel-on-close", b"", 1, transport.cancel)
                        except TransferError as error:
                            self.trace.emit("cancel_unconfirmed", error=str(error))
                    transport.close()
                    self.trace.emit("session_closed", session_id=session_id)
                except CaptureError:
                    raise
                except Exception as error:
                    self.trace.emit("session_close_error", session_id=session_id, error=str(error))
