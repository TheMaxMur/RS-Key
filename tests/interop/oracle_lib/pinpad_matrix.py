# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Part 10 driver results and selected-applet grants are separate witnesses."""
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from . import codec
from .ccid_cases import ioctl, verify_structure
from .lifecycle import Action, change
from .trace import Outcome, TransferError

REFERENCES = (("piv", 0x80), ("openpgp", 0x81), ("openpgp", 0x82), ("openpgp", 0x83))


def structures(reference):
    base = verify_structure(reference)
    yield "valid", base
    for size in (0, 1, 14, 15, 18, 19, 22):
        yield f"truncated-{size}", base[:size]
    for size in (0, 3, 5, 0xffffffff):
        yield f"declared-{size}", base[:15] + size.to_bytes(4, "little") + base[19:]
    yield "trailing", base + b"\x00"
    for label, offset, value in (("binary-format", 2, 0), ("BCD-format", 2, 1),
            ("PIN-block", 3, 0x48), ("PIN-length-offset", 4, 0x88),
            ("entry-condition", 7, 0xff), ("message-count", 8, 0xff),
            ("CLA", 19, 0x80), ("INS", 20, 0x24), ("P1", 21, 0xff),
            ("reference", 22, 0xff)):
        yield label, base[:offset] + bytes([value]) + base[offset + 1:]


class Grant:
    def __init__(self, session, applet, reference):
        self.session, self.applet, self.reference = session, applet, reference
        self.sdk = self.pin_mode = self.tag = None
        self.key_attempted = self.do_attempted = False
        try:
            self.install(session, applet, reference)
        except BaseException:
            self.restore_partial()
            raise

    def install(self, session, applet, reference):
        self.session, self.applet, self.reference = session, applet, reference
        self.original = self.key = None
        if applet == "piv":
            from yubikit.piv import SLOT, PIN_POLICY, TOUCH_POLICY
            from .piv_lifecycle import fixture_session
            self.sdk = fixture_session(session)
            self.key = ec.derive_private_key(219, ec.SECP256R1())
            self.key_attempted = True
            self.sdk.put_key(SLOT.RETIRED1, self.key, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        else:
            from .openpgp_lifecycle import fixture_session
            self.sdk = fixture_session(session)
            if reference == 0x81:
                from yubikit.openpgp import KEY_REF
                from . import pgp_keys
                self.pin_mode = self.sdk.get_data(0xc4)[0]
                self.sdk.put_data(0xc4, b"\x01")
                self.key = ec.derive_private_key(220, ec.SECP256R1())
                self.key_attempted = True
                pgp_keys.put_key(session, self.sdk, KEY_REF.SIG, self.key)
            else:
                self.tag = 0x0103 if reference == 0x82 else 0x5e
                if reference == 0x82:
                    self.sdk.verify_pin(session.options.openpgp_pin, extended=True)
                self.original = self.sdk.get_data(self.tag)
                self.marker = session.fixture("pinpad.protected-DO", 24)
                self.do_attempted = True
                self.sdk.put_data(self.tag, self.marker)
        session.select("piv" if applet == "openpgp" else "openpgp")
        session.select(applet, required=True)

    def restore_partial(self):
        s = self.session
        if s.broken:
            s.trace.emit("fixture_cleanup_pending", fixture="pinpad grant", reason="setup transport state unknown; no automatic mutation retry")
            return
        if self.sdk is None or not (self.key_attempted or self.do_attempted or self.pin_mode is not None):
            return
        previous, s.trace.phase = s.trace.phase, "cleanup"
        try:
            if self.applet == "piv":
                from yubikit.piv import SLOT
                self.sdk.authenticate(s.options.management_key)
                self.sdk.delete_key(SLOT.RETIRED1)
            else:
                self.sdk.verify_admin(s.options.openpgp_admin)
                if self.key_attempted:
                    from yubikit.openpgp import KEY_REF
                    from . import pgp_keys
                    pgp_keys.delete_key(s, self.sdk, KEY_REF.SIG)
                if self.pin_mode is not None:
                    self.sdk.put_data(0xc4, bytes([self.pin_mode]))
                if self.do_attempted:
                    if self.reference == 0x82:
                        self.sdk.verify_pin(s.options.openpgp_pin, extended=True)
                    self.sdk.put_data(self.tag, self.original)
        finally:
            s.trace.phase = previous

    def authorize(self):
        s = self.session
        if self.applet == "piv":
            self.sdk.verify_pin(s.options.piv_pin)
        elif self.reference == 0x83:
            self.sdk.verify_admin(s.options.openpgp_admin)
        else:
            self.sdk.verify_pin(s.options.openpgp_pin, extended=self.reference == 0x82)

    def probe(self, expected):
        s = self.session
        if self.applet == "piv":
            from yubikit.piv import SLOT, KEY_TYPE
            from yubikit.core.smartcard import ApduError
            try:
                value = ("success", self.sdk.sign(SLOT.RETIRED1, KEY_TYPE.ECCP256,
                    s.fixture("pinpad.signature"), hashes.SHA256()))
            except ApduError as error:
                value = (error.sw, b"")
            if expected:
                s.check("secure PIN grants the protected private operation", value[0], "success")
                self.key.public_key().verify(value[1], s.fixture("pinpad.signature"), ec.ECDSA(hashes.SHA256()))
                s.check("secure PIN private result verifies independently", True)
            else:
                s.check("secure-entry failure cannot create a PIV grant", value[0], 0x6982)
        elif self.reference == 0x81:
            from yubikit.core.smartcard import ApduError
            try:
                signature = self.sdk.sign(s.fixture("pinpad.PGP.signature"), hashes.SHA256())
                status = 0x9000
            except ApduError as error:
                signature, status = None, error.sw
            s.check("secure entry controls the actual PW1-SIG private operation", status, 0x9000 if expected else 0x6982)
            if expected:
                self.key.public_key().verify(signature, s.fixture("pinpad.PGP.signature"), ec.ECDSA(hashes.SHA256()))
                s.check("secure PW1-SIG private result verifies independently", True)
        elif self.reference == 0x82:
            result = s.apdu(codec.apdu(0xca, 1, 3), "pinpad.private-DO.grant-probe")
            s.check("secure-entry PW1-DEC grant controls private DO", result.status, 0x9000 if expected else 0x6982)
            if expected:
                s.check("private DO retained exactly", result.data[:-2], self.marker)
        else:
            result = s.apdu(codec.apdu(0xda, 0, self.tag, self.marker), "pinpad.PW3.protected-write")
            s.check("secure-entry PW3 grant controls protected write", result.status, 0x9000 if expected else 0x6982)

    def close(self):
        s = self.session
        s.trace.phase = "cleanup"
        self.authorize()
        self.probe(True)
        if self.applet == "piv":
            from yubikit.piv import SLOT
            self.sdk.authenticate(s.options.management_key)
            self.sdk.delete_key(SLOT.RETIRED1)
        else:
            self.sdk.verify_admin(s.options.openpgp_admin)
            if self.reference == 0x81:
                from yubikit.openpgp import KEY_REF
                from . import pgp_keys
                pgp_keys.delete_key(s, self.sdk, KEY_REF.SIG)
                self.sdk.put_data(0xc4, bytes([self.pin_mode]))
            else:
                self.sdk.put_data(self.tag, self.original)

    def retries(self):
        if self.applet == "piv":
            return self.sdk.get_pin_metadata().attempts_remaining
        return self.sdk.get_data(0xc4)[6 if self.reference == 0x83 else 4]


def run(session):
    from smartcard.pcsc.PCSCPart10 import CM_IOCTL_GET_FEATURE_REQUEST
    for applet, reference in REFERENCES:
        for standing in (False, True):
            vectors = [(mode, verify_structure(reference)) for mode in ("correct", "cancel-ceremony", "cancel-pad", "timeout")]
            vectors += [("structure-" + label, body) for label, body in structures(reference) if label != "valid"]
            for mode, body in vectors:
                with session.case(f"transport.pinpad-matrix.{applet}.{reference:02x}.grant-{standing}.{mode}",
                        ("T16", "P03" if applet == "piv" else "O02", "G14"),
                        effects=("replace_piv_keys", "write_and_restore_openpgp_DO", "session_recovery") +
                                (("replace_openpgp_sig_key", "config_change") if applet == "openpgp" and reference == 0x81 else ()), touch=True,
                        parameters={"standing_grant": standing, "entry_action": mode, "structure": body}):
                    session.require(session.profile != "trezor", "wallet profile excludes pinpad", "excluded_by_profile")
                    session.require(session.options.operator, "pinpad requires an operator to enter or decline the declared input")
                    session.require(session.profile != "rsk" or "display" in session.options.features, "selected RS-Key build needs a display for secure PIN entry")
                    session.require(mode != "timeout" or session.options.timeout > 130, "timeout witness needs --timeout above the largest panel presence window")
                    secret = session.options.piv_pin if applet == "piv" else session.options.openpgp_admin if reference == 0x83 else session.options.openpgp_pin
                    session.require(secret is not None and secret.isascii() and secret.isdigit(), "panel input needs the known numeric fixture PIN")
                    feature_data = ioctl(session, CM_IOCTL_GET_FEATURE_REQUEST, b"", "pcsc.features")
                    session.check("feature structures are complete six-byte TLVs", len(feature_data) % 6, 0)
                    session.check("feature control widths are four bytes", all(feature_data[i + 1] == 4 for i in range(0, len(feature_data), 6)))
                    features = {feature_data[i]: int.from_bytes(feature_data[i + 2:i + 6], "big") for i in range(0, len(feature_data), 6)}
                    session.require(6 in features, "VERIFY_PIN_DIRECT not exposed by this driver", "unsupported_confirmed")
                    grant = Grant(session, applet, reference)
                    try:
                        if standing:
                            grant.authorize()
                        grant.probe(standing)
                        retries = grant.retries()
                        print(f"oracle: {applet} {reference:02x}: {mode}; use ONLY the declared fixture PIN if entry is offered", file=sys.stderr)
                        session.trace.emit("interaction", action=mode, stage="requested", source="runner", observed_touch_ns=None)
                        try:
                            result = ioctl(session, features[6], body, "pcsc.verify-pin-direct.matrix")
                        except TransferError as error:
                            if not mode.startswith("structure-") or error.outcome not in (Outcome.HOST_REJECTED, Outcome.RUNNER_ERROR):
                                raise
                            session.observe("driver_structure_refusal", {"outcome": error.outcome, "code": error.code}, "presence")
                            session.observe("grant_evidence_limit", "driver refused the control request; reconnect retires prior grant, so its preservation is not inferred")
                            change(session, Action.RECONNECT)
                            session.select(applet, required=True)
                            session.check("driver structure refusal preserves PIN retries", grant.retries(), retries)
                        else:
                            session.check("secure entry returns a complete status word", len(result), 2)
                            sw = int.from_bytes(result, "big")
                            session.observe("driver_secure_status", sw)
                            remaining = grant.retries()
                            if remaining != retries or sw & 0xfff0 == 0x63c0 or sw == 0x6983:
                                session.broken = True
                                session.values["halt_reason"] = "secure-entry request unexpectedly consumed a PIN retry; fixtures retained for explicit recovery"
                                session.check("secure-entry structure/action never submits an unintended wrong PIN", (remaining, sw), (retries, 0x9000))
                            if mode == "correct":
                                session.check("correct secure entry succeeds", sw, 0x9000)
                                grant.probe(True)
                            elif mode in ("cancel-ceremony", "cancel-pad", "timeout"):
                                session.check("secure entry has the requested termination", sw, 0x6400 if mode == "timeout" else 0x6401)
                                grant.probe(standing)
                            else:
                                session.observe("structure_driver_interpretation", "driver may reject, normalize or dispatch this structure; resulting grant is checked against its returned status")
                                grant.probe(sw == 0x9000 or standing)
                    finally:
                        if not session.broken:
                            grant.close()


def properties(session):
    from smartcard.pcsc.PCSCPart10 import CM_IOCTL_GET_FEATURE_REQUEST
    with session.case("transport.pinpad.properties-and-idle-ABORT", ("T16", "P03", "G14"), effects=("replace_piv_keys", "session_recovery")):
        session.require(session.profile != "trezor", "wallet profile excludes pinpad", "excluded_by_profile")
        packed = ioctl(session, CM_IOCTL_GET_FEATURE_REQUEST, b"", "pcsc.features")
        session.check("Part 10 feature list is complete", len(packed) % 6, 0)
        session.check("Part 10 feature control lengths are explicit", all(packed[i + 1] == 4 for i in range(0, len(packed), 6)))
        controls = {packed[i]: int.from_bytes(packed[i + 2:i + 6], "big") for i in range(0, len(packed), 6)}
        session.require(any(tag in controls for tag in (10, 11, 17, 18)), "driver exposes no PIN/display property or abort controls", "unsupported_confirmed")
        grant = Grant(session, "piv", 0x80)
        try:
            grant.authorize()
            pin_properties = tlv_properties = None
            for tag in (10, 17, 18):
                if tag not in controls:
                    continue
                value = ioctl(session, controls[tag], b"", f"pcsc.property.{tag:02x}")
                session.observe(f"Part10.property.{tag:02x}", value)
                session.check("Part 10 property read is stable", ioctl(session, controls[tag], b"", f"pcsc.property.{tag:02x}.repeat"), value)
                if tag == 10:
                    session.check("PIN_PROPERTIES has its four-byte structure", len(value), 4)
                    pin_properties = value
                elif tag == 18:
                    entries = codec.parse_tlv(value)
                    session.check("Part 10 TLV properties have unique tags", len({key for key, _ in entries}), len(entries))
                    tlv_properties = dict(entries)
                    if 6 in tlv_properties and 7 in tlv_properties:
                        minimum, maximum = (int.from_bytes(tlv_properties[key], "little") for key in (6, 7))
                        session.check("driver PIN length limits are coherent", 0 < minimum <= maximum)
                grant.probe(True)
            if pin_properties is not None and tlv_properties and 1 in tlv_properties:
                session.check("property APIs agree on LCD geometry", pin_properties[:2], tlv_properties[1])
            if 11 in controls:
                try:
                    result = ioctl(session, controls[11], b"", "pcsc.abort.idle")
                except TransferError as error:
                    if error.outcome not in (Outcome.HOST_REJECTED, Outcome.RUNNER_ERROR):
                        raise
                    session.observe("idle_abort_driver_result", {"outcome": error.outcome, "code": error.code}, "presence")
                    change(session, Action.RECONNECT)
                    session.select("piv", required=True)
                    grant.authorize()
                else:
                    session.observe("idle_abort_driver_result", result, "presence")
                grant.probe(True)
                session.observe("ABORT_layer", "PC/SC Part 10 control only; it does not establish USB control-transfer or bulk ABORT behavior")
        finally:
            if not session.broken:
                grant.close()


def headless(session):
    from .ccid_cases import ccid
    for standing in (False, True):
        with session.case(f"transport.pinpad.unavailable-display.grant-{standing}", ("T16", "P03", "G14"), effects=("replace_piv_keys",)):
            session.require(session.profile == "rsk" and "headless" in session.options.features,
                            "unavailable-display witness needs a positively declared headless RS-Key build", "excluded_by_profile")
            session.require(session.card is not None and hasattr(session.card, "raw"), "raw Secure CCID unavailable through PC/SC", "excluded_by_mode")
            grant = Grant(session, "piv", 0x80)
            try:
                if standing:
                    grant.authorize()
                grant.probe(standing)
                prefix = bytes([0, 0, 0x82, 0, 0, 6, 8, 2, 1, 0, 0, 0, 0, 0, 0])
                response = ccid(session, 0x69, prefix + codec.apdu(0x20, p2=0x80))
                session.check("headless Secure fails at CCID rather than creating an APDU success", (response[7] & 0xc0, response[8], len(response)), (0x40, 0, 10))
                grant.probe(standing)
            finally:
                if not session.broken:
                    grant.close()
