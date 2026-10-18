# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Biometric sequences retain only owned templates and expose full-store feedback."""
from . import codec
from .fido import info, pin_token, token_mac

MAX_TEMPLATES = 256
MAX_SAMPLES = 64


class Bio:
    def __init__(self, session, version):
        self.s, self.version = session, version
        options = info(session).get(4, {})
        session.require(session.profile != "trezor", "biometric scenarios excluded on wallet profile", "excluded_by_profile")
        if "bioEnroll" in options:
            self.command = 9
        else:
            session.require(session.profile == "yubikey" and "userVerificationMgmtPreview" in options,
                            "standard or confirmed preview biometric command not advertised", "unsupported_confirmed")
            self.command = 0x40
        self.refresh()

    def refresh(self):
        self.version, self.token = pin_token(self.s, 8, version=self.version)

    def call(self, sub, parameters=None, defect=None):
        fields = {1: 1, 2: sub}
        if parameters is not None:
            fields[3] = parameters
        if sub not in (3, 7):
            payload = bytes([1, sub]) + (codec.encode(parameters) if parameters is not None else b"")
            fields.update({4: self.version, 5: token_mac(self.version, self.token, payload)})
        if defect == "missing-MAC":
            fields.pop(5, None)
        elif defect == "missing-protocol":
            fields.pop(4, None)
        elif defect == "bad-MAC":
            fields[5] = bytes(len(fields[5]))
        elif defect == "unsupported-protocol":
            fields[4] = 255
        return self.s.ctap(self.command, fields)

    def templates(self):
        response = self.call(4)
        if response.status == 0x2e:
            return {}
        value = self.s.ctap_value(response)
        rows = value.get(7, [])
        self.s.check("template IDs are unique", len(rows), len({row[1] for row in rows}))
        return {row[1]: row.get(2, "") for row in rows}

    def enroll(self, owned):
        result = self.call(1, {3: int(self.s.options.timeout * 1000)})
        if result.protocol != "success":
            return None, result.status
        value = self.s.ctap_value(result)
        template = value.get(4)
        if template is not None:
            owned.add(template)
        if value.get(5) == 12:
            return None, "FP_DATABASE_FULL"
        self.s.check("begin returns an owned template reference", type(template) is bytes and len(template) > 0)
        for _ in range(MAX_SAMPLES):
            remaining = value[6]
            self.s.check("sensor sample count is bounded", type(remaining) is int and 0 <= remaining <= MAX_SAMPLES)
            if remaining == 0:
                return template, 0
            value = self.s.ctap_value(self.call(2, {1: template, 3: int(self.s.options.timeout * 1000)}))
            self.s.observe("sample_feedback", value.get(5))
        raise AssertionError("sensor did not complete enrollment within the explicit sample budget")

    def cleanup(self, owned):
        if not self.s.broken:
            self.s.trace.phase = "cleanup"
            self.call(3)
            self.refresh()
            live = self.templates()
            for template in owned:
                if template in live:
                    self.s.ctap_value(self.call(6, {1: template}))


def sequences(session):
    for version in (1, 2):
        for defect in ("missing-MAC", "missing-protocol", "bad-MAC", "unsupported-protocol", "wrong-permission", "capture-before-begin", "unknown-template", "cancel", "repeat-cancel", "rename-bounds", "duplicate-sample", "timeout"):
            with session.case(f"fido.biometric.matrix.protocol-{version}.{defect}", ("F24", "G01", "G03", "G09", "G10", "G14"),
                    effects=("biometric_enrollment",), touch=True, parameters={"biometric_action": defect}):
                bio = Bio(session, version)
                session.require(defect != "timeout" or session.options.operator, "biometric timeout needs an operator to withhold a sample")
                before, owned = bio.templates(), set()
                try:
                    sensor = session.ctap_value(bio.call(7))
                    if defect in ("missing-MAC", "missing-protocol", "bad-MAC", "unsupported-protocol", "wrong-permission"):
                        if defect == "wrong-permission":
                            bio.version, bio.token = pin_token(session, 2, version=version)
                        result = bio.call(4, defect=defect)
                        session.check("biometric authorization defect refused", result.is_rejection)
                    elif defect == "duplicate-sample":
                        session.require(session.options.operator and before, "duplicate enrollment needs an operator and an existing enrollment")
                        import sys
                        print("oracle: present an ALREADY enrolled fingerprint; do not enroll a different finger", file=sys.stderr)
                        session.trace.emit("interaction", action="present_existing_biometric", stage="requested", source="runner")
                        value = session.ctap_value(bio.call(1, {3: int(session.options.timeout * 1000)}))
                        if 4 in value and value[4] not in before:
                            owned.add(value[4])
                        session.check("duplicate fingerprint has explicit FP_EXISTS feedback", value.get(5), 11)
                        bio.call(3)
                        session.check("duplicate fingerprint cannot publish another template", bio.templates(), before)
                    elif defect in ("capture-before-begin", "unknown-template"):
                        bio.call(3)
                        session.check("invalid capture sequence refused", bio.call(2, {1: b"oracle-unknown-template", 3: 1000}).is_rejection)
                        if defect == "unknown-template":
                            session.check("unknown template cannot be removed", bio.call(6, {1: b"oracle-unknown-template"}).is_rejection)
                            session.check("unknown template cannot be renamed", bio.call(5, {1: b"oracle-unknown-template", 2: "unknown"}).is_rejection)
                    elif defect == "timeout":
                        session.trace.emit("interaction", action="withhold_biometric_sample", source="runner", stage="requested")
                        result = bio.call(1, {3: 1000})
                        if result.protocol == "success":
                            value = session.ctap_value(result)
                            if 4 in value:
                                owned.add(value[4])
                            session.check("silent biometric sample reports no activity", value.get(5), 13)
                        else:
                            session.check("silent biometric sample terminates explicitly", result.status in (0x2f, 0x3a))
                        bio.call(3)
                    elif defect in ("cancel", "repeat-cancel"):
                        pending = session.ctap_value(bio.call(1, {3: int(session.options.timeout * 1000)}))
                        template = pending[4]
                        owned.add(template)
                        session.require(pending[6] > 0, "single-sample sensor completed before cancellation; no pending-capture claim", "excluded_by_mode")
                        session.ctap_value(bio.call(3))
                        if defect == "repeat-cancel":
                            session.observe("repeat_cancel", bio.call(3).status)
                        session.check("cancel retires the incomplete capture cursor", bio.call(2, {1: template, 3: 1000}).is_rejection)
                        session.check("cancel cannot publish an incomplete template", template not in bio.templates())
                        template, status = bio.enroll(owned)
                        session.check("fresh enrollment succeeds after cancellation", template is not None)
                    else:
                        template, status = bio.enroll(owned)
                        session.require(template is not None, "sensor cannot allocate a fixture template; full state recorded", "blocked_by_precondition")
                        if defect == "rename-bounds":
                            maximum = sensor.get(8, 64)
                            for name in ("", "x" * (maximum - 1), "x" * maximum, "x" * (maximum + 1), "é" * (maximum // 2), "é" * (maximum // 2 + 1)):
                                previous = bio.templates()[template]
                                result = bio.call(5, {1: template, 2: name})
                                session.observe("rename." + str(len(name.encode())), (result.protocol, result.status))
                                live = bio.templates()
                                session.check("renaming cannot change template identity", template in live)
                                if len(name.encode()) > maximum:
                                    session.check("friendly name beyond advertised byte bound is refused", result.is_rejection)
                                    session.check("refused friendly name preserves the prior name", live[template], previous)
                                elif result.protocol == "success":
                                    session.check("accepted friendly name has exact readback", live[template], name)
                        else:
                            session.ctap_value(bio.call(3))
                            if defect == "repeat-cancel":
                                session.observe("repeat_cancel", bio.call(3).status)
                            session.check("completed template survives later cancellation", template in bio.templates())
                    bio.refresh()
                    current = bio.templates()
                    session.check("biometric failure preserves all preexisting templates", {key: current.get(key) for key in before}, before)
                finally:
                    bio.cleanup(owned)
                    if not session.broken:
                        session.check("only fixture biometric templates were removed", bio.templates(), before)


def capacity(session):
    for version in (1, 2):
        with session.case(f"fido.biometric.full-and-reclaim.protocol-{version}", ("F24", "G09", "G14"),
                effects=("biometric_enrollment", "capacity"), touch=True):
            bio = Bio(session, version)
            before, owned = bio.templates(), set()
            try:
                full = False
                for _ in range(MAX_TEMPLATES):
                    template, status = bio.enroll(owned)
                    if template is None:
                        session.check("full sensor reports database capacity", status in (0x17, 0x28, "FP_DATABASE_FULL"))
                        full = True
                        break
                session.check("sensor reaches a bounded explicit capacity result", full)
                live = bio.templates()
                session.check("full sensor retains all allocated templates", set(live), set(before) | owned)
                session.require(bool(owned), "sensor was initially full; reclaim cannot delete an unowned template")
                removed = next(iter(owned))
                session.ctap_value(bio.call(6, {1: removed}))
                owned.remove(removed)
                template, status = bio.enroll(owned)
                session.check("removing one owned template makes enrollment possible", template is not None)
            finally:
                bio.cleanup(owned)
                if not session.broken:
                    session.check("biometric capacity cleanup preserves original store", bio.templates(), before)


def run(session):
    sequences(session)
    capacity(session)
