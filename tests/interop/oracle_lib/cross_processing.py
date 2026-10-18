# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Observe actual PQC processing before a second applet's request, then verify both."""
from itertools import product

from . import codec
from .binding import require_pair
from .fido import auth_data, authorize, info, verified
from .fido_fixtures import credential
from .hid_sequences import hooks
from .otp import oath_open

ALGORITHMS = (-48, -49, -50)


def run(session):
    for algorithm, operation, target in product(ALGORITHMS, ("make", "assert"), ("piv", "openpgp", "oath")):
        with session.case(f"cross.PQC-processing.{algorithm}.{operation}.CCID-{target}", ("X05", "X09", "X12", "T06", "F11", "F12", "G14"),
                effects=("create_fido_credential",), touch=True, parameters={"algorithm": algorithm, "operation": operation, "competing_applet": target}):
            session.require(session.profile == "rsk", "profiled PQC and concurrent applet contracts require RS-Key", "excluded_by_profile")
            require_pair(session)
            session.observe("PQC_advertised", any(row.get("alg") == algorithm for row in info(session).get(10, [])))
            session.require(session.hid is not None and hasattr(session.hid, "send_only"), "processing overlap requires raw KEEPALIVE callbacks", "excluded_by_mode")
            if target == "oath":
                oath_open(session)
            else:
                session.select(target, required=True)
            wire = codec.apdu(0xfd) if target == "piv" else codec.apdu(0x84, le=8) if target == "openpgp" else codec.apdu(0xa1)
            baseline = session.card_value(session.apdu(wire))
            label = session.current.name
            rp = session.fixture(label + ".rp", 8).hex() + ".oracle.invalid"
            timeline, overlap = [], []
            def processing(status, timestamp):
                timeline.append((status, timestamp))
                if status != 1 or overlap:
                    return
                overlap.append({"processing_observed_ns": timestamp, "request_started_ns": session.trace.now()})
                result = session.card_value(session.apdu(wire, "cross.PQC.other-applet-during-processing"))
                overlap[0]["request_completed_ns"] = session.trace.now()
                session.check("other applet returns its actual result during the scheduled overlap", len(result) if target == "openpgp" else result,
                    8 if target == "openpgp" else baseline)
            if operation == "make":
                extra = {}
                authorize(session, extra, 1, rp, session.fixture(label + ".hash"), 8, 9)
                with hooks(session, keepalive=processing):
                    with credential(session, label, algorithms=[algorithm], rp=rp, extra=extra, authenticate=False) as fixture:
                        session.check("PQC make selects its requested algorithm", fixture.algorithm, algorithm)
                fixture.assertion(session)
            else:
                with credential(session, label, algorithms=[algorithm], rp=rp) as fixture:
                    query = fixture.query(session)
                    with hooks(session, keepalive=processing):
                        value = session.ctap_value(session.ctap(2, query))
                    session.check("PQC completion stays bound to the initiating credential", value[1], fixture.descriptor)
                    session.check("PQC completion stays bound to the initiating RP", auth_data(value[2])["rp_hash"], fixture.parsed["rp_hash"])
                    verified(session, "overlapped PQC assertion retains its real private key", fixture.key, algorithm, value[3], value[2] + fixture.challenge)
                    fixture.assertion(session)
            session.require(bool(overlap), "no PROCESSING KEEPALIVE was observed; no device-processing overlap is claimed", "excluded_by_mode")
            session.check("processing observations are ordered", all(left[1] <= right[1] for left, right in zip(timeline, timeline[1:])))
            session.observe("processing_overlap", {"timeline": timeline, "other_request": overlap[0],
                "scope": "host observed PROCESSING before submitting CCID; CPU parallelism and the exact device completion instant are unobservable; nested API time includes callback work"})
            after = session.card_value(session.apdu(wire))
            session.check("other applet remains usable after PQC completion", len(after) if target == "openpgp" else after, 8 if target == "openpgp" else baseline)
