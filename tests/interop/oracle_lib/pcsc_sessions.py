# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""PC/SC transactions and dispositions are backend observations, not raw CCID."""
from . import codec
from .trace import Outcome, TransferError


def control(session, request):
    session.require(session.card is not None and hasattr(session.card, "pipe"), "native PC/SC transaction backend unavailable", "excluded_by_mode")
    data = codec.encode(request)
    return session._exchange("card", "pcsc_control", "pcsc." + request["control"], data, session.options.timeout,
                             lambda deadline, observe: session.card.transfer(request, deadline, observe))


def run(session):
    for disposition in ("leave", "reset", "unpower"):
        with session.case("transport.PCSC.transaction.disposition-" + disposition, ("T14", "X11", "G14")):
            session.require(session.card is not None and hasattr(session.card, "pipe"), "native PC/SC backend required", "excluded_by_mode")
            session.select("piv")
            active = False
            try:
                session.check("PC/SC transaction begins", control(session, {"control": "transaction", "begin": True}).protocol, "success")
                active = True
                session.check("APDU inside transaction", len(session.card_value(session.apdu(codec.apdu(0xFD)))), 3)
                session.check("PC/SC transaction ends with selected disposition", control(session, {"control": "transaction", "begin": False, "disposition": disposition}).protocol, "success")
                active = False
                session.check("PC/SC reconnect disposition accepted", control(session, {"control": "reset", "disposition": disposition}).protocol, "success")
                session.select("piv", required=True)
                session.check("APDU works after disposition and reconnect", len(session.card_value(session.apdu(codec.apdu(0xFD)))), 3)
            finally:
                if active and not session.broken:
                    session.trace.phase = "cleanup"
                    control(session, {"control": "transaction", "begin": False, "disposition": "leave"})
    with session.case("transport.PCSC.second-client-during-transaction", ("T14", "G12", "G14")):
        session.require(session.card is not None and hasattr(session.card, "probe_client"), "bounded secondary PC/SC client unavailable", "excluded_by_mode")
        session.select("piv")
        session.check("owner transaction begins", control(session, {"control": "transaction", "begin": True}).protocol, "success")
        try:
            request = codec.apdu(0xFD)
            session.trace.emit("interaction", action="second_pcsc_client", stage="open_requested", source="runner", reader_binding="same exact reader")
            try:
                reply = session.trace.exchange("card-client2", "pcsc_apdu", "pcsc.second-client.PIV-version", request, session.options.timeout,
                                               lambda deadline, observe: session.card.probe_client(request, deadline, observe))
            except TransferError as error:
                if error.outcome not in (Outcome.DEADLINE, Outcome.HOST_REJECTED):
                    raise
                session.observe("second_client_termination", {"outcome": error.outcome, "protocol": error.protocol, "detail": str(error)}, "presence")
            else:
                session.observe("second_client_response", (reply.protocol, reply.status, reply.data))
            session.observe("driver_limit", "secondary-client timeout does not establish firmware refusal or reader-busy status")
        finally:
            session.trace.phase = "cleanup"
            if not session.broken:
                control(session, {"control": "transaction", "begin": False, "disposition": "leave"})
                control(session, {"control": "reset", "disposition": "reset"})
                session.select("piv", required=True)
                session.check("owner usable after secondary client terminates", len(session.card_value(session.apdu(codec.apdu(0xFD)))), 3)


def sharing(session):
    for active in (False, True):
        for mode in ("shared", "exclusive", "direct"):
            with session.case(f"transport.PCSC.second-client.mode-{mode}.transaction-{active}", ("T01", "T14", "G12", "G14")):
                session.require(session.card is not None and hasattr(session.card, "probe_client"), "secondary PC/SC connection backend required", "excluded_by_mode")
                session.select("piv")
                started = False
                try:
                    if active:
                        session.check("owner begins transaction before competing connection", control(session, {"control": "transaction", "begin": True}).protocol, "success")
                        started = True
                    try:
                        reply = session.trace.exchange("card-client2", "pcsc_apdu", "pcsc.second-client." + mode, codec.apdu(0xFD), session.options.timeout,
                            lambda deadline, observe: session.card.probe_client(codec.apdu(0xFD), deadline, observe, sharing=mode))
                    except TransferError as error:
                        session.check("sharing refusal is a bounded host outcome", error.outcome in (Outcome.DEADLINE, Outcome.HOST_REJECTED, Outcome.RUNNER_ERROR, Outcome.DISCONNECTED))
                        session.observe("driver_sharing_refusal", {"outcome": error.outcome, "code": error.code, "detail": str(error)}, "presence")
                    else:
                        session.observe("secondary_connection_result", (reply.protocol, reply.status, reply.data), "presence")
                        if mode == "shared" and not active:
                            session.check("shared client PIV response is complete", (reply.protocol, len(reply.data)), ("success", 5))
                    session.observe("sharing_evidence_limit", "driver sharing and transaction policy; a host refusal is not a firmware status")
                finally:
                    if not session.broken:
                        session.trace.phase = "cleanup"
                        if started:
                            control(session, {"control": "transaction", "begin": False, "disposition": "leave"})
                        control(session, {"control": "reset", "disposition": "reset"})
                        session.select("piv", required=True)
                        session.check("owner survives competing sharing mode", len(session.card_value(session.apdu(codec.apdu(0xFD)))), 3)
