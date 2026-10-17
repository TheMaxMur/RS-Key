# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Observe neighboring public records and configuration across applet resets."""
from . import codec
from .runner import AIDS


def snapshot(session, excluded):
    if session.profile != "rsk" or session.card is None:
        session.observe("reset_neighbor_scope", "RS-Key card witness unavailable; no neighboring-state preservation claim")
        return None
    result = {}
    for applet in ("management", "piv", "openpgp", "oath"):
        if applet == excluded:
            continue
        selection = session.apdu(codec.apdu(0xA4, 4, data=AIDS[applet]), "reset.neighbor.select." + applet)
        if selection.status == 0x6A82:
            result[applet] = {"selection": selection.status}
            continue
        session.card_value(selection)
        if applet == "management":
            result[applet] = session.card_value(session.apdu(codec.apdu(0x1D), "reset.neighbor.DeviceInfo"))
        elif applet == "piv":
            values = []
            for reference in (0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0xF9):
                reply = session.apdu(codec.apdu(0xF7, p2=reference), "reset.neighbor.PIV.metadata")
                session.check("neighbor PIV metadata is present or absent", reply.status in (0x9000, 0x6A88))
                values.append((reference, reply.status, reply.data[:-2]))
            result[applet] = values
        elif applet == "openpgp":
            result[applet] = [session.card_value(session.apdu(codec.apdu(0xCA, tag >> 8, tag & 255), "reset.neighbor.OpenPGP.DO")) for tag in (0x5E, 0x65, 0x6E)]
        else:
            from .otp import oath_open, oath_names
            oath_open(session)
            result[applet] = sorted(oath_names(session))
    session.observe("reset_neighbor_public_state", result)
    session.observe("reset_neighbor_limit", "configuration, selected PIV public metadata, OpenPGP public DOs and OATH names; no inference about unobserved private records")
    return result


def preserved(session, excluded, original):
    if original is not None:
        session.check("applet reset preserves observed neighboring state", snapshot(session, excluded), original)
