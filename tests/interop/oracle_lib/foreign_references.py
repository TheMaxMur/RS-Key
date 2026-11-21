# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Replay previously proved public references without opening the source device."""
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from . import codec
from .fido import auth_data, public_key, u2f_apdu, u2f_registration, verify, verified
from .fido_fixtures import credential
from .u2f_semantics import assertion as u2f_assertion, payload

MAX_BUNDLE_BYTES, MAX_REFERENCES = 1_048_576, 32


def validate(entry):
    if not isinstance(entry, dict):
        raise ValueError("foreign reference entry must be a public proof object")
    if entry.get("kind") not in ("fido2", "u2f") or entry.get("seed_relation") not in ("distinct", "same", "unknown"):
        raise ValueError("foreign reference needs a known kind and an explicit distinct/same/unknown seed relation")
    if not isinstance(entry.get("source_serial"), str) or not 1 <= len(entry["source_serial"]) <= 128:
        raise ValueError("foreign reference requires its source USB serial metadata")
    result = dict(entry)
    names = ("credential_id", "cose_key", "auth_data", "client_hash", "signature") if entry["kind"] == "fido2" else ("handle", "application", "challenge", "public_key", "auth_head", "signature")
    try:
        for name in names:
            result[name] = bytes.fromhex(entry[name])
        if entry["kind"] == "fido2":
            if not isinstance(entry.get("rp"), str) or not entry["rp"] or len(result["client_hash"]) != 32 or not result["credential_id"]:
                raise ValueError("invalid foreign FIDO binding widths")
            cose = codec.decode(result["cose_key"])
            parsed = auth_data(result["auth_data"])
            if parsed["rp_hash"] != hashlib.sha256(entry["rp"].encode()).digest():
                raise ValueError("foreign proof uses a different RP")
            verify(public_key(cose), cose[3], result["signature"], result["auth_data"] + result["client_hash"])
        else:
            if not 1 <= len(result["handle"]) <= 255 or len(result["application"]) != 32 or len(result["challenge"]) != 32 or len(result["auth_head"]) != 5:
                raise ValueError("invalid foreign U2F binding widths")
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), result["public_key"])
            verify(key, -7, result["signature"], result["application"] + result["auth_head"] + result["challenge"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid foreign reference or origin proof") from error
    except Exception as error:
        from cryptography.exceptions import InvalidSignature
        if isinstance(error, InvalidSignature):
            raise ValueError("foreign reference origin signature does not verify") from error
        raise
    return result


def load(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BUNDLE_BYTES + 1)
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ValueError("foreign-reference bundle exceeds its bounded input size")
    bundle = json.loads(raw)
    if not isinstance(bundle, list) or not 1 <= len(bundle) <= MAX_REFERENCES:
        raise ValueError("foreign-reference file must contain 1..32 public proof objects")
    return tuple(validate(entry) for entry in bundle)


def run(session):
    for kind in ("fido2", "u2f"):
        entries = [entry for entry in session.options.foreign_references if entry["kind"] == kind]
        for index in range(max(1, len(entries))):
            with session.case(f"reference.other-device.{kind}.{index}", ("G09", "G14", "F12" if kind == "fido2" else "U04"),
                    effects=("create_fido_credential" if kind == "fido2" else "create_u2f_credential",), touch=True):
                session.require(session.profile in ("rsk", "yubikey"), "foreign identity rejection expectations require a confirmed security-key profile", "excluded_by_profile")
                session.require(bool(entries), "supply --foreign-references with a previously recorded and signed public reference from another test key")
                entry = entries[index]
                serial = getattr(session.hid, "descriptor", {}).get("serial_number")
                session.require(serial and serial != entry["source_serial"], "target USB serial must be observed and different from source metadata")
                session.observe("foreign_reference_basis", {"source_serial": entry["source_serial"], "target_serial": serial,
                    "seed_relation": entry["seed_relation"], "origin_signature_verified_offline": True,
                    "serial_binding": "capture/operator metadata, not a cryptographic serial attestation"})
                if kind == "fido2":
                    with credential(session, session.current.name) as retained:
                        challenge = session.fixture("foreign.reference.fresh-hash")
                        request = {1: entry["rp"], 2: challenge, 3: [{"type": "public-key", "id": entry["credential_id"]}], 5: {"up": False, "uv": False}}
                        from .fido import authorize
                        authorize(session, request, 2, entry["rp"], challenge, 6, 7)
                        reply = session.ctap(2, request)
                        if entry["seed_relation"] == "distinct":
                            session.check("distinct source identity cannot authorize its private reference on this device", reply.status, 0x2e)
                        else:
                            session.check("portable or unknown-seed reference either signs or reports no credential", reply.status in (0, 0x2e))
                        if reply.status == 0:
                            value = session.ctap_value(reply)
                            cose = codec.decode(entry["cose_key"])
                            session.check("accepted foreign reference retains its original RP", auth_data(value[2])["rp_hash"], hashlib.sha256(entry["rp"].encode()).digest())
                            verified(session, "portable reference proves its original private key", public_key(cose), cose[3], value[3], value[2] + challenge)
                        retained.assertion(session)
                else:
                    retained = u2f_registration(session, session.current.name)
                    before = u2f_assertion(session, retained)
                    reply = session.hid_call(3, u2f_apdu(2, 7, payload(entry)), "u2f.foreign-reference.check-only")
                    if entry["seed_relation"] == "distinct":
                        session.check("distinct source U2F handle is not recognized by the target", reply.status, 0x6a80)
                    else:
                        session.check("foreign U2F handle is explicitly recognized or rejected", reply.status in (0x6985, 0x6a80))
                    session.check("foreign check-only cannot advance the global U2F counter", u2f_assertion(session, retained), before + 1)
                    if reply.status == 0x6985:
                        u2f_assertion(session, entry)
