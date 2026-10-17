# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""previewSign v4 signatures are verified with an independently derived ARKG key."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from . import arkg, codec
from .fido import auth_data, info, public_key
from .fido_fixtures import credential

SPLIT_ARKG = -65539


def run(session):
    for flags in (0, 1, 5):
        for context_size in (0, 1, 64):
            with session.case(f"fido.previewSign.flags-{flags}.ctx-{context_size}", ("FE10", "G03", "G09", "G14"), effects=("create_fido_credential",), touch=True):
                session.require("previewSign" in info(session).get(2, []), "previewSign build not advertised", "unknown")
                session.require(flags != 5 or session.options.pin is not None or info(session).get(4, {}).get("uv"), "UV-required preview key needs configured verification")
                with credential(session, session.current.name, extensions={"previewSign": {3: [SPLIT_ARKG], 4: flags}}) as fixture:
                    attestation = codec.decode(fixture.registration[6]["previewSign"][7])
                    attested = auth_data(attestation["authData"])
                    session.check("preview key RP binding", attested["rp_hash"], fixture.parsed["rp_hash"])
                    seed = attested["cose"]
                    session.check("ARKG public seed profile", (seed[1], seed[3], seed[-3]), (-65537, -65700, -9))
                    context = session.fixture("preview.ctx", context_size)
                    derived, handle = arkg.derive(public_key(seed[-1]), public_key(seed[-2]), session.fixture("preview.ikm"), context)
                    digest = session.fixture("preview.digest")
                    args = codec.encode({3: SPLIT_ARKG, -1: handle, -2: context})
                    fields = {2: attested["credential_id"], 6: digest, 7: args}
                    def check_signature():
                        _, signed = fixture.assertion(session, extensions={"previewSign": fields})
                        signature = signed["extensions"]["previewSign"][6]
                        derived.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                        session.check("previewSign independent ARKG signature", True)
                        try:
                            derived.verify(signature, bytes([digest[0] ^ 1]) + digest[1:], ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                        except InvalidSignature:
                            session.check("previewSign altered digest refused", True)
                        else:
                            session.check("previewSign altered digest refused", False)
                    check_signature()
                    for defect in ("short-digest", "long-digest", "damaged-handle", "damaged-derivation", "missing-args", "oversize-context"):
                        invalid = dict(fields)
                        if defect == "short-digest":
                            invalid[6] = digest[:-1]
                        elif defect == "long-digest":
                            invalid[6] = digest + b"\x00"
                        elif defect == "damaged-handle":
                            invalid[2] = bytes([invalid[2][0] ^ 1]) + invalid[2][1:]
                        elif defect == "damaged-derivation":
                            invalid[7] = codec.encode({3: SPLIT_ARKG, -1: handle[:-1] + bytes([handle[-1] ^ 1]), -2: context})
                        elif defect == "missing-args":
                            del invalid[7]
                        else:
                            invalid[7] = codec.encode({3: SPLIT_ARKG, -1: handle, -2: bytes(65)})
                        result = session.ctap(2, fixture.query(session, extensions={"previewSign": invalid}))
                        session.check("invalid previewSign " + defect + " refused", result.protocol, "applet_error")
                        check_signature()
