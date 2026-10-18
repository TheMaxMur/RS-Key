# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Fixed-scalar release rsk-ec signatures are checked by independent OpenSSL math."""
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, utils

from oracle_lib import openpgp_operations
from oracle_lib.runner import Session
from oracle_lib.trace import Trace

VECTORS = (
    (ec.SECP384R1, 0, "5b1d331e6985f867324cebc2ee22d7de83deeaefaa38ec71f33698c2ea0b4ce05a52cb2bd6db9e63a505da1245d5272a0707988122c94c199ef10044a86b2a6577b179f63a876db06d7694f265c4a9943bdd615762a45a65793d37a397ce2083"),
    (ec.SECP521R1, 0, "000f919331e2010efc47819130eae42a5b5699b5509e7e10d028206ddce345cc0013fd9b53ae7714132a83260ad3b5bc7e7e2b895a4e463578cb4aaeda0bda9cee630035ba10852c631ff1e745b3fc2551f2bd83109dcfd10f61b322448a4f7b30dc36160addceddee4196b03f24d6e3da5319f85c4538abefd59316615a58d8062556d6"),
    (ec.SECP521R1, 66, "012f5c3bffc5cda522a34aa562d5083d1c4ecd0ee6ca8917e848de9cbe9ea07008753e8bb5d8f3eb66f92f13774e3759ae407ada0eeab4dc611acfbad749839bd06d0150d1e10c6e3b6c8cb414851cc40bbce4fcb78843ca3da4dbc8e5fe1aab9be0f9df9149ffe2b78b793990c916617079cf594196eafd2c235d72e3dab5e3c2610028"),
    (ec.BrainpoolP384R1, 0, "50c3e34888bf0f9c1f03c93f5730b73ee3073c61db3e0ca9d73f2e5ec1a0897b67f6ca8662d8464519e1fbef0c53faa304c2fa9ca8d97390262fae2f893a4236617c01635fd87c2bbeb3df826e8f7483a52326da1b39a71f55aad004c16a7bee"),
)


@pytest.mark.parametrize("curve,size,encoded", VECTORS)
def test_release_rsk_ec_prehash_vectors_and_profile_distinction(tmp_path, curve, size, encoded):
    public = ec.derive_private_key(42, curve()).public_key()
    payload, signature = bytes(range(size)), bytes.fromhex(encoded)
    trace = Trace(tmp_path / "raw-prehash", {})
    session = Session(trace)
    with session.case("release-rsk-ec-vector"):
        openpgp_operations.verify_signature(session, public, payload, signature)
    trace.finish()
    assert trace.cases[0]["verdict"] == "pass", trace.cases
    width = len(signature) // 2
    der = utils.encode_dss_signature(int.from_bytes(signature[:width], "big"), int.from_bytes(signature[width:], "big"))
    digest = openpgp_operations.verification_digest(public, payload)
    bit = 0x80 if curve is ec.SECP521R1 and len(digest) == 66 else 1
    altered = digest[:-1] + bytes([digest[-1] ^ bit])
    with pytest.raises(InvalidSignature):
        public.verify(der, altered, ec.ECDSA(utils.Prehashed(openpgp_operations.RawPrehash(len(altered)))))
    if size == 66:
        with pytest.raises(InvalidSignature):
            public.verify(der, payload, ec.ECDSA(utils.Prehashed(openpgp_operations.RawPrehash(size))))
