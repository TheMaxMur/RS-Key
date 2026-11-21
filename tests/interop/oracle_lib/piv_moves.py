# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""MOVE verifies source/destination metadata and both occupied-slot controls."""
from . import codec
from .card_keys import PIV_SLOTS, private_operation
from .cards import encoded_public, sdk_supported
from .piv_lifecycle import fixture_session, status


def metadata_values(value):
    return value.key_type, value.pin_policy, value.touch_policy, value.generated


def run(session):
    from yubikit.piv import KEY_TYPE, SLOT, OBJECT_ID, PIN_POLICY, TOUCH_POLICY
    from .piv_objects import read as read_object
    for source in PIV_SLOTS:
        for target in PIV_SLOTS:
            for occupied in (False, True):
                with session.case(f"piv.MOVE.{source:02x}-to-{target:02x}.occupied-{occupied}", ("P15", "P02", "P11", "G09", "G14"), effects=("replace_piv_keys",), touch=True):
                    sdk = fixture_session(session)
                    created, certificates = set(), {}
                    try:
                        for reference in dict.fromkeys((source, target)):
                            identifier = int(OBJECT_ID.from_slot(SLOT(reference)))
                            certificates[identifier] = read_object(session, identifier)
                            sdk.put_object(identifier, b"oracle-certificate-" + bytes([reference]))
                        public = sdk_supported(session, lambda: sdk.generate_key(SLOT(source), KEY_TYPE.ECCP256, PIN_POLICY.ALWAYS, TOUCH_POLICY.NEVER))
                        created.add(source)
                        original_metadata = sdk.get_slot_metadata(SLOT(source))
                        destination = None
                        if not occupied and target != source:
                            empty = session.apdu(codec.apdu(0xF7, p2=target), "piv.MOVE.empty-destination-precondition")
                            session.require(empty.status == 0x6A88, "empty-destination case will not replace an existing key")
                        if occupied and target != source:
                            destination = sdk_supported(session, lambda: sdk.generate_key(SLOT(target), KEY_TYPE.ECCP256))
                            created.add(target)
                        result = session.apdu(codec.apdu(0xF6, target, source), "piv.MOVE")
                        if target == source or occupied:
                            session.check("self/occupied MOVE refused", result.status, 0x6A80)
                            session.check("refused MOVE retains source", encoded_public(sdk.get_slot_metadata(SLOT(source)).public_key), encoded_public(public))
                            session.check("refused MOVE retains source policies and origin", metadata_values(sdk.get_slot_metadata(SLOT(source))), metadata_values(original_metadata))
                            sdk.verify_pin(session.options.piv_pin)
                            private_operation(session, sdk, SLOT(source), public, "ECCP256", piv=True)
                            if destination is not None:
                                session.check("refused MOVE retains destination", encoded_public(sdk.get_slot_metadata(SLOT(target)).public_key), encoded_public(destination))
                                sdk.verify_pin(session.options.piv_pin)
                                private_operation(session, sdk, SLOT(target), destination, "ECCP256", piv=True)
                        else:
                            session.card_value(result)
                            created.remove(source)
                            created.add(target)
                            status(session, 0xF7, p2=source, expected=0x6A88)
                            session.check("MOVE carries public metadata", encoded_public(sdk.get_slot_metadata(SLOT(target)).public_key), encoded_public(public))
                            sdk.verify_pin(session.options.piv_pin)
                            moved = sdk.get_slot_metadata(SLOT(target))
                            session.check("MOVE carries algorithm, PIN, touch and origin metadata", metadata_values(moved), metadata_values(original_metadata))
                            private_operation(session, sdk, SLOT(target), public, "ECCP256", piv=True)
                            status(session, 0xF6, target, source, expected=0x6A88)
                        for reference in dict.fromkeys((source, target)):
                            identifier = int(OBJECT_ID.from_slot(SLOT(reference)))
                            session.check("MOVE leaves certificate objects at their original references", read_object(session, identifier), b"oracle-certificate-" + bytes([reference]))
                    finally:
                        if not session.broken:
                            session.trace.phase = "cleanup"
                            sdk.authenticate(session.options.management_key)
                            for slot in sorted(created):
                                sdk_supported(session, lambda: sdk.delete_key(SLOT(slot)))
                            for identifier, original in certificates.items():
                                sdk.put_object(identifier, original)
    for target in (0, 0x9B, 0xF9, 0xFE):
        with session.case(f"piv.MOVE.protected-destination.{target:02x}", ("P15", "G09", "G14"), effects=("replace_piv_keys", "replace_identity"), touch=True):
            sdk = fixture_session(session)
            public = sdk_supported(session, lambda: sdk.generate_key(SLOT(0x82), KEY_TYPE.ECCP256))
            try:
                status(session, 0xF6, target, 0x82, expected=0x6A80)
                session.check("protected MOVE refusal retains fixture", encoded_public(sdk.get_slot_metadata(SLOT(0x82)).public_key), encoded_public(public))
            finally:
                if not session.broken:
                    session.trace.phase = "cleanup"
                    sdk.authenticate(session.options.management_key)
                    sdk_supported(session, lambda: sdk.delete_key(SLOT(0x82)))
