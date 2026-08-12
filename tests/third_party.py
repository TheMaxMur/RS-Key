#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Run the vendored upstream suites against RS-Key, with every divergence named.

`third_party/` holds two ecosystems' own conformance suites — pico-fido's and
pico-openpgp/Gnuk's. They are somebody else's tests under somebody else's
license, so nothing here edits them: the run is steered from outside by a pytest
plugin, and everything RS-Key deliberately does not do for them is listed in
[`DIVERGENCES`] with its reason.

A listed test is `xfail(strict=True)`, not a skip. If it starts passing, the run
*fails* and says which entry to delete — because an allow-list that silently
absorbs a fixed divergence is how it rots, and this repo has already been bitten
by one that did (`tests/interop`).

    python tests/third_party.py fido            # the pico-fido suite
    python tests/third_party.py openpgp         # the OpenPGP card suite
    python tests/third_party.py all -- -x       # everything; extra pytest args

Both suites want a device that answers like a flashed no-touch build. Against
`tools/emu` that means `--usbip` on a Linux host (they use python-fido2's and
pyscard's own transports, which want real USB), and `pcscd` carrying the
`ccid-rs-key` reader list for the card half.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import emu  # noqa: E402  (needs the path above)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Each suite, and whether the emulator's socket shim can stand in for its
# transport. `openpgp` reaches the card through pyscard alone, so the card socket
# is enough — no PC/SC, no USB, no root, which is what lets it run anywhere.
# `fido` is driven by python-fido2's own HID transport, which wants a real device:
# that one needs `--usbip`.
SUITES = {
    "fido": ("third_party/pico-fido-tests/pico-fido", False),
    "openpgp": ("third_party/openpgp-card-tests", True),
}

# What RS-Key deliberately does not do the way these suites expect. The key is a
# substring of the pytest node id; the value is why, in one line, aimed at
# whoever finds the entry in three years.
#
# Only *deliberate* divergences belong here. A test failing because RS-Key is
# wrong is a bug, and putting it here hides it.
DIVERGENCES: dict[str, dict[str, str]] = {
    "fido": {
        # Not about RS-Key at all: the suite calls its own `Device.doGA()` with an
        # `options=` argument that helper does not take, so it raises TypeError
        # before a byte reaches the device. (Its sibling `test_option_uv` never
        # gets there — it is gated on the `uv` option, which this build does not
        # advertise.) Upstream defect; nothing to fix here.
        "test_021_authenticate.py::test_option_up": "the suite's own doGA() takes no options= argument",
        # The emulator answers faster than the transport's keepalive interval, so
        # there is nothing to count. A board doing on-card RSA does emit them —
        # `tests/50_touch_latency.py` is where that is measured.
        "test_055_hid.py::TestHID::test_keep_alive": "no command here is slow enough to stream a keepalive",
        # CTAP 2.1 §6.1.2: `up` is implicitly true for makeCredential and an
        # explicit `up: true` is accepted — only `up: false` is INVALID_OPTION.
        # The FIDO conformance tool checks both (MakeCredential Req-6, P-3/F-1)
        # and RS-Key passes it; the suite asserts the opposite for `up: true`.
        "test_000_getinfo.py::test_Check_up_option": "CTAP 2.1 accepts an explicit up:true; only up:false is INVALID_OPTION",
        # CTAP 2.1 §6.5.5.5, verbatim: "If a PIN has already been set,
        # authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error". The suite wants
        # NOT_ALLOWED, which is the CTAP 2.0 answer.
        "test_010_pin.py::test_set_pin_twice": "§6.5.5.5 makes a second setPIN PIN_AUTH_INVALID, not NOT_ALLOWED",
        # CTAP 2.1 zero-length-pinUvAuthParam probe: PIN_INVALID when a PIN is set,
        # PIN_NOT_SET when it is not. The suite wants PIN_AUTH_INVALID — again the
        # 2.0 answer. Both halves are pinned by `conformance::pin`.
        "test_010_pin.py::test_zero_length_pin_auth": "the CTAP 2.1 probe answers PIN_INVALID, not PIN_AUTH_INVALID",
        # RS-Key advertises `makeCredUvNotRqd`, under which CTAP 2.1 §6.1.2 lets a
        # NON-discoverable credential be made on presence alone. The suite asserts
        # PUAT_REQUIRED unconditionally, without reading the option.
        "test_010_pin.py::test_get_no_pin_auth": "makeCredUvNotRqd: a non-discoverable credential needs no token",
        "test_010_pin.py::test_make_credential_no_pin": "makeCredUvNotRqd: a non-discoverable credential needs no token",
        # The test calls `device.reboot()` when it sees PIN_AUTH_BLOCKED and then
        # asserts PIN_AUTH_BLOCKED again — a ladder that only holds while that
        # reboot does nothing. Given a real power cycle (which the runner supplies,
        # see `_install_reboot`), the consecutive-mismatch counter clears at
        # attempt 4 exactly as §6.5.5.7 requires, and the next answer is
        # PIN_INVALID.
        "test_010_pin.py::test_lockout": "asserts a lockout its own reboot() is supposed to clear",
        # The request's keyAgreement is an all-zero point, which is not on P-256.
        # Refusing it (INVALID_PARAMETER) before deriving anything is the
        # invalid-curve defence; reaching the saltAuth check first would mean doing
        # ECDH with an attacker-chosen off-curve point.
        "test_035_hmac_secret.py::test_bad_auth": "the off-curve keyAgreement is refused before the salt MAC is looked at",
        # After the card reset the test performs, no applet is selected, so a bare
        # LIST is 6A82 (file not found) rather than 6982. Dropping the selection on
        # a power transition is deliberate — it is what makes a second local
        # process re-authenticate (ApduHandler::reset_card).
        "test_070_oath.py::test_auth": "a card reset deselects the applet, so LIST without SELECT is 6A82",
        "test_070_oath.py::test_noauth": "a card reset deselects the applet, so LIST without SELECT is 6A82",
        # These send CALCULATE with a bare `74` tag — no length byte, no value —
        # which is not a TLV. With the encoded empty challenge `74 00` that ykman
        # actually sends, RS-Key computes the same truncation these expect. It no
        # longer sends the same *bytes*: their literals (`45 d9 0f 25` for the IMF
        # case) are the raw 31-bit truncation, and a YubiKey 5.7.4 reduces it to
        # the credential's six digits, which RS-Key now does too (E65).
        "test_070_oath.py::test_bothoath": "the challenge TLV is sent truncated (`74` with no length)",
        "test_070_oath.py::test_imf_overwrite": "the challenge TLV is sent truncated (`74` with no length)",
        "test_070_oath.py::test_imf_more": "the challenge TLV is sent truncated (`74` with no length)",
        # These enroll 7-byte and 9-byte HMAC secrets (`foo bar`, `blahonga!`).
        # A YubiKey 5.7.4 answers `6A80` and stores nothing below a 16-byte KEY
        # TLV — measured across the whole boundary — and RS-Key matches the card
        # rather than pico-fido here (E34). `test_bothoath` and
        # `test_imf_overwrite` above enroll short secrets too; they were already
        # listed for the challenge TLV and now fail one step earlier.
        "test_070_oath.py::test_rename_prefix_extension": "enrolls a 7-byte OATH secret; a YubiKey refuses a KEY TLV under 16 bytes",
        "test_070_oath.py::test_delete": "enrolls a 9-byte OATH secret; a YubiKey refuses a KEY TLV under 16 bytes",
        # CTAP 2.3.1 §6.4 lists encCredStoreState (0x1E) as **Optional**, like its
        # sibling encIdentifier (0x19); RS-Key emits neither. Both are conveniences
        # for a platform holding the persistent pinUvAuthToken — a cache-invalidation
        # hint and a device id — and §6.4 conditions neither on the perCredMgmtRO
        # option, which RS-Key does set. Not implemented, not required.
        "test_000_getinfo.py::test_get_info_ctap_23_fields_are_well_formed": "encCredStoreState (0x1E) is Optional in §6.4 and not implemented",
        "test_000_getinfo.py::test_enc_cred_store_state_changes_with_resident_credentials": "encCredStoreState (0x1E) is Optional in §6.4 and not implemented",
        # pinComplexityPolicy (0x1B), also Optional in §6.4. Absent, so
        # python-fido2 refuses the setMinPINLength parameter locally.
        "test_037_minpinlength.py::test_pin_complexity_policy_extension": "pinComplexityPolicy (0x1B) is Optional in §6.4 and not implemented",
        # The suite hardcodes its own device's limit (120) instead of reading
        # `maxRPIDsForSetMinPINLength`, which §6.11.4 tells platforms to read:
        # "Platform can track how many RP IDs it can set, by checking value of the
        # maxRPIDsForSetMinPINLength member". RS-Key advertises 8, so 121 RP IDs
        # overrun MAX_RAW_SUBPARA before the count is reached and the answer is
        # REQUEST_TOO_LARGE. At *this* device's limit + 1 the answer is the
        # KEY_STORE_FULL the test wants — measured, not assumed.
        "test_037_minpinlength.py::test_setminpin_too_many_rpids": "the suite sends 121 RP IDs, ignoring the maxRPIDsForSetMinPINLength (8) §6.11.4 says to read",
        # CTAP 2.3.1 §12.9, verbatim: "authenticatorMakeCredential authenticator
        # extension output: None." The test asserts an authData extension output
        # the extension does not define. RS-Key persists the flag and returns it
        # where §12.9 does define an output — getAssertion, and credMgmt 0x0C.
        "test_040_cred_mgmt.py::test_credential_management_reports_third_party_payment": "§12.9 defines NO makeCredential extension output for thirdPartyPayment",
        # The CTAPHID MSG channel exposes the RS-Key vendor AID (`F0 00 00 00 01`),
        # not the Yubico Management one — device config over FIDO is CTAPHID `0x41`
        # here (docs/protocol.md §9), and ykman reaches management over CCID or its
        # own CTAPHID vendor commands, never an AID SELECT on MSG. The property the
        # test is named for holds: with the vendor applet selected a U2F VERSION is
        # 6D00, and after CTAPHID_INIT it is `U2F_V2 9000` again (`deselect_msg`).
        "test_055_hid.py::TestHID::test_msg_vendor_select_does_not_hijack_u2f_after_init": "the FIDO MSG channel carries the RS-Key vendor AID, not the Management one",
    },
    # The first three entries are one question, and the spec answers it twice,
    # differently.
    #
    # §4.4.1: "Simple DOs (S) return only the value with GET DATA. Constructed DOs
    # (C, marked yellow) are returned INCLUDING THEIR TAG AND LENGTH."
    # §7.2.6, worked example: `00 CA 00 65 00` → `5B 0B … 5F2D 02 … 5F35 01 31`,
    # with no `65` wrapper at all.
    #
    # RS-Key follows §4.4.1 and sends the wrapper (`7a 05 93 03 …`); the
    # Gnuk-derived suite follows the §7.2.6 example and expects the children alone.
    # GnuPG 2.4.8 reads our card completely — every field of `gpg --card-status`,
    # including everything inside DO 6E — so both framings are live in the wild and
    # the dominant client copes with either.
    #
    # Listed rather than "fixed" because moving to the other reading is a wire
    # change: a `bcdDevice` bump and every reader of these DOs (`tools/tui`'s
    # `ber_find`, `tools/rsk`, the trusted display's OpenPGP screens) revisited.
    # That is the maintainer's call on an ambiguous spec, not a test's.
    "openpgp": {
        "::test_ds_counter": "§4.4.1 vs §7.2.6: we send DO 7A with its own tag; the example omits it",
        "::test_app_data": "§4.4.1 vs §7.2.6: we send DO 6E with its own tag; the example omits it",
        # This one asks a second question too: with the wrapper gone we would send
        # `5b 00 5f 2d 00 5f 35 00`, and the suite wants an unset cardholder DO to
        # be empty rather than to carry empty children. §4.4.1 allows a zero-length
        # Name; whether it must be absent is unstated.
        "::test_name_lang_sex": "§4.4.1 vs §7.2.6 wrapper, plus: unset cardholder children present vs absent",
        # The same wrapper question, reached through the new pcsc section: it reads
        # DO 6E and asserts the response *starts* with the child tag `4F`.
        "::test_openpgp_status_objects": "§4.4.1 vs §7.2.6: DO 6E arrives with its own tag, so it starts 6E, not 4F",
        # Both halves of this one are content errors, not length errors: an ECDSA
        # attribute whose OID is 16 zero bytes, and an RSA attribute truncated to
        # two. The spec's own gloss splits them — `6700 Wrong length (Lc and/or
        # Le)` is about the ISO length fields, `6A80 Incorrect parameters in the
        # command data field` is about the content. RS-Key answers 6A80 to both;
        # the rejection the test is named for happens either way.
        "::test_openpgp_rejects_invalid_algorithm_attributes": "6A80 (bad data field) rather than 6700, whose gloss is 'Lc and/or Le'",
        # CHANGE REFERENCE DATA with P2 = 82. §7.2.3 defines exactly two: "P2 81
        # (PW1) or 83 (PW3)". An undefined P2 is what `6B00 Wrong parameters P1-P2`
        # is for; `6A88 Referenced data … not found` describes a defined reference
        # that is absent. RS-Key answers 6B00 for 82 and for 84 alike.
        "::test_openpgp_reset_code_and_pw_status": "§7.2.3 defines P2 81/83 only, so 82 is 6B00 (wrong P1-P2), not 6A88",
        # Reported firmware version. RS-Key defaults to 5.7.4 (a current YubiKey 5,
        # `FW_VERSION=X.Y.Z` at build time); the suite hardcodes its own device's
        # 5.7.0. One number, read through the Management DeviceInfo TLV and through
        # PIV GET VERSION.
        "::test_management_applet_config": "the suite hardcodes its own 5.7.0; RS-Key reports FW_VERSION (5.7.4)",
        "::test_piv_basic_version_serial_and_object_round_trip": "the suite hardcodes its own 5.7.0; RS-Key reports FW_VERSION (5.7.4)",
        # Replaying a single-auth challenge as a mutual-auth witness. RS-Key
        # refuses it a step earlier than the suite expects — on the challenge
        # *kind* (`ChallengeKind::MutualWitness`, audit run-34), so it never
        # reaches the witness comparison that would answer 6984. 6A80 is the
        # bad-data-field code for a witness the card never issued.
        "::test_piv_management_auth_flow_binding": "the replayed witness is refused by challenge kind (6A80) before the comparison that answers 6984",
    },
}

# Whole modules that exercise a *vendor extension* RS-Key does not implement.
# Unlike a divergence these are removed at collection, because an xfail still runs
# the test: admin-less mode expects PW3 verification to fail, and on a card without
# it those are three wrong admin PINs — the counter blocks and every later module
# fails on a card the suite itself bricked. Deselecting the feature took the run
# from 192 failures to 13; the difference was all cascade.
#
# This is upstream's own `skip_gnuk_only_tests` fixture, reinstated from outside
# after upstream deleted it. Removing an entry is a claim that RS-Key grew the
# feature, and the tests are here to check that claim.
INAPPLICABLE: dict[str, dict[str, str]] = {
    "fido": {},
    "openpgp": {
        # Gnuk's admin-less mode: setting PW1 equal to PW3 makes PW1 authorize
        # admin operations, and PW3 then answers 6982 rather than counting down.
        # OpenPGP Card 3.4.1 does not mention it — the phrase appears nowhere in
        # the spec — and it is a security-relevant privilege change, so adopting it
        # is a maintainer's decision, not a test's.
        "010_kdfnone/test_040_adminless_kdfnone.py": "Gnuk admin-less mode: PW1 gains admin rights, absent from OpenPGP Card 3.4.1",
        "010_kdfnone/test_041_adminless_kdfnone.py": "runs inside the admin-less block above",
        "010_kdfnone/test_042_adminless_kdfnone.py": "runs inside the admin-less block above",
        "010_kdfnone/test_043_adminless_kdfnone.py": "runs inside the admin-less block above",
        "010_kdfnone/test_044_adminless_kdfnone.py": "runs inside the admin-less block above",
        "010_kdfnone/test_045_adminless_kdfnone.py": "runs inside the admin-less block above",
        "010_kdfnone/test_046_adminless_kdfnone.py": "runs inside the admin-less block above",
        "010_kdfnone/test_047_adminless_upgrade_kdfnone.py": "opts an admin-full card into admin-less mode explicitly",
        "030_kdfsingle/test_070_adminless_kdfsingle.py": "Gnuk admin-less mode, over a single-salt KDF",
        "030_kdfsingle/test_071_adminless_kdfsingle.py": "runs inside the admin-less block above",
        "030_kdfsingle/test_072_adminless_kdfsingle.py": "runs inside the admin-less block above",
        "030_kdfsingle/test_073_adminless_kdfsingle.py": "runs inside the admin-less block above",
        "030_kdfsingle/test_074_adminless_kdfsingle.py": "runs inside the admin-less block above",
        "030_kdfsingle/test_075_adminless_kdfsingle.py": "runs inside the admin-less block above",
        # Clearing PW3 to the empty string — the doorway into admin-less mode, and
        # upstream's own comment used to read "Gnuk specific feature of clear PW3"
        # before the guard was dropped. §4.3.1 puts PW3 at "8 characters/digits
        # minimum", so a zero-length new PW3 is 6985 here (the APDU is well
        # formed; it is the value inside it the card will not take).
        "010_kdfnone/test_019_adminfull_kdfnone.py": "clearing PW3 to empty: §4.3.1 sets an 8-character minimum",
        "020_kdffull/05_finalize/test_059_adminfull_kdffull.py": "clearing PW3 to empty: §4.3.1 sets an 8-character minimum",
        "030_kdfsingle/test_066_adminfull_kdfsingle.py": "clearing PW3 to empty: §4.3.1 sets an 8-character minimum",
        "030_kdfsingle/test_076_adminless_kdfsingle.py": "clearing PW3 to empty: §4.3.1 sets an 8-character minimum",
    },
}

# Sections moved to the end of the run. `040_pcsc_extra` switches applets (PIV,
# Management) and restores the OpenPGP selection on its last line — a line an
# xfailed test never reaches, which leaves the next section talking to the wrong
# applet (VERIFY answers 6A88, PUT DATA 6D00). Ordering it last costs nothing,
# because nothing comes after it, and keeps a listed divergence from failing seven
# tests in `090_finalize` that have nothing to do with it.
LAST: dict[str, tuple[str, ...]] = {
    "fido": (),
    "openpgp": ("040_pcsc_extra/",),
}


def _match(patterns, nodeid):
    """The first pattern that is a substring of `nodeid`, with its reason."""
    for pattern, reason in patterns.items():
        if pattern in nodeid:
            return pattern, reason
    return None, None


class Plugin:
    """Steers a vendored suite from outside: the power cycle it cannot ask for,
    the sections that must not poison the card, and the divergences it does not
    know about."""

    def __init__(self, suite):
        self.suite = suite
        self.marked = []
        self.dropped = {}

    def pytest_configure(self, config):
        _install_power_cycle()
        _install_reboot()
        config.addinivalue_line("markers", "rsk_divergence: expected, and why")

    def pytest_collection_modifyitems(self, config, items):
        import pytest

        keep, drop = [], []
        for item in items:
            pattern, reason = _match(INAPPLICABLE[self.suite], item.nodeid)
            if pattern:
                self.dropped.setdefault(pattern, [reason, 0])[1] += 1
                drop.append(item)
                continue
            _, reason = _match(DIVERGENCES[self.suite], item.nodeid)
            if reason:
                item.add_marker(
                    pytest.mark.xfail(reason=f"RS-Key: {reason}", strict=True)
                )
                self.marked.append((item.nodeid, reason))
            keep.append(item)

        if drop:
            config.hook.pytest_deselected(items=drop)
        late = LAST[self.suite]
        items[:] = [i for i in keep if not any(p in i.nodeid for p in late)]
        items += [i for i in keep if any(p in i.nodeid for p in late)]

    def pytest_terminal_summary(self, terminalreporter):
        if self.dropped:
            terminalreporter.write_sep("=", "RS-Key: not applicable (deselected)")
            for pattern, (reason, count) in self.dropped.items():
                terminalreporter.write_line(f"  {pattern} ({count})\n      {reason}")
        if not self.marked:
            return
        terminalreporter.write_sep("=", "RS-Key divergences (expected, xfail)")
        for nodeid, reason in self.marked:
            terminalreporter.write_line(f"  {nodeid}\n      {reason}")


def _install_power_cycle():
    """Let `authenticatorReset` through.

    RS-Key accepts a reset only inside the CTAP 2.1 §6.6 power-up window, which
    an operator reopens by unplugging; pico-fido has no such window, so its
    fixtures reset whenever they like and every one of them would fail. On a
    board that gap is a human with a USB port. Against the emulator it is one
    message on the card socket, so the suite gets what it would have got from a
    person — rather than an allow-list entry per fixture, which would mark 60
    tests as divergent when the divergence is a single rule.
    """
    try:
        from fido2.ctap2.base import Ctap2
    except ImportError:
        return  # the card suite has no CTAP2 in it

    original = Ctap2.reset

    def reset(self, *args, **kwargs):
        emu.power_cycle()
        return original(self, *args, **kwargs)

    Ctap2.reset = reset


def _install_reboot():
    """Answer the suite's "Please reboot authenticator and hit enter".

    pico-fido's `Device.reboot()` prompts an operator and waits five seconds; the
    tests that call it are checking state a power cycle clears — RS-Key's
    three-wrong-PINs-per-boot soft lock, which is exactly what the prompt is for.
    Left unanswered it times out and the device never actually rebooted, so those
    tests measure a lockout that was never lifted.

    The same operator stand-in the reset gets, for the same reason: a power cycle
    is one message on the card socket here.
    """
    conftest = sys.modules.get("conftest")
    device = getattr(conftest, "Device", None)
    if device is None or not hasattr(device, "reboot"):
        return

    original = device.reboot

    def reboot(self, *args, **kwargs):
        emu.power_cycle()
        return original(self, *args, **kwargs)

    device.reboot = reboot


def run(suite, extra):
    import pytest

    rel, shim = SUITES[suite]
    if shim:
        emu.install()
    print(f"== {suite}: {rel}{' (over the emulator socket)' if shim else ''}")
    return pytest.main([os.path.join(ROOT, rel), *extra], plugins=[Plugin(suite)])


def main():
    args = sys.argv[1:]
    which = args[0] if args and not args[0].startswith("-") else "all"
    extra = [a for a in args[1:] if a != "--"]
    if which not in (*SUITES, "all"):
        sys.exit(f"usage: {sys.argv[0]} [{'|'.join(SUITES)}|all] [pytest args…]")

    codes = {s: run(s, extra) for s in (SUITES if which == "all" else [which])}
    for suite, code in codes.items():
        print(f"{suite}: pytest exit {code}")
    sys.exit(max(int(c) for c in codes.values()))


if __name__ == "__main__":
    main()
