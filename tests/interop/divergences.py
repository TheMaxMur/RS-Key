# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""The known-divergence allow-list for the RS-Key ↔ YubiKey differential.

`diff.py` compares two device snapshots field by field. Most fields must match;
the ones that legitimately differ between RS-Key and a genuine YubiKey are
declared here as *rules*, so a real fidelity gap (an unexplained diff) stands out
from an expected one. Each rule is a spec, not a blindfold: it says *how* the two
sides are allowed to differ, and flags a `RULE_VIOLATION` if the divergence
itself drifts (the firmware changed, or this list went stale).

Rule kinds, first match wins (list order = most specific first):

- `Ignore`      — drop the field (per-device randomness: key material, GUIDs, salts).
- `Tolerance`   — a live/capacity counter; any value is fine (retries, fw patch).
- `ExpectDiff`  — assert each side matches its own pattern; the diff is expected
                  but pinned, so a drift on either side is a RULE_VIOLATION.
- `Superset`    — a set field; RS-Key may add elements, but must not *lack* one the
                  real key has (except an explicit `exclude` set, e.g. U2F_V2).
- (no rule)     — differ ⇒ `UNEXPECTED` (a fidelity gap); equal ⇒ `MATCH`.
"""
import fnmatch
import re

# Sentinel for a canonical key present in only one snapshot.
MISSING = "<missing>"

# Result buckets diff.py sorts every field into.
MATCH = "MATCH"
ALLOWED = "ALLOWED"
RULE_VIOLATION = "RULE_VIOLATION"
UNEXPECTED = "UNEXPECTED"


def _scalar(v):
    """Canonical string form for pattern matching. Lists collapse to a sorted,
    comma-joined form so a set-valued field can be pinned by ExpectDiff too."""
    if isinstance(v, (list, tuple)):
        return ",".join(sorted(str(x) for x in v))
    return str(v)


class Rule:
    kind = "RULE"

    def __init__(self, reason):
        self.reason = reason

    def classify(self, real, rsk):
        """Return (bucket, detail). Overridden per kind."""
        raise NotImplementedError


class Ignore(Rule):
    kind = "IGNORE"

    def classify(self, real, rsk):
        return ALLOWED, "ignored"


class Tolerance(Rule):
    kind = "TOLERANCE"

    def classify(self, real, rsk):
        return (MATCH if real == rsk else ALLOWED), None


class ExpectDiff(Rule):
    kind = "EXPECT_DIFF"

    def __init__(self, real, rsk, reason):
        super().__init__(reason)
        self._real = re.compile(real) if real else None
        self._rsk = re.compile(rsk) if rsk else None

    def classify(self, real, rsk):
        if real == rsk:
            return MATCH, None  # no divergence to explain — the pins are moot
        ok_real = self._real is None or bool(self._real.search(_scalar(real)))
        ok_rsk = self._rsk is None or bool(self._rsk.search(_scalar(rsk)))
        if ok_real and ok_rsk:
            return ALLOWED, None
        bad = []
        if not ok_real:
            bad.append(f"real={real!r} !~ /{self._real.pattern}/")
        if not ok_rsk:
            bad.append(f"rsk={rsk!r} !~ /{self._rsk.pattern}/")
        return RULE_VIOLATION, "; ".join(bad)


class Superset(Rule):
    kind = "SUPERSET"

    def __init__(self, reason, exclude=()):
        super().__init__(reason)
        self.exclude = frozenset(exclude)

    @staticmethod
    def _as_set(v):
        if v is MISSING:
            return set()
        if isinstance(v, (list, tuple, set)):
            return set(v)
        return {v}

    def classify(self, real, rsk):
        missing = (self._as_set(real) - self._as_set(rsk)) - self.exclude
        if not missing:
            return ALLOWED, None
        return UNEXPECTED, f"RS-Key lacks {sorted(missing)}"


# ── The allow-list ──────────────────────────────────────────────────────────
# Ordered; the first glob (fnmatch, case-sensitive) that matches a canonical
# dotted path wins. Keep the most specific paths above the broad globs.

RULES = [
    # ── per-device randomness — never diff the value ───────────────────────
    ("*.pubkey", Ignore("independent keygen — public key material")),
    ("*.cert", Ignore("independent keygen — certificate bytes")),
    ("*.certSerial", Ignore("random per-cert serial")),
    ("*.fingerprint", Ignore("independent keygen — key fingerprint")),
    ("*.timestamp", Ignore("key generation timestamp")),
    ("*.guid", Ignore("random GUID")),
    ("piv.chuid", Ignore("random CHUID/CCC GUID")),
    ("oath.deviceId", Ignore("random OATH device id / SELECT salt")),
    ("*.salt", Ignore("random salt")),
    ("otp.slot*.publicId", Ignore("Yubico-OTP public id / device serial")),

    # ── live or capacity counters — any value is acceptable ────────────────
    ("*Retries", Tolerance("live PIN/PUK/PW retry counter — never diff, never wrong-PIN")),
    ("fido.getinfo.remainingDiscoverableCredentials", Tolerance("capacity + live occupancy")),
    ("fido.credmgmt.maxPossibleRemainingResidentCredentialsCount",
     Tolerance("RS-Key store capacity differs from YubiKey's 25")),
    ("*.remaining*", Tolerance("live remaining-capacity counter")),

    # ── version fields — tolerate a 5.7.x patch skew across the two keys ────
    ("fido.getinfo.firmwareVersion", Tolerance("fw version; 5.7.x patch skew")),
    ("mgmt.version", Tolerance("reported fw version; 5.7.x patch skew")),
    ("piv.version", Tolerance("PIV applet version; 5.7.x patch skew")),
    ("oath.version", Tolerance("OATH applet version; 5.7.x patch skew")),
    ("openpgp.card.version", Tolerance("OpenPGP card-spec version (both 3.4)")),

    # ── identity — expected to differ, each side pinned ────────────────────
    ("usb.serialNumber",
     ExpectDiff(None, r"rs-key-0001",
                "RS-Key ships a fixed USB serial string; a real YubiKey exposes none (serial is via the mgmt applet)")),
    ("usb.bcdDevice",
     ExpectDiff(None, r"(?i)0x08", "RS-Key bcdDevice is an internal build counter (0x08xx)")),
    ("usb.product", ExpectDiff(None, r"(?i)yubikey", "product strings differ; RS-Key carries 'RSK'")),
    ("usb.manufacturer", ExpectDiff(None, None, "manufacturer string may differ")),
    ("ccid.atr", ExpectDiff(None, None, "ATR historical bytes differ (real spells 'YubiKey')")),
    ("ccid.reader", ExpectDiff(None, None, "PC/SC reader name differs")),
    ("mgmt.serial", ExpectDiff(r"\d+", None, "serial is chip-id-derived and differs")),
    ("mgmt.formFactor",
     ExpectDiff(None, None, "RS-Key hardcodes USB-A keychain (0x01) vs the real 5C's USB-C")),
    ("mgmt.nfcSupported", ExpectDiff(None, r"(?i)(<missing>|^0$|none)", "RS-Key has no NFC")),
    ("mgmt.nfcEnabled", ExpectDiff(None, r"(?i)(<missing>|^0$|none)", "RS-Key has no NFC")),
    ("fido.getinfo.aaguid",
     ExpectDiff(None, r"(?i)2479c7bf", "RS-Key self-assigns AAGUID 2479c7bf-… (not Yubico's)")),
    ("openpgp.aid", ExpectDiff(None, None, "OpenPGP AID manufacturer + serial bytes differ")),
    ("openpgp.appVersion",
     ExpectDiff(None, r"4\.6", "vendor app version pico-openpgp 4.6.x vs Yubico's")),

    # ── capacity constants — RS-Key is larger, expected to differ ──────────
    ("fido.getinfo.maxMsgSize", ExpectDiff(None, r"7609", "RS-Key maxMsgSize 7609 vs real ~1200")),
    ("fido.getinfo.maxCredentialCountInList",
     ExpectDiff(None, r"16", "RS-Key allows 16 vs real 8")),
    ("fido.getinfo.maxCredentialIdLength", ExpectDiff(None, None, "credential-id box length differs")),
    ("fido.getinfo.maxSerializedLargeBlobArray",
     ExpectDiff(None, r"2046",
                "RS-Key advertises its store's true per-value ceiling, rsk_fs::MAX_VALUE_BYTES")),
    ("fido.getinfo.maxCredBlobLength", ExpectDiff(None, r"128", "RS-Key 128 vs real 32")),
    ("fido.getinfo.maxRPIDsForSetMinPINLength", ExpectDiff(None, None, "RS-Key 8 vs real 1")),

    # ── FIDO getInfo option skew (build-config), each side pinned ──────────
    # alwaysUv is a runtime toggle on BOTH keys (`ykman fido config
    # toggle-always-uv`), so neither side can be pinned without the rule going
    # stale the next time someone flips it — and makeCredUvNotRqd just mirrors it
    # (CTAP 2.1 §6.4: alwaysUv true ⇒ makeCredUvNotRqd false).
    ("fido.getinfo.options.alwaysUv",
     ExpectDiff(None, None, "alwaysUv is runtime-toggleable on both keys (and a build knob here)")),
    ("fido.getinfo.options.makeCredUvNotRqd",
     ExpectDiff(None, None, "mirrors alwaysUv, which is runtime-toggleable on both keys")),
    ("fido.getinfo.minPINLength",
     ExpectDiff(None, r"^[46]$",
                "RS-Key's PIN floor is a build knob (strong-pin / fips-profile raise CTAP's 4 to 6)")),
    ("fido.getinfo.options.bioEnroll", ExpectDiff(None, r"(?i)<missing>", "no bio on either 5-series / RS-Key")),
    ("fido.getinfo.options.uvBioEnroll", ExpectDiff(None, r"(?i)<missing>", "no bio on RS-Key")),
    ("fido.getinfo.options.credentialMgmtPreview",
     ExpectDiff(None, None, "legacy preview option — presence differs by firmware era")),

    # ── set-valued fields ─────────────────────────────────────────────────
    ("fido.getinfo.versions",
     Superset("RS-Key drops U2F_V2 under alwaysUv (CTAP 2.1 §7.2.4) and the legacy FIDO_2_1_PRE, "
              "and adds FIDO_2_2/2_3", exclude={"U2F_V2", "FIDO_2_1_PRE"})),
    ("fido.getinfo.extensions", Superset("RS-Key extension set is a superset")),
    ("fido.getinfo.algorithms", Superset("RS-Key advertises a superset (ES384/512/256K, +ML-DSA)")),
    ("fido.getinfo.attestationFormats", Superset("attestation-format set; order-insensitive")),
    ("fido.getinfo.transports",
     ExpectDiff(r"nfc", r"^usb$", "RS-Key is USB-only; a real 5C NFC also lists nfc")),
    ("fido.getinfo.certifications",
     ExpectDiff(None, r"(?i)<missing>", "RS-Key advertises no FIDO/FIPS certification levels")),

    # ── OpenPGP structural divergences ────────────────────────────────────
    ("openpgp.secureMessaging",
     ExpectDiff(None, r"(?i)(<missing>|^0$|off|false)", "RS-Key does not implement OpenPGP secure messaging")),
    ("openpgp.algoInfo", Superset("Ed448/X448 advertised-unimplemented; no Brainpool — set differences")),

    # ── PIV structural ────────────────────────────────────────────────────
    ("piv.attestation.rootSelfSigned",
     ExpectDiff(None, r"(?i)(true|1|yes)", "RS-Key F9 attestation CA is self-signed, not the Yubico PKI")),
    ("piv.not_before", Ignore("attestation/CHUID certificate validity date")),
    ("piv.not_after", Ignore("attestation/CHUID certificate validity date")),
    ("piv.serial", Ignore("attestation certificate serial — random per device")),
    # `ykman piv info` renders a slot only once something is loaded into it, so
    # these describe what each key was provisioned with, not what it can do.
    ("piv.issuer_dn", Ignore("provisioned slot contents, not a firmware property")),
    ("piv.subject_dn", Ignore("provisioned slot contents, not a firmware property")),
    ("piv.private_key_type", Ignore("provisioned slot contents, not a firmware property")),
    ("piv.public_key_type", Ignore("provisioned slot contents, not a firmware property")),
    ("openpgp.touch_policy", Ignore("per-key UIF, rendered only for a slot that holds a key")),

    # ── extra getInfo fields RS-Key advertises that the reference lacks ────
    # (the reverse — real has a field rsk lacks — fails the real-side pin below
    #  and surfaces as a RULE_VIOLATION, which is what we want.)
    ("fido.getinfo.key_0x*",
     ExpectDiff(r"<missing>", None, "RS-Key advertises an extra/experimental getInfo field")),
    ("fido.getinfo.options.ep",
     ExpectDiff(r"<missing>", None, "RS-Key advertises the enterprise-attestation (ep) option")),
    ("fido.getinfo.options.plat",
     ExpectDiff(None, r"<missing>", "reference advertises plat=false; RS-Key omits the default")),

    # ── management DeviceInfo TLV ──────────────────────────────────────────
    # Both the supported and the enabled masks: the real 5C carries YubiHSM Auth
    # (+extras) RS-Key does not implement. (RS-Key's own enabled ⊆ supported is a
    # within-device invariant, checked by rsk-mgmt's read_config_clamps test, not
    # here — a cross-device diff can only compare the two keys.)
    ("mgmt.usb*",
     ExpectDiff(None, None, "real 5C also supports/enables YubiHSM Auth (+extras) RS-Key lacks")),
    ("mgmt.chalRespTimeout", Ignore("challenge-response typing timeout — cosmetic; RS-Key leaves 0")),
    ("mgmt.autoEjectTimeout", Ignore("auto-eject timeout — cosmetic")),
    ("mgmt.deviceFlags", ExpectDiff(None, r"(?i)<missing>", "RS-Key's DeviceInfo omits the device-flags tag")),
    ("mgmt.configLock", ExpectDiff(None, r"(?i)<missing>", "RS-Key's DeviceInfo omits the config-lock tag")),
    ("mgmt.tag_0x*", Ignore("vendor-specific DeviceInfo tags differ between models")),

    # ── OpenPGP / OATH / OTP prose from ykman ─────────────────────────────
    ("openpgp.application_version",
     ExpectDiff(None, r"4\.6", "RS-Key OpenPGP app version is pico-openpgp 4.6.x; a real key tracks firmware")),

    # ── gpg-card / OpenSC views of the same two cards ─────────────────────
    ("openpgp.gpg.serial_number", Ignore("the OpenPGP AID embeds the chip-derived serial")),
    ("openpgp.gpg.displayed_s_n", Ignore("the OpenPGP AID embeds the chip-derived serial")),
    ("openpgp.gpg.reader", ExpectDiff(None, None, "PC/SC reader name differs")),
    ("openpgp.gpg.signature_counter", Tolerance("live PSO:CDS counter")),
    ("openpgp.gpg.signature_key", Ignore("independent keygen — key fingerprint or [none]")),
    ("openpgp.gpg.encryption_key", Ignore("independent keygen — key fingerprint or [none]")),
    ("openpgp.gpg.authentication_key", Ignore("independent keygen — key fingerprint or [none]")),
    # `-O` lists every object and kv_lines is last-write-wins, so these fields name
    # whichever object each key happens to end on — not a surface a diff can pin.
    # The comparable OpenSC view is the slot/token block, left compared below.
    ("pkcs11.obj.*", Ignore("flattened PKCS#11 object dump — provisioning-dependent and order-dependent")),
    ("pkcs11.slot_description", ExpectDiff(None, None, "PC/SC reader name differs")),
    ("pkcs11.serial_num", Ignore("OpenSC derives the token serial from the random CHUID GUID")),
    ("pkcs11.uri", Ignore("embeds the token serial")),
    ("pkcs11.token_label", Ignore("OpenSC labels the token from the provisioned 9A certificate")),

    # ── ykman-rendered mirrors (the precise raw cells are authoritative) ───
    ("ykman.info.device_type",
     ExpectDiff(None, None, "RS-Key reports model 'YubiKey 5A'; the reference is a '5C NFC'")),
    ("ykman.info.*", Ignore("ykman-rendered mirror of the precise mgmt DeviceInfo TLV")),
    ("fido.token.*", Ignore("fido2-token prose mirrors the authoritative raw getInfo cell (kept as raw evidence)")),
]


def rule_for(path):
    """The first rule whose glob matches `path`, or None."""
    for glob, rule in RULES:
        if fnmatch.fnmatchcase(path, glob):
            return rule
    return None


def classify(path, real, rsk):
    """Bucket one canonical field. Returns a dict the report renders directly."""
    rule = rule_for(path)
    if rule is None:
        bucket = MATCH if real == rsk else UNEXPECTED
        return {"path": path, "real": real, "rsk": rsk, "bucket": bucket,
                "rule": None, "reason": None, "detail": None}
    bucket, detail = rule.classify(real, rsk)
    return {"path": path, "real": real, "rsk": rsk, "bucket": bucket,
            "rule": rule.kind, "reason": rule.reason, "detail": detail}
