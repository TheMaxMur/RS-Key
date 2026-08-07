// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! FIDO constants — AIDs, CTAP command bytes, COSE algorithms/curves, auth-data
//! flags, the AAGUID, size limits and flash file ids.

use rsk_fs::KeyFid;

/// FIDO2 applet AID.
pub const FIDO_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
/// Backup FIDO2 applet AID.
pub const FIDO_AID_BACKUP: &[u8] = &[0xB0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
/// U2F applet AID.
pub const U2F_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x10, 0x02];

// CTAP1 / U2F command INS bytes.
pub const CTAP_REGISTER: u8 = 0x01;
pub const CTAP_AUTHENTICATE: u8 = 0x02;
pub const CTAP_VERSION: u8 = 0x03;
/// The U2F APDU INS that carries a CTAP2 CBOR message.
pub const CTAP_CBOR: u8 = 0x10;

// CTAP2 command bytes (the first byte of a CTAPHID_CBOR message).
pub const CTAP_MAKE_CREDENTIAL: u8 = 0x01;
pub const CTAP_GET_ASSERTION: u8 = 0x02;
pub const CTAP_GET_INFO: u8 = 0x04;
pub const CTAP_CLIENT_PIN: u8 = 0x06;
pub const CTAP_RESET: u8 = 0x07;
pub const CTAP_GET_NEXT_ASSERTION: u8 = 0x08;
pub const CTAP_CREDENTIAL_MGMT: u8 = 0x0A;
pub const CTAP_SELECTION: u8 = 0x0B;
pub const CTAP_LARGE_BLOBS: u8 = 0x0C;
pub const CTAP_CONFIG: u8 = 0x0D;
pub const CTAP_VENDOR: u8 = 0x41; // vendor range: seed backup + MSE channel

// authenticatorVendor (0x41) subcommands — wallet-style seed backup. Export hands
// the raw 32-byte seed *value* over the encrypted MSE channel so the host can
// render it as a BIP-39 / SLIP-39 mnemonic; restore re-seals it under this
// chip's kbase.
pub const VENDOR_MSE: u64 = 0x01; // establish the ECDH key-agreement channel
pub const VENDOR_BACKUP_EXPORT: u64 = 0x02; // hand the seed to the host (gated)
pub const VENDOR_BACKUP_LOAD: u64 = 0x03; // install a seed from the host (gated)
pub const VENDOR_BACKUP_FINALIZE: u64 = 0x04; // seal the one-time export window
pub const VENDOR_BACKUP_STATE: u64 = 0x05; // read the lock/backup flags (ungated)
pub const VENDOR_UNLOCK: u64 = 0x06; // soft-lock: decrypt EF_KEY_DEV_ENC to RAM
pub const VENDOR_AUDIT_READ: u64 = 0x07; // export the audit journal window
pub const VENDOR_AUDIT_CHECKPOINT: u64 = 0x08; // DEVK-signed chain checkpoint
pub const VENDOR_ATT_IMPORT: u64 = 0x09; // install org attestation key + chain
pub const VENDOR_ATT_CLEAR: u64 = 0x0A; // remove the org attestation
pub const VENDOR_ATT_STATE: u64 = 0x0B; // {present, chain hash} — ungated
pub const VENDOR_CONFIG_WRITE: u64 = 0x0C; // persist a device-config blob (PIN + touch)
pub const VENDOR_CONFIG_READ: u64 = 0x0D; // read a device-config record (ungated, for host RMW)
pub const VENDOR_AUDIT_CONFIG: u64 = 0x0E; // turn the audit journal on/off (PIN + touch), OFF by default

// Config-write targets — `subCommandParams` key 1 of `VENDOR_CONFIG_WRITE`. The
// FIDO-transport twin of the CCID device-config writes, so a host without a
// working pcscd can still configure the key (gated by PIN + touch, not the CCID
// path's presence-only).
pub const CONFIG_TARGET_DEV_CONF: u64 = 0x00; // management enabled-apps TLV (EF_DEV_CONF)
pub const CONFIG_TARGET_PHY: u64 = 0x01; // phy record: VID/PID, USB itf, LED, presence-timeout (EF_PHY)
pub const CONFIG_TARGET_LED: u64 = 0x02; // LED config block (EF_LED_CONF); applied live after the write

// authenticatorConfig subcommands.
pub const CONFIG_ENABLE_EA: u64 = 0x01; // enableEnterpriseAttestation
pub const CONFIG_TOGGLE_ALWAYS_UV: u64 = 0x02; // toggleAlwaysUv
pub const CONFIG_SET_MIN_PIN: u64 = 0x03; // setMinPINLength
pub const CONFIG_VENDOR: u64 = 0xFF; // vendor subcommands, selected by a u64 id

// authenticatorConfig vendor command ids — the soft-lock enable/disable pair.
pub const CONFIG_AUT_ENABLE: u64 = 0x03e43f56b34285e2;
pub const CONFIG_AUT_DISABLE: u64 = 0x1831a40f04a25ed9;

// PicoForge physical-config vendor ids — hardware config over FIDO
// (authenticatorConfig 0xFF, integer param at subCommandParams key 3). These are
// the ids PicoForge's legacy hardware-config path writes, so it configures the phy
// record over FIDO with no PC/SC. Each writes EF_PHY (effective on the next boot).
pub const CONFIG_PHY_VIDPID: u64 = 0x6fcb19b0cbe3acfa; // param = (vid << 16) | pid
pub const CONFIG_PHY_LED_BRIGHTNESS: u64 = 0x76a85945985d02fd; // param = brightness u8
pub const CONFIG_PHY_LED_GPIO: u64 = 0x7b392a394de9f948; // param = gpio u8
pub const CONFIG_PHY_OPTIONS: u64 = 0x269f3b09eceb805f; // param = opts u16 bitmask

// authenticatorClientPIN subcommands compared at more than one site (the rest
// are dispatched once as literals).
pub const CP_GET_PIN_TOKEN: u64 = 0x05;
pub const CP_GET_PIN_UV_TOKEN_USING_PIN: u64 = 0x09; // getPinUvAuthTokenUsingPinWithPermissions

// authenticatorCredentialManagement subcommands.
pub const CM_GET_CREDS_METADATA: u64 = 0x01;
pub const CM_ENUMERATE_RPS_BEGIN: u64 = 0x02;
pub const CM_ENUMERATE_RPS_NEXT: u64 = 0x03;
pub const CM_ENUMERATE_CREDS_BEGIN: u64 = 0x04;
pub const CM_ENUMERATE_CREDS_NEXT: u64 = 0x05;
pub const CM_DELETE_CREDENTIAL: u64 = 0x06;
pub const CM_UPDATE_USER_INFO: u64 = 0x07;

// credProtect levels.
pub const CRED_PROT_UV_OPTIONAL: u64 = 0x01;
pub const CRED_PROT_UV_OPTIONAL_WITH_LIST: u64 = 0x02;
pub const CRED_PROT_UV_REQUIRED: u64 = 0x03;

/// Max credBlob length; also advertised by getInfo (0x0F).
pub const MAX_CREDBLOB_LENGTH: usize = 128;

// COSE algorithm identifiers. Negative per the COSE registry.
pub const ALG_ES256: i64 = -7;
pub const ALG_ES384: i64 = -35;
pub const ALG_ES512: i64 = -36;
pub const ALG_ES256K: i64 = -47;
pub const ALG_EDDSA: i64 = -8;
pub const ALG_ECDH_ES_HKDF_256: i64 = -25; // clientPIN key agreement
// Curve-explicit aliases also accepted in pubKeyCredParams.
pub const ALG_ESP256: i64 = -9; // ECDSA-SHA256 P-256
pub const ALG_ED25519: i64 = -19; // EdDSA Ed25519
pub const ALG_ESP384: i64 = -51; // ECDSA-SHA384 P-384
pub const ALG_ESP512: i64 = -52; // ECDSA-SHA512 P-521

// ML-DSA (FIPS 204) COSE identifiers, from draft-ietf-cose-dilithium. ML-DSA-44
// (-48) and ML-DSA-65 (-49) have enabled in-tree backends; ML-DSA-87 (-50)
// overflows the RP2350 stack and is recognized but unsupported.
pub const ALG_MLDSA44: i64 = -48;
pub const ALG_MLDSA65: i64 = -49;
pub const ALG_MLDSA87: i64 = -50;
/// COSE key type AKP (Algorithm Key Pair) — ML-DSA public keys: `{1:7, 3:alg, -1:pub}`.
pub const KTY_AKP: u8 = 7;

// FIDO curve identifiers, used inside COSE keys.
pub const CURVE_P256: u8 = 1;
pub const CURVE_P384: u8 = 2;
pub const CURVE_P521: u8 = 3;
pub const CURVE_ED25519: u8 = 6;
pub const CURVE_P256K1: u8 = 8;
/// Internal key-slot id for ML-DSA-44 credentials. Not a real COSE curve — AKP
/// keys have none — but the credential box stores `(alg, curve)` and `CredKey`
/// selects on `curve`, so the lattice scheme gets a private id well clear of
/// the registered EC ids (0x2C = 44).
pub const CURVE_MLDSA44: u8 = 0x2C;
/// Internal key-slot id for ML-DSA-65 credentials (0x2D = 45), the sibling of
/// [`CURVE_MLDSA44`] for the higher-security parameter set.
pub const CURVE_MLDSA65: u8 = 0x2D;

// authenticatorData flag bits.
pub const FLAG_UP: u8 = 0x01; // user present
pub const FLAG_UV: u8 = 0x04; // user verified
pub const FLAG_AT: u8 = 0x40; // attested credential data included
pub const FLAG_ED: u8 = 0x80; // extension data included

/// AAGUID — RS-Key's own authenticator-model identifier (UUID **v5**), so the
/// device stops claiming the inherited model identity. Derived reproducibly as
/// `uuid5(NAMESPACE_URL, "https://github.com/TheMaxMur/RS-Key")`
/// = `2479c7bf-6b30-5683-9ec8-0e8171a918b7`. Self-assigned: an AAGUID needs no
/// central registration; FIDO MDS *listing* (a separate, certification-gated
/// step) is not required for the value itself. One AAGUID across every VID/PID
/// flavor — it identifies the firmware model, not the USB branding. Build-time
/// override: `AAGUID=<uuid-or-32-hex> cargo build` (resolved in `build.rs` and
/// baked as `PK_AAGUID`); the checked-in metadata statement then no longer matches.
pub const AAGUID: [u8; 16] = parse_aaguid(env!("PK_AAGUID"));

/// Const-parse the 32-char lowercase-hex `PK_AAGUID` (validated in `build.rs`)
/// into the 16 AAGUID bytes at compile time.
const fn parse_aaguid(s: &str) -> [u8; 16] {
    let b = s.as_bytes();
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = (hex_nibble(b[2 * i]) << 4) | hex_nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0, // build.rs guarantees lowercase hex, so this is unreachable
    }
}

/// firmwareVersion reported by getInfo (CTAP `0x0E`): the shared
/// [`rsk_sdk::FIRMWARE_VERSION`] (default 5.7.4, `FW_VERSION`-overridable) in
/// Yubico's `(major << 16) | (minor << 8) | patch` form, so FIDO tooling
/// (`ykman` / Yubico Authenticator) reads a current YubiKey 5 version
/// consistent with the default YubiKey 5 VID/PID.
pub const FIRMWARE_VERSION: u32 = rsk_sdk::FIRMWARE_VERSION_U32;

// Size limits advertised by getInfo.
/// ML-DSA-44 responses run ~3.9 KB, so we advertise the full CTAPHID transport
/// maximum (57 + 128·59) end-to-end — every buffer on the path (reassembler,
/// worker exchange, applet response) holds this. `MAX_FRAGMENT_LENGTH` tracks
/// it per the spec's `maxMsgSize - 64`.
pub const MAX_MSG_SIZE: u64 = 7609;
/// Mirrors `credential::CRED_BOX_MAX`: the largest credentialId this device
/// mints (a non-resident box) — and therefore the largest it will assert.
pub const MAX_CRED_ID_LENGTH: u64 = crate::credential::CRED_BOX_MAX as u64;
pub const MAX_CREDENTIAL_COUNT_IN_LIST: u64 = 16;

// pinUvAuthParam MAC covers subCommand ‖ subCommandParams; cap on the raw bytes
// (vendor.rs deliberately overrides with its own larger cap). A maximal legal
// updateUserInformation — 42-byte resident credId + 64-byte user.id + 64-byte
// name + 64-byte displayName — encodes to 286; a full transports echo adds ~40.
pub const MAX_RAW_SUBPARA: usize = 384;

/// Max serialized large-blob array stored; also the getInfo
/// `maxSerializedLargeBlobArray` (0x0B). Bounded by the store's per-value ceiling
/// so the advertised number is one the device can actually commit — the sibling
/// of the ATT_IMPORT cap mismatch (audit run-32).
pub const MAX_LARGE_BLOB_SIZE: usize = rsk_fs::MAX_VALUE_BYTES;
/// Max bytes per `authenticatorLargeBlobs` fragment.
pub const MAX_FRAGMENT_LENGTH: usize = MAX_MSG_SIZE as usize - 64;
/// Initial serialized large-blob array: the empty CBOR array `0x80` followed
/// by the left 16 bytes of its SHA-256 — the CTAP2.1 default value.
pub const LARGEBLOB_INITIAL: [u8; 17] = [
    0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d,
    0x3c,
];
/// Minimum serialized large-blob array: the empty CBOR array `0x80` + 16-byte
/// SHA-256 tail — the CTAP2.1 default.
pub const LARGEBLOB_MIN: usize = LARGEBLOB_INITIAL.len();

/// Max resident credentials / relying parties.
pub const MAX_RESIDENT_CREDENTIALS: u16 = 256;
/// Max RP-id hashes the setMinPINLength `minPinLengthRPIDs` list keeps (getInfo
/// `maxRPIDsForSetMinPINLength`, 0x10).
pub const MAX_MIN_PIN_RPIDS: usize = 8;

// FIDO flash file ids (device-local; fids never cross the wire).
// Audit journal (journal.rs) — deliberately outside every reset range: FIDO's
// authenticatorReset wipes an explicit set (reset.rs), PIV factory-reset wipes
// 0xD100..=0xD2FF; the journal survives both by construction.
pub const EF_AUDIT_META: u16 = 0xC100; // ver ‖ seq_next ‖ start ‖ epoch hash
/// Opt-in flag for the audit journal: journalling is OFF unless this file is
/// present. Absent by default (fresh + upgraded devices) so `journal::append`
/// writes nothing; the host turns it on with `VENDOR_AUDIT_CONFIG`. Sits in the
/// audit block (outside `authenticatorReset`), so a host reset keeps the user's
/// choice while the full display factory-wipe clears it back to the OFF default.
pub const EF_AUDIT_ENABLED: u16 = 0xC101;
pub const EF_AUDIT_RING: u16 = 0xC110; // entry slots, 0xC110..0xC110+AUDIT_RING_SLOTS
pub const AUDIT_RING_SLOTS: u32 = 128;
pub const EF_KEY_DEV: KeyFid = KeyFid::new(0xCC00); // device master seed, kbase-sealed
pub const EF_BACKUP_SEALED: u16 = 0xCC02; // [1] once the seed has been backed up
/// Soft-locked seed: ChaCha20-Poly1305(host lock key) over the seed value.
pub const EF_KEY_DEV_ENC: KeyFid = KeyFid::new(0xCC03);
pub const EF_EE_DEV: u16 = 0xCE00; // U2F end-entity attestation certificate
// Org-provisioned attestation (vendor ATT_IMPORT). Device identity, not user
// data: both survive authenticatorReset; ATT_CLEAR removes them.
pub const EF_ATT_KEY: KeyFid = KeyFid::new(0xCE10); // org attestation P-256 scalar, kbase-sealed
pub const EF_ATT_CHAIN: u16 = 0xCE11; // packed DER chain: count ‖ (len LE ‖ der)*
/// `enableEnterpriseAttestation` — persists until reset (CTAP 2.1), hence flash.
pub const EF_EA_ENABLED: u16 = 0xCE12;
/// `alwaysUv` state, read via [`crate::config::always_uv_enabled`] — tri-state:
/// absent = the compile default (`DEFAULT_ALWAYS_UV`), `[1]` = on, `[0]` = explicit
/// off. Do NOT probe with `has_data` (a present `[0]` would read as on). Persists
/// until authenticatorReset (flash, CTAP 2.1).
pub const EF_ALWAYS_UV: u16 = 0xCE13;
/// The at-rest hardening marker. Defined in `rsk-fs` (every applet that lazily
/// re-keys a pre-OTP record must be able to re-arm the scrub); re-exported here
/// because the boot wiring and the FIDO reset scope both name it.
pub use rsk_fs::EF_HARDENED;
/// Trusted-display **device PIN** — gates the on-device UI (unlock, delete, factory
/// reset), independent of the FIDO clientPIN (`EF_PIN`). Same record format
/// `[retries, len, format, verifier(32)]`, device-sealed. Wiped by `authenticatorReset`
/// (so a forgotten device PIN is recoverable by a host reset) and by factory reset. NOT
/// in the OpenPGP 0x10xx range — kept in FIDO's 0xCExx block to avoid an applet clash.
pub const EF_DEVICE_PIN: u16 = 0xCE20;
pub const EF_COUNTER: u16 = 0xC000; // global signature counter (U2F + legacy-cred migration seed)
/// Per-credential signature counters, a single packed `u32`-LE array indexed by
/// EF_CRED slot (`[..MAX_RESIDENT_CREDENTIALS*4]`). One file keeps the
/// dynamic-file budget flat, and being independent of the EF_CRED record version
/// it migrates every stored credential without touching its box or keys. An
/// absent slot entry means a credential created before this region existed: its
/// counter is seeded from `EF_COUNTER` on first use so it never DEcreases.
pub const EF_CRED_CTR: u16 = 0xC001;
pub const EF_CRED: u16 = 0xCF00; // resident credentials, 0xCF00..0xCFFF
pub const EF_RP: u16 = 0xD000; // relying-party metadata, 0xD000..0xD0FF
// Device-local relying-party display nicknames, 0xD300..0xD3FF (one slot per EF_RP
// slot). A trusted-display-only label sealed at rest; never crosses the wire and is
// not part of any credential, so it can't touch the box / signing key (PIV owns
// 0xD100..=0xD2FF, so this sits clear of it). Additive: absent on devices upgraded
// from before this region, which simply show the rpId.
pub const EF_RPNICK: u16 = 0xD300;
/// Longest device-local RP nickname (bytes) the trusted display stores + accepts.
pub const RP_NICK_MAX_LEN: usize = 24;
pub const EF_PIN: u16 = 0x1080; // PIN: [retries, len, format, verifier(32)]
pub const EF_AUTHTOKEN: u16 = 0x1090; // pinUvAuthToken seed
/// The **persistent** pinUvAuthToken (CTAP 2.2 §6.5.2.2): a bearer secret the
/// platform keeps across power cycles, so it is kbase-sealed like the seed. Its
/// *presence* is the `pcmr` grant — written at the first pcmr issuance, dropped
/// wherever the spec calls `resetPersistentPinUvAuthToken` (§6.5.4).
pub const EF_PAUTHTOKEN: KeyFid = KeyFid::new(0x1091);
pub const EF_MINPINLEN: u16 = 0x1100; // minimum PIN length policy
pub const EF_LARGEBLOB: u16 = 0x1101; // serialized large-blob array

/// PIN retry budget.
pub const MAX_PIN_RETRIES: u8 = 8;
/// Consecutive wrong PINs allowed per power cycle before clientPIN soft-locks and
/// demands a real power cycle (CTAP 2.1 §6.5.5.6). The batch is the whole point of
/// the rule, so it must survive a warm reset — see [`crate::state::PinLock`].
pub const PIN_MISMATCH_LIMIT: u8 = 3;
/// Default minimum PIN length when no policy is set.
#[cfg(not(any(feature = "fips-profile", feature = "strong-pin")))]
pub const MIN_PIN_LENGTH: u8 = 4;
/// The `fips-profile` and `strong-pin` builds raise the PIN floor to six code points.
#[cfg(any(feature = "fips-profile", feature = "strong-pin"))]
pub const MIN_PIN_LENGTH: u8 = 6;

/// pinUvAuthToken rolling inactivity window (CTAP 2.1 §6.5.5.7 initial usage
/// time limit): each use of the token pushes its deadline out by this much; if
/// the window elapses with no use, the token is retired. 30 s matches USB.
pub const PUAT_INITIAL_USAGE_LIMIT_MS: u64 = 30_000;
/// pinUvAuthToken absolute lifetime (CTAP 2.1 §6.5.5.7 max usage time period):
/// the token can never outlive this from issuance, even under constant use, so
/// it cannot linger for the whole power cycle.
pub const PUAT_MAX_USAGE_PERIOD_MS: u64 = 600_000;

/// `authenticatorReset` power-up window (CTAP 2.1 §6.6): an authenticator with no
/// display honors a reset only this long after power-up, so the wipe takes a
/// deliberate replug. Measured from a *power-on* reset — see
/// [`FidoState::warm_boot`](crate::FidoState#structfield.warm_boot).
pub const RESET_WINDOW_MS: u64 = 10_000;

// U2F authenticate control byte (P1) and flags.
pub const U2F_AUTH_ENFORCE: u8 = 0x03; // enforce user presence and sign
pub const U2F_AUTH_CHECK_ONLY: u8 = 0x07; // is this key handle ours?
pub const U2F_AUTH_NO_ENFORCE: u8 = 0x08; // don't enforce user presence and sign
pub const U2F_AUTH_FLAG_TUP: u8 = 0x01; // test-of-user-presence bit
pub const U2F_REGISTER_ID: u8 = 0x05; // registration response leading byte
