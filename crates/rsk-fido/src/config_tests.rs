// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::FidoState;
use crate::tests::journals;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::Device;
use rsk_crypto::pinproto;
use rsk_crypto::pinproto::PinProto;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

const TOKEN: [u8; 32] = [0x99; 32];

fn armed(perms: u8) -> FidoState {
    let mut s = FidoState::new();
    s.paut.token = TOKEN;
    s.paut.permissions = perms;
    s.begin_using_token(false, 0);
    s
}

// The setMinPINLength subCommandParams map `{1: new_min}`.
fn subpara_min_pin(new_min: u64) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 32];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(1).unwrap().u8(1).unwrap().u64(new_min).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

// Build a config request, MACing over 0xff×32 ‖ 0x0d ‖ subcmd ‖ subpara.
// A CBOR unsigned int: past 23 the value no longer fits the type byte.
fn push_uint(out: &mut std::vec::Vec<u8>, v: u8) {
    if v > 0x17 {
        out.push(0x18);
    }
    out.push(v);
}

// `{1: subCommand}` and nothing else — no pinUvAuthParam, no params.
fn bare_sub(subcmd: u8) -> std::vec::Vec<u8> {
    let mut req = std::vec![0xA1u8, 0x01];
    push_uint(&mut req, subcmd);
    req
}

fn config_request(subcmd: u8, subpara: &[u8], token: &[u8; 32]) -> std::vec::Vec<u8> {
    let mut vp = std::vec![0xffu8; 32];
    vp.push(CTAP_CONFIG);
    vp.push(subcmd);
    vp.extend_from_slice(subpara);
    let mut mac = [0u8; 32];
    let mlen = pinproto::authenticate(PinProto::Two, token, &vp, &mut mac).unwrap();

    let mut req = std::vec::Vec::new();
    let fields = if subpara.is_empty() { 3u8 } else { 4 };
    req.push(0xA0 | fields); // map(fields)
    req.push(0x01); // 1: subCommand
    push_uint(&mut req, subcmd);
    if !subpara.is_empty() {
        req.push(0x02); // 2: subCommandParams (raw)
        req.extend_from_slice(subpara);
    }
    req.extend_from_slice(&[0x03, 0x02]); // 3: pinUvAuthProtocol = 2
    req.push(0x04); // 4: pinUvAuthParam
    req.push(0x58); // byte string, 1-byte length
    req.push(mlen as u8);
    req.extend_from_slice(&mac[..mlen]);
    req
}

fn run(state: &mut FidoState, req: &[u8]) -> CtapResult {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    let mut out = [0u8; 64];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state,
        now_ms: 0,
    };
    authenticator_config(&mut ctx, req, &mut out)
}

fn run_fs<S: Storage>(fs: &mut Fs<S>, state: &mut FidoState, req: &[u8]) -> CtapResult {
    let mut rng = SeqRng(1);
    let mut out = [0u8; 64];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng: &mut rng,
        state,
        now_ms: 0,
    };
    authenticator_config(&mut ctx, req, &mut out)
}

#[test]
fn set_min_pin_length_stores_policy() {
    let mut fs = Fs::new(RamStorage::new());
    let mut state = armed(PERM_ACFG);
    let req = config_request(0x03, &subpara_min_pin(6), &TOKEN);
    assert_eq!(run_fs(&mut fs, &mut state, &req), Ok(0));
    let mut buf = [0u8; 2];
    assert_eq!(fs.read(EF_MINPINLEN, &mut buf), Some(2));
    assert_eq!(buf, [6, 0]); // minPINLength 6, no forced change
}

#[test]
fn set_min_pin_length_rejects_truncating_value() {
    // run-3 #3: a newMinPINLength above the max PIN length must be rejected
    // before the `as u8` store, which would truncate (256 -> 0) and pass the
    // `256 < current` monotonic guard while silently lowering the floor.
    let mut fs = Fs::new(RamStorage::new());
    let mut state = armed(PERM_ACFG);
    assert_eq!(
        run_fs(
            &mut fs,
            &mut state,
            &config_request(0x03, &subpara_min_pin(8), &TOKEN)
        ),
        Ok(0)
    );
    assert_eq!(
        run_fs(
            &mut fs,
            &mut state,
            &config_request(0x03, &subpara_min_pin(256), &TOKEN)
        ),
        Err(CtapError::PinPolicyViolation)
    );
    let mut buf = [0u8; 2];
    assert_eq!(fs.read(EF_MINPINLEN, &mut buf), Some(2));
    assert_eq!(buf[0], 8, "floor not lowered by the truncating value");
}

#[test]
fn toggle_always_uv_flips_state() {
    let mut fs = Fs::new(RamStorage::new());
    let mut state = armed(PERM_ACFG);
    let req = config_request(CONFIG_TOGGLE_ALWAYS_UV as u8, &[], &TOKEN);
    // Starts at the compiled default; each toggle flips the effective state and a
    // round trip restores it. Asserted through the tri-state helper (not raw
    // `has_data`) so it stays meaningful on both the default and `always-uv` builds.
    assert_eq!(always_uv_enabled(&mut fs), DEFAULT_ALWAYS_UV);
    assert_eq!(run_fs(&mut fs, &mut state, &req), Ok(0));
    assert_eq!(always_uv_enabled(&mut fs), !DEFAULT_ALWAYS_UV);
    assert_eq!(run_fs(&mut fs, &mut state, &req), Ok(0));
    assert_eq!(always_uv_enabled(&mut fs), DEFAULT_ALWAYS_UV);
}

#[test]
fn always_uv_read_prefers_explicit_override() {
    // No record → the compile-time default (off on a normal build, on with
    // `--features always-uv`). An explicit override wins in either direction, and
    // clearing it (what authenticatorReset does) returns to the default.
    let mut fs = Fs::new(RamStorage::new());
    assert_eq!(always_uv_enabled(&mut fs), DEFAULT_ALWAYS_UV);
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();
    assert!(always_uv_enabled(&mut fs));
    fs.put(EF_ALWAYS_UV, &[0]).unwrap();
    assert!(!always_uv_enabled(&mut fs));
    fs.delete(EF_ALWAYS_UV).unwrap();
    assert_eq!(always_uv_enabled(&mut fs), DEFAULT_ALWAYS_UV);
}

#[test]
fn toggle_always_uv_requires_acfg_permission() {
    // The shared token check rejects a token lacking the acfg permission, so
    // alwaysUv cannot be flipped without it.
    let mut fs = Fs::new(RamStorage::new());
    let mut state = armed(0);
    let req = config_request(CONFIG_TOGGLE_ALWAYS_UV as u8, &[], &TOKEN);
    assert_eq!(
        run_fs(&mut fs, &mut state, &req),
        Err(CtapError::PinAuthInvalid)
    );
    assert!(!fs.has_data(EF_ALWAYS_UV));
}

// setMinPINLength subCommandParams `{1: new_min, 2: [rpIds…]}`.
fn subpara_min_pin_rpids(new_min: u64, rp_ids: &[&str]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().u64(new_min).unwrap();
        e.u8(2).unwrap().array(rp_ids.len() as u64).unwrap();
        for id in rp_ids {
            e.str(id).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn set_min_pin_stores_rpid_hashes() {
    let mut fs = Fs::new(RamStorage::new());
    let mut state = armed(PERM_ACFG);
    let req = config_request(0x03, &subpara_min_pin_rpids(6, &["example.com"]), &TOKEN);
    assert_eq!(run_fs(&mut fs, &mut state, &req), Ok(0));
    // EF_MINPINLEN = [6, 0, sha256("example.com")].
    let mut buf = [0u8; 2 + 32];
    assert_eq!(fs.read(EF_MINPINLEN, &mut buf), Some(2 + 32));
    assert_eq!(buf[0], 6);
    assert_eq!(&buf[2..], &sha256(b"example.com"));
}

#[test]
fn set_min_pin_rpid_list_over_capacity_is_key_store_full() {
    let mut fs = Fs::new(RamStorage::new());
    let mut state = armed(PERM_ACFG);
    // §6.11: "If the authenticator cannot store or add the minPinLengthRPIDs, it
    // returns CTAP2_ERR_KEY_STORE_FULL" — the list is not silently truncated to
    // maxRPIDsForSetMinPINLength, and nothing is written.
    let ids: std::vec::Vec<&str> = std::vec![
        "a.example",
        "b.example",
        "c.example",
        "d.example",
        "e.example",
        "f.example",
        "g.example",
        "h.example",
        "i.example",
    ];
    let req = config_request(0x03, &subpara_min_pin_rpids(6, &ids), &TOKEN);
    assert_eq!(
        run_fs(&mut fs, &mut state, &req),
        Err(CtapError::KeyStoreFull)
    );
    let mut buf = [0u8; 2];
    assert_eq!(fs.read(EF_MINPINLEN, &mut buf), None);
}

#[test]
fn set_min_pin_cannot_be_lowered() {
    let mut fs = Fs::new(RamStorage::new());
    let mut state = armed(PERM_ACFG);
    run_fs(
        &mut fs,
        &mut state,
        &config_request(0x03, &subpara_min_pin(8), &TOKEN),
    )
    .unwrap();
    // 6 < current 8 → policy violation.
    assert_eq!(
        run_fs(
            &mut fs,
            &mut state,
            &config_request(0x03, &subpara_min_pin(6), &TOKEN)
        ),
        Err(CtapError::PinPolicyViolation)
    );
}

#[test]
fn config_requires_acfg_permission() {
    // A token without the acfg permission is rejected.
    let mut state = armed(crate::state::PERM_MC);
    assert_eq!(
        run(
            &mut state,
            &config_request(0x03, &subpara_min_pin(6), &TOKEN)
        ),
        Err(CtapError::PinAuthInvalid)
    );
}

#[test]
fn config_bad_mac_rejected() {
    let mut state = armed(PERM_ACFG);
    // MAC under the wrong token → PinAuthInvalid.
    let req = config_request(0x03, &subpara_min_pin(6), &[0x11; 32]);
    assert_eq!(run(&mut state, &req), Err(CtapError::PinAuthInvalid));
}

#[test]
fn config_without_param_is_puat_required() {
    let mut state = armed(PERM_ACFG);
    // {1: 3} — no pinUvAuthParam.
    let req = std::vec![0xA1, 0x01, 0x03];
    assert_eq!(run(&mut state, &req), Err(CtapError::PuatRequired));
}

#[test]
fn enable_enterprise_attestation() {
    let mut fs = Fs::new(RamStorage::new());
    let mut state = armed(PERM_ACFG);
    let req = config_request(0x01, &[], &TOKEN);
    assert_eq!(run_fs(&mut fs, &mut state, &req), Ok(0));
    // Persisted: a fresh power cycle (new FidoState) still sees it.
    assert!(fs.has_data(EF_EA_ENABLED));
}

/// The same rule under a medium that would not answer, on both of the probes that
/// decide it. `set_min_pin_length` reads `EF_PIN` twice — `has_data` for "is a PIN
/// set at all", then the record for its length — and a collapsed answer at either
/// leaves `force` FALSE. That value is then PERSISTED as `EF_MINPINLEN[1] = 0`, so a
/// PIN below the new floor keeps working with no change demanded, `force_change_pending`
/// reads the cleared flag forever, and the live token is never invalidated. Nothing
/// short of another setMinPINLength repairs it, and nothing tells the owner.
#[test]
fn a_faulted_pin_probe_does_not_clear_the_forced_change() {
    for skip in [0u32, 1] {
        let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        // A 4-char PIN on file, and a floor already above it.
        let mut pin_file = [0u8; 35];
        pin_file[0] = 8;
        pin_file[1] = 4;
        pin_file[2] = 1;
        fs.put(EF_PIN, &pin_file).unwrap();
        let mut state = armed(PERM_ACFG);
        let before = state.paut.token;

        medium.stick_after(EF_PIN, skip);
        let r = run_fs(
            &mut fs,
            &mut state,
            &config_request(0x03, &subpara_min_pin(6), &TOKEN),
        );
        medium.stick(None);

        assert_ne!(
            medium.value(EF_MINPINLEN).as_deref().map(|v| v[1]),
            Some(0),
            "probe {skip}: a faulted read persisted forceChangePin = 0 over a PIN \
             shorter than the floor it just raised"
        );
        assert_eq!(
            r,
            Err(CtapError::Other),
            "probe {skip}: a setMinPINLength that could not read the PIN it must \
             judge has to refuse"
        );
        assert_eq!(
            state.paut.token, before,
            "probe {skip}: and a refused command must not disturb the live token"
        );
    }
}

#[test]
fn set_min_pin_forces_change_when_pin_too_short() {
    let mut fs = Fs::new(RamStorage::new());
    // A 4-char PIN on file (`[retries, len, format, verifier…]`).
    let mut pin_file = [0u8; 35];
    pin_file[0] = 8;
    pin_file[1] = 4;
    pin_file[2] = 1;
    fs.put(EF_PIN, &pin_file).unwrap();
    let mut state = armed(PERM_ACFG);
    // Raising the minimum above the current PIN length forces a change and
    // resets the token.
    run_fs(
        &mut fs,
        &mut state,
        &config_request(0x03, &subpara_min_pin(6), &TOKEN),
    )
    .unwrap();
    let mut buf = [0u8; 2];
    fs.read(EF_MINPINLEN, &mut buf).unwrap();
    assert_eq!(buf, [6, 1]); // forceChangePin set
    assert_ne!(state.paut.token, TOKEN); // token regenerated
}

// The vendor (0xFF) subCommandParams `{1: vendorCommandId, 3: int}` — the
// PicoForge physical-config shape (integer param at key 3).
fn subpara_vendor_int(vendor_id: u64, val: u64) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 48];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().u64(vendor_id).unwrap();
        e.u8(3).unwrap().u64(val).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

// Wrap a vendor (0xFF) subCommandParams blob into a full authenticatorConfig
// request. Unlike config_request it encodes subCommand 0xFF as CBOR `0x18 0xFF`
// (a bare 0xFF byte is the CBOR break marker, not the integer 255).
fn vendor_req(sub: &[u8], token: &[u8; 32]) -> std::vec::Vec<u8> {
    let mut vp = std::vec![0xffu8; 32];
    vp.push(CTAP_CONFIG);
    vp.push(CONFIG_VENDOR as u8);
    vp.extend_from_slice(sub);
    let mut mac = [0u8; 32];
    let mlen = pinproto::authenticate(PinProto::Two, token, &vp, &mut mac).unwrap();

    let mut req = std::vec::Vec::new();
    req.push(0xA4); // map(4)
    req.extend_from_slice(&[0x01, 0x18, 0xFF]); // 1: subCommand = 0xFF
    req.push(0x02); // 2: subCommandParams (raw)
    req.extend_from_slice(sub);
    req.extend_from_slice(&[0x03, 0x02]); // 3: pinUvAuthProtocol = 2
    req.push(0x04); // 4: pinUvAuthParam
    req.push(0x58);
    req.push(mlen as u8);
    req.extend_from_slice(&mac[..mlen]);
    req
}

// The CONFIG_EA_RPIDS subCommandParams map `{1: id, 4: [rpId…]}`.
fn subpara_ea_rpids(ids: &[&str]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().u64(CONFIG_EA_RPIDS).unwrap();
        e.u8(4).unwrap().array(ids.len() as u64).unwrap();
        for id in ids {
            e.str(id).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn set_rpids(fs: &mut Fs<RamStorage>, ids: &[&str]) -> CtapResult {
    let mut st = armed(PERM_ACFG);
    run_fs(fs, &mut st, &vendor_req(&subpara_ea_rpids(ids), &TOKEN))
}

#[test]
fn ea_rpids_stored_as_hashes_and_survive_a_remount() {
    let mut fs = Fs::new(RamStorage::new());
    assert_eq!(
        set_rpids(&mut fs, &["corp.example.com", "sso.example"]),
        Ok(0)
    );
    // A remount is the power cycle: the record is read back off the same storage
    // by a filesystem that has never seen the write.
    let mut fs = Fs::new(fs.into_storage());
    let mut buf = [0u8; 32 * MAX_EA_RPIDS];
    assert_eq!(fs.read(EF_EA_RPIDS, &mut buf), Some(64));
    assert_eq!(&buf[..32], &sha256(b"corp.example.com"));
    assert_eq!(&buf[32..64], &sha256(b"sso.example"));
}

#[test]
fn ea_rpids_empty_list_clears_the_record() {
    let mut fs = Fs::new(RamStorage::new());
    assert_eq!(set_rpids(&mut fs, &["corp.example.com"]), Ok(0));
    assert!(fs.has_data(EF_EA_RPIDS));
    assert_eq!(set_rpids(&mut fs, &[]), Ok(0));
    assert!(
        !fs.has_data(EF_EA_RPIDS),
        "an empty list returns the device to its shipped state"
    );
}

#[test]
fn ea_rpids_overflow_is_refused_not_truncated() {
    // The allowList-truncation shape: a list past the bound must fail loudly and
    // leave the previous one intact, never silently store its first MAX_EA_RPIDS.
    let mut fs = Fs::new(RamStorage::new());
    assert_eq!(set_rpids(&mut fs, &["kept.example"]), Ok(0));
    let too_many: std::vec::Vec<&str> = std::vec![
        "a.example",
        "b.example",
        "c.example",
        "d.example",
        "e.example",
        "f.example",
        "g.example",
        "h.example",
        "i.example",
    ];
    assert_eq!(too_many.len(), MAX_EA_RPIDS + 1);
    assert_eq!(set_rpids(&mut fs, &too_many), Err(CtapError::KeyStoreFull));
    let mut buf = [0u8; 32 * MAX_EA_RPIDS];
    assert_eq!(fs.read(EF_EA_RPIDS, &mut buf), Some(32));
    assert_eq!(&buf[..32], &sha256(b"kept.example"));
}

#[test]
fn ea_rpids_needs_the_acfg_permission() {
    let mut fs = Fs::new(RamStorage::new());
    let mut st = armed(0); // a valid token, no acfg
    assert_eq!(
        run_fs(
            &mut fs,
            &mut st,
            &vendor_req(&subpara_ea_rpids(&["corp.example.com"]), &TOKEN)
        ),
        Err(CtapError::PinAuthInvalid)
    );
    assert!(!fs.has_data(EF_EA_RPIDS));
}

#[test]
fn picoforge_config_sets_vidpid_in_phy() {
    let mut fs = Fs::new(RamStorage::new());
    let mut st = armed(PERM_ACFG);
    let vidpid = (0x1050u64 << 16) | 0x0407; // Yubico
    let sub = subpara_vendor_int(CONFIG_PHY_VIDPID, vidpid);
    assert_eq!(run_fs(&mut fs, &mut st, &vendor_req(&sub, &TOKEN)), Ok(0));
    assert_eq!(
        rsk_phy::load(&mut fs).unwrap().vid_pid,
        Some((0x1050, 0x0407))
    );
}

#[test]
fn picoforge_config_sets_led_gpio_and_options_in_phy() {
    let mut fs = Fs::new(RamStorage::new());
    let g = subpara_vendor_int(CONFIG_PHY_LED_GPIO, 22);
    let mut st = armed(PERM_ACFG);
    assert_eq!(run_fs(&mut fs, &mut st, &vendor_req(&g, &TOKEN)), Ok(0));
    // opts 0x0A = dimmable (0x2) | led-steady (0x8); a fresh token for the 2nd write.
    let o = subpara_vendor_int(CONFIG_PHY_OPTIONS, 0x0A);
    let mut st2 = armed(PERM_ACFG);
    assert_eq!(run_fs(&mut fs, &mut st2, &vendor_req(&o, &TOKEN)), Ok(0));
    let p = rsk_phy::load(&mut fs).unwrap();
    assert_eq!(p.led_gpio, Some(22));
    assert_eq!(p.opts, 0x0A);
}

#[test]
fn picoforge_config_requires_acfg_permission() {
    let mut fs = Fs::new(RamStorage::new());
    let mut st = armed(0); // no acfg permission
    let sub = subpara_vendor_int(CONFIG_PHY_VIDPID, 0x1050_0407);
    assert_eq!(
        run_fs(&mut fs, &mut st, &vendor_req(&sub, &TOKEN)),
        Err(CtapError::PinAuthInvalid)
    );
}

#[test]
fn unknown_vendor_config_id_rejected() {
    let mut st = armed(PERM_ACFG);
    let sub = subpara_vendor_int(0xDEAD_BEEF, 1);
    assert_eq!(
        run(&mut st, &vendor_req(&sub, &TOKEN)),
        Err(CtapError::InvalidSubcommand)
    );
}

/// The subcommand is judged before the token, pinned to a YubiKey 5.7.4 cell for
/// cell: `0` is the absent sentinel, an id the card does not implement is
/// INVALID_PARAMETER whether or not a token came with it, and only a known one
/// reaches PUAT_REQUIRED. Measured on 0x00 / 0x04 / 0x7F / 0xFF, stable across
/// runs. Unlike `credentialManagement`, this command tells an unauthenticated
/// caller which subcommands exist — so does the YubiKey, and getInfo's options
/// name all three anyway.
#[test]
fn undefined_config_subcommand_matches_a_yubikey() {
    for sub in [0x05u8, 0x7F] {
        let mut st = armed(PERM_ACFG);
        assert_eq!(
            run(&mut st, &config_request(sub, &[], &TOKEN)),
            Err(CtapError::InvalidParameter),
            "config subcommand {sub:#04x} with a token"
        );
        let mut st = FidoState::new();
        assert_eq!(
            run(&mut st, &bare_sub(sub)),
            Err(CtapError::InvalidParameter),
            "config subcommand {sub:#04x} without one"
        );
    }
    let mut st = armed(PERM_ACFG);
    assert_eq!(
        run(&mut st, &config_request(0x00, &[], &TOKEN)),
        Err(CtapError::MissingParameter),
        "subCommand 0 is the absent-parameter sentinel"
    );
    let mut st = FidoState::new();
    assert_eq!(
        run(&mut st, &bare_sub(CONFIG_SET_MIN_PIN as u8)),
        Err(CtapError::PuatRequired),
        "a KNOWN subcommand still reaches the auth gate"
    );
}

/// `pinUvAuthProtocol: 0` is a value the platform sent, and a YubiKey 5.7.4 judges
/// it before it has looked at the subcommand or missed the token: `0x02`, not the
/// `0x36` a bare "no param" gets and not the `0x14` subcommand `0` gets.
#[test]
fn an_unsupported_protocol_is_judged_before_the_subcommand_and_the_token() {
    for sub in [0x03u8, 0x00, 0x09] {
        // {1: sub, 3: proto} — no pinUvAuthParam at all. 255 needs its own header.
        for proto in [std::vec![0x00u8], std::vec![0x03], std::vec![0x18, 0xFF]] {
            let mut req = std::vec![0xA2, 0x01, sub, 0x03];
            req.extend_from_slice(&proto);
            let mut state = armed(PERM_ACFG);
            assert_eq!(
                run(&mut state, &req),
                Err(CtapError::InvalidParameter),
                "subcommand {sub:#x} protocol {proto:?}"
            );
        }
    }
    // Control: the same requests with a supported protocol keep their own answers,
    // so the rule above is the protocol's and not a blanket refusal.
    for (sub, want) in [
        (0x03u8, CtapError::PuatRequired),
        (0x00, CtapError::MissingParameter),
        (0x09, CtapError::InvalidParameter),
    ] {
        let req = std::vec![0xA2, 0x01, sub, 0x03, 0x02];
        let mut state = armed(PERM_ACFG);
        assert_eq!(run(&mut state, &req), Err(want), "subcommand {sub:#x}");
    }
}

/// `alwaysUv` is the UV requirement for every makeCredential and getAssertion, and
/// an absent `EF_ALWAYS_UV` means "the compile default" — normally OFF. `Fs::read`
/// answers the same `None` for that and for a read the flash could not serve, so a
/// faulted probe silently dropped the gate to user presence. It resolves ON now.
#[test]
fn a_faulted_always_uv_read_resolves_to_on() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();
    assert!(crate::config::always_uv_enabled(&mut fs));
    medium.stick(Some(EF_ALWAYS_UV));
    assert!(
        crate::config::always_uv_enabled(&mut fs),
        "a faulted EF_ALWAYS_UV read dropped the UV gate to the compile default"
    );
}

/// `set_phy` is the FIDO half of the phy read-modify-write, and it carried its own
/// copy of the merge rather than going through `rsk_phy`'s: a `load(..)
/// .unwrap_or_default()` that read a failed probe as "nothing was ever written",
/// so one PicoForge field write saved the DEFAULT record with that field on top
/// and took the owner's USB identity, product string and LED wiring with it.
#[test]
fn a_faulted_phy_probe_does_not_wipe_the_record_a_config_write_edits() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let owner = rsk_phy::PhyData {
        vid_pid: Some((0x1234, 0x5678)),
        usb_product: rsk_phy::Product::new(b"RSK Custom"),
        led_gpio: Some(21),
        led_num: Some(4),
        ..Default::default()
    };
    rsk_phy::save(&mut fs, &owner).unwrap();
    let before = medium.value(rsk_phy::EF_PHY).expect("record written");

    let mut st = armed(PERM_ACFG);
    let sub = subpara_vendor_int(CONFIG_PHY_LED_BRIGHTNESS, 64);
    medium.stick_once(rsk_phy::EF_PHY);
    let r = run_fs(&mut fs, &mut st, &vendor_req(&sub, &TOKEN));
    let after = medium.value(rsk_phy::EF_PHY).expect("record present");
    let kept = rsk_phy::PhyData::parse(&after);
    assert_eq!(
        (kept.vid_pid, kept.usb_product, kept.led_gpio, kept.led_num),
        (
            owner.vid_pid,
            owner.usb_product,
            owner.led_gpio,
            owner.led_num
        ),
        "a faulted probe wiped the fields the config write did not carry \
         ({} bytes stored, was {})",
        after.len(),
        before.len()
    );
    assert_eq!(after, before, "a refused write must leave the record alone");
    assert_eq!(
        r,
        Err(CtapError::Other),
        "a config write that could not read the record it edits must refuse"
    );
}

/// CTAP 2.1 §6.11 makes minPINLength monotonic — setMinPINLength may only raise it,
/// and nothing but a factory reset puts a lowered floor back. `current_min_pin` is
/// the only thing that knows what the floor currently is, and it read `EF_MINPINLEN`
/// with `Fs::read`, whose `None` covers both "no policy set" and "the flash could not
/// serve it". The collapsed arm resolves to the build's `MIN_PIN_LENGTH`, so one
/// faulted probe let the monotonic guard pass and wrote the LOWER floor.
#[test]
fn a_faulted_min_pin_probe_does_not_lower_the_floor() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let mut state = armed(PERM_ACFG);
    run_fs(
        &mut fs,
        &mut state,
        &config_request(0x03, &subpara_min_pin(16), &TOKEN),
    )
    .unwrap();
    assert_eq!(
        medium.value(EF_MINPINLEN).as_deref().map(|v| v[0]),
        Some(16),
        "the enterprise floor is in place before the fault"
    );

    // Control: the monotonic guard refuses a lower floor on a healthy medium. 8 is
    // above every profile's `MIN_PIN_LENGTH`, so a collapsed probe cannot refuse it
    // for the length's own sake under `fips-profile` either.
    assert_eq!(
        run_fs(
            &mut fs,
            &mut state,
            &config_request(0x03, &subpara_min_pin(8), &TOKEN)
        ),
        Err(CtapError::PinPolicyViolation),
        "control: minPINLength can only grow"
    );

    medium.stick_once(EF_MINPINLEN);
    let r = run_fs(
        &mut fs,
        &mut state,
        &config_request(0x03, &subpara_min_pin(8), &TOKEN),
    );
    medium.stick(None);
    assert_eq!(
        medium.value(EF_MINPINLEN).as_deref().map(|v| v[0]),
        Some(16),
        "a faulted probe lowered the minPINLength floor, which only a reset raises back"
    );
    assert_eq!(
        r,
        Err(CtapError::Other),
        "a setMinPINLength that could not read the floor it must not lower has to refuse"
    );
}

/// setMinPINLength over a PIN too short for the new floor, cut at every mutation.
/// The floor never comes back lower than it was — it is monotonic across a power cut
/// too — and the record that lands with `forceChangePin` never stands over the grant
/// the old PIN's holder had: `clear_ppuat` runs before the put, so no cut point can
/// leave a token minted under a PIN the owner is now required to change.
#[test]
fn a_torn_set_min_pin_length_never_lowers_the_floor_or_keeps_the_grant() {
    use crate::consts::EF_PAUTHTOKEN;

    rsk_fs::cut::sweep(
        || {
            let (cut, medium) = rsk_fs::storage::faults::Cut::new();
            let mut fs = Fs::new(cut);
            let mut pin_file = [0u8; 35];
            pin_file[0] = 8; // retries
            pin_file[1] = 4; // a 4-code-point PIN, under the floor this raises
            pin_file[2] = 1; // verifier format
            fs.put(EF_PIN, &pin_file).unwrap();
            fs.put(EF_MINPINLEN, &[4, 0]).unwrap();
            // The grant the old PIN's holder carries, minted as provisioning mints it.
            crate::seed::ensure_ppuat(&dev(), &mut fs, &mut SeqRng(3)).unwrap();
            (fs, medium)
        },
        |fs| {
            let mut state = armed(PERM_ACFG);
            let req = config_request(0x03, &subpara_min_pin(6), &TOKEN);
            run_fs(fs, &mut state, &req).is_ok()
        },
        |fs, budget, completed, medium| {
            let mut buf = [0u8; 2];
            let n = fs
                .read(EF_MINPINLEN, &mut buf)
                .unwrap_or_else(|| panic!("budget {budget}: the policy record is gone"));
            assert_eq!(
                n, 2,
                "budget {budget}: the record that landed is not a policy record"
            );
            assert!(
                buf[0] == 4 || buf[0] == 6,
                "budget {budget}: the floor is neither the old one (4) nor the new one (6): {} — {:?}",
                buf[0],
                medium.ops()
            );
            if buf[1] == 1 {
                assert!(
                    !fs.has_data(EF_PAUTHTOKEN.get()),
                    "budget {budget}: a forced PIN change landed over the old holder's grant — {:?}",
                    medium.ops()
                );
            }
            if completed {
                assert_eq!(buf, [6, 1], "budget {budget}: the command reported success");
            }
        },
    );
}

/// A present-but-empty `EF_MINPINLEN` sets no policy, so the floor the monotonic
/// guard holds is the build's `MIN_PIN_LENGTH` — not the zero an unread byte of the
/// buffer holds, under which setMinPINLength could lower it.
#[test]
fn an_empty_min_pin_record_holds_the_build_floor() {
    let mut fs = Fs::new(RamStorage::new());
    fs.put(EF_MINPINLEN, &[]).unwrap();
    let mut state = armed(PERM_ACFG);
    let under = u64::from(MIN_PIN_LENGTH) - 1;
    assert_eq!(
        run_fs(
            &mut fs,
            &mut state,
            &config_request(0x03, &subpara_min_pin(under), &TOKEN)
        ),
        Err(CtapError::PinPolicyViolation),
        "setMinPINLength went under the build floor over an empty policy record"
    );
}

// The setMinPINLength subCommandParams map `{1: new_min, 3: forceChangePin = true}`.
fn subpara_min_pin_force(new_min: u64) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 32];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap().u8(1).unwrap().u64(new_min).unwrap();
        e.u8(3).unwrap().bool(true).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// `forceChangePin` (CTAP 2.1 §6.11.4) demands a change of a PIN the new floor does
/// not itself condemn, so it is honoured over a PIN long enough — and with no PIN to
/// change it is PIN_NOT_SET, with no policy stored. No test sent the key before.
#[test]
fn force_change_pin_is_honoured_and_needs_a_pin() {
    let mut fs = Fs::new(RamStorage::new());
    let mut state = armed(PERM_ACFG);
    let req = config_request(0x03, &subpara_min_pin_force(6), &TOKEN);
    assert_eq!(run_fs(&mut fs, &mut state, &req), Err(CtapError::PinNotSet));
    assert!(
        !fs.has_data(EF_MINPINLEN),
        "a forced change with no PIN stored a policy"
    );

    // An 8-character PIN: the floor of 6 does not force a change, the request does.
    let mut pin_file = [0u8; crate::clientpin::PIN_FILE_LEN];
    pin_file[..3].copy_from_slice(&[8, 8, 1]);
    fs.put(EF_PIN, &pin_file).unwrap();
    assert_eq!(run_fs(&mut fs, &mut state, &req), Ok(0));
    let mut buf = [0u8; 2];
    assert_eq!(fs.read(EF_MINPINLEN, &mut buf), Some(2));
    assert_eq!(buf, [6, 1], "forceChangePin was not stored");
    assert_ne!(
        state.paut.token, TOKEN,
        "a forced change left the token alive"
    );
}

/// A PIN exactly as long as the new floor meets it: no change is forced, and the
/// token that set the floor stands.
#[test]
fn a_pin_at_the_new_floor_is_not_forced_to_change() {
    let mut fs = Fs::new(RamStorage::new());
    let mut pin_file = [0u8; crate::clientpin::PIN_FILE_LEN];
    pin_file[..3].copy_from_slice(&[8, 6, 1]);
    fs.put(EF_PIN, &pin_file).unwrap();
    let mut state = armed(PERM_ACFG);
    assert_eq!(
        run_fs(
            &mut fs,
            &mut state,
            &config_request(0x03, &subpara_min_pin(6), &TOKEN)
        ),
        Ok(0)
    );
    let mut buf = [0u8; 2];
    assert_eq!(fs.read(EF_MINPINLEN, &mut buf), Some(2));
    assert_eq!(buf, [6, 0], "a PIN at the floor was forced to change");
    assert_eq!(state.paut.token, TOKEN, "a PIN at the floor lost its token");
}

/// With newMinPINLength absent the floor stays where it is (CTAP 2.1 §6.11.4), so a
/// request that only sets forceChangePin must not read the absence as a floor of 0.
#[test]
fn force_change_pin_alone_keeps_the_floor() {
    let mut fs = Fs::new(RamStorage::new());
    let mut pin_file = [0u8; crate::clientpin::PIN_FILE_LEN];
    pin_file[..3].copy_from_slice(&[8, 8, 1]);
    fs.put(EF_PIN, &pin_file).unwrap();
    let mut state = armed(PERM_ACFG);
    let mut sub = [0u8; 8];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut sub[..]));
        e.map(1).unwrap().u8(3).unwrap().bool(true).unwrap();
        e.writer().position()
    };
    assert_eq!(
        run_fs(
            &mut fs,
            &mut state,
            &config_request(0x03, &sub[..n], &TOKEN)
        ),
        Ok(0),
        "a forceChangePin with no newMinPINLength was read as lowering the floor"
    );
    let mut buf = [0u8; 2];
    assert_eq!(fs.read(EF_MINPINLEN, &mut buf), Some(2));
    assert_eq!(buf, [MIN_PIN_LENGTH, 1]);
}

/// The one-record config commands, cut at every mutation with the audit journal on:
/// enableEnterpriseAttestation, the enterprise RP list set and cleared, and
/// toggleAlwaysUv both ways. Each record is written before its journal entry, so a
/// cut leaves the old record or the new one, and the journal never records a change
/// whose record did not land. The journal swallows its own write failures, so a
/// command counts as done only once its entry is in the window.
#[test]
fn a_torn_one_record_config_write_never_journals_a_change_that_did_not_land() {
    let kept = sha256(b"kept.example").to_vec();
    let flipped = std::vec![u8::from(!DEFAULT_ALWAYS_UV)];
    let toggle = config_request(CONFIG_TOGGLE_ALWAYS_UV as u8, &[], &TOKEN);
    let cases = [
        (
            "enableEnterpriseAttestation",
            EF_EA_ENABLED,
            None,
            config_request(CONFIG_ENABLE_EA as u8, &[], &TOKEN),
            journal::EV_CFG_EA,
        ),
        (
            "set the enterprise RP list",
            EF_EA_RPIDS,
            None,
            vendor_req(&subpara_ea_rpids(&["corp.example.com"]), &TOKEN),
            journal::EV_CFG_EA_RPIDS,
        ),
        (
            "clear the enterprise RP list",
            EF_EA_RPIDS,
            Some(kept),
            vendor_req(&subpara_ea_rpids(&[]), &TOKEN),
            journal::EV_CFG_EA_RPIDS,
        ),
        (
            "toggleAlwaysUv",
            EF_ALWAYS_UV,
            None,
            toggle.clone(),
            journal::EV_CFG_ALWAYS_UV,
        ),
        (
            "toggleAlwaysUv back",
            EF_ALWAYS_UV,
            Some(flipped),
            toggle,
            journal::EV_CFG_ALWAYS_UV,
        ),
    ];
    for (name, fid, before, req, ev) in cases {
        let provision = || {
            let (cut, medium) = rsk_fs::storage::faults::Cut::new();
            let mut fs = Fs::new(cut);
            journal::set_enabled(&mut fs, true).unwrap();
            if let Some(v) = &before {
                fs.put(fid, v).unwrap();
            }
            (fs, medium)
        };
        let (mut healthy, _) = provision();
        assert_eq!(
            run_fs(&mut healthy, &mut armed(PERM_ACFG), &req),
            Ok(0),
            "{name}"
        );
        let after = read_record(&mut healthy, fid);
        assert_ne!(
            after, before,
            "{name}: the command changes nothing to sweep"
        );
        rsk_fs::cut::sweep(
            provision,
            |fs| run_fs(fs, &mut armed(PERM_ACFG), &req).is_ok() && journals(&dev(), fs, ev),
            |fs, budget, completed, medium| {
                let now = read_record(fs, fid);
                assert!(
                    now == before || now == after,
                    "{name}, budget {budget}: {now:02x?} is neither record — {:?}",
                    medium.ops()
                );
                if journals(&dev(), fs, ev) {
                    assert_eq!(
                        now,
                        after,
                        "{name}, budget {budget}: journalled a change that did not land — {:?}",
                        medium.ops()
                    );
                }
                if completed {
                    assert_eq!(now, after, "{name}, budget {budget}: reported done, is not");
                }
            },
        );
    }
}

fn read_record<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Option<std::vec::Vec<u8>> {
    let mut buf = [0u8; 32 * MAX_EA_RPIDS];
    fs.read(fid, &mut buf).map(|n| buf[..n].to_vec())
}
