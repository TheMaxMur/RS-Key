// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::FidoState;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::Device;
use rsk_crypto::pinproto;
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
    req.extend_from_slice(&[0x01, subcmd]); // 1: subCommand
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

fn run_fs(fs: &mut Fs<RamStorage>, state: &mut FidoState, req: &[u8]) -> CtapResult {
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

#[test]
fn picoforge_config_sets_vidpid_in_phy() {
    let mut fs = Fs::new(RamStorage::new());
    let mut st = armed(PERM_ACFG);
    let vidpid = (0x1050u64 << 16) | 0x0407; // Yubico
    let sub = subpara_vendor_int(CONFIG_PHY_VIDPID, vidpid);
    assert_eq!(run_fs(&mut fs, &mut st, &vendor_req(&sub, &TOKEN)), Ok(0));
    assert_eq!(
        rsk_rescue::phy::load(&mut fs).unwrap().vid_pid,
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
    let p = rsk_rescue::phy::load(&mut fs).unwrap();
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
