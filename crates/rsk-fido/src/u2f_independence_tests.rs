// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

struct PinOnly {
    entries: usize,
}

impl crate::UserPresence for PinOnly {
    fn request(&mut self, _: crate::Confirm<'_>) -> crate::Presence {
        panic!("built-in UV already supplies the gesture");
    }

    fn uv_available(&self) -> bool {
        true
    }

    fn collect_pin(&mut self, _: usize, out: &mut [u8]) -> crate::PinEntry {
        self.entries += 1;
        out[..PIN.len()].copy_from_slice(PIN);
        crate::PinEntry::Entered(PIN.len())
    }
}

#[test]
fn builtin_uv_without_a_confirmation_screen_registers_without_an_extra_touch() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    crate::clientpin::store_local_pin(&dev(), &mut fs, PIN).unwrap();
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();
    let mut pad = PinOnly { entries: 0 };
    let mut state = crate::FidoState::new();
    let request = ext_apdu(CTAP_REGISTER, 0, &[CHAL, APP].concat());
    let mut out = [0xa5; 1024];
    let (sw, len) = process_u2f(
        &mut Ctx {
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
            presence: &mut pad,
        },
        &Apdu::parse(&request).unwrap(),
        &mut out,
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(pad.entries, 1);
    assert_eq!(out[0], 0x05);
    assert_eq!(usize::from(out[66]), KEY_HANDLE_LEN);
    let cert = registered_cert(&out[..len]);
    let signature = &out[67 + KEY_HANDLE_LEN + cert.len()..len];
    let mut base = vec![0];
    base.extend_from_slice(&APP);
    base.extend_from_slice(&CHAL);
    base.extend_from_slice(&out[67..67 + KEY_HANDLE_LEN]);
    base.extend_from_slice(&out[1..66]);
    let mut scalar = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
    let public = crate::ec::P256Key::from_scalar(scalar.expose())
        .unwrap()
        .public_xy();
    scalar.wipe();
    vkey(&public.0, &public.1)
        .verify(&base, &Signature::from_der(signature).unwrap())
        .unwrap();
}
