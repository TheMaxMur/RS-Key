// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// Every authenticatorConfig vendorCommandId this build serves, as the wire publishes
/// it (protocol.md §9, §11): the list getInfo's `0x15` cannot carry (issue #111).
const SERVED: [u64; 7] = [
    0x03e4_3f56_b342_85e2, // AUT_ENABLE
    0x1831_a40f_04a2_5ed9, // AUT_DISABLE
    0x6fcb_19b0_cbe3_acfa, // PhysicalVidPid
    0x7b39_2a39_4de9_f948, // PhysicalLedGpio
    0x76a8_5945_985d_02fd, // PhysicalLedBrightness
    0x269f_3b09_eceb_805f, // PhysicalOptions
    0x0e68_4193_4e71_9be7, // the enterprise-attestation RP list
];

/// A presence that refuses and counts: the list is asked for no touch.
struct Counting(u32);
impl UserPresence for Counting {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> Presence {
        self.0 += 1;
        Presence::Declined
    }
}

/// Issue #122: which vendor config commands a build serves was in protocol.md's prose
/// alone. `0x41`/`0x0F` answers `{1: [id, …]}` in that order, with a PIN set or not,
/// asking no touch and no token.
#[test]
fn config_commands_lists_every_vendor_config_id_the_build_serves() {
    let (mut fs, mut rng, mut st) = setup();
    for pin in [false, true] {
        if pin {
            fs.put(EF_PIN, &[8, 4, 1]).unwrap();
        }
        let mut presence = Counting(0);
        let mut out = [0u8; 128];
        let req = [0xA1, 0x01, 0x0F]; // {1: 0x0F}
        let n = call(&mut fs, &mut rng, &mut st, &mut presence, &req, &mut out)
            .expect("CONFIG_COMMANDS");
        let mut d = Decoder::new(&out[..n]);
        assert_eq!(d.map().unwrap(), Some(1), "pin {pin}");
        assert_eq!(d.u8().unwrap(), 1, "pin {pin}");
        let ids: std::vec::Vec<u64> = d.array_iter::<u64>().unwrap().map(Result::unwrap).collect();
        assert_eq!(ids, SERVED, "pin {pin}");
        assert_eq!(d.position(), n, "pin {pin}: trailing bytes");
        assert_eq!(presence.0, 0, "pin {pin}: a touch was asked");
    }
}
