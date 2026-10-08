// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn arm_admin(fs: &mut Fs<RamStorage>, state: &mut FidoState) -> [u8; 32] {
    crate::clientpin::store_local_pin(&dev(), fs, crate::test_pins::PIN).unwrap();
    let token = [0x77; 32];
    state.paut.token = token;
    state.paut.permissions = PERM_ACFG;
    state.begin_using_token(false, 0);
    token
}

#[test]
fn a_pin_authorized_identity_import_owes_only_its_operation_confirmation() {
    let (mut fs, mut rng, mut state) = setup();
    let token = arm_admin(&mut fs, &mut state);
    let host = handshake(&mut fs, &mut rng, &mut state);
    let boxed = wrap32(&host, &[0x21; 32]);
    let mut request = [0; 512];
    let n = att_import_req(&mut request, &boxed, &[0x30, 3, 1, 2, 3]);
    let mut message = [0; 32 + 2 + MAX_RAW_SUBPARA];
    let m = crate::state::puat_subcommand_msg(
        &mut message,
        CTAP_VENDOR,
        VENDOR_ATT_IMPORT as u8,
        parse(&request[..n]).unwrap().raw_subpara,
    );
    let mut mac = [0; 32];
    let mac_len =
        rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &message[..m], &mut mac).unwrap();
    request[0] += 2;
    let mut tail = [0; 64];
    let mut e = Encoder::new(Cursor::new(&mut tail[..]));
    e.u8(3)
        .unwrap()
        .u8(2)
        .unwrap()
        .u8(4)
        .unwrap()
        .bytes(&mac[..mac_len])
        .unwrap();
    let tail_len = e.writer().position();
    request[n..n + tail_len].copy_from_slice(&tail[..tail_len]);
    let mut presence = CountingPresence { calls: 0 };
    let mut out = [0xa5; 256];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut state,
            &mut presence,
            &request[..n + tail_len],
            &mut out
        ),
        Ok(0)
    );
    assert_eq!(presence.calls, 1);
    assert_eq!(
        *crate::seed::load_att_key(&dev(), &mut fs).unwrap().expose(),
        [0x21; 32]
    );
}

#[test]
fn pin_gated_oversized_raw_parameters_are_refused_before_token_verification() {
    for unknown in [2, 3] {
        let (mut fs, mut rng, mut state) = setup();
        arm_admin(&mut fs, &mut state);
        handshake(&mut fs, &mut rng, &mut state);
        let mut request = [0; MAX_RAW_SUBPARA + 256];
        let mut e = Encoder::new(Cursor::new(&mut request[..]));
        e.map(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .u64(VENDOR_BACKUP_LOAD)
            .unwrap();
        e.u8(2)
            .unwrap()
            .map(2)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&[0; 60])
            .unwrap();
        e.u8(unknown)
            .unwrap()
            .bytes(&[0; MAX_RAW_SUBPARA + 1])
            .unwrap();
        e.u8(3)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(4)
            .unwrap()
            .bytes(&[0; 32])
            .unwrap();
        let n = e.writer().position();
        let generation = fs.write_gen();
        let entropy = rng.0;
        let mut presence = CountingPresence { calls: 0 };
        let mut out = [0xa5; 256];
        assert_eq!(
            call(
                &mut fs,
                &mut rng,
                &mut state,
                &mut presence,
                &request[..n],
                &mut out
            ),
            Err(CtapError::RequestTooLarge)
        );
        assert_eq!(out, [0xa5; 256]);
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(rng.0, entropy);
        assert_eq!(presence.calls, 0);
        assert!(state.mse_key_for_test().is_none());
    }
}

#[test]
fn mse_retries_an_out_of_range_scalar_before_publishing_its_point() {
    struct RejectFirst(usize);
    impl Rng for RejectFirst {
        fn fill(&mut self, out: &mut [u8]) {
            assert_eq!(out.len(), 32);
            out.fill(if self.0 == 0 { 0xff } else { 1 });
            self.0 += 1;
        }
    }
    let (hx, hy) = P256Key::from_scalar(&[0x42; 32]).unwrap().public_xy();
    let mut request = [0; 256];
    let n = build_mse(&mut request, &hx, &hy);
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = RejectFirst(0);
    let mut state = FidoState::new();
    let mut presence = AlwaysConfirm;
    let mut out = [0; 256];
    let mut ctx = Ctx {
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        presence: &mut presence,
        now_ms: 0,
    };
    let n = vendor(&mut ctx, &request[..n], &mut out).unwrap();
    assert_eq!(rng.0, 2);
    let expected = P256Key::from_scalar(&[1; 32]).unwrap().public_xy();
    let mut d = Decoder::new(&out[..n]);
    assert_eq!(d.map().unwrap(), Some(1));
    assert_eq!(d.u8().unwrap(), 1);
    let fields = d.map().unwrap().unwrap();
    let (mut got_x, mut got_y) = (None, None);
    for _ in 0..fields {
        match d.i32().unwrap() {
            -2 => got_x = Some(d.bytes().unwrap().try_into().unwrap()),
            -3 => got_y = Some(d.bytes().unwrap().try_into().unwrap()),
            _ => {
                d.skip().unwrap();
            }
        }
    }
    assert_eq!(got_x, Some(expected.0));
    assert_eq!(got_y, Some(expected.1));
    assert_eq!(d.position(), n);
}

#[test]
fn refused_attestation_chain_write_preserves_the_identity_and_spends_the_channel() {
    let (backend, medium) = rsk_fs::storage::faults::Cut::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    crate::seed::store_att_key(&dev(), &mut fs, &[0x21; 32]).unwrap();
    let old_chain = [1, 0, 5, 0x30, 3, 1, 2, 3];
    fs.put(EF_ATT_CHAIN, &old_chain).unwrap();
    let old_key = medium.value(crate::consts::EF_ATT_KEY.get()).unwrap();
    let mut state = FidoState::new();
    let host = handshake(&mut fs, &mut rng, &mut state);
    let boxed = wrap32(&host, &[0x22; 32]);
    let mut request = [0; 256];
    let n = att_import_req(&mut request, &boxed, &[0x30, 3, 4, 5, 6]);
    let generation = fs.write_gen();
    medium.arm(0);
    let mut out = [0xa5; 256];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut state,
            &mut AlwaysConfirm,
            &request[..n],
            &mut out
        ),
        Err(CtapError::Other)
    );
    assert_eq!(out, [0xa5; 256]);
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(medium.value(crate::consts::EF_ATT_KEY.get()), Some(old_key));
    assert_eq!(medium.value(EF_ATT_CHAIN), Some(old_chain.to_vec()));
    assert!(state.mse_key_for_test().is_none());
    medium.arm(u32::MAX);
    let host = handshake(&mut fs, &mut rng, &mut state);
    let boxed = wrap32(&host, &[0x22; 32]);
    let n = att_import_req(&mut request, &boxed, &[0x30, 3, 4, 5, 6]);
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut state,
            &mut AlwaysConfirm,
            &request[..n],
            &mut out
        ),
        Ok(0)
    );
    assert_eq!(
        *crate::seed::load_att_key(&dev(), &mut fs).unwrap().expose(),
        [0x22; 32]
    );
}

#[cfg(not(feature = "fips-profile"))]
#[test]
fn a_short_backup_response_cannot_publish_an_export_journal_entry() {
    let (mut fs, mut rng, mut state) = setup();
    handshake(&mut fs, &mut rng, &mut state);
    let mut request = [0; 32];
    let n = one_byte_req(&mut request, VENDOR_BACKUP_EXPORT);
    let generation = fs.write_gen();
    let mut output = [];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut state,
            &mut AlwaysConfirm,
            &request[..n],
            &mut output
        ),
        Err(CtapError::Other)
    );
    assert_eq!(fs.write_gen(), generation);
    assert!(state.mse_key_for_test().is_none());
}
