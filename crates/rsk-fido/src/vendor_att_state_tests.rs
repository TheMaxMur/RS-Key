// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn the_import_chain_ceiling_fits_the_actual_pin_mac_parameters() {
    let mut chain = std::vec![0; cert::ATT_CHAIN_MAX];
    let [hi, lo] = u16::try_from(chain.len().checked_sub(4).unwrap())
        .unwrap()
        .to_be_bytes();
    chain
        .get_mut(..4)
        .unwrap()
        .copy_from_slice(&[0x30, 0x82, hi, lo]);
    let mut packed = [0; cert::ATT_CHAIN_REC_MAX];
    assert!(cert::att_chain_pack(&chain, &mut packed).is_some());
    let mut wire = [0; crate::consts::MAX_MSG_SIZE as usize];
    let len = att_import_req(&mut wire, &[0xA5; 60], &chain);
    let req = parse(wire.get(..len).unwrap()).unwrap();
    assert!(
        req.raw_subpara.len() <= MAX_RAW_SUBPARA,
        "the declared chain ceiling must fit the real PIN-MAC parameters"
    );
}

#[test]
fn attestation_state_emits_one_complete_map_for_each_key_and_chain_state() {
    let packed = [1, 2, 0, 0x30, 0];
    let expected = sha256(&packed);
    for (present, chain, fields, hash) in [
        (false, None, 1, None),
        (false, Some(packed.as_slice()), 1, None),
        (true, None, 1, None),
        (true, Some(&[][..]), 1, None),
        (true, Some(packed.as_slice()), 2, Some(expected)),
    ] {
        let (mut fs, mut rng, mut state) = setup();
        if present {
            let mut key = Secret::new([0x21; 32]);
            crate::seed::store_att_key(&dev(), &mut fs, key.expose()).unwrap();
            key.wipe();
        }
        if let Some(chain) = chain {
            fs.put(EF_ATT_CHAIN, chain).unwrap();
        }
        let mut req = [0; 16];
        let len = one_byte_req(&mut req, VENDOR_ATT_STATE);
        let mut out = [0; 128];
        let mut presence = CountingPresence { calls: 0 };
        let generation = fs.write_gen();
        let len = call(
            &mut fs,
            &mut rng,
            &mut state,
            &mut presence,
            req.get(..len).unwrap(),
            &mut out,
        )
        .unwrap();
        let mut decoder = Decoder::new(out.get(..len).unwrap());
        assert_eq!(decoder.map().unwrap(), Some(fields));
        assert_eq!(decoder.u8().unwrap(), 1);
        assert_eq!(decoder.bool().unwrap(), present);
        if let Some(hash) = hash {
            assert_eq!(
                decoder
                    .u8()
                    .expect("ATT_STATE must emit its declared hash field"),
                2
            );
            assert_eq!(decoder.bytes().unwrap(), hash);
        }
        assert_eq!(
            decoder.position(),
            len,
            "ATT_STATE must end with its declared map"
        );
        assert_eq!(presence.calls, 0);
        assert_eq!(fs.write_gen(), generation);
    }
}
