// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// The code `ykman config set-lock-code` would set, in DeviceInfo's `CONFIG_LOCK`.
fn lock_code(code: [u8; 16]) -> std::vec::Vec<u8> {
    let mut blob = std::vec![0x0A, 16];
    blob.extend_from_slice(&code);
    blob
}

fn write_req(target: u64, blob: &[u8]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 128];
    let n = config_write_req(target, blob, false, &mut buf);
    buf[..n].to_vec()
}

fn record<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Option<std::vec::Vec<u8>> {
    let mut buf = [0u8; 256];
    fs.read(fid, &mut buf).map(|n| buf[..n].to_vec())
}

fn phy_blob(timeout: u8) -> std::vec::Vec<u8> {
    let mut blob = [0u8; rsk_phy::PHY_MAX_SIZE];
    let rec = rsk_phy::PhyData {
        presence_timeout: Some(timeout),
        ..Default::default()
    };
    let n = rec.serialize(&mut blob).unwrap();
    blob[..n].to_vec()
}

/// The configuration lock covers the phy and LED records, where no code opens it:
/// while one is set, CONFIG_WRITE of either is refused as a DeviceInfo write without
/// its code is (`NOT_ALLOWED`), a replay too, and stores and marks nothing.
#[test]
fn a_locked_configuration_refuses_the_phy_and_led_records() {
    let (mut fs, mut rng, mut st) = setup();
    let led = [0x11u8; rsk_led::CONF_LEN];
    let mut out = [0u8; 64];
    for req in [
        write_req(CONFIG_TARGET_PHY, &phy_blob(45)),
        write_req(CONFIG_TARGET_LED, &led),
    ] {
        assert_eq!(
            call(
                &mut fs,
                &mut rng,
                &mut st,
                &mut AlwaysConfirm,
                &req,
                &mut out
            ),
            Ok(0)
        );
    }
    let (_, _) = (st.take_led_written(), st.take_phy_written());
    rsk_devconf::persist_touched(&[0; 4], &mut fs, &lock_code([0xA5; 16])).unwrap();
    let before = (
        record(&mut fs, rsk_phy::EF_PHY),
        record(&mut fs, rsk_led::EF_LED_CONF),
    );

    let rows = [
        (
            "a phy write",
            write_req(CONFIG_TARGET_PHY, &phy_blob(50)),
            CtapError::NotAllowed,
        ),
        (
            "a phy replay",
            write_req(CONFIG_TARGET_PHY, &phy_blob(45)),
            CtapError::NotAllowed,
        ),
        (
            "an LED write",
            write_req(CONFIG_TARGET_LED, &[0x22; rsk_led::CONF_LEN]),
            CtapError::NotAllowed,
        ),
        (
            "an LED replay",
            write_req(CONFIG_TARGET_LED, &led),
            CtapError::NotAllowed,
        ),
        // A malformed block is still judged first, as a malformed DeviceInfo write is.
        (
            "a short LED block",
            write_req(CONFIG_TARGET_LED, &led[1..]),
            CtapError::InvalidLength,
        ),
    ];
    for (name, req, want) in rows {
        let r = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req,
            &mut out,
        );
        assert_eq!(r, Err(want), "{name}");
        let marks = (st.take_led_written(), st.take_phy_written());
        assert_eq!(marks, (false, false), "{name} marked a live effect");
    }
    let after = (
        record(&mut fs, rsk_phy::EF_PHY),
        record(&mut fs, rsk_led::EF_LED_CONF),
    );
    assert_eq!(after, before, "a refused write reached a record");

    // With the lock cleared, the same write lands.
    let mut clear = std::vec![0x0B, 16];
    clear.extend_from_slice(&[0xA5; 16]);
    clear.extend_from_slice(&lock_code([0; 16]));
    rsk_devconf::persist_touched(&[0; 4], &mut fs, &clear).unwrap();
    let req = write_req(CONFIG_TARGET_PHY, &phy_blob(50));
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req,
            &mut out
        ),
        Ok(0)
    );
    assert_eq!(rsk_phy::load(&mut fs).unwrap().presence_timeout, Some(50));
}
