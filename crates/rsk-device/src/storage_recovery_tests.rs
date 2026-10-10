// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::{StorageAction, StorageState};

struct Recovery {
    writes: usize,
    action: Option<StorageAction>,
}

impl Storage for Recovery {
    fn state(&self) -> StorageState {
        StorageState::Recovery
    }
    fn read(&mut self, _: u16, _: &mut [u8]) -> Option<usize> {
        None
    }
    fn size(&mut self, _: u16) -> Option<usize> {
        None
    }
    fn last_error(&self) -> bool {
        true
    }
    fn write(&mut self, _: u16, _: &[u8]) -> rsk_sdk::error::Result<()> {
        self.writes += 1;
        Err(rsk_sdk::error::Error::MemoryFatal)
    }
    fn remove(&mut self, _: u16) -> rsk_sdk::error::Result<()> {
        self.writes += 1;
        Err(rsk_sdk::error::Error::MemoryFatal)
    }
    fn for_each_key(&mut self, _: &mut dyn FnMut(u16)) -> bool {
        false
    }
    fn administer(&mut self, action: StorageAction, _: [u8; 16]) -> rsk_sdk::error::Result<()> {
        self.action = Some(action);
        Ok(())
    }
}

fn select(aid: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0, 0xA4, 4, 0, u8::try_from(aid.len()).unwrap()];
    apdu.extend_from_slice(aid);
    apdu
}

#[test]
fn unknown_authority_exposes_only_rescue_and_requires_presence_for_storage_actions() {
    let env = Env::with_storage(Recovery {
        writes: 0,
        action: None,
    });
    let mut ccid = env.ccid();
    for aid in [
        rsk_vendor::VENDOR_AID,
        rsk_openpgp::consts::OPENPGP_AID,
        rsk_piv::PIV_AID,
    ] {
        assert_eq!(
            ccid.handle_apdu(&select(aid), 0),
            rsk_sdk::Sw::FILE_NOT_FOUND.to_bytes()
        );
    }
    assert_eq!(
        ccid.handle_apdu(&select(rsk_rescue::RESCUE_AID), 0).last(),
        Some(&0)
    );
    assert_eq!(
        ccid.handle_apdu(&[0x80, 0x1E, 8, 0, 0], 0),
        &[2, 0, 0x90, 0]
    );
    assert_eq!(
        ccid.handle_apdu(&[0x80, 0x10, 2, 0, 0], 0),
        rsk_sdk::Sw::MEMORY_FAILURE.to_bytes()
    );
    env.finger.borrow_mut().answer = false;
    assert_eq!(
        ccid.handle_apdu(
            &[0x80, 0x20, 0, 0, 6, b'I', b'N', b'I', b'T', b'V', b'2'],
            0
        ),
        rsk_sdk::Sw::CONDITIONS_NOT_SATISFIED.to_bytes()
    );
    env.finger.borrow_mut().answer = true;
    assert_eq!(
        ccid.handle_apdu(
            &[0x80, 0x20, 0, 0, 6, b'I', b'N', b'I', b'T', b'V', b'2'],
            0
        ),
        rsk_sdk::Sw::OK.to_bytes()
    );
    assert!(ccid.ctap_mgmt(0x40, &[]).is_none());
    assert_eq!(ccid.handle_otp_hid(1, &[0; 64]), ([0; 64], 0, [0; 8]));
    assert!(ccid.otp_button_ticket(1, 0).is_none());
    let mut ctap = env.ctap();
    assert_eq!(
        ctap.handle_cbor(1, &[4], 0),
        &[rsk_fido::CtapError::Other.as_u8()]
    );
    assert_eq!(
        ctap.handle_msg(&[0, 1, 0, 0, 0], 0),
        rsk_sdk::Sw::MEMORY_FAILURE.to_bytes()
    );
    drop((ccid, ctap));
    let medium = env.fs.into_inner().into_storage();
    assert_eq!(medium.writes, 0);
    assert_eq!(medium.action, Some(StorageAction::Initialize));
    assert_eq!(env.rescue.borrow().reboots, vec![false]);
}
