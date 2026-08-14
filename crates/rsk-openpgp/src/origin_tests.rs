// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

fn fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    fs
}

#[test]
fn an_unrecorded_slot_reads_as_imported() {
    // A card provisioned before this record existed carries no proof of on-card
    // generation, so it must not claim any.
    let mut fs = fs();
    for pk in [EF_PK_SIG, EF_PK_DEC, EF_PK_AUT] {
        assert_eq!(of(&mut fs, pk), ORIGIN_IMPORTED);
    }
}

#[test]
fn each_slot_is_independent() {
    let mut fs = fs();
    mark(&mut fs, EF_PK_SIG, ORIGIN_GENERATED).unwrap();
    assert_eq!(of(&mut fs, EF_PK_SIG), ORIGIN_GENERATED);
    assert_eq!(of(&mut fs, EF_PK_DEC), ORIGIN_IMPORTED);
    assert_eq!(of(&mut fs, EF_PK_AUT), ORIGIN_IMPORTED);

    mark(&mut fs, EF_PK_AUT, ORIGIN_GENERATED).unwrap();
    mark(&mut fs, EF_PK_DEC, ORIGIN_IMPORTED).unwrap();
    assert_eq!(of(&mut fs, EF_PK_SIG), ORIGIN_GENERATED);
    assert_eq!(of(&mut fs, EF_PK_DEC), ORIGIN_IMPORTED);
    assert_eq!(of(&mut fs, EF_PK_AUT), ORIGIN_GENERATED);

    // Generated is not sticky — an import over it reads back as imported.
    mark(&mut fs, EF_PK_SIG, ORIGIN_IMPORTED).unwrap();
    assert_eq!(of(&mut fs, EF_PK_SIG), ORIGIN_IMPORTED);
}

#[test]
fn a_short_or_junk_record_reads_as_imported() {
    // Only a byte that is exactly 01 may be believed: anything else — a record
    // an older build left one byte long, a value no spec assigns — is unproven.
    let mut fs = fs();
    fs.put(EF_KEY_ORIGIN, &[ORIGIN_GENERATED]).unwrap();
    assert_eq!(of(&mut fs, EF_PK_SIG), ORIGIN_GENERATED);
    assert_eq!(of(&mut fs, EF_PK_DEC), ORIGIN_IMPORTED);
    assert_eq!(of(&mut fs, EF_PK_AUT), ORIGIN_IMPORTED);

    fs.put(EF_KEY_ORIGIN, &[0x00, 0xFF, 0x03]).unwrap();
    for pk in [EF_PK_SIG, EF_PK_DEC, EF_PK_AUT] {
        assert_eq!(of(&mut fs, pk), ORIGIN_IMPORTED);
    }
}

#[test]
fn marking_a_slot_over_a_short_record_keeps_the_rest_imported() {
    let mut fs = fs();
    fs.put(EF_KEY_ORIGIN, &[ORIGIN_GENERATED]).unwrap();
    mark(&mut fs, EF_PK_AUT, ORIGIN_GENERATED).unwrap();
    assert_eq!(of(&mut fs, EF_PK_SIG), ORIGIN_GENERATED);
    assert_eq!(of(&mut fs, EF_PK_DEC), ORIGIN_IMPORTED);
    assert_eq!(of(&mut fs, EF_PK_AUT), ORIGIN_GENERATED);
}

/// A flash that refuses to write one file and accepts every other, so the mark's
/// failure can be produced by driving the real IMPORT rather than by
/// hand-assembling the state it would leave. Reads keep working, as a card's do
/// after a failed write.
struct RefusesFid {
    inner: RamStorage,
    fid: std::rc::Rc<std::cell::Cell<u16>>,
}
impl Storage for RefusesFid {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        if fid == self.fid.get() {
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

struct CountRng(u8);
impl crate::Rng for CountRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn dev() -> rsk_crypto::Device<'static> {
    rsk_crypto::Device {
        serial_hash: &[0x33; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

/// §4.4.3.8's claim is the whole point of the DO, so an IMPORT that cannot record
/// it must not go on to store the key: the slot would keep the `01` of the key it
/// replaced. The mark is best-effort in the other direction only — a GENERATE
/// whose mark fails reads as imported, which under-claims.
#[test]
fn an_import_that_cannot_record_its_origin_stores_no_key() {
    const SENTINEL: &[u8] = b"the key the record describes";
    let refused = std::rc::Rc::new(std::cell::Cell::new(0xFFFFu16));
    let mut fs = Fs::new(RefusesFid {
        inner: RamStorage::new(),
        fid: refused.clone(),
    });
    fs.scan();
    let d = dev();
    crate::init::scan_files(&d, &mut fs, &mut CountRng(0)).unwrap();
    let mut sess = crate::Session::new();
    assert_eq!(
        crate::pin::verify(
            &d,
            &mut fs,
            &mut sess,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );

    // A P-256 slot holding a key recorded as generated on card.
    fs.put(
        EF_ALGO_PRIV1,
        &[ALGO_ECDSA, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    )
    .unwrap();
    fs.put(EF_PK_SIG.get(), SENTINEL).unwrap();
    mark(&mut fs, EF_PK_SIG, ORIGIN_GENERATED).unwrap();

    // Now the origin record is unwritable. The import must fail, and fail before
    // it has replaced the key the record still describes.
    refused.set(EF_KEY_ORIGIN);
    let body = [
        &[CRT_SIG, 0x00][..],
        &[0x7F, 0x48, 0x02, 0x92, 0x20][..],
        &[0x5F, 0x48, 0x20][..],
        &[0x44u8; 32][..],
    ]
    .concat();
    let mut ehl = vec![0x4D, body.len() as u8];
    ehl.extend_from_slice(&body);
    assert_eq!(
        crate::importdata::import_data(&d, &mut fs, &sess, 0x3F, 0xFF, &ehl),
        Sw::MEMORY_FAILURE
    );
    assert_eq!(of(&mut fs, EF_PK_SIG), ORIGIN_GENERATED);
    let mut slot = [0u8; 64];
    let n = fs.read(EF_PK_SIG.get(), &mut slot).unwrap_or(0);
    assert_eq!(&slot[..n], SENTINEL);
}
