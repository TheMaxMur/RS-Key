// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `rebuild_meta` walks persisted — possibly corrupt — flash contents.
/// For ANY blob up to 16 bytes (several records' worth, every truncation),
/// any record to drop, and any record to append into a too-small output:
/// no panic, no out-of-bounds write, the reported length fits, nothing is
/// written past it, and — the point of the harness — **the old record for
/// `fid` is gone from the output**.
///
/// That last clause is what `meta_delete` and `meta_add` both mean by their
/// names, and it was the unasserted one. `meta_add` is a replace: it rebuilds
/// with the same fid and appends the new value, so a walk that missed one
/// occurrence leaves two records under one fid in `EF_META` — and `meta_find`
/// returns the **first**, which is the stale one. A deleted credential whose
/// metadata outlives it, or a replaced one that keeps answering with its old
/// value, is exactly the shape this tree has shipped before.
///
/// It is stated without a second decoder, which would be the same walk written
/// twice and would prove agreement between two copies of a bug: feeding the
/// output back through `rebuild_meta` for the same fid with nothing to append
/// must drop **only** the record this pass appended. Any survivor would shrink
/// it further.
#[kani::proof]
// The longest loop is now the tail sentinel — `out.len()` = 8 iterations, +1 for
// the unwinding assertion. The rebuild itself needs 5 (a 16-byte blob holds at
// most four 4-byte headers) and the second pass 3. Every loop reports
// `unwind SUCCESS` at this bound; at 6 the sentinel loop failed outright, which
// is how an insufficient bound shows up — never as a silent under-approximation.
#[kani::unwind(10)]
fn rebuild_meta_any_blob() {
    const B: usize = 16;
    // Not 0: "the rebuild wrote a zero byte" and "the rebuild wrote nothing"
    // have to stay distinguishable for the tail claim below.
    const PAD: u8 = 0xA5;
    let blob: [u8; B] = kani::any();
    let bn: usize = kani::any();
    kani::assume(bn <= B);
    let fid: u16 = kani::any();
    let data: [u8; 4] = kani::any();
    let dn: usize = kani::any();
    kani::assume(dn <= 4);
    let with_new: bool = kani::any();
    let new = if with_new { Some(&data[..dn]) } else { None };
    // Smaller than the worst-case rebuild → the NoMemory arms are reachable.
    let mut out = [PAD; 8];
    let Ok(w) = rebuild_meta(&blob[..bn], fid, new, &mut out) else {
        return;
    };
    assert!(w <= out.len(), "reported more than the buffer holds");
    let mut i = w;
    while i < out.len() {
        assert!(out[i] == PAD, "wrote past the length it reported");
        i += 1;
    }

    // `out[..w]` is a concatenation of whole records, so this pass cannot end on
    // a truncated tail, and it only ever drops — it always fits.
    let mut again = [PAD; 8];
    let appended = if with_new { META_REC_HDR + dn } else { 0 };
    match rebuild_meta(&out[..w], fid, None, &mut again) {
        Ok(w2) => assert!(
            w2 == w - appended,
            "a record for the rebuilt fid survived the rebuild"
        ),
        Err(_) => assert!(false, "a rebuild that only drops records must fit"),
    }
    kani::cover!(
        !with_new && w + META_REC_HDR <= bn,
        "a rebuild that dropped at least a record's worth"
    );
    kani::cover!(
        with_new && w > META_REC_HDR + dn,
        "an append after survivors"
    );
}
