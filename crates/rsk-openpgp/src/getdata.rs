// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! GET DATA / GET NEXT DATA: build the DO ([`DoWriter`]) and, for a PRIMITIVE
//! non-flash DO whose whole response is a single TLV, strip the outer
//! tag+length — returning the bare value, as `gpg`/`opensc` expect. A
//! CONSTRUCTED template DO (6E/65/73/7A/FA) keeps its tag+length: real
//! OpenPGP cards return it wrapped, `gpg` tolerates it, and ykman/yubikit
//! REQUIRE it (`ApplicationRelatedData.parse` does `Tlv.unpack(0x6E, …)`).

use rsk_fs::{Fs, Storage};
use rsk_sdk::Sw;

use crate::consts::*;
use crate::dobj::DoWriter;
use crate::files::{DoSource, source};

/// If `buf` is exactly one BER-TLV, return its header length (tag + length
/// bytes); otherwise 0.
fn outer_tlv_header(buf: &[u8]) -> usize {
    let data_len = buf.len();
    if data_len < 2 {
        return 0;
    }
    let tag_bytes = if buf[0] & 0x1f == 0x1f { 2 } else { 1 };
    if tag_bytes >= data_len {
        return 0;
    }
    let len_byte = buf[tag_bytes];
    let (tg_len, header) = if len_byte & 0x80 == 0 {
        (len_byte as usize, tag_bytes + 1)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 2 || tag_bytes + 1 + n > data_len {
            return 0;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | buf[tag_bytes + 1 + i] as usize;
        }
        (v, tag_bytes + 1 + n)
    };
    if tg_len + header == data_len {
        header
    } else {
        0
    }
}

/// Resolve the tag, enforce the read ACL, build the DO into `out`, and strip
/// the outer wrapper for non-flash DOs. Returns `(len, sw)` and records the
/// selected DO in `current_ef` for a following GET NEXT DATA.
pub fn get_data<S: Storage>(
    fid: u16,
    has_pw2: bool,
    has_pw3: bool,
    fs: &mut Fs<S>,
    full_aid: &[u8; 16],
    current_ef: &mut Option<u16>,
    out: &mut [u8],
) -> (usize, Sw) {
    let src = source(fid);
    match src {
        // A P1P2 this command does not serve is a wrong P1P2, whether it names
        // nothing at all or an internal EF: a YubiKey 5.7.4 answers `6B00` to
        // 65513 of the 65536 cells and keeps `6982` for the two private DOs it
        // does serve. Telling the two apart located every internal EF for a
        // caller holding no credential.
        DoSource::None | DoSource::Internal => return (0, Sw::WRONG_P1P2),
        _ => {}
    }
    // §5's access table gives the private DOs two different owners and no admin
    // override: `0103` is the cardholder's (PW1 no. 82), `0104` the admin's. A
    // YubiKey 5.7.4 implements exactly that, 3/3 from a genuine deselect —
    // unauthenticated both are `6982`, PW1-82 alone opens `0103` and not `0104`,
    // PW3 alone opens `0104` and not `0103`. (An earlier reading had it serving
    // `0104` to anyone; that one was taken with PW3 still standing, since a
    // re-SELECT of the same AID does not clear this card's PW state.)
    if fid == EF_PRIV_DO_3 && !has_pw2 {
        return (0, Sw::SECURITY_STATUS_NOT_SATISFIED);
    }
    if fid == EF_PRIV_DO_4 && !has_pw3 {
        return (0, Sw::SECURITY_STATUS_NOT_SATISFIED);
    }

    let mut data_len = {
        let mut w = DoWriter::new(out, fs, full_aid);
        w.build(fid)
    };
    // `build` reports a DO's full stored length, which can exceed `out` when an
    // over-long object was stored (Fs::read returns the value's full length, the
    // Func(AlgoInfo) C1/C2/C3 arm returns fs.size() directly). PUT DATA bounds
    // every write at MAX_DO_BYTES = out.len(), so reaching here means a value an
    // older build wrote through the wider chaining buffer. Refuse rather than
    // slice: a short body under `9000` is indistinguishable from a complete one,
    // and the caller would panic on `&out[..data_len]` if we did not.
    if data_len > out.len() {
        return (0, Sw::MEMORY_FAILURE);
    }
    // GET DATA returns a PRIMITIVE DO's bare value (gpg/opensc want the value,
    // not its tag+length), but a CONSTRUCTED template DO keeps its outer
    // tag+length. The BER constructed bit (0x20 on the first tag byte) is the
    // discriminator: 6E/65/73/7A/FA all carry it, the primitives (4F/C1/C4/DE…)
    // do not. Real cards wrap the templates, gpg tolerates either, but ykman's
    // `ApplicationRelatedData.parse` does `Tlv.unpack(0x6E, response)` and an
    // unwrapped `4F …` makes `ykman openpgp info` fail (`Incorrect TLV
    // length`, reproduced live on 0x0755). Flash DOs are raw stored values and
    // carry no wrapper to strip.
    // EF_GFM (7F74) is a constructed DO whose value is itself the sub-DO 81 01 20;
    // read standalone that value is one primitive TLV, but it must NOT be unwrapped
    // — a real YubiKey returns the whole 81 01 20, and clients expect the sub-DO.
    // This strip is only sound because `build` always emits a real tag+length for a
    // primitive DO: it decides by *sniffing*, so a bare value that happens to parse
    // as one TLV loses two bytes. `emit_algoinfo` used to emit C1/C2/C3 bare when
    // read standalone, which is how `rsa1024` (`01 04 00 00 20 00` — length 4, four
    // bytes left) came back as `00 00 20 00`.
    if !matches!(src, DoSource::Flash) && fid != EF_GFM && data_len > 0 && out[0] & 0x20 == 0 {
        let dec = outer_tlv_header(&out[..data_len]);
        if dec > 0 {
            out.copy_within(dec..data_len, 0);
            data_len -= dec;
        }
    }
    *current_ef = Some(fid);
    (data_len, Sw::OK)
}

#[cfg(test)]
#[path = "getdata_tests.rs"]
mod tests;
