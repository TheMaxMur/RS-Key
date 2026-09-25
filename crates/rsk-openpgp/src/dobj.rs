// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Data-object builders. Each `emit_*` appends BER-TLV to the [`DoWriter`]
//! output cursor, reading sub-objects from flash or the ROM table.

use rsk_fs::{Fs, Storage};

use crate::consts::*;
use crate::files::{DoSource, FuncDo, source};

// Algorithm-attribute templates, each prefixed with its TLV length byte —
// `emit_algo` copies `algo[0]+1` bytes after the tag.
const E_HI: u8 = RSA_E_BITS_BE[0];
const E_LO: u8 = RSA_E_BITS_BE[1];
const ATTR_RSA1K: &[u8] = &[6, ALGO_RSA, 0x04, 0x00, E_HI, E_LO, 0x00];
const ATTR_RSA2K: &[u8] = &[6, ALGO_RSA, 0x08, 0x00, E_HI, E_LO, 0x00];
const ATTR_RSA3K: &[u8] = &[6, ALGO_RSA, 0x0C, 0x00, E_HI, E_LO, 0x00];
const ATTR_RSA4K: &[u8] = &[6, ALGO_RSA, 0x10, 0x00, E_HI, E_LO, 0x00];
pub(crate) const ATTR_P256K1: &[u8] = &[6, ALGO_ECDSA, 0x2b, 0x81, 0x04, 0x00, 0x0a];
pub(crate) const ATTR_P256R1: &[u8] = &[
    9, ALGO_ECDSA, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
];
pub(crate) const ATTR_P384R1: &[u8] = &[6, ALGO_ECDSA, 0x2B, 0x81, 0x04, 0x00, 0x22];
pub(crate) const ATTR_P521R1: &[u8] = &[6, ALGO_ECDSA, 0x2B, 0x81, 0x04, 0x00, 0x23];
// brainpoolP256r1/384r1 (RFC 5639, OID 1.3.36.3.3.2.8.1.1.{7,11}) — bp256/bp384 0.14
// fiat-crypto backend. bp512r1 (…1.1.13) is still omitted: no bp512 crate exists.
pub(crate) const ATTR_BP256R1: &[u8] = &[
    10, ALGO_ECDSA, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
];
pub(crate) const ATTR_BP384R1: &[u8] = &[
    10, ALGO_ECDSA, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B,
];
pub(crate) const ATTR_CV25519: &[u8] = &[
    11, ALGO_ECDH, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
];
pub(crate) const ATTR_ED25519: &[u8] = &[
    10, ALGO_EDDSA, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01,
];

// The algorithms each slot supports. `emit_algoinfo` publishes these in DO `0xFA`
// and `putdata` accepts nothing else into C1/C2/C3 — one definition, so the card
// can never generate a key it does not advertise (OpenPGP 3.4 §4.4.3.9: "a card
// should reject unsupported values in the DO"). Without the check, `nbits` came
// straight off the wire and `rsk_rsa::RsaKeygen::usable` took any 32-byte
// multiple, so a PW3 holder could set 512 and have the *owner* generate a
// factorable key later.
//
// §4.4.3.9 also makes this the machine-readable contract a terminal is told to
// use for key import, so an entry here is a promise, not a wish list: X448 and
// Ed448 sat in it while GENERATE and IMPORT refused them, and the only thing a
// host could do with the advertisement was store an attribute that left the slot
// dead — `gpg --card-status` showing Ed448 for a slot where nothing works.
pub(crate) const ALGO_SIG_SUPPORTED: &[&[u8]] = &[
    ATTR_RSA1K,
    ATTR_RSA2K,
    ATTR_RSA3K,
    ATTR_RSA4K,
    ATTR_P256K1,
    ATTR_P256R1,
    ATTR_P384R1,
    ATTR_P521R1,
    ATTR_BP256R1,
    ATTR_BP384R1,
    ATTR_ED25519,
];
pub(crate) const ALGO_DEC_SUPPORTED: &[&[u8]] = &[
    ATTR_RSA1K,
    ATTR_RSA2K,
    ATTR_RSA3K,
    ATTR_RSA4K,
    ATTR_P256K1,
    ATTR_P256R1,
    ATTR_P384R1,
    ATTR_P521R1,
    ATTR_BP256R1,
    ATTR_BP384R1,
    ATTR_CV25519,
];
pub(crate) const ALGO_AUT_SUPPORTED: &[&[u8]] = ALGO_SIG_SUPPORTED;
/// The attestation key's one algorithm: the card mints it, and `DA` takes no write.
pub(crate) const ALGO_ATT_SUPPORTED: &[&[u8]] = &[ATTR_P384R1];

/// Whether `data`, a C1/C2/C3 value, is an attribute DO `0xFA` advertises for `fid`:
/// matched against `attr[1..]` after [`DoWriter::emit_algo`]'s ECDSA→ECDH rewrite, and
/// with an RSA exponent length from 17 bits up read as the 17 it is stored as.
pub(crate) fn advertised_algo(fid: u16, data: &[u8]) -> bool {
    let set = match fid {
        EF_ALGO_SIG => ALGO_SIG_SUPPORTED,
        EF_ALGO_DEC => ALGO_DEC_SUPPORTED,
        EF_ALGO_AUT => ALGO_AUT_SUPPORTED,
        _ => return false,
    };
    set.iter().any(|a| {
        let val = &a[1..a[0] as usize + 1];
        match (val.split_first(), data.split_first()) {
            // ECDSA (0x13) and ECDH (0x12) over the same OID name the same curve —
            // which one a slot carries depends on how the key is used, and MSE can
            // repoint DECIPHER at the AUT slot. Match on the OID and treat the two
            // ids as interchangeable, exactly as `curve_from_attr` does; the point
            // of this gate is the *curve/size*, not the operation byte.
            (Some((&(ALGO_ECDSA | ALGO_ECDH), lhs)), Some((&(ALGO_ECDSA | ALGO_ECDH), rhs))) => {
                lhs == rhs
            }
            // A YubiKey 5.8.0 takes any e length from 17 bits and stores 17
            // ([`canonical_algo`]); the size and the import format must match.
            (Some((&ALGO_RSA, lhs)), Some((&ALGO_RSA, rhs))) => {
                rhs.len() == lhs.len()
                    && lhs[..2] == rhs[..2]
                    && lhs[4] == rhs[4]
                    && u16::from_be_bytes([rhs[2], rhs[3]]) >= RSA_E_BITS
            }
            _ => val == data,
        }
    })
}

/// An RSA attribute as a YubiKey 5.8.0 stores and reports it: an exponent length of
/// 17 bits or more becomes [`RSA_E_BITS`]. `None` for anything else, a shorter length
/// an older build stored included, so it reads back as the refusal it is.
pub(crate) fn canonical_algo(attr: &[u8]) -> Option<[u8; 6]> {
    match *attr {
        [ALGO_RSA, n_hi, n_lo, e_hi, e_lo, format]
            if u16::from_be_bytes([e_hi, e_lo]) >= RSA_E_BITS =>
        {
            Some([ALGO_RSA, n_hi, n_lo, E_HI, E_LO, format])
        }
        _ => None,
    }
}

/// Whether `a` and `b` name the same key, reading RSA as [`canonical_algo`] does.
pub(crate) fn same_algo(a: &[u8], b: &[u8]) -> bool {
    match (canonical_algo(a), canonical_algo(b)) {
        (Some(a), Some(b)) => a == b,
        _ => a == b,
    }
}

/// Builds DO responses into a caller buffer, reading sub-DOs from `fs`.
pub struct DoWriter<'a, S: Storage> {
    out: &'a mut [u8],
    pos: usize,
    fs: &'a mut Fs<S>,
    full_aid: &'a [u8; 16],
}

impl<'a, S: Storage> DoWriter<'a, S> {
    pub fn new(out: &'a mut [u8], fs: &'a mut Fs<S>, full_aid: &'a [u8; 16]) -> Self {
        Self {
            out,
            pos: 0,
            fs,
            full_aid,
        }
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    pub fn bytes(&self) -> &[u8] {
        &self.out[..self.pos]
    }

    fn push(&mut self, b: u8) {
        if self.pos < self.out.len() {
            self.out[self.pos] = b;
            self.pos += 1;
        }
    }

    fn extend(&mut self, s: &[u8]) {
        let n = s.len().min(self.out.len() - self.pos);
        self.out[self.pos..self.pos + n].copy_from_slice(&s[..n]);
        self.pos += n;
    }

    /// BER-TLV length encoding: 1 byte (<128), `81 LL` (<256), or `82 HH LL`.
    fn fmt_len(&mut self, len: usize) {
        if len < 0x80 {
            self.push(len as u8);
        } else if len < 0x100 {
            self.push(0x81);
            self.push(len as u8);
        } else {
            self.push(0x82);
            self.push((len >> 8) as u8);
            self.push((len & 0xff) as u8);
        }
    }

    fn read_flash(&mut self, fid: u16) {
        let cap = &mut self.out[self.pos..];
        if let Some(n) = self.fs.read(fid, cap) {
            // `fs.read` returns the value's FULL stored length while it copies only
            // `min(len, cap.len())`; advance by what actually fit, or an over-long
            // stored DO would push `pos` past `out` and panic on the next slice.
            self.pos += n.min(cap.len());
        }
    }

    /// Top-level builder for a GET DATA tag: `[1, fid]` with `mode == 1`.
    pub fn build(&mut self, fid: u16) -> usize {
        self.emit_do(&[1, fid], 1)
    }

    /// Walk a fid list, appending each sub-DO. For a multi-element list (a
    /// constructed DO) each child is tag + length prefixed.
    fn emit_do(&mut self, fids: &[u16], mode: i32) -> usize {
        let mut len = 0usize;
        let count = fids[0] as usize;
        for i in 0..count {
            let fid = fids[i + 1];
            match source(fid) {
                DoSource::Func(f) => len += self.emit_func(f, fid, mode),
                DoSource::None | DoSource::Internal => {}
                src => {
                    let data_len = match src {
                        DoSource::Rom(c) => c.len(),
                        DoSource::FullAid => self.full_aid.len(),
                        DoSource::Flash => self.fs.size(fid).unwrap_or(0),
                        _ => 0,
                    };
                    if mode == 1 {
                        if count > 1 && self.pos > 0 {
                            if fid < 0x0100 {
                                self.push((fid & 0xff) as u8);
                            } else {
                                self.push((fid >> 8) as u8);
                                self.push((fid & 0xff) as u8);
                            }
                            self.fmt_len(data_len);
                        }
                        match src {
                            DoSource::Rom(c) => self.extend(c),
                            DoSource::FullAid => {
                                let a = *self.full_aid;
                                self.extend(&a);
                            }
                            DoSource::Flash => self.read_flash(fid),
                            _ => {}
                        }
                    }
                    len += data_len;
                }
            }
        }
        len
    }

    fn emit_func(&mut self, f: FuncDo, fid: u16, mode: i32) -> usize {
        match f {
            FuncDo::AppData => self.emit_app_data(mode),
            FuncDo::ChData => self.emit_ch_data(mode),
            FuncDo::DiscreteDo => self.emit_discrete_do(mode),
            FuncDo::SecTpl => self.emit_sec_tpl(),
            FuncDo::Fp => self.emit_fp(),
            FuncDo::CaFp => self.emit_cafp(),
            FuncDo::Ts => self.emit_ts(),
            FuncDo::KeyInfo => self.emit_keyinfo(),
            FuncDo::PwStatus => self.emit_pw_status(),
            FuncDo::AlgoInfo => self.emit_algoinfo(fid),
            FuncDo::ChCert => 0,
        }
    }

    /// A constructed DO: outer tag (1 byte) + `82 HH LL` + nested, length
    /// back-patched.
    fn constructed(&mut self, tag: u8, fids: &[u16], mode: i32) -> usize {
        let lp = self.open(tag);
        self.emit_do(fids, mode);
        self.close(lp)
    }

    /// Open a constructed DO: its tag and a two-byte length [`Self::close`] fills.
    fn open(&mut self, tag: u8) -> usize {
        self.push(tag);
        self.push(0x82);
        let lp = self.pos;
        self.pos += 2;
        lp
    }

    fn close(&mut self, lp: usize) -> usize {
        let lpdif = self.pos - lp - 2;
        self.out[lp] = (lpdif >> 8) as u8;
        self.out[lp + 1] = (lpdif & 0xff) as u8;
        lpdif + 4
    }

    fn emit_app_data(&mut self, mode: i32) -> usize {
        let fids = [
            5,
            EF_FULL_AID,
            EF_HIST_BYTES,
            EF_EXLEN_INFO,
            EF_GFM,
            EF_DISCRETE_DO,
        ];
        self.constructed((EF_APP_DATA & 0xff) as u8, &fids, mode)
    }

    fn emit_ch_data(&mut self, mode: i32) -> usize {
        let fids = [3, EF_CH_NAME, EF_LANG_PREF, EF_SEX];
        self.constructed((EF_CH_DATA & 0xff) as u8, &fids, mode)
    }

    fn emit_discrete_do(&mut self, mode: i32) -> usize {
        // 0xDE (Key Information) is a child of the 0x73 discretionary DOs per the
        // OpenPGP Card spec — where ykman >= 5.2 looks for it — not a bare child of 0x6E.
        // A YubiKey 5.8.0's order, but for the 7F66 it puts after DE, which ours keeps in 6E.
        let lp = self.open((EF_DISCRETE_DO & 0xff) as u8);
        self.emit_do(
            &[4, EF_EXT_CAP, EF_ALGO_SIG, EF_ALGO_DEC, EF_ALGO_AUT],
            mode,
        );
        // DA is served here and nowhere else: GET DATA DA is `6B00` on a YubiKey.
        self.emit_algo(ALGO_ATT_SUPPORTED[0], EF_ALGO_ATT);
        let fids = [
            9,
            EF_PW_STATUS,
            EF_FP,
            EF_CA_FP,
            EF_TS_ALL,
            EF_KEY_INFO,
            EF_UIF_SIG,
            EF_UIF_DEC,
            EF_UIF_AUT,
            EF_UIF_ATT,
        ];
        self.emit_do(&fids, mode);
        self.close(lp)
    }

    fn emit_sec_tpl(&mut self) -> usize {
        let start = self.pos;
        self.push((EF_SEC_TPL & 0xff) as u8);
        self.push(5);
        if self.fs.has_data(EF_SIG_COUNT) {
            self.push((EF_SIG_COUNT & 0xff) as u8);
            self.push(3);
            self.read_flash(EF_SIG_COUNT);
        }
        // Return what was actually written: when EF_SIG_COUNT is absent (or short)
        // only the 2-byte header lands, so a constant `5 + 2` would over-read the
        // scratch tail (stale bytes from a prior command).
        self.pos - start
    }

    /// `fids`, each written as exactly `size` bytes: zero-padded when short or absent,
    /// cut when over-long, so the aggregate's fixed length byte stays honest and no
    /// stale scratch from a prior command leaks past what was written.
    fn emit_fixed(&mut self, fids: &[u16], size: usize) -> usize {
        for &f in fids {
            let before = self.pos;
            if self.fs.has_data(f) {
                self.read_flash(f);
            }
            let written = self.pos - before;
            if written < size {
                for _ in written..size {
                    self.push(0);
                }
            } else {
                self.pos = before + size;
            }
        }
        fids.len() * size
    }

    fn emit_fp(&mut self) -> usize {
        self.push((EF_FP & 0xff) as u8);
        self.push((FP_DOS.len() * FP_LEN) as u8);
        self.emit_fixed(&FP_DOS, FP_LEN) + 2
    }

    fn emit_cafp(&mut self) -> usize {
        self.push((EF_CA_FP & 0xff) as u8);
        self.push((CA_FP_DOS.len() * FP_LEN) as u8);
        self.emit_fixed(&CA_FP_DOS, FP_LEN) + 2
    }

    fn emit_ts(&mut self) -> usize {
        self.push((EF_TS_ALL & 0xff) as u8);
        self.push((TS_DOS.len() * TS_LEN) as u8);
        self.emit_fixed(&TS_DOS, TS_LEN) + 2
    }

    fn emit_keyinfo(&mut self) -> usize {
        let init = self.pos;
        if self.pos > 0 {
            self.push((EF_KEY_INFO & 0xff) as u8);
            self.push(2 * (KEY_SLOTS + 1) as u8);
        }
        // OpenPGP Card 3.4 §4.4.3.8: key-ref 01=SIG, 02=DEC, 03=AUT, then a status
        // byte — 00 not present, 01 generated on card, 02 imported. ykman >= 5.2
        // keys its parse on these refs, so they must be the spec values, not
        // 0-indexed.
        for (key_ref, fid) in [
            (KEY_REF_SIG, EF_PK_SIG),
            (KEY_REF_DEC, EF_PK_DEC),
            (KEY_REF_AUT, EF_PK_AUT),
        ] {
            self.push(key_ref);
            let status = if self.fs.has_key(fid) {
                crate::origin::of(self.fs, fid)
            } else {
                0x00
            };
            self.push(status);
        }
        // Yubico's attestation key, which only the card generates.
        self.push(KEY_REF_ATT);
        let att = if self.fs.has_key(EF_PK_ATT) {
            crate::origin::ORIGIN_GENERATED
        } else {
            0x00
        };
        self.push(att);
        self.pos - init
    }

    fn emit_pw_status(&mut self) -> usize {
        let init = self.pos;
        if self.pos > 0 {
            self.push((EF_PW_STATUS & 0xff) as u8);
            self.push(7);
        }
        if self.fs.has_data(EF_PW_PRIV) {
            self.read_flash(EF_PW_PRIV);
        }
        self.pos - init
    }

    /// Append `tag | length-prefixed-template`.
    fn emit_algo(&mut self, algo: &[u8], tag: u16) -> usize {
        self.push((tag & 0xff) as u8);
        let n = algo[0] as usize + 1;
        // The DEC list carries the same curve OIDs as SIG/AUT but as ECDH (0x12),
        // not ECDSA (0x13): a decryption key does key agreement (matches YubiKey).
        if tag == EF_ALGO_DEC && algo.get(1) == Some(&ALGO_ECDSA) {
            self.push(algo[0]);
            self.push(ALGO_ECDH);
            self.extend(&algo[2..n]);
        } else {
            self.extend(&algo[..n]);
        }
        algo[0] as usize + 2
    }

    fn emit_algoinfo(&mut self, fid: u16) -> usize {
        if fid == EF_ALGO_INFO {
            self.push((EF_ALGO_INFO & 0xff) as u8);
            self.push(0x82);
            let lp = self.pos;
            self.pos += 2;
            for a in ALGO_SIG_SUPPORTED {
                self.emit_algo(a, EF_ALGO_SIG);
            }
            for a in ALGO_DEC_SUPPORTED {
                self.emit_algo(a, EF_ALGO_DEC);
            }
            for a in ALGO_AUT_SUPPORTED {
                self.emit_algo(a, EF_ALGO_AUT);
            }
            for a in ALGO_ATT_SUPPORTED {
                self.emit_algo(a, EF_ALGO_ATT);
            }
            let lpdif = self.pos - lp - 2;
            self.out[lp] = (lpdif >> 8) as u8;
            self.out[lp + 1] = (lpdif & 0xff) as u8;
            lpdif + 4
        } else {
            // C1/C2/C3: the stored algorithm attributes, or rsa2k by default. The
            // tag+length goes on unconditionally, exactly as the default arm's
            // `emit_algo` does: `get_data` strips a primitive DO's header for a
            // standalone read by *sniffing* one, so a value emitted bare here loses
            // two bytes whenever it happens to parse as a single TLV. `rsa1024`
            // (`01 04 00 00 20 00`) is precisely that shape, so the card answered
            // `00 00 20 00` to GET DATA C1 while GENERATE still read the stored six
            // bytes and made a 1024-bit key. Found by differential against a real
            // YubiKey while verifying audit run-34.
            let priv_fid = algo_tag_to_priv(fid);
            if !self.fs.has_data(priv_fid) {
                self.emit_algo(ATTR_RSA2K, fid)
            } else {
                let len = self.fs.size(priv_fid).unwrap_or(0);
                self.push((fid & 0xff) as u8);
                self.push((len & 0xff) as u8);
                let at = self.pos;
                self.read_flash(priv_fid);
                // An older build stored the e length it was sent.
                if let Some(attr) = canonical_algo(&self.out[at..self.pos]) {
                    self.out[at..self.pos].copy_from_slice(&attr);
                }
                2 + len
            }
        }
    }
}

#[cfg(test)]
#[path = "dobj_tests.rs"]
mod tests;
