// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! NIST ACVP Known-Answer-Test vectors for ML-DSA-44, ML-DSA-65 and ML-DSA-87
//! — the independent ground truth for the host tests: key generation, signing
//! (deterministic and hedged), and verification (accept + each tamper-reject
//! reason). All fields are hex.
//!
//! The cases live in `third_party/acvp/` under NIST's notice, written by
//! `scripts/acvp_vectors.py`; each file's header names the ACVP-Server commit,
//! the sha256 of the JSON it came from and the filter. `include_str!` makes a
//! missing file a build error rather than zero cases, and the tests assert the
//! counts, so a case lost in a refresh is red too.

use std::sync::LazyLock;

pub(crate) struct KeyGenKat {
    pub tc_id: &'static str,
    pub set: u16,
    pub seed: &'static str,
    pub pk: &'static str,
    pub sk: &'static str,
}

pub(crate) struct SigGenKat {
    pub tc_id: &'static str,
    pub set: u16,
    pub rnd: &'static str,
    pub sk: &'static str,
    pub msg: &'static str,
    pub ctx: &'static str,
    pub sig: &'static str,
}

pub(crate) struct SigVerKat {
    pub tc_id: &'static str,
    pub set: u16,
    pub expected: bool,
    pub pk: &'static str,
    pub msg: &'static str,
    pub ctx: &'static str,
    pub sig: &'static str,
    pub reason: &'static str,
}

pub(crate) static KEYGEN: LazyLock<Vec<KeyGenKat>> = LazyLock::new(|| {
    cases(include_str!("../../../third_party/acvp/mldsa-keygen.txt"))
        .map(|[tc_id, set, seed, pk, sk]| KeyGenKat {
            tc_id,
            set: size(set),
            seed,
            pk,
            sk,
        })
        .collect()
});

pub(crate) static SIGGEN: LazyLock<Vec<SigGenKat>> = LazyLock::new(|| {
    cases(include_str!("../../../third_party/acvp/mldsa-siggen.txt"))
        .map(|[tc_id, set, rnd, sk, msg, ctx, sig]| SigGenKat {
            tc_id,
            set: size(set),
            rnd,
            sk,
            msg,
            ctx,
            sig,
        })
        .collect()
});

pub(crate) static SIGVER: LazyLock<Vec<SigVerKat>> = LazyLock::new(|| {
    cases(include_str!("../../../third_party/acvp/mldsa-sigver.txt"))
        .map(
            |[tc_id, set, passes, pk, msg, ctx, sig, reason]| SigVerKat {
                tc_id,
                set: size(set),
                expected: verdict(passes),
                pk,
                msg,
                ctx,
                sig,
                reason,
            },
        )
        .collect()
});

/// The data lines of a vector file, each split into its `N` fields. The last one
/// keeps its spaces, because a sigVer reason is prose; `-` stands for empty.
fn cases<const N: usize>(text: &'static str) -> impl Iterator<Item = [&'static str; N]> {
    text.lines().filter(|l| !l.starts_with('#')).map(|line| {
        let fields: Vec<&'static str> = line
            .splitn(N, ' ')
            .map(|f| if f == "-" { "" } else { f })
            .collect();
        fields
            .try_into()
            .unwrap_or_else(|f: Vec<_>| panic!("{} of {N} fields: {line:.60}", f.len()))
    })
}

fn size(field: &str) -> u16 {
    field.parse().expect("a parameter set is 44, 65 or 87")
}

fn verdict(field: &str) -> bool {
    match field {
        "1" => true,
        "0" => false,
        v => panic!("a sigVer verdict of {v:?}, not 1 or 0"),
    }
}
