// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// [`split_period`] on ANY credential name never panics or overflows; the bare
/// label it returns really is the input's own **suffix**, and what it consumed
/// really was `<digits>/`.
///
/// The suffix claim is the one that matters and the one the old harness only
/// stated in prose: the label is what LIST returns to the host and what the
/// display shows the user, so a label that is a *copy* — or a window at a
/// shifted offset — would let a name be shown differently from the one stored.
/// The prefix claim is its other half: a period may only be taken off a name
/// that actually carried one, or `12345issuer:acct` silently becomes `issuer`
/// at period 1234 for one host and stays whole for another.
///
/// `p <= 9999` is where the `u16` fold cannot wrap; the `i < 4` cap is what
/// guarantees it, and the `k <= 5` bound below is the same fact seen from the
/// input side.
#[kani::proof]
#[kani::unwind(6)]
fn split_period_total_and_bounded() {
    let name: [u8; 6] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= name.len());
    let input = &name[..len];
    let (period, label) = split_period(input);

    // The suffix, by address: the label points into the input, `k` bytes in.
    assert!(label.len() <= len, "label longer than the name");
    let k = len - label.len();
    assert!(
        core::ptr::eq(label.as_ptr(), input[k..].as_ptr()),
        "label is not the input's own suffix"
    );

    match period {
        Some(p) => {
            assert!(p <= 9999, "period does not fit the u16 fold");
            // `<= 4 digits> '/'`, so 2..=5 bytes went; and every one of them was
            // a digit but the separator.
            assert!(
                (2..=5).contains(&k),
                "consumed prefix is not 1..=4 digits + '/'"
            );
            assert!(input[k - 1] == b'/', "consumed prefix does not end in '/'");
            let mut i = 0;
            while i < k - 1 {
                assert!(
                    input[i].is_ascii_digit(),
                    "consumed a non-digit as a period"
                );
                i += 1;
            }
        }
        // No numeric prefix → the whole input is the label, untouched.
        None => assert!(k == 0, "dropped a prefix without reporting a period"),
    }
    kani::cover!(period.is_some(), "a name that carries a period prefix");
}
