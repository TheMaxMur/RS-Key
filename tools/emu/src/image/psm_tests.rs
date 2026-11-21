// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const SET: u32 = 2;
const CLR: u32 = 3;

#[test]
fn frce_off_proc1_holds_core1_and_its_release_is_counted() {
    let atomics = Arc::new(CoreAtomics::default());
    let mut p = Psm::new(atomics.clone());
    let mut ctx = MmioCtx::default();
    p.write(PSM_FRCE_OFF, PSM_PROC1, 4, SET, &mut ctx);
    assert!(p.core1_off);
    assert!(atomics.is_halted(1));
    assert_eq!(
        p.read(PSM_DONE, 4, &mut ctx) & PSM_PROC1,
        0,
        "not done while forced off"
    );
    p.write(PSM_FRCE_OFF, PSM_PROC1, 4, CLR, &mut ctx);
    assert!(!p.core1_off);
    assert_eq!(p.core1_released, 1);
    assert!(atomics.is_halted(1), "held until the chip resets it");
    assert_eq!(p.read(PSM_DONE, 4, &mut ctx), PSM_ALL);
}

#[test]
fn rewriting_the_same_state_is_not_a_release() {
    let atomics = Arc::new(CoreAtomics::default());
    let mut p = Psm::new(atomics);
    let mut ctx = MmioCtx::default();
    p.write(PSM_FRCE_OFF, 0, 4, 0, &mut ctx);
    p.write(PSM_FRCE_OFF, 1 << 3, 4, SET, &mut ctx);
    assert_eq!(p.core1_released, 0);
    assert!(!p.core1_off);
}
