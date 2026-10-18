// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

pub const GROUPS: usize = 4;
pub const WIDTH: usize = 4;
pub const ROUNDS: usize = 24;
pub const STRIDE: usize = GROUPS * ROUNDS;
pub const ENTRIES: usize = 1 << (WIDTH - 1);

const _: () = assert!(GROUPS * WIDTH * ROUNDS == 384 && WIDTH <= 8);
