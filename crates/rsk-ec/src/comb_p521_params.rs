// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

pub const BITS: usize = 521;
pub const WIDTH: usize = 4;
pub const GROUPS: usize = 4;
pub const ROUNDS: usize = BITS.div_ceil(WIDTH * GROUPS);
pub const STRIDE: usize = GROUPS * ROUNDS;
pub const ENTRIES: usize = 1 << (WIDTH - 1);
