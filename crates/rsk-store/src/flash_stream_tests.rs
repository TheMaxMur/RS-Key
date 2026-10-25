// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::collections::VecDeque;

#[derive(Default)]
struct Fake {
    address: u32,
    remaining: u32,
    fifo: VecDeque<u32>,
    stale: usize,
    stops: usize,
    starts: usize,
    polls: usize,
    delay: usize,
    stall: bool,
    bad_count: bool,
    bad_address: bool,
    extra: bool,
    invalid_available: bool,
    single_word: bool,
    fill: Option<u32>,
    damage: Option<(u32, u32)>,
    reads: usize,
    flags: Option<(bool, bool)>,
}

impl Stream for Fake {
    fn stop(&mut self) {
        self.stops += 1;
        self.remaining = 0;
    }
    fn readable(&mut self) -> Result<bool, Error> {
        if self.starts == 0 {
            return fifo_readable(
                self.stale == 0 || self.stale > FIFO_WORDS,
                self.stale >= FIFO_WORDS,
            );
        }
        if self.invalid_available {
            return fifo_readable(true, true);
        }
        if self.delay != 0 {
            self.delay -= 1;
            return fifo_readable(true, false);
        }
        if !self.stall {
            let capacity = if self.single_word { 1 } else { FIFO_WORDS };
            while self.fifo.len() < capacity && self.remaining != 0 {
                let word = if let Some((at, value)) = self.damage {
                    if self.address == at {
                        value
                    } else {
                        self.fill.unwrap_or(self.address)
                    }
                } else {
                    self.fill.unwrap_or(self.address)
                };
                self.fifo.push_back(word);
                self.address += WORD_BYTES as u32;
                self.remaining -= 1;
            }
            if self.remaining == 0 && self.fifo.is_empty() && self.extra {
                self.fifo.push_back(0xbad);
            }
        }
        let (empty, full) = self
            .flags
            .take()
            .unwrap_or((self.fifo.is_empty(), self.fifo.len() == FIFO_WORDS));
        fifo_readable(empty, full)
    }
    fn start(&mut self, offset: u32, words: u32) {
        self.starts += 1;
        self.address = offset;
        self.remaining = words;
    }
    fn read_word(&mut self) -> u32 {
        if self.starts == 0 {
            self.stale -= 1;
            return 0xbad;
        }
        self.reads += 1;
        self.fifo.pop_front().expect("driver read an empty FIFO")
    }
    fn remaining(&mut self) -> u32 {
        self.remaining + u32::from(self.bad_count)
    }
    fn address(&mut self) -> u32 {
        self.address + u32::from(self.bad_address)
    }
    fn expired(&mut self) -> bool {
        self.polls += 1;
        self.polls > 32
    }
}

#[test]
fn reads_words_in_order_drains_stale_fifo_and_preserves_output_guards() {
    for (stale, delay, single_word) in [
        (0, 0, false),
        (1, 0, false),
        (FIFO_WORDS, 0, false),
        (0, 3, false),
        (0, 0, true),
        (1, 3, true),
    ] {
        for length in [4, 8, 12, 60] {
            let mut stream = Fake {
                stale,
                delay,
                single_word,
                ..Fake::default()
            };
            let mut out = [0x5a; 64];
            assert_eq!(
                read(&mut stream, 1024, 256, &mut out[1..1 + length]),
                Ok(())
            );
            for (i, word) in out[1..1 + length].chunks_exact(WORD_BYTES).enumerate() {
                assert_eq!(word, (256 + i as u32 * WORD_BYTES as u32).to_le_bytes());
            }
            assert_eq!(out[0], 0x5a);
            assert!(out[1 + length..].iter().all(|byte| *byte == 0x5a));
            assert_eq!((stream.stops, stream.starts), (2, 1));
        }
    }
}

#[test]
fn every_captured_status_runs_through_the_checked_transfer() {
    for flags in [(true, false), (false, false), (false, true), (true, true)] {
        let mut stream = Fake {
            flags: Some(flags),
            ..Fake::default()
        };
        let mut out = [0x5a; 10];
        let result = read(&mut stream, 64, 4, &mut out[1..9]);
        if flags == (true, true) {
            assert_eq!(result, Err(Error::Transfer));
            assert_eq!(out, [0x5a; 10]);
        } else {
            assert_eq!(result, Ok(()));
            assert_eq!(&out[1..5], &4_u32.to_le_bytes());
            assert_eq!(&out[5..9], &8_u32.to_le_bytes());
            assert_eq!(out[0], 0x5a);
            assert_eq!(out[9], 0x5a);
        }
        assert_eq!((stream.stops, stream.starts), (2, 1));
        assert_eq!(stream.remaining, 0);
    }
}

#[test]
fn byte_reads_bound_the_offset_before_the_hardware_callback() {
    for offset in [0, 1, 63] {
        let mut calls = 0;
        assert_eq!(
            read_byte(64, offset, |actual| {
                calls += 1;
                assert_eq!(actual, offset);
                0x7b
            }),
            Ok(0x7b)
        );
        assert_eq!(calls, 1);
    }
    for (capacity, offset) in [(0, 0), (64, 64), (64, u32::MAX)] {
        let mut calls = 0;
        assert_eq!(
            read_byte(capacity, offset, |_| {
                calls += 1;
                0x7b
            }),
            Err(Error::OutOfBounds)
        );
        assert_eq!(calls, 0);
    }
}

#[test]
fn refuses_bounds_alignment_and_oversized_transfers_before_io() {
    let mut stream = Fake::default();
    for (capacity, offset, length, error) in [
        (64, 1, 4, Error::Unaligned),
        (64, 0, 3, Error::Unaligned),
        (64, 64, 4, Error::OutOfBounds),
        (usize::MAX, u32::MAX - 3, 4, Error::OutOfBounds),
    ] {
        assert_eq!(
            read(&mut stream, capacity, offset, &mut [0; 4][..length]),
            Err(error)
        );
    }
    let mut oversized = vec![0; (MAX_WORDS + 1) * WORD_BYTES];
    assert_eq!(
        read(&mut stream, oversized.len(), 0, &mut oversized),
        Err(Error::Unaligned)
    );
    assert_eq!(read(&mut stream, 64, 64, &mut []), Ok(()));
    assert_eq!((stream.stops, stream.starts), (0, 0));

    let mut maximum = vec![0; MAX_WORDS * WORD_BYTES];
    assert_eq!(read(&mut stream, maximum.len(), 0, &mut maximum), Ok(()));
    assert_eq!((stream.stops, stream.starts), (2, 1));
    assert_eq!(&maximum[..4], &0_u32.to_le_bytes());
    assert_eq!(
        &maximum[maximum.len() - 4..],
        &((MAX_WORDS as u32 - 1) * WORD_BYTES as u32).to_le_bytes()
    );
}

#[test]
fn stops_after_stall_stale_overflow_invalid_fill_and_wrong_final_progress() {
    for mut stream in [
        Fake {
            stall: true,
            ..Fake::default()
        },
        Fake {
            stale: FIFO_WORDS + 1,
            ..Fake::default()
        },
        Fake {
            bad_count: true,
            ..Fake::default()
        },
        Fake {
            bad_address: true,
            ..Fake::default()
        },
        Fake {
            extra: true,
            ..Fake::default()
        },
        Fake {
            invalid_available: true,
            ..Fake::default()
        },
    ] {
        assert_eq!(read(&mut stream, 64, 4, &mut [0; 16]), Err(Error::Transfer));
        assert_eq!(stream.stops, 2);
        assert_eq!(stream.remaining, 0);
    }
}

#[test]
fn byte_pairs_check_both_bounds_before_either_callback() {
    for (capacity, offset) in [(0, 0), (1, 0), (8, 7), (8, 8), (usize::MAX, u32::MAX)] {
        let mut calls = 0;
        assert_eq!(
            read_pair(capacity, offset, |_| {
                calls += 1;
                0
            }),
            Err(Error::OutOfBounds)
        );
        assert_eq!(calls, 0);
    }
    for (capacity, offset) in [(2, 0), (8, 1), (8, 6)] {
        let mut calls = std::vec::Vec::new();
        assert_eq!(
            read_pair(capacity, offset, |at| {
                calls.push(at);
                (at & 0xff) as u8
            }),
            Ok([offset as u8, (offset + 1) as u8])
        );
        assert_eq!(calls, [offset, offset + 1]);
    }
}

#[test]
fn erased_stream_checks_every_word_and_every_bit_before_accepting() {
    for length in [4, 8, 60, 4096] {
        let mut flash = Fake {
            fill: Some(u32::MAX),
            ..Fake::default()
        };
        assert_eq!(read_erased(&mut flash, 8192, 256, length), Ok(true));
        assert_eq!(flash.reads, length / WORD_BYTES);
        assert_eq!((flash.stops, flash.starts), (2, 1));
        for index in 0..length / WORD_BYTES {
            for bit in 0..32 {
                let mut flash = Fake {
                    fill: Some(u32::MAX),
                    damage: Some((
                        256 + index as u32 * WORD_BYTES as u32,
                        u32::MAX ^ (1 << bit),
                    )),
                    ..Fake::default()
                };
                assert_eq!(read_erased(&mut flash, 8192, 256, length), Ok(false));
                assert_eq!(flash.reads, length / WORD_BYTES);
                assert_eq!((flash.stops, flash.starts), (2, 1));
            }
        }
    }
}

#[test]
fn erased_stream_preserves_transfer_faults_even_when_every_word_is_erased() {
    for mut flash in [
        Fake {
            stall: true,
            ..Fake::default()
        },
        Fake {
            stale: FIFO_WORDS + 1,
            ..Fake::default()
        },
        Fake {
            bad_count: true,
            ..Fake::default()
        },
        Fake {
            bad_address: true,
            ..Fake::default()
        },
        Fake {
            extra: true,
            ..Fake::default()
        },
        Fake {
            invalid_available: true,
            ..Fake::default()
        },
    ] {
        flash.fill = Some(u32::MAX);
        assert_eq!(read_erased(&mut flash, 64, 4, 16), Err(Error::Transfer));
        assert_eq!(
            (flash.stops, flash.starts),
            (2, usize::from(flash.stale == 0))
        );
    }
    for (stale, delay, single_word) in [(1, 3, false), (FIFO_WORDS, 0, false), (0, 0, true)] {
        let mut flash = Fake {
            stale,
            delay,
            single_word,
            fill: Some(u32::MAX),
            ..Fake::default()
        };
        assert_eq!(read_erased(&mut flash, 64, 4, 16), Ok(true));
        assert_eq!(flash.reads, 4);
        assert_eq!((flash.stops, flash.starts), (2, 1));
    }
}

#[test]
fn erased_stream_refuses_invalid_ranges_before_touching_flash() {
    for (capacity, offset, length, error) in [
        (64, 1, 4, Error::Unaligned),
        (64, 0, 3, Error::Unaligned),
        (64, 64, 4, Error::OutOfBounds),
        (usize::MAX, u32::MAX - 3, 4, Error::OutOfBounds),
        (
            usize::MAX,
            0,
            (MAX_WORDS + 1) * WORD_BYTES,
            Error::Unaligned,
        ),
    ] {
        let mut flash = Fake::default();
        assert_eq!(
            read_erased(&mut flash, capacity, offset, length),
            Err(error)
        );
        assert_eq!((flash.stops, flash.starts, flash.reads), (0, 0, 0));
    }
    let mut flash = Fake::default();
    assert_eq!(read_erased(&mut flash, 64, 64, 0), Ok(true));
    assert_eq!((flash.stops, flash.starts, flash.reads), (0, 0, 0));
}
