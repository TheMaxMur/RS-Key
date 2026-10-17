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
}

impl Stream for Fake {
    fn stop(&mut self) {
        self.stops += 1;
        self.remaining = 0;
    }
    fn available(&mut self) -> usize {
        if self.starts == 0 {
            return self.stale;
        }
        if self.invalid_available {
            return FIFO_WORDS + 1;
        }
        if self.delay != 0 {
            self.delay -= 1;
            return 0;
        }
        if !self.stall {
            while self.fifo.len() < FIFO_WORDS && self.remaining != 0 {
                self.fifo.push_back(self.address);
                self.address += WORD_BYTES as u32;
                self.remaining -= 1;
            }
            if self.remaining == 0 && self.fifo.is_empty() && self.extra {
                self.fifo.push_back(0xbad);
            }
        }
        self.fifo.len()
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
    for (stale, delay) in [(0, 0), (1, 0), (FIFO_WORDS, 0), (0, 3)] {
        for length in [4, 8, 12, 60] {
            let mut stream = Fake {
                stale,
                delay,
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
