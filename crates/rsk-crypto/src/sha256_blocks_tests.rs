// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[derive(Default)]
struct Capture {
    bytes: std::vec::Vec<u8>,
    calls: usize,
    refuse: Option<usize>,
}
impl Sha256Compression for Capture {
    fn compress(&mut self, block: &[u8; 64]) -> bool {
        let accepted = self.refuse != Some(self.calls);
        self.calls += 1;
        if accepted {
            self.bytes.extend_from_slice(block);
        }
        accepted
    }
}

#[test]
fn fragmented_inputs_emit_exact_standard_padding_at_every_block_boundary() {
    for length in [
        0usize, 1, 3, 13, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 1024,
    ] {
        let input: std::vec::Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
        let padded_len = (length + 9).div_ceil(64) * 64;
        let mut expected = std::vec![0; padded_len];
        expected[..length].copy_from_slice(&input);
        expected[length] = 0x80;
        expected[padded_len - 8..].copy_from_slice(&(length as u64 * 8).to_be_bytes());
        for chunk in [1, 3, 4, 13, 55, 64, 65, 256] {
            let mut frame = Sha256Blocks::default();
            let mut actual = Capture::default();
            for bytes in input.chunks(chunk) {
                assert!(frame.update(bytes, &mut actual));
                assert!(frame.update(&[], &mut actual));
            }
            assert!(frame.finish(&mut actual));
            assert_eq!(actual.bytes, expected, "length={length} chunk={chunk}");
        }
    }
}

#[test]
fn refused_compression_stops_before_another_block_or_padding_is_emitted() {
    for length in [0, 55, 56, 64, 65, 128, 1024] {
        let input = std::vec![1; length];
        for refused in 0..(length + 9).div_ceil(64) {
            let mut frame = Sha256Blocks::default();
            let mut sink = Capture {
                refuse: Some(refused),
                ..Capture::default()
            };
            let accepted = frame.update(&input, &mut sink) && frame.finish(&mut sink);
            assert!(!accepted, "length={length} refused={refused}");
            assert_eq!(sink.calls, refused + 1);
        }
    }
}

#[test]
fn a_refused_buffered_block_stops_before_direct_blocks() {
    let mut frame = Sha256Blocks::default();
    let mut sink = Capture {
        refuse: Some(0),
        ..Capture::default()
    };
    assert!(frame.update(&[7; 13], &mut sink));
    assert!(!frame.update(&[9; 256], &mut sink));
    assert_eq!(sink.calls, 1);
    assert!(sink.bytes.is_empty());
}
