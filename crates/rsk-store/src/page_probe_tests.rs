// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::FlashFault;
use core::cell::RefCell;
use embedded_storage_async::nor_flash::{ErrorType, ReadNorFlash};
use sequential_storage::cache::Cache;
use std::{rc::Rc, vec, vec::Vec};

const PAGE: usize = 128;

struct Medium {
    bytes: Vec<u8>,
    range: Range<u32>,
    reads: Vec<(u32, usize)>,
    fail: Option<usize>,
    change: Option<(usize, usize, u8)>,
}

#[derive(Clone)]
struct Probe<const R: usize>(Rc<RefCell<Medium>>);

impl<const R: usize> Probe<R> {
    fn new(states: &[u8]) -> Self {
        let range = PAGE as u32..((states.len() + 1) * PAGE) as u32;
        let mut bytes = vec![0xff; (states.len() + 2) * PAGE];
        for (page, state) in states.iter().enumerate() {
            if matches!(state, 1 | 2) {
                bytes[(page + 1) * PAGE] = 0xf0;
            }
            if matches!(state, 2 | 3) {
                bytes[(page + 2) * PAGE - R] = 0xf0;
            }
        }
        Self(Rc::new(RefCell::new(Medium {
            bytes,
            range,
            reads: Vec::new(),
            fail: None,
            change: None,
        })))
    }

    fn check(&self) -> core::result::Result<bool, sequential_storage::Error<FlashFault>> {
        let config = MapConfig::new(self.0.borrow().range.clone());
        let mut map = MapStorage::<u16, _, _>::new(self.clone(), config, Cache::new_uncached());
        block_on(map.needs_repair())
    }
}

impl<const R: usize> ErrorType for Probe<R> {
    type Error = FlashFault;
}
impl<const R: usize> ReadNorFlash for Probe<R> {
    const READ_SIZE: usize = R;
    async fn read(&mut self, at: u32, out: &mut [u8]) -> core::result::Result<(), FlashFault> {
        let mut medium = self.0.borrow_mut();
        assert!(at >= medium.range.start && at as usize + out.len() <= medium.range.end as usize);
        assert!(at.is_multiple_of(R as u32) && out.len().is_multiple_of(R));
        let call = medium.reads.len();
        medium.reads.push((at, out.len()));
        if medium.fail == Some(call) {
            return Err(FlashFault);
        }
        if let Some((trigger, index, value)) = medium.change
            && call == trigger
        {
            medium.bytes[index] = value;
        }
        out.copy_from_slice(&medium.bytes[at as usize..at as usize + out.len()]);
        Ok(())
    }
    fn capacity(&self) -> usize {
        self.0.borrow().bytes.len()
    }
}
impl<const R: usize> NorFlash for Probe<R> {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = PAGE;
    async fn write(&mut self, _: u32, _: &[u8]) -> core::result::Result<(), FlashFault> {
        panic!("a repair probe must not program flash")
    }
    async fn erase(&mut self, _: u32, _: u32) -> core::result::Result<(), FlashFault> {
        panic!("a repair probe must not erase flash")
    }
}

fn combinations<const R: usize>() {
    for pages in 2..=5 {
        for mut code in 0..4usize.pow(pages) {
            let states: Vec<_> = (0..pages)
                .map(|_| {
                    let s = (code % 4) as u8;
                    code /= 4;
                    s
                })
                .collect();
            let expected = states
                .iter()
                .enumerate()
                .any(|(i, &s)| s == 3 || (s == 1 && states[(i + 1) % states.len()] != 0));
            assert_eq!(
                Probe::<R>::new(&states).check().unwrap(),
                expected,
                "{states:?}, read {R}"
            );
        }
    }
}

#[test]
fn every_page_state_combination_matches_the_ring_repair_rule() {
    combinations::<1>();
    combinations::<4>();
    combinations::<32>();
}

#[test]
fn healthy_sweeps_read_every_marker_with_one_boundary_call_per_page() {
    for states in [[0; 5], [2; 5]] {
        let probe = Probe::<1>::new(&states);
        assert!(!probe.check().unwrap());
        let medium = probe.0.borrow();
        assert_eq!(medium.reads.len(), states.len() + 1);
        assert_eq!(
            medium.reads.iter().map(|(_, n)| n).sum::<usize>(),
            2 * states.len()
        );
        assert_eq!(medium.reads.first(), Some(&(PAGE as u32, 1)));
        assert_eq!(medium.reads.last(), Some(&((6 * PAGE - 1) as u32, 1)));
    }
}

#[test]
fn every_boundary_read_error_is_propagated() {
    for call in 0..=5 {
        let probe = Probe::<1>::new(&[2; 5]);
        probe.0.borrow_mut().fail = Some(call);
        assert!(matches!(
            probe.check(),
            Err(sequential_storage::Error::Storage { value: FlashFault })
        ));
        assert_eq!(probe.0.borrow().reads.len(), call + 1);
    }
}

#[test]
fn a_partial_last_page_checks_the_first_page_again_after_the_sweep() {
    let probe = Probe::<1>::new(&[0, 2, 1]);
    probe.0.borrow_mut().change = Some((3, PAGE, 0xf0));
    assert!(probe.check().unwrap());
}

#[test]
fn a_lookahead_successor_is_read_fresh_when_it_is_visited() {
    let probe = Probe::<1>::new(&[1, 0, 2]);
    probe.0.borrow_mut().change = Some((4, 2 * PAGE, 0xf0));
    assert!(probe.check().unwrap());
}

#[test]
fn marker_threshold_counts_bits_across_the_complete_read_word() {
    for zeros in 0..=4 {
        let probe = Probe::<32>::new(&[0, 0]);
        for index in 0..zeros {
            probe.0.borrow_mut().bytes[2 * PAGE - 32 + index] = 0xfe;
        }
        assert_eq!(probe.check().unwrap(), zeros == 4);
    }
}

#[test]
fn lookahead_refresh_and_wrap_read_errors_are_propagated() {
    for (states, calls) in [([1, 0, 2], 7), ([0, 2, 1], 6)] {
        let healthy = Probe::<1>::new(&states);
        assert!(!healthy.check().unwrap());
        assert_eq!(healthy.0.borrow().reads.len(), calls);
        for call in 0..calls {
            let probe = Probe::<1>::new(&states);
            probe.0.borrow_mut().fail = Some(call);
            assert!(
                matches!(
                    probe.check(),
                    Err(sequential_storage::Error::Storage { value: FlashFault })
                ),
                "{states:?} read {call}"
            );
            assert_eq!(probe.0.borrow().reads.len(), call + 1);
        }
    }
}
