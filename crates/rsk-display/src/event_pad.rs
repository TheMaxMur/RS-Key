// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::PanelSignal;
use crate::TouchPad;
use core::cell::Cell;
use std::collections::VecDeque;
use std::rc::Rc;

pub struct SignalAfterTouches {
    pub samples: VecDeque<Option<rsk_ui::Point>>,
    pub signal: Rc<Cell<PanelSignal>>,
    pub event: PanelSignal,
    pub sent: bool,
}

impl TouchPad for SignalAfterTouches {
    fn read(&mut self) -> Option<rsk_ui::Point> {
        if let Some(sample) = self.samples.pop_front() {
            return sample;
        }
        if !self.sent {
            self.sent = true;
            self.signal.set(self.event);
        }
        None
    }
}
