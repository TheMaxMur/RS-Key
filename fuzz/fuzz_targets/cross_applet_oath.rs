// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! OATH observations after the real CCID dispatcher has answered.

use super::{APPLETS, Apdu, INS_GET_RESPONSE, Sw, status};

const PUT: u8 = 0x01;
const DELETE: u8 = 0x02;
const SET_CODE: u8 = 0x03;
const RESET: u8 = 0x04;
const RENAME: u8 = 0x05;
const CALCULATE: u8 = 0xA2;
const VALIDATE: u8 = 0xA3;
const OATH_INDEX: usize = 3;
const NAME: u8 = 0x71;
const KEY: u8 = 0x73;
const PROPERTY: u8 = 0x78;

type Header = (u8, u8, u8, u8);

#[derive(Default)]
pub(super) struct OathOracle {
    selected: Option<usize>,
    code_set: bool,
    validated: bool,
    live: Vec<Vec<u8>>,
    chain: Option<(Header, Vec<u8>)>,
}

impl OathOracle {
    pub(super) fn reset_card(&mut self) {
        self.selected = None;
        self.validated = false;
        self.clear_chaining();
    }

    pub(super) fn clear_chaining(&mut self) {
        self.chain = None;
    }

    pub(super) fn factory_wipe(&mut self) {
        self.code_set = false;
        self.live.clear();
        // This target wipes Fs directly while the applets remain live: neither
        // the dispatcher's selection nor its buffered command was reset.
    }

    pub(super) fn observe(&mut self, raw: &[u8], res: &[u8], enabled: [bool; 8]) {
        let Ok(p) = Apdu::parse(raw) else { return };
        if res.is_empty() {
            return;
        }
        let sw = status(res);
        let select = p.ins == 0xA4 && p.p1 == 4 && matches!(p.p2, 0 | 4);
        let header = (p.cla & !0x10, p.ins, p.p1, p.p2);
        // A held response and the no-chain GET RESPONSE acknowledgement do
        // not execute an applet command or open a new command chain.
        if p.ins == INS_GET_RESPONSE && self.chain.is_none() {
            return;
        }
        if !p.is_chaining() && p.is_secure_messaging() && !select && sw == Sw::CLA_NOT_SUPPORTED {
            return;
        }
        if p.is_chaining() {
            if sw != Sw::OK {
                self.clear_chaining();
                return;
            }
            let (_, body) = self.chain.get_or_insert_with(|| (header, Vec::new()));
            body.extend_from_slice(p.data);
            return;
        }
        if select {
            self.clear_chaining();
            let found = APPLETS.iter().enumerate().position(|(i, (aid, _))| {
                enabled[i] && !p.data.is_empty() && aid.starts_with(p.data)
            });
            if let Some(i) = found {
                self.validated = i == OATH_INDEX
                    && (!self.code_set || (self.selected == Some(i) && self.validated));
                self.selected = Some(i);
            }
            return;
        }
        let data = if let Some((opener, mut body)) = self.chain.take() {
            if header != opener || body.len() + p.nc > rsk_sdk::applet::CHAIN_BUF_SIZE {
                return;
            }
            body.extend_from_slice(p.data);
            body
        } else {
            p.data.to_vec()
        };
        if self.selected != Some(OATH_INDEX) || !enabled[OATH_INDEX] {
            return;
        }
        self.command(p.ins, &data, sw);
    }

    fn command(&mut self, ins: u8, data: &[u8], sw: Sw) {
        let success = sw == Sw::OK || sw.to_bytes()[0] == 0x61;
        if self.code_set
            && !self.validated
            && matches!(ins, PUT | DELETE | SET_CODE | RENAME | CALCULATE)
        {
            assert!(
                !success,
                "OATH {ins:#04x} was served without a validated code"
            );
        }
        match ins {
            SET_CODE if success => {
                let removed = fields(data).any(|(tag, value)| tag == KEY && value.is_empty());
                self.code_set = !removed;
                self.validated = removed;
            }
            VALIDATE if success => self.validated = true,
            VALIDATE if sw == Sw::DATA_INVALID && self.code_set => self.validated = false,
            RESET if success => {
                self.factory_wipe();
                self.validated = true;
            }
            _ => {}
        }
        if !success {
            return;
        }
        let mut names = fields(data).filter_map(|(tag, value)| (tag == NAME).then_some(value));
        // DELETE uses the SDK's BER walker, without PUT/RENAME's bare PROPERTY.
        let name = if ins == DELETE {
            rsk_sdk::tlv::find_tag(data, u16::from(NAME))
        } else {
            names.next()
        };
        let Some(name) = name else { return };
        match ins {
            PUT => {
                if !self.live.iter().any(|held| held == name) {
                    self.live.push(name.to_vec());
                }
            }
            DELETE => self.live.retain(|held| held != name),
            RENAME => {
                let new_name = names.next().expect("successful RENAME has two names");
                let held = self
                    .live
                    .iter_mut()
                    .find(|held| held.as_slice() == name)
                    .expect("OATH RENAME served a credential no acknowledged PUT left live");
                *held = new_name.to_vec();
            }
            CALCULATE => assert!(
                self.live.iter().any(|held| held == name),
                "OATH CALCULATE served a credential no acknowledged PUT left live"
            ),
            _ => {}
        }
    }
}

// OATH accepts BER lengths and a bare PROPERTY byte in PUT/RENAME; the SDK's
// general TLV walker treats that byte as a length. Only observed fields matter.
fn fields(mut data: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    std::iter::from_fn(move || {
        let tag = *data.first()?;
        let (start, len) = if tag == PROPERTY {
            (1, 1)
        } else {
            match *data.get(1)? {
                0x81 => (3, *data.get(2)? as usize),
                0x82 => (
                    4,
                    u16::from_be_bytes([*data.get(2)?, *data.get(3)?]) as usize,
                ),
                len => (2, len as usize),
            }
        };
        let end = start + len;
        let value = data.get(start..end)?;
        data = data.get(end..)?;
        Some((tag, value))
    })
}

#[cfg(test)]
#[path = "cross_applet_oath_tests.rs"]
mod tests;
