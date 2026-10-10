// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Io {
    Read,
    Program,
    Erase,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Refuse,
    Drop,
    KeepTail,
}
#[derive(Clone, Copy, Debug)]
pub struct Rule {
    pub io: Io,
    pub skip: usize,
    pub effect: Effect,
    pub latched: bool,
}

struct Armed {
    rule: Rule,
    remaining: usize,
    hits: usize,
}
struct ReadImage {
    remaining: usize,
    bytes: Vec<u8>,
}
#[derive(Clone)]
pub struct FaultFlash {
    pub inner: SharedMock,
    rules: Rc<RefCell<Vec<Armed>>>,
    events: Rc<RefCell<Vec<(Io, u32, usize)>>>,
    read_image: Rc<RefCell<Option<ReadImage>>>,
}

impl FaultFlash {
    pub fn new() -> Self {
        Self {
            inner: SharedMock::new(),
            rules: Rc::new(RefCell::new(Vec::new())),
            events: Rc::new(RefCell::new(Vec::new())),
            read_image: Rc::new(RefCell::new(None)),
        }
    }
    pub fn arm(&self, rules: &[Rule]) {
        *self.rules.borrow_mut() = rules
            .iter()
            .map(|&rule| {
                assert!(rule.io != Io::Read || rule.effect == Effect::Refuse);
                Armed {
                    remaining: rule.skip,
                    rule,
                    hits: 0,
                }
            })
            .collect();
        self.events.borrow_mut().clear();
    }
    pub fn clear(&self) {
        self.rules.borrow_mut().clear();
    }
    pub fn events(&self) -> Vec<(Io, u32, usize)> {
        self.events.borrow().clone()
    }
    pub fn hits(&self) -> Vec<usize> {
        self.rules.borrow().iter().map(|rule| rule.hits).collect()
    }
    pub fn replace_image_before_read(&self, skip: usize, image: Vec<u8>) {
        *self.read_image.borrow_mut() = Some(ReadImage {
            remaining: skip,
            bytes: image,
        });
    }
    fn effect(&self, io: Io, address: u32, len: usize) -> Option<Effect> {
        self.events.borrow_mut().push((io, address, len));
        let mut result = None;
        for armed in self.rules.borrow_mut().iter_mut() {
            if armed.rule.io != io || (!armed.rule.latched && armed.hits > 0) {
                continue;
            }
            if armed.remaining > 0 {
                armed.remaining -= 1;
                continue;
            }
            armed.hits += 1;
            result = Some(armed.rule.effect);
        }
        result
    }
}

impl ErrorType for FaultFlash {
    type Error = FlashFault;
}
impl ReadNorFlash for FaultFlash {
    const READ_SIZE: usize = SharedMock::READ_SIZE;
    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result2<()> {
        if self.effect(Io::Read, offset, bytes.len()).is_some() {
            return Err(FlashFault);
        }
        let image = self.read_image.borrow_mut().take();
        if let Some(mut image) = image {
            if image.remaining == 0 {
                *self.inner.bytes.borrow_mut() = image.bytes;
            } else {
                image.remaining -= 1;
                *self.read_image.borrow_mut() = Some(image);
            }
        }
        self.inner.read(offset, bytes).await
    }
    fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}
impl NorFlash for FaultFlash {
    const WRITE_SIZE: usize = SharedMock::WRITE_SIZE;
    const ERASE_SIZE: usize = SharedMock::ERASE_SIZE;
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result2<()> {
        match self.effect(Io::Program, offset, bytes.len()) {
            Some(Effect::Refuse) => Err(FlashFault),
            Some(Effect::Drop) => Ok(()),
            Some(Effect::KeepTail) => {
                self.inner
                    .write(
                        offset,
                        bytes.get(..bytes.len().saturating_sub(WORD)).unwrap(),
                    )
                    .await
            }
            None => self.inner.write(offset, bytes).await,
        }
    }
    async fn erase(&mut self, from: u32, to: u32) -> Result2<()> {
        match self.effect(Io::Erase, from, (to - from) as usize) {
            Some(Effect::Refuse) => Err(FlashFault),
            Some(Effect::Drop) => Ok(()),
            Some(Effect::KeepTail) => {
                self.inner.bytes.borrow_mut()[from as usize..(to as usize).saturating_sub(WORD)]
                    .fill(0xFF);
                Ok(())
            }
            None => self.inner.erase(from, to).await,
        }
    }
}
impl MultiwriteNorFlash for FaultFlash {}
