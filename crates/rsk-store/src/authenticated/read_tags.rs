// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::Entry;
use super::authority::Bound;

const CACHED_PAYLOAD_TAGS: usize = 32;

#[derive(Clone, Copy)]
struct Tagged {
    entry: Entry,
    tag: [u8; 32],
}

pub(super) struct ReadTags {
    bound: Option<Bound>,
    mount: Option<[u8; 32]>,
    records: [Option<Tagged>; CACHED_PAYLOAD_TAGS],
    next: usize,
}

impl ReadTags {
    pub(super) const fn new() -> Self {
        Self {
            bound: None,
            mount: None,
            records: [None; CACHED_PAYLOAD_TAGS],
            next: 0,
        }
    }

    pub(super) fn clear(&mut self) {
        self.bound = None;
        self.mount = None;
        self.records.fill(None);
        self.next = 0;
    }

    pub(super) fn find(&self, bound: Bound, entry: Entry) -> Option<[u8; 32]> {
        if !self.bound.is_some_and(|cached| cached.same_context(bound)) {
            return None;
        }
        self.records
            .iter()
            .flatten()
            .find(|cached| cached.entry == entry)
            .map(|cached| cached.tag)
    }

    pub(super) fn mount_tag(&self, bound: Bound) -> Option<[u8; 32]> {
        self.bound
            .is_some_and(|cached| cached.same_context(bound))
            .then_some(self.mount)
            .flatten()
    }

    pub(super) fn bind(&mut self, bound: Bound, tag: [u8; 32]) {
        if !self.bound.is_some_and(|cached| cached.same_context(bound)) {
            self.clear();
            self.bound = Some(bound);
        }
        self.mount = Some(tag);
    }

    pub(super) fn insert(&mut self, bound: Bound, entry: Entry, tag: [u8; 32]) {
        if !self.bound.is_some_and(|cached| cached.same_context(bound)) {
            self.clear();
            self.bound = Some(bound);
        }
        if let Some(slot) = self.records.get_mut(self.next) {
            *slot = Some(Tagged { entry, tag });
        }
        self.next = (self.next + 1) % CACHED_PAYLOAD_TAGS;
    }
}
