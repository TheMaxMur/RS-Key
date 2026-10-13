// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Ownership of one copied request across transport resets and dropped futures.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Idle,
    Queued(u32),
    Running(u32),
    Reply(u32),
    DiscardQueued(u32),
    DiscardRunning(u32),
    DiscardReply(u32),
    Resetting,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Job {
    Dispatch(u32),
    Discard(u32),
    Reset,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Poll {
    Pending,
    Ready,
    Abandoned,
}

pub struct Session {
    state: State,
    next_ticket: u32,
    reset_pending: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub const fn new() -> Self {
        Self {
            state: State::Idle,
            next_ticket: 1,
            reset_pending: false,
        }
    }

    pub fn submit(&mut self) -> Option<u32> {
        if self.state != State::Idle || self.reset_pending || self.next_ticket >= u32::MAX - 2 {
            return None;
        }
        let ticket = self.next_ticket;
        self.next_ticket += 1;
        self.state = State::Queued(ticket);
        Some(ticket)
    }

    pub fn next_job(&mut self) -> Option<Job> {
        match self.state {
            State::Queued(ticket) => {
                self.state = State::Running(ticket);
                Some(Job::Dispatch(ticket))
            }
            State::DiscardQueued(ticket) | State::DiscardReply(ticket) => {
                Some(Job::Discard(ticket))
            }
            State::Idle if self.reset_pending => {
                self.reset_pending = false;
                self.state = State::Resetting;
                Some(Job::Reset)
            }
            _ => None,
        }
    }

    pub fn finish(&mut self, ticket: u32) -> bool {
        match self.state {
            State::Running(id) if id == ticket => {
                self.state = State::Reply(ticket);
                true
            }
            State::DiscardRunning(id) if id == ticket => {
                self.state = State::DiscardReply(ticket);
                false
            }
            _ => false,
        }
    }

    pub fn poll(&self, ticket: u32) -> Poll {
        match self.state {
            State::Queued(id) | State::Running(id) if id == ticket => Poll::Pending,
            State::Reply(id) if id == ticket => Poll::Ready,
            _ => Poll::Abandoned,
        }
    }

    pub fn release(&mut self, ticket: u32) -> bool {
        match self.state {
            State::Reply(id) | State::DiscardQueued(id) | State::DiscardReply(id)
                if id == ticket =>
            {
                self.state = State::Idle;
                true
            }
            _ => false,
        }
    }

    pub fn abandon(&mut self, ticket: u32) {
        self.state = match self.state {
            State::Queued(id) if id == ticket => State::DiscardQueued(id),
            State::Running(id) if id == ticket => State::DiscardRunning(id),
            State::Reply(id) if id == ticket => State::DiscardReply(id),
            state => state,
        };
    }

    pub fn reset(&mut self) {
        self.reset_pending = true;
        self.state = match self.state {
            State::Queued(id) => State::DiscardQueued(id),
            State::Running(id) => State::DiscardRunning(id),
            State::Reply(id) => State::DiscardReply(id),
            state => state,
        };
    }

    pub fn reset_complete(&mut self) {
        if self.state == State::Resetting {
            self.state = State::Idle;
        }
    }
}

#[cfg(test)]
#[path = "transport_session_tests.rs"]
mod tests;

#[cfg(kani)]
#[path = "transport_session_kani.rs"]
mod proofs;
