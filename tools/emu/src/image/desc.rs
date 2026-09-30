// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The image's descriptors read the way a host reads them: the configuration's
//! interfaces and endpoints, and which HID interface is the FIDO one — by its
//! report descriptor's usage page, as hidapi finds it, not by its position.

use super::hc::{Endpoint, Kind};

const DESC_CONFIG: u8 = 0x02;
const DESC_INTERFACE: u8 = 0x04;
const DESC_ENDPOINT: u8 = 0x05;
const DESC_IAD: u8 = 0x0B;
const DESC_HID: u8 = 0x21;
const CLASS_HID: u8 = 0x03;
const CLASS_CCID: u8 = 0x0B;
const DEVICE_DESC_LEN: usize = 18;
/// Usage Page (FIDO Alliance), the first item of a CTAPHID report descriptor.
const FIDO_USAGE_PAGE: [u8; 3] = [0x06, 0xD0, 0xF1];
const EP_DIR_IN: u8 = 0x80;
const EP_TYPE_BULK: u8 = 2;
const EP_TYPE_INTERRUPT: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointDesc {
    pub address: u8,
    pub attributes: u8,
    pub mps: u16,
    pub interval: u8,
}

impl EndpointDesc {
    fn is(&self, dir_in: bool, kind: u8) -> bool {
        (self.address & EP_DIR_IN != 0) == dir_in && self.attributes & 3 == kind
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub number: u8,
    /// Class, subclass, protocol.
    pub class: [u8; 3],
    pub endpoints: Vec<EndpointDesc>,
    /// A HID interface's report descriptor length, from its HID descriptor.
    pub report_len: Option<u16>,
}

impl Interface {
    pub fn is_hid(&self) -> bool {
        self.class[0] == CLASS_HID
    }

    fn endpoint(&self, dir_in: bool, kind: u8) -> Option<u8> {
        self.endpoints
            .iter()
            .find(|e| e.is(dir_in, kind))
            .map(|e| e.address & 0x0F)
    }

    /// Interrupt IN and OUT endpoint numbers.
    pub fn interrupt_pair(&self) -> Option<(u8, u8)> {
        Some((
            self.endpoint(true, EP_TYPE_INTERRUPT)?,
            self.endpoint(false, EP_TYPE_INTERRUPT)?,
        ))
    }
}

/// The device as the host configured it.
#[derive(Clone, Debug)]
pub struct Device {
    pub descriptor: Vec<u8>,
    pub config: Vec<u8>,
    pub interfaces: Vec<Interface>,
    /// The FIDO HID interface's interrupt IN and OUT endpoints.
    pub fido: Option<(u8, u8)>,
}

impl Device {
    pub fn new(descriptor: Vec<u8>, config: Vec<u8>) -> Result<Self, String> {
        if descriptor.len() != DEVICE_DESC_LEN || descriptor[1] != 1 {
            return Err(format!("device descriptor {descriptor:02x?}"));
        }
        let interfaces = parse_config(&config)?;
        Ok(Self {
            descriptor,
            config,
            interfaces,
            fido: None,
        })
    }

    fn word(&self, offset: usize) -> u16 {
        u16::from_le_bytes([self.descriptor[offset], self.descriptor[offset + 1]])
    }

    pub fn vid(&self) -> u16 {
        self.word(8)
    }

    pub fn pid(&self) -> u16 {
        self.word(10)
    }

    pub fn bcd(&self) -> u16 {
        self.word(12)
    }

    /// bDeviceClass, bDeviceSubClass, bDeviceProtocol.
    pub fn class(&self) -> [u8; 3] {
        [self.descriptor[4], self.descriptor[5], self.descriptor[6]]
    }

    pub fn configuration_value(&self) -> u8 {
        self.config[5]
    }

    /// The CCID interface's bulk OUT and bulk IN endpoints.
    pub fn ccid(&self) -> Option<(u8, u8)> {
        let i = self.interfaces.iter().find(|i| i.class[0] == CLASS_CCID)?;
        Some((
            i.endpoint(false, EP_TYPE_BULK)?,
            i.endpoint(true, EP_TYPE_BULK)?,
        ))
    }

    /// Every endpoint but EP0, keyed as the host controller keys its pipes.
    pub fn endpoints(&self) -> Vec<((u8, bool), Endpoint)> {
        let mut out = Vec::new();
        for i in &self.interfaces {
            for e in &i.endpoints {
                let kind = match e.attributes & 3 {
                    EP_TYPE_INTERRUPT => Kind::Interrupt,
                    _ => Kind::Bulk,
                };
                let ep = Endpoint {
                    kind,
                    mps: usize::from(e.mps & 0x7FF),
                    interval: e.interval.max(1),
                    interface: i.number,
                };
                out.push(((e.address & 0x0F, e.address & EP_DIR_IN != 0), ep));
            }
        }
        out
    }
}

pub fn is_fido_report(report: &[u8]) -> bool {
    report.starts_with(&FIDO_USAGE_PAGE)
}

/// Walk a whole configuration descriptor into its interfaces.
pub fn parse_config(d: &[u8]) -> Result<Vec<Interface>, String> {
    if d.len() < 9 || d[1] != DESC_CONFIG {
        return Err(format!("not a configuration descriptor: {d:02x?}"));
    }
    let mut ifaces: Vec<Interface> = Vec::new();
    let mut i = 0;
    while i < d.len() {
        let len = usize::from(d[i]);
        if len < 2 || i + len > d.len() {
            return Err(format!("descriptor at {i} has bLength {len}"));
        }
        let x = &d[i..i + len];
        match x[1] {
            DESC_CONFIG | DESC_IAD => {}
            DESC_INTERFACE if len >= 9 => ifaces.push(Interface {
                number: x[2],
                class: [x[5], x[6], x[7]],
                endpoints: Vec::new(),
                report_len: None,
            }),
            DESC_ENDPOINT if len >= 7 => {
                let it = ifaces
                    .last_mut()
                    .ok_or("an endpoint before any interface")?;
                it.endpoints.push(EndpointDesc {
                    address: x[2],
                    attributes: x[3],
                    mps: u16::from_le_bytes([x[4], x[5]]),
                    interval: x[6],
                });
            }
            DESC_HID => {
                let it = ifaces
                    .last_mut()
                    .ok_or("a class descriptor before any interface")?;
                if it.is_hid() && len >= 9 {
                    it.report_len = Some(u16::from_le_bytes([x[7], x[8]]));
                }
            }
            t => return Err(format!("unexpected descriptor type {t:#04x} at {i}")),
        }
        i += len;
    }
    Ok(ifaces)
}

#[cfg(test)]
#[path = "desc_tests.rs"]
mod tests;
