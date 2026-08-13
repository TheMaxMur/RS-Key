// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `bDescriptorType` of an interface descriptor.
const DT_INTERFACE: u8 = 0x04;

/// Build the config descriptor the way [`serve`] does and hand back the bytes.
///
/// Everything borrows the buffer, so the whole device is built and dropped inside
/// this function; what comes out is what a host would read.
fn config_descriptor() -> Vec<u8> {
    let mut config_desc = [0u8; CONFIG_DESC_LEN];
    let mut bos = [0u8; BOS_DESC_LEN];
    let mut msos = [0u8; MSOS_DESC_LEN];
    let mut control = [0u8; CONTROL_BUF_LEN];
    let mut kbd_state = HidState::new();
    let mut fido_state = HidState::new();
    let (jobs, _rx) = crate::device::job_queue();
    let used = {
        let (driver, _port) = crate::usbip_driver::new();
        let mut builder = Builder::new(
            driver,
            usb_config(false),
            &mut config_desc,
            &mut bos,
            &mut msos,
            &mut control,
        );
        let classes = declare(
            &mut builder,
            &mut kbd_state,
            &mut fido_state,
            None,
            &jobs,
            rsk_usb::ccid::ATR_RSKEY,
        );
        let usb = builder.build();
        let used = usb.buffer_usage().config_descriptor_used;
        drop(usb);
        drop(classes);
        used
    };
    config_desc[..used].to_vec()
}

/// One interface as the config descriptor declares it.
#[derive(Debug, PartialEq, Eq)]
struct Iface {
    triple: [u8; 3],
    /// `wDescriptorLength` from the HID class descriptor, for a HID interface.
    hid_report_len: Option<usize>,
    endpoints: Vec<u8>,
}

/// Walk the config descriptor once and pull out every interface, in order.
///
/// The walk is class-aware because descriptor type `0x21` is both HID's class
/// descriptor and CCID's functional one — reading it blind would count the card
/// reader as a third HID.
fn interfaces_in(desc: &[u8]) -> Vec<Iface> {
    const DT_HID: u8 = 0x21;
    const DT_ENDPOINT: u8 = 0x05;
    let mut out: Vec<Iface> = Vec::new();
    let mut i = 0;
    while i + 1 < desc.len() {
        let len = desc[i] as usize;
        if len < 2 || i + len > desc.len() {
            break;
        }
        let body = &desc[i..i + len];
        match body[1] {
            DT_INTERFACE if len >= 9 => out.push(Iface {
                triple: [body[5], body[6], body[7]],
                hid_report_len: None,
                endpoints: Vec::new(),
            }),
            DT_HID if len >= 9 => {
                if let Some(f) = out.last_mut().filter(|f| f.triple[0] == 0x03) {
                    f.hid_report_len = Some(u16::from_le_bytes([body[7], body[8]]) as usize);
                }
            }
            DT_ENDPOINT if len >= 7 => {
                if let Some(f) = out.last_mut() {
                    f.endpoints.push(body[2]);
                }
            }
            _ => {}
        }
        i += len;
    }
    out
}

/// The list a USB/IP client is handed before it imports anything must be the list
/// the descriptors declare, in the same order.
///
/// Both were written from the same intent, which is exactly why one can drift
/// from the other without a compiler noticing — and the ORDER is issue #55's whole
/// content: KeePassXC went blind on Linux when the keyboard interface stopped
/// being interface 0.
#[test]
fn the_devlist_matches_the_descriptors() {
    let declared: Vec<[u8; 3]> = interfaces_in(&config_descriptor())
        .iter()
        .map(|f| f.triple)
        .collect();
    assert_eq!(declared, INTERFACES.to_vec());
}

/// …and the count the kernel is told before it reads anything is that same list's.
#[test]
fn the_device_info_counts_the_interfaces_it_has() {
    let d = device_info(false);
    assert_eq!(
        d.num_interfaces as usize,
        interfaces_in(&config_descriptor()).len()
    );
    assert_eq!(d.id_vendor, VID);
    assert_eq!(d.id_product, PID);
    // …and `--yubico` is one identity or none: the tools that look for it match
    // the VID, and read the PID out of the PC/SC reader name.
    let yk = device_info(true);
    assert_eq!(yk.id_vendor, YUBICO_VID);
    assert_eq!(yk.id_product, YUBICO_PID);
    assert_eq!(d.bcd_device, BCD_DEVICE);
}

/// The keyboard is interface 0 and FIDO is interface 1. Stated separately from
/// the order test because it is the property, not a consequence — and because
/// the class triples cannot say it: both are plain HID, so the only thing on the
/// wire that tells them apart is which report descriptor each one points at.
///
/// `ykpers`/`ykcore`'s libusb backend claims interface 0 and sends the OTP frame
/// reports there without looking at anything else; issue #55 was that interface
/// being FIDO's.
#[test]
fn the_keyboard_is_interface_zero_and_fido_is_one() {
    let ifaces = interfaces_in(&config_descriptor());
    let hid: Vec<Option<usize>> = ifaces.iter().map(|f| f.hid_report_len).collect();
    assert_eq!(
        hid,
        vec![
            Some(rsk_usb::kbd::KEYBOARD_REPORT_DESCRIPTOR.len()),
            Some(FIDO_REPORT_DESCRIPTOR.len()),
            None,
        ]
    );
}

/// Every endpoint the descriptors declare has its own address, and none of them
/// is endpoint 0 — that is the control pipe, and an interface landing on it would
/// answer descriptor reads with its own data.
#[test]
fn every_declared_endpoint_has_its_own_address() {
    let addrs: Vec<u8> = interfaces_in(&config_descriptor())
        .iter()
        .flat_map(|f| f.endpoints.clone())
        .collect();
    assert!(!addrs.is_empty());
    assert!(addrs.iter().all(|&a| a & 0x0f != 0), "{addrs:02x?}");
    let mut sorted = addrs.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        addrs.len(),
        "duplicate address in {addrs:02x?}"
    );
}

/// The emulator must not present itself as a real key by accident: same VID/PID
/// so hosts treat it the same, and a product string that says which it is.
#[test]
fn the_product_string_says_it_is_an_emulator() {
    assert!(PRODUCT.contains("emulator"));
}
