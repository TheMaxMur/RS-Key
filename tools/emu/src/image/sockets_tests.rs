// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn info(vid: u16, pid: u16, interfaces: Vec<[u8; 3]>) -> UsbipInfo {
    UsbipInfo {
        device: UsbDeviceInfo {
            path: "image-test",
            busid: "rsk-emu",
            busnum: 1,
            devnum: 7,
            speed: 2,
            id_vendor: vid,
            id_product: pid,
            bcd_device: 0,
            device_class: 0,
            device_subclass: 0,
            device_protocol: 0,
            configuration_value: 1,
            num_configurations: 1,
            num_interfaces: interfaces.len() as u8,
        },
        interfaces,
    }
}

#[test]
fn usbip_advertises_the_latest_enumeration_after_bootloader_and_image_reboots() {
    let firmware = info(0x1209, 0xF1D2, vec![[3, 1, 1], [3, 0, 0], [11, 0, 0]]);
    let bootloader = info(0x2E8A, 0x000F, vec![[8, 6, 80], [0xFF, 0, 0]]);
    let shared = Arc::new(Mutex::new(firmware.clone()));
    let (chip, _) = mpsc::channel();
    let port = UsbipPort {
        chip,
        info: shared.clone(),
    };
    for current in [&firmware, &bootloader, &firmware] {
        *shared.lock().unwrap() = current.clone();
        let (device, interfaces) = port.description();
        assert_eq!(device, current.device);
        assert_eq!(interfaces, current.interfaces);
    }
}
