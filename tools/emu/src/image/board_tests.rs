// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn board() -> Board {
    let image = std::env::temp_dir().join(format!("rsk-emu-board-{}.elf", std::process::id()));
    let mut elf = [0; 52];
    elf[..6].copy_from_slice(&[0x7F, b'E', b'L', b'F', 1, 1]);
    std::fs::write(&image, elf).unwrap();
    let result = Board::new(Options {
        image: image.clone(),
        rom: None,
        store: None,
        host: "127.0.0.1".into(),
        fido_port: 0,
        ccid_port: 0,
        usbip: None,
        touch: false,
        seed: Some(vec![0; 32]),
        serial: *b"RSKEMU\0\x01",
        trace: false,
        inspect_port: None,
    });
    std::fs::remove_file(image).unwrap();
    result.unwrap()
}

#[test]
fn transport_handover_preserves_bootloader_but_a_replug_cold_boots() {
    let mut board = board();
    for (mode, expected) in [
        (BootMode::Image, End::PowerCycle),
        (BootMode::UsbBootloader, End::Warm { bootsel: true }),
    ] {
        board.boot_mode = mode;
        let (rets, _) = mpsc::channel();
        assert_eq!(
            board.request(Request::UsbipAttach { rets }, false),
            Some(expected)
        );
        assert!(matches!(board.owner, Owner::Usbip { .. }));
        let expected = board.boot_mode.handover();
        assert_eq!(board.request(Request::UsbipDetach, false), Some(expected));
        assert!(matches!(board.owner, Owner::Sockets));
        let (done, _) = mpsc::channel();
        assert_eq!(
            board.request(Request::Replug { done }, false),
            Some(End::PowerCycle)
        );
    }
    board.bootsel = true;
    assert!(matches!(
        board.stopped(Stop::Nsboot(String::new())),
        Flow::Run
    ));
    assert!(matches!(board.boot_mode, BootMode::UsbBootloader));
    assert!(!board.bootsel);
    board.announced = true;
    board.power_up(None).unwrap();
    assert!(matches!(board.boot_mode, BootMode::Image));
    assert!(!board.announced);
}
