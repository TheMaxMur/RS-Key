// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn board() -> Board {
    board_with_taps(Vec::new())
}

fn board_with_taps(taps: Vec<crate::taps::Tap>) -> Board {
    let image = std::env::temp_dir().join(format!(
        "rsk-emu-board-{}-{:?}.elf",
        std::process::id(),
        std::thread::current().id()
    ));
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
        display: !taps.is_empty(),
        headless: true,
        taps,
        taps_port: None,
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

#[test]
fn a_tap_script_owns_the_finger_across_an_image_reboot() {
    let mut board = board_with_taps(vec![crate::taps::Tap::at(10, 10)]);
    let input = board.display_input.clone().unwrap();
    assert!(input.lock().unwrap().pad.is_some());
    assert_eq!(
        board.inspect(
            Command::PanelTouch {
                x: 10,
                y: 10,
                hold_ms: 800
            },
            false
        ),
        Err("scripted pad owns the touch input".into())
    );
    board.power_up(None).unwrap();
    assert!(Arc::ptr_eq(board.chip.touch.as_ref().unwrap(), &input));
    assert!(input.lock().unwrap().pad.is_some());
    assert_eq!(
        board.inspect(Command::PanelRelease, false),
        Err("scripted pad owns the touch input".into())
    );
}
