// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use std::sync::mpsc;

use rsk_display::TouchPad;

use super::*;

/// A pad over a script that is fully queued before the first read — the shape a
/// `--taps` file and a test both produce.
fn pad(taps: &[Tap]) -> TapPad {
    let (tx, rx) = mpsc::channel();
    for t in taps {
        tx.send(*t).expect("the receiver is alive");
    }
    TapPad::new(rx)
}

/// Poll the pad the way a modal does, collecting what it reports.
fn poll(p: &mut TapPad, times: usize) -> Vec<Option<rsk_ui::Point>> {
    (0..times)
        .map(|_| {
            let s = p.read();
            std::thread::sleep(Duration::from_millis(16));
            s
        })
        .collect()
}

#[test]
fn a_tap_is_preceded_by_a_lifted_sample() {
    // Every flow debounces the contact that opened it (`wait_release`), so a pad
    // that opens with the contact already down would have one press satisfy both
    // the debounce and the tap after it.
    let mut p = pad(&[Tap::at(10, 20)]);
    assert_eq!(p.read(), None, "the pad opens lifted");
    let seen = poll(&mut p, 12);
    assert!(seen[0].is_none(), "still lifted on the next poll");
    assert!(
        seen.contains(&Some(rsk_ui::Point::new(10, 20))),
        "the contact never arrived"
    );
}

/// Two nested release waits is the deepest gesture boundary in the flow (a menu
/// row debounces, then the pad it opens debounces), and each returns on the first
/// lifted sample it sees. So a boundary has to be several polls wide, or the
/// second wait eats the next contact — which is exactly what it did.
#[test]
fn taps_are_separated_by_several_lifted_samples() {
    let mut p = pad(&[Tap::at(1, 2), Tap::at(3, 4)]);
    let seen: Vec<_> = poll(&mut p, 20).into_iter().collect();
    let first = seen
        .iter()
        .position(|s| *s == Some(rsk_ui::Point::new(1, 2)))
        .expect("the first contact");
    let second = seen
        .iter()
        .position(|s| *s == Some(rsk_ui::Point::new(3, 4)))
        .expect("the second contact");
    let lifted = seen[first + 1..second]
        .iter()
        .filter(|s| s.is_none())
        .count();
    assert!(
        lifted >= 3,
        "only {lifted} lifted samples between contacts — a nested release wait eats one each"
    );
    assert!(
        seen[second + 1..].iter().all(Option::is_none),
        "the pad stays lifted once the script is spent"
    );
}

#[test]
fn a_hold_is_reported_for_its_whole_duration() {
    let mut p = pad(&[Tap {
        hold: Duration::from_millis(120),
        ..Tap::at(5, 6)
    }]);
    // Poll through the lift that precedes every contact, then time the contact.
    while p.read().is_none() {
        std::thread::sleep(Duration::from_millis(8));
    }
    let start = Instant::now();
    let mut samples = 1;
    while let Some(at) = p.read() {
        assert_eq!(at, rsk_ui::Point::new(5, 6));
        samples += 1;
        std::thread::sleep(Duration::from_millis(8));
    }
    assert!(start.elapsed() >= Duration::from_millis(120), "held short");
    assert!(samples > 1, "a hold read once is a tap, not a hold");
}

#[test]
fn a_gap_holds_the_pad_lifted_before_the_contact() {
    let mut p = pad(&[Tap {
        gap: Duration::from_millis(300),
        ..Tap::at(7, 8)
    }]);
    let start = Instant::now();
    while p.read().is_none() {
        std::thread::sleep(Duration::from_millis(8));
        assert!(start.elapsed() < Duration::from_secs(2), "never contacted");
    }
    assert!(start.elapsed() >= Duration::from_millis(300));
}

#[test]
fn an_empty_or_closed_script_reads_as_lifted() {
    let (tx, rx) = mpsc::channel::<Tap>();
    let mut p = TapPad::new(rx);
    assert_eq!(p.read(), None);
    drop(tx);
    assert_eq!(p.read(), None);
}

/// A tap pushed after the pad has already been polled is still played — the
/// channel is a queue, not a sampler, which is what lets a test hand the panel a
/// gesture at the moment a host command needs it.
#[test]
fn a_tap_queued_late_is_not_missed() {
    let (tx, rx) = mpsc::channel();
    let mut p = TapPad::new(rx);
    assert_eq!(p.read(), None);
    assert_eq!(p.read(), None);
    tx.send(Tap::at(9, 9)).expect("the receiver is alive");
    assert!(
        poll(&mut p, 12).contains(&Some(rsk_ui::Point::new(9, 9))),
        "a tap queued after the first poll was lost"
    );
}

#[test]
fn the_script_parser_takes_coordinates_durations_and_comments() {
    let taps = parse_script(
        "# a comment\n\
         \n\
         120,300\n\
         10 , 20 , 900\n\
         1,2,3,4  # trailing comment\n",
    )
    .expect("a valid script");
    assert_eq!(taps.len(), 3);
    assert_eq!(taps[0].at, rsk_ui::Point::new(120, 300));
    assert_eq!(taps[0].hold, Duration::ZERO);
    assert_ne!(
        taps[0].gap,
        Duration::ZERO,
        "a two-field line keeps the default lift"
    );
    assert_eq!(taps[1].hold, Duration::from_millis(900));
    assert_eq!(taps[2].gap, Duration::from_millis(4));
}

#[test]
fn the_script_parser_refuses_what_it_cannot_place() {
    for bad in [
        "1",         // no y
        "1,",        // empty y
        "1,2,,4",    // empty hold, named as such rather than as a missing y
        "1,2,3,4,5", // more than the four fields
        "left,2",    // not a number
        "70000,2",   // off the u16 axis
        "-1,2",      // negative
        "240,0",     // one past the right edge of the glass
        "0,320",     // one past the bottom
    ] {
        assert!(
            parse_script(bad).is_err(),
            "{bad:?} was accepted as a tap script"
        );
    }
    // The last pixel of the panel is still on it.
    assert!(parse_script("239,319").is_ok());
}

/// The socket pad, driven the way a suite drives it — and the property that makes
/// it worth having: `ok` is not "queued", it is "the panel has room".
///
/// The bound is one, so the first line is buffered and answered at once and the
/// second cannot be answered until the pad takes the first. The negative half is
/// asserted with a read timeout rather than a sleep-and-hope: a slow machine only
/// makes "no answer yet" more true, so it cannot go flaky in the direction that
/// would matter.
#[test]
fn the_socket_pad_answers_a_line_only_once_the_panel_has_room() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral port");
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || serve(listener, tx));

    let mut sock = TcpStream::connect(addr).expect("the pad's socket");
    let mut answers = BufReader::new(sock.try_clone().unwrap());
    let mut answer = || {
        let mut line = String::new();
        answers.read_line(&mut line).map(|_| line)
    };

    sock.write_all(b"10,20\n").unwrap();
    assert_eq!(answer().unwrap(), "ok\n", "the first contact has room");

    sock.write_all(b"30,40\n").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(
        answer().is_err(),
        "the second was answered with the first still on the pad"
    );

    assert_eq!(rx.recv().unwrap().at, rsk_ui::Point::new(10, 20));
    sock.set_read_timeout(None).unwrap();
    assert_eq!(
        answer().unwrap(),
        "ok\n",
        "taking one makes room for the next"
    );
    assert_eq!(rx.recv().unwrap().at, rsk_ui::Point::new(30, 40));

    // `settle` is two lifted samples, because one is what a nested release wait
    // swallows; and a malformed line is answered on the connection that sent it
    // rather than taking the pad down.
    sock.write_all(b"settle\n").unwrap();
    let expect = nowhere();
    assert_eq!(rx.recv().unwrap().at, expect);
    assert_eq!(answer().unwrap(), "ok\n");
    assert_eq!(rx.recv().unwrap().at, expect);

    sock.write_all(b"nine,nine\n").unwrap();
    assert!(
        answer().unwrap().starts_with("err "),
        "a bad line is answered"
    );

    // A name resolves through the panel's OWN hit test, which is the whole reason
    // a suite says `key 7` rather than a pixel: a control that moves takes its
    // name with it, and a coordinate in a Python file would not follow.
    sock.write_all(b"key 7\n").unwrap();
    let at = rx.recv().unwrap().at;
    assert_eq!(answer().unwrap(), "ok\n");
    assert_eq!(
        rsk_ui::hit_pin(at, &rsk_ui::PinLayout::identity()),
        Some(rsk_ui::PinKey::Digit(7)),
        "`key 7` must land where the pad dispatches a 7"
    );

    // The tail is the file grammar's, so a consent hold and its lead-in are one
    // line: `allow,800,400` is the 800 ms fill behind 400 ms of lifted samples.
    sock.write_all(b"onboard skip,0,250\n").unwrap();
    let tap = rx.recv().unwrap();
    assert_eq!(answer().unwrap(), "ok\n");
    assert_eq!(
        rsk_ui::hit_onboard(tap.at),
        Some(rsk_ui::OnboardChoice::Skip)
    );
    assert_eq!(tap.gap, Duration::from_millis(250), "the tail still parses");

    sock.write_all(b"key 11\n").unwrap();
    assert!(
        answer().unwrap().starts_with("err "),
        "a key the pad does not have is refused, not silently resolved"
    );
}
