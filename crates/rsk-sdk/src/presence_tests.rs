// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// A backend with no screen: it implements only `request`, so the ceremony ask
/// has to reach the same code — this is the default every simple front-end and
/// every host test relies on.
struct TouchOnly(Presence);

impl UserPresence for TouchOnly {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        self.0
    }
}

/// A backend with a screen: the two asks answer differently, and the CCID one
/// folds a cancel into a timeout exactly as `firmware`'s button backend does.
struct Screen;

impl UserPresence for Screen {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        Presence::Timeout
    }

    fn request_ceremony(&mut self, _confirm: Confirm<'_>) -> Presence {
        Presence::Cancelled
    }
}

#[test]
fn ceremony_defaults_to_request() {
    for p in [
        Presence::Confirmed,
        Presence::Timeout,
        Presence::Declined,
        Presence::Cancelled,
    ] {
        let mut b = TouchOnly(p);
        assert_eq!(b.request_ceremony(Confirm::titled("x")), p);
    }
}

#[test]
fn ceremony_override_does_not_leak_into_request() {
    let mut b = Screen;
    assert_eq!(b.request(Confirm::titled("x")), Presence::Timeout);
    assert_eq!(
        b.request_ceremony(Confirm::titled("x")),
        Presence::Cancelled
    );
}

#[test]
fn always_confirm_confirms_both_asks() {
    let mut b = AlwaysConfirm;
    assert_eq!(b.request(Confirm::titled("x")), Presence::Confirmed);
    assert_eq!(
        b.request_ceremony(Confirm::register(b"rp", b"user")),
        Presence::Confirmed
    );
}

/// The stand-in has no screen and no pad: `getInfo` must not advertise
/// `options.uv` because a host test happened to be the backend.
#[test]
fn always_confirm_has_no_screen_and_no_pad() {
    let mut b = AlwaysConfirm;
    assert!(!b.shows_confirm());
    assert!(!b.uv_available());
    let mut out = [0u8; 8];
    assert_eq!(b.collect_pin(4, &mut out), PinEntry::Unsupported);
    assert_eq!(b.collect_device_pin(4, &mut out), PinEntry::Unsupported);
}

/// Every production presence ask and which of the two it is, as
/// `(path, ceremony asks, touch-policy asks)`.
///
/// A census, because the compiler cannot tell the two apart at a call site:
/// `request_ceremony` defaults to `request`, and every applet re-exports this
/// trait under its own name, so a call that moves between them keeps building
/// and quietly means something else. Measured: splitting this trait re-pointed
/// `firmware`'s CCID pinpad gate — which imported `rsk_fido::UserPresence` —
/// from the ceremony ask onto the touch-policy one, dropping the trusted
/// display's closing "Approved" card, and the gate stayed green because that
/// path is `display`-gated firmware that nothing on the host executes.
///
/// Sorted by path, which is the order [`scan_presence_asks`] returns.
const ASK_CENSUS: &[(&str, usize, usize)] = &[
    ("crates/rsk-fido/src/lib.rs", 2, 0),
    ("crates/rsk-fido/src/reset.rs", 1, 0),
    ("crates/rsk-fido/src/selection.rs", 1, 0),
    ("crates/rsk-mgmt/src/lib.rs", 0, 1),
    ("crates/rsk-oath/src/lib.rs", 0, 3),
    ("crates/rsk-openpgp/src/lib.rs", 0, 1),
    ("crates/rsk-otp/src/lib.rs", 0, 1),
    ("crates/rsk-piv/src/auth.rs", 0, 1),
    ("crates/rsk-rescue/src/lib.rs", 0, 1),
    // The default body's own forward, not a call site.
    ("crates/rsk-sdk/src/presence.rs", 0, 1),
    ("crates/rsk-vendor/src/lib.rs", 0, 1),
    ("firmware/src/worker.rs", 1, 0),
];

/// Collect `(path relative to `root`, ceremony asks, touch-policy asks)` for every
/// non-empty file under `dir`. Test and proof modules are skipped: cfg-gated code
/// never reaches the image, and a stand-in backend's ask is the test's own business.
fn scan_presence_asks(
    root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut std::vec::Vec<(std::string::String, usize, usize)>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name != "target" {
                scan_presence_asks(root, &path, out);
            }
            continue;
        }
        if !name.ends_with(".rs")
            || name.ends_with("_tests.rs")
            || name.ends_with("_kani.rs")
            || name == "tests.rs"
            || name == "kani.rs"
        {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        // The `(` is literal, so `.request(` cannot match inside `.request_ceremony(`.
        let ceremony = src.matches(".request_ceremony(").count();
        let touch = src.matches(".request(").count();
        if ceremony + touch > 0 {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            out.push((rel.to_string_lossy().replace('\\', "/"), ceremony, touch));
        }
    }
}

/// A call that changes column changes meaning, so [`ASK_CENSUS`] has to move with it.
#[test]
fn every_presence_ask_is_the_one_its_caller_means() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let mut found = std::vec::Vec::new();
    for dir in ["crates", "firmware/src"] {
        scan_presence_asks(&root, &root.join(dir), &mut found);
    }
    found.sort();
    // Both trees must actually have been walked, or the comparison below passes on an
    // empty scan — the shape four guards in this tree shipped with. One anchor each:
    // the FIDO funnel, and the firmware pinpad gate that was re-pointed once already.
    for anchor in ["crates/rsk-fido/src/lib.rs", "firmware/src/worker.rs"] {
        assert!(
            found.iter().any(|(p, ..)| p == anchor),
            "the scan missed {anchor:?}, so it proves nothing about that tree"
        );
    }
    let want: std::vec::Vec<_> = ASK_CENSUS
        .iter()
        .map(|(p, c, t)| ((*p).to_string(), *c, *t))
        .collect();
    assert_eq!(
        found, want,
        "left is the tree, right is the census. A presence ask moved: \
         `request_ceremony` runs the trusted display's registration card and its \
         closing \"Approved\" pop and alone can report `Presence::Cancelled`; \
         `request` does none of that and is spent once per signature. Move the \
         census only after deciding the call itself is right."
    );
}
