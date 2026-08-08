// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const TOUCH: usize = STATUS_TOUCH as usize;

fn sample() -> LedConfig {
    LedConfig {
        steady: true,
        status: [
            StatusCfg {
                effect: 1,
                color: 2,
                brightness: 16,
                speed: 0,
            },
            StatusCfg {
                effect: 3,
                color: 2,
                brightness: 32,
                speed: 5,
            },
            StatusCfg {
                effect: 2,
                color: 4,
                brightness: 64,
                speed: 0,
            },
            StatusCfg {
                effect: 4,
                color: 1,
                brightness: 8,
                speed: 200,
            },
        ],
    }
}

#[test]
fn conf_len_matches_layout() {
    assert_eq!(CONF_LEN, 17);
    assert_eq!(CONF_LEN, 1 + 4 * N_STATUS);
}

#[test]
fn encode_decode_roundtrip() {
    let cfg = sample();
    let mut got = LedConfig::default();
    got.apply_block(&cfg.encode());
    assert_eq!(got, cfg);
}

#[test]
fn encode_layout_is_steady_then_quads() {
    let b = sample().encode();
    assert_eq!(b.len(), 17);
    assert_eq!(b[0], 1); // steady
    // touch (status index 2): effect, color, brightness, speed at 1+4*2 = 9..13
    assert_eq!(&b[9..13], &[2, 4, 64, 0]);
}

#[test]
fn color_is_masked_to_low_three_bits() {
    let mut cfg = LedConfig::default();
    let mut b = [0u8; CONF_LEN];
    b[2] = 0xFA; // idle color slot; 0xFA & 0x7 == 2
    cfg.apply_block(&b);
    assert_eq!(cfg.status[0].color, 0x2);
    // and encode re-masks rather than leaking high bits
    cfg.status[1].color = 0xFF;
    // status 1 (processing) color byte sits at index 2 + 4 = 6
    assert_eq!(cfg.encode()[6], 0x7);
}

#[test]
fn pre_speed_13_byte_block_keeps_current_speed() {
    let mut cfg = sample(); // speeds 0, 5, 0, 200
    let mut b = [0u8; 13]; // [steady, (effect, color, brightness) × 4]
    b[0] = 0;
    for i in 0..N_STATUS {
        b[1 + 3 * i] = 0; // effect legacy
        b[2 + 3 * i] = if i == TOUCH { 6 } else { 1 }; // cyan touch, red rest
        b[3 + 3 * i] = 100 + i as u8; // brightness
    }
    cfg.apply_block(&b);
    assert!(!cfg.steady);
    for (i, s) in cfg.status.iter().enumerate() {
        let color = if i == TOUCH { 6 } else { 1 };
        assert_eq!((s.effect, s.color, s.brightness), (0, color, 100 + i as u8));
    }
    assert_eq!(cfg.status[1].speed, 5); // preserved
    assert_eq!(cfg.status[3].speed, 200); // preserved
}

#[test]
fn pre_effect_9_byte_block_keeps_current_effect_and_speed() {
    let mut cfg = sample(); // effects 1,3,2,4 ; speeds 0,5,0,200
    let mut b = [0u8; 9]; // [steady, (color, brightness) × 4]
    b[0] = 1;
    for i in 0..N_STATUS {
        b[1 + 2 * i] = if i == TOUCH { 6 } else { 3 }; // cyan touch, blue rest
        b[2 + 2 * i] = 50; // brightness
    }
    cfg.apply_block(&b);
    assert!(cfg.steady);
    for (i, s) in cfg.status.iter().enumerate() {
        assert_eq!(
            (s.color, s.brightness),
            (if i == TOUCH { 6 } else { 3 }, 50)
        );
    }
    assert_eq!(cfg.status[0].effect, 1); // preserved
    assert_eq!(cfg.status[3].effect, 4); // preserved
    assert_eq!(cfg.status[3].speed, 200); // preserved
}

#[test]
fn legacy_2_byte_block_maps_onto_idle_only() {
    let mut cfg = sample();
    let processing_before = cfg.status[1];
    cfg.apply_block(&[80, 0x0B]); // brightness 80, color 0x0B & 7 = 3 onto idle
    assert_eq!(cfg.status[0].brightness, 80);
    assert_eq!(cfg.status[0].color, 3);
    assert_eq!(cfg.status[1], processing_before); // others untouched
}

#[test]
fn legacy_3_byte_block_sets_steady() {
    let mut cfg = LedConfig::default();
    cfg.apply_block(&[10, 2, 1]);
    assert!(cfg.steady);
    assert_eq!((cfg.status[0].brightness, cfg.status[0].color), (10, 2));
}

#[test]
fn too_short_block_is_ignored() {
    let mut cfg = sample();
    let before = cfg;
    cfg.apply_block(&[]);
    cfg.apply_block(&[7]);
    assert_eq!(cfg, before);
}

#[test]
fn block_longer_than_conf_len_reads_the_known_prefix() {
    // A future, longer block still loads its first 17 bytes (the >= branch).
    let cfg = sample();
    let mut b = [0u8; 21];
    b[..CONF_LEN].copy_from_slice(&cfg.encode());
    let mut got = LedConfig::default();
    got.apply_block(&b);
    assert_eq!(got, cfg);
}

/// The touch indicator is lit, above the floor, animated, and the only status
/// in its colour.
fn assert_touch_invariant(cfg: &LedConfig) {
    let t = cfg.status[TOUCH];
    assert_ne!(t.color, 0);
    assert!(t.brightness >= TOUCH_MIN_BRIGHTNESS);
    assert!(t.speed == SPEED_DEFAULT || t.speed >= TOUCH_MIN_SPEED);
    for (i, s) in cfg.status.iter().enumerate() {
        assert!(
            i == TOUCH || s.color != t.color,
            "status {i} wears the touch colour"
        );
    }
}

#[test]
fn zeroed_touch_quad_is_floored_on_decode() {
    let mut cfg = LedConfig::default();
    cfg.apply_block(&[0u8; CONF_LEN]);
    assert_eq!(cfg.status[TOUCH].color, DEFAULT_COLOR[TOUCH]);
    assert_eq!(cfg.status[TOUCH].brightness, TOUCH_MIN_BRIGHTNESS);
    // only the touch status is held up; the rest may go dark
    assert_eq!(cfg.status[STATUS_IDLE as usize], StatusCfg::default());
    assert_touch_invariant(&cfg);
}

#[test]
fn degenerate_touch_speed_is_raised() {
    let mut cfg = sample();
    cfg.status[TOUCH].speed = 1; // vapor's period / 2 == 0 → an all-black frame
    let mut got = LedConfig::default();
    got.apply_block(&cfg.encode());
    assert_eq!(got.status[TOUCH].speed, TOUCH_MIN_SPEED);

    cfg.status[TOUCH].speed = SPEED_DEFAULT; // 0 keeps its "built-in default" meaning
    got.apply_block(&cfg.encode());
    assert_eq!(got.status[TOUCH].speed, SPEED_DEFAULT);
}

#[test]
fn a_status_aliasing_touch_is_reset_to_its_own_defaults() {
    let mut cfg = sample();
    cfg.status[STATUS_IDLE as usize] = cfg.status[TOUCH];
    let mut got = LedConfig::default();
    got.apply_block(&cfg.encode());
    assert_eq!(
        got.status[STATUS_IDLE as usize],
        default_status(STATUS_IDLE)
    );
    assert_eq!(got.status[TOUCH], cfg.status[TOUCH]); // the touch look itself is kept
    assert_touch_invariant(&got);
}

#[test]
fn touch_copying_another_status_factory_look_gives_way() {
    let mut cfg = sample();
    cfg.status[STATUS_IDLE as usize] = default_status(STATUS_IDLE);
    cfg.status[TOUCH] = default_status(STATUS_IDLE);
    let mut got = LedConfig::default();
    got.apply_block(&cfg.encode());
    assert_eq!(
        got.status[STATUS_IDLE as usize],
        default_status(STATUS_IDLE)
    );
    assert_eq!(got.status[TOUCH], default_status(STATUS_TOUCH));
    assert_touch_invariant(&got);
}

/// One brightness unit apart is not a distinct look: 16 vs 17 of 255 renders the
/// same frame to a human, so a near-miss alias must fail closed exactly like an
/// exact copy. The block goes in through the ungated FIDO `CONFIG_WRITE` path.
#[test]
fn a_status_one_unit_off_the_touch_look_is_still_reset() {
    let touch = StatusCfg {
        effect: EFFECT_BOUNCE,
        color: COLOR_YELLOW,
        brightness: 16,
        speed: SPEED_DEFAULT,
    };
    for impostor in [
        StatusCfg {
            brightness: 17,
            ..touch
        },
        StatusCfg { speed: 1, ..touch },
        StatusCfg {
            effect: EFFECT_FLOW,
            ..touch
        }, // on a one-LED board bounce and flow render the same frame
    ] {
        let mut cfg = sample();
        cfg.status[TOUCH] = touch;
        cfg.status[STATUS_IDLE as usize] = impostor;
        let mut got = LedConfig::default();
        got.apply_block(&cfg.encode());
        assert_eq!(
            got.status[STATUS_IDLE as usize],
            default_status(STATUS_IDLE)
        );
        assert_eq!(got.status[TOUCH], touch); // the touch look itself is kept
        assert_touch_invariant(&got);
    }
}

/// The rule fires on impersonation, not on customisation: statuses that differ
/// in colour keep whatever effect, brightness and speed the host asked for —
/// including a fully dark one, since only touch has a floor.
#[test]
fn a_distinct_configuration_survives_untouched() {
    let cfg = LedConfig {
        steady: true,
        status: [
            StatusCfg {
                effect: EFFECT_BOUNCE,
                color: COLOR_BLUE,
                brightness: 200,
                speed: 3,
            },
            StatusCfg {
                effect: EFFECT_BOUNCE,
                color: 6, // cyan
                brightness: 1,
                speed: 3,
            },
            StatusCfg {
                effect: EFFECT_BOUNCE,
                color: COLOR_GREEN, // idle's factory colour, but idle is blue here
                brightness: TOUCH_MIN_BRIGHTNESS + 1,
                speed: TOUCH_MIN_SPEED,
            },
            StatusCfg {
                effect: EFFECT_SPARKLE,
                color: 0, // fully dark
                brightness: 0,
                speed: 0,
            },
        ],
    };
    let mut got = LedConfig::default();
    got.apply_block(&cfg.encode());
    assert_eq!(got, cfg);
    assert_touch_invariant(&got);
}

/// The touch look only gives way when the impostor's *factory* colour is the
/// touch colour too — resetting it could not fix the clash.
#[test]
fn touch_gives_way_only_when_the_impostor_cannot_be_reset_away() {
    let mut cfg = sample();
    cfg.status[TOUCH].color = COLOR_RED;
    cfg.status[STATUS_BOOT as usize] = default_status(STATUS_BOOT); // red by factory
    let mut got = LedConfig::default();
    got.apply_block(&cfg.encode());
    assert_eq!(got.status[TOUCH], default_status(STATUS_TOUCH));
    assert_eq!(
        got.status[STATUS_BOOT as usize],
        default_status(STATUS_BOOT)
    );
    assert_touch_invariant(&got);

    cfg.status[STATUS_BOOT as usize].color = COLOR_BLUE; // nobody wears red now
    got.apply_block(&cfg.encode());
    assert_eq!(got.status[TOUCH].color, COLOR_RED); // so a red touch is legitimate
    assert_eq!(got.status[STATUS_BOOT as usize].color, COLOR_BLUE);
    assert_touch_invariant(&got);
}

#[test]
fn enforcement_is_idempotent() {
    let mut cfg = LedConfig::default();
    cfg.apply_block(&[0u8; CONF_LEN]);
    let once = cfg;
    cfg.apply_block(&once.encode()); // re-applying what the codec produced changes nothing
    assert_eq!(cfg, once);
    cfg.enforce_touch_invariants();
    assert_eq!(cfg, once);
}

/// Every branch lands on a fixpoint. `apply_block` re-enforces on each decode,
/// so a non-converging reset would restyle the key on every boot.
#[test]
fn enforcement_is_a_fixpoint_on_every_branch() {
    let mut aliased = sample();
    aliased.status[STATUS_IDLE as usize].color = aliased.status[TOUCH].color;
    let mut gives_way = sample();
    gives_way.status[TOUCH].color = COLOR_RED;
    gives_way.status[STATUS_BOOT as usize] = default_status(STATUS_BOOT);
    for cfg in [aliased, gives_way, LedConfig::default(), sample()] {
        let mut once = cfg;
        once.enforce_touch_invariants();
        let mut twice = once;
        twice.enforce_touch_invariants();
        assert_eq!(twice, once);
        let mut decoded = LedConfig::default();
        decoded.apply_block(&once.encode()); // and a flash round-trip changes nothing
        assert_eq!(decoded, once);
        assert_touch_invariant(&once);
    }
}

#[test]
fn every_block_length_decodes_and_holds_the_invariant() {
    let blocks: [&[u8]; 8] = [
        &[],
        &[7],
        &[80, 0x0C],
        &[10, 2, 1],
        &[0u8; 9],
        &[0u8; 13],
        &[0u8; CONF_LEN],
        &[0u8; 21],
    ];
    for b in blocks {
        let mut cfg = sample();
        cfg.apply_block(b);
        assert_touch_invariant(&cfg);
    }
}

#[test]
fn clamp_leds_saturates_to_ceiling() {
    assert_eq!(clamp_leds(4, 8), 4);
    assert_eq!(clamp_leds(8, 8), 8);
    assert_eq!(clamp_leds(99, 8), 8); // the brick-fix invariant: no panic, saturate
    assert_eq!(clamp_leds(0, 8), 0);
}

/// The wink burst must actually *flash*: it starts lit, alternates on a fixed
/// half-period, and fits the advertised number of blinks. A burst that came out
/// solid (or one phase long) would answer CTAPHID_WINK invisibly — the failure the
/// capability bit is supposed to rule out.
#[test]
fn wink_alternates_and_starts_lit() {
    assert!(wink_lit(WINK_MS), "a wink starts lit");
    let phases = WINK_MS / WINK_HALF_MS;
    assert_eq!(phases, 8, "600/75 = four on/off blinks");
    for p in 0..phases {
        // Sample the middle of each half-period, walking the burst down to 0.
        let ms_left = WINK_MS - p * WINK_HALF_MS - WINK_HALF_MS / 2;
        assert_eq!(
            wink_lit(ms_left),
            p % 2 == 0,
            "phase {p} (ms_left={ms_left}) must alternate"
        );
    }
}

/// The whole point of answering the frame at once is that a lone wink starts
/// flashing immediately — an arm that deferred to the next phase boundary would
/// leave the key dark for up to a half-period after the host asked.
#[test]
fn a_lone_wink_arms_and_lights_at_once() {
    let end = wink_arm(0, 1_000);
    assert_eq!(end, 1_000 + WINK_MS);
    assert!(wink_running(end, 1_000));
    assert!(wink_lit(end - 1_000), "the burst starts on its lit phase");
}

/// §11.2.9.2.1 asks for *a* burst. A running one is never extended, so the burst
/// ends `WINK_MS` after the *first* arm however many CTAPHID_WINK frames land in
/// between.
#[test]
fn a_running_wink_is_never_extended() {
    let end = wink_arm(0, 1_000);
    for now in 1_000..1_000 + WINK_MS {
        assert_eq!(wink_arm(end, now), end, "re-armed at {now}");
    }
    // The instant it expires, a fresh burst is allowed again.
    assert_eq!(wink_arm(end, end), end + WINK_MS);
}

/// The attack the bound exists for: an unprivileged host flooding CTAPHID_WINK
/// faster than the blink half-period used to re-arm the deadline every time, so the
/// burst never reached a dark phase and the reserved awaiting-touch colour sat solid
/// for as long as the flood lasted — a forged consent prompt. No cadence may now
/// produce a lit run longer than one half-period.
#[test]
fn flooding_wink_cannot_hold_the_indicator_lit() {
    // 70/74/75 ms are the measured cadences that used to pin it solid; 1 ms is the
    // fastest a 64-byte report can arrive on a `poll_ms:1` interface.
    for cadence in [1u32, 10, 70, 74, 75, 76, 601] {
        let (mut end, mut run, mut longest) = (0u32, 0u32, 0u32);
        for now in 0..10 * WINK_MS {
            if now.is_multiple_of(cadence) {
                end = wink_arm(end, now);
            }
            run = if wink_running(end, now) && wink_lit(end.wrapping_sub(now)) {
                run + 1
            } else {
                0
            };
            longest = longest.max(run);
        }
        assert!(
            longest <= WINK_HALF_MS,
            "a {cadence} ms flood held the touch colour lit for {longest} ms"
        );
    }
}
