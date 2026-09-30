// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn attached() -> UsbCore {
    let mut u = UsbCore::new(Arc::new(Mutex::new(Vec::new())));
    u.reg_write(MAIN_CTRL, MAIN_CTRL_CONTROLLER_EN, 0, 0);
    u.reg_write(USB_MUXING, 0x9, 0, 0);
    u.reg_write(SIE_CTRL, SIE_CTRL_PULLUP_EN | SIE_CTRL_EP0_INT_1BUF, 0, 0);
    u
}

fn arm(u: &mut UsbCore, off: usize, v: u32) {
    u.wr32(off, v);
}

#[test]
fn setup_lands_in_dpram_raises_setup_req_and_disarms_stall() {
    let mut u = attached();
    u.reg_write(INTE, IN_SETUP_REQ, 0, 0);
    u.reg_write(EP_STALL_ARM, 3, 0, 0);
    let pkt = [0x80, 6, 0, 1, 0, 0, 64, 0];
    assert_eq!(u.host_setup(0, pkt, 0), Handshake::Ack);
    assert_eq!(u.dpram[..8], pkt);
    assert_ne!(u.reg_read(INTR, 0) & IN_SETUP_REQ, 0);
    assert_ne!(u.ints(), 0);
    assert_eq!(u.reg_read(EP_STALL_ARM, 0), 0);
    // SIE_STATUS.SETUP_REC is write-1-to-clear; a 0 leaves it.
    u.reg_write(SIE_STATUS, 0, 0, 0);
    assert_ne!(u.reg_read(SIE_STATUS, 0) & ST_SETUP_REC, 0);
    u.reg_write(SIE_STATUS, ST_SETUP_REC, 3, 0); // the CLR alias clears it too
    assert_eq!(u.reg_read(SIE_STATUS, 0) & ST_SETUP_REC, 0);
    assert_eq!(u.ints(), 0);
}

#[test]
fn ep0_in_naks_until_available_then_hands_over_the_buffer() {
    let mut u = attached();
    assert_eq!(u.host_in(0, 0, 0), Err(Handshake::Nak));
    u.dpram[0x100..0x103].copy_from_slice(&[1, 2, 3]);
    arm(&mut u, 0x80, BC_AVAILABLE | BC_FULL | BC_PID | 3);
    assert_eq!(u.host_in(0, 0, 0), Ok((1, vec![1, 2, 3])));
    assert_eq!(
        u.rd32(0x80) & (BC_AVAILABLE | BC_FULL),
        0,
        "status written back"
    );
    assert_eq!(u.reg_read(BUFF_STATUS, 0), 1, "EP0 IN done, EP0_INT_1BUF");
    assert_eq!(
        u.host_in(0, 0, 0),
        Err(Handshake::Nak),
        "buffer is the CPU's again"
    );
}

#[test]
fn ep0_stall_needs_its_arm_bit_and_a_setup_clears_it() {
    let mut u = attached();
    arm(&mut u, 0x80, BC_STALL);
    assert_eq!(
        u.host_in(0, 0, 0),
        Err(Handshake::Nak),
        "STALL without EP_STALL_ARM"
    );
    u.reg_write(EP_STALL_ARM, 1, 0, 0);
    assert_eq!(u.host_in(0, 0, 0), Err(Handshake::Stall));
    u.host_setup(0, [0; 8], 0);
    assert_eq!(u.host_in(0, 0, 0), Err(Handshake::Nak));
}

#[test]
fn out_with_the_wrong_toggle_is_acked_and_dropped() {
    let mut u = attached();
    arm(&mut u, 0x84, BC_AVAILABLE | 64); // expects DATA0
    assert_eq!(u.host_out(0, 0, 1, &[9; 4], 0), Handshake::Ack);
    assert_ne!(u.reg_read(SIE_STATUS, 0) & ST_DATA_SEQ_ERROR, 0);
    assert_ne!(u.rd32(0x84) & BC_AVAILABLE, 0, "still armed");
    assert_eq!(u.host_out(0, 0, 0, &[9; 4], 0), Handshake::Ack);
    let bc = u.rd32(0x84);
    assert_eq!(
        (bc & BC_AVAILABLE, bc & BC_FULL, bc & BC_LEN),
        (0, BC_FULL, 4)
    );
    assert_eq!(u.dpram[0x100..0x104], [9; 4]);
}

#[test]
fn epx_uses_its_buffer_address_and_interrupt_per_buff() {
    let mut u = attached();
    arm(
        &mut u,
        0x08,
        EC_ENABLE | EC_INTERRUPT_PER_BUFF | (3 << 26) | 0x180,
    ); // EP1 IN
    u.dpram[0x180..0x182].copy_from_slice(&[0xAB, 0xCD]);
    arm(&mut u, 0x88, BC_AVAILABLE | BC_FULL | 2);
    assert_eq!(u.host_in(0, 1, 0), Ok((0, vec![0xAB, 0xCD])));
    assert_eq!(u.reg_read(BUFF_STATUS, 0), 1 << 2);
    u.reg_write(BUFF_STATUS, 1 << 2, 0, 0);
    assert_eq!(u.reg_read(BUFF_STATUS, 0), 0);
}

#[test]
fn double_buffered_endpoint_alternates_and_reports_the_buffer() {
    let u = Arc::new(Mutex::new(attached()));
    let mut dp = UsbDpram(u.clone());
    let mut ctx = MmioCtx::default();
    let mut c = u.lock().unwrap();
    c.wr32(
        0x08 + 8 * 2,
        EC_ENABLE | EC_DOUBLE_BUFFERED | EC_INTERRUPT_PER_BUFF | (2 << 26) | 0x200,
    ); // EP3 IN
    c.dpram[0x200] = 0xA0;
    c.dpram[0x240] = 0xB1;
    drop(c);
    // buffer 0: DATA0, 1 byte, FULL|AVAILABLE, with the selector reset;
    // buffer 1: DATA1, 1 byte.
    let lo = BC_AVAILABLE | BC_FULL | BC_RESET_SELECTOR | 1;
    let hi = BC_AVAILABLE | BC_FULL | BC_PID | 1;
    dp.write(0x80 + 8 * 3, lo | hi << 16, 4, 0, &mut ctx);
    let mut c = u.lock().unwrap();
    assert_eq!(c.host_in(0, 3, 0), Ok((0, vec![0xA0])));
    assert_eq!(
        (
            c.reg_read(BUFF_STATUS, 0),
            c.reg_read(BUFF_CPU_SHOULD_HANDLE, 0)
        ),
        (1 << 6, 0)
    );
    assert_eq!(c.host_in(0, 3, 0), Ok((1, vec![0xB1])));
    assert_eq!(
        c.reg_read(BUFF_CPU_SHOULD_HANDLE, 0),
        1 << 6,
        "buffer 1 completed"
    );
    assert_eq!(c.host_in(0, 3, 0), Err(Handshake::Nak), "both handed back");
}

#[test]
fn no_answer_off_address_disabled_or_detached() {
    let mut u = attached();
    assert_eq!(u.host_setup(5, [0; 8], 0), Handshake::Timeout);
    assert_eq!(
        u.host_in(0, 2, 0),
        Err(Handshake::Timeout),
        "EP2 not enabled"
    );
    u.reg_write(ADDR_ENDP_REG, 5, 0, 0);
    assert_eq!(u.host_setup(5, [0; 8], 0), Handshake::Ack);
    u.reg_write(SIE_CTRL, 0, 0, 0);
    assert_eq!(
        u.host_setup(5, [0; 8], 0),
        Handshake::Timeout,
        "pull-up gone"
    );
}

#[test]
fn ints_is_intr_or_intf_masked_by_inte() {
    let mut u = attached();
    u.host_bus_reset(0);
    assert_eq!(u.ints(), 0, "nothing enabled");
    u.reg_write(INTF, IN_TRANS_COMPLETE, 0, 0);
    u.reg_write(INTE, IN_BUS_RESET | IN_TRANS_COMPLETE, 0, 0);
    assert_eq!(u.ints(), IN_BUS_RESET | IN_TRANS_COMPLETE);
    u.reg_write(SIE_STATUS, ST_BUS_RESET, 0, 0);
    assert_eq!(u.ints(), IN_TRANS_COMPLETE);
}
