/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* USB device-side driver for the RP2350 USBCTRL block: chapter-9 EP0 control
 * transfers plus the EP1 interrupt endpoints that carry CTAPHID. Plain MMIO,
 * one event per usb_task call; the model harness (asm/usbtest.c) runs it
 * against a datasheet-derived SIE simulation. Register facts cite the
 * pico-sdk 2.2.0 RP2350 headers; init order mirrors pico-examples
 * dev_lowlevel (unreset, muxing, vbus override, then pullup last). */

.equ USB_REGS,    0x50110000
.equ USB_DPRAM,   0x50100000
.equ RESETS,      0x40020000

/* register offsets (pico-sdk 2.2.0, hardware/regs/usb.h) */
.equ R_ADDR_ENDP,   0x00
.equ R_MAIN_CTRL,   0x40
.equ R_SIE_CTRL,    0x4c
.equ R_SIE_STATUS,  0x50
.equ R_BUFF_STATUS, 0x58
.equ R_MUXING,      0x74
.equ R_PWR,         0x78

/* resets block (hardware/regs/resets.h) */
.equ RST_RESET,    0x00
.equ RST_DONE,     0x08
.equ RST_USBCTRL,  0x10000000

.equ MAIN_CTRL_EN,   0x00000001
.equ MUX_TO_PHY_SOFT, 0x00000009    /* TO_PHY | SOFTCON */
.equ PWR_VBUS_FORCE, 0x0000000c    /* VBUS_DETECT | OVERRIDE_EN */
.equ SIE_PULLUP,     0x00010000
.equ SIE_EP0_1BUF,   0x20000000    /* without it EP0 never reaches BUFF_STATUS */
.equ ST_BUS_RESET,   0x00080000
.equ ST_SETUP_REC,    0x00020000
.equ BS_EP0_IN,      0x00000001
.equ BS_EP0_OUT,     0x00000002
.equ BS_EP1_IN,      0x00000004
.equ BS_EP1_OUT,     0x00000008

/* DPSRAM layout (hardware/regs/usb_device_dpram.h) */
.equ D_SETUP,       0x000
.equ D_EP1_CTRL_IN,  0x008
.equ D_EP1_CTRL_OUT, 0x00c
.equ D_BC_IN,    0x080
.equ D_BC_OUT,   0x084
.equ D_BC1_IN,   0x088
.equ D_BC1_OUT,  0x08c
.equ D_EP0_BUF,  0x100
.equ D_EP1_OUT_BUF, 0x180
.equ D_EP1_IN_BUF,  0x1c0

/* ep_ctrl word (device mode) */
.equ EP_ENABLE,      0x80000000
.equ EP_INT_PER_BUF, 0x20000000    /* required for BUFF_STATUS on non-EP0 */
.equ EP_TYPE_INT,    3 << 26

/* buffer control word */
.equ BC_FULL,    0x8000
.equ BC_LAST,    0x4000
.equ BC_DATA1,   0x2000
.equ BC_STALL,   0x0800
.equ BC_AVAIL,   0x0400

/* chapter-9 requests */
.equ REQ_GET_STATUS,     0x00
.equ REQ_SET_ADDRESS,    0x05
.equ REQ_GET_DESCRIPTOR, 0x06
.equ REQ_GET_CONFIG,     0x08
.equ REQ_SET_CONFIG,     0x09
.equ REQ_GET_IFACE,     0x0a
.equ DESC_DEVICE, 0x01
.equ DESC_CONFIG,  0x02
.equ DESC_STRING,  0x03
.equ DESC_REPORT,  0x22
.equ STR_MANUF,     1
.equ STR_PROD,      2
.equ LANGID_US,     0x0409

/* offsets into asm/ctaphid.S's caller state (kept in sync by hand) */
.equ ST_CID,     0
.equ ST_IN_TX,   20
.equ ST_BUF_MAX, 24
.equ ST_BUF,     28
.equ CTAPHID_MAX, 7609

.syntax unified
.cpu cortex-m33
.thumb

.section .bss
.align 2
.global usb_state
/* +0 addr_pending (bit 31 marks pending), +4 configured,
 * +8 ep1_out_pid, +12 ep1_in_pid, +16 tx_done */
usb_state:
    .space 20

.global ctaphid_state
ctaphid_state:
    .space 48

.global ctaphid_msg
ctaphid_msg:
    .space CTAPHID_MAX

.section .rodata
.align 2
.global usb_dev_desc
usb_dev_desc:
    .byte 0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40
    .byte 0x09, 0x12, 0x01, 0x00, 0x00, 0x01, STR_MANUF, STR_PROD, 0x00, 0x01

.global usb_cfg_desc
usb_cfg_desc:
    .byte 0x09, 0x02, 0x29, 0x00, 0x01, 0x01, 0x00, 0x80, 0x19
    .byte 0x09, 0x04, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00
    .byte 0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x21, 0x00
    .byte 0x07, 0x05, 0x81, 0x03, 0x40, 0x00, 0x05
    .byte 0x07, 0x05, 0x01, 0x03, 0x40, 0x00, 0x05

.global usb_report_desc
usb_report_desc:
    .byte 0x05, 0xF1, 0x09, 0x00, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00
    .byte 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09
    .byte 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40
    .byte 0x91, 0x02, 0xC0

/* string index 0: LANGUAGE ID (§9.6.7), 0x0409 little-endian */
.global usb_str_langid
usb_str_langid:
    .byte 4, DESC_STRING
    .hword LANGID_US

/* string index 1: manufacturer "RS-Key contributors" */
.global usb_str_manuf
usb_str_manuf:
    .byte 40, DESC_STRING      /* 2 + 2*19 */
    .hword 0x52, 0x53, 0x2D, 0x4B, 0x65, 0x79, 0x20   /* "RS-Key " */
    .hword 0x63, 0x6F, 0x6E, 0x74, 0x72, 0x69, 0x62   /* contribut */
    .hword 0x75, 0x74, 0x6F, 0x72, 0x73               /* ors */

/* string index 2: product "RS-Key" */
.global usb_str_prod
usb_str_prod:
    .byte 14, DESC_STRING      /* 2 + 2*6 */
    .hword 0x52, 0x53, 0x2D, 0x4B, 0x65, 0x79         /* "RS-Key" */

.section .text
.thumb_func
.global usb_init
usb_init:
        push {r4, r5, lr}
        /* the bootrom leaves USBCTRL in reset: release it, wait for done */
        ldr  r0, =RESETS
        ldr  r1, [r0, #RST_RESET]
        ldr  r2, =RST_USBCTRL
        bic  r1, r1, r2
        str  r1, [r0, #RST_RESET]
1:      ldr  r1, [r0, #RST_DONE]
        tst  r1, r2
        beq  1b

        ldr  r0, =USB_REGS
        movs r1, #MUX_TO_PHY_SOFT
        str  r1, [r0, #R_MUXING]
        movs r1, #PWR_VBUS_FORCE
        str  r1, [r0, #R_PWR]
        movs r1, #0
        str  r1, [r0, #R_ADDR_ENDP]
        movs r1, #MAIN_CTRL_EN
        str  r1, [r0, #R_MAIN_CTRL]

        ldr  r5, =USB_DPRAM
        ldr  r1, =EP_ENABLE|EP_INT_PER_BUF|EP_TYPE_INT|D_EP1_OUT_BUF
        str  r1, [r5, #D_EP1_CTRL_OUT]
        ldr  r1, =EP_ENABLE|EP_INT_PER_BUF|EP_TYPE_INT|D_EP1_IN_BUF
        str  r1, [r5, #D_EP1_CTRL_IN]

        /* reassembler state: buf_max/buf are set here, rest stays zeroed */
        ldr  r0, =ctaphid_state
        movs r1, #0
        str  r1, [r0, #ST_CID]
        str  r1, [r0, #ST_IN_TX]
        ldr  r1, =CTAPHID_MAX
        str  r1, [r0, #ST_BUF_MAX]
        ldr  r1, =ctaphid_msg
        str  r1, [r0, #ST_BUF]

        /* present the device only once everything is set up; plain MMIO
         * means no set-alias, so pullup and the EP0 interrupt bit go in
         * together or the second write erases the first */
        ldr  r0, =USB_REGS
        ldr  r1, =SIE_PULLUP|SIE_EP0_1BUF
        str  r1, [r0, #R_SIE_CTRL]
        pop  {r4, r5, pc}

/* one event per call: bus reset, setup, then one buffer completion */
.thumb_func
.global usb_task
usb_task:
        push {r4, r5, r6, lr}
        ldr  r4, =USB_REGS
        ldr  r5, =USB_DPRAM

        ldr  r0, [r4, #R_SIE_STATUS]
        ldr  r1, =ST_BUS_RESET
        tst  r0, r1
        beq  1f
        str  r1, [r4, #R_SIE_STATUS]
        movs r2, #0
        str  r2, [r4, #R_ADDR_ENDP]
        ldr  r3, =usb_state
        str  r2, [r3, #0]              /* pending address */
        str  r2, [r3, #4]              /* configured */
        str  r2, [r3, #8]              /* data toggles */
        str  r2, [r3, #12]
        str  r2, [r3, #16]             /* tx_done */
        ldr  r3, =ctaphid_state
        str  r2, [r3, #ST_CID]         /* reassembler back to idle */
        str  r2, [r3, #ST_IN_TX]
        b    task_done

1:      ldr  r1, =ST_SETUP_REC
        tst  r0, r1
        beq  2f
        str  r1, [r4, #R_SIE_STATUS]
        movs r2, #0
        str  r2, [r5, #D_BC_IN]        /* the SIE resets EP0 on setup */
        str  r2, [r5, #D_BC_OUT]

        ldrb r0, [r5, #D_SETUP+0]      /* bmRequestType */
        ldrb r1, [r5, #D_SETUP+1]      /* bRequest */
        ldrb r2, [r5, #D_SETUP+3]      /* wValue hi */
        ldrb r6, [r5, #D_SETUP+7]      /* wLength is little-endian */
        ldrb r3, [r5, #D_SETUP+6]
        lsls r6, r6, #8
        orrs r6, r6, r3                /* r6 = wLength */

        movs r3, #0xE0
        ands r3, r0                    /* direction + type */
        cmp  r3, #0x80                 /* IN, standard, any recipient */
        beq  in_std
        cmp  r0, #0x00                 /* OUT + standard + device */
        bne  stall_both
        cmp  r1, #REQ_SET_ADDRESS
        beq  set_address
        cmp  r1, #REQ_SET_CONFIG
        beq  set_config
        b    stall_both

in_std:
        cmp  r1, #REQ_GET_DESCRIPTOR
        beq  get_descriptor
        cmp  r1, #REQ_GET_STATUS
        beq  get_status
        cmp  r1, #REQ_GET_CONFIG
        beq  get_config
        cmp  r1, #REQ_GET_IFACE
        beq  get_iface
        b    stall_both

get_status:
        movs r2, #0
        str  r2, [r5, #D_EP0_BUF]
        str  r2, [r5, #D_EP0_BUF+1]
        ldr  r2, =BC_AVAIL|BC_FULL|BC_DATA1|BC_LAST|2
        str  r2, [r5, #D_BC_IN]
        b    task_done

get_config:
        ldr  r3, =usb_state
        ldr  r3, [r3, #4]
        strb r3, [r5, #D_EP0_BUF]
        ldr  r2, =BC_AVAIL|BC_FULL|BC_DATA1|BC_LAST|1
        str  r2, [r5, #D_BC_IN]
        b    task_done

get_iface:
        movs r2, #0                    /* one interface, alternate 0 */
        strb r2, [r5, #D_EP0_BUF]
        ldr  r2, =BC_AVAIL|BC_FULL|BC_DATA1|BC_LAST|1
        str  r2, [r5, #D_BC_IN]
        b    task_done

get_descriptor:
        cmp  r2, #DESC_DEVICE
        bne  3f
        ldr  r3, =usb_dev_desc
        movs r0, #18
        b    send_desc
3:      cmp  r2, #DESC_CONFIG
        bne  4f
        ldr  r3, =usb_cfg_desc
        movs r0, #41
        b    send_desc
4:      cmp  r2, #DESC_REPORT
        bne  8f
        ldr  r3, =usb_report_desc
        movs r0, #33
        b    send_desc
8:      cmp  r2, #DESC_STRING
        bne  stall_both
        ldrb r2, [r5, #D_SETUP+2]     /* wValue lo = string index */
        cmp  r2, #STR_MANUF
        bne  9f
        ldr  r3, =usb_str_manuf
        movs r0, #40
        b    send_desc
9:      cmp  r2, #STR_PROD
        bne  10f
        ldr  r3, =usb_str_prod
        movs r0, #14
        b    send_desc
10:     cmp  r2, #0
        bne  stall_both               /* unknown index */
        ldr  r3, =usb_str_langid
        movs r0, #4
send_desc:
        cmp  r0, r6
        bls  5f
        movs r0, r6                    /* min(desc_len, wLength) */
5:      adds r2, r5, #D_EP0_BUF
        movs r1, #0
6:      cmp  r1, r0
        bcs  7f
        ldrb r6, [r3, r1]
        strb r6, [r2, r1]
        adds r1, #1
        b    6b
7:      ldr  r6, =BC_AVAIL|BC_FULL|BC_DATA1|BC_LAST
        orrs r6, r6, r0
        str  r6, [r5, #D_BC_IN]
        b    task_done

set_address:
        ldrb r3, [r5, #D_SETUP+3]      /* wValue hi must be zero too */
        cmp  r3, #0
        bne  stall_both
        ldrb r2, [r5, #D_SETUP+2]      /* wValue lo = address */
        cmp  r2, #0x7F                 /* §9.6.2: 7-bit, larger is an error */
        bhi  stall_both
        movs r3, #1
        lsls r3, r3, #31
        orrs r2, r2, r3                /* pending marker */
        ldr  r3, =usb_state
        str  r2, [r3, #0]
        b    status_in                 /* latch after the host saw the ack */

set_config:
        ldrb r2, [r5, #D_SETUP+2]
        subs r2, #1
        bne  8f
        ldr  r3, =usb_state
        movs r2, #1
        str  r2, [r3, #4]
        /* data toggles reset on SET_CONFIGURATION */
        movs r2, #0
        str  r2, [r3, #8]
        str  r2, [r3, #12]
        ldr  r2, =BC_AVAIL|64          /* first EP1 OUT is DATA0 */
        str  r2, [r5, #D_BC1_OUT]
        b    status_in
8:      ldr  r3, =usb_state
        movs r2, #0
        str  r2, [r3, #4]
status_in:
        ldr  r2, =BC_AVAIL|BC_FULL|BC_DATA1   /* zero-length IN status stage */
        str  r2, [r5, #D_BC_IN]
        b    task_done

stall_both:
        ldr  r2, =BC_STALL
        str  r2, [r5, #D_BC_IN]
        str  r2, [r5, #D_BC_OUT]
        b    task_done

2:      ldr  r0, [r4, #R_BUFF_STATUS]
        movs r1, #BS_EP0_IN
        tst  r0, r1
        beq  10f
        str  r1, [r4, #R_BUFF_STATUS]
        ldr  r2, =usb_state
        ldr  r3, [r2, #0]
        cmp  r3, #0
        bpl  20f
        lsls r3, r3, #1                /* drop the pending flag, latch now */
        lsrs r3, r3, #1
        str  r3, [r4, #R_ADDR_ENDP]
        movs r3, #0
        str  r3, [r2, #0]
        b    task_done
20:     ldr  r2, =BC_AVAIL|BC_DATA1    /* IN data stage done: host OUT status */
        str  r2, [r5, #D_BC_OUT]
        b    task_done

10:     movs r1, #BS_EP0_OUT
        tst  r0, r1
        beq  11f
        str  r1, [r4, #R_BUFF_STATUS]  /* status stage observed, done */
        b    task_done

11:     movs r1, #BS_EP1_IN
        tst  r0, r1
        beq  12f
        str  r1, [r4, #R_BUFF_STATUS]
        ldr  r2, =usb_state
        ldr  r3, [r2, #12]             /* flip the EP1 IN data toggle */
        eors r3, r3, #1
        str  r3, [r2, #12]
        movs r3, #1
        str  r3, [r2, #16]             /* tx_done event */
        b    task_done

12:     movs r1, #BS_EP1_OUT
        tst  r0, r1
        beq  task_done
        str  r1, [r4, #R_BUFF_STATUS]
        /* a short host packet leaves stale bytes in the 57/59-byte window
         * the reassembler reads; zero them so input stays deterministic */
        ldr  r2, [r5, #D_BC1_OUT]
        ldr  r3, =0x3ff
        ands r2, r2, r3                /* received length */
        cmp  r2, #64
        bcs  15f
        adds r3, r5, #D_EP1_OUT_BUF
14:     movs r6, #0
        strb r6, [r3, r2]
        adds r2, #1
        cmp  r2, #64
        bcc  14b
15:     ldr  r0, =ctaphid_state
        adds r1, r5, #D_EP1_OUT_BUF     /* DPRAM is plain RAM: feed in place */
        bl   ctaphid_feed
        /* re-arm the receiver with the flipped data toggle */
        ldr  r2, =usb_state
        ldr  r3, [r2, #8]
        eors r3, r3, #1
        str  r3, [r2, #8]
        ldr  r2, =BC_AVAIL|64
        cmp  r3, #0
        beq  13f
        ldr  r3, =BC_DATA1
        orrs r2, r2, r3
13:     str  r2, [r5, #D_BC1_OUT]
        b    task_done

task_done:
        pop  {r4, r5, r6, pc}

/* r0 = payload, r1 = len (<=64). Caller waits for tx_done between packets. */
.thumb_func
.global usb_send_ep1
usb_send_ep1:
        push {r4, r5, r6, lr}
        cmp  r1, #64
        bls  1f
        movs r1, #64
1:      ldr  r4, =USB_DPRAM
        adds r5, r4, #D_EP1_IN_BUF
        movs r2, #0
2:      cmp  r2, r1
        bcs  3f
        ldrb r3, [r0, r2]
        strb r3, [r5, r2]
        adds r2, #1
        b    2b
3:      ldr  r5, =usb_state
        ldr  r6, [r5, #12]             /* ep1_in_pid */
        ldr  r2, =BC_AVAIL|BC_FULL
        cmp  r6, #0
        beq  4f
        ldr  r3, =BC_DATA1
        orrs r2, r2, r3
4:      orrs r2, r2, r1
        str  r2, [r4, #D_BC1_IN]
        pop  {r4, r5, r6, pc}
