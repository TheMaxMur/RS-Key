/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* Model-level USB harness: maps the RP2350 USBCTRL register file and DPSRAM
 * as plain memory (qemu-user MAP_FIXED), then runs the asm USB driver
 * against a datasheet-derived model of the SIE. The model owns the
 * write-to-clear status registers — it rewrites them from its shadow each
 * cycle, so the driver's own WC writes (correct for hardware) are absorbed.
 * EP1 OUT packets are delivered explicitly by the test (the host decides
 * when to talk); EP1 IN completes on the next cycle (the host is polling).
 * Hardware execution remains the unverified step. */

#define REGS_BASE 0x50110000u
#define DPRAM_BASE 0x50100000u
#define RESETS_BASE 0x40020000u

#define REG(n) (*(volatile unsigned *)(REGS_BASE + (n)))
#define REGS2(n) (*(volatile unsigned *)(RESETS_BASE + (n)))
#define BC_IN (*(volatile unsigned *)(DPRAM_BASE + 0x80))
#define BC_OUT (*(volatile unsigned *)(DPRAM_BASE + 0x84))
#define BC1_IN (*(volatile unsigned *)(DPRAM_BASE + 0x88))
#define BC1_OUT (*(volatile unsigned *)(DPRAM_BASE + 0x8c))
#define EP1_CTRL_IN (*(volatile unsigned *)(DPRAM_BASE + 0x008))
#define EP1_CTRL_OUT (*(volatile unsigned *)(DPRAM_BASE + 0x00c))
#define EPBUF(i) (*(volatile unsigned char *)(DPRAM_BASE + 0x100 + (i)))
#define EP1_OUT_BUF(i) (*(volatile unsigned char *)(DPRAM_BASE + 0x180 + (i)))
#define EP1_IN_BUF(i) (*(volatile unsigned char *)(DPRAM_BASE + 0x1c0 + (i)))

#define R_ADDR_ENDP 0x00
#define R_MAIN_CTRL 0x40
#define R_SIE_CTRL 0x4c
#define R_SIE_STATUS 0x50
#define R_BUFF_STATUS 0x58
#define R_MUXING 0x74
#define R_PWR 0x78

#define ST_SETUP_REC 0x20000u
#define ST_BUS_RESET 0x80000u
#define BC_AVAIL 0x400u
#define BC_STALL 0x800u
#define BC_DATA1 0x2000u
#define BC_LAST 0x4000u
#define BC_FULL 0x8000u

/* ctaphid reassembler state, as words (asm/ctaphid.S layout) */
#define CS_CID 0
#define CS_CUR 3
#define CS_IN_TX 5
#define CS_EV_TAG 8
#define CS_EV_VAL 9
#define CS_EV_CID 10
#define CS_EV_CMD 11
#define EV_DONE 1
#define EV_ERROR 2
#define ERR_INVALID_SEQ 4

/* tx state (asm/ctaphid_tx.S layout) */
#define CTAPHID_TX_STATE 28

/* init exchange (asm/ctaphid_init.S + asm/ctaphid_tx.S layouts) */
#define CTAPHID_INIT_STATE 4
#define INIT_DATA 7          /* INIT report payload offset (asm/ctaphid_tx.S) */
#define INIT_NONCE_LEN 8     /* nonce field        (asm/ctaphid_init.S)        */
#define INIT_CID_OFF  8      /* newcid[4 LE]      (asm/ctaphid_init.S)         */
#define INIT_IFACE_OFF 12    /* interface version (asm/ctaphid_init.S)         */
#define INIT_VER_OFF  13     /* major/minor/build (+0/+1/+2)                   */
#define INIT_CAPS_OFF 16     /* capability bits   (asm/ctaphid_init.S)         */
#define INIT_RESP_LEN 17     /* full reply length                              */
#define INIT_IFACE 2         /* CTAPHID_IF_VERSION                             */
#define INIT_MAJ 5           /* CI_VERSION_MAJOR                               */
#define INIT_MIN 8           /* CI_VERSION_MINOR                               */
#define INIT_BLD 0           /* CI_VERSION_BUILD                               */
#define CAP_LOCK 0x02        /* capability bits (§11.2.9.3)                    */
#define CAP_CBOR 0x04
#define CAPS_NOWINK 0x06     /* CAP_LOCK|CAP_CBOR: no display in this model    */
#define INIT_BROADCAST_CID 0xffffffffu
#define INIT_CMD 0x86        /* allocation command (CTAP2.1 §11.2.9.4)         */

/* dispatcher command bytes (ctaphid.rs:31-52); MSG is 0x83 — TYPE_INIT|0x03,
 * not the FIDO spec's 0x87 */
#define CMD_LOCK   0x84
#define CMD_MSG    0x83
#define CMD_CBOR   0x90
#define CMD_CANCEL 0x91
#define CMD_ERROR  0xBF
#define CMD_KEEPALIVE 0xBB
/* dispatcher error codes (ctaphid.rs:46-52) */
#define ERRCODE_INVALID_CMD  0x01
#define ERRCODE_INVALID_LEN  0x03
#define ERRCODE_CHANNEL_BUSY 0x06
/* keepalive status bytes (ctaphid.rs:55-58) */
#define KA_PROCESSING 0x01
#define KA_UPNEEDED   0x02

extern void usb_init(void);
extern void usb_task(void);
extern void usb_send_ep1(const unsigned char *buf, unsigned len);
extern void ctaphid_init_init(unsigned *state);
extern unsigned ctaphid_init_run(unsigned *state, const unsigned char *nonce,
                                 unsigned nonce_len, unsigned can_wink,
                                 unsigned char *out17);
extern void ctaphid_tx_init(unsigned *state, unsigned cid, unsigned char cmd,
                            const unsigned char *data, unsigned len);
extern unsigned ctaphid_tx_next(unsigned *state, unsigned char *out);
extern unsigned usb_state[5];       /* pending, configured, out_pid, in_pid, tx_done */
extern unsigned ctaphid_state[12];
extern unsigned char ctaphid_msg[7609];

/* dispatcher verdicts + transport control + worker wait (the asm/ctaphid_
 * {dispatch,ctrl,wait}.S layouts; the same caller-owned states difftest.c
 * mirrors) */
struct lock_state { unsigned cid, until_lo, until_hi; };
struct wait_state { unsigned active, next_lo, next_hi; };
extern unsigned ctaphid_lock_command(const unsigned char *body, unsigned len);
extern unsigned ctaphid_wink(unsigned can_wink);
extern unsigned ctaphid_msg_guard(unsigned cmd, unsigned len);
extern void ctaphid_lock_arm(struct lock_state *st, unsigned cid, unsigned secs,
                             unsigned now_lo, unsigned now_hi);
extern unsigned ctaphid_lock_refuses(struct lock_state *st, unsigned cid,
                                     unsigned cmd, unsigned now_lo, unsigned now_hi);
extern unsigned ctaphid_keepalive_status(unsigned is_cbor, unsigned up_pending);
extern void ctaphid_wait_start(struct wait_state *st, unsigned now_lo, unsigned now_hi);
extern unsigned ctaphid_wait_tick(struct wait_state *st, unsigned now_lo, unsigned now_hi);
extern unsigned ctaphid_wait_frame(unsigned up_pending, const unsigned char *frame,
                                   unsigned n, unsigned cid);
extern void ctaphid_wait_finish(struct wait_state *st);

extern long sys_mmap2(long addr, long len, long prot, long flags, long fd, long off);
extern long sys_write(long fd, const void *buf, long n);

static const unsigned char DEV[18] = {
    0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40,
    0x09, 0x12, 0x01, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00, 0x01,
};
static const unsigned char CFG[41] = {
    0x09, 0x02, 0x29, 0x00, 0x01, 0x01, 0x00, 0x80, 0x19,
    0x09, 0x04, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00,
    0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x21, 0x00,
    0x07, 0x05, 0x81, 0x03, 0x40, 0x00, 0x05,
    0x07, 0x05, 0x01, 0x03, 0x40, 0x00, 0x05,
};
static const unsigned char RPT[33] = {
    0x05, 0xF1, 0x09, 0x00, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00,
    0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09,
    0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40,
    0x91, 0x02, 0xC0,
};
static const unsigned char STR0[4] = { 0x04, 0x03, 0x09, 0x04 };
static const unsigned char STR1[40] = {
    40, 3,
    0x52,0x00, 0x53,0x00, 0x2D,0x00, 0x4B,0x00, 0x65,0x00, 0x79,0x00, 0x20,0x00,
    0x63,0x00, 0x6F,0x00, 0x6E,0x00, 0x74,0x00, 0x72,0x00, 0x69,0x00, 0x62,0x00,
    0x75,0x00, 0x74,0x00, 0x6F,0x00, 0x72,0x00, 0x73,0x00,
};
static const unsigned char STR2[14] = {
    14, 3,
    0x52,0x00, 0x53,0x00, 0x2D,0x00, 0x4B,0x00, 0x65,0x00, 0x79,0x00,
};

static unsigned sie_shadow, buff_shadow;
static int fails;

static void say(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    sys_write(1, s, n);
}

#define CHECK(cond, name) \
    do { if (cond) { say("ok   " name "\n"); } else { fails++; say("FAIL " name "\n"); } } while (0)

static void cycle(void)
{
    REG(R_SIE_STATUS) = sie_shadow;
    REG(R_BUFF_STATUS) = buff_shadow;
    usb_task();
    /* one-shot: an event is visible to exactly one usb_task call, matching
     * what the driver's write-to-clear achieves on hardware */
    sie_shadow = 0;
    buff_shadow = 0;
    if (BC_IN & BC_AVAIL) {
        BC_IN &= ~BC_AVAIL;
        buff_shadow |= 1u;
    }
    if (BC_OUT & BC_AVAIL) {
        BC_OUT &= ~BC_AVAIL;
        buff_shadow |= 2u;
    }
    if (BC1_IN & BC_AVAIL) {
        BC1_IN &= ~BC_AVAIL;
        buff_shadow |= 4u;
    }
}

static void pump(int n)
{
    while (n-- > 0) cycle();
}

static void inject(const unsigned char *s)
{
    volatile unsigned char *d = (volatile unsigned char *)DPRAM_BASE;
    for (int i = 0; i < 8; i++) d[i] = s[i];
    sie_shadow |= ST_SETUP_REC;
}

/* the host sends an EP1 OUT packet into the armed receive buffer */
static void host_send_ep1(const unsigned char *data, int n)
{
    for (int i = 0; i < n; i++) EP1_OUT_BUF(i) = data[i];
    BC1_OUT = (BC1_OUT & ~(BC_AVAIL | 0x3ffu)) | BC_FULL | n;
    buff_shadow |= 8u;
}

static int buf_matches(const unsigned char *exp, int n)
{
    for (int i = 0; i < n; i++)
        if (EPBUF(i) != exp[i]) return 0;
    return 1;
}

static int msg_matches(const unsigned char *exp, int n)
{
    for (int i = 0; i < n; i++)
        if (ctaphid_msg[i] != exp[i]) return 0;
    return 1;
}

/* one CTAPHID frame padded to a 64-byte USB report */
static void ctaphid_packet(unsigned char *p, unsigned cid, int is_init,
                           unsigned char type_or_seq, int bcnt,
                           const unsigned char *data, int dlen)
{
    for (int i = 0; i < 64; i++) p[i] = 0;
    p[0] = cid & 0xff; p[1] = (cid >> 8) & 0xff;
    p[2] = (cid >> 16) & 0xff; p[3] = (cid >> 24) & 0xff;
    p[4] = type_or_seq;
    int off, cap;
    if (is_init) {
        p[5] = (bcnt >> 8) & 0xff; p[6] = bcnt & 0xff;
        off = 7; cap = 57;
    } else {
        off = 5; cap = 59;
    }
    int n = bcnt < cap ? bcnt : cap;
    if (n > dlen) n = dlen;
    for (int i = 0; i < n; i++) p[off + i] = data[i];
}

/* the responder's IN read after the driver sent one frame: the model
 * auto-completes on the next cycle; compare the EP1 IN DPRAM against
 * the frame the TX kernel produced */
static int send_and_read_ep1_in(const unsigned char *frame)
{
    usb_state[4] = 0;                   /* consume the prior completion */
    usb_send_ep1(frame, 64);
    pump(2);
    if (usb_state[4] != 1) return 0;
    int ok = 1;
    for (int i = 0; i < 64; i++)
        if (EP1_IN_BUF(i) != frame[i]) ok = 0;
    return ok;
}

int harness_main(void)
{
    long m = sys_mmap2(DPRAM_BASE, 0x20000, 3, 0x32, -1, 0);
    if ((unsigned long)m > 0xfffff000u) {
        say("FAIL mmap dpram\n");
        return 1;
    }
    m = sys_mmap2(RESETS_BASE, 0x1000, 3, 0x32, -1, 0);
    if ((unsigned long)m > 0xfffff000u) {
        say("FAIL mmap resets\n");
        return 1;
    }
    /* pretend the reset sequencer already finished, so usb_init's poll
     * passes; the pre-set RESET word lets us check the release write */
    REGS2(0x8) = 0x10000000u;
    REGS2(0x0) = 0xffffffffu;

    usb_init();
    CHECK(REGS2(0x0) == 0xefffffffu, "init releases usbctrl reset");
    CHECK(REG(R_MUXING) == 0x9, "init muxing to_phy|softcon");
    CHECK(REG(R_PWR) == 0xc, "init pwr vbus forced");
    CHECK(REG(R_MAIN_CTRL) & 1, "init main_ctrl en");
    CHECK(REG(R_SIE_CTRL) == 0x20010000u, "init pullup + ep0_int_1buf");
    CHECK(REG(R_ADDR_ENDP) == 0, "init addr 0");
    CHECK(EP1_CTRL_OUT == 0xAC000180u, "init ep1 out ctrl");
    CHECK(EP1_CTRL_IN == 0xAC0001C0u, "init ep1 in ctrl");
    CHECK(ctaphid_state[6] == 7609, "init ctaphid buf_max");
    CHECK((unsigned)ctaphid_state[7] == (unsigned)ctaphid_msg, "init ctaphid buf");

    /* device descriptor, full length */
    inject((const unsigned char[]){0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 18, "devdesc len 18");
    CHECK((BC_IN & (BC_FULL | BC_DATA1 | BC_LAST)) == (BC_FULL | BC_DATA1 | BC_LAST), "devdesc full/pid/last");
    CHECK(buf_matches(DEV, 18), "devdesc bytes");
    CHECK(EPBUF(14) == 1 && EPBUF(15) == 2, "devdesc string indices 1/2");

    /* wLength clamp */
    inject((const unsigned char[]){0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x08, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 8, "devdesc clamped to 8");
    CHECK(buf_matches(DEV, 8), "devdesc clamp bytes");

    /* SET_ADDRESS latches after the zero-length IN status stage */
    inject((const unsigned char[]){0x00, 0x05, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(REG(R_ADDR_ENDP) == 5, "set_address 5");

    /* bus reset clears address, configuration and the data toggles */
    sie_shadow |= ST_BUS_RESET;
    pump(1);
    CHECK(REG(R_ADDR_ENDP) == 0, "bus reset clears addr");

    inject((const unsigned char[]){0x00, 0x05, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(REG(R_ADDR_ENDP) == 7, "set_address 7");

    inject((const unsigned char[]){0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(usb_state[1] == 1, "set_config 1");
    CHECK((BC1_OUT & (BC_AVAIL | 0x3ff)) == (BC_AVAIL | 64), "config arms ep1 out");
    CHECK(!(BC1_OUT & BC_DATA1), "first ep1 out is DATA0");

    /* §9.6.2: an address above 0x7F is a request error */
    inject((const unsigned char[]){0x00, 0x05, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK((BC_IN & BC_STALL) && (BC_OUT & BC_STALL), "set_address 0xff stalls");
    CHECK(REG(R_ADDR_ENDP) == 7, "stalled address not latched");

    /* wValue 0x0109 has the same low byte as address 9 but is not one */
    inject((const unsigned char[]){0x00, 0x05, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK((BC_IN & BC_STALL) && (BC_OUT & BC_STALL), "set_address 0x109 stalls");

    /* GET_CONFIGURATION follows the configured state */
    inject((const unsigned char[]){0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 1, "get_configuration len 1");
    CHECK(EPBUF(0) == 1, "get_configuration value 1");

    /* GET_INTERFACE: one interface, alternate setting 0 */
    inject((const unsigned char[]){0x81, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 1, "get_interface len 1");
    CHECK(EPBUF(0) == 0, "get_interface alt 0");

    inject((const unsigned char[]){0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(usb_state[1] == 0, "set_config 0");

    inject((const unsigned char[]){0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 1, "get_configuration after unconfig");
    CHECK(EPBUF(0) == 0, "unconfigured reports 0");

    /* config descriptor */
    inject((const unsigned char[]){0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 0x29, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 41, "cfgdesc len 41");
    CHECK(buf_matches(CFG, 41), "cfgdesc bytes");

    /* HID report descriptor (recipient = interface) */
    inject((const unsigned char[]){0x81, 0x06, 0x00, 0x22, 0x00, 0x00, 0x21, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 33, "reportdesc len 33");
    CHECK(buf_matches(RPT, 33), "reportdesc bytes");

    /* string descriptor 0 (LANGID, US English) */
    inject((const unsigned char[]){0x80, 0x06, 0x00, 0x03, 0x00, 0x00, 0x04, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 4, "str0 langid len 4");
    CHECK(buf_matches(STR0, 4), "str0 langid bytes");

    /* string 0 clamps when wLength < bLength */
    inject((const unsigned char[]){0x80, 0x06, 0x00, 0x03, 0x00, 0x00, 0x02, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 2, "str0 clamped to 2");
    CHECK(buf_matches(STR0, 2), "str0 clamp bytes");

    /* string 1 (manufacturer) */
    inject((const unsigned char[]){0x80, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x40});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 40, "str1 len 40");
    CHECK(buf_matches(STR1, 40), "str1 bytes");

    /* string 2 (product) */
    inject((const unsigned char[]){0x80, 0x06, 0x02, 0x03, 0x00, 0x00, 0x00, 0x40});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 14, "str2 len 14");
    CHECK(buf_matches(STR2, 14), "str2 bytes");

    /* unknown string index stalls both directions */
    inject((const unsigned char[]){0x80, 0x06, 0x07, 0x03, 0x00, 0x00, 0x04, 0x00});
    pump(5);
    CHECK((BC_IN & BC_STALL) && (BC_OUT & BC_STALL), "unknown string index stalls");

    /* GET_STATUS */
    inject((const unsigned char[]){0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00});
    pump(5);
    CHECK((BC_IN & 0x3ff) == 2, "get_status len 2");
    CHECK(EPBUF(0) == 0 && EPBUF(1) == 0, "get_status zeros");

    /* unknown request stalls both directions */
    inject((const unsigned char[]){0x80, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK((BC_IN & BC_STALL) && (BC_OUT & BC_STALL), "unknown stalls");

    /* ---- EP1 data path: configure, then talk CTAPHID over interrupt ---- */
    inject((const unsigned char[]){0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK((BC1_OUT & (BC_AVAIL | 0x3ff)) == (BC_AVAIL | 64), "reconfig rearms ep1 out");

    unsigned char pkt[64];
    unsigned char payload[64];
    for (int i = 0; i < 64; i++) payload[i] = (unsigned char)(i * 7 + 3);

    /* single-packet message completes on the INIT report */
    ctaphid_packet(pkt, 0xA1B2C3D4u, 1, 0x90, 16, payload, 16);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "ep1 single packet done");
    CHECK(ctaphid_state[CS_CUR] == 16, "ep1 single length");
    CHECK(msg_matches(payload, 16), "ep1 single bytes");
    CHECK((BC1_OUT & (BC_AVAIL | BC_DATA1)) == (BC_AVAIL | BC_DATA1), "ep1 out re-armed DATA1");

    /* multi-packet: INIT carries 57, CONT 0 carries the rest */
    ctaphid_packet(pkt, 0xA1B2C3D4u, 1, 0x90, 100, payload, 100);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_IN_TX] == 1, "ep1 mid-transaction");
    CHECK(ctaphid_state[CS_EV_TAG] == 0, "ep1 no event mid-transaction");
    ctaphid_packet(pkt, 0xA1B2C3D4u, 0, 0x00, 100, payload + 57, 43);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "ep1 multi done");
    CHECK(ctaphid_state[CS_CUR] == 100, "ep1 multi length");
    CHECK(msg_matches(payload, 100), "ep1 multi bytes");

    /* out-of-sequence CONT aborts with INVALID_SEQ */
    ctaphid_packet(pkt, 0xA1B2C3D4u, 1, 0x90, 200, payload, 57);
    host_send_ep1(pkt, 64);
    pump(2);
    ctaphid_packet(pkt, 0xA1B2C3D4u, 0, 0x01, 200, payload + 57, 59);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_ERROR, "ep1 bad seq error");
    CHECK(ctaphid_state[CS_EV_VAL] == ERR_INVALID_SEQ, "ep1 bad seq code");

    /* short host packet: the stale DPRAM tail must not reach the message */
    ctaphid_packet(pkt, 0x11223344u, 1, 0x90, 16, payload, 16);
    for (int i = 10; i < 64; i++) pkt[i] = 0xBB;   /* would-be stale bytes */
    host_send_ep1(pkt, 10);                        /* host stops at byte 10 */
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "ep1 short packet done");
    CHECK(ctaphid_state[CS_CUR] == 16, "ep1 short length");
    {
        int stale = 0;
        for (int i = 10; i < 16; i++)
            if (ctaphid_msg[i] != 0) stale = 1;
        CHECK(!stale, "ep1 short tail zeroed");
    }

    /* ---- EP1 IN: transmit with data-toggle tracking ---- */
    usb_send_ep1(payload, 32);
    CHECK((BC1_IN & (BC_AVAIL | BC_FULL | 0x3ff)) == (BC_AVAIL | BC_FULL | 32), "ep1 in armed");
    CHECK(!(BC1_IN & BC_DATA1), "first ep1 in is DATA0");
    pump(2);
    CHECK(usb_state[4] == 1, "ep1 tx_done");
    CHECK(usb_state[3] == 1, "ep1 in pid toggled");

    usb_send_ep1(payload, 32);
    CHECK((BC1_IN & BC_DATA1) != 0, "second ep1 in is DATA1");
    pump(2);
    CHECK(usb_state[4] == 1, "ep1 tx_done again");

    /* tx payload lands in the EP1 IN buffer */
    usb_send_ep1(payload, 8);
    int ok = 1;
    for (int i = 0; i < 8; i++)
        if (EP1_IN_BUF(i) != payload[i]) ok = 0;
    pump(2);
    CHECK(ok, "ep1 in bytes");

    /* bus reset returns the data toggles to DATA0 */
    sie_shadow |= ST_BUS_RESET;
    pump(1);
    CHECK(usb_state[2] == 0 && usb_state[3] == 0, "bus reset clears pids");

    inject((const unsigned char[]){0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(!(BC1_OUT & BC_DATA1), "post-reset ep1 out DATA0");
    usb_send_ep1(payload, 16);
    CHECK(!(BC1_IN & BC_DATA1), "post-reset ep1 in DATA0");
    pump(2);

    /* ---- E2E: host -> EP1 OUT -> ctaphid_feed -> done -> harness
     * echoes via ctaphid_tx + usb_send_ep1 -> model host reads EP1 IN ---- */
    unsigned char txst[CTAPHID_TX_STATE];
    unsigned char frame[64];
    unsigned char data400[400];
    for (int i = 0; i < 400; i++) data400[i] = (unsigned char)(i * 3 + 11);
    unsigned char req32[32];
    for (int i = 0; i < 32; i++) req32[i] = (unsigned char)(i + 100);

    /* (a) single-frame response: host request payload 32b, response 32b
     * (fits in one INIT, seq path = INIT only). The wire INIT byte is
     * cmd|0x80 (CTAP2 §11.2.9.2); the response cmd reuses it, bit 7
     * already set — 0x83 here */
    ctaphid_packet(pkt, 0x5EED5EEDu, 1, 0x83, 32, req32, 32);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "e2e single request done");
    CHECK((unsigned)ctaphid_state[CS_EV_CMD] == (unsigned)0x83u, "e2e single cmd echo");
    ctaphid_tx_init((unsigned*)txst, 0x5EED5EEDu, 0x83, req32, 32);
    CHECK(ctaphid_tx_next((unsigned*)txst, frame) == 1, "e2e single tx frame 1");
    CHECK(!(BC1_IN & BC_DATA1), "e2e single in DATA0 (post-reset pid)");
    CHECK(send_and_read_ep1_in(frame), "e2e single dpram == tx frame");
    CHECK(ctaphid_tx_next((unsigned*)txst, frame) == 0, "e2e single tx exhausted");

    /* (b) 100-byte response crosses 57/59: INIT + 1 CONT (seq 0) */
    ctaphid_packet(pkt, 0x5EED5EEDu, 1, 0x84, 40, data400, 40);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "e2e mid request done");
    ctaphid_tx_init((unsigned*)txst, 0x5EED5EEDu, 0x84, data400, 100);
    CHECK(ctaphid_tx_next((unsigned*)txst, frame) == 1, "e2e multi tx init");
    CHECK(send_and_read_ep1_in(frame), "e2e multi dpram == tx init");
    CHECK(usb_state[3] == 1, "e2e multi pid toggled toward DATA1");
    CHECK(ctaphid_tx_next((unsigned*)txst, frame) == 1, "e2e multi tx cont");
    CHECK(send_and_read_ep1_in(frame), "e2e multi dpram == tx cont");
    CHECK(usb_state[3] == 0, "e2e multi pid back to DATA0 after 2 frames");
    CHECK(ctaphid_tx_next((unsigned*)txst, frame) == 0, "e2e multi tx exhausted");

    /* (c) 400-byte response: INIT + CONT seq 0..5, 6 CONT frames
     * (INIT 57 + 5*59 = 352, tail 48 in CONT5) */
    ctaphid_packet(pkt, 0x5EED5EEDu, 1, 0x85, 20, data400, 20);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "e2e large request done");
    /* INIT 57 + 5 contiguous runs of 59 (293..352) + 48 tail = 7 frames */
    ctaphid_tx_init((unsigned*)txst, 0x5EED5EEDu, 0x85, data400, 400);
    int nframes = 0;
    while (ctaphid_tx_next((unsigned*)txst, frame) == 1) {
        CHECK(send_and_read_ep1_in(frame), "e2e large dpram == tx frame");
        nframes++;
    }
    CHECK(nframes == 7, "e2e large frame count 7");

    /* (d) IN data toggle alternated through the whole exchange above:
     * odd IN completion since the SET_CONFIGURATION just before the
     * section, so the next frame must go out on DATA1 */
    CHECK(usb_state[3] == 1, "e2e toggle odd count leaves pid DATA1");
    usb_send_ep1(frame, 64);
    CHECK(BC1_IN & BC_DATA1, "e2e toggle next in DATA1");
    CHECK(send_and_read_ep1_in(frame), "e2e toggle dpram == tx frame");
    CHECK(usb_state[3] == 0, "e2e toggle flipped back to DATA0");
    inject((const unsigned char[]){0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00});
    pump(5);
    CHECK(usb_state[3] == 0 && usb_state[2] == 0, "e2e set_config resets both pids");
    CHECK(!(BC1_OUT & BC_DATA1), "e2e set_config re-arms out DATA0");

    /* (e) interleaving: a second host->device message after the response
     * completes exercises reassembler state reset; the echo must still
     * match byte-for-byte */
    unsigned char data200[200];
    for (int i = 0; i < 200; i++) data200[i] = (unsigned char)(i * 5 + 77);
    ctaphid_packet(pkt, 0x0BAD5EEDu, 1, 0x86, 12, data200, 12);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "e2e interleave request done");
    CHECK((unsigned)ctaphid_state[CS_EV_CMD] == (unsigned)0x86u, "e2e interleave cmd echo");
    CHECK(ctaphid_state[CS_CUR] == 12, "e2e interleave length");
    CHECK(msg_matches(data200, 12), "e2e interleave bytes");
    ctaphid_tx_init((unsigned*)txst, 0x0BAD5EEDu, 0x86, data200, 150);
    nframes = 0;
    while (ctaphid_tx_next((unsigned*)txst, frame) == 1) {
        CHECK(send_and_read_ep1_in(frame), "e2e interleave dpram == tx frame");
        nframes++;
    }
    CHECK(nframes == 3, "e2e interleave frame count 3");
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "e2e interleave rx still settled");
    CHECK(ctaphid_state[CS_CID] == 0x0BAD5EEDu, "e2e interleave rx cid holds new channel");

    /* ---- E2E: INIT allocation (CTAP2.1 §11.2.9.1.3/§11.2.9.4) — the full
     * exchange: broadcast INIT demand -> reassembler done -> allocation
     * kernel -> TX kernel -> EP1 IN -> model host reads the reply. The
     * reply to a broadcast INIT is itself broadcast. ---- */
    unsigned char initst[CTAPHID_INIT_STATE];
    /* the caller-owned next_cid the allocation kernel persists in
     * (asm/ctaphid_init.S state layout) */
    ctaphid_init_init((unsigned *)initst);

    /* (i) broadcast INIT demand: cid 0xffffffff may only carry 0x86, and the
     * reassembler must complete it on the nonce */
    unsigned char nonce1[INIT_NONCE_LEN] = {
        0xA0, 0x14, 0x62, 0x7B, 0xC5, 0x08, 0x3D, 0xE1
    };
    ctaphid_packet(pkt, INIT_BROADCAST_CID, 1, INIT_CMD, INIT_NONCE_LEN,
                   nonce1, INIT_NONCE_LEN);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "init e2e request done");
    CHECK((unsigned)ctaphid_state[CS_EV_CMD] == (unsigned)INIT_CMD, "init e2e cmd 0x86");
    CHECK(msg_matches(nonce1, INIT_NONCE_LEN), "init e2e nonce reassembled");
    CHECK(ctaphid_state[CS_CUR] == INIT_NONCE_LEN, "init e2e length");

    /* (ii) the allocation kernel composes the 17-byte reply into the caller's
     * buffer; the TX kernel frames it, the model host reads it out of DPRAM.
     * The field asserts below make a layout corruption visible even if the
     * whole-copy above is clean */
    unsigned char resp17[INIT_RESP_LEN];
    CHECK(ctaphid_init_run((unsigned *)initst, nonce1, INIT_NONCE_LEN, 0, resp17) == 1,
          "init e2e run ok");
    ctaphid_tx_init((unsigned *)txst, INIT_BROADCAST_CID, INIT_CMD, resp17, INIT_RESP_LEN);
    CHECK(ctaphid_tx_next((unsigned *)txst, frame) == 1, "init e2e tx frame 1");
    CHECK(send_and_read_ep1_in(frame), "init e2e dpram == tx frame");
    CHECK(frame[0] == 0xff && frame[1] == 0xff && frame[2] == 0xff &&
          frame[3] == 0xff, "init reply broadcast cid");
    CHECK(frame[4] == INIT_CMD, "init reply type 0x86");
    CHECK(frame[5] == 0 && frame[6] == INIT_RESP_LEN, "init reply bcnt 17");
    /* report payload = INIT_DATA + reply offset */
    for (int i = 0; i < INIT_NONCE_LEN; i++)
        CHECK(frame[INIT_DATA + i] == nonce1[i], "init reply nonce echo");
    CHECK(frame[INIT_DATA + INIT_CID_OFF + 0] == 0x00 &&
          frame[INIT_DATA + INIT_CID_OFF + 1] == 0x00 &&
          frame[INIT_DATA + INIT_CID_OFF + 2] == 0x00 &&
          frame[INIT_DATA + INIT_CID_OFF + 3] == 0x01,
          "init reply first cid 0x01000000");
    CHECK(frame[INIT_DATA + INIT_IFACE_OFF] == INIT_IFACE, "init reply iface 2");
    CHECK(frame[INIT_DATA + INIT_VER_OFF + 0] == INIT_MAJ &&
          frame[INIT_DATA + INIT_VER_OFF + 1] == INIT_MIN &&
          frame[INIT_DATA + INIT_VER_OFF + 2] == INIT_BLD, "init reply version 5.8.0");
    CHECK(frame[INIT_DATA + INIT_CAPS_OFF] == CAPS_NOWINK, "init reply caps LOCK|CBOR");

    /* (iv, first half) the stored toggle is the pid of the NEXT IN frame:
     * the interleave echo's 3 frames since SET_CONFIGURATION left it armed
     * for DATA1, so this response went out on DATA1 and the toggle is now
     * armed for DATA0 */
    CHECK(usb_state[3] == 0, "init e2e toggle armed DATA0 after first response");

    /* (iii) different nonce, same broadcast channel: the counter is caller
     * state, so it must persist across the whole section */
    unsigned char nonce2[INIT_NONCE_LEN] = {
        0x47, 0x39, 0xE6, 0x1C, 0x88, 0xB2, 0x05, 0xA9
    };
    ctaphid_packet(pkt, INIT_BROADCAST_CID, 1, INIT_CMD, INIT_NONCE_LEN,
                   nonce2, INIT_NONCE_LEN);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "init e2e second request done");
    CHECK(msg_matches(nonce2, INIT_NONCE_LEN), "init e2e second nonce");
    unsigned char resp17b[INIT_RESP_LEN];
    CHECK(ctaphid_init_run((unsigned *)initst, nonce2, INIT_NONCE_LEN, 0, resp17b) == 1,
          "init e2e second run ok");
    ctaphid_tx_init((unsigned *)txst, INIT_BROADCAST_CID, INIT_CMD, resp17b, INIT_RESP_LEN);
    CHECK(ctaphid_tx_next((unsigned *)txst, frame) == 1, "init second tx frame 1");
    CHECK(send_and_read_ep1_in(frame), "init second dpram == tx frame");
    for (int i = 0; i < INIT_NONCE_LEN; i++)
        CHECK(frame[INIT_DATA + i] == nonce2[i], "init second nonce echo");
    CHECK(frame[INIT_DATA + INIT_CID_OFF + 0] == 0x01 &&
          frame[INIT_DATA + INIT_CID_OFF + 1] == 0x00 &&
          frame[INIT_DATA + INIT_CID_OFF + 2] == 0x00 &&
          frame[INIT_DATA + INIT_CID_OFF + 3] == 0x01,
          "init second cid 0x01000001");
    CHECK(ctaphid_tx_next((unsigned *)txst, frame) == 0, "init e2e tx exhausted");

    /* (iv, second half) the IN data toggle kept alternating through the
     * two INIT responses: the second went out on DATA0 and the stored
     * toggle is armed back on DATA1 */
    CHECK(usb_state[3] == 1, "init e2e toggle armed DATA1 after 2 responses");

    /* ---- E2E: the full transport stack — the dispatcher verdicts and the
     * worker-wait cadence over EP1, the INIT e2e one layer up: host ->
     * EP1 OUT -> reassembler done -> verdict / cadence -> CTAPHID_ERROR or
     * CTAPHID_KEEPALIVE or the response, framed through the TX kernel ->
     * EP1 IN. The lock and wait states are the kernels' caller-owned
     * structs, exactly as difftest.c drives them. ---- */
    struct lock_state lks = {0, 0, 0};
    struct wait_state wst = {0, 0, 0};
    unsigned lcid = 0xCAFE0001u, ocid = 0xCAFE0002u;
    unsigned char one[1] = {5};

    /* (a) LOCK arms and answers empty: verdict, arm at now_ms 100, the
     * zero-length reply is the TX kernel's always-at-least-INIT contract */
    ctaphid_packet(pkt, lcid, 1, CMD_LOCK, 1, one, 1);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "stack e2e lock request done");
    CHECK(ctaphid_state[CS_CUR] == 1 && ctaphid_msg[0] == 5, "stack e2e lock body 1 byte, secs 5");
    CHECK(ctaphid_lock_command(ctaphid_msg, ctaphid_state[CS_CUR]) == 0, "stack e2e lock verdict arm");
    ctaphid_lock_arm(&lks, lcid, 5, 100, 0);
    ctaphid_tx_init((unsigned *)txst, lcid, CMD_LOCK, one, 0);
    CHECK(ctaphid_tx_next((unsigned *)txst, frame) == 1, "stack e2e lock reply one INIT frame");
    CHECK(send_and_read_ep1_in(frame), "stack e2e lock dpram == tx frame");
    CHECK(frame[0] == 0x01 && frame[1] == 0x00 && frame[2] == 0xfe && frame[3] == 0xca,
          "stack e2e lock reply cid");
    CHECK(frame[4] == CMD_LOCK && frame[5] == 0 && frame[6] == 0, "stack e2e lock reply bcnt 0");
    CHECK(ctaphid_tx_next((unsigned *)txst, frame) == 0, "stack e2e lock tx exhausted");
    CHECK(usb_state[3] == 0, "stack e2e toggle armed DATA0 after lock reply");

    /* (b) a second host's MSG while locked earns CHANNEL_BUSY; the owner
     * routes, and at the just-expired instant (now == until, armed 5 s at
     * now_ms 100) the lock is already gone */
    ctaphid_packet(pkt, ocid, 1, CMD_MSG, 4, one, 0);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "stack e2e msg request done");
    CHECK(ctaphid_lock_refuses(&lks, ocid, CMD_MSG, 1000, 0) == 1, "stack e2e lock refuses the second host");
    CHECK(ctaphid_lock_refuses(&lks, lcid, CMD_CBOR, 1000, 0) == 0, "stack e2e owner routes while locked");
    CHECK(ctaphid_lock_refuses(&lks, ocid, CMD_CBOR, 5099, 0) == 1, "stack e2e still locked at 5099");
    CHECK(ctaphid_lock_refuses(&lks, ocid, CMD_CBOR, 5100, 0) == 0, "stack e2e expired at the boundary");
    one[0] = ERRCODE_CHANNEL_BUSY;
    ctaphid_tx_init((unsigned *)txst, ocid, CMD_ERROR, one, 1);
    CHECK(ctaphid_tx_next((unsigned *)txst, frame) == 1, "stack e2e busy error one frame");
    CHECK(send_and_read_ep1_in(frame), "stack e2e busy dpram == tx frame");
    CHECK(frame[4] == CMD_ERROR && frame[5] == 0 && frame[6] == 1 && frame[7] == ERRCODE_CHANNEL_BUSY,
          "stack e2e busy error frame 0xbf/06");
    CHECK(ctaphid_tx_next((unsigned *)txst, frame) == 0, "stack e2e busy tx exhausted");

    /* (c) WINK without an indicator is INVALID_CMD */
    CHECK(ctaphid_wink(0) == 1, "stack e2e wink refused without an indicator");
    one[0] = ERRCODE_INVALID_CMD;
    ctaphid_tx_init((unsigned *)txst, lcid, CMD_ERROR, one, 1);
    CHECK(ctaphid_tx_next((unsigned *)txst, frame) == 1, "stack e2e wink error one frame");
    CHECK(send_and_read_ep1_in(frame), "stack e2e wink dpram == tx frame");
    CHECK(frame[4] == CMD_ERROR && frame[7] == ERRCODE_INVALID_CMD, "stack e2e wink error frame 0xbf/01");

    /* (d) an empty CBOR message is INVALID_LEN; the reassembler completes
     * the zero-bcnt INIT frame, the guard refuses it */
    ctaphid_packet(pkt, lcid, 1, CMD_CBOR, 0, one, 0);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "stack e2e empty cbor done");
    CHECK(ctaphid_state[CS_CUR] == 0, "stack e2e empty cbor length 0");
    CHECK(ctaphid_msg_guard(CMD_CBOR, 0) == 1, "stack e2e empty cbor refused");
    one[0] = ERRCODE_INVALID_LEN;
    ctaphid_tx_init((unsigned *)txst, lcid, CMD_ERROR, one, 1);
    CHECK(ctaphid_tx_next((unsigned *)txst, frame) == 1, "stack e2e cbor error one frame");
    CHECK(send_and_read_ep1_in(frame), "stack e2e cbor dpram == tx frame");
    CHECK(frame[4] == CMD_ERROR && frame[7] == ERRCODE_INVALID_LEN, "stack e2e cbor error frame 0xbf/03");

    /* (e) a CBOR request enters the worker wait: one keepalive per 100 ms
     * deadline, PROCESSING off the touch wait and UPNEEDED on it, both out
     * EP1 IN */
    unsigned char cborbody[4] = {0x01, 0xA2, 0x03, 0xB4};
    ctaphid_packet(pkt, lcid, 1, CMD_CBOR, 4, cborbody, 4);
    host_send_ep1(pkt, 64);
    pump(2);
    CHECK(ctaphid_state[CS_EV_TAG] == EV_DONE, "stack e2e wait request done");
    CHECK(ctaphid_msg_guard(CMD_CBOR, ctaphid_state[CS_CUR]) == 0, "stack e2e wait cbor routes");
    ctaphid_wait_start(&wst, 0, 0);
    CHECK(ctaphid_wait_tick(&wst, 50, 0) == 0, "stack e2e nothing before the deadline");
    CHECK(ctaphid_wait_tick(&wst, 100, 0) == 1, "stack e2e deadline due");
    CHECK(ctaphid_keepalive_status(1, 0) == KA_PROCESSING, "stack e2e processing status");
    one[0] = KA_PROCESSING;
    ctaphid_tx_init((unsigned *)txst, lcid, CMD_KEEPALIVE, one, 1);
    CHECK(ctaphid_tx_next((unsigned *)txst, frame) == 1, "stack e2e ka processing one frame");
    CHECK(send_and_read_ep1_in(frame), "stack e2e ka processing dpram == tx frame");
    CHECK(frame[4] == CMD_KEEPALIVE && frame[5] == 0 && frame[6] == 1 && frame[7] == KA_PROCESSING,
          "stack e2e ka frame 0xbb/01");
    CHECK(ctaphid_wait_tick(&wst, 100, 0) == 0, "stack e2e next deadline not due yet");
    CHECK(ctaphid_wait_tick(&wst, 200, 0) == 1, "stack e2e second deadline due");
    CHECK(ctaphid_keepalive_status(1, 1) == KA_UPNEEDED, "stack e2e upneeded status");
    one[0] = KA_UPNEEDED;
    ctaphid_tx_init((unsigned *)txst, lcid, CMD_KEEPALIVE, one, 1);
    CHECK(ctaphid_tx_next((unsigned *)txst, frame) == 1, "stack e2e ka upneeded one frame");
    CHECK(send_and_read_ep1_in(frame), "stack e2e ka upneeded dpram == tx frame");
    CHECK(frame[4] == CMD_KEEPALIVE && frame[7] == KA_UPNEEDED, "stack e2e ka frame 0xbb/02");

    /* (f) the touch goes pending: a CANCEL on the waiting channel signals
     * the worker, one on a foreign channel is dropped; the raw frames go
     * straight to the wait window — the driver never reassembles them, so
     * no pump runs and the OUT buffer is consumed by the watch read,
     * exactly the firmware's reader split */
    unsigned char watch[64];
    ctaphid_packet(pkt, ocid, 1, CMD_CANCEL, 0, one, 0);
    host_send_ep1(pkt, 64);
    for (int i = 0; i < 64; i++) watch[i] = EP1_OUT_BUF(i);
    BC1_OUT &= ~(BC_FULL | 0x3ffu);
    buff_shadow &= ~8u;
    CHECK(ctaphid_wait_frame(1, watch, 64, lcid) == 1, "stack e2e foreign cancel drops");
    ctaphid_packet(pkt, lcid, 1, CMD_CANCEL, 0, one, 0);
    host_send_ep1(pkt, 64);
    for (int i = 0; i < 64; i++) watch[i] = EP1_OUT_BUF(i);
    BC1_OUT &= ~(BC_FULL | 0x3ffu);
    buff_shadow &= ~8u;
    CHECK(ctaphid_wait_frame(1, watch, 64, lcid) == 2, "stack e2e own cancel signals");
    CHECK(ctaphid_wait_frame(0, watch, 64, lcid) == 0, "stack e2e off the touch wait it queues");

    /* (g) the worker answers the cancelled touch with CTAP2_ERR_KEEPALIVE_
     * CANCEL in the CBOR response; the wait ends and the cadence with it */
    ctaphid_wait_finish(&wst);
    CHECK(ctaphid_wait_tick(&wst, 9999, 0) == 0, "stack e2e finished wait never due");
    one[0] = 0x2d; /* CTAP2_ERR_KEEPALIVE_CANCEL (rsk-fido/src/error.rs:31) */
    ctaphid_tx_init((unsigned *)txst, lcid, CMD_CBOR, one, 1);
    CHECK(ctaphid_tx_next((unsigned *)txst, frame) == 1, "stack e2e response one frame");
    CHECK(send_and_read_ep1_in(frame), "stack e2e response dpram == tx frame");
    CHECK(frame[4] == CMD_CBOR && frame[7] == 0x2d, "stack e2e response 0x90/0x2d");
    CHECK(ctaphid_tx_next((unsigned *)txst, frame) == 0, "stack e2e response tx exhausted");

    /* (h) a U2F fast op stays silent: the deadline is due but the status
     * is None, so nothing goes out EP1 IN */
    ctaphid_wait_start(&wst, 0, 0);
    CHECK(ctaphid_wait_tick(&wst, 100, 0) == 1, "stack e2e u2f deadline due");
    CHECK(ctaphid_keepalive_status(0, 0) == 0, "stack e2e u2f fast op stays silent");
    ctaphid_wait_finish(&wst);

    /* the whole section sent seven IN frames since the INIT pair left the
     * toggle armed DATA1: lock reply, busy error, wink error, cbor error,
     * two keepalives, the response — an odd count, so the toggle is armed
     * back on DATA0 */
    CHECK(usb_state[3] == 0, "stack e2e toggle armed DATA0 after seven IN frames");

    say(fails ? "USB MODEL TESTS: FAILED\n" : "USB MODEL TESTS: PASSED\n");
    return fails;
}
