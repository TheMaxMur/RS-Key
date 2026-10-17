/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

/* Differential harness: one 64-byte CTAPHID report per stdin line (128 hex
 * chars, '#' comments); feeds each to asm/ctaphid.S and prints the event
 * stream. "T <cid> <cmd> <payload-hex>" lines instead drive asm/ctaphid_tx.S
 * and print the resulting frame stream. The Rust oracle over rsk-usb's
 * Reassembler / TxFrames prints the identical format; the two outputs must
 * be byte-identical. Input is streamed line-by-line so no input size is
 * silently truncated. */

struct state {
    unsigned cid, cmd, bcnt, cur, seq, in_tx, buf_max;
    unsigned char *buf;
    unsigned ev_tag, ev_val, ev_cid, ev_cmd;
};

/* mirror of asm/ctaphid_tx.S's caller-owned state */
struct tx_state {
    unsigned cid, cmd;
    const unsigned char *data;
    unsigned len, off, seq, started;
};

/* mirror of asm/ctaphid_init.S's caller-owned state */
struct init_state {
    unsigned next_cid;
};

/* mirror of asm/ctaphid_ctrl.S's caller-owned lock state: cid plus the
 * until_ms u64 split into two words (until_lo/until_hi), zero-init */
struct lock_state {
    unsigned cid;
    unsigned until_lo;
    unsigned until_hi;
};

/* mirror of asm/ctaphid_wait.S's caller-owned worker-wait state: whether a
 * request is in flight plus the next KEEPALIVE deadline as a u64 split into
 * two words, zero-init */
struct wait_state {
    unsigned active;
    unsigned next_lo;
    unsigned next_hi;
};

#define MSG_CAP 7609 /* CTAP_MAX_MESSAGE: 57 + 128*59 */

extern void ctaphid_feed(struct state *st, const unsigned char *rpt);
extern void ctaphid_tx_init(struct tx_state *st, unsigned cid, unsigned cmd,
                            const unsigned char *data, unsigned len);
extern unsigned ctaphid_tx_next(struct tx_state *st, unsigned char *out);
extern void ctaphid_init_init(struct init_state *st);
extern unsigned ctaphid_init_run(struct init_state *st,
                                 const unsigned char *nonce, unsigned nonce_len,
                                 unsigned can_wink, unsigned char *out17);
extern unsigned ctaphid_lock_command(const unsigned char *body, unsigned len);
extern unsigned ctaphid_wink(unsigned can_wink);
extern unsigned ctaphid_msg_guard(unsigned cmd, unsigned len);
extern unsigned ctaphid_unknown(unsigned cmd);
extern void ctaphid_wait_start(struct wait_state *st, unsigned now_lo, unsigned now_hi);
extern unsigned ctaphid_wait_tick(struct wait_state *st, unsigned now_lo, unsigned now_hi);
extern unsigned ctaphid_wait_frame(unsigned up_pending, const unsigned char *frame,
                                   unsigned n, unsigned cid);
extern void ctaphid_wait_finish(struct wait_state *st);
extern unsigned ccid_process(const unsigned char *msg, unsigned msg_len,
                             const unsigned char *atr, unsigned atr_len,
                             unsigned char *status, unsigned char *out,
                             unsigned out_cap);
extern unsigned ccid_xfr_apdu(const unsigned char *msg, unsigned len, unsigned *range);
extern unsigned ccid_secure_apdu(const unsigned char *msg, unsigned len, unsigned *range);
extern void ccid_put_header(unsigned char *out, unsigned msg_type, unsigned length,
                            unsigned seq, unsigned status);
extern long sys_read(long fd, void *buf, long n);
extern long sys_write(long fd, const void *buf, long n);

static struct state st;
static struct tx_state txs;
static struct init_state inis;
static struct lock_state lks;
static struct wait_state wst;
static unsigned char msgbuf[MSG_CAP];
static unsigned char paybuf[MSG_CAP];
static unsigned char tframe[64];
static unsigned char qbody[MSG_CAP]; /* body slots for the Q dispatch line */
static unsigned char codebuf[1];
static unsigned long long cur_now;    /* clock for Q lock guards (last L line) */
static unsigned wait_up, wait_cbor;   /* the worker's touch flag; the applet in flight */

/* CCID (M13): the slot's bStatus and the ATR the card presents on power-on.
 * The defaults are an unpowered slot (STATUS_INACTIVE) and ATR_RSKEY
 * (ccid.rs:100), byte-pinned by the differential, not restated in a mirror. */
static unsigned char ccid_status = 1;
static unsigned char ccid_atr[256] = {
    0x3b, 0xfc, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x15, 0x80, 0x73, 0xc0,
    0x21, 0xc0, 0x56, 0x52, 0x53, 0x2d, 0x4b, 0x65, 0x79, 0x4b,
};
static unsigned ccid_atr_len = 22;
static unsigned char ccid_out[2048]; /* MAX_CCID_MSG, the reply slice */

/* any real line fits with two orders of magnitude to spare: the longest is
 * a maximum-size T payload at ~15.3 KB */
static unsigned char inbuf[1 << 20];

/* CTAPHID framing offsets, mirroring asm/ctaphid.S. */
#define RPT_CMD     0
#define RPT_CID     1
#define RPT_BCNT_HI 5
#define RPT_BCNT_LO 6

/* CTAPHID command bytes the dispatcher keys on (ctaphid.rs:31-52); MSG is
 * 0x83 here, not the FIDO spec's 0x87 — the shipping const is TYPE_INIT|0x03
 * and 0x87 falls to the unknown-command verdict */
#define CMD_PING   0x81
#define CMD_LOCK   0x84
#define CMD_MSG    0x83
#define CMD_WINK   0x88
#define CMD_CBOR   0x90
#define CMD_CANCEL 0x91
#define CMD_ERROR  0xBF
/* dispatcher error verdicts, returned as the Q code byte (ctaphid.rs:46-52) */
#define Q_INVALID_CMD  0x01
#define Q_INVALID_PAR  0x02
#define Q_INVALID_LEN  0x03
#define Q_CHANNEL_BUSY 0x06

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned char *hex2(unsigned char *p, unsigned v)
{
    static const char d[] = "0123456789abcdef";
    *p++ = d[(v >> 4) & 0xf];
    *p++ = d[v & 0xf];
    return p;
}

static unsigned char *hexp(unsigned char *p, unsigned v)
{
    /* plain hex, no leading zeros — matches the oracle's {:x} */
    static const char d[] = "0123456789abcdef";
    int started = 0;
    for (int i = 7; i >= 0; i--) {
        unsigned n = (v >> (4 * i)) & 0xf;
        if (n || started || i == 0) {
            *p++ = d[n];
            started = 1;
        }
    }
    return p;
}

static unsigned char *hex8(unsigned char *p, unsigned v)
{
    static const char d[] = "0123456789abcdef";
    for (int i = 7; i >= 0; i--) *p++ = d[(v >> (4 * i)) & 0xf];
    return p;
}

static unsigned char *hexn(unsigned char *p, const unsigned char *b, unsigned n)
{
    static const char d[] = "0123456789abcdef";
    for (unsigned i = 0; i < n; i++) {
        *p++ = d[b[i] >> 4];
        *p++ = d[b[i] & 0xf];
    }
    return p;
}

/* bare decimal, no padding — the oracle's "{}" formatting */
static unsigned char *decn(unsigned char *p, unsigned v)
{
    char tmp[10];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n) *p++ = (unsigned char)tmp[--n];
    return p;
}

static void emit(const unsigned char *p, unsigned len)
{
    sys_write(1, p, len);
}

/* the control lines are whitespace-separated; replicate Rust's split(' ')
 * exactly so parsed field counts agree on malformed input (consecutive
 * spaces → empty fields). The outer trim() leaves no leading/trailing
 * separators, so `("a b c") -> 3` and `("a  b") -> 3` with an empty middle. */
#define MAX_FIELDS 6
struct field {
    const unsigned char *p;
    unsigned len;
};
static unsigned split_fields(const unsigned char *p, const unsigned char *eol,
                             struct field *out, unsigned max)
{
    const unsigned char *q = p;
    unsigned n = 0;
    while (q <= eol) {
        const unsigned char *s = q;
        while (q < eol && *q != ' ') q++;
        if (n < max) {
            out[n].p = s;
            out[n].len = (unsigned)(q - s);
        }
        n++;
        if (q >= eol) break;
        q++;
    }
    return n;
}

/* decimal u64, no libc: any non-digit or >u64::MAX overflows cleanly, which
 * X-parses exactly where Rust's u64::from_str returns Err. The overflow guard
 * uses compile-time constants for u64::MAX/10 = 1844674407370955161 and
 * u64::MAX%10 = 5 — not runtime division, which would drag in __aeabi_uldivmod
 * that this freestanding harness has no libc to satisfy. */
#define U64_MAX_DIV10 1844674407370955161ULL
#define U64_MAX_MOD10 5
static int parse_dec_u64(const unsigned char *p, unsigned len, unsigned long long *v)
{
    unsigned long long x = 0;
    if (len == 0) return 0;
    for (unsigned i = 0; i < len; i++) {
        if (p[i] < '0' || p[i] > '9') return 0;
        unsigned d = (unsigned)(p[i] - '0');
        if (x > U64_MAX_DIV10 || (x == U64_MAX_DIV10 && d > U64_MAX_MOD10))
            return 0;
        x = x * 10 + d;
    }
    *v = x;
    return 1;
}

/* decimal u32 within [0, bound]; the cancel n and arm secs fields are bounded
 * up front so an out-of-range value X-parses identically on both sides */
static int parse_dec_u32_bounded(const unsigned char *p, unsigned len,
                                 unsigned long long bound, unsigned *v)
{
    unsigned long long x;
    if (!parse_dec_u64(p, len, &x) || x > bound) return 0;
    *v = (unsigned)x;
    return 1;
}

static int parse_hex_u32(const unsigned char *p, unsigned len, unsigned *v)
{
    if (len != 8) return 0;
    unsigned x = 0;
    for (unsigned i = 0; i < 8; i++) {
        int n = hexval(p[i]);
        if (n < 0) return 0;
        x = (x << 4) | (unsigned)n;
    }
    *v = x;
    return 1;
}

static int parse_hex_byte(const unsigned char *p, unsigned len, unsigned char *v)
{
    if (len != 2) return 0;
    int hi = hexval(p[0]), lo = hexval(p[1]);
    if (hi < 0 || lo < 0) return 0;
    *v = (unsigned char)((hi << 4) | lo);
    return 1;
}

static int parse_hex_n(const unsigned char *p, unsigned len, unsigned char *out)
{
    if (len & 1) return 0;
    for (unsigned i = 0; i < len; i += 2) {
        int hi = hexval(p[i]), lo = hexval(p[i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

extern unsigned ctaphid_keepalive_status(unsigned is_cbor, unsigned up_pending);
extern unsigned ctaphid_is_cancel(const unsigned char *frame, unsigned n,
                                  unsigned cid);
extern void ctaphid_lock_arm(struct lock_state *st, unsigned cid, unsigned secs,
                             unsigned now_lo, unsigned now_hi);
extern unsigned ctaphid_lock_refuses(struct lock_state *st, unsigned cid,
                                     unsigned cmd, unsigned now_lo,
                                     unsigned now_hi);

static void parse_error(void)
{
    emit((const unsigned char *)"X parse\n", 8);
}

static void process_line(unsigned char *p, unsigned char *eol)
{
    unsigned char rpt[64];
    unsigned char out[2 * MSG_CAP + 64];

    while (p < eol && (*p == ' ' || *p == '\t' || *p == '\r')) p++;
    /* mirror the oracle's trim(): trailing whitespace too, so \r\n and
     * padded lines parse identically on both sides */
    while (eol > p && (eol[-1] == ' ' || eol[-1] == '\t' || eol[-1] == '\r')) eol--;
    if (p >= eol || *p == '#') return;

    if (*p == 'T' && p + 1 < eol && *(p + 1) == ' ') {
        p += 2;
        unsigned cid = 0, cmd = 0, plen = 0;
        int ok = 1;
        for (int i = 0; i < 8 && ok; i++) {
            int v = (p < eol) ? hexval(*p++) : -1;
            if (v < 0) ok = 0; else cid = (cid << 4) | v;
        }
        if (ok && p < eol && *p == ' ') p++; else ok = 0;
        for (int i = 0; i < 2 && ok; i++) {
            int v = (p < eol) ? hexval(*p++) : -1;
            if (v < 0) ok = 0; else cmd = (cmd << 4) | v;
        }
        if (ok && p == eol) {
            /* empty payload: the bare INIT */
        } else if (ok && p < eol && *p == ' ') {
            p++;
            while (p < eol) {
                int hi = hexval(*p++);
                int lo = (p < eol) ? hexval(*p++) : -1;
                if (hi < 0 || lo < 0 || plen >= MSG_CAP) { ok = 0; break; }
                paybuf[plen++] = (unsigned char)((hi << 4) | lo);
            }
        } else {
            ok = 0;
        }
        if (!ok) {
            emit((const unsigned char *)"X parse\n", 8);
            return;
        }
        ctaphid_tx_init(&txs, cid, cmd, paybuf, plen);
        unsigned n = 0;
        while (n < 256 && ctaphid_tx_next(&txs, tframe)) {
            unsigned char *o = out;
            *o++ = 'F'; *o++ = ' ';
            o = hexn(o, tframe, 64);
            *o++ = '\n';
            emit(out, o - out);
            n++;
        }
        if (n == 256) emit((const unsigned char *)"X runaway\n", 10);
        return;
    }

    if (*p == 'I' && p + 1 < eol && *(p + 1) == ' ') {
        p += 2;
        int can_wink, ok = 1;
        if (p < eol && (*p == '0' || *p == '1')) {
            can_wink = (*p == '1');
            p++;
        } else {
            ok = 0;
        }
        if (ok && p < eol && *p == ' ') p++; else ok = 0;
        unsigned char nonce[8];
        for (int i = 0; i < 8 && ok; i++) {
            int hi = (p < eol) ? hexval(*p++) : -1;
            int lo = (p < eol) ? hexval(*p++) : -1;
            if (hi < 0 || lo < 0) ok = 0; else nonce[i] = (unsigned char)((hi << 4) | lo);
        }
        if (ok && p != eol) ok = 0; /* nonce must be exactly 8 bytes */
        if (!ok) {
            emit((const unsigned char *)"X parse\n", 8);
            return;
        }
        unsigned char out17[17];
        ctaphid_init_run(&inis, nonce, 8, can_wink, out17);
        ctaphid_tx_init(&txs, 0xffffffffu, 0x86, out17, 17);
        unsigned n = 0;
        while (n < 256 && ctaphid_tx_next(&txs, tframe)) {
            unsigned char *o = out;
            *o++ = 'F'; *o++ = ' ';
            o = hexn(o, tframe, 64);
            *o++ = '\n';
            emit(out, o - out);
            n++;
        }
        return;
    }

    /* keepalive status: "K <is_cbor 0|1> <up_pending 0|1>" -> "S 00|01|02" */
    if (*p == 'K' && p + 1 < eol && *(p + 1) == ' ') {
        struct field f[MAX_FIELDS];
        unsigned nf = split_fields(p + 2, eol, f, MAX_FIELDS);
        if (nf != 2 || f[0].len != 1 || f[1].len != 1 ||
            !((f[0].p[0] == '0' || f[0].p[0] == '1') &&
              (f[1].p[0] == '0' || f[1].p[0] == '1'))) {
            parse_error();
            return;
        }
        unsigned r = ctaphid_keepalive_status(
            (unsigned)(f[0].p[0] - '0'), (unsigned)(f[1].p[0] - '0'));
        unsigned char *o = out;
        *o++ = 'S'; *o++ = ' ';
        o = hex2(o, r);
        *o++ = '\n';
        emit(out, o - out);
        return;
    }

    /* cancel detection: "C <128-hex frame> <n dec> <cid 8-hex>" -> "C 0|1" */
    if (*p == 'C' && p + 1 < eol && *(p + 1) == ' ') {
        struct field f[MAX_FIELDS];
        unsigned nf = split_fields(p + 2, eol, f, MAX_FIELDS);
        unsigned char frame[64], cmd;
        unsigned n, cid;
        int ok = nf == 3 && f[0].len == 128 && parse_hex_n(f[0].p, f[0].len, frame) &&
                 parse_dec_u32_bounded(f[1].p, f[1].len, 64, &n) &&
                 parse_hex_u32(f[2].p, f[2].len, &cid);
        if (!ok) {
            parse_error();
            return;
        }
        unsigned r = ctaphid_is_cancel(frame, n, cid);
        unsigned char *o = out;
        *o++ = 'C'; *o++ = ' ';
        *o++ = (unsigned char)('0' + r); *o++ = '\n';
        emit(out, o - out);
        return;
    }

    /* channel lock: "L arm <cid 8-hex> <secs dec> <now_ms dec>" persists the
     * lock state; "L refuse <cid 8-hex> <cmd 2-hex> <now_ms dec>" -> "R 0|1". */
    if (*p == 'L' && p + 1 < eol && *(p + 1) == ' ') {
        struct field f[MAX_FIELDS];
        unsigned nf = split_fields(p + 2, eol, f, MAX_FIELDS);
        unsigned cid, secs, now_lo, now_hi;
        unsigned char cmd;
        unsigned long long now;
        if (nf != 4) {
            parse_error();
            return;
        }
        if (f[0].len == 3 && f[0].p[0] == 'a' && f[0].p[0 + 1] == 'r' && f[0].p[2] == 'm') {
            if (!(parse_hex_u32(f[1].p, f[1].len, &cid) &&
                  parse_dec_u32_bounded(f[2].p, f[2].len, 255, &secs) &&
                  parse_dec_u64(f[3].p, f[3].len, &now))) {
                parse_error();
                return;
            }
            now_lo = (unsigned)now;
            now_hi = (unsigned)(now >> 32);
            cur_now = now; /* Q lock guards share the L branch's clock */
            ctaphid_lock_arm(&lks, cid, secs, now_lo, now_hi);
            return; /* arm emits nothing; the lock persists for later lines */
        }
        if (f[0].len == 6 && f[0].p[0] == 'r' && f[0].p[1] == 'e' &&
            f[0].p[2] == 'f' && f[0].p[3] == 'u' && f[0].p[4] == 's' &&
            f[0].p[5] == 'e') {
            if (!(parse_hex_u32(f[1].p, f[1].len, &cid) &&
                  parse_hex_byte(f[2].p, f[2].len, &cmd) &&
                  parse_dec_u64(f[3].p, f[3].len, &now))) {
                parse_error();
                return;
            }
            now_lo = (unsigned)now;
            now_hi = (unsigned)(now >> 32);
            cur_now = now; /* Q lock guards share the L branch's clock */
            unsigned r = ctaphid_lock_refuses(&lks, cid, (unsigned)cmd, now_lo, now_hi);
            unsigned char *o = out;
            *o++ = 'R'; *o++ = ' ';
            *o++ = (unsigned char)('0' + r); *o++ = '\n';
            emit(out, o - out);
            return;
        }
        parse_error();
        return;
    }

    /* dispatcher verdicts: "Q <can_wink 0|1> <cmd 2-hex> <cid 8-hex> [body-hex]"
     * -> "Q <code 2-hex>" (00 = route/no-transport-response, else the error
     * code); an immediate error verdict also frames CTAPHID_ERROR though tx.
     * A missing body field is the empty body (the trailing-space trim would
     * swallow a bare empty field), matching the T line's bare-INIT handling.
     * The lock guard consults the persistent lock + the L branch's clock. */
    if (*p == 'Q' && p + 1 < eol && *(p + 1) == ' ') {
        struct field f[MAX_FIELDS];
        unsigned nf = split_fields(p + 2, eol, f, MAX_FIELDS);
        unsigned char cmd, can_wink;
        unsigned cid, blen = 0;
        int ok = (nf == 3 || nf == 4) && f[0].len == 1 &&
                 (f[0].p[0] == '0' || f[0].p[0] == '1') &&
                 parse_hex_byte(f[1].p, f[1].len, &cmd) &&
                 parse_hex_u32(f[2].p, f[2].len, &cid);
        if (ok && nf == 4) {
            if ((f[3].len & 1) == 0) {
                blen = f[3].len / 2;
                if (blen) ok = (blen <= MSG_CAP) && parse_hex_n(f[3].p, f[3].len, qbody);
            } else {
                ok = 0;
            }
        }
        if (!ok) {
            parse_error();
            return;
        }
        can_wink = (unsigned char)(f[0].p[0] - '0');
        unsigned code = 0x00;
        int frame = 0;
        if (cmd == CMD_CANCEL) {
            /* never acknowledged, never errored, in any state */
        } else if (cmd == CMD_PING || cmd == CMD_MSG || cmd == CMD_CBOR) {
            /* the lock guard fires on a refused channel, before any routing */
            unsigned now_lo = (unsigned)cur_now, now_hi = (unsigned)(cur_now >> 32);
            if (ctaphid_lock_refuses(&lks, cid, (unsigned)cmd, now_lo, now_hi)) {
                code = Q_CHANNEL_BUSY; frame = 1;
            } else if (ctaphid_msg_guard((unsigned)cmd, blen) == 1) {
                code = Q_INVALID_LEN; frame = 1; /* only an empty CBOR refuses */
            } else {
                code = 0x00; /* route */
            }
        } else if (cmd == CMD_LOCK) {
            unsigned r = ctaphid_lock_command(qbody, blen);
            if (r == 2) { code = Q_INVALID_PAR; frame = 1; }
            else if (r == 1) { code = Q_INVALID_LEN; frame = 1; }
            else {
                /* arm, the caller-side half of the dispatcher's LOCK verdict */
                unsigned now_lo = (unsigned)cur_now, now_hi = (unsigned)(cur_now >> 32);
                ctaphid_lock_arm(&lks, cid, qbody[0], now_lo, now_hi);
                code = 0x00;
            }
        } else if (cmd == CMD_WINK) {
            if (ctaphid_wink((unsigned)can_wink) != 0) { code = Q_INVALID_CMD; frame = 1; }
            else { code = 0x00; } /* empty wink reply */
        } else {
            ctaphid_unknown((unsigned)cmd);
            code = Q_INVALID_CMD; frame = 1;
        }
        unsigned char *o = out;
        *o++ = 'Q'; *o++ = ' ';
        o = hex2(o, code);
        *o++ = '\n';
        emit(out, o - out);
        if (frame) {
            codebuf[0] = (unsigned char)code;
            ctaphid_tx_init(&txs, cid, CMD_ERROR, codebuf, 1);
            unsigned n = 0;
            while (n < 256 && ctaphid_tx_next(&txs, tframe)) {
                o = out;
                *o++ = 'F'; *o++ = ' ';
                o = hexn(o, tframe, 64);
                *o++ = '\n';
                emit(out, o - out);
                n++;
            }
        }
        return;
    }

    /* worker-wait orchestration (M10): "W start <is_cbor 0|1> <now_ms dec>"
     * arms the cadence, "W up <0|1>" sets the worker's touch flag,
     * "W tick <now_ms dec>" -> one "W ka <00|01|02>" per 100 ms deadline
     * crossed (00 = the U2F fast-op silence, the M8 S-line encoding),
     * "W frame <frame 128-hex> <n dec> <cid 8-hex>" -> "W r 0|1|2"
     * (0 queued off the touch wait, 1 dropped mid-wait, 2 cancel signalled),
     * "W done" ends the wait. The tick's catch-up loop is capped so a huge
     * clock jump cannot hang either side; the cap matches the oracle's. */
    if (*p == 'W' && p + 1 < eol && *(p + 1) == ' ') {
        struct field f[MAX_FIELDS];
        unsigned nf = split_fields(p + 2, eol, f, MAX_FIELDS);
        unsigned long long now;
        if (nf == 3 && f[0].len == 5 && f[0].p[0] == 's' && f[0].p[1] == 't' &&
            f[0].p[2] == 'a' && f[0].p[3] == 'r' && f[0].p[4] == 't') {
            if (!(f[1].len == 1 && (f[1].p[0] == '0' || f[1].p[0] == '1') &&
                  parse_dec_u64(f[2].p, f[2].len, &now))) {
                parse_error();
                return;
            }
            wait_cbor = (unsigned)(f[1].p[0] - '0');
            ctaphid_wait_start(&wst, (unsigned)now, (unsigned)(now >> 32));
            return; /* start emits nothing; the cadence persists */
        }
        if (nf == 2 && f[0].len == 2 && f[0].p[0] == 'u' && f[0].p[1] == 'p') {
            if (!(f[1].len == 1 && (f[1].p[0] == '0' || f[1].p[0] == '1'))) {
                parse_error();
                return;
            }
            wait_up = (unsigned)(f[1].p[0] - '0');
            return; /* the flag flip emits nothing; the next tick reads it */
        }
        if (nf == 2 && f[0].len == 4 && f[0].p[0] == 't' && f[0].p[1] == 'i' &&
            f[0].p[2] == 'c' && f[0].p[3] == 'k') {
            if (!parse_dec_u64(f[1].p, f[1].len, &now)) {
                parse_error();
                return;
            }
            for (unsigned i = 0; i < 65536; i++) {
                if (!ctaphid_wait_tick(&wst, (unsigned)now, (unsigned)(now >> 32)))
                    break;
                unsigned s = ctaphid_keepalive_status(wait_cbor, wait_up);
                unsigned char *o = out;
                *o++ = 'W'; *o++ = ' '; *o++ = 'k'; *o++ = 'a'; *o++ = ' ';
                o = hex2(o, s);
                *o++ = '\n';
                emit(out, o - out);
            }
            return;
        }
        if (nf == 4 && f[0].len == 5 && f[0].p[0] == 'f' && f[0].p[1] == 'r' &&
            f[0].p[2] == 'a' && f[0].p[3] == 'm' && f[0].p[4] == 'e') {
            unsigned char wframe[64];
            unsigned n, cid;
            if (!(f[1].len == 128 && parse_hex_n(f[1].p, f[1].len, wframe) &&
                  parse_dec_u32_bounded(f[2].p, f[2].len, 64, &n) &&
                  parse_hex_u32(f[3].p, f[3].len, &cid))) {
                parse_error();
                return;
            }
            unsigned r = ctaphid_wait_frame(wait_up, wframe, n, cid);
            unsigned char *o = out;
            *o++ = 'W'; *o++ = ' '; *o++ = 'r'; *o++ = ' ';
            *o++ = (unsigned char)('0' + r); *o++ = '\n';
            emit(out, o - out);
            return;
        }
        if (nf == 1 && f[0].len == 4 && f[0].p[0] == 'd' && f[0].p[1] == 'o' &&
            f[0].p[2] == 'n' && f[0].p[3] == 'e') {
            ctaphid_wait_finish(&wst);
            return; /* the response itself is a T line, the caller's */
        }
        parse_error();
        return;
    }

    /* CCID (M13): "A <hex>" selects the ATR the card presents (persists,
     * emits nothing), "N <2-hex>" seeds the slot bStatus, "H <type 2-hex>
     * <len dec> <seq 2-hex> <status 2-hex>" -> "H <20-hex>" pins the
     * response header alone, "X|E <msg-hex>" -> "X|E 0" or "X|E 1 <start>
     * <end>" ranges an XfrBlock/Secure payload, and "M <cap dec> <msg-hex>"
     * runs one whole message -> "M <n> <resp-hex>" (n 0: no response).
     * A cap in [10,17] is only fed to non-params/non-rate traffic: the Rust
     * process_message slices out[10..17]/out[10..18] unguarded there and
     * panics on its own bounds — a crash, not a divergence — so the
     * generators keep that window to the messages that fit it. */
    if (*p == 'A' && p + 1 < eol && *(p + 1) == ' ') {
        struct field f[MAX_FIELDS];
        unsigned nf = split_fields(p + 2, eol, f, MAX_FIELDS);
        if (nf != 1 || (f[0].len & 1) != 0 || f[0].len / 2 > sizeof ccid_atr ||
            (f[0].len && !parse_hex_n(f[0].p, f[0].len, ccid_atr))) {
            parse_error();
            return;
        }
        ccid_atr_len = f[0].len / 2;
        return; /* persists; the next M line reads it */
    }

    if (*p == 'N' && p + 1 < eol && *(p + 1) == ' ') {
        struct field f[MAX_FIELDS];
        unsigned nf = split_fields(p + 2, eol, f, MAX_FIELDS);
        unsigned char v;
        if (nf != 1 || !parse_hex_byte(f[0].p, f[0].len, &v)) {
            parse_error();
            return;
        }
        ccid_status = v;
        return;
    }

    if (*p == 'H' && p + 1 < eol && *(p + 1) == ' ') {
        struct field f[MAX_FIELDS];
        unsigned nf = split_fields(p + 2, eol, f, MAX_FIELDS);
        unsigned char type, seq, stt;
        unsigned long long len;
        if (nf != 4 || !parse_hex_byte(f[0].p, f[0].len, &type) ||
            !parse_dec_u64(f[1].p, f[1].len, &len) || len > 0xffffffffull ||
            !parse_hex_byte(f[2].p, f[2].len, &seq) ||
            !parse_hex_byte(f[3].p, f[3].len, &stt)) {
            parse_error();
            return;
        }
        ccid_put_header(ccid_out, type, (unsigned)len, seq, stt);
        unsigned char *o = out;
        *o++ = 'H'; *o++ = ' ';
        o = hexn(o, ccid_out, 10);
        *o++ = '\n';
        emit(out, o - out);
        return;
    }

    if ((*p == 'X' || *p == 'E') && p + 1 < eol && *(p + 1) == ' ') {
        struct field f[MAX_FIELDS];
        unsigned nf = split_fields(p + 2, eol, f, MAX_FIELDS);
        if (nf != 1 || (f[0].len & 1) != 0 || f[0].len / 2 > MSG_CAP ||
            (f[0].len && !parse_hex_n(f[0].p, f[0].len, paybuf))) {
            parse_error();
            return;
        }
        unsigned range[2];
        unsigned r = (*p == 'X') ? ccid_xfr_apdu(paybuf, f[0].len / 2, range)
                                : ccid_secure_apdu(paybuf, f[0].len / 2, range);
        unsigned char *o = out;
        *o++ = *p; *o++ = ' ';
        if (r) {
            *o++ = '1'; *o++ = ' ';
            o = decn(o, range[0]); *o++ = ' ';
            o = decn(o, range[1]);
        } else {
            *o++ = '0';
        }
        *o++ = '\n';
        emit(out, o - out);
        return;
    }

    if (*p == 'M' && p + 1 < eol && *(p + 1) == ' ') {
        struct field f[MAX_FIELDS];
        unsigned nf = split_fields(p + 2, eol, f, MAX_FIELDS);
        unsigned cap;
        if (nf != 2 || !parse_dec_u32_bounded(f[0].p, f[0].len, 2048, &cap) ||
            (f[1].len & 1) != 0 || f[1].len / 2 > MSG_CAP ||
            (f[1].len && !parse_hex_n(f[1].p, f[1].len, paybuf))) {
            parse_error();
            return;
        }
        for (unsigned i = 0; i < cap; i++) ccid_out[i] = 0;
        unsigned n = ccid_process(paybuf, f[1].len / 2, ccid_atr, ccid_atr_len,
                                  &ccid_status, ccid_out, cap);
        unsigned char *o = out;
        *o++ = 'M'; *o++ = ' ';
        o = decn(o, n);
        if (n) {
            *o++ = ' ';
            o = hexn(o, ccid_out, n);
        }
        *o++ = '\n';
        emit(out, o - out);
        return;
    }

    for (int i = 0; i < 64; i++) rpt[i] = 0;
    int ok = 1;
    for (int i = 0; i < 64; i++) {
        int hi = hexval(*p++);
        int lo = (p < eol) ? hexval(*p++) : -1;
        if (hi < 0 || lo < 0) { ok = 0; break; }
        rpt[i] = (unsigned char)((hi << 4) | lo);
    }
    if (!ok) {
        emit((const unsigned char *)"X parse\n", 8);
        return;
    }

    ctaphid_feed(&st, rpt);
    unsigned tag = st.ev_tag, val = st.ev_val;
    unsigned char *o = out;
    switch (tag) {
    case 0:
        *o++ = 'B'; *o++ = '\n';
        break;
    case 1:
        *o++ = 'D'; *o++ = ' ';
        o = hex8(o, st.ev_cid); *o++ = ' ';
        o = hex2(o, st.ev_cmd); *o++ = ' ';
        o = hexp(o, val); *o++ = ' ';
        o = hexn(o, msgbuf, val); *o++ = '\n';
        break;
    case 2:
        *o++ = 'E'; *o++ = ' ';
        o = hex8(o, st.ev_cid); *o++ = ' ';
        o = hex2(o, val); *o++ = '\n';
        break;
    default:
        *o++ = 'I'; *o++ = '\n';
        break;
    }
    emit(out, o - out);
}

int harness_main(void)
{
    st.buf_max = MSG_CAP;
    st.buf = msgbuf;
    ctaphid_init_init(&inis);

    unsigned have = 0;
    for (;;) {
        long n = sys_read(0, inbuf + have, sizeof inbuf - have);
        if (n <= 0) break;
        have += (unsigned)n;

        unsigned char *line = inbuf;
        unsigned char *end = inbuf + have;
        while (line < end) {
            unsigned char *eol = line;
            while (eol < end && *eol != '\n') eol++;
            if (eol == end) break;
            process_line(line, eol);
            line = eol + 1;
        }
        if (line == inbuf) {
            if (have == sizeof inbuf) {
                /* a line with no room to exist: drop it, keep streaming */
                emit((const unsigned char *)"X parse\n", 8);
                have = 0;
            }
            continue;
        }
        have = end - line;
        for (unsigned i = 0; i < have; i++) inbuf[i] = line[i];
    }
    if (have > 0) process_line(inbuf, inbuf + have);
    return 0;
}
