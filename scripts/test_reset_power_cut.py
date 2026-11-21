# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""What `tests/29_reset_power_cut.py`'s cut instrument decides, driven on a fake board.

That script is board-only and the gate runs none of it, so its own guard — the
`PROCESSING` keepalive that separates a torn wipe from a cut which never reached
the device — could be deleted with `check.sh` fully green. It is the shape
`scripts/test_sram_residue_dump.py` already covers for `tests/54_sram_residue.py`,
and this file is that, one script over: the instrument is host-testable, because
everything below the USB handle is stubbed and the handle itself is a model of
hidapi's contract — a timed-out read returns an EMPTY list and raises nothing, a
write can be accepted by the host stack and never reach the device, and the
supply can go at an instant the open handle never notices.

Two tables, and the second is what makes the first worth reading. [`CHECKS`] is
one assertion per fact the record claims; [`MUTANTS`] breaks the instrument one
way per entry and NAMES the checks that must go red for it — so an arm that goes
red for the wrong reason is a failure here rather than a kill, which is the
distinction this programme has already been caught getting wrong. A mutant runs
only the scenarios its named checks need, which is why the table is affordable
as a gate row rather than as an overnight sweep.

What none of it can tell you is on the subject's own docstring: a keepalive is a
lower bound on `inside the handler`, never on `the first erase landed`. And what
it does not yet cover, found by review and left rather than padded: the post-cut
`getInfo` and `BACKUP_STATE` status asserts in `main`, `TappedHid.write`'s death
recorder, the foreign-keepalive console line, and the `len(frame) > 7` guard —
which goes red only as a mutant whose PATTERN stopped matching, so a weakening
that rewrote the arm with it would pass.
"""

import builtins
import importlib.util
import json
import os
import pathlib
import stat
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tests" / "29_reset_power_cut.py"

#: The fake stack spins at 0.5 ms and the record rounds to 0.1, so an instant
#: compared against one the harness measured itself is equal within this.
TOL_MS = 1.0
#: …and this is the same comparison for the ONE check that reads a recorded
#: instant against one taken on the board a few microseconds earlier. Wide, so a
#: scheduler pause between the two cannot redden it, and still an order of
#: magnitude under the 100 ms cadence the two mutants it exists for move it by.
KEEPALIVE_TOL_MS = 10.0

REPORT_LEN = 64
CID = b"\x11\x22\x33\x44"
#: Another host process's channel. hidraw and IOHIDManager hand every input
#: report to every open handle, so its frames land in our read queue.
FOREIGN_CID = b"\xaa\xbb\xcc\xdd"
STATUS_PROCESSING, STATUS_UPNEEDED = 0x01, 0x02
CTAPHID_KEEPALIVE, CTAPHID_CBOR = 0xBB, 0x90


# --------------------------------------------------------------- the board ---
def frame(cmd, payload, cid=CID):
    body = cid + bytes([cmd, len(payload) >> 8, len(payload) & 0xFF]) + payload
    return list(body + b"\x00" * (REPORT_LEN - len(body)))


class Board:
    """A device on the other side of a hidapi handle, and a supply that can go.

    `busy_elsewhere` is the case the channel check exists for: the board answers
    on `keepalive_cid` whether or not it ever saw OUR request.
    """

    def __init__(self, cut_after_ms, every_ms=100.0, status=STATUS_PROCESSING,
                 reset_takes_ms=487.2, notices=True, read_timeout_ms=None,
                 deliver_writes=True, quiet_after_ms=None,
                 keepalive_cid=CID, busy_elsewhere=False, response=b"\x00", first_after_ms=None):
        self.cut_after_ms = cut_after_ms      # None: the supply never goes
        self.every_ms = every_ms              # the keepalive cadence
        self.first_after_ms = every_ms if first_after_ms is None else first_after_ms
        self.status = status                  # the byte those frames carry
        self.reset_takes_ms = reset_takes_ms
        self.notices = notices                # does the handle raise at all?
        self.read_timeout_ms = read_timeout_ms  # hidapi's own budget, scaled
        self.deliver_writes = deliver_writes
        self.quiet_after_ms = quiet_after_ms  # a powered device that stops answering
        self.keepalive_cid = keepalive_cid
        self.busy_elsewhere = busy_elsewhere
        self.response = response              # the CBOR body the RESET answers
        self.sender_started = None
        self.true_cut = None
        self.saw_reset_request = False
        self.sent = 0                         # keepalives written so far
        self.sent_at = []                     # …and when each one really went

    def arm(self):
        if self.sender_started is None:
            self.sender_started = time.perf_counter()
            if self.cut_after_ms is not None:
                self.true_cut = self.sender_started + self.cut_after_ms / 1000

    def powered(self):
        return self.true_cut is None or time.perf_counter() < self.true_cut


class FakeHid:
    def __init__(self, board, close_raises=False):
        self.board = board
        self.close_raises = close_raises
        self.closed = 0

    def write(self, data):
        self.board.arm()
        if self.board.notices and not self.board.powered():
            raise OSError("write error")
        if self.board.deliver_writes and self.board.powered():
            self.board.saw_reset_request = True
        return len(data)

    def read(self, length, timeout_ms):
        started = time.perf_counter()
        board = self.board
        budget = (board.read_timeout_ms if board.read_timeout_ms is not None
                  else timeout_ms) / 1000
        while True:
            now = time.perf_counter()
            if board.notices and not board.powered():
                raise OSError("read error")     # the handle dies under the read
            # An unpowered board writes nothing, whether or not the handle
            # notices; a wedged one stops writing while still powered.
            quiet = (board.quiet_after_ms is not None
                     and now - board.sender_started >= board.quiet_after_ms / 1000)
            if (board.saw_reset_request or board.busy_elsewhere) and board.powered() and not quiet:
                if (board.saw_reset_request
                        and now - board.sender_started >= board.reset_takes_ms / 1000):
                    return frame(CTAPHID_CBOR, board.response)
                due = board.sender_started + (board.first_after_ms + board.sent * board.every_ms) / 1000
                if now >= due:
                    board.sent += 1
                    board.sent_at.append(now)
                    return frame(CTAPHID_KEEPALIVE, bytes([board.status]),
                                 board.keepalive_cid)
            if now - started >= budget:
                return []                        # hidapi returns EMPTY on timeout
            time.sleep(0.0005)

    def close(self):
        self.closed += 1
        if self.close_raises:
            raise OSError("close error")


# --------------------------------------------------------------- the driver ---
class FakeBackup:
    FINALIZE, STATE = 1, 2

    def __init__(self, sealed=1, post_seed=b"owner-seed"):
        self.sealed, self.post_seed, self.calls = sealed, post_seed, 0

    def read_seed(self, dev, cid, pin):
        self.calls += 1
        return b"owner-seed" if self.calls == 1 else self.post_seed

    def _vendor(self, dev, cid, request):
        return (0, {1: self.sealed}) if request == {1: self.STATE} else (0, {1: 1})


class Stamped:
    """stdout with a clock on it: the driver reads WHEN a line was printed."""

    def __init__(self, under):
        self.under, self.at = under, []

    def write(self, text):
        if text.strip():
            self.at.append((time.perf_counter(), text.strip()))
        return self.under.write(text)

    def flush(self):
        self.under.flush()


def load(path, record_path):
    """The script as a module, its `sys.path` edit undone.

    It puts `tests/` and `tools/` on the path at import; leaving them there for
    the rest of a `pytest scripts` session would let either shadow a module some
    other table imports. The dependencies stay in `sys.modules` once loaded,
    which is what lets a mutant loaded from a temp directory find them.
    """
    if record_path is None:
        os.environ.pop("RSK_POWER_CUT_LOG", None)
    else:
        os.environ["RSK_POWER_CUT_LOG"] = str(record_path)
    name = "reset_power_cut_" + pathlib.Path(path).stem.lstrip("_")
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    held = list(sys.path)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = held
    return module


def stub(mod, board, post_cut_assertion=0x36, options=None, backup=None,
         gone=None, back=None, fresh=None):
    """Everything but the tapped RESET, which is the path under test."""
    real_send_cbor = mod.send_cbor

    def fake_wait_gone(timeout=None):
        if gone is not None:
            return gone()
        while board.powered():
            time.sleep(mod.replug.POLL_S)

    def fake_wait_back(timeout=None):
        if back is not None:
            return back()
        return (fresh if fresh is not None else FakeHid(Board(None))), CID, time.time()

    def fake_send_cbor(dev, cid, payload):
        if payload == bytes([mod.CTAP_RESET]):
            return real_send_cbor(dev, cid, payload)   # the tapped path, unstubbed
        return b"\x00"

    mod.replug.wait_gone = fake_wait_gone
    mod.replug.wait_back = fake_wait_back
    mod.replug.reset = lambda dev=None, why="": (FakeHid(board), CID)
    mod.backup = backup or FakeBackup()
    mod.set_pin = lambda dev, cid: None
    mod.make_resident_credential = lambda dev, cid: b"cred"
    mod.enable_always_uv = lambda dev, cid: None
    mod.send_cbor = fake_send_cbor
    mod.decode = lambda body: {4: options or {"clientPin": True, "alwaysUv": True}}
    mod.old_credential_without_gates = lambda dev, cid, cred: post_cut_assertion


class Run:
    """One driven run: the module, the board, the record lines and the outcome."""

    def __init__(self, mod, board, rows, result, stamps, path):
        self.mod, self.board, self.rows = mod, board, rows
        self.result, self.stamps, self.path = result, stamps, path

    @property
    def row(self):
        return self.rows[-1] if self.rows else None

    @property
    def passed(self):
        return any(line.startswith("PASS") for _, line in self.stamps)

    @property
    def exit_code(self):
        if isinstance(self.result, SystemExit):
            return self.result.code
        if isinstance(self.result, BaseException):
            return f"{type(self.result).__name__}: {self.result}"
        return 0

    def said(self, fragment):
        return [line for _, line in self.stamps if fragment in line]

    def zero(self):
        """The record's zero in perf_counter terms, owned by the HARNESS.

        `board.sender_started` is stamped by the first write, a few hundred
        microseconds after the script's own `opened`. Deriving it from a
        RECORDED field instead would make every mutant that moves that field
        look like one that moved the bounds.
        """
        return self.board.sender_started

    def true_cut_ms(self):
        z = self.zero()
        if z is None or self.board.true_cut is None:
            return None
        return (self.board.true_cut - z) * 1000

    def sent_ms(self, n):
        """When the board REALLY wrote its n-th keepalive, ms after zero."""
        z = self.zero()
        if z is None or len(self.board.sent_at) <= n:
            return None
        return (self.board.sent_at[n] - z) * 1000


def records(path):
    p = pathlib.Path(path)
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]


def drive(path, board, log, cmd="true", commanded=None, patch=None, **kw):
    """Load the script fresh, point its record at `log`, and run its `main()`."""
    if commanded is None:
        os.environ.pop("RSK_POWER_CUT_DELAY_MS", None)
    else:
        os.environ["RSK_POWER_CUT_DELAY_MS"] = str(commanded)
    if cmd is None:
        os.environ.pop("RSK_POWER_CUT_CMD", None)
    else:
        os.environ["RSK_POWER_CUT_CMD"] = cmd
    mod = load(path, log)
    stub(mod, board, **kw)
    if patch is not None:
        patch(mod)

    def fake_input(prompt=""):
        sys.stdout.write(prompt + "\n")
        return ""

    stamped = Stamped(sys.stdout)
    real_input, real_stdout = builtins.input, sys.stdout
    builtins.input, sys.stdout = fake_input, stamped
    try:
        result = mod.main()
    except BaseException as stop:
        result = stop
    finally:
        builtins.input, sys.stdout = real_input, real_stdout
    return Run(mod, board, records(log), result, stamped.at, log)


# ------------------------------------------------------------ the scenarios ---
def scenarios(path, default, tmp):
    """name -> a thunk producing one driven Run of `path`. Lazy: mutants re-run them."""

    def R(tag, **kw):
        def go():
            log = tmp / f"{tag}.jsonl"
            log.unlink(missing_ok=True)
            return drive(path, log=str(log), **kw)
        return go

    def missing_dir():
        # Removed HERE and not once per session: the second run through would
        # otherwise find the directory the first one made, and the mutant that
        # deletes the `makedirs` would survive on a directory it did not create.
        nest = tmp / "no-such-dir"
        if nest.exists():
            for stale in nest.glob("*"):
                stale.unlink()
            nest.rmdir()
        return drive(path, Board(cut_after_ms=default + 5),
                     log=str(nest / "cut.jsonl"))

    def blocked_dir(**kw):
        # A record path whose PARENT is a regular file: unwritable for every
        # uid, where a 0500 directory is writable for one of them.
        wall = tmp / "blocked"
        wall.write_text("not a directory\n")
        return drive(path, Board(cut_after_ms=default + 5),
                     log=str(wall / "cut.jsonl"), **kw)

    def planted_symlink():
        target = tmp / "someone-elses.jsonl"
        target.write_text("")
        link = tmp / "planted.jsonl"
        link.unlink(missing_ok=True)
        link.symlink_to(target)
        run = drive(path, Board(cut_after_ms=default + 5), log=str(link))
        run.target = target
        return run

    def clipped_summary():
        # `say_cut` reads `error_ms[name]` for every bound it prints, so a
        # record missing one raises there — AFTER the line is on disk.
        def clip(mod):
            real = mod.bounds

            def wrapped(opened, gone, tap, outcome):
                measured = real(opened, gone, tap, outcome)
                measured["error_ms"].pop("host_saw_gone")
                return measured

            mod.bounds = wrapped

        log = tmp / "clipped.jsonl"
        log.unlink(missing_ok=True)
        return drive(path, Board(cut_after_ms=default + 5), log=str(log), patch=clip)

    def poll_moved():
        """`replug.POLL_S` is 0.05 today, so a floor hard-coded to 50.0 IS the
        derived value and the check that reads it is blind BY CONSTRUCTION.
        Moved for one run, and put back — the module is shared by every load."""
        log = tmp / "S20.jsonl"
        log.unlink(missing_ok=True)
        held = {}

        def move(mod):
            held["replug"], held["was"] = mod.replug, mod.replug.POLL_S
            mod.replug.POLL_S = 0.02

        try:
            run = drive(path, Board(cut_after_ms=default + 5), log=str(log), patch=move)
        finally:
            if held:
                held["replug"].POLL_S = held["was"]
        run.poll_s = 0.02
        return run

    def sweep():
        log = tmp / "sweep.jsonl"
        log.unlink(missing_ok=True)
        last = None
        for ms in (150, 250):
            last = drive(path, Board(cut_after_ms=ms + 5), log=str(log), commanded=ms)
        return last

    return {
        # the default relay arm, cut at its own commanded delay
        # Keep the first-frame floor independent of a mutated cut delay;
        # a faster following cadence leaves scheduler room before cutoff.
        "torn-default": R("torn-default", board=Board(cut_after_ms=default + 5,
                         every_ms=load(SCRIPT, None).KEEPALIVE_MS / 2,
                         first_after_ms=load(SCRIPT, None).KEEPALIVE_MS)),
        # hidapi's read TIMES OUT and returns EMPTY; the handle never notices.
        # 35 and not 30: a cut ON a keepalive boundary races the frame due at
        # that instant, and the lower-bound check then decides on which side of
        # `powered()` the loop happened to be. Measured flaky at 30.
        "S1-empty-read": R("S1", board=Board(cut_after_ms=35.0, every_ms=10.0,
                                             reset_takes_ms=1e9, notices=False,
                                             read_timeout_ms=300.0), commanded=25),
        # a board that answered, then wedged: the transfer dies of ctaphid's own
        # read budget at ~160 ms, and the supply goes 240 ms LATER
        "S2-read-timeout-death": R("S2", board=Board(cut_after_ms=400.0, every_ms=30.0,
                                                     quiet_after_ms=60.0, reset_takes_ms=1e9,
                                                     notices=False, read_timeout_ms=100.0),
                                   commanded=25),
        # the supply is gone before the host stack accepts the first write
        "S3a-cut-before-write": R("S3a", board=Board(cut_after_ms=0.0), cmd=None),
        # the write is buffered into a void: the device never sees the request
        "S3b-buffered-write": R("S3b", board=Board(cut_after_ms=5.0, deliver_writes=False),
                                cmd=None),
        # a touch build, cut while the ceremony is still waiting for a finger
        # (210, off the 20 ms grid, for S1's reason one scenario up)
        "S10-touch-wait": R("S10", board=Board(cut_after_ms=210.0, every_ms=20.0,
                                               status=STATUS_UPNEEDED, reset_takes_ms=1e9),
                            commanded=25),
        # our request is unread in the OUT buffer while ANOTHER channel's
        # ceremony streams PROCESSING frames into our read queue
        "S14-foreign-channel": R("S14", board=Board(cut_after_ms=250.0, every_ms=100.0,
                                                    deliver_writes=False, busy_elsewhere=True,
                                                    keepalive_cid=FOREIGN_CID),
                                 commanded=200),
        # the board REFUSED the reset: CTAP 2.1 §6.6 answers 0x30 in well under
        # the keepalive floor, and no later cut changes that
        "S15-refused": R("S15", board=Board(cut_after_ms=250.0, reset_takes_ms=20.0,
                                            response=b"\x30"), commanded=200),
        # …and one whose status byte IS `STATUS_PROCESSING` at offset 7
        "S16-answered-01": R("S16", board=Board(cut_after_ms=250.0, reset_takes_ms=20.0,
                                                response=b"\x01"), commanded=200),
        # RSK_POWER_CUT_LOG points into a directory that does not exist
        "S4-missing-dir": missing_dir,
        # ... and into one that cannot be made at all
        "S4b-unwritable": blocked_dir,
        # the same, with the post-cut security assertion FAILING underneath it
        "S4c-unwritable-and-red": lambda: blocked_dir(post_cut_assertion=0x00),
        # somebody planted a symlink where the record goes
        "S18-planted-symlink": planted_symlink,
        # the line is written and the console summary of it then raises
        "S17-summary-raises": clipped_summary,
        # the fresh handle's close() raises
        "S5-close-raises": R("S5", board=Board(cut_after_ms=default + 5),
                             fresh=FakeHid(Board(None), close_raises=True)),
        # replug.wait_gone() times out — the real one sys.exits
        "S6-wait-gone-timeout": R("S6", board=Board(cut_after_ms=None),
                                  gone=lambda: sys.exit("FAIL: the key is still enumerated")),
        # the board was cut and never came back
        "S7-never-came-back": R("S7", board=Board(cut_after_ms=40.0),
                                back=lambda: sys.exit("FAIL: the FIDO HID device did not come back")),
        # the relay command exits non-zero
        "S8-relay-nonzero": R("S8", board=Board(cut_after_ms=default + 5), cmd="false"),
        # the cut lands after the wipe finished
        "S11-missed-window": R("S11", board=Board(cut_after_ms=900.0), commanded=850),
        # the supply went and the SENDER never noticed: `worker.join(5)` times
        # out, so nothing on this wire is evidence about the cut. Costs its five
        # seconds honestly — that timeout is the subject's, not this file's.
        "S12-sender-stuck": R("S12", board=Board(cut_after_ms=150.0, every_ms=50.0,
                                                 reset_takes_ms=1e9, notices=False,
                                                 read_timeout_ms=5500.0), commanded=100),
        # the backup seal did NOT survive the cut, and the seed behind it is new
        "S19-seal-gone": R("S19", board=Board(cut_after_ms=default + 5),
                           backup=FakeBackup(sealed=0, post_seed=b"fresh-seed")),
        # ...and the same with the OWNER's seed still behind it, which is the
        # clause `SEC-FIDO-006C` cites this script for
        "S19b-owner-seed-survived": R("S19b", board=Board(cut_after_ms=default + 5),
                                      backup=FakeBackup(sealed=0, post_seed=b"owner-seed")),
        # the same run with `replug.POLL_S` moved, so the floor cannot be right
        # by coincidence
        "S20-poll-moved": poll_moved,
        # a hand, with no commanded delay at all
        "manual-arm": R("manual", board=Board(cut_after_ms=250.0), cmd=None),
        # the old credential authorises after the cut: the run must go red
        "S13-failing-assert": R("S13", board=Board(cut_after_ms=default + 5),
                                post_cut_assertion=0x00),
        "sweep": sweep,
    }


# --------------------------------------------------------------- the checks ---
#: label -> (scenario, predicate). A predicate answers `(ok, what it saw)`, and
#: the detail is what a mutant's kill is READ from — a row that went red for the
#: inverse defect is a failure of this table, not evidence for it.
CHECKS = {}


def check(label, scenario):
    def keep(fn):
        CHECKS[label] = (scenario, fn)
        return fn
    return keep


def brackets(run):
    """(true cut, lower bound, upper bound) in ms after the record's zero."""
    row = run.row
    return (run.true_cut_ms(), row["cut_lower_ms"]["last_frame"],
            row["cut_upper_ms"]["transfer_death"])


@check("torn: the cut is recorded as torn", "torn-default")
def _(r):
    return r.row is not None and r.row["verdict"] == "torn", r.row and r.row["verdict"]


@check("torn: the wipe was observed", "torn-default")
def _(r):
    return r.row["wipe_observed"] is True, r.row["wipe_observed"]


@check("torn: every keepalive said PROCESSING", "torn-default")
def _(r):
    ks = r.row["keepalives"]
    return bool(ks) and set(ks) == {STATUS_PROCESSING}, ks


@check("torn: the default delay is above the keepalive floor", "torn-default")
def _(r):
    began = r.row["wipe_lower_ms"]["first_keepalive"]
    return began is not None, f"first_keepalive={began}, commanded={r.row['commanded_delay_ms']}"


@check("torn: first_keepalive is the instant the board wrote its FIRST one", "torn-default")
def _(r):
    """The VALUE, against an instant this harness measured on the board itself.

    Nothing else here reads it: `is not None` above passes just as happily on the
    LAST keepalive, and on a hard-coded 0.0 — both of which the record's own
    field name and docstring call the earliest instant.
    """
    said, first = r.row["wipe_lower_ms"]["first_keepalive"], r.sent_ms(0)
    ok = said is not None and first is not None and abs(said - first) <= KEEPALIVE_TOL_MS
    return ok, f"recorded {said}, board wrote its first keepalive at {first}"


@check("torn: a SECOND keepalive went out, so the check above can fail", "torn-default")
def _(r):
    """Its arm. First and last coincide on a one-keepalive board, and then the
    check above is blind to the difference BY CONSTRUCTION rather than by luck."""
    sent = r.board.sent_at
    first, last = r.sent_ms(0), r.sent_ms(len(sent) - 1)
    ok = len(sent) >= 2 and last - first > 2 * KEEPALIVE_TOL_MS
    return ok, f"{len(sent)} keepalive(s), first {first}, last {last}"


@check("torn: PASS is printed and the exit is 0", "torn-default")
def _(r):
    return r.passed and r.exit_code == 0, f"passed={r.passed} exit={r.exit_code}"


@check("torn: lower bound <= the true cut", "torn-default")
def _(r):
    true, lo, _hi = brackets(r)
    return lo is not None and lo <= true + TOL_MS, f"{lo} <= {true:.1f}"


@check("torn: transfer_death >= the true cut", "torn-default")
def _(r):
    true, _lo, hi = brackets(r)
    return hi is not None and hi >= true - TOL_MS, f"{hi} >= {true:.1f}"


@check("torn: transfer_death is the tighter upper bound", "torn-default")
def _(r):
    hi, loose = r.row["cut_upper_ms"]["transfer_death"], r.row["cut_upper_ms"]["host_saw_gone"]
    return hi is not None and loose is not None and hi <= loose + TOL_MS, f"{hi} <= {loose}"


@check("torn: host_saw_gone declares replug.POLL_S as its floor", "torn-default")
def _(r):
    want = round(r.mod.replug.POLL_S * 1000, 1)
    return r.row["error_ms"]["host_saw_gone"] == want, f"{r.row['error_ms']['host_saw_gone']} == {want}"


@check("torn: exactly one line", "torn-default")
def _(r):
    return len(r.rows) == 1, len(r.rows)


@check("torn: the line carries the run id the console printed", "torn-default")
def _(r):
    """The join between a pasted record and the transcript that produced it."""
    said = r.said(f"[run {r.mod.RUN_ID}]")
    return r.row["run_id"] == r.mod.RUN_ID and len(said) >= 2, \
        f"row {r.row['run_id']!r} vs module {r.mod.RUN_ID!r}, {len(said)} console line(s)"


@check("torn: the line says the verdict is the CUT's, not the run's", "torn-default")
def _(r):
    """A failed run leaves a `torn` line a passing one would have left, so the
    line has to say so itself — it is what an operator pastes into `actual`."""
    says = r.row.get("records", "")
    return "not the run" in says and "exit code" in says, says


@check("S1: an empty read is not a surviving call", "S1-empty-read")
def _(r):
    true, lo, _hi = brackets(r)
    return lo is not None and lo <= true + TOL_MS, f"last_frame={lo} vs true cut {true:.1f}"


@check("S1: the timed-out reads are counted", "S1-empty-read")
def _(r):
    return r.row["empty_reads"] >= 1, r.row["empty_reads"]


@check("S2: a read-budget death is classified as one", "S2-read-timeout-death")
def _(r):
    kind = r.row["death"]["kind"] if r.row["death"] else None
    return kind == "read_timeout", kind


@check("S2: a read-budget death bounds nothing", "S2-read-timeout-death")
def _(r):
    true, lo, hi = brackets(r)
    return hi is None, f"transfer_death={hi}, true cut {true:.1f}, lower {lo}"


@check("S3a: a cut before the write does not print PASS", "S3a-cut-before-write")
def _(r):
    return not r.passed and "INCONCLUSIVE" in str(r.exit_code), f"passed={r.passed} exit={r.exit_code}"


@check("S3a: it is recorded as unconfirmed", "S3a-cut-before-write")
def _(r):
    return r.row["verdict"] == "unconfirmed" and r.row["wipe_observed"] is False, r.row["verdict"]


@check("S3b: a request the device never saw does not print PASS", "S3b-buffered-write")
def _(r):
    return (not r.passed and not r.board.saw_reset_request
            and "INCONCLUSIVE" in str(r.exit_code)), f"passed={r.passed} exit={r.exit_code}"


@check("S3b: it is recorded as unconfirmed", "S3b-buffered-write")
def _(r):
    return r.row["verdict"] == "unconfirmed", r.row["verdict"]


@check("S3b: host_saw_gone >= the true cut", "S3b-buffered-write")
def _(r):
    # S3b and not the torn arm: there the relay's own sleep puts a `gone` taken
    # too early within a few ms of the cut, so the check would decide on
    # subprocess-spawn latency. Here the poll grid gives it 45 ms of margin.
    true, loose = r.true_cut_ms(), r.row["cut_upper_ms"]["host_saw_gone"]
    return loose is not None and loose >= true - TOL_MS, f"{loose} >= {true:.1f}"


@check("S3b: the death instant is the handle's, not the host's poll", "S3b-buffered-write")
def _(r):
    # The poll grid cannot see the cut for a whole replug.POLL_S, so a death
    # instant taken from it lands ~45 ms late here and the two collapse.
    hi, loose = r.row["cut_upper_ms"]["transfer_death"], r.row["cut_upper_ms"]["host_saw_gone"]
    gap = None if (hi is None or loose is None) else loose - hi
    return gap is not None and gap > 10.0, f"host_saw_gone - transfer_death = {gap}"


@check("S10: a touch wait is not a running wipe", "S10-touch-wait")
def _(r):
    return not r.passed and r.row["verdict"] == "unconfirmed", f"{r.row['verdict']} passed={r.passed}"


@check("S10: the UPNEEDED frames are recorded, not dropped", "S10-touch-wait")
def _(r):
    ks = r.row["keepalives"]
    return bool(ks) and set(ks) == {STATUS_UPNEEDED}, ks


@check("S10: the refusal names the ceremony rather than a late cut", "S10-touch-wait")
def _(r):
    """`STATUS_UPNEEDED` was assigned and never read, and the one remedy the
    script printed — cut later — is the wrong advice for this world."""
    said = str(r.exit_code)
    return "UPNEEDED" in said and "waiting for a finger" in said, said


@check("S14: a keepalive on ANOTHER channel does not confirm our reset", "S14-foreign-channel")
def _(r):
    """The hole this closes: our RESET never left the host, the device is busy
    on somebody else's channel, and its PROCESSING frames land in our queue."""
    return (not r.passed and not r.board.saw_reset_request
            and r.row["verdict"] == "unconfirmed"), \
        f"verdict={r.row['verdict']} passed={r.passed} saw_request={r.board.saw_reset_request}"


@check("S14: the foreign frames are counted, not silently dropped", "S14-foreign-channel")
def _(r):
    return r.row["foreign_keepalives"] >= 1 and r.row["keepalives"] == [], \
        f"foreign={r.row['foreign_keepalives']} ours={r.row['keepalives']}"


@check("S14: the refusal says the device was busy elsewhere", "S14-foreign-channel")
def _(r):
    return "another channel" in str(r.exit_code), str(r.exit_code)


@check("S15: a board that ANSWERED is unconfirmed, not torn", "S15-refused")
def _(r):
    return not r.passed and r.row["verdict"] == "unconfirmed", \
        f"{r.row['verdict']} passed={r.passed}"


@check("S15: the remedy names the refusal instead of a later cut", "S15-refused")
def _(r):
    """A RESET refused past CTAP 2.1 §6.6 comes back 0x30 well under the
    keepalive floor. `cut later than 100 ms` is the wrong remedy for it, and
    `sender` was the clue the record held and the console never printed."""
    said, console = str(r.exit_code), r.said("what the RESET sender came back with")
    return ("0x30" in said and "no cut delay changes that" in said
            and len(console) == 1), f"{said!r} / console={console}"


@check("S16: a CBOR response is not a keepalive, whatever byte 7 carries", "S16-answered-01")
def _(r):
    """Its body IS `STATUS_PROCESSING`. Without the `CTAPHID_KEEPALIVE` test the
    tap reads the answer as proof of the wipe it refused to start."""
    return not r.passed and r.row["verdict"] == "unconfirmed" and r.row["keepalives"] == [], \
        f"{r.row['verdict']} passed={r.passed} keepalives={r.row['keepalives']}"


@check("S4: a missing directory is created and the line written", "S4-missing-dir")
def _(r):
    return len(r.rows) == 1 and r.passed, f"{len(r.rows)} line(s), passed={r.passed}"


@check("S4: the directory it creates is private", "S4-missing-dir")
def _(r):
    """0700: the default lives in a shared temp under a predictable name."""
    mode = stat.S_IMODE(pathlib.Path(r.path).parent.stat().st_mode)
    return mode == 0o700, oct(mode)


@check("S4: the record file it creates is private too", "S4-missing-dir")
def _(r):
    """0600 on the FILE, not just 0700 on the directory: `os.open`'s mode is the
    only thing that sets it, and it applies on create — which is this run."""
    mode = stat.S_IMODE(pathlib.Path(r.path).stat().st_mode)
    return mode == 0o600, oct(mode)


@check("S4b: an unwritable record costs the line, not the run", "S4b-unwritable")
def _(r):
    warned = any("WARNING" in line for _, line in r.stamps)
    return len(r.rows) == 0 and r.passed and r.exit_code == 0 and warned, \
        f"{len(r.rows)} line(s), passed={r.passed}, exit={r.exit_code}, warned={warned}"


@check("S4c: an unwritable record never masks a failed assertion", "S4c-unwritable-and-red")
def _(r):
    return isinstance(r.result, AssertionError), r.exit_code


@check("S18: the append refuses a symlink somebody planted", "S18-planted-symlink")
def _(r):
    warned = r.said("no cut record written")
    return r.target.read_text() == "" and len(warned) == 1, \
        f"target={r.target.read_text()!r}, warnings={warned}"


@check("S18: refusing it costs the line, not the run", "S18-planted-symlink")
def _(r):
    return r.passed and r.exit_code == 0, f"passed={r.passed} exit={r.exit_code}"


@check("S17: a console summary that raises does not report the line as missing",
       "S17-summary-raises")
def _(r):
    """One `try` spanned the write AND the narration, so a raise in the loop
    printed `no cut record written` over a record that was already on disk."""
    lied = r.said("no cut record written")
    owned = r.said("the cut IS recorded")
    return not lied and len(owned) == 1, f"lied={lied}, owned={owned}"


@check("S17: …and the line really is on disk", "S17-summary-raises")
def _(r):
    return len(r.rows) == 1 and r.row["verdict"] == "torn", f"{len(r.rows)} line(s)"


@check("S5: a close() that raises does not cost the record", "S5-close-raises")
def _(r):
    return len(r.rows) == 1 and r.row["verdict"] == "torn", f"{len(r.rows)} line(s)"


@check("S6: a key that never disappeared is still a line", "S6-wait-gone-timeout")
def _(r):
    return len(r.rows) == 1 and r.row["verdict"] == "never_gone", \
        f"{len(r.rows)} line(s), {r.row['verdict'] if r.row else None}"


@check("S7: a key that never came back is still a line", "S7-never-came-back")
def _(r):
    return len(r.rows) == 1 and r.row["verdict"] == "never_back", \
        f"{len(r.rows)} line(s), {r.row['verdict'] if r.row else None}"


@check("S8: a relay that failed is still a line", "S8-relay-nonzero")
def _(r):
    return len(r.rows) == 1 and r.row["verdict"] == "relay_failed", \
        f"{len(r.rows)} line(s), {r.row['verdict'] if r.row else None}"


@check("S11: a cut after the wipe is recorded as missed", "S11-missed-window")
def _(r):
    return (len(r.rows) == 1 and r.row["verdict"] == "missed"
            and "INCONCLUSIVE" in str(r.exit_code)), \
        f"{r.row['verdict'] if r.row else None}, exit={r.exit_code}"


@check("S11: a transfer that survived bounds nothing", "S11-missed-window")
def _(r):
    return r.row["death"] is None and r.row["cut_upper_ms"]["transfer_death"] is None, r.row["death"]


@check("S12: a sender that never saw the cut is stuck, not torn", "S12-sender-stuck")
def _(r):
    """`worker.join(5)` timed out, so the transfer observed nothing and neither
    bound is anything. A device on which the reset never ended is fail-closed
    for free, exactly like one on which it never began."""
    return (r.row["verdict"] == "stuck" and not r.passed
            and "INCONCLUSIVE" in str(r.exit_code)), \
        f"{r.row['verdict']} passed={r.passed} exit={r.exit_code}"


@check("S19: an absent seal over a FRESH seed is not a failure", "S19-seal-gone")
def _(r):
    return r.passed and r.exit_code == 0, f"passed={r.passed} exit={r.exit_code}"


@check("S19b: the owner's seed behind an absent seal is an AssertionError",
       "S19b-owner-seed-survived")
def _(r):
    """`ResetKeepsTheBackupSeal`, the one clause with an assertion of its own —
    and the arm no scenario drove: every board here left `sealed` at its default,
    so the whole `if not sealed:` body could be replaced by `pass`."""
    return isinstance(r.result, AssertionError) and "owner seed survived" in str(r.result), \
        f"{type(r.result).__name__}: {r.result}"


@check("S20: the host_saw_gone floor is DERIVED, not the number it is today",
       "S20-poll-moved")
def _(r):
    """Its twin above reads `replug.POLL_S` at 0.05, where a floor hard-coded to
    50.0 is indistinguishable from one that computes it. This run moves it."""
    want = round(r.poll_s * 1000, 1)
    return r.row["error_ms"]["host_saw_gone"] == want, \
        f"{r.row['error_ms']['host_saw_gone']} == {want} (POLL_S moved to {r.poll_s})"


@check("manual: a hand commands no delay", "manual-arm")
def _(r):
    return r.row["arm"] == "manual" and r.row["commanded_delay_ms"] is None, \
        f"{r.row['arm']}, {r.row['commanded_delay_ms']}"


@check("manual: the CUT line reaches the operator before the keepalive floor", "manual-arm")
def _(r):
    zero = r.zero()
    at = [t for t, line in r.stamps if "CUT POWER NOW" in line]
    if not at:
        return False, "the CUT line was never printed"
    late = (at[0] - zero) * 1000
    return late < r.mod.KEEPALIVE_MS, f"printed {late:.2f} ms after zero, floor {r.mod.KEEPALIVE_MS} ms"


@check("manual: a hand-driven cut is torn", "manual-arm")
def _(r):
    return r.row["verdict"] == "torn" and r.passed, f"{r.row['verdict']}, passed={r.passed}"


@check("S13: a credential that authorises after the cut is an AssertionError", "S13-failing-assert")
def _(r):
    return isinstance(r.result, AssertionError), r.exit_code


@check("S13: the cut's own numbers survive the failure", "S13-failing-assert")
def _(r):
    return len(r.rows) == 1 and r.row["cut_upper_ms"]["transfer_death"] is not None, \
        f"{len(r.rows)} line(s)"


@check("sweep: two cuts are two enumerable lines", "sweep")
def _(r):
    return len(r.rows) == 2 and [x["commanded_delay_ms"] for x in r.rows] == [150, 250], \
        [x["commanded_delay_ms"] for x in r.rows]


# -------------------------------------------------------------- the mutants ---
#: (name, edits, the checks that MUST go red). Each entry breaks the instrument
#: one way and names the assertions that catch it, so a kill is read by WHICH
#: check fell rather than by how many did — an arm that goes red for the inverse
#: defect is a failure here. Only the scenarios those checks need are run, which
#: is what keeps the table inside a gate row's budget. Every pattern must hit
#: exactly once: a mutant that did not apply is a broken arm wearing a pass.
MUTANTS = [
    ("M1  the wipe-observed gate", [
        ('        if tap.processing_at() is None:\n            cut["verdict"] = "unconfirmed"\n',
         '        if False and tap.processing_at() is None:\n            cut["verdict"] = "unconfirmed"\n')],
     ["S3a: a cut before the write does not print PASS",
      "S3a: it is recorded as unconfirmed",
      "S3b: a request the device never saw does not print PASS",
      "S3b: it is recorded as unconfirmed"]),
    ("M2  the keepalive STATUS is read", [
        ("        at = (when for carried, when in self.keepalives if carried == status)",
         "        at = (when for carried, when in self.keepalives)")],
     ["S10: a touch wait is not a running wipe",
      "S10: the refusal names the ceremony rather than a late cut"]),
    ("M3  an empty read is not a frame", [
        ("        if not frame:\n            self.empty_reads += 1\n            return frame\n", "")],
     ["S1: an empty read is not a surviving call", "S1: the timed-out reads are counted"]),
    ("M4  transfer_death is qualified by WHY the transfer died", [
        ('''        except Exception as error:  # the expected path is a dead USB handle
            outcome["error"] = repr(error)''',
         '''        except Exception as error:  # the expected path is a dead USB handle
            outcome["died"] = time.perf_counter()
            outcome["error"] = repr(error)'''),
        ('            "transfer_death": since(tap.death[0]) if death and death["bounds_the_cut"] else None,',
         '            "transfer_death": since(outcome.get("died")),')],
     ["S2: a read-budget death bounds nothing"]),
    ("M5  the append is inside a try", [
        ("""        try:
            cut.update(bounds(opened, gone, tap, outcome))
            append_cut(cut)
        except Exception as error:
            print(f"WARNING: no cut record written to {CUT_RECORD}: {error!r}")
        else:""",
         """        if True:
            cut.update(bounds(opened, gone, tap, outcome))
            append_cut(cut)
        if True:""")],
     ["S4b: an unwritable record costs the line, not the run",
      "S4c: an unwritable record never masks a failed assertion"]),
    ("M6  the record is written from the finally", [
        ("    finally:\n        # Two scopes,",
         "    finally:\n        pass\n    if True:\n        # Two scopes,")],
     ["S6: a key that never disappeared is still a line",
      "S7: a key that never came back is still a line",
      "S8: a relay that failed is still a line"]),
    ("M7  makedirs before the append", [
        ("    directory = os.path.dirname(CUT_RECORD)\n    if directory:\n"
         "        os.makedirs(directory, mode=0o700, exist_ok=True)\n", "")],
     ["S4: a missing directory is created and the line written",
      "S4: the directory it creates is private"]),
    ("M8  the manual arm's honest null", [
        ("""    commanded = (
        int(os.environ.get("RSK_POWER_CUT_DELAY_MS", str(DEFAULT_DELAY_MS)))
        if command
        else None
    )""",
         """    commanded = int(os.environ.get("RSK_POWER_CUT_DELAY_MS", str(DEFAULT_DELAY_MS)))""")],
     ["manual: a hand commands no delay"]),
    ("M9  host_saw_gone taken after the wait", [
        ("        replug.wait_gone()\n        gone = time.perf_counter()\n",
         "        gone = time.perf_counter()\n        replug.wait_gone()\n")],
     ["S3b: host_saw_gone >= the true cut"]),
    ("M10 the default delay clears the keepalive", [
        ("DEFAULT_DELAY_MS = 2 * KEEPALIVE_MS", "DEFAULT_DELAY_MS = 25")],
     ["torn: the cut is recorded as torn", "torn: the wipe was observed",
      "torn: the default delay is above the keepalive floor",
      "torn: PASS is printed and the exit is 0"]),
    ("M11 the death instant comes from the tap", [
        ('            "transfer_death": since(tap.death[0]) if death and death["bounds_the_cut"] else None,',
         '            "transfer_death": since(gone) if death and death["bounds_the_cut"] else None,')],
     ["S3b: the death instant is the handle's, not the host's poll"]),
    ("M12 first_said answers the FIRST, not the last", [
        ("        at = (when for carried, when in self.keepalives if carried == status)\n"
         "        return next(at, None)",
         "        at = [when for carried, when in self.keepalives if carried == status]\n"
         "        return at[-1] if at else None")],
     ["torn: first_keepalive is the instant the board wrote its FIRST one"]),
    ("M13 first_keepalive is measured, not a constant", [
        ('        "wipe_lower_ms": {"first_keepalive": since(tap.processing_at())},',
         '        "wipe_lower_ms": {"first_keepalive": 0.0 if tap.processing_at() else None},')],
     ["torn: first_keepalive is the instant the board wrote its FIRST one"]),
    ("M14 the KEEPALIVE command byte is checked", [
        ("        if len(frame) > 7 and frame[4] == CTAPHID_KEEPALIVE:",
         "        if len(frame) > 7:")],
     ["S16: a CBOR response is not a keepalive, whatever byte 7 carries"]),
    ("M15 the keepalive's CHANNEL is checked", [
        ("            if bytes(frame[:4]) == self.cid:",
         "            if True:")],
     ["S14: a keepalive on ANOTHER channel does not confirm our reset",
      "S14: the foreign frames are counted, not silently dropped",
      "S14: the refusal says the device was busy elsewhere"]),
    ("M16 the write and the summary have their own scopes", [
        ("""            append_cut(cut)
        except Exception as error:
            print(f"WARNING: no cut record written to {CUT_RECORD}: {error!r}")
        else:
            try:
                say_cut(cut)
            except Exception as error:
                print(f"WARNING: the cut IS recorded in {CUT_RECORD}; only this "
                      f"summary of it failed: {error!r}")""",
         """            append_cut(cut)
            say_cut(cut)
        except Exception as error:
            print(f"WARNING: no cut record written to {CUT_RECORD}: {error!r}")""")],
     ["S17: a console summary that raises does not report the line as missing"]),
    ("M17 the append refuses to follow a symlink", [
        ("    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW",
         "    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND")],
     ["S18: the append refuses a symlink somebody planted"]),
    ("M18 the record directory is made private", [
        ("        os.makedirs(directory, mode=0o700, exist_ok=True)",
         "        os.makedirs(directory, exist_ok=True)")],
     ["S4: the directory it creates is private"]),
    ("M19 a refusal is not diagnosed as a late cut", [
        ("            if response:\n                why = (f\"the board ANSWERED",
         "            if False:\n                why = (f\"the board ANSWERED")],
     ["S15: the remedy names the refusal instead of a later cut"]),
    ("M20 a touch wait is not diagnosed as a late cut", [
        ("            elif tap.touch_wait_at() is not None:", "            elif False:")],
     ["S10: the refusal names the ceremony rather than a late cut"]),
    ("M22 a sender that never noticed is refused", [
        ("""        if worker.is_alive():
            cut["verdict"] = "stuck"
            fresh.close()
            sys.exit("INCONCLUSIVE: the RESET sender did not observe the power loss")
""", "")],
     ["S12: a sender that never saw the cut is stuck, not torn"]),
    ("M23 the backup-seal clause is asserted", [
        ("""        if not sealed:
            current = backup.read_seed(dev, cid, PIN.decode() if options.get("clientPin") else None)
            assert current != owner_seed, "owner seed survived after its backup seal disappeared"
""",
         "        if not sealed:\n            pass\n")],
     ["S19b: the owner's seed behind an absent seal is an AssertionError"]),
    ("M24 the host_saw_gone floor is computed", [
        ('            "host_saw_gone": round(replug.POLL_S * 1000, 1),',
         '            "host_saw_gone": 50.0,')],
     ["S20: the host_saw_gone floor is DERIVED, not the number it is today"]),
    ("M25 the record file is created private", [
        ("    with os.fdopen(os.open(CUT_RECORD, flags, 0o600), \"a\") as record:",
         "    with os.fdopen(os.open(CUT_RECORD, flags, 0o666), \"a\") as record:")],
     ["S4: the record file it creates is private too"]),
    ("M21 the line describes what it is a verdict about", [
        ('        "run_id": RUN_ID,\n', ""),
        ('''        "records": ("this CUT, not the run: main's post-reboot assertions run "
                    "after this line is written, so a run that FAILED them "
                    "leaves the same verdict a passing one does. The run's "
                    "answer is its exit code, on the transcript carrying run_id"),\n''', "")],
     ["torn: the line carries the run id the console printed",
      "torn: the line says the verdict is the CUT's, not the run's"]),
]


# ------------------------------------------------------------- the evaluator ---
class World:
    """One loaded subject per source file, one driven Run per (subject, scenario)."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.runs = {}
        self.defaults = {}
        # The pristine load first, so `replug`, `ctaphid` and `rsk.backup` are in
        # `sys.modules` before a mutant is exec'd from a temp directory, where
        # its own `sys.path` edit cannot reach them.
        self.subject = load(SCRIPT, None)

    def default_delay(self, path):
        """The subject's OWN `DEFAULT_DELAY_MS` — a mutant may have moved it, and
        a board built from the pristine number would not notice."""
        if str(path) not in self.defaults:
            self.defaults[str(path)] = load(path, None).DEFAULT_DELAY_MS
        return self.defaults[str(path)]

    def run(self, path, name):
        key = (str(path), name)
        if key not in self.runs:
            room = self.tmp / pathlib.Path(path).stem
            room.mkdir(exist_ok=True)
            made = scenarios(path, self.default_delay(path), room)
            self.runs[key] = made[name]()
        return self.runs[key]

    def verdict(self, path, label):
        scenario, predicate = CHECKS[label]
        try:
            run = self.run(path, scenario)
        except BaseException as blew:               # a scenario that cannot run
            return False, f"scenario {scenario} blew up: {blew!r}"
        try:
            return predicate(run)
        except BaseException as blew:               # a check that cannot decide
            return False, (f"check raised {type(blew).__name__}: {blew}"
                           f" ({len(run.rows)} record line(s))")

    def mutate(self, name, edits, labels):
        """Apply `edits` to the subject in a temp file and answer those labels.

        The mutant is written OUTSIDE the checkout, which is the same rule its
        subject's own record follows and for the plainer reason: a gate row must
        not leave a broken copy of a test script in the tree if it dies.
        """
        text = SCRIPT.read_text()
        for old, new in edits:
            if text.count(old) != 1:
                raise AssertionError(
                    f"{name}: the pattern hits {text.count(old)} times, so this arm "
                    f"applies nothing and would pass by not existing: {old[:70]!r}")
            text = text.replace(old, new)
        # Named after the mutant rather than hashed: `hash()` is salted per
        # process, and a temp file nobody can point at is one nobody can read.
        path = self.tmp / f"mutant_{name.split()[0].lower()}.py"
        path.write_text(text)
        # A normalised umask, for the one arm that is about a MODE: `makedirs`
        # with no mode takes 0o777 & ~umask, which is already 0700 for a
        # developer running at 077 — the arm would survive on their machine and
        # on nobody else's.
        held = os.umask(0o022)
        try:
            return {label: self.verdict(path, label) for label in labels}
        finally:
            os.umask(held)


@pytest.fixture(scope="session")
def world(tmp_path_factory):
    room = tmp_path_factory.mktemp("reset-power-cut")
    made = World(room)
    yield made
    for name in ("RSK_POWER_CUT_LOG", "RSK_POWER_CUT_CMD", "RSK_POWER_CUT_DELAY_MS"):
        os.environ.pop(name, None)


# ------------------------------------------------------------------ the rows ---
@pytest.mark.parametrize("label", list(CHECKS))
def test_the_instrument_says_what_the_cut_was(label, world):
    ok, detail = world.verdict(SCRIPT, label)
    assert ok, f"{label} — {detail}"


@pytest.mark.parametrize("mutant", MUTANTS, ids=lambda m: m[0])
def test_a_broken_instrument_is_caught_by_the_check_that_names_it(mutant, world):
    """The arm. Every check above is only worth its row if breaking the thing it
    is about makes THAT check red — not some other one, and not merely some.

    A mutant that makes the script UNLOADABLE would redden every check it names
    without saying anything about the clause it removed, which is the "red for
    the wrong reason" this programme has already scored a kill on. That shape is
    refused separately; a check that RAISES is not, because a missing field or a
    missing directory legitimately reaches its predicate as an exception.
    """
    name, edits, kills = mutant
    verdicts = world.mutate(name, edits, kills)
    survived = [label for label, (ok, _) in verdicts.items() if ok]
    assert not survived, (
        f"{name}: survived {survived}; the others read "
        + "; ".join(f"{label} → {detail}" for label, (ok, detail) in verdicts.items() if not ok))
    # `str(detail)`: a predicate answers with what it SAW, which is as often an
    # int or a bool as a sentence, and `in` over one of those raises.
    unloadable = [f"{label} → {detail}" for label, (ok, detail) in verdicts.items()
                  if not ok and "blew up" in str(detail)]
    assert not unloadable, (
        f"{name}: red because the SCENARIO could not run, which says nothing "
        f"about the clause this arm removed — {unloadable}")


# ----------------------------------------------------------- the table's own ---
def test_every_check_names_a_scenario_that_exists():
    """A label pointing at no scenario is a check that reports a harness fault
    as a finding about the subject."""
    made = scenarios(SCRIPT, 200, pathlib.Path("/nonexistent"))
    unknown = sorted({name for name, _ in CHECKS.values()} - set(made))
    assert not unknown, unknown


def test_every_mutant_names_checks_that_exist_and_at_least_one():
    """A mutant with no kills passes by asserting nothing, which is the shape
    this whole file exists to refuse."""
    empty = [name for name, _, kills in MUTANTS if not kills]
    unknown = {name: sorted(set(kills) - set(CHECKS)) for name, _, kills in MUTANTS
               if set(kills) - set(CHECKS)}
    assert not empty and not unknown, f"kill-nothing: {empty}, unknown labels: {unknown}"


def test_every_scenario_is_read_by_some_check():
    """…and the other direction: a scenario nothing asserts about is a run whose
    only cost is the gate row's clock."""
    read = {name for name, _ in CHECKS.values()}
    made = set(scenarios(SCRIPT, 200, pathlib.Path("/nonexistent")))
    assert not made - read, sorted(made - read)


def test_the_guard_this_file_exists_for_is_named_by_a_mutant():
    """The `PROCESSING` gate, the channel check and the first-keepalive value:
    the three clauses a review found unfalsified, each owed a deletion arm."""
    edits = "".join(old for _n, pairs, _k in MUTANTS for old, _new in pairs)
    assert "if tap.processing_at() is None:" in edits
    assert "bytes(frame[:4]) == self.cid" in edits
    assert 'since(tap.processing_at())' in edits


def test_the_channel_check_reads_every_shape_a_handle_returns(world):
    """`cid` is `bytes` and a frame is not, which is how this check fails CLOSED.

    hidapi hands back a list of ints; a wrapper may hand back `bytes`, and
    `[17, 34, 51, 68] == b"\x11\x22\x33\x44"` is False — a comparison written
    without the `bytes(...)` would reject OUR frames too, and every run would
    come back `unconfirmed` for a reason no scenario above distinguishes from a
    cut that landed early. Both directions, over all three shapes.
    """

    class Handle:
        def __init__(self, carried):
            self.carried = carried

        def read(self, length, timeout_ms):
            return self.carried

    ours = frame(CTAPHID_KEEPALIVE, bytes([STATUS_PROCESSING]))
    theirs = frame(CTAPHID_KEEPALIVE, bytes([STATUS_PROCESSING]), FOREIGN_CID)
    for shape in (list, bytes, bytearray):
        mine = world.subject.TappedHid(Handle(shape(ours)), CID)
        mine.read(REPORT_LEN, 10)
        assert mine.processing_at() is not None, shape
        assert mine.foreign_keepalives == 0, shape

        alien = world.subject.TappedHid(Handle(shape(theirs)), CID)
        alien.read(REPORT_LEN, 10)
        assert alien.processing_at() is None, shape
        assert alien.foreign_keepalives == 1, shape


def test_two_runs_do_not_share_a_run_id():
    """The id joins ONE record line to ONE transcript, so a constant is worse
    than none: it would match every transcript the operator has. `os.urandom`
    per import is the whole mechanism, and nothing else here reads it twice."""
    assert load(SCRIPT, None).RUN_ID != load(SCRIPT, None).RUN_ID


def test_the_published_size_of_this_table_is_its_own():
    """Three run-counts about this file are published in prose, and prose rots.

    `run_count_gate.py` exists for exactly that class — seven stale ones in the
    tree the day it was written — but it scans named regions and these are not
    in one, so they are held here, where the numbers live.
    """
    said = ((ROOT / "CHANGELOG.md").read_text()
            + (ROOT / "assurance/board/PLAT-FLASH-001.toml").read_text())
    made = scenarios(SCRIPT, 200, pathlib.Path("/nonexistent"))
    # Phrases and not bare numbers: a page this long says "8" somewhere about
    # something else, and a rule matching that would pass over thirteen deleted
    # arms. Each phrase carries the noun it counts, in the sentence it counts in.
    wrong = [phrase for phrase in (f"{len(CHECKS)} checks over {len(made)} scenarios",
                                   f"{len(MUTANTS)} mutants that each name")
             if said.count(phrase) < 2]
    assert not wrong, f"the two published copies do not both say {wrong}"


# ------------------------------------------------------- where the record goes ---
def test_the_default_record_escapes_the_checkout(world):
    """A run must leave nothing untracked in the tree — `tests/54_sram_residue.py`'s
    finding, for a file that is timings rather than a key image."""
    default = load(SCRIPT, None).CUT_RECORD
    assert os.path.isabs(default)
    assert ROOT not in pathlib.Path(default).resolve().parents


def test_the_default_record_directory_is_not_shared_between_users(world):
    """A predictable name in a shared temp is a directory somebody else can
    create first. The uid stops two accounts meeting in one path — it does not
    stop a squatter, and `append_cut` says so; the 0700, the 0600 and the
    `O_NOFOLLOW` are what the mutation table above covers."""
    default = load(SCRIPT, None).CUT_RECORD
    assert str(os.getuid()) in os.path.basename(os.path.dirname(default)), default


def test_an_explicit_record_path_is_honoured_verbatim(world, tmp_path):
    """`RSK_POWER_CUT_LOG` is the operator aiming it at a file to be committed."""
    aimed = tmp_path / "cuts.jsonl"
    assert load(SCRIPT, aimed).CUT_RECORD == str(aimed)


def test_the_subject_is_board_only_and_this_table_is_not():
    """Why this file is under `scripts/`: no `check.sh` row runs the script, so
    nothing but a host table can hold its instrument to anything. The row that
    collects this directory is `test_gate_scripts.py`'s to assert; this is the
    half about WHICH directory."""
    row = (ROOT / "scripts" / "check.sh").read_text()
    assert "29_reset_power_cut" not in row
    assert pathlib.Path(__file__).resolve().parent == ROOT / "scripts"
