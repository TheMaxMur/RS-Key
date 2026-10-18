# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""All three FIDO walks start from owned RPs and credentials before interruption."""
import hashlib
from contextlib import ExitStack

from . import codec
from .fido import auth_data, cm, pin_token, token_mac, verified
from .fido_fixtures import credential
from .hid_sequences import allocate
from .lifecycle import Action, change
from .runner import CtapRoute
from .timers import wait


def run(session):
    for kind in ("RP", "credential", "assertion"):
        for action in ("complete", "idle", "new-begin", "getInfo", "refused-command", "metadata", "update", "delete", "replace", "create", "foreign-CID", "wrong-walk", "card-command", "card-continuation", *(item.value for item in Action)):
            with session.case(f"fido.owned-cursor.{kind}.{action}", ("F13", "F15", "F16", "F18", "T08", "G10", "G11", "G12", "G14"),
                    effects=("create_fido_credential", "reboot") if action == Action.POWER_CYCLE.value else ("create_fido_credential",), touch=True, parameters={"walk": kind, "interruption": action}):
                session.require(session.profile == "rsk", "cursor retirement and foreign-channel contract requires RS-Key", "excluded_by_profile")
                session.require(action != "idle" or session.options.timeout > 31, "cursor idle expiry requires a 30-second observation interval")
                if action == "foreign-CID":
                    session.require(session.hid is not None and hasattr(session.hid, "cid"), "foreign HID channel unavailable", "excluded_by_mode")
                    other = allocate(session)
                if action.startswith("card-"):
                    from .binding import require_pair
                    require_pair(session)
                    session.select("fido")
                rp = session.fixture(session.current.name + ".rp", 8).hex() + ".oracle.invalid"
                with ExitStack() as stack:
                    owned = [stack.enter_context(credential(session, session.current.name + f".{i}", True, rp=rp if i < 2 else "other." + rp)) for i in range(3)]
                    write_version, write_token = pin_token(session, 5)
                    version, token = pin_token(session, 64)
                    by_id = {fixture.descriptor["id"]: fixture for fixture in owned}
                    query = owned[0].query(session, authenticate=False, options={"up": False, "uv": False})
                    del query[3]
                    # All grants precede Begin; token issuance must not mask a mutation's effect.
                    begin, following, count_key = (2, 3, 5) if kind == "RP" else (4, 5, 9)
                    parameters = {1: hashlib.sha256(rp.encode()).digest()} if kind == "credential" else None
                    def start():
                        return session.ctap_value(session.ctap(2, query)) if kind == "assertion" else session.ctap_value(cm(session, version, token, begin, parameters))
                    def next_leg():
                        return session.ctap(8) if kind == "assertion" else cm(session, version, token, following)
                    first = start()
                    total = first.get(5 if kind == "assertion" else count_key, 1)
                    session.check("owned fixtures establish a nonempty continuation", 2 <= total <= 4096)
                    seen = set()
                    def witness(value):
                        if kind == "RP":
                            identifier = value[4]
                            session.check("RP row hashes the reported RP", identifier, hashlib.sha256(value[3]["id"].encode()).digest())
                        elif kind == "credential":
                            identifier = value[7]["id"]
                            session.check("credential cursor returns an owned reference", identifier in by_id)
                            session.check("credential cursor retains exact user ID", value[6]["id"], session.fixture(session.current.name + f".{0 if identifier == owned[0].descriptor['id'] else 1}.user", 16))
                        else:
                            identifier = value[1]["id"]
                            session.check("assertion cursor returns an owned reference", identifier in by_id)
                            fixture = by_id[identifier]
                            signed = auth_data(value[2])
                            session.check("continuation preserves initiating RP", signed["rp_hash"], fixture.parsed["rp_hash"])
                            verified(session, "cursor signature binds the initiating clientDataHash", fixture.key, fixture.algorithm, value[3], value[2] + owned[0].challenge)
                        session.check("cursor never repeats a previously emitted row", identifier not in seen)
                        seen.add(identifier)
                    witness(first)
                    if action == "idle":
                        wait(session, 30.25)
                    elif action == "new-begin":
                        first = start()
                        seen.clear()
                        witness(first)
                    elif action == "getInfo":
                        session.ctap_value(session.ctap(4))
                    elif action == "refused-command":
                        session.check("unrelated command is refused", session.ctap(0xff).status, 1)
                    elif action == "metadata":
                        session.ctap_value(cm(session, version, token, 1))
                    elif action == "update":
                        user = {"id": session.fixture(session.current.name + ".0.user", 16), "name": "cursor-updated"}
                        session.ctap_value(cm(session, write_version, write_token, 7, {2: owned[0].descriptor, 3: user}))
                    elif action == "delete":
                        session.ctap_value(cm(session, write_version, write_token, 6, {2: owned[0].descriptor}))
                        owned[0].deleted = True
                    elif action in ("replace", "create"):
                        replacement_label = session.current.name + (".0" if action == "replace" else ".created")
                        challenge = session.fixture(replacement_label + ".hash")
                        extra = {8: token_mac(write_version, write_token, challenge), 9: write_version}
                        fresh = stack.enter_context(credential(session, replacement_label, True, rp=rp, extra=extra, authenticate=False))
                        if action == "replace":
                            owned[0].deleted = True
                        owned.append(fresh)
                    elif action == "card-command":
                        session.select("piv")
                        session.card_value(session.apdu(codec.apdu(0xfd)))
                    elif action == "card-continuation":
                        with session.route(CtapRoute.CARD):
                            session.check("card cannot continue a HID-owned walk", next_leg().status, 0x30)
                    elif action in {item.value for item in Action}:
                        change(session, Action(action))
                    elif action == "foreign-CID":
                        owner = session.hid.cid
                        try:
                            session.hid.cid = other
                            session.check("foreign channel cannot continue an owned walk", next_leg().status, 0x30)
                        finally:
                            session.hid.cid = owner
                    elif action == "wrong-walk":
                        wrong = cm(session, version, token, 5 if kind == "RP" else 3) if kind != "assertion" else cm(session, version, token, 3)
                        session.check("different walk cannot consume another kind's continuation", wrong.status, 0x30)
                    if action in ("complete", "new-begin", "foreign-CID", "card-command", "card-continuation", Action.RECONNECT.value, Action.CARD_RESET.value):
                        for _ in range(total - 1):
                            witness(session.ctap_value(next_leg()))
                        session.check("walk exhausts exactly its declared count", len(seen), total)
                        session.check("walk cannot replay its final continuation", next_leg().status, 0x30)
                    elif action == "wrong-walk" and kind != "assertion":
                        witness(session.ctap_value(next_leg()))
                        session.check("wrong-kind refusal leaves the owner's walk usable", len(seen), 2)
                    else:
                        session.check("interruption retires the initialized walk", next_leg().status, 0x30)
                    for fixture in owned:
                        if fixture.deleted:
                            session.check("mutated reference cannot revive its deleted private key", session.ctap(2, fixture.query(session)).status, 0x2e)
                        else:
                            fixture.assertion(session)
