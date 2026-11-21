# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Bounded stateful generation reestablishes an owned fixture for every replay."""
import random
from enum import Enum

from . import codec
from .oath_states import calculate
from .otp import oath_names, oath_open, oath_request, otp_value

SEQUENCE_COUNT, SEQUENCE_LENGTH = 16, 12


class Step(str, Enum):
    PUT = "put"
    CALCULATE = "calculate"
    DELETE = "delete"
    SELECT = "select"
    REFUSE = "refuse"


def steps(recipe):
    if not isinstance(recipe, dict) or recipe.get("model") != "oath-v1" or not isinstance(recipe.get("seed"), str):
        raise ValueError("sequence recipe needs the oath-v1 model and seed")
    values = recipe.get("steps")
    if not isinstance(values, list) or not 0 <= len(values) <= 256:
        raise ValueError("sequence recipe requires at most 256 semantic steps")
    parsed, live = [], False
    for value in values:
        step = Step(value)
        if step in (Step.CALCULATE, Step.DELETE) and not live:
            raise ValueError("sequence transition needs an existing owned record")
        if step == Step.PUT:
            live = True
        elif step == Step.DELETE:
            live = False
        parsed.append(step)
    return parsed


def recipes(seed):
    generator = random.Random(seed + ":OATH-state-sequences-v1")
    for _ in range(SEQUENCE_COUNT):
        program, live = [], False
        for _ in range(SEQUENCE_LENGTH):
            choices = list(Step) if live else [Step.PUT, Step.SELECT, Step.REFUSE]
            selected = generator.choice(choices)
            program.append(selected.value)
            if selected in (Step.PUT, Step.DELETE):
                live = selected == Step.PUT
        yield {"model": "oath-v1", "seed": seed, "steps": program,
               "initial_state": "owned names absent; preserve all preexisting OATH records"}


def replay(session, recipe, name):
    program = steps(recipe)
    with session.case(name, ("A02", "A03", "A04", "A05", "G09", "G11", "G13", "G14"),
            effects=("create_oath_record",), parameters={"sequence_recipe": recipe},
            method="seeded bounded state sequence; fresh setup and private witness after every step"):
        session.require(session.profile == "rsk", "sequence transition semantics require RS-Key", "excluded_by_profile")
        session.require(session.options.seed == recipe["seed"], "replay must use the original fixture seed")
        oath_open(session)
        before = oath_names(session)
        target = b"oracle-sequence-" + session.fixture(name + ".name", 8).hex().encode()
        neighbor = target + b"-neighbor"
        session.require(not {target, neighbor} & before, "sequence names must be confirmed absent")
        neighbor_secret = session.fixture(name + ".neighbor", 20)
        created, live, revision, counter = set(), False, 0, 0
        secret = None
        try:
            oath_request(session, 1, codec.tlv(0x71, neighbor) + codec.tlv(0x73, b"\x21\x06" + neighbor_secret))
            created.add(neighbor)
            for index, step in enumerate(program):
                session.trace.emit("sequence_step", index=index, action=step.value, record_live=live, counter=counter)
                session.observe("sequence_action", step.value)
                if step == Step.PUT:
                    revision += 1
                    secret = session.fixture(name + f".secret-{revision}", 20)
                    oath_request(session, 1, codec.tlv(0x71, target) + codec.tlv(0x73, b"\x11\x06" + secret))
                    created.add(target)
                    live, counter = True, 0
                elif step == Step.DELETE:
                    oath_request(session, 2, codec.tlv(0x71, target))
                    created.remove(target)
                    live = False
                elif step == Step.CALCULATE:
                    session.check("generated explicit HOTP operation matches its moving factor", calculate(session, target, bytes(8)),
                                  otp_value(secret, counter.to_bytes(8, "big"), "sha1", 6))
                    counter += 1
                elif step == Step.SELECT:
                    oath_open(session)
                else:
                    session.check("generated parser refusal has the selected cause", session.apdu(codec.apdu(1, data=b"\x71\xff")).status, 0x6a80)
                session.check("generated transition retains the exact record set", oath_names(session), before | created)
                session.check("generated transition preserves neighboring private material", calculate(session, neighbor, bytes(8)),
                              otp_value(neighbor_secret, bytes(8), "sha1", 6))
                if live:
                    session.check("generated transition preserves HOTP private state", calculate(session, target, bytes(8)),
                                  otp_value(secret, counter.to_bytes(8, "big"), "sha1", 6))
                    counter += 1
        finally:
            if not session.broken:
                session.trace.phase = "cleanup"
                oath_open(session)
                for owned in (target, neighbor):
                    if owned in oath_names(session):
                        oath_request(session, 2, codec.tlv(0x71, owned))
                session.check("generated sequence restores original names", oath_names(session), before)


def run(session):
    for index, recipe in enumerate(recipes(session.options.seed)):
        replay(session, recipe, f"oath.generated-sequence.{index}")
