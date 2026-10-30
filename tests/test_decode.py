"""Round-trip the P-extension decoder against the generated encoding table."""

import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from riscv_p_data import INSNS, KIND_IMM, KIND_PAIR, KIND_REG
from riscv_p_decode import decode, encode, format_insn, operand_value


def row_by_name(name, xlen):
    found = [row for row in INSNS if row[0] == name and row[1] in (0, xlen)]
    if len(found) != 1:
        raise AssertionError(f"{name} xlen {xlen}: {len(found)} rows")
    return found[0]


def test_hand_encoded_words():
    cases = [
        ("pli.b", 32, [10, 0xA5], 0xB4A5251B, "x10, 165"),
        ("pli.h", 32, [10, -2], 0xB1FEA51B, "x10, -2"),
        ("padd.b", 32, [10, 11, 12], 0x84C5853B, "x10, x11, x12"),
        ("psati.h", 32, [10, 11, 8], 0xE175C51B, "x10, x11, 8"),
        ("pusati.h", 32, [10, 11, 8], None, "x10, x11, 8"),
        ("srari", 32, [10, 11, 3], None, "x10, x11, 3"),
        ("srari", 64, [10, 11, 3], None, "x10, x11, 3"),
    ]
    for name, xlen, values, expected, text in cases:
        row = row_by_name(name, xlen)
        word = encode(row, values)
        if expected is not None and word != expected:
            raise AssertionError(f"{name}: encoded {word:#x}, expected {expected:#x}")
        got = decode(word, xlen)
        if got != row:
            raise AssertionError(f"{name}: decoded {None if got is None else got[0]}")
        rendered = format_insn(word, xlen)
        if rendered != f"{name} {text}":
            raise AssertionError(f"{name}: rendered {rendered!r}")
        if name == "psati.h" and operand_value(word, row[4][2]) != 8:
            raise AssertionError("psati.h width was not reconstructed as uimm+1")


def test_base_instructions_are_not_claimed():
    add = 0x00B50533  # add a0, a0, a1
    jalr = 0x00008067  # jalr zero, ra, 0
    for word in (add, jalr, 0x00000013, 0x00000000):
        for xlen in (32, 64):
            if decode(word, xlen) is not None:
                raise AssertionError(f"{word:#x} decoded on RV{xlen}")


def test_xlen_is_separate():
    rv32 = row_by_name("pli.db", 32)
    word = encode(rv32, [2, 1])
    if decode(word, 64) is not None:
        raise AssertionError("RV32 pli.db decoded on RV64")
    rv64 = row_by_name("pli.w", 64)
    word = encode(rv64, [10, -1])
    if decode(word, 32) is not None:
        raise AssertionError("RV64 pli.w decoded on RV32")


def _samples(operand):
    kind, signed, bias, bits = operand
    width = len(bits)
    if kind == KIND_REG:
        return (0, 1, 31)
    if kind == KIND_PAIR:
        return (0, 2, 30)
    if kind != KIND_IMM:
        raise AssertionError(kind)
    limit = 1 << width
    raw_values = (0, 1, limit // 2, limit - 1)
    shown = []
    for raw in raw_values:
        if signed and raw & (1 << (width - 1)):
            shown.append(raw - limit + bias)
        else:
            shown.append(raw + bias)
    return tuple(shown)


def test_round_trip_every_instruction():
    for row in INSNS:
        xlen = 64 if row[1] == 64 else 32
        choices = [_samples(op) for op in row[4]]
        if not choices:
            word = encode(row, [])
            if decode(word, xlen) != row:
                raise AssertionError(f"{row[0]} did not round-trip")
            continue
        for values in itertools.product(*choices):
            word = encode(row, values)
            got = decode(word, xlen)
            if got != row:
                raise AssertionError(
                    f"{row[0]} RV{xlen} {values} -> {word:#x} decoded as "
                    f"{None if got is None else got[0]}"
                )
            for operand, value in zip(row[4], values):
                if operand_value(word, operand) != value:
                    raise AssertionError(f"{row[0]} operand {value} did not round-trip")


def main():
    test_hand_encoded_words()
    test_base_instructions_are_not_claimed()
    test_xlen_is_separate()
    test_round_trip_every_instruction()
    print(f"decode tests passed ({len(INSNS)} instructions)")


if __name__ == "__main__":
    main()
