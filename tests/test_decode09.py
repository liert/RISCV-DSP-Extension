"""Round-trip the P v0.9 decoder and keep it off the revision 0.6 encodings."""

import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from riscv_p09_data import INSNS, KIND_IMM, KIND_REG
from riscv_p09_decode import decode, encode, format_insn, operand_value
from riscv_p_decode import decode as decode06
from riscv_p_decode import encode as encode06
from riscv_p_data import INSNS as INSNS06


def row_by_name(name, xlen):
    found = [row for row in INSNS if row[0] == name and row[1] in (0, xlen)]
    if len(found) != 1:
        raise AssertionError(f"{name} xlen {xlen}: {len(found)} rows")
    return found[0]


def test_user_add64_word():
    # .text bytes 77 17 E6 C0, little-endian word 0xC0E61777.
    word = 0xC0E61777
    row = row_by_name("add64", 32)
    if (word & row[3]) != row[2]:
        raise AssertionError(f"add64 mask missed {word:#x}")
    if decode(word, 32) != row:
        raise AssertionError("RV32 did not decode the E907 add64 word")
    if format_insn(word, 32) != "add64 x14, x12, x14":
        raise AssertionError(format_insn(word, 32))
    if decode(word, 64) is not None:
        raise AssertionError("RV32 add64 decoded on RV64")
    if decode06(word, 32) is not None or decode06(word, 64) is not None:
        raise AssertionError("revision 0.6 claimed the add64 word")
    for bit in (7, 15, 20):
        if decode(word | (1 << bit), 32) is not None:
            raise AssertionError(f"odd register at bit {bit} was accepted")
    try:
        encode(row, [15, 12, 14])
    except ValueError:
        pass
    else:
        raise AssertionError("encode accepted an odd rd")


def test_normal_and_immediate_forms():
    cases = [
        ("add16", 32, [10, 11, 12], "x10, x11, x12"),
        ("kaddh", 32, [10, 11, 12], "x10, x11, x12"),
        ("kaddh", 64, [1, 31, 0], "x1, x31, x0"),
        ("srai16.u", 32, [10, 11, 7], "x10, x11, 7"),
        ("srai16.u", 32, [10, 11, 15], "x10, x11, 15"),
        ("swap8", 32, [14, 12], "x14, x12"),
        ("pkbt16", 32, [14, 12, 14], "x14, x12, x14"),
    ]
    for name, xlen, values, text in cases:
        row = row_by_name(name, xlen)
        word = encode(row, values)
        if decode(word, xlen) != row:
            raise AssertionError(f"{name} did not round-trip")
        rendered = format_insn(word, xlen)
        if rendered != f"{name} {text}":
            raise AssertionError(f"{name}: {rendered!r}")
        if decode06(word, xlen) is not None:
            raise AssertionError(f"revision 0.6 claimed {name}")


def test_xlen_and_even_split():
    clz = row_by_name("clz32", 64)
    word = encode(clz, [10, 11])
    if decode(word, 32) is not None:
        raise AssertionError("RV64 clz32 decoded on RV32")
    wide = row_by_name("bitrevi", 64)
    word = encode(wide, [10, 11, 32])
    if decode(word, 32) is not None:
        raise AssertionError("RV64 bitrevi immediate decoded on RV32")
    if operand_value(word, wide[4][2]) != 32:
        raise AssertionError("bitrevi n6 immediate was truncated")
    wext = row_by_name("wexti", 64)
    odd = encode(wext, [10, 11, 3])
    if decode(odd, 64) != wext:
        raise AssertionError("RV64 wexti rejected an odd rs1")
    if decode(odd, 32) is not None:
        raise AssertionError("RV32 wexti accepted an odd rs1")
    kadd = row_by_name("kadd64", 64)
    odd_rd = encode(kadd, [15, 12, 14])
    if decode(odd_rd, 64) != kadd:
        raise AssertionError("RV64 kadd64 rejected an odd rd")
    if decode(odd_rd, 32) is not None:
        raise AssertionError("RV32 kadd64 accepted an odd rd")


def test_base_and_revision_06_stay_separate():
    for word in (0x00B50533, 0x00008067, 0x00000013, 0x00000000):
        for xlen in (32, 64):
            if decode(word, xlen) is not None:
                raise AssertionError(f"{word:#x} decoded on RV{xlen}")
    for row in INSNS06:
        xlen = 64 if row[1] == 64 else 32
        values = []
        for operand in row[4]:
            kind = operand[0]
            if kind == KIND_REG:
                values.append(1)
            elif kind == 1:
                values.append(2)
            else:
                values.append(operand[2])
        word = encode06(row, values)
        if decode(word, xlen) is not None:
            raise AssertionError(f"v0.9 claimed revision 0.6 {row[0]}")


def _samples(operand, even):
    kind, _signed, _bias, bits = operand
    if kind == KIND_REG:
        field = (7, 15, 20).index(bits[0])
        if even & (1 << field):
            return (0, 2, 30)
        return (0, 1, 31)
    if kind != KIND_IMM:
        raise AssertionError(kind)
    limit = 1 << len(bits)
    return (0, 1, limit // 2, limit - 1)


def test_round_trip_every_instruction():
    for row in INSNS:
        xlen = 64 if row[1] == 64 else 32
        choices = [_samples(op, row[5]) for op in row[4]]
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
            other = 32 if xlen == 64 else 64
            if row[1] == xlen and decode(word, other) is not None and row[1] != 0:
                # A same-width immediate can also match the other XLEN row of
                # a split mnemonic. Only the row selected for that XLEN is used.
                other_row = decode(word, other)
                if other_row is not None and other_row[0] != row[0] and other_row[1] in (0, other):
                    if (word & other_row[3]) == other_row[2] and other_row[0] != row[0]:
                        raise AssertionError(f"{row[0]} collided with {other_row[0]}")


def main():
    test_user_add64_word()
    test_normal_and_immediate_forms()
    test_xlen_and_even_split()
    test_base_and_revision_06_stay_separate()
    test_round_trip_every_instruction()
    print(f"v0.9 decode tests passed ({len(INSNS)} instructions)")


if __name__ == "__main__":
    main()
