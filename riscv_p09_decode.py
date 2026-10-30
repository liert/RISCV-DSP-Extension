"""Decode T-Head E907 / P v0.9.11 instructions.

The encoding table comes from the historical binutils P opcode list.
This module does not import IDA, so the decoder can be tested on its own.
Register fields are full 5-bit numbers. Even-register constraints are
match predicates, not a pair shift. Immediates are unsigned.
"""

from riscv_p09_data import (
    INSNS,
    KIND_IMM,
    KIND_REG,
    SOURCE_COMMIT,
    SOURCE_VERSION,
)

_FIELD_LSB = (7, 15, 20)
_BY_OPCODE = {}
for _index, _row in enumerate(INSNS):
    _name, _xlen, _match, _mask, _ops, _even = _row
    if (_mask & 0x7F) != 0x7F or (_match & 0x7F) != 0x77:
        raise RuntimeError(f"{_name} is not opcode 0x77")
    if _match & ~_mask:
        raise RuntimeError(f"{_name} has match bits outside its mask")
    if _even & ~0b111:
        raise RuntimeError(f"{_name} has an unknown even-register bit")
    _covered = 0
    for _op in _ops:
        for _bit in _op[3]:
            if _covered & (1 << _bit) or _mask & (1 << _bit):
                raise RuntimeError(f"{_name} has overlapping operand bit {_bit}")
            _covered |= 1 << _bit
    for _bit_index, _lsb in enumerate(_FIELD_LSB):
        if _even & (1 << _bit_index):
            if not any(_op[0] == KIND_REG and _op[3][0] == _lsb for _op in _ops):
                raise RuntimeError(f"{_name} requires an even register that it does not have")
    _BY_OPCODE.setdefault(_match & 0x7F, []).append(_index)

MNEMONIC_WIDTH = max(len(row[0]) for row in INSNS)


def _even_ok(word, even):
    if even & 0b001 and ((word >> 7) & 1):
        return False
    if even & 0b010 and ((word >> 15) & 1):
        return False
    if even & 0b100 and ((word >> 20) & 1):
        return False
    return True


def decode(word, xlen):
    """Return the instruction row, or None.

    xlen is 32 or 64. A row is (name, xlen, match, mask, operands, even_mask).
    """
    word &= 0xFFFFFFFF
    found = None
    found_bits = -1
    for index in _BY_OPCODE.get(word & 0x7F, ()):
        row = INSNS[index]
        if row[1] not in (0, xlen):
            continue
        if (word & row[3]) != row[2]:
            continue
        if not _even_ok(word, row[5]):
            continue
        bits = row[3].bit_count()
        if found is not None and bits == found_bits:
            raise RuntimeError(f"ambiguous P v0.9 encoding {word:#x}: {found[0]} and {row[0]}")
        if bits > found_bits:
            found = row
            found_bits = bits
    return found


def operand_value(word, operand):
    """Return the architectural operand value."""
    kind, signed, bias, bits = operand
    raw = 0
    for index, bit in enumerate(bits):
        if word & (1 << bit):
            raw |= 1 << index
    if kind != KIND_IMM:
        return raw
    width = len(bits)
    if signed and width and (raw & (1 << (width - 1))):
        raw -= 1 << width
    return raw + bias


def encode(row, values):
    """Encode operand values into the instruction word described by row."""
    word = row[2]
    operands = row[4]
    even = row[5]
    if len(values) != len(operands):
        raise ValueError(f"{row[0]} expects {len(operands)} operands, got {len(values)}")
    for operand, value in zip(operands, values):
        kind, _signed, _bias, bits = operand
        if kind == KIND_IMM:
            if not 0 <= value < (1 << len(bits)):
                raise ValueError(f"immediate {value} does not fit in {row[0]}")
            raw = value
        else:
            if not 0 <= value <= 31:
                raise ValueError(f"register {value} is out of range")
            field = _FIELD_LSB.index(bits[0])
            if even & (1 << field) and value & 1:
                raise ValueError(f"{row[0]} requires an even register, got {value}")
            raw = value
        for index, bit in enumerate(bits):
            if raw & (1 << index):
                word |= 1 << bit
    return word & 0xFFFFFFFF


def format_insn(word, xlen):
    """Format one instruction with numeric xN register names."""
    row = decode(word, xlen)
    if row is None:
        return None
    rendered = []
    for operand in row[4]:
        value = operand_value(word, operand)
        if operand[0] == KIND_IMM:
            rendered.append(str(value))
        else:
            rendered.append(f"x{value}")
    if not rendered:
        return row[0]
    return row[0] + " " + ", ".join(rendered)
