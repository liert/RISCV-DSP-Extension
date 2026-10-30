"""Decode RISC-V P-extension instructions.

The encoding table comes from revision 0.6 of the Packed SIMD specification.
This module does not import IDA, so the decoder can be tested on its own.
"""

from riscv_p_data import (
    INSNS,
    KIND_IMM,
    KIND_PAIR,
    KIND_REG,
    SPEC_COMMIT,
    SPEC_VERSION,
)

_BY_OPCODE = {}
for _index, _row in enumerate(INSNS):
    _name, _xlen, _match, _mask, _ops = _row
    if (_mask & 0x7F) != 0x7F:
        raise RuntimeError(f"{_name} does not fix the whole opcode")
    if _match & ~_mask:
        raise RuntimeError(f"{_name} has match bits outside its mask")
    _covered = 0
    for _op in _ops:
        for _bit in _op[3]:
            if _covered & (1 << _bit) or _mask & (1 << _bit):
                raise RuntimeError(f"{_name} has overlapping operand bit {_bit}")
            _covered |= 1 << _bit
    _BY_OPCODE.setdefault(_match & 0x7F, []).append(_index)

MNEMONIC_WIDTH = max(len(row[0]) for row in INSNS)


def decode(word, xlen):
    """Return the instruction row, or None.

    xlen is 32 or 64. A row is (name, xlen, match, mask, operands).
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
        bits = row[3].bit_count()
        if found is not None and bits == found_bits:
            raise RuntimeError(f"ambiguous P encoding {word:#x}: {found[0]} and {row[0]}")
        if bits > found_bits:
            found = row
            found_bits = bits
    return found


def operand_value(word, operand):
    """Return the architectural operand value, including pair and width adjustments."""
    kind, signed, bias, bits = operand
    raw = 0
    for index, bit in enumerate(bits):
        if word & (1 << bit):
            raw |= 1 << index
    if kind == KIND_PAIR:
        return raw << 1
    if kind != KIND_IMM:
        return raw
    width = len(bits)
    if signed and width and (raw & (1 << (width - 1))):
        raw -= 1 << width
    return raw + bias


def encode(row, values):
    """Encode operand values into the instruction word described by row."""
    word = row[2]
    if len(values) != len(row[4]):
        raise ValueError(f"{row[0]} expects {len(row[4])} operands, got {len(values)}")
    for operand, value in zip(row[4], values):
        kind, signed, bias, bits = operand
        if kind == KIND_PAIR:
            if value & 1 or not 0 <= value <= 31:
                raise ValueError(f"register pair {value} is not an even register")
            raw = value >> 1
        elif kind == KIND_IMM:
            raw = value - bias
            if signed:
                raw &= (1 << len(bits)) - 1
        else:
            raw = value
        for index, bit in enumerate(bits):
            if raw & (1 << index):
                word |= 1 << bit
            elif raw & ~((1 << len(bits)) - 1):
                raise ValueError(f"value {value} does not fit in {row[0]}")
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
