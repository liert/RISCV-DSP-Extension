"""Build riscv_p09_data.py from the P v0.9.11 binutils opcode table.

Arguments are a local riscv-opc.c and riscv-opc.h. Those files stay out of
this repository: binutils is GPL, and the generated table stores only the
match word, mask, and operand fields.

The table this script reads is the one cited for historical P encodings:
ruyisdk binutils commit 1bcac7513f9faa4cd969f8dc7cf2491b6c22d7db.
T-Head E907 publishes its DSP unit as P v0.9.4. ADD64 in that table matches
the E907 encoding. Assembly aliases (swap16, rdov, clrov, kmada32, smbb32)
are omitted. bpick is not in this table.
"""

import re
import sys
from pathlib import Path

KIND_REG = 0
KIND_IMM = 2

SOURCE_VERSION = "0.9.11"
SOURCE_COMMIT = "1bcac7513f9faa4cd969f8dc7cf2491b6c22d7db"

# even_mask: bit 0 = rd, bit 1 = rs1, bit 2 = rs2.
EVEN = {
    "match_opcode": 0,
    "match_rd_even": 0b001,
    "match_rs1_even": 0b010,
    "match_rs2_rd_even": 0b101,
    "match_rs1_rd_even": 0b011,
    "match_rs2_rs1_rd_even": 0b111,
}

REG_FIELDS = {
    "d": (7, 8, 9, 10, 11),
    "s": (15, 16, 17, 18, 19),
    "t": (20, 21, 22, 23, 24),
}
IMM_FIELDS = {
    "n2": (20, 21),
    "n3": (20, 21, 22),
    "n4": (20, 21, 22, 23),
    "n5": (20, 21, 22, 23, 24),
    "n6": (20, 21, 22, 23, 24, 25),
}

ROW_RE = re.compile(
    r'\{"([^"]+)"\s*,\s*(\d+)\s*,\s*(INSN_CLASS_ZPN|INSN_CLASS_ZPSF)\s*,\s*"([^"]*)"\s*,\s*'
    r"([A-Za-z0-9_]+)\s*,\s*([A-Za-z0-9_]+)\s*,\s*(match_[A-Za-z0-9_]+)\s*,\s*([^}]*)\}"
)
DEF_RE = re.compile(
    r"^\s*#define\s+((?:MATCH|MASK)_[A-Z0-9_]+)\s+\(?\s*(0x[0-9a-fA-F]+)U?\s*\)?\s*(?:/\*.*\*/)?\s*$"
)


def load_defines(path):
    defines = {}
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        found = DEF_RE.match(line)
        if found:
            defines[found.group(1)] = int(found.group(2), 16)
    return defines


def operands_for(fmt):
    if fmt == "":
        return ()
    operands = []
    covered = 0
    for field in fmt.split(","):
        if field in REG_FIELDS:
            bits = REG_FIELDS[field]
            kind = KIND_REG
        elif field in IMM_FIELDS:
            bits = IMM_FIELDS[field]
            kind = KIND_IMM
        else:
            raise ValueError(f"unknown operand field {field!r} in {fmt!r}")
        for bit in bits:
            if covered & (1 << bit):
                raise ValueError(f"operand bits overlap in {fmt!r}")
            covered |= 1 << bit
        # signed=False, bias=0. P v0.9 immediates are unsigned.
        operands.append((kind, False, 0, bits))
    return tuple(operands)


def check_even(name, operands, even):
    by_lsb = {}
    for operand in operands:
        if operand[0] == KIND_REG:
            by_lsb[operand[3][0]] = operand
    expected = ((0b001, 7, "rd"), (0b010, 15, "rs1"), (0b100, 20, "rs2"))
    for bit, lsb, label in expected:
        if even & bit and lsb not in by_lsb:
            raise ValueError(f"{name} requires an even {label} but has no such register")


def conflicts(left, right):
    return ((left[2] ^ right[2]) & left[3] & right[3]) == 0


def check_table(rows):
    for name, xlen, match, mask, operands, _even in rows:
        if (mask & 0x7F) != 0x7F or (match & 0x7F) != 0x77:
            raise ValueError(f"{name} is not opcode 0x77")
        if match & ~mask:
            raise ValueError(f"{name} has match bits outside its mask")
        covered = 0
        for operand in operands:
            for bit in operand[3]:
                if mask & (1 << bit) or covered & (1 << bit):
                    raise ValueError(f"{name} operand bit {bit} overlaps the mask or another operand")
                covered |= 1 << bit
    for xlen in (32, 64):
        chosen = [row for row in rows if row[1] in (0, xlen)]
        for index, left in enumerate(chosen):
            for right in chosen[index + 1 :]:
                if not conflicts(left, right):
                    continue
                if left[3].bit_count() == right[3].bit_count():
                    raise ValueError(
                        f"ambiguous RV{xlen} encoding {left[0]} and {right[0]} "
                        f"({left[2]:#x}/{left[3]:#x})"
                    )


def parse_rows(opc_path, defines):
    rows = []
    skipped = []
    for line_number, line in enumerate(Path(opc_path).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if "INSN_CLASS_ZPN" not in line and "INSN_CLASS_ZPSF" not in line:
            continue
        found = ROW_RE.search(line)
        if not found:
            raise ValueError(f"{opc_path}:{line_number}: unparsed P opcode row: {line.strip()}")
        name, xlen_s, _klass, fmt, match_name, mask_name, matcher, flags = found.groups()
        if "INSN_ALIAS" in flags:
            skipped.append(name)
            continue
        if flags.strip() != "0":
            raise ValueError(f"{name} has unexpected flags {flags.strip()}")
        if matcher not in EVEN:
            raise ValueError(f"{name} has unknown matcher {matcher}")
        if match_name not in defines or mask_name not in defines:
            raise ValueError(f"{name} is missing a literal {match_name} or {mask_name}")
        xlen = int(xlen_s)
        if xlen not in (0, 32, 64):
            raise ValueError(f"{name} has xlen {xlen}")
        operands = operands_for(fmt)
        even = EVEN[matcher]
        check_even(name, operands, even)
        rows.append((name, xlen, defines[match_name], defines[mask_name], operands, even))
    if not rows:
        raise ValueError("no P instructions found")
    check_table(rows)
    return rows, skipped


def emit(rows, destination):
    lines = [
        '"""Generated P v0.9.11 encoding table. Do not edit by hand.',
        "",
        "Source: ruyisdk binutils opcodes/riscv-opc.c and riscv-opc.h,",
        f"commit {SOURCE_COMMIT}.",
        "The C sources are GPL and are not vendored. This table stores match,",
        "mask, and operand-field facts used by T-Head E907 P v0.9 encodings.",
        '"""',
        "",
        f'SOURCE_VERSION = "{SOURCE_VERSION}"',
        f'SOURCE_COMMIT = "{SOURCE_COMMIT}"',
        "KIND_REG = 0",
        "KIND_PAIR = 1",
        "KIND_IMM = 2",
        "# name, xlen (0 = RV32 and RV64), match, mask, operands, even_mask.",
        "# An operand is (kind, signed, bias, bits). bits[i] is the instruction",
        "# bit that contributes value bit i. Immediates are unsigned, with bit 0",
        "# at instruction bit 20. even_mask bit 0 = rd, bit 1 = rs1, bit 2 = rs2.",
        "# Register numbers are the full 5-bit fields. There is no pair shift.",
        "INSNS = (",
    ]
    for name, xlen, match, mask, operands, even in rows:
        rendered = []
        for kind, signed, bias, bits in operands:
            rendered.append(f"({kind}, {int(signed)}, {bias}, {bits})")
        ops = "(" + ", ".join(rendered) + ("," if len(rendered) == 1 else "") + ")"
        lines.append(f'    ("{name}", {xlen}, {match:#x}, {mask:#x}, {ops}, {even}),')
    lines.append(")")
    lines.append("")
    Path(destination).write_text("\n".join(lines), encoding="utf-8")


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: extract_p09.py riscv-opc.c riscv-opc.h riscv_p09_data.py")
    defines = load_defines(sys.argv[2])
    rows, skipped = parse_rows(sys.argv[1], defines)
    emit(rows, sys.argv[3])
    print(f"wrote {len(rows)} instructions, skipped {len(skipped)} aliases: {', '.join(skipped)}")


if __name__ == "__main__":
    main()
