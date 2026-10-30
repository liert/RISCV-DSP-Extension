"""Build riscv_p_data.py from the RISC-V P-extension AsciiDoc specification.

The input is P-ext-proposal.adoc from https://github.com/riscv/riscv-p-spec.
Encodings are read from the wavedrom diagrams in "Detailed Instruction
Descriptions". The equivalence chapter at the end of the document is not
an instruction list and is ignored.
"""

import re
import sys
from pathlib import Path

KIND_REG = 0
KIND_PAIR = 1
KIND_IMM = 2

SPEC_VERSION = "0.6"
SPEC_COMMIT = "85857f3eb17f93ba7076df6e6dab5568050d95e0"

FIXED_RE = re.compile(r"^0x([0-9a-fA-F]+)$")
SLICE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\[([^\]]+)\]$")
MIXED_RE = re.compile(r"^[01x]+$")
HEADING_RE = re.compile(r"^==== (.+)$", re.M)


def parse_index_list(spec):
    """MSB-to-LSB indices. '8:0|9' -> [8, 7, 6, 5, 4, 3, 2, 1, 0, 9]."""
    bits = []
    for part in spec.split("|"):
        part = part.strip()
        if ":" in part:
            hi_s, lo_s = part.split(":")
            hi, lo = int(hi_s), int(lo_s)
            step = -1 if hi >= lo else 1
            bits.extend(range(hi, lo + step, step))
        else:
            bits.append(int(part))
    return bits


def parse_field_name(raw):
    raw = raw.strip().strip("'\"")
    if re.fullmatch(r"0x[0-9a-fA-F]+", raw):
        return int(raw, 16)
    if re.fullmatch(r"\d+", raw):
        return int(raw)
    return raw


def diagram_fields(text):
    diagrams = re.findall(r"\{reg:\s*\[(.*?)\n\s*\]\}", text, re.S)
    parsed = []
    for diagram in diagrams:
        fields = []
        for match in re.finditer(
            r"\{\s*bits:\s*(\d+)\s*,\s*name:\s*([^,}\n]+)",
            diagram,
        ):
            fields.append({
                "width": int(match.group(1)),
                "name": parse_field_name(match.group(2)),
            })
        parsed.append(fields)
    return parsed


def layout_fields(title, raw_fields):
    """Return match, mask, and variable operands extracted LSB-first."""
    pos = 0
    match = 0
    mask = 0
    variables = []
    for field in raw_fields:
        width = field["width"]
        name = field["name"]
        lo = pos
        hi = pos + width - 1
        pos += width
        if isinstance(name, int):
            if name >= (1 << width):
                raise ValueError(f"{title}: fixed value 0x{name:x} does not fit in {width} bits")
            match |= name << lo
            mask |= ((1 << width) - 1) << lo
            continue
        if SLICE_RE.fullmatch(name):
            stem, spec = SLICE_RE.fullmatch(name).groups()
            indices = parse_index_list(spec)
            if len(indices) != width:
                raise ValueError(f"{title}: {name} has {len(indices)} indices for {width} bits")
            # Diagram names list the field from its MSB down to its LSB.
            bit_for_value = [0] * (max(indices) + 1)
            for offset, index in enumerate(indices):
                bit_for_value[index] = hi - offset
            base = min(indices)
            if indices != list(range(max(indices), base - 1, -1)) and sorted(indices) != list(range(base, base + width)):
                # Permutation of 0..width-1, or a contiguous window.
                if sorted(indices) != list(range(base, base + width)):
                    raise ValueError(f"{title}: immediate {name} is not a contiguous window")
            value_bits = tuple(bit_for_value[base + i] for i in range(width))
            variables.append({"stem": stem, "bits": value_bits, "signed_width": width})
            continue
        if isinstance(name, str) and MIXED_RE.fullmatch(name) and "x" in name:
            if len(name) != width:
                raise ValueError(f"{title}: pattern {name} has width {width}")
            xs = [i for i, ch in enumerate(name) if ch == "x"]
            # Leftmost character is the MSB of the field. The rightmost x is value bit 0.
            value_bits_rev = []
            for index in xs:
                value_bits_rev.append(hi - index)
            value_bits = tuple(reversed(value_bits_rev))
            for index, ch in enumerate(name):
                if ch in "01":
                    bit = hi - index
                    mask |= 1 << bit
                    if ch == "1":
                        match |= 1 << bit
            variables.append({
                "stem": f"uimm{len(xs)}",
                "bits": value_bits,
                "signed_width": len(xs),
            })
            continue
        variables.append({
            "stem": name,
            "bits": tuple(lo + i for i in range(width)),
            "signed_width": width,
        })
    if pos != 32:
        raise ValueError(f"{title}: diagram is {pos} bits, not 32")
    return match, mask, variables


def parse_operands(line):
    line = re.sub(r"\(RV(?:32|64)\)", "", line)
    line = line.replace("+", " ").strip()
    if not line:
        return None, []
    parts = line.split(None, 1)
    asm = parts[0].strip().strip("_")
    if len(parts) == 1:
        return asm, []
    operands = []
    for piece in parts[1].split(","):
        name = piece.strip().strip("_").strip()
        if name:
            operands.append(name)
    return asm, operands


def mnemonic_variants(block):
    lines = block.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == "Mnemonic::":
            start = index + 1
            break
    if start is None:
        return []
    collected = []
    for line in lines[start:]:
        if not line.strip():
            if collected:
                break
            continue
        if line.strip().endswith("::"):
            break
        collected.append(line.strip())
    variants = []
    for raw in collected:
        xlen = None
        tag = re.search(r"\((RV32|RV64)\)", raw)
        if tag:
            xlen = 32 if tag.group(1) == "RV32" else 64
        asm, operands = parse_operands(raw)
        if asm:
            variants.append((xlen, asm, operands))
    return variants


def encoding_text(block):
    found = re.search(
        r"Encoding::\s*\n(.*?)(?:\n(?:Description|Operation|Notes|Exceptions|Implementation)::)",
        block,
        re.S,
    )
    if not found:
        raise ValueError("encoding section not found")
    return found.group(1)


def diagram_variants(title, block, title_xlen):
    encoded = encoding_text(block)
    marked = re.split(r"\n(RV32|RV64):\s*\n", encoded)
    variants = []
    if len(marked) > 1:
        # re.split keeps the delimiters: [pre, 'RV32', body, 'RV64', body]
        it = iter(marked[1:])
        for label, body in zip(it, it):
            diagrams = diagram_fields(body)
            if len(diagrams) != 1:
                raise ValueError(f"{title}: {label} section has {len(diagrams)} diagrams")
            xlen = 32 if label == "RV32" else 64
            match, mask, variables = layout_fields(title, diagrams[0])
            variants.append((xlen, match, mask, variables))
        return variants
    diagrams = diagram_fields(encoded)
    if len(diagrams) != 1:
        raise ValueError(f"{title}: expected 1 diagram, found {len(diagrams)}")
    match, mask, variables = layout_fields(title, diagrams[0])
    return [(title_xlen, match, mask, variables)]


def width_bias(block):
    specs = re.findall(r"`width` is specified by `uimm\d+`(\+1)?", block)
    if not specs:
        return None
    biases = {1 if extra else 0 for extra in specs}
    if len(biases) != 1:
        raise ValueError("conflicting width immediate biases")
    return biases.pop()


def bind_operands(title, operand_names, variables, bias):
    pool = list(variables)
    bound = []

    def take(stem):
        for index, field in enumerate(pool):
            if field["stem"] == stem:
                return pool.pop(index)
        return None

    for name in operand_names:
        signed = False
        this_bias = 0
        if name in ("rd", "rs1", "rs2"):
            field = take(name)
            kind = KIND_REG
        elif name in ("rd_p", "rs1_p", "rs2_p"):
            field = take(name)
            kind = KIND_PAIR
        elif name in ("imm8", "simm10"):
            field = take("imm")
            kind = KIND_IMM
            signed = name.startswith("simm")
        elif re.fullmatch(r"uimm\d+", name):
            field = take(name)
            kind = KIND_IMM
        elif name == "width":
            field = next((item for item in pool if item["stem"].startswith("uimm")), None)
            if field is not None:
                pool.remove(field)
            kind = KIND_IMM
            if bias is None:
                raise ValueError(f"{title}: width operand has no 'specified by' sentence")
            this_bias = bias
        else:
            raise ValueError(f"{title}: unknown operand {name}")
        if field is None:
            raise ValueError(f"{title}: operand {name} has no encoding field")
        bound.append((kind, int(signed), this_bias, field["bits"]))
    if pool:
        raise ValueError(f"{title}: unused fields {[item['stem'] for item in pool]}")
    return bound


def overlaps(left, right):
    both = left["mask"] & right["mask"]
    return (both & (left["match"] ^ right["match"])) == 0


def extract(adoc_text):
    start = adoc_text.find("== Detailed Instruction Descriptions")
    if start < 0:
        raise SystemExit("detailed instruction chapter not found")
    end = adoc_text.find("=== RV32 Double-Register Equivalences", start)
    if end < 0:
        raise SystemExit("equivalence chapter not found")
    body = adoc_text[start:end]
    headings = list(HEADING_RE.finditer(body))
    instructions = []
    for index, heading in enumerate(headings):
        title = heading.group(1).strip()
        block_end = headings[index + 1].start() if index + 1 < len(headings) else len(body)
        block = body[heading.end():block_end]
        title_xlen = 0
        tagged = re.search(r"\((RV32|RV64)\)\s*$", title)
        if tagged:
            title_xlen = 32 if tagged.group(1) == "RV32" else 64
            title = title[:tagged.start()].strip()
        if "Mnemonic::" not in block or "{reg:" not in block:
            continue
        bias = width_bias(block)
        mnemonics = mnemonic_variants(block)
        diagrams = diagram_variants(title, block, title_xlen)
        if len(mnemonics) == 1 and mnemonics[0][0] is None:
            paired = [((diagram[0] or 0), mnemonics[0][1], mnemonics[0][2], *diagram[1:]) for diagram in diagrams]
        elif len(mnemonics) == len(diagrams):
            paired = []
            for mnemonic, diagram in zip(mnemonics, diagrams):
                xlen = diagram[0] or mnemonic[0] or title_xlen or 0
                paired.append((xlen, mnemonic[1], mnemonic[2], *diagram[1:]))
        else:
            raise ValueError(f"{title}: {len(mnemonics)} mnemonics and {len(diagrams)} diagrams")
        for xlen, asm, operands, match, mask, variables in paired:
            ops = bind_operands(title, operands, variables, bias)
            instructions.append({
                "name": asm,
                "title": title,
                "xlen": xlen,
                "match": match,
                "mask": mask,
                "ops": ops,
            })
    return instructions


def check_overlaps(instructions):
    problems = []
    for xlen in (32, 64):
        group = [ins for ins in instructions if ins["xlen"] in (0, xlen)]
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                if overlaps(group[i], group[j]):
                    problems.append((xlen, group[i]["name"], group[j]["name"]))
                    if len(problems) > 20:
                        return problems
    return problems


def render(instructions):
    lines = [
        '"""Generated RISC-V P-extension encoding table. Do not edit by hand.',
        "",
        "Source: RISC-V Packed SIMD Extension, revision "
        + SPEC_VERSION + ", tag v0.6, commit " + SPEC_COMMIT + ".",
        "https://github.com/riscv/riscv-p-spec/blob/v0.6/P-ext-proposal.adoc",
        "Specification text is (c) RISC-V International, licensed CC-BY-4.0.",
        '"""',
        "",
        f'SPEC_VERSION = "{SPEC_VERSION}"',
        f'SPEC_COMMIT = "{SPEC_COMMIT}"',
        "KIND_REG = 0",
        "KIND_PAIR = 1",
        "KIND_IMM = 2",
        "# name, xlen (0 = RV32 and RV64), match, mask, operands.",
        "# An operand is (kind, signed, bias, bits). bits[i] is the instruction",
        "# bit that contributes value bit i. Pair fields encode the register",
        "# number shifted right by 1. bias is added to saturation widths.",
        "INSNS = (",
    ]
    for ins in instructions:
        ops = ", ".join(
            "(%d, %d, %d, %s)" % (kind, signed, bias, bits)
            for kind, signed, bias, bits in ins["ops"]
        )
        lines.append(
            '    ("%s", %d, 0x%08x, 0x%08x, (%s)),'
            % (ins["name"], ins["xlen"], ins["match"], ins["mask"], ops)
        )
    lines.append(")")
    lines.append("")
    return "\n".join(lines)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: extract_p_encodings.py P-ext-proposal.adoc riscv_p_data.py")
    source = Path(sys.argv[1]).read_text(encoding="utf-8")
    instructions = extract(source)
    problems = check_overlaps(instructions)
    if problems:
        for problem in problems:
            print("overlap", problem)
        raise SystemExit(f"{len(problems)} overlapping encodings")
    names = {}
    for ins in instructions:
        names.setdefault((ins["name"], ins["xlen"]), 0)
        names[(ins["name"], ins["xlen"])] += 1
    duplicates = [key for key, count in names.items() if count > 1]
    if duplicates:
        raise SystemExit(f"duplicate mnemonics: {duplicates[:10]}")
    Path(sys.argv[2]).write_text(render(instructions), encoding="utf-8", newline="\n")
    print(f"wrote {len(instructions)} instructions to {sys.argv[2]}")


if __name__ == "__main__":
    main()
