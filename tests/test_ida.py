"""Open a RISC-V ELF in idalib and check P-extension disassembly."""

import struct
import sys
import tempfile
from pathlib import Path

import idapro

idapro.enable_console_messages(True)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_lines
import ida_segment
import ida_ua

from riscv_p import install_hooks, reanalyze
from riscv_p09_decode import encode as encode09
from riscv_p_decode import encode


VADDR = 0x80000000


def row(name, xlen):
    from riscv_p_data import INSNS
    found = [item for item in INSNS if item[0] == name and item[1] in (0, xlen)]
    if len(found) != 1:
        raise AssertionError(name)
    return found[0]


def row09(name, xlen):
    from riscv_p09_data import INSNS
    found = [item for item in INSNS if item[0] == name and item[1] in (0, xlen)]
    if len(found) != 1:
        raise AssertionError(name)
    return found[0]


def words_rv32():
    # c.nop, then a 2-byte-aligned padd.b, then scalar add and jalr.
    padd = encode(row("padd.b", 32), [10, 11, 12]).to_bytes(4, "little")
    pli = encode(row("pli.h", 32), [10, -2]).to_bytes(4, "little")
    sat = encode(row("psati.h", 32), [10, 11, 8]).to_bytes(4, "little")
    pair = encode(row("pli.db", 32), [10, 7]).to_bytes(4, "little")
    add = (0x00B50533).to_bytes(4, "little")
    jalr = (0x00008067).to_bytes(4, "little")
    # E907 bytes 77 17 E6 C0: add64 a4, a2, a4. jalr stays last so the
    # function's fall-through covers the new instructions.
    add64 = (0xC0E61777).to_bytes(4, "little")
    kaddh = encode09(row09("kaddh", 32), [10, 11, 12]).to_bytes(4, "little")
    # srai16.u reads a0, so kaddh stays live for the decompiler.
    shift = encode09(row09("srai16.u", 32), [10, 10, 7]).to_bytes(4, "little")
    # add a0, a0, a4 keeps the add64 result live for the decompiler.
    use = (0x00E50533).to_bytes(4, "little")
    return b"\x01\x00" + padd + pli + sat + pair + add + add64 + kaddh + shift + use + jalr


def words_add64_zext():
    # c.mv a4, a0; c.li a5, 0; add64 a4, a2, a4; c.mv a0, a4; c.mv a1, a5; c.ret
    # High half of the addend is zero, and both result halves are returned.
    return b"".join(
        word.to_bytes(2, "little")
        for word in (0x872A, 0x4781)
    ) + (0xC0E61777).to_bytes(4, "little") + b"".join(
        word.to_bytes(2, "little")
        for word in (0x853A, 0x85BE, 0x8082)
    )


def elf32(text):
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
    e_phoff = 52
    text_off = e_phoff + 32
    header = ident + struct.pack(
        "<HHIIIIIHHHHHH",
        2, 243, 1, VADDR, e_phoff, 0, 1,
        52, 32, 1, 0, 0, 0,
    )
    phdr = struct.pack(
        "<IIIIIIII",
        1, text_off, VADDR, VADDR, len(text), len(text), 5, 4,
    )
    return header + phdr + text


def elf64(text):
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    e_phoff = 64
    text_off = e_phoff + 56
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2, 243, 1, VADDR, e_phoff, 0, 1,
        64, 56, 1, 0, 0, 0,
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1, 5, text_off, VADDR, VADDR, len(text), len(text), 4,
    )
    return header + phdr + text


def line_at(ea):
    raw = ida_lines.generate_disasm_line(ea, 0) or ""
    text = " ".join(ida_lines.tag_remove(raw).split())
    return text, raw


FAILURES = []


def check(label, ea, mnemonic, regs, imm=None):
    insn = ida_ua.insn_t()
    size = ida_ua.decode_insn(insn, ea)
    text, raw = line_at(ea)
    values = [(op.type, op.reg, op.value) for op in insn.ops if op.type != ida_ua.o_void]
    problems = []
    if size != 4:
        problems.append(f"size {size}")
    if not text.startswith(mnemonic + " ") and text != mnemonic:
        problems.append(f"text {text!r}")
    for index, reg in enumerate(regs):
        if insn.ops[index].type != ida_ua.o_reg or insn.ops[index].reg != reg:
            problems.append(f"reg{index} {insn.ops[index].reg}")
    if imm is not None:
        rendered = text.split(",")[-1].strip()
        if rendered != str(imm):
            problems.append(f"immediate {rendered!r}")
    if problems:
        FAILURES.append(f"{label}: {', '.join(problems)}")
        print(f"{label}: FAIL size={size} text={text!r} ops={values} raw={raw!r}")
    else:
        print(f"{label}: {text}")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "rv32.elf"
        body = words_rv32()
        path.write_bytes(elf32(body + words_add64_zext()))
        rc = idapro.open_database(str(path), True)
        if rc != 0:
            raise SystemExit(f"open_database returned {rc}")
        try:
            print("processor", ida_idp.ph.id, "riscv", ida_idp.PLFM_RISCV, "64bit", ida_ida.inf_is_64bit())
            if ida_idp.ph.id != ida_idp.PLFM_RISCV:
                raise AssertionError("processor is not RISC-V")
            if ida_ida.inf_is_64bit():
                raise AssertionError("ELF32 opened as 64-bit")
            install_hooks()
            count = reanalyze()
            print("reanalyzed", count)
            base = VADDR
            # c.nop is two bytes; padd.b follows it.
            nop, _raw = line_at(base)
            print("nop", nop)
            if "nop" not in nop:
                raise AssertionError(f"compressed nop not decoded: {nop!r}")
            check("padd.b", base + 2, "padd.b", (10, 11, 12))
            check("pli.h", base + 6, "pli.h", (10,), -2)
            check("psati.h", base + 10, "psati.h", (10, 11), 8)
            check("pli.db", base + 14, "pli.db", (10,), 7)
            check("add", base + 18, "add", (10, 10, 11))
            check("add64", base + 22, "add64", (14, 12, 14))
            check("kaddh", base + 26, "kaddh", (10, 11, 12))
            check("srai16.u", base + 30, "srai16.u", (10, 10), 7)
            check("add a4", base + 34, "add", (10, 10, 14))
            jalr, _raw = line_at(base + 38)
            print("jalr", jalr)
            if "jalr" not in jalr and "ret" not in jalr:
                raise AssertionError(f"jalr/ret not decoded: {jalr!r}")
            if not ida_funcs.add_func(base):
                print("add_func returned false")
            func = ida_funcs.func_entry_info_t()
            if not ida_funcs.get_func_entry_info(func, base):
                raise AssertionError("no function")
            print("function", hex(func.start_ea), hex(func.end_ea))
            if func.end_ea - func.start_ea < len(words_rv32()):
                raise AssertionError(f"flow stopped early at size {func.end_ea - func.start_ea}")
            seg = ida_segment.segment_info_t()
            if not ida_segment.get_segment_info(seg, base, ida_segment.GSI_NAME):
                raise AssertionError("no segment")
            print("segment", seg.get_name(), hex(seg.start_ea), hex(seg.end_ea))
            if FAILURES:
                raise AssertionError("; ".join(FAILURES))
            import ida_hexrays
            from riscv_p_lift import install_lifter

            if not install_lifter():
                raise AssertionError("decompiler lift was not installed")
            hf = ida_hexrays.hexrays_failure_t()
            flags = ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_NO_CACHE
            cfunc = ida_hexrays.decompile(base, hf, flags)
            text = "" if cfunc is None else str(cfunc)
            print("pseudocode", text)
            if cfunc is None:
                raise AssertionError(f"decompile failed: {hf}")
            for needle in ("kaddh", "srai16"):
                if needle not in text:
                    raise AssertionError(f"pseudocode missing {needle}: {text}")
            if "add64" in text:
                raise AssertionError(f"add64 stayed a helper call: {text}")
            second = base + len(body)
            if not ida_funcs.add_func(second):
                print("add_func second returned false")
            hf = ida_hexrays.hexrays_failure_t()
            widened = ida_hexrays.decompile(second, hf, flags)
            widened_text = "" if widened is None else str(widened)
            print("add64 pseudocode", widened_text)
            if widened is None:
                raise AssertionError(f"add64 decompile failed: {hf}")
            if "return a2 + a1;" not in widened_text:
                raise AssertionError(f"add64 did not become a plus: {widened_text}")
        finally:
            idapro.close_database(False)

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "rv64.elf"
        text = encode(row("pli.w", 64), [10, -5]).to_bytes(4, "little")
        text += (0x00008067).to_bytes(4, "little")
        path.write_bytes(elf64(text))
        rc = idapro.open_database(str(path), True)
        if rc != 0:
            raise SystemExit(f"open rv64 returned {rc}")
        try:
            print("rv64 bitness", ida_ida.inf_is_64bit(), "proc", ida_idp.ph.id)
            if not ida_ida.inf_is_64bit():
                raise AssertionError("ELF64 opened as 32-bit")
            install_hooks()
            reanalyze()
            check("pli.w", VADDR, "pli.w", (10,), -5)
            if FAILURES:
                raise AssertionError("; ".join(FAILURES))
        finally:
            idapro.close_database(False)
    print("ida tests passed")


if __name__ == "__main__":
    main()
