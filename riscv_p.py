"""IDA Pro 9.5 processor hook for the RISC-V P (Packed SIMD) extension.

The hook claims revision 0.6 encodings and T-Head E907 P v0.9 encodings.
Base integer instructions stay with IDA's RISC-V processor module.
add64 is lifted as a 64-bit add. Other P instructions become pure helper
calls, so a function that contains them can still be decompiled.
"""

import os
import sys
import traceback

_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

import ida_auto
import ida_bytes
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_segment
import ida_ua
import ida_xref

from riscv_p_data import INSNS as INSNS_06
from riscv_p_data import KIND_IMM
from riscv_p_decode import SPEC_COMMIT, SPEC_VERSION
from riscv_p_decode import MNEMONIC_WIDTH as MNEMONIC_WIDTH_06
from riscv_p_decode import decode as decode06
from riscv_p_decode import operand_value as operand_value06
from riscv_p09_data import INSNS as INSNS_09
from riscv_p09_data import KIND_IMM as KIND_IMM_09
from riscv_p09_data import SOURCE_COMMIT as SOURCE09_COMMIT
from riscv_p09_data import SOURCE_VERSION as SOURCE09_VERSION
from riscv_p09_decode import MNEMONIC_WIDTH as MNEMONIC_WIDTH_09
from riscv_p09_decode import decode as decode09
from riscv_p09_decode import operand_value as operand_value09

if KIND_IMM != KIND_IMM_09:
    raise RuntimeError("P operand kind numbers diverged")

MNEMONIC_WIDTH = max(MNEMONIC_WIDTH_06, MNEMONIC_WIDTH_09)

ITYPE = ida_idp.CUSTOM_INSN_ITYPE + 0x180
_HOOKS = None
_COMPLAINED = False


def _xlen():
    return 64 if ida_ida.inf_is_64bit() else 32


def _word(ea):
    if not ida_bytes.is_mapped(ea) or not ida_bytes.is_mapped(ea + 3):
        return None
    return ida_bytes.get_dword(ea)


class PHooks(ida_idp.IDP_Hooks):
    def __init__(self):
        ida_idp.IDP_Hooks.__init__(self)

    def ev_ana_insn(self, insn):
        try:
            return self._analyze(insn)
        except Exception:
            _report_failure("analyze")
            return 0

    def ev_emu_insn(self, insn):
        if insn.itype != ITYPE:
            return 0
        try:
            ida_xref.add_cref(insn.ea, insn.ea + insn.size, ida_xref.fl_F)
        except Exception:
            _report_failure("emulate")
            return 0
        return 1

    def ev_out_insn(self, outctx):
        # The RISC-V module appends a bare '#' after immediates of instruction
        # types it does not know. Print the line here and flush it ourselves.
        if outctx.insn.itype != ITYPE:
            return 0
        try:
            outctx.out_mnemonic()
            for index in range(8):
                if outctx.insn.ops[index].type == ida_ua.o_void:
                    break
                if index:
                    outctx.out_symbol(",")
                    outctx.out_char(" ")
                outctx.out_one_operand(index)
            outctx.set_gen_cmt(False)
            outctx.flush_outbuf()
        except Exception:
            _report_failure("print")
            return 0
        return 1

    def ev_out_mnem(self, outctx):
        if outctx.insn.itype != ITYPE:
            return 0
        row = _row_at(outctx.insn)
        if row is None:
            return 0
        outctx.out_custom_mnem(row[0], MNEMONIC_WIDTH)
        return 1

    def ev_out_operand(self, outctx, op):
        if outctx.insn.itype != ITYPE or op.type != ida_ua.o_imm:
            return 0
        value = op.value
        if value >= 0x80000000:
            value -= 0x100000000
        if value < 0:
            outctx.out_symbol("-")
            value = -value
        outctx.out_long(value, 10)
        return 1

    def _analyze(self, insn):
        if ida_idp.ph.id != ida_idp.PLFM_RISCV:
            return 0
        word = _word(insn.ea)
        if word is None:
            return 0
        row, value_of = _lookup(word)
        if row is None:
            return 0
        insn.itype = ITYPE
        insn.size = 4
        insn.auxpref = INSNS_INDEX[id(row)]
        dtype = ida_ua.dt_qword if _xlen() == 64 else ida_ua.dt_dword
        for index, operand in enumerate(row[4]):
            op = insn.ops[index]
            value = value_of(word, operand)
            if operand[0] == KIND_IMM:
                op.type = ida_ua.o_imm
                op.value = value & 0xFFFFFFFF
                op.dtype = ida_ua.dt_dword
            else:
                op.type = ida_ua.o_reg
                op.reg = value
                op.dtype = dtype
        return 4


def _lookup(word):
    """Prefer revision 0.6, then the E907 P v0.9 table."""
    xlen = _xlen()
    row = decode06(word, xlen)
    if row is not None:
        return row, operand_value06
    row = decode09(word, xlen)
    if row is not None:
        return row, operand_value09
    return None, None


def _row_at(insn):
    word = _word(insn.ea)
    if word is None:
        return None
    row, _value_of = _lookup(word)
    return row


def _report_failure(where):
    global _COMPLAINED
    if _COMPLAINED:
        return
    _COMPLAINED = True
    ida_kernwin.msg("riscv-p: failed to %s an instruction\n%s\n" % (where, traceback.format_exc()))


class PPlugmod(ida_idaapi.plugmod_t):
    def run(self, arg):
        if ida_idp.ph.id != ida_idp.PLFM_RISCV:
            ida_kernwin.msg("riscv-p: the current processor is not RISC-V.\n")
            return
        count = reanalyze()
        ida_kernwin.msg("riscv-p: reanalyzed %d code items.\n" % count)
        ida_kernwin.refresh_idaview_anyway()


class PPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_MULTI
    comment = "Disassemble RISC-V P revision %s and P v%s encodings." % (SPEC_VERSION, SOURCE09_VERSION)
    help = "Reanalyze executable segments so existing code picks up P-extension instructions."
    wanted_name = "RISC-V P extension"
    wanted_hotkey = ""

    def init(self):
        install_hooks()
        try:
            from riscv_p_lift import schedule_lifter

            schedule_lifter()
        except Exception:
            ida_kernwin.msg("riscv-p: decompiler lift was not installed\n")
            traceback.print_exc()
        ida_kernwin.msg(
            "riscv-p: loaded P %s (%s), %d instructions; P v%s (%s), %d instructions.\n"
            % (
                SPEC_VERSION,
                SPEC_COMMIT[:8],
                len(INSNS_06),
                SOURCE09_VERSION,
                SOURCE09_COMMIT[:8],
                len(INSNS_09),
            )
        )
        return PPlugmod()


def install_hooks():
    """Install the processor hook once per IDA process.

    IDA may import this file under a different module name than a test script.
    The sentinel lives on ida_idaapi so both copies share one hook.
    """
    global _HOOKS
    existing = getattr(ida_idaapi, "_riscv_p_hooks", None)
    if existing is not None:
        _HOOKS = existing
        return _HOOKS
    if _HOOKS is None:
        _HOOKS = PHooks()
        _HOOKS.hook()
        ida_idaapi._riscv_p_hooks = _HOOKS
    return _HOOKS


def reanalyze():
    """Undefine and recreate existing code items in executable segments."""
    flags = ida_bytes.DELIT_SIMPLE | ida_bytes.DELIT_NOTRUNC
    count = 0
    for index in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(index)
        if seg is None:
            continue
        executable = seg.type == ida_segment.SEG_CODE or bool(seg.perm & ida_segment.SEGPERM_EXEC)
        if not executable:
            continue
        ea = seg.start_ea
        end = seg.end_ea
        while ea < end:
            item = ida_bytes.get_flags(ea)
            if not ida_bytes.is_code(item):
                nxt = ida_bytes.next_head(ea, end)
                if nxt <= ea or nxt == ida_idaapi.BADADDR:
                    break
                ea = nxt
                continue
            size = ida_bytes.get_item_size(ea)
            ida_bytes.del_items(ea, flags, size)
            made = ida_ua.create_insn(ea)
            count += 1
            ea += made if made > 0 else max(size, 1)
    ida_auto.auto_wait()
    return count


# Row identity for auxpref. Each decoder returns a tuple from its own table.
INSNS_INDEX = {id(row): index for index, row in enumerate(INSNS_06)}
INSNS_INDEX.update({id(row): len(INSNS_06) + index for index, row in enumerate(INSNS_09)})


def PLUGIN_ENTRY():
    return PPlugin()
