"""Lift RISC-V P instructions into Hex-Rays microcode.

Most instructions become a pure helper call. The call name is the mnemonic.
Register pairs are the even register and the following odd register: on
RV32 that is how both P encodings hold a 64-bit value. add64 is the
exception: it is a plain 64-bit add of two pairs, so it is lifted as an
add and can print as a C plus. Instructions whose destination is also an
accumulator take the old destination as an input.

This is a dataflow lift so the surrounding function can be decompiled. It
does not expand packed arithmetic, saturation, or vxsat into C operators.
"""

import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_typeinf

from riscv_p_data import KIND_IMM, KIND_PAIR
from riscv_p_decode import decode as decode06
from riscv_p_decode import operand_value as operand_value06
from riscv_p09_decode import decode as decode09
from riscv_p09_decode import operand_value as operand_value09

ITYPE = ida_idp.CUSTOM_INSN_ITYPE + 0x180
_EVEN_BIT = {7: 0b001, 15: 0b010, 20: 0b100}
_READS_DEST = (
    "mada",
    "mads",
    "madrs",
    "maxda",
    "maxds",
    "mabb",
    "mabt",
    "matt",
    "mmaw",
    "mmat",
    "mmac",
    "mmsb",
    "msda",
    "msxda",
    "maddr",
    "msubr",
    "pbsada",
    "smaqa",
    "umaqa",
    "smal",
    "smsl",
    "mar64",
    "msr64",
)


def reads_destination(name):
    """True when rd is an accumulator input as well as the result."""
    if "acc" in name:
        return True
    return any(part in name for part in _READS_DEST)


def helper_name(mnemonic, immediates):
    """Build a C identifier for the helper call.

    Dots are not identifiers. A numeric argument on the call makes ctree
    generation fail, so each immediate is appended to the name instead.
    """
    text = mnemonic.replace(".", "_")
    for value in immediates:
        text += "_n%d" % -value if value < 0 else "_%d" % value
    return text


def instruction_effect(row, word, value_of):
    """Return (name, destination registers, arguments).

    An argument is ("reg", number) or ("imm", value). Destination registers
    are architectural GPR numbers. A pair contributes the even register and
    the next register.
    """
    even = row[5] if len(row) > 5 else 0
    destinations = []
    arguments = []
    for index, operand in enumerate(row[4]):
        kind = operand[0]
        value = value_of(word, operand)
        if kind == KIND_IMM:
            arguments.append(("imm", value))
            continue
        registers = [value]
        if kind == KIND_PAIR or (even & _EVEN_BIT.get(operand[3][0], 0)):
            registers.append(value + 1)
        if index == 0:
            destinations = registers
            if reads_destination(row[0]):
                arguments.extend(("reg", reg) for reg in registers)
        else:
            arguments.extend(("reg", reg) for reg in registers)
    return row[0], destinations, arguments


def _lookup(word):
    xlen = 64 if ida_ida.inf_is_64bit() else 32
    row = decode06(word, xlen)
    if row is not None:
        return row, operand_value06
    row = decode09(word, xlen)
    if row is not None:
        return row, operand_value09
    return None, None


class PMicroFilter(object):
    """Created after Hex-Rays is initialized. The base class is bound lazily."""


def _bind_filter():
    import ida_hexrays

    class _Filter(ida_hexrays.microcode_filter_t):
        def __init__(self):
            ida_hexrays.microcode_filter_t.__init__(self)

        def match(self, cdg):
            try:
                return cdg.insn.itype == ITYPE
            except Exception:
                return False

        def apply(self, cdg):
            try:
                return _apply(cdg)
            except Exception:
                import traceback

                ida_kernwin.msg("riscv-p: failed to lift %x\n" % cdg.insn.ea)
                ida_kernwin.msg(traceback.format_exc())
                return ida_hexrays.MERR_INSN

    return _Filter


def _word(ea):
    import ida_bytes

    if not ida_bytes.is_mapped(ea) or not ida_bytes.is_mapped(ea + 3):
        return None
    return ida_bytes.get_dword(ea)


def _emit_add64(cdg, destinations, arguments):
    """Lift RV32 add64 as an 8-byte add.

    The instruction adds two register pairs. A later pass folds a zero high
    half, so a zero-extended 32-bit addend prints as a C plus.
    """
    import ida_hexrays

    def pair(reg):
        return ida_hexrays.reg2mreg(reg), ida_hexrays.reg2mreg(reg + 1)

    add = ida_hexrays.minsn_t(cdg.insn.ea)
    add.opcode = ida_hexrays.m_add
    add.l.make_reg_pair(*pair(arguments[0][1]), 4)
    add.r.make_reg_pair(*pair(arguments[2][1]), 4)
    add.d.make_reg_pair(*pair(destinations[0]), 4)
    cdg.mb.insert_into_block(add, cdg.mb.tail)
    return ida_hexrays.MERR_OK


def _apply(cdg):
    import ida_hexrays

    word = _word(cdg.insn.ea)
    if word is None:
        return ida_hexrays.MERR_INSN
    row, value_of = _lookup(word)
    if row is None:
        return ida_hexrays.MERR_INSN
    name, destinations, arguments = instruction_effect(row, word, value_of)
    if not destinations:
        return ida_hexrays.MERR_INSN
    if (
        name == "add64"
        and len(destinations) == 2
        and len(arguments) == 4
        and all(kind == "reg" for kind, _value in arguments)
    ):
        return _emit_add64(cdg, destinations, arguments)
    immediates = [value for kind, value in arguments if kind == "imm"]
    arguments = [item for item in arguments if item[0] != "imm"]
    name = helper_name(name, immediates)

    width = 8 if ida_ida.inf_is_64bit() else 4
    tif = ida_typeinf.tinfo_t()
    tif.create_simple_type(ida_typeinf.BT_INT64 if width == 8 else ida_typeinf.BT_INT32)
    model = ida_typeinf.CM_N64 if width == 8 else ida_typeinf.CM_N32_F48

    info = ida_hexrays.mcallinfo_t()
    info.callee = ida_idaapi.BADADDR
    info.solid_args = len(arguments)
    info.cc = ida_typeinf.CM_CC_SPECIAL | model
    info.flags = ida_hexrays.FCI_PURE | ida_hexrays.FCI_NOSIDE | ida_hexrays.FCI_FINAL
    info.role = ida_hexrays.ROLE_UNK
    if len(destinations) == 1:
        info.return_type = tif
        info.return_argloc.set_reg1(destinations[0])
    else:
        wide = ida_typeinf.tinfo_t()
        wide.create_simple_type(ida_typeinf.BT_INT64)
        info.return_type = wide
        info.return_argloc.set_reg2(destinations[0], destinations[1])

    for kind, value in arguments:
        arg = ida_hexrays.mcallarg_t()
        mreg = ida_hexrays.reg2mreg(value)
        arg.set_regarg(mreg, width, tif)
        arg.argloc.set_reg1(value)
        info.args.push_back(arg)

    if len(destinations) == 1:
        mreg = ida_hexrays.reg2mreg(destinations[0])
        ret = ida_hexrays.mop_t()
        ret.make_reg(mreg, width)
        info.retregs.push_back(ret)
        info.return_regs.add(mreg, width)
        info.spoiled.add(mreg, width)
    else:
        low = ida_hexrays.reg2mreg(destinations[0])
        high = ida_hexrays.reg2mreg(destinations[1])
        ret = ida_hexrays.mop_t()
        ret.make_reg_pair(low, high, width)
        info.retregs.push_back(ret)
        info.return_regs.add(low, width)
        info.return_regs.add(high, width)
        info.spoiled.add(low, width)
        info.spoiled.add(high, width)

    call = ida_hexrays.minsn_t(cdg.insn.ea)
    call.opcode = ida_hexrays.m_call
    call.l.make_helper(name)
    call.d._make_callinfo(info)
    # The call operand's size is the total size of the returned registers.
    # Hex-Rays rejects the instruction when this stays zero.
    call.d.size = width * len(destinations)
    cdg.mb.insert_into_block(call, cdg.mb.tail)
    return ida_hexrays.MERR_OK


def install_lifter():
    """Install the microcode filter once Hex-Rays is available."""
    existing = getattr(ida_idaapi, "_riscv_p_lifter", None)
    if existing is not None:
        return True
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        return False
    if not ida_hexrays.is_decompiler_usable():
        return False
    filter_type = _bind_filter()
    filt = filter_type()
    if not ida_hexrays.install_microcode_filter(filt, True):
        return False
    ida_idaapi._riscv_p_lifter = filt
    ida_kernwin.msg("riscv-p: P instructions are lifted for the decompiler.\n")
    return True


def schedule_lifter():
    """Retry until Hex-Rays has finished loading."""
    if getattr(ida_idaapi, "_riscv_p_lifter_timer", None):
        return

    def tick():
        if install_lifter():
            return -1
        tick.left -= 1
        if tick.left <= 0:
            return -1
        return 500

    tick.left = 40
    ida_idaapi._riscv_p_lifter_timer = True
    ida_kernwin.register_timer(0, tick)
