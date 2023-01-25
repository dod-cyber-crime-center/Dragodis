"""
This is a partial port of IDA's intel.hpp from the Hex-Rays SDK.
(Hex-Rays does not officially expose this module in IDAPython.)
"""
from enum import IntEnum, auto

import ida_allins
import ida_bytes
import ida_ua
import idc
import idaapi


# region - Copied from kordesii.utils.function_tracing.utils

def signed(n, bit_width):
    """
    Convert an unsigned integer to a signed integer

    :param uint n: value to convert
    :param int bit_width: byte width of n

    :return int: signed conversion
    """
    if n >> (bit_width - 1):  # Is the hi-bit set?
        return n - (1 << bit_width)

    return n


def get_bits():
    """
    Gets the architecture of the input file.

    :return int: bit width
    """
    info = idaapi.get_inf_structure()
    result = 16
    if info.is_64bit():
        result = 64
    elif info.is_32bit():
        result = 32

    return result

# endregion


# Intel 80x86 insn_t.auxpref bits
aux_lock = 0x00000001
aux_rep = 0x00000002
aux_repne = 0x00000004
aux_use32 = 0x00000008         # segment type is 32-bits
aux_use64 = 0x00000010         # segment type is 64-bits
aux_large = 0x00000020         # offset field is 32-bit (16-bit is not enough)
aux_short = 0x00000040         # short (byte) displacement used
aux_sgpref = 0x00000080        # a segment prefix byte is not used
aux_oppref = 0x00000100        # operand size prefix byte is not used
aux_adpref = 0x00000200        # address size prefix byte is not used
aux_basess = 0x00000400        # SS based instruction
aux_natop = 0x00000800         # operand size is not overridden by prefix
aux_natad = 0x00001000         # addressing mode is not overridden by prefix
aux_fpemu = 0x00002000         # FP emulator instruction
aux_vexpr = 0x00004000         # VEX-encoded instruction
aux_bnd = 0x00008000           # MPX-encoded instruction
aux_evex = 0x00010000          # EVEX-encoded instruction
aux_xop = 0x00020000           # XOP-encoded instruction
aux_xacquire = 0x00040000      # HLE prefix hints
aux_xrelease = 0x00080000      # HLE prefix hints


# bits in insn_t.evex_flags:
EVEX_R = 0x01           # High-16 register specifier modifier
EVEX_L = 0x02           # Vector length/RC
EVEX_z = 0x04           # Zeroing/Merging
EVEX_b = 0x08           # Broadcast/RC/SAE Context
EVEX_V = 0x10           # High-16 NDS/VIDX register specifier

# bits in insn_t.rex:
REX_W = 8               # 64-bit operand size
REX_R = 4               # modrm reg field extension
REX_X = 2               # sib index field extension
REX_B = 1               # modrm r/m, sib base, or opcode reg fields extension
VEX_L = 0x80            # 256-bit operation (YMM register)

regnum_t = int


class RegNo(IntEnum):
    R_none = -1
    R_ax = 0
    R_cx = auto() # 1
    R_dx = auto() # 2
    R_bx = auto() # 3
    R_sp = auto() # 4
    R_bp = auto() # 5
    R_si = auto() # 6
    R_di = auto() # 7
    R_r8 = auto() # 8
    R_r9 = auto() # 9
    R_r10 = auto() # 10
    R_r11 = auto() # 11
    R_r12 = auto() # 12
    R_r13 = auto() # 13
    R_r14 = auto() # 14
    R_r15 = auto() # 15

    R_al = auto()
    R_cl = auto()
    R_dl = auto()
    R_bl = auto()
    R_ah = auto()
    R_ch = auto()
    R_dh = auto()
    R_bh = auto()

    R_spl = auto()
    R_bpl = auto()
    R_sil = auto()
    R_dil = auto()

    R_ip = auto()

    R_es = auto() # 0
    R_cs = auto() # 1
    R_ss = auto() # 2
    R_ds = auto() # 3
    R_fs = auto()
    R_gs = auto()

    R_cf = auto() # main cc's
    R_zf = auto()
    R_sf = auto()
    R_of = auto()

    R_pf = auto() # additional cc's
    R_af = auto()
    R_tf = auto()
    R_if = auto()
    R_df = auto()

    R_efl = auto() # eflags

    # the following registers will be used in the disassembly
    # starting from ida v5.7

    R_st0 = auto() # floating point registers(not used in disassembly)
    R_st1 = auto()
    R_st2 = auto()
    R_st3 = auto()
    R_st4 = auto()
    R_st5 = auto()
    R_st6 = auto()
    R_st7 = auto()
    R_fpctrl = auto() # fpu control register
    R_fpstat = auto() # fpu status register
    R_fptags = auto() # fpu tags register

    R_mm0 = auto() # mmx registers
    R_mm1 = auto()
    R_mm2 = auto()
    R_mm3 = auto()
    R_mm4 = auto()
    R_mm5 = auto()
    R_mm6 = auto()
    R_mm7 = auto()

    R_xmm0 = auto() # xmm registers
    R_xmm1 = auto()
    R_xmm2 = auto()
    R_xmm3 = auto()
    R_xmm4 = auto()
    R_xmm5 = auto()
    R_xmm6 = auto()
    R_xmm7 = auto()
    R_xmm8 = auto()
    R_xmm9 = auto()
    R_xmm10 = auto()
    R_xmm11 = auto()
    R_xmm12 = auto()
    R_xmm13 = auto()
    R_xmm14 = auto()
    R_xmm15 = auto()
    R_mxcsr = auto()

    R_ymm0 = auto() # AVX 256 - bit registers
    R_ymm1 = auto()
    R_ymm2 = auto()
    R_ymm3 = auto()
    R_ymm4 = auto()
    R_ymm5 = auto()
    R_ymm6 = auto()
    R_ymm7 = auto()
    R_ymm8 = auto()
    R_ymm9 = auto()
    R_ymm10 = auto()
    R_ymm11 = auto()
    R_ymm12 = auto()
    R_ymm13 = auto()
    R_ymm14 = auto()
    R_ymm15 = auto()

    R_bnd0 = auto() # MPX registers
    R_bnd1 = auto()
    R_bnd2 = auto()
    R_bnd3 = auto()

    R_xmm16 = auto() # AVX - 512 extended XMM registers
    R_xmm17 = auto()
    R_xmm18 = auto()
    R_xmm19 = auto()
    R_xmm20 = auto()
    R_xmm21 = auto()
    R_xmm22 = auto()
    R_xmm23 = auto()
    R_xmm24 = auto()
    R_xmm25 = auto()
    R_xmm26 = auto()
    R_xmm27 = auto()
    R_xmm28 = auto()
    R_xmm29 = auto()
    R_xmm30 = auto()
    R_xmm31 = auto()

    R_ymm16 = auto() # AVX - 512 extended YMM registers
    R_ymm17 = auto()
    R_ymm18 = auto()
    R_ymm19 = auto()
    R_ymm20 = auto()
    R_ymm21 = auto()
    R_ymm22 = auto()
    R_ymm23 = auto()
    R_ymm24 = auto()
    R_ymm25 = auto()
    R_ymm26 = auto()
    R_ymm27 = auto()
    R_ymm28 = auto()
    R_ymm29 = auto()
    R_ymm30 = auto()
    R_ymm31 = auto()

    R_zmm0 = auto() # AVX - 512 ZMM registers
    R_zmm1 = auto()
    R_zmm2 = auto()
    R_zmm3 = auto()
    R_zmm4 = auto()
    R_zmm5 = auto()
    R_zmm6 = auto()
    R_zmm7 = auto()
    R_zmm8 = auto()
    R_zmm9 = auto()
    R_zmm10 = auto()
    R_zmm11 = auto()
    R_zmm12 = auto()
    R_zmm13 = auto()
    R_zmm14 = auto()
    R_zmm15 = auto()
    R_zmm16 = auto()
    R_zmm17 = auto()
    R_zmm18 = auto()
    R_zmm19 = auto()
    R_zmm20 = auto()
    R_zmm21 = auto()
    R_zmm22 = auto()
    R_zmm23 = auto()
    R_zmm24 = auto()
    R_zmm25 = auto()
    R_zmm26 = auto()
    R_zmm27 = auto()
    R_zmm28 = auto()
    R_zmm29 = auto()
    R_zmm30 = auto()
    R_zmm31 = auto()

    R_k0 = auto() # AVX - 512 opmask registers
    R_k1 = auto()
    R_k2 = auto()
    R_k3 = auto()
    R_k4 = auto()
    R_k5 = auto()
    R_k6 = auto()
    R_k7 = auto()

    R_last = auto()


def hasSIB(op: ida_ua.op_t) -> bool:
    """specflag1 indicates if there is a SIB or not"""
    return bool(op.specflag1)


def sib(op: ida_ua.op_t) -> int:
    """specflag2 holds the SIB if there is one"""
    return op.specflag2


def is_segreg(reg: int) -> bool:
    return RegNo.R_es <= reg <= RegNo.R_gs


def is_fpureg(reg: int) -> bool:
    return RegNo.R_st0 <= reg <= RegNo.R_st7


def is_mmxreg(reg: int) -> bool:
    return RegNo.R_mm0 <= reg <= RegNo.R_mm7


def is_xmmreg(reg: int) -> bool:
    return RegNo.R_xmm0 <= reg <= RegNo.R_xmm15


def is_ymmreg(reg: int) -> bool:
    return RegNo.R_ymm0 <= reg <= RegNo.R_ymm15


def insn_jcc(insn: ida_ua.insn_t) -> bool:
    """Determine if an instruction is a Jcc (jump) instruction"""
    return insn.itype in (
        ida_allins.NN_ja,
        ida_allins.NN_jae,
        ida_allins.NN_jb,
        ida_allins.NN_jbe,
        ida_allins.NN_jc,
        ida_allins.NN_je,
        ida_allins.NN_jg,
        ida_allins.NN_jge,
        ida_allins.NN_jl,
        ida_allins.NN_jle,
        ida_allins.NN_jna,
        ida_allins.NN_jnae,
        ida_allins.NN_jnb,
        ida_allins.NN_jnbe,
        ida_allins.NN_jnc,
        ida_allins.NN_jne,
        ida_allins.NN_jng,
        ida_allins.NN_jnge,
        ida_allins.NN_jnl,
        ida_allins.NN_jnle,
        ida_allins.NN_jno,
        ida_allins.NN_jnp,
        ida_allins.NN_jns,
        ida_allins.NN_jnz,
        ida_allins.NN_jo,
        ida_allins.NN_jp,
        ida_allins.NN_jpe,
        ida_allins.NN_jpo,
        ida_allins.NN_js,
        ida_allins.NN_jz,
    )


def insn_default_opsize_64(insn: ida_ua.insn_t) -> bool:
    """Determine, based on the instruction type, if the instruction, by default, is 64-bit"""
    if insn_jcc(insn):
        return True

    return insn.itype in (
        # use ss
        ida_allins.NN_pop,
        ida_allins.NN_popf,
        ida_allins.NN_popfq,
        ida_allins.NN_push,
        ida_allins.NN_pushf,
        ida_allins.NN_pushfq,
        ida_allins.NN_retn,
        ida_allins.NN_retf,
        ida_allins.NN_retnq,
        ida_allins.NN_retfq,
        ida_allins.NN_call,
        ida_allins.NN_callfi,
        ida_allins.NN_callni,
        ida_allins.NN_enter,
        ida_allins.NN_enterq,
        ida_allins.NN_leave,
        ida_allins.NN_leaveq,
        # near branches
        ida_allins.NN_jcxz,
        ida_allins.NN_jecxz,
        ida_allins.NN_jrcxz,
        ida_allins.NN_jmp,
        ida_allins.NN_jmpni,
        ida_allins.NN_jmpshort,
        ida_allins.NN_loop,
        ida_allins.NN_loopq,
        ida_allins.NN_loope,
        ida_allins.NN_loopqe,
        ida_allins.NN_loopne,
        ida_allins.NN_loopqne,
    )


def mode16(insn: ida_ua.insn_t) -> bool:
    """16-bit mode?"""
    return (insn.auxpref & (aux_use32 | aux_use64)) == 0


def mode32(insn: ida_ua.insn_t) -> bool:
    """32-bit mode?"""
    return (insn.auxpref & aux_use32) != 0


def mode64(insn: ida_ua.insn_t) -> bool:
    """64-bit mode?"""
    return (insn.auxpref & aux_use64) != 0


def natad(insn: ida_ua.insn_t) -> bool:
    """natural address size (no prefixes)?"""
    return (insn.auxpref & aux_natad) != 0


def natop(insn: ida_ua.insn_t) -> bool:
    """natural operand size (no prefixes)?"""
    return (insn.auxpref & aux_natop) != 0


def vexpr(insn: ida_ua.insn_t) -> bool:
    """VEX encoding used"""
    return (insn.auxpref & aux_vexpr) != 0


def evexpr(insn: ida_ua.insn_t) -> bool:
    """EVEX encoding used"""
    return (insn.auxpref & aux_evex) != 0


def xopexpr(insn: ida_ua.insn_t) -> bool:
    """XOP encoding used"""
    return (insn.auxpref & aux_xop) != 0


def ad16(insn: ida_ua.insn_t) -> bool:
    """is current addressing 16-bit?"""
    p = insn.auxpref & (aux_use32 | aux_use64 | aux_natad)
    return p == aux_natad or p == aux_use32


def ad32(insn: ida_ua.insn_t) -> bool:
    """is current addressing 32-bit?"""
    p = insn.auxpref & (aux_use32 | aux_use64 | aux_natad)
    return (
        p == (aux_natad | aux_use32)
        or p == 0
        or p == aux_use64
    )


def ad64(insn: ida_ua.insn_t) -> bool:
    """is current addressing 64-bit?"""
    if not idc.__EA64__:
        return False
    p = insn.auxpref & (aux_use32 | aux_use64 | aux_natad)
    return p == (aux_natad | aux_use64)


def op16(insn: ida_ua.insn_t) -> bool:
    """is current operand size 16-bit?"""
    p = insn.auxpref & (aux_use32 | aux_use64 | aux_natop)
    return (
        p == aux_natop     # 16-bit segment, no prefixes
        or p == aux_use32  # 32-bit segment, 66h
        or p == aux_use64 and (insn.insnpref & REX_W) == 0  # 64-bit segment, 66h, no rex.w
    )


def op32(insn: ida_ua.insn_t) -> bool:
    """is current operand size 32-bit?"""
    p = insn.auxpref & (aux_use32 | aux_use64 | aux_natop)
    return (
        p == 0                           # 16-bit segment, 66h
        or p == (aux_use32 | aux_natop)  # 32-bit segment, no prefiexes
        or p == (aux_use64 | aux_natop) and (insn.insnpref & REX_W) == 0  # 64-bit segment, 66h, no rex.w
    )


def op64(insn: ida_ua.insn_t) -> bool:
    """is current operand size 64-bit?"""
    if not idc.__EA64__:
        return False
    return (
        mode64(insn)
        and (
            (insn.insnpref & REX_W) != 0
            or natop(insn) and insn_default_opsize_64(insn)  # 64-bit segment, rex.w or insns-64
        )
    )


def op256(insn: ida_ua.insn_t) -> bool:
    """is VEX.L == 1 or EVEX.L'L == 01?"""
    return (
        (insn.insnpref & VEX_L) != 0
        and (
            vexpr(insn)
            or xopexpr(insn)
            or evexpr(insn) and (insn.Op6.specflag2 & EVEX_L) == 0
        )
    )


def op512(insn: ida_ua.insn_t) -> bool:
    """is EVEX.L'L == 10?"""
    return (
        evexpr(insn)
        and (insn.insnpref & VEX_L) == 0
        and (insn.Op6.specflag2 & EVEX_L) != 0
    )


def is_vsib(insn: ida_ua.insn_t) -> bool:
    """does instruction use VSIB variant of the sib byte?"""
    return insn.itype in (
        ida_allins.NN_vgatherdps,
        ida_allins.NN_vgatherdpd,
        ida_allins.NN_vgatherqps,
        ida_allins.NN_vgatherqpd,
        ida_allins.NN_vpgatherdd,
        ida_allins.NN_vpgatherdq,
        ida_allins.NN_vpgatherqd,
        ida_allins.NN_vpgatherqq,

        ida_allins.NN_vscatterdps,
        ida_allins.NN_vscatterdpd,
        ida_allins.NN_vscatterqps,
        ida_allins.NN_vscatterqpd,
        ida_allins.NN_vpscatterdd,
        ida_allins.NN_vpscatterdq,
        ida_allins.NN_vpscatterqd,
        ida_allins.NN_vpscatterqq,

        ida_allins.NN_vgatherpf0dps,
        ida_allins.NN_vgatherpf0qps,
        ida_allins.NN_vgatherpf0dpd,
        ida_allins.NN_vgatherpf0qpd,
        ida_allins.NN_vgatherpf1dps,
        ida_allins.NN_vgatherpf1qps,
        ida_allins.NN_vgatherpf1dpd,
        ida_allins.NN_vgatherpf1qpd,

        ida_allins.NN_vscatterpf0dps,
        ida_allins.NN_vscatterpf0qps,
        ida_allins.NN_vscatterpf0dpd,
        ida_allins.NN_vscatterpf0qpd,
        ida_allins.NN_vscatterpf1dps,
        ida_allins.NN_vscatterpf1qps,
        ida_allins.NN_vscatterpf1dpd,
        ida_allins.NN_vscatterpf1qpd,
    )


def vsib_index_fixreg(insn: ida_ua.insn_t, index: regnum_t) -> regnum_t:
    insn_type = insn.itype

    if insn_type in (
        ida_allins.NN_vscatterdps,
        ida_allins.NN_vscatterqps,
        ida_allins.NN_vscatterqpd,
        ida_allins.NN_vpscatterdd,
        ida_allins.NN_vpscatterqd,
        ida_allins.NN_vpscatterqq,

        ida_allins.NN_vpgatherdd,
        ida_allins.NN_vpgatherqd,
        ida_allins.NN_vpgatherqq,
        ida_allins.NN_vgatherdps,
        ida_allins.NN_vgatherqps,
        ida_allins.NN_vgatherqpd,
    ):
        if index > 15:
            if op512(insn):
                index += RegNo.R_zmm0
            elif op256(insn):
                index += RegNo.R_ymm16 - 16
            else:
                index += RegNo.R_xmm16 - 16
        else:
            if op512(insn):
                index += RegNo.R_zmm0
            elif op256(insn):
                index += RegNo.R_ymm0
            else:
                index += RegNo.R_xmm0

    elif insn_type in (
        ida_allins.NN_vscatterdpd,
        ida_allins.NN_vpscatterdq,

        ida_allins.NN_vgatherdpd,
        ida_allins.NN_vpgatherdq,
    ):
        if index > 15:
            if op512(insn):
                index += RegNo.R_ymm16 - 16
            else:
                index += RegNo.R_xmm16 - 16
        else:
            if op512(insn):
                index += RegNo.R_ymm0
            else:
                index += RegNo.R_xmm0

    elif insn_type in (
        ida_allins.NN_vgatherpf0dps,
        ida_allins.NN_vgatherpf0qps,
        ida_allins.NN_vgatherpf0qpd,
        ida_allins.NN_vgatherpf1dps,
        ida_allins.NN_vgatherpf1qps,
        ida_allins.NN_vgatherpf1qpd,

        ida_allins.NN_vscatterpf0dps,
        ida_allins.NN_vscatterpf0qps,
        ida_allins.NN_vscatterpf0qpd,
        ida_allins.NN_vscatterpf1dps,
        ida_allins.NN_vscatterpf1qps,
        ida_allins.NN_vscatterpf1qpd,
    ):
      index += RegNo.R_zmm0

    elif insn_type in (
        ida_allins.NN_vgatherpf0dpd,
        ida_allins.NN_vgatherpf1dpd,
        ida_allins.NN_vscatterpf0dpd,
        ida_allins.NN_vscatterpf1dpd,
    ):
        if index > 15:
            index += RegNo.R_ymm16 - 16
        else:
            index += RegNo.R_ymm0

    return index


def sib_base(insn: ida_ua.insn_t, op: ida_ua.op_t) -> regnum_t:
    """Calculate the base register number for a phrase/displacment"""
    base = sib(op) & 7
    if idc.__EA64__ and (insn.insnpref & REX_B):  # Do we need to convert the base to a 64-bit register number?
        base |= 8  # Upconvert to 64-bit register number if not already

    return base


def sib_index(insn: ida_ua.insn_t, op: ida_ua.op_t) -> regnum_t:
    """Calculate the index register number for a phrase/displacement"""
    index = (sib(op) >> 3) & 7
    if idc.__EA64__ and (insn.insnpref & REX_X):  # Do we need to convert the index to a 64-bit register number?
        index |= 8  # Upconvert to 64-bit register number if not already
    if is_vsib(insn):
        # Op6 is used for opmask registers in EVEX.
        # spec flags from Op6 are used to extend insn_t.
        if (insn.Op6.specflag2 & EVEX_V) != 0:
            index |= 16
        index = vsib_index_fixreg(insn, index)

    return index


def sib_scale(op: ida_ua.op_t) -> int:
    """Calculate the scale for the index register"""
    return (sib(op) >> 6) & 3


def x86_base_reg(insn: ida_ua.insn_t, op: ida_ua.op_t) -> regnum_t:
    """
    Get the base register of the operand with a displacement.
    Returns correct register for 16-bit code too
    """
    if hasSIB(op):
        if op.type == ida_ua.o_mem:
            return RegNo.R_none
        return sib_base(insn, op)  # base register encoded in the SIB

    if not ad16(insn):
        return op.phrase  # "phrase" contains the base register number

    if signed(op.phrase, get_bits()) == RegNo.R_none:
        return RegNo.R_sp

    if op.phrase in (0, 1, 7):  # ([BX+SI], [BX+DI], [BX])
        return RegNo.R_bx

    if op.phrase in (2, 3, 6):  # ([BP+SI], [BP+DI], [BP])
        return RegNo.R_bp

    if op.phrase == 4:  # [SI]
        return RegNo.R_si

    if op.phrase == 5:  # [DI]
        return RegNo.R_di

    raise ValueError("Unable to parse x86 base register from instruction")


INDEX_NONE = 4  # no index register is present


def x86_index_reg(insn: ida_ua.insn_t, op: ida_ua.op_t) -> regnum_t:
    """Get the index register (if there is one) (handle 16-bit as well for completeness)"""
    if hasSIB(op):
        idx = sib_index(insn, op)
        if idx != INDEX_NONE:
            return idx
        return RegNo.R_none

    if not ad16(insn):
        return RegNo.R_none

    if op.phrase in (0, 2):  # ([BX+SI], [BP+SI])
        return RegNo.R_si

    if op.phrase in (1, 3):  # ([BX+DI], [BP+DI])
        return RegNo.R_di

    if op.phrase in (4, 5, 6, 7):  # ([SI], [DI], [BP], [BX])
        return RegNo.R_none

    raise ValueError("Unable to parse x86 index register from instruction")


def x86_scale(op: ida_ua.op_t) -> int:
    """get the scale factor of the operand with a displacement"""
    return sib_scale(op) if hasSIB(op) else 0


def has_displ(op: ida_ua.op_t) -> bool:
    """does the operand have a displacement?"""
    return op.type == ida_ua.o_displ or op.type == ida_ua.o_mem and hasSIB(op)


def has_tls_segpref(insn: ida_ua.insn_t) -> bool:
    """does the insn refer to the TLS variable?"""
    if insn.segpref == 0:
        return False
    return (
        (mode64(insn) and insn.segpref == RegNo.R_fs)
        or (mode32(insn) and insn.segpref == RegNo.R_gs)
    )


def mem_as_displ(insn: ida_ua.insn_t, op: ida_ua.op_t) -> bool:
    """
    should we treat the memory operand as a displacement?

    the operand should be an offset and it should be the TLS variable
    or the second operand of "lea" instruction
    .text:08000000 mov eax, gs:(ti1 - static_TP)
    .text:08000E8F lea ecx, (_ZN4dmngL4sessE - _GLOBAL_OFFSET_TABLE_)
    """
    return (
        (has_tls_segpref(insn) or insn.itype == ida_allins.NN_lea)
        and ida_bytes.is_off(ida_bytes.get_flags(insn.ea), op.n)
    )
