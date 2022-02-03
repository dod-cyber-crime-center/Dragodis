"""
This is a partial port of IDA's module/arm/arm.hpp from the Hex-Rays SDK.
(Hex-Rays does not officially expose this module in IDAPython.)

NOTE: NEON is currently being ignored. We may add it in the future.
"""
from enum import IntEnum, auto

import ida_allins
import ida_ua


# ARM insn.auxpref bits
aux_cond =        0x0001  # set condition codes (S postfix is required)
aux_byte =        0x0002  # byte transfer (B postfix is required)
aux_npriv =       0x0004  # non-privileged transfer (T postfix is required)
aux_regsh =       0x0008  # shift count is held in a register (see o_shreg)
aux_negoff =      0x0010  # memory offset is negated in LDR,STR
aux_immcarry =    0x0010  # carry flag is set to bit 31 of the immediate operand (see may_set_carry)
aux_wback =       0x0020  # write back (! postfix is required)
aux_wbackldm =    0x0040  # write back for LDM/STM (! postfix is required)
aux_postidx =     0x0080  # post-indexed mode in LDR,STR
aux_ltrans =      0x0100  # long transfer in LDC/STC (L postfix is required)
aux_wimm =        0x0200  # thumb32 wide encoding of immediate constant (MOVW)
aux_sb =          0x0400  # signed byte (SB postfix)
aux_sh =          0x0800  # signed halfword (SH postfix)
aux_sw =          (aux_sb|aux_sh)  # signed word (SW postfix)
aux_h =           0x1000  # halfword (H postfix)
aux_x =           (aux_h|aux_byte)  # doubleword (X postfix in A64)
aux_d =           aux_x   # dual (D postfix in A32/T32)
aux_p =           0x2000  # priviledged (P postfix)
aux_coproc =      0x4000  # coprocessor instruction
aux_wide =        0x8000  # wide (32-bit) thumb instruction (.W suffix)
aux_pac =        0x10000  # Pointer Authentication Code instruction (see PAC_ flags)
aux_ns =         0x20000  # non-secure branch (NS suffix)

# assembler flags
UAS_GNU =         0x0001  # GNU assembler
UAS_LEGACY =      0x0002  # Legacy (pre-UAL) assembler


# Operand Types:

o_shreg = ida_ua.o_idpspec0   # Shifted register

#define shtype          specflag2          //  op.shtype - shift type
#define shreg(x)        uchar(x.specflag1) //  op.shreg  - shift register
#define shcnt           value              //  op.shcnt  - shift counter

#define ishtype         specflag2          // o_imm - shift type
#define ishcnt          specval            // o_imm - shift counter

def shreg(op: ida_ua.op_t) -> int:
    """op.shreg - shift register"""
    return op.specflag1 & 0xFF

secreg = shreg  # o_phrase - the second register is here

#define ralign          specflag3          # o_phrase, o_displ: NEON alignment (power-of-two bytes, i.e. 8*(1<<a))
                                           # minimal alignment is 16 (a==1)

#define simd_sz         specflag1          # o_reg: SIMD vector element size
                                           # 0=scalar, 1=8 bits, 2=16 bits, 3=32 bits, 4=64 bits, 5=128 bits)
                                           # number of lanes is derived from the vector size (dtype)
#define simd_idx        specflag3          // o_reg: SIMD scalar index plus 1 (Vn.H[i])

# o_phrase: the second register is held in secreg (specflag1)
#           the shift type is in shtype (specflag2)
#           the shift counter is in shcnt (value)


o_reglist = ida_ua.o_idpspec1    # Register list (for LDM/STM)
#define reglist         specval            // The list is in op.specval
#define uforce          specflag1          // PSR & force user bit (^ suffix)

o_creglist = ida_ua.o_idpspec2   # Coprocessor register list (for CDP)
#define CRd             reg                //
#define CRn             specflag1          //
#define CRm             specflag2          //

o_creg = ida_ua.o_idpspec3       # Coprocessor register (for LDC/STC)

o_fpreglist = ida_ua.o_idpspec4  # Floating point register list
#define fpregstart      reg                // First register
#define fpregcnt        value              // number of registers; 0: single register (NEON scalar)
#define fpregstep       specflag2          // register spacing (0: {Dd, Dd+1,... }, 1: {Dd, Dd+2, ...} etc)
#define fpregindex      specflag3          // NEON scalar index plus 1 (Dd[x])


o_text = ida_ua.o_idpspec5    # Arbitrary text stored in the operand
                              # structure starting at the 'value' field
                              # up to 16 bytes (with terminating zero)
o_cond = ida_ua.o_idpspec5+1  # ARM condition as an operand
                              # condition is stored in 'value' field


# bits stored in specflag1 for APSR register
APSR_nzcv =       0x01
APSR_q =          0x02
APSR_g =          0x04
# for SPSR/CPSR
CPSR_c =          0x01
CPSR_x =          0x02
CPSR_s =          0x04
CPSR_f =          0x08
# for banked registers (R8-R12, SP, LR/ELR, SPSR), this flag is set
BANKED_MODE =     0x80  # the mode is in low 5 bits (arm_mode_t)


# Shift types:
class shift_t(IntEnum):
    LSL = 0               # logical left         LSL #0 - don't shift
    LSR = auto()          # logical right        LSR #0 means LSR #32
    ASR = auto()          # arithmetic right     ASR #0 means ASR #32
    ROR = auto()          # rotate right         ROR #0 means RRX
    RRX = auto()          # extended rotate right

    # ARMv8 shifts
    MSL = auto()          # masked shift left (ones are shifted in from the right)

    # extending register operations
    UXTB = auto()
    UXTH = auto()
    UXTW = auto()
    UXTX = auto()         # alias for LSL
    SXTB = auto()
    SXTH = auto()
    SXTW = auto()
    SXTX = auto()


class RegNo(IntEnum):
    R0 = 0
    R1 = auto()
    R2 = auto()
    R3 = auto()
    R4 = auto()
    R5 = auto()
    R6 = auto()
    R7 = auto()
    R8 = auto()
    R9 = auto()
    R10 = auto()
    R11 = auto()
    R12 = auto()
    R13 = auto()
    R14 = auto()
    R15 = auto()

    CPSR = auto()
    CPSR_flg = auto()

    SPSR = auto()
    SPSR_flg = auto()

    T = auto()
    rVcs = auto()
    rVds = auto()   # virtual registers for code and data segments
    Racc0 = auto()  # Intel xScale coprocessor accumulator

    # VFP system registers
    FPSID = auto()
    FPSCR = auto()
    FPEXC = auto()
    FPINST = auto()
    FPINST2 = auto()
    MVFR0 = auto()
    MVFR1 = auto()

    # msr system registers
    SYSM_APSR = auto()
    SYSM_IAPSR = auto()
    SYSM_EAPSR = auto()
    SYSM_XPSR = auto()
    SYSM_IPSR = auto()
    SYSM_EPSR = auto()
    SYSM_IEPSR = auto()
    SYSM_MSP = auto()
    SYSM_PSP = auto()
    SYSM_PRIMASK = auto()
    SYSM_BASEPRI = auto()
    SYSM_BASEPRI_MAX = auto()
    SYSM_FAULTMASK = auto()
    SYSM_CONTROL = auto()

    Q0 = auto()
    Q1 = auto()
    Q2 = auto()
    Q3 = auto()
    Q4 = auto()
    Q5 = auto()
    Q6 = auto()
    Q7 = auto()
    Q8 = auto()
    Q9 = auto()
    Q10 = auto()
    Q11 = auto()
    Q12 = auto()
    Q13 = auto()
    Q14 = auto()
    Q15 = auto()

    D0 = auto()
    D1 = auto()
    D2 = auto()
    D3 = auto()
    D4 = auto()
    D5 = auto()
    D6 = auto()
    D7 = auto()
    D8 = auto()
    D9 = auto()
    D10 = auto()
    D11 = auto()
    D12 = auto()
    D13 = auto()
    D14 = auto()
    D15 = auto()
    D16 = auto()
    D17 = auto()
    D18 = auto()
    D19 = auto()
    D20 = auto()
    D21 = auto()
    D22 = auto()
    D23 = auto()
    D24 = auto()
    D25 = auto()
    D26 = auto()
    D27 = auto()
    D28 = auto()
    D29 = auto()
    D30 = auto()
    D31 = auto()

    S0 = auto()
    S1 = auto()
    S2 = auto()
    S3 = auto()
    S4 = auto()
    S5 = auto()
    S6 = auto()
    S7 = auto()
    S8 = auto()
    S9 = auto()
    S10 = auto()
    S11 = auto()
    S12 = auto()
    S13 = auto()
    S14 = auto()
    S15 = auto()
    S16 = auto()
    S17 = auto()
    S18 = auto()
    S19 = auto()
    S20 = auto()
    S21 = auto()
    S22 = auto()
    S23 = auto()
    S24 = auto()
    S25 = auto()
    S26 = auto()
    S27 = auto()
    S28 = auto()
    S29 = auto()
    S30 = auto()
    S31 = auto()

    FIRST_FPREG = Q0
    LAST_FPREG = S31

    CF = auto()
    ZF = auto()
    NF = auto()
    VF = auto()

    # AArch64 registers
    # general-purpose registers
    X0 = auto()
    X1 = auto()
    X2 = auto()
    X3 = auto()
    X4 = auto()
    X5 = auto()
    X6 = auto()
    X7 = auto()
    X8 = auto()
    X9 = auto()
    X10 = auto()
    X11 = auto()
    X12 = auto()
    X13 = auto()
    X14 = auto()
    X15 = auto()
    X16 = auto()
    X17 = auto()
    X18 = auto()
    X19 = auto()
    X20 = auto()
    X21 = auto()
    X22 = auto()
    X23 = auto()
    X24 = auto()
    X25 = auto()
    X26 = auto()
    X27 = auto()
    X28 = auto()
    X29 = auto()
    XFP = X29  # frame pointer
    X30 = auto()
    XLR = X30  # link register
    XZR = auto()  # zero register (special case of GPR=31)
    XSP = auto()  # stack pointer (special case of GPR=31)
    XPC = auto()  # PC (not available as actual register)

    # 128-bit SIMD registers
    V0 = auto()
    V1 = auto()
    V2 = auto()
    V3 = auto()
    V4 = auto()
    V5 = auto()
    V6 = auto()
    V7 = auto()
    V8 = auto()
    V9 = auto()
    V10 = auto()
    V11 = auto()
    V12 = auto()
    V13 = auto()
    V14 = auto()
    V15 = auto()
    V16 = auto()
    V17 = auto()
    V18 = auto()
    V19 = auto()
    V20 = auto()
    V21 = auto()
    V22 = auto()
    V23 = auto()
    V24 = auto()
    V25 = auto()
    V26 = auto()
    V27 = auto()
    V28 = auto()
    V29 = auto()
    V30 = auto()
    V31 = auto()

    ARM_MAXREG = auto()  # must be the last entry


# ------------------------------------------------------------------
#      r0         *    argument word/integer result
#      r1-r3           argument word
#
#      r4-r8        S  register variable
#      r9           S  (rfp) register variable (real frame pointer)
#
#      r10        F S  (sl) stack limit (used by -mapcs-stack-check)
#      r11        F S  (fp) argument pointer
#      r12             (ip) temp workspace
#      r13        F S  (sp) lower end of current stack frame
#      r14             (lr) link address/workspace
#      r15        F    (pc) program counter
#
#      f0              floating point result
#      f1-f3           floating point scratch
#
#      f4-f7        S  floating point variables
PC =      RegNo.R15
LR =      RegNo.R14
SP =      RegNo.R13
FP =      RegNo.R11
FP2 =     RegNo.R7  # in thumb mode


def getreg(op: ida_ua.op_t) -> int:
    if (
        op.type == ida_ua.o_reg
        or op.type == o_shreg
        and op.specflag2 == shift_t.LSL  # specflag2 = shift type
        and op.value == 0   # value = shift count
    ):
        return op.reg
    else:
        return -1


def isreg(op: ida_ua.op_t, reg: int) -> bool:
    return getreg(op) == reg


def is_simple_phrase(insn: ida_ua.insn_t, op: ida_ua.op_t) -> bool:
    """
    is it simply [Rx, Ry]?
    no shift, no negation, no post-index, no writeback
    """
    return (
        op.type == ida_ua.o_phrase
        and op.specflag2 == shift_t.LSL
        and op.value == 0
        and (insn.auxpref & (aux_negoff | aux_postidx | aux_wback)) == 0
    )


# ------------------------------------------------------------------
# Condition codes:
class cond_t(IntEnum):
    cEQ = 0               # 0000 Z                        Equal
    cNE = auto()          # 0001 !Z                       Not equal
    cCS = auto()          # 0010 C                        Unsigned higher or same
    cCC = auto()          # 0011 !C                       Unsigned lower
    cMI = auto()          # 0100 N                        Negative
    cPL = auto()          # 0101 !N                       Positive or Zero
    cVS = auto()          # 0110 V                        Overflow
    cVC = auto()          # 0111 !V                       No overflow
    cHI = auto()          # 1000 C & !Z                   Unsigned higher
    cLS = auto()          # 1001 !C | Z                   Unsigned lower or same
    cGE = auto()          # 1010 (N & V) | (!N & !V)      Greater or equal
    cLT = auto()          # 1011 (N & !V) | (!N & V)      Less than
    cGT = auto()          # 1100 !Z & ((N & V)|(!N & !V)) Greater than
    cLE = auto()          # 1101 Z | (N & !V) | (!N & V)  Less than or equal
    cAL = auto()          # 1110 Always
    cNV = auto()          # 1111 Never
    cLAST = auto()


def get_cond(insn: ida_ua.insn_t) -> cond_t:
    # condition code of instruction will be kept in segpref
    return cond_t(insn.segpref)


def has_cond(insn: ida_ua.insn_t) -> bool:
    return insn.segpref != cond_t.cAL


def is_negated_cond(cond: cond_t) -> bool:
    return (cond & cond_t.cNE) != 0


def invert_cond(cond: cond_t) -> cond_t:
    if cond < cond_t.cLAST:
        return cond_t(cond ^ 1)
    return cond_t.cLAST


# ----------------------------------------------------------------------
# see ARMExpandImm_C/ThumbExpandImm_C in ARM ARM
def may_set_carry(itype: int) -> bool:
    return itype in (
        ida_allins.ARM_and,
        ida_allins.ARM_bic,
        ida_allins.ARM_eor,
        ida_allins.ARM_mov,
        ida_allins.ARM_mvn,
        ida_allins.ARM_orn,
        ida_allins.ARM_orr,
        ida_allins.ARM_teq,
        ida_allins.ARM_tst,
    )


# ----------------------------------------------------------------------
# if true, then ASPR.C is set to bit 31 of the immediate constant
def imm_sets_carry(insn: ida_ua.insn_t) -> bool:
    itype = insn.itype

    if itype in (
        ida_allins.ARM_and,
        ida_allins.ARM_bic,
        ida_allins.ARM_eor,
        ida_allins.ARM_mov,
        ida_allins.ARM_mvn,
        ida_allins.ARM_orn,
        ida_allins.ARM_orr,
    ):
        # flags are updated if S suffix is used
        return (insn.auxpref & (aux_immcarry|aux_cond)) == (aux_immcarry|aux_cond)
    elif itype in (
        ida_allins.ARM_teq,
        ida_allins.ARM_tst,
    ):
        # these two always update flags
        return (insn.auxpref & aux_immcarry) != 0
    else:
        return False

