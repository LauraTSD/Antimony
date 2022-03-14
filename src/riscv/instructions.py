from dataclasses import dataclass

from src.riscv.registers import RiscvRegister

@dataclass
class RiscvInstruction:
    pass


@dataclass
class RType(RiscvInstruction):
    ra: RiscvRegister
    rb: RiscvRegister
    rdest: RiscvRegister


@dataclass
class IType(RiscvInstruction):
    ra: RiscvRegister
    immediate: int
    rdest: RiscvRegister


@dataclass
class SType(RiscvInstruction):
    ra: RiscvRegister
    rb: RiscvRegister
    immediate: int


@dataclass
class BType(RiscvInstruction):
    ra: RiscvRegister
    rb: RiscvRegister
    immediate: int


@dataclass
class UType(RiscvInstruction):
    immediate: int
    rdest: RiscvRegister


@dataclass
class JType(RiscvInstruction):
    immediate: int
    rdest: RiscvRegister


@dataclass
class Add(RType):
    pass


@dataclass
class Sub(RType):
    pass


@dataclass
class Xor(RType):
    pass


@dataclass
class Or(RType):
    pass


@dataclass
class And(RType):
    pass


@dataclass
class Sll(RType):
    pass


@dataclass
class Srl(RType):
    pass


@dataclass
class Sra(RType):
    pass


@dataclass
class Slt(RType):
    pass


@dataclass
class Sltu(RType):
    pass


@dataclass
class Addi(IType):
    pass


@dataclass
class Xori(IType):
    pass


@dataclass
class Ori(IType):
    pass


@dataclass
class Andi(IType):
    pass


@dataclass
class Slli(IType):
    # 6 bit shift offset instead of 5 because rv64i
    pass


@dataclass
class Srli(IType):
    # 6 bit shift offset instead of 5 because rv64i
    pass


@dataclass
class Srai(IType):
    # 6 bit shift offset instead of 5 because rv64i
    pass


@dataclass
class Slti(IType):
    pass


@dataclass
class Sltiu(IType):
    pass


@dataclass
class Lb(IType):
    pass


@dataclass
class Lh(IType):
    pass


@dataclass
class Lw(IType):
    pass


@dataclass
class Lbu(IType):
    pass


@dataclass
class Lhu(IType):
    pass


@dataclass
class Sb(SType):
    pass


@dataclass
class Sh(SType):
    pass


@dataclass
class Sw(SType):
    pass


@dataclass
class Beq(BType):
    pass


@dataclass
class Bneq(BType):
    pass


@dataclass
class Blt(BType):
    pass


@dataclass
class Bge(BType):
    pass


@dataclass
class Bltu(BType):
    pass


@dataclass
class Bgeu(BType):
    pass


@dataclass
class Jal(JType):
    pass


@dataclass
class Jalr(IType):
    pass


@dataclass
class   Lui(UType):
    pass


@dataclass
class Auipc(UType):
    pass


@dataclass
class ECall(IType):
    pass


@dataclass
class EBreak(IType):
    pass


@dataclass
class Addiw(IType):
    pass


@dataclass
class Slliw(IType):
    # 5 bit shamt because 32 bits
    pass


@dataclass
class Srliw(IType):
    # 5 bit shamt because 32 bits
    pass


@dataclass
class Sraiw(IType):
    # 5 bit shamt because 32 bits
    pass


@dataclass
class Addw(RType):
    pass


@dataclass
class Sllw(RType):
    pass


@dataclass
class Srlw(RType):
    pass


@dataclass
class Subw(RType):
    pass


@dataclass
class Sraw(RType):
    pass


@dataclass
class Ld(IType):
    pass


@dataclass
class Sd(IType):
    pass


@dataclass
class Lwu(IType):
    pass


