
class RiscvInstruction:
    pass


class RType(RiscvInstruction):
    pass


class IType(RiscvInstruction):
    pass


class SType(RiscvInstruction):
    pass


class BType(RiscvInstruction):
    pass


class UType(RiscvInstruction):
    pass


class JType(RiscvInstruction):
    pass


class Add(RType):
    pass


class Sub(RType):
    pass


class Xor(RType):
    pass


class Or(RType):
    pass


class And(RType):
    pass


class Sll(RType):
    pass


class Srl(RType):
    pass


class Sra(RType):
    pass


class Slt(RType):
    pass


class Sltu(RType):
    pass


class Addi(IType):
    pass


class Xori(IType):
    pass


class Ori(IType):
    pass


class Andi(IType):
    pass


class Slli(IType):
    # 6 bit shift offset instead of 5 because rv64i
    pass


class Srli(IType):
    # 6 bit shift offset instead of 5 because rv64i
    pass


class Srai(IType):
    # 6 bit shift offset instead of 5 because rv64i
    pass


class Slti(IType):
    pass


class Sltiu(IType):
    pass


class Lb(IType):
    pass


class Lh(IType):
    pass


class Lw(IType):
    pass


class Lbu(IType):
    pass


class Lhu(IType):
    pass


class Sb(SType):
    pass


class Sh(SType):
    pass


class Sw(SType):
    pass


class Beq(BType):
    pass


class Bneq(BType):
    pass


class Blt(BType):
    pass


class Bge(BType):
    pass


class Bltu(BType):
    pass


class Bgeu(BType):
    pass


class Jal(JType):
    pass


class Jalr(IType):
    pass


class Lui(UType):
    pass


class Auipc(UType):
    pass


class ECall(IType):
    pass


class EBreak(IType):
    pass


class Addiw(IType):
    pass


class Slliw(IType):
    # 5 bit shamt because 32 bits
    pass


class Srliw(IType):
    # 5 bit shamt because 32 bits
    pass


class Sraiw(IType):
    # 5 bit shamt because 32 bits
    pass


class Addw(RType):
    pass


class Sllw(RType):
    pass


class Srlw(RType):
    pass


class Subw(RType):
    pass


class Sraw(RType):
    pass


class Ld(IType):
    pass


class Sd(IType):
    pass


class Lwu(IType):
    pass