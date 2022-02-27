from src.riscv.instructions import *
from src.riscv.registers import RiscvRegister


class BitAccess(int):
    def __getitem__(self, item) -> int:
        """
        NOTE: unlike arrays, indexes are inclusive on both sides
        """

        if isinstance(item, slice):
            assert item.step == 1 or item.step is None
            if item.stop is None:
                stop = self.bit_length() + 1
            else:
                stop = item.stop + 1

            if item.start is None:
                start = 0
            else:
                start = item.start

            mask = (1 << (stop - start)) - 1
            return (self >> start) & mask
        elif isinstance(item, int):
            return 1 if self & 1 << item > 0 else 0
        else:
            raise TypeError(f"Can't slice BitAccess with type {type(item)}")

    def __repr__(self):
        return f"BitAccess({super().__repr__()})"


def r_type(instruction: BitAccess) -> tuple[RiscvRegister, RiscvRegister, RiscvRegister]:
    rd = instruction[7:11]
    ra = instruction[15:19]
    rb = instruction[20:24]

    return RiscvRegister(ra), RiscvRegister(rb), RiscvRegister(rd)


def i_type(instruction: BitAccess) -> tuple[RiscvRegister, int, RiscvRegister]:
    rd = instruction[7:11]
    ra = instruction[15:19]
    imm = instruction[20:31]

    return RiscvRegister(ra), interpret_signed(imm, 12), RiscvRegister(rd)


def s_type(instruction: BitAccess) -> tuple[RiscvRegister, RiscvRegister, int]:
    ra = instruction[15:19]
    rb = instruction[20:24]

    imm = instruction[7:11] | instruction[25:31] << 4

    return RiscvRegister(ra), RiscvRegister(rb), interpret_signed(imm, 12)


def b_type(instruction: BitAccess) -> tuple[RiscvRegister, RiscvRegister, int]:
    ra = instruction[15:19]
    rb = instruction[20:24]

    imm = instruction[7] << 11 | \
          instruction[8:11] << 1 | \
          instruction[25:30] << 5 | \
          instruction[31] << 12

    return RiscvRegister(ra), RiscvRegister(rb), interpret_signed(imm, 13)


def u_type(instruction: BitAccess) -> tuple[int, RiscvRegister]:
    rd = instruction[7:11]

    imm = instruction[12:31] << 12
    return interpret_signed(imm, 32), RiscvRegister(rd)


def j_type(instruction: BitAccess) -> tuple[int, RiscvRegister]:
    rd = instruction[7:11]
    imm = instruction[12:19] << 12 | \
        instruction[20] << 11 | \
        instruction[21:30] << 1 | \
        instruction[31] << 20

    return interpret_signed(imm, 21), RiscvRegister(rd)


def interpret_signed(value: int, length: int):
    value = BitAccess(value)

    if value[length-1] == 1:
        return value - (1 << length)
    else:
        return value


class InvalidInstruction(Exception):
    pass


def parse_instruction(instruction: int) -> RiscvInstruction:
    instruction = BitAccess(instruction)

    match instruction[0:6]:
        case 0b0110011:
            ra, rb, rd = r_type(instruction)

            match instruction[12:14]:
                case 0b000 if instruction[25:31] == 0b0000000:
                    return Add(ra, rb, rd)
                case 0b000 if instruction[25:31] == 0b0100000:
                    return Sub(ra, rb, rd)
                case 0b001:
                    return Sll(ra, rb, rd)
                case 0b010:
                    return Slt(ra, rb, rd)
                case 0b011:
                    return Sltu(ra, rb, rd)
                case 0b100:
                    return Xor(ra, rb, rd)
                case 0b101 if instruction[25:31] == 0b0000000:
                    return Srl(ra, rb, rd)
                case 0b101 if instruction[25:31] == 0b1000000:
                    return Sra(ra, rb, rd)
                case 0b110:
                    return Or(ra, rb, rd)
                case 0b111:
                    return And(ra, rb, rd)
                case _: raise InvalidInstruction()
        case 0b0010011:
            ra, imm, rd = i_type(instruction)

            match instruction[12:14]:
                case 0b000:
                    return Addi(ra, imm, rd)
                case 0b010:
                    return Slti(ra, imm, rd)
                case 0b011:
                    return Sltiu(ra, imm, rd)
                case 0b100:
                    return Xori(ra, imm, rd)
                case 0b110:
                    return Ori(ra, imm, rd)
                case 0b111:
                    return Andi(ra, imm, rd)
                case _: raise InvalidInstruction()
        case 0b0000011:
            ra, imm, rd = i_type(instruction)
            match instruction[12:14]:
                case 0b000:
                    return Lb(ra, imm, rd)
                case 0b001:
                    return Lh(ra, imm, rd)
                case 0b010:
                    return Lw(ra, imm, rd)
                case 0b100:
                    return Lbu(ra, imm, rd)
                case 0b101:
                    return Lhu(ra, imm, rd)
                case _: raise InvalidInstruction()
        case 0b0100011:
            ra, rb, imm = s_type(instruction)
            match instruction[12:14]:
                case 0b000:
                    return Sb(ra, rb, imm)
                case 0b001:
                    return Sh(ra, rb, imm)
                case 0b010:
                    return Sw(ra, rb, imm)
                case _: raise InvalidInstruction()
        case 0b1100011:
            ra, rb, imm = b_type(instruction)
            match instruction[12:14]:
                case 0b000:
                   return Beq(ra, rb, imm)
                case 0b001:
                    return Bneq(ra, rb, imm)
                case 0b100:
                    return Blt(ra, rb, imm)
                case 0b101:
                    return Bge(ra, rb, imm)
                case 0b110:
                    return Bltu(ra, rb, imm)
                case 0b111:
                    return Bgeu(ra, rb, imm)
                case _: raise InvalidInstruction()
        case 0b0110111:
            return Lui(*u_type(instruction))
        case 0b0010111:
            return Auipc(*u_type(instruction))
        case 0b1100111 if instruction[12:14] == 0b000:
            return Jalr(*i_type(instruction))
        case 0b1101111:
            return Jal(*j_type(instruction))
        case 0b1110011 if instruction[20:31] == 0b000000000000:
            return ECall(RiscvRegister(0), 0, RiscvRegister(0))
        case 0b1110011 if instruction[20:31] == 0b000000000001:
            return EBreak(RiscvRegister(0), 0, RiscvRegister(0))
        case _: raise InvalidInstruction()



