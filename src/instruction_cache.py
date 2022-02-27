from src.address import Address
from src.riscv.instructions import RiscvInstruction


class InstructionCache:
    cache: dict[Address, RiscvInstruction]

    def __init__(self):
        pass