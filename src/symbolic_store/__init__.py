
import claripy
from src.riscv.registers import RiscvRegister
from src.program import Address

class SymbolicStore:
    registers: dict[RiscvRegister, claripy.Base]
    memory: dict[Address, claripy.Base]

    def __init__(self):
        pass


