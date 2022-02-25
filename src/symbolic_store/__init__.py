from __future__ import annotations

import copy

import claripy
from src.riscv.registers import RiscvRegister
from src.program import Address
from src.vulnerability import WriteToPC


class SymbolicStore:
    registers: dict[RiscvRegister, claripy.Base]
    memory: dict[Address, claripy.Base]

    pc: int

    def __init__(self, pc, registers=None, memory=None):
        self.pc = pc
        self.registers = {} if registers is None else registers
        self.memory = {} if registers is None else memory

    def get_register(self, reg: RiscvRegister) -> claripy.Base:
        if reg == RiscvRegister.Zero:
            return claripy.BVV(0, 64)

        if reg == RiscvRegister.Tp:
            return claripy.BVV(self.pc, 64)

        return self.registers[reg]

    def set_register(self, reg: RiscvRegister, value: claripy.Base):
        if reg == RiscvRegister.Zero:
            # TODO: log this. It's not an error, but it's useful to know
            return

        if reg == RiscvRegister.Tp:
            raise WriteToPC(self)

        self.registers[reg] = value

    def set_pc(self, pc: int):
        self.pc = pc

    def advance_pc(self):
        self.pc += 1

    def copy(self) -> SymbolicStore:
        return SymbolicStore(self.pc, copy.copy(self.registers), copy.copy(self.memory))


