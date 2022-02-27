from __future__ import annotations

import copy

from src.constraints import Constraint, BitVector
from src.riscv.registers import RiscvRegister
from src.address import Address
from src.vulnerability import WriteToPC


class SymbolicStore:
    registers: dict[RiscvRegister, Constraint]
    memory: dict[Address, Constraint]
    path_constraints: list[Constraint]

    pc: int

    def __init__(self, pc, registers=None, memory=None):
        self.pc = pc
        self.registers = {} if registers is None else registers
        self.memory = {} if registers is None else memory

    def with_path_constraint(self, constraint: Constraint) -> SymbolicStore:
        self.path_constraints.append(constraint)
        return self

    def get_register(self, reg: RiscvRegister) -> Constraint:
        if reg == RiscvRegister.Zero:
            return BitVector(0, 64)

        if reg == RiscvRegister.Tp:
            return BitVector(self.pc, 64)

        return self.registers[reg]

    def set_register(self, reg: RiscvRegister, value: Constraint):
        if reg == RiscvRegister.Zero:
            # TODO: log this. It's not an error, but it's useful to know
            # TODO: DONT, for some instruction sequences, writing to r0 and discarding
            #       results is completely expected. For example `j test` == `jal x0, test`
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


