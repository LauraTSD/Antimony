from __future__ import annotations

import copy

from src.constraints import Constraint, BitVector, BoundedPointer
from src.riscv.registers import RiscvRegister
from src.address import Address
from src.vulnerability import WriteToPC

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from src.program import Program


class SymbolicStore:
    registers: dict[RiscvRegister, Constraint]
    memory: dict[Address, Constraint]
    path_constraints: list[Constraint]

    pc: Address
    program: Program

    def __init__(self, pc: Address, program: Program, registers=None, memory=None):
        self.pc = pc
        self.registers = {} if registers is None else registers
        self.memory = {} if memory is None else memory
        self.path_constraints = []
        self.program = program

    def with_path_constraint(self, constraint: Constraint) -> SymbolicStore:
        self.path_constraints.append(constraint)
        return self

    def allocate_zeroed(self, size: int) -> BoundedPointer:
        start = Address(int(0 if len(self.memory) == 0 else max(self.memory.keys())))
        for i in range(start, start + size):
            self.memory[Address(i)] = BitVector(0, 8)

        return BoundedPointer(start, start, start + size)

    def get_byte(self, address: Address) -> Constraint:
        if address not in self.memory:
            # ask gdb
            return BitVector(self.program.get_data(address), 8)

        return self.memory[address]

    def set_byte(self, address: Address, value: Constraint):
        self.memory[address] = value

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

    def set_pc(self, pc: Address):
        self.pc = pc

    def get_pc(self):
        return self.pc

    def set_pc_offset(self, offset: int):
        self.pc += offset

    def advance_pc(self):
        self.pc += 4

    def copy(self) -> SymbolicStore:
        return SymbolicStore(self.pc, self.program, copy.copy(self.registers), copy.copy(self.memory))

    def __repr__(self):
        newline = "\n"
        def should_show(k: Constraint):
            if not isinstance(k, BitVector):
                return True
            elif k.as_integer() == 0:
                return False
            else:
                return True

        return f"registers: {newline.join(f'{k} => {v}' for k, v in self.registers.items() if should_show(v))}" \
               f"\npc: 0x{self.pc:08x}\nmemory: {len(self.memory)}\npath: {self.path_constraints}"
