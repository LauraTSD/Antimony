from __future__ import annotations

from typing import Iterable

from src.riscv.instructions import RiscvInstruction
from src.symbolic_store import SymbolicStore


class Address(int):
    pass


class Program:
    def __init__(self):
        pass

    @classmethod
    def from_c_file(cls, filename: str):
        pass

    @classmethod
    def from_binary_file(cls, filename: str) -> Program:
        pass

    def address_of_symbol(self, symbol: str) -> Address:
        raise NotImplemented

    def get_instruction(self, pc: Address) -> RiscvInstruction:
        raise NotImplemented

    def initialize_store(self, initial_pc: Address) -> SymbolicStore:
        raise NotImplemented