from __future__ import annotations

from typing import Iterable

from src.instructions import RiscvInstruction
from src.symbolic_store import SymbolicStore


class Program:
    def __init__(self):
        pass

    @classmethod
    def from_file(cls, filename: str) -> Program:
        pass

    def instructions(self) -> Iterable[RiscvInstruction]:
        raise NotImplemented

    def initialize_store(self) -> SymbolicStore:
        raise NotImplemented