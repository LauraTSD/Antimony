from __future__ import annotations

import os
import tempfile
from io import BytesIO

from typing import TYPE_CHECKING, IO

from src.riscv.instructions import RiscvInstruction
import subprocess
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Symbol

if TYPE_CHECKING:
    from src.symbolic_store import SymbolicStore


script_path = os.path.dirname(os.path.abspath(__file__))


class Address(int):
    pass


class Program:
    elffile: ELFFile

    def __init__(self, b: IO):
        self.elffile = ELFFile(b)

    @classmethod
    def from_elf_bytes(cls, b: bytes) -> Program:
        io = BytesIO()
        io.write(b)
        io.seek(0)
        return cls(io)

    @classmethod
    def from_c_file(cls, filename: str) -> Program:
        with tempfile.NamedTemporaryFile("w+b") as f:
            cmd = [
                f"{script_path}/../toolchain/bin/riscv64-unknown-linux-gnu-gcc",
                "-o", f.name,
                filename,
                "-march=rv64i",
                "-mabi=lp64",
            ]
            print(f"running {' '.join(cmd)}")
            output = subprocess.run(cmd)
            if output.returncode != 0:
                raise Exception("couldn't compile riscv code")

            f.seek(0)
            return cls(f)

    @classmethod
    def from_elf_file(cls, filename: str) -> Program:
        with open(filename, "rb") as f:
            return cls(f)

    def address_of_symbol(self, symbol_name: str, executable: bool = False) -> Address:
        found_symbols: list[Symbol] = []

        for section in self.elffile.iter_sections(type="SHT_PROGBITS" if executable else None):
            if (symbols := section.get_symbol_by_name(symbol_name)) is not None:
                found_symbols.extend(symbols)

        if len(found_symbols) == 0:
            raise ValueError("symbol not found")
        elif len(found_symbols) == 1:
            symbol = found_symbols[0]
            print(symbol)
        else:
            raise ValueError(f"found multiple symbols with that name ({symbol_name})")

    def get_instruction(self, pc: Address) -> RiscvInstruction:
        raise NotImplemented

    def initialize_store(self, initial_pc: Address) -> SymbolicStore:
        raise NotImplemented
