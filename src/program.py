from __future__ import annotations

import os
import re
import tempfile

from typing import TYPE_CHECKING, IO, Optional

from src.address import Address
from src.constraints import BitVector, BoundedPointer
from src.riscv.instructions import RiscvInstruction
from src.riscv.registers import RiscvRegister
import subprocess
from pygdbmi.gdbcontroller import GdbController
from functools import cache



from src.riscv.parse import parse_instruction

if TYPE_CHECKING:
    from src.symbolic_store import SymbolicStore


script_path = os.path.dirname(os.path.abspath(__file__))

parse_get_symbol = re.compile(r".*Symbol .* is a .* at address 0x([0-9a-f]*)\.?\n?")
parse_entry_point = re.compile(r".*Entry.* 0x([0-9a-f]*)\.?\n?")
parse_instruction_text = re.compile(r".*0x.*:(.*)\n?.*")
parse_instruction_bytes = re.compile(r".*0x.*:.*0x(.*)\\n.*")


class Symbol(str):
    """
    symbol in an ELF binary
    """
    pass


class Program:
    file: IO  # to keep temporary files alive and not gc them
    gdb: GdbController

    def __init__(self, b: bytes):
        f = tempfile.NamedTemporaryFile("w+b")
        f.write(b)
        f.seek(0)

        controller = GdbController(command=[
            f"{script_path}/../toolchain/bin/riscv64-unknown-linux-gnu-gdb",
            "--interpreter=mi3",
            f.name
        ])

        # write returns all startup logs from gdb. This basically discards them
        controller.write("")

        self.file = f
        self.gdb = controller

    def __del__(self):
        self.gdb.exit()
        self.file.close()

    @classmethod
    def from_elf_bytes(cls, b: bytes) -> Program:
        return cls(b)

    @classmethod
    def from_c_string(cls, program: str, debug: bool = True) -> Program:
        with tempfile.NamedTemporaryFile("w+") as f:
            f.write(program)
            f.seek(0)
            return cls.from_c_file(f.name, debug)

    @classmethod
    def from_c_file(cls, filename: str, debug: bool = True) -> Program:
        with tempfile.NamedTemporaryFile("w+b") as f:
            cmd = [
                f"{script_path}/../toolchain/bin/riscv64-unknown-linux-gnu-gcc",
                "-x", "c",
                "-o", f.name,
                filename,
                "-march=rv64i",
                "-mabi=lp64",
                "-g" if debug else "",
            ]
            print(f"running {' '.join(cmd)}")
            output = subprocess.run(cmd)
            if output.returncode != 0:
                raise Exception("couldn't compile riscv code")

            f.seek(0)
            return cls(f.read())

    @classmethod
    def from_elf_file(cls, filename: str) -> Program:
        with open(filename, "rb") as f:
            return cls(f.read())

    def address_of_symbol(self, symbol: Symbol) -> Optional[Address]:
        """
        :param symbol: the symbol to look for
        :return: the address of the symbol or None. None may be because
        a) the symbol wasn't in the file
        b) there were no debugging symbols
        """

        addresses = set()

        response = self.gdb.write(f"info address {str(symbol)}")
        for i in filter(lambda r: r["type"] == "console" and "Symbol" in r["payload"], response):
            if (m := parse_get_symbol.match(i["payload"])) is not None:
                addresses.add(Address(int(m.group(1), 16)))

        if len(addresses) > 1:
            raise ValueError(f"Somehow got multiple addresses for symbol {symbol}")
        elif len(addresses) == 0:
            return None
        else:
            return addresses.pop()

    @cache
    def get_instruction_disassembly_string(self, pc: Address) -> str:
        response = self.gdb.write(f"disassemble {hex(pc)}, +1")

        for i in filter(lambda r: r["type"] == "console" and "Dump of assembler" not in r["payload"], response):
            if (m := parse_instruction_text.match(i["payload"])) is not None:
                instruction = m.group(1)
                return instruction.strip().replace("\\t", " ").replace("\\n", " ")

    @cache  # make sure that gdb is called as little as possible
    # TODO: maybe read multiple instructions at once to improve speed
    def get_instruction(self, pc: Address) -> RiscvInstruction:
        response = self.gdb.write(f"x/1wx {hex(pc)}")

        for i in filter(lambda r: r["type"] == "console", response):
            if (m := parse_instruction_bytes.match(i["payload"])) is not None:
                instruction = m.group(1)
                return parse_instruction(int(instruction, 16))

    def get_data(self, address: Address) -> int:
        response = self.gdb.write(f"x/1bx {hex(address)}")

        for i in filter(lambda r: r["type"] == "console", response):
            if (m := parse_instruction_bytes.match(i["payload"])) is not None:
                instruction = m.group(1)
                return int(instruction, 16)

    def initialize_store(self, initial_pc: Address) -> SymbolicStore:
        from src.symbolic_store import SymbolicStore
        regs = {k: BitVector(0, 64) for k in RiscvRegister}
        store = SymbolicStore(initial_pc, self, registers=regs)
        store.set_register(RiscvRegister.Sp, store.allocate_zeroed(4 * 1024))

        return store

    def entry_point(self):
        addresses = set()

        response = self.gdb.write(f"info files")
        for i in filter(lambda r: r["type"] == "console" and "Entry point" in r["payload"], response):
            if (m := parse_entry_point.match(i["payload"])) is not None:
                addresses.add(Address(int(m.group(1), 16)))

        if len(addresses) > 1:
            raise ValueError(f"Somehow got multiple entry point addresses")
        elif len(addresses) == 0:
            return None
        else:
            return addresses.pop()

