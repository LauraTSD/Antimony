from __future__ import annotations

from src.executor import Executor, StoppedExecutor, SingleExecutor
from src.program import Program, Symbol
from src.address import Address


class SymbolicExecutor:
    executor: Executor

    def __init__(self, program: Program, start_symbol: Symbol | Address | None = None):
        """
        Create a symbolic executor
        :param program: the program to run
        :param start_symbol: either a symbol, address or nothing.

        When a symbol: the symbol must exist and be findable.
        That will likely mean that debug info needs to be present in the binary.

        When an address: Any value will work, but there will be no verification. The symbolic
        executor will start at this address and assume there are valid instructions there. If not an
        error can be expected

        When None: start at the program's entry point.
        """
        if isinstance(start_symbol, Symbol):
            start_address = program.address_of_symbol(start_symbol)
            if start_address is None:
                pass
        elif isinstance(start_symbol, Address):
            start_address = start_symbol
        elif start_symbol is None:
            start_address = program.first_address
        else:
            raise TypeError(f"invalid value for parameter start_symbol: {start_symbol}")

        self.executor = SingleExecutor(program, program.initialize_store(start_address))

    def run(self):
        num_instructions = 0
        while True:
            self.executor = self.executor.step()

            if isinstance(self.executor, StoppedExecutor):
                break

            num_instructions += 1
