from __future__ import annotations

from src.executor import Executor, StoppedExecutor, SingleExecutor
from src.program import Program


class SymbolicExecutor:
    executor: Executor

    def __init__(self, program: Program, start_symbol: str):
        start_address = program.address_of_symbol(start_symbol)
        self.executor = SingleExecutor(program, start_address)

    def run(self):
        while True:
            self.executor = self.executor.step()

            if isinstance(self.executor, StoppedExecutor):
                break
