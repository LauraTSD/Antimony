from __future__ import annotations

from abc import ABC, abstractmethod

from src.program import Address, Program


class InvalidInstruction(Exception):
    pass


class Executor(ABC):
    depth: int

    def __init__(self, depth=0):
        self.depth = depth

    @abstractmethod
    def step(self) -> Executor: ...


class StoppedExecutor(Executor):
    def step(self):
        return self


class SingleExecutor(Executor):
    pc: Address
    program: Program

    def __init__(self, program: Program, initial_pc: Address, depth=0):
        super().__init__(depth)

        self.program = program
        self.pc = initial_pc

    def step(self) -> Executor:
        instruction = self.program.get_instruction(self.pc)

        match instruction:

            case _: raise InvalidInstruction()
        # parse

        # 1:
        # generate constraints
        # solve constraints


        # 2:
        # detect branch
        # generate branch constraints
        # split

        return self


class BranchedExecutor(Executor):
    executors: tuple[Executor, Executor]

    def __init__(self, executors: tuple[Executor, Executor], depth=0):
        super().__init__(depth)
        self.executors = executors

    def step(self) -> Executor:
        # noinspection PyTypeChecker
        self.executors = tuple((i.step() for i in self.executors))

        if all(isinstance(i, StoppedExecutor) for i in self.executors):
            return StoppedExecutor()
        else:
            return self