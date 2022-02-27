from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from src.constraints import BitVector
from src.program import Address, Program
from src.riscv.instructions import *
from src.symbolic_store import SymbolicStore


class InvalidInstruction(Exception):
    pass


class ShortTermState:
    take_slt_branch: Optional[bool]

    def __init__(self, take_slt_branch = None):
        self.take_slt_branch = take_slt_branch


class Executor(ABC):
    depth: int
    ststate: ShortTermState

    def __init__(self, ststate = None, depth=0):
        self.ststate = ShortTermState() if ststate is None else ststate
        self.depth = depth

    @abstractmethod
    def step(self) -> Executor: ...


class StoppedExecutor(Executor):
    def step(self):
        return self


class SingleExecutor(Executor):
    pc: Address
    program: Program
    store: SymbolicStore

    def __init__(self, program: Program, store: SymbolicStore, ststate = None, depth=0):
        super().__init__(ststate, depth)

        self.program = program
        self.store = store

    def advance_pc(self):
        self.store.advance_pc()

    def advance(self) -> SingleExecutor:
        """
        Resets self for the next instruction
        """

        self.advance_pc()
        self.ststate = ShortTermState()
        return self

    def step(self) -> Executor:
        instruction = self.program.get_instruction(self.pc)

        match instruction:
            case Add(ra, rb, rdest):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                # TODO: integer overflow?
                self.store.set_register(rdest, ra + rb)

                return self.advance()

            case Sub(ra, rb, rdest):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                # TODO: integer overflow?
                self.store.set_register(rdest, ra - rb)

                return self.advance()

            case Xor(ra, rb, rdest):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                self.store.set_register(rdest, ra ^ rb)

                return self.advance()

            case Or(ra, rb, rdest):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                self.store.set_register(rdest, ra | rb)

                return self.advance()

            case And(ra, rb, rdest):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                self.store.set_register(rdest, ra & rb)

                return self.advance()

            # TODO: Shifts

            case Slt(_, _, rdest) | Sltu(_, _, rdest) | Slti(_, _, rdest) | Sltiu(_, _, rdest) if self.ststate.take_slt_branch is not None:
                if self.ststate.take_slt_branch:
                    self.store.set_register(rdest, BitVector(1, 64))
                else:
                    self.store.set_register(rdest, BitVector(0, 64))

                return self.advance()

            case Slt(ra, rb, _) | Sltu(ra, rb, _):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                return BranchedExecutor(
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra < rb),
                        ststate=ShortTermState(True), depth=self.depth + 1
                    ),
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra >= rb),
                        ststate=ShortTermState(False), depth=self.depth + 1
                    ),
                )
            case Slti(ra, immediate, _) | Sltiu(ra, immediate, _):
                ra = self.store.get_register(ra)
                rb = BitVector(immediate, 12).sign_extend(64)

                return BranchedExecutor(
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra < rb),
                        ststate=ShortTermState(True), depth=self.depth + 1
                    ),
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra >= rb),
                        ststate=ShortTermState(False), depth=self.depth + 1
                    ),
                )

            case Addi(ra, immediate, rdest):
                ra = self.store.get_register(ra)
                rb = BitVector(immediate, 12).sign_extend(64)

                # TODO: integer overflow?
                self.store.set_register(rdest, ra + rb)

                return self.advance()

            case Xori(ra, immediate, rdest):
                ra = self.store.get_register(ra)
                rb = BitVector(immediate, 12).sign_extend(64)

                # TODO: integer overflow?
                self.store.set_register(rdest, ra ^ rb)

                return self.advance()

            case Ori(ra, immediate, rdest):
                ra = self.store.get_register(ra)
                rb = BitVector(immediate, 12).sign_extend(64)

                # TODO: integer overflow?
                self.store.set_register(rdest, ra | rb)

                return self.advance()

            case Andi(ra, immediate, rdest):
                ra = self.store.get_register(ra)
                rb = BitVector(immediate, 12).sign_extend(64)

                # TODO: integer overflow?
                self.store.set_register(rdest, ra & rb)

                return self.advance()

            # TODO: Shift

            case Lb(ra, immediate, rdest):
                pass
                # ra = self.store.get_register(ra)
                # rb = claripy.BVV(immediate, 12).sign_extend(64)
                # address = ra + rb
                #
                # self.store.bounds_check(address)
                #
                #
                #
                #
                # self.store.set_register(rdest, ra & rb)

                return self.advance()
            case _:
                raise InvalidInstruction()


class BranchedExecutor(Executor):
    executors: tuple[Executor, ...]

    def __init__(self, *executors: Executor, ststate=None, depth=0):
        super().__init__(ststate, depth)
        self.executors = executors

    def step(self) -> Executor:
        # noinspection PyTypeChecker
        self.executors = tuple((i.step() for i in self.executors))

        if all(isinstance(i, StoppedExecutor) for i in self.executors):
            return StoppedExecutor()
        else:
            return self