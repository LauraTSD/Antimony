from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from src.constraints import BitVector
from src.program import Program
from src.address import Address
from src.riscv.instructions import *
from src.symbolic_store import SymbolicStore


@dataclass
class InvalidInstruction(Exception):
    instruction: RiscvInstruction


class ShouldHaveReturned(Exception):
    def __repr__(self):
        return "function should have returned in one of the match-branches now!"


class ShortTermState:
    take_slt_branch: Optional[bool]

    def __init__(self, take_slt_branch = None):
        self.take_slt_branch = take_slt_branch


class Executor(ABC):
    depth: int
    ststate: ShortTermState

    num_executed: int = 0

    def __init__(self, ststate=None, depth=0):
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

    @property
    def pc(self) -> Address:
        return Address(self.store.pc)

    def advance_pc(self):
        self.store.advance_pc()

    def advance(self) -> SingleExecutor:
        """
        Resets self for the next instruction
        """

        self.advance_pc()
        self.ststate = ShortTermState()
        print(f"new pc: 0x{self.store.get_pc():08x}")
        return self

    def jump_offset(self, offset: int) -> SingleExecutor:
        """
        Resets self for the next instruction
        """

        self.store.set_pc_offset(offset)
        self.ststate = ShortTermState()
        print(f"new pc: 0x{self.store.get_pc():08x}")
        return self

    def jump(self, address: Address) -> SingleExecutor:
        """
        Resets self for the next instruction
        """

        self.store.set_pc(address)
        self.ststate = ShortTermState()
        print(f"new pc: 0x{self.store.get_pc():08x}")
        return self

    def step(self) -> Executor:
        instruction = self.program.get_instruction(self.pc)
        # input()
        self.__class__.num_executed += 1
        print(f"----------- execute instruction #{self.__class__.num_executed} -----------")
        print(instruction)
        print(self.store)

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

            case Subw(ra, rb, rdest):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                # TODO: integer overflow?
                self.store.set_register(rdest, (ra.slice(0, 31) - rb.slice(0, 31)).sign_extend(64))

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

            case Addiw(ra, immediate, rdest):
                ra = self.store.get_register(ra)
                rb = BitVector(immediate, 12).sign_extend(32)

                # TODO: integer overflow?
                self.store.set_register(rdest, (ra.slice(0, 31) + rb).sign_extend(64))

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

            # TODO: All Shifts
            case Srliw(ra, rdest, immediate):
                ra = self.store.get_register(ra)

                self.store.set_register(
                    rdest,
                    ra.slice(0, 31)
                    .shift_left(immediate, False)
                    .zero_extend(64)
                )
                return self.advance()

            case Srlw(ra, rb, rdest):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                self.store.set_register(
                    rdest,
                    ra.slice(0, 31)
                        .shift_right(rb, False)
                        .zero_extend(64)
                )
                return self.advance()

            case Sraw(ra, rb, rdest):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                self.store.set_register(
                    rdest,
                    ra.slice(0, 31)
                        .shift_right(rb, True)
                        .zero_extend(64)
                )
                return self.advance()

            case Sllw(ra, rb, rdest):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                self.store.set_register(
                    rdest,
                    ra.slice(0, 31)
                        .shift_left(rb, False)
                        .zero_extend(64)
                )
                return self.advance()

            case Sraiw(ra, rdest, immediate):
                ra = self.store.get_register(ra)

                self.store.set_register(
                    rdest,
                    ra.slice(0, 31)
                    .shift_right(immediate, True)
                    .zero_extend(64)
                )
                return self.advance()

            case Slliw(ra, rdest, immediate):
                ra = self.store.get_register(ra)

                self.store.set_register(
                    rdest,
                    ra.slice(0, 31)
                        .shift_right(immediate, False)
                        .zero_extend(64)
                )
                return self.advance()

            case Srliw(ra, rdest, immediate):
                ra = self.store.get_register(ra)

                self.store.set_register(
                    rdest,
                    ra.slice(0, 31)
                    .shift_right(immediate, False)
                    .zero_extend(64)
                )
                return self.advance()

            case Srli(ra, rdest, immediate):
                ra = self.store.get_register(ra)

                self.store.set_register(
                    rdest,
                    ra.shift_right(immediate, False)
                )
                return self.advance()

            case Slli(ra, rdest, immediate):
                ra = self.store.get_register(ra)

                self.store.set_register(
                    rdest,
                    ra.shift_left(immediate, False)
                )
                return self.advance()

            case Lb(ra, immediate, rdest):
                ra = self.store.get_register(ra)

                executors = []
                for address in ra.possible_values():
                    store = self.store.copy().with_path_constraint(ra == address)
                    address = address.as_integer()

                    store.set_register(rdest, store.get_byte(address + immediate).sign_extend(64))

                    executors.append(SingleExecutor(
                        self.program,
                        store,
                    ).advance())

                return BranchedExecutor(*executors)

            case Lh(ra, immediate, rdest):
                ra = self.store.get_register(ra)

                executors = []
                for address in ra.possible_values():
                    store = self.store.copy().with_path_constraint(ra == address)
                    address = address.as_integer()

                    store.set_register(
                        rdest,
                        (
                            store.get_byte(address + immediate).zero_extend(16) |
                            store.get_byte(address + immediate + 1).zero_extend(16).shift_left(BitVector(8, 16))
                        ).sign_extend(64)
                    )

                    executors.append(SingleExecutor(
                        self.program,
                        store,
                    ).advance())

                return BranchedExecutor(*executors)

            case Lw(ra, immediate, rdest):
                ra = self.store.get_register(ra)
                print(ra)
                print(ra.possible_values())

                executors = []
                for address in ra.possible_values():
                    print(address)
                    store = self.store.copy().with_path_constraint(ra == address)
                    address = address.as_integer()

                    store.set_register(
                        rdest,
                        (
                            store.get_byte(address + immediate).zero_extend(32) |
                            store.get_byte(address + immediate + 1).zero_extend(32).shift_left(BitVector(8, 32)) |
                            store.get_byte(address + immediate + 2).zero_extend(32).shift_left(BitVector(16, 32)) |
                            store.get_byte(address + immediate + 3).zero_extend(32).shift_left(BitVector(24, 32))
                        ).sign_extend(64)
                    )

                    executors.append(SingleExecutor(
                        self.program,
                        store,
                    ).advance())

                return BranchedExecutor(*executors)

            case Ld(ra, immediate, rdest):
                ra = self.store.get_register(ra)

                executors = []
                for address in ra.possible_values():
                    store = self.store.copy().with_path_constraint(ra == address)
                    address = address.as_integer()

                    store.set_register(
                        rdest,
                        store.get_byte(address + immediate).zero_extend(64) |
                        store.get_byte(address + immediate + 1).zero_extend(64).shift_left(BitVector(8, 64)) |
                        store.get_byte(address + immediate + 2).zero_extend(64).shift_left(BitVector(16, 64)) |
                        store.get_byte(address + immediate + 3).zero_extend(64).shift_left(BitVector(24, 64)) |
                        store.get_byte(address + immediate + 4).zero_extend(64).shift_left(BitVector(32, 64)) |
                        store.get_byte(address + immediate + 5).zero_extend(64).shift_left(BitVector(40, 64)) |
                        store.get_byte(address + immediate + 6).zero_extend(64).shift_left(BitVector(48, 64)) |
                        store.get_byte(address + immediate + 7).zero_extend(64).shift_left(BitVector(56, 64))
                    )

                    executors.append(SingleExecutor(
                        self.program,
                        store,
                    ).advance())

                return BranchedExecutor(*executors)

            case Lbu(ra, immediate, rdest):
                ra = self.store.get_register(ra)

                executors = []
                for address in ra.possible_values():
                    store = self.store.copy().with_path_constraint(ra == address)
                    address = address.as_integer()

                    store.set_register(rdest, store.get_byte(address + immediate).zero_extend(64))

                    executors.append(SingleExecutor(
                        self.program,
                        store,
                    ).advance())

                return BranchedExecutor(*executors)

            case Lhu(ra, immediate, rdest):
                ra = self.store.get_register(ra)

                executors = []
                for address in ra.possible_values():
                    store = self.store.copy().with_path_constraint(ra == address)
                    address = address.as_integer()

                    store.set_register(
                        rdest,
                        (
                            store.get_byte(address + immediate).zero_extend(16) |
                            store.get_byte(address + immediate + 1).zero_extend(16).shift_left(BitVector(8, 16))
                        ).zero_extend(64)
                    )

                    executors.append(SingleExecutor(
                        self.program,
                        store,
                    ).advance())

                return BranchedExecutor(*executors)

            case Lwu(ra, immediate, rdest):
                ra = self.store.get_register(ra)

                executors = []
                for address in ra.possible_values():
                    store = self.store.copy().with_path_constraint(ra == address)
                    address = address.as_integer()

                    store.set_register(
                        rdest,
                        (
                            store.get_byte(address + immediate).zero_extend(32) |
                            store.get_byte(address + immediate + 1).zero_extend(32).shift_left(BitVector(8, 32)) |
                            store.get_byte(address + immediate + 2).zero_extend(32).shift_left(BitVector(16, 32)) |
                            store.get_byte(address + immediate + 3).zero_extend(32).shift_left(BitVector(24, 32))
                        ).zero_extend()
                    )

                    executors.append(SingleExecutor(
                        self.program,
                        store,
                    ).advance())

                return BranchedExecutor(*executors)

            # TODO: All Stores
            case Sd(ra, rb, immediate):
                ra = self.store.get_register(ra)

                executors = []
                for address in ra.possible_values():
                    store = self.store.copy().with_path_constraint(ra == address)
                    address = address.as_integer()
                    value = self.store.get_register(rb)

                    store.set_byte(address + immediate,     value.slice(0, 7))
                    store.set_byte(address + immediate + 1, value.slice(8, 15))
                    store.set_byte(address + immediate + 2, value.slice(15, 23))
                    store.set_byte(address + immediate + 3, value.slice(24, 31))
                    store.set_byte(address + immediate + 4, value.slice(32, 39))
                    store.set_byte(address + immediate + 5, value.slice(40, 47))
                    store.set_byte(address + immediate + 6, value.slice(48, 55))
                    store.set_byte(address + immediate + 7, value.slice(56, 63))

                    executors.append(SingleExecutor(
                        self.program,
                        store,
                    ).advance())

                return BranchedExecutor(*executors)

            case Sw(ra, rb, immediate):
                ra = self.store.get_register(ra)

                executors = []
                for address in ra.possible_values():
                    store = self.store.copy().with_path_constraint(ra == address)
                    address = address.as_integer()
                    value = self.store.get_register(rb)

                    store.set_byte(address + immediate,     value.slice(0, 7))
                    store.set_byte(address + immediate + 1, value.slice(8, 15))
                    store.set_byte(address + immediate + 2, value.slice(15, 23))
                    store.set_byte(address + immediate + 3, value.slice(24, 31))

                    executors.append(SingleExecutor(
                        self.program,
                        store,
                    ).advance())

                return BranchedExecutor(*executors)
            case Sh(ra, rb, immediate):
                ra = self.store.get_register(ra)

                executors = []
                for address in ra.possible_values():
                    store = self.store.copy().with_path_constraint(ra == address)
                    address = address.as_integer()
                    value = self.store.get_register(rb)

                    store.set_byte(address + immediate,     value.slice(0, 7))
                    store.set_byte(address + immediate + 1, value.slice(8, 15))

                    executors.append(SingleExecutor(
                        self.program,
                        store,
                    ).advance())

                return BranchedExecutor(*executors)

            case Sb(ra, rb, immediate):
                ra = self.store.get_register(ra)

                executors = []
                for address in ra.possible_values():
                    store = self.store.copy().with_path_constraint(ra == address)
                    address = address.as_integer()
                    value = self.store.get_register(rb)

                    store.set_byte(address + immediate,     value.slice(0, 7))

                    executors.append(SingleExecutor(
                        self.program,
                        store,
                    ).advance())

                return BranchedExecutor(*executors)

            case Beq(ra, rb, immediate):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                return BranchedExecutor(
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra != rb),
                    ).advance(),
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra == rb),
                    ).jump_offset(immediate),
                )

            case Bneq(ra, rb, immediate):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                return BranchedExecutor(
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra == rb),
                    ).advance(),
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra != rb),
                    ).jump_offset(immediate),
                )

            case Blt(ra, rb, immediate):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                return BranchedExecutor(
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra.greater_than_or_eq(rb, True)),
                    ).advance(),
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra.less_than(rb, True)),
                    ).jump_offset(immediate),
                )

            case Bge(ra, rb, immediate):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                return BranchedExecutor(
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra.less_than(rb, True)),
                    ).advance(),
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra.greater_than_or_eq(rb, True)),
                    ).jump_offset(immediate),
                )

            case Bltu(ra, rb, immediate):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                return BranchedExecutor(
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra.greater_than_or_eq(rb, False)),
                    ).advance(),
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra.less_than(rb, False)),
                    ).jump_offset(immediate),
                )

            case Bgeu(ra, rb, immediate):
                ra = self.store.get_register(ra)
                rb = self.store.get_register(rb)

                return BranchedExecutor(
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra.less_than(rb, False)),
                    ).advance(),
                    SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra.greater_than_or_eq(rb, False)),
                    ).jump_offset(immediate),
                )

            case Jal(immediate, rdest):
                self.store.set_register(rdest, BitVector(self.store.get_pc(), 64) + BitVector(4, 64))
                return self.jump_offset(immediate)

            case Jalr(ra, immediate, rdest):
                self.store.set_register(rdest, BitVector(self.store.get_pc(), 64) + BitVector(4, 64))
                ra = self.store.get_register(ra)

                executors = []

                for address in ra.possible_values():
                    executors.append(SingleExecutor(
                        self.program,
                        self.store.copy().with_path_constraint(ra == address)
                    ).jump(immediate + address.as_integer()))

                return BranchedExecutor(*executors)

            case Lui(immediate, rdest):
                self.store.set_register(rdest, BitVector(immediate, 64))
                return self.advance()

            case Auipc(immediate, rdest):
                self.store.set_register(
                    rdest,
                    BitVector(immediate, 64) + BitVector(self.store.get_pc(), 64)
                )
                return self.advance()

            case a:
                raise InvalidInstruction(a)

        raise ShouldHaveReturned


class BranchedExecutor(Executor):
    executors: tuple[Executor, ...]

    def __init__(self, *executors: Executor, ststate=None, depth=0):
        super().__init__(ststate, depth)
        self.executors = executors

    def step(self) -> Executor:
        # noinspection PyTypeChecker
        self.executors = tuple((i.step() for i in self.executors))

        not_stopped = [i for i in self.executors if not isinstance(i, StoppedExecutor)]
        if len(not_stopped) == 0:
            return StoppedExecutor()
        elif len(not_stopped) == 1:
            return not_stopped[0]
        else:
            return self
