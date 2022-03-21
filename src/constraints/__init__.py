from __future__ import annotations

import itertools
import math
from abc import abstractmethod, ABC
from typing import Iterator

import claripy

from src.address import Address
from src.riscv.parse import BitAccess


class Constraint(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def as_claripy_constraint(self) -> claripy.Base: ...
    @abstractmethod
    def possible_values(self) -> list[Value]: ...

    @abstractmethod
    def __repr__(self) -> str: ...

    def sign_extend(self, bits: int) -> Constraint:
        return SignExtend(self, bits)

    def zero_extend(self, bits: int) -> Constraint:
        return ZeroExtend(self, bits)

    def slice(self, start: int, stop: int):
        return Slice(self, start, stop)

    def concat(self, *others: Constraint):
        return Concat(self, *others)

    def __eq__(self, other) -> Constraint:
        return Eq(self, other)

    def __ne__(self, other) -> Constraint:
        return Neq(self, other)

    def greater_than(self, other, signed=True) -> BooleanConstraint:
        return GreaterThan(self, other, signed)

    def less_than(self, other, signed=True) -> BooleanConstraint:
        return LessThan(self, other, signed)

    def greater_than_or_eq(self, other, signed=True) -> BooleanConstraint:
        return self.less_than(other, signed).boolean_not()

    def less_than_or_eq(self, other, signed=True) -> Constraint:
        return self.greater_than(other, signed).boolean_not()

    def __lt__(self, other: Constraint) -> BooleanConstraint:
        return self.less_than(other, signed=True)

    def __gt__(self, other: Constraint) -> BooleanConstraint:
        return self.greater_than(other, signed=True)

    def __le__(self, other):
        return self.less_than_or_eq(other, signed=True)

    def __ge__(self, other):
        return self.greater_than_or_eq(other, signed=True)

    def __and__(self, other: Constraint):
        return BitwiseAnd(self, other)

    def __or__(self, other: Constraint):
        return BitwiseOr(self, other)

    def __xor__(self, other: Constraint):
        return BitwiseXor(self, other)

    def __invert__(self):
        return BitwiseNot(self)

    def __add__(self, other: Constraint) -> Constraint:
        return Add(self, other)

    def __sub__(self, other: Constraint) -> Constraint:
        return Sub(self, other)

    def shift_left(self, other: Constraint, arithmetic: bool = False) -> Constraint:
        return ShiftLeft(self, other, arithmetic)

    def shift_right(self, other: Constraint, arithmetic: bool = False) -> Constraint:
        return ShiftRight(self, other, arithmetic)


class BooleanConstraint(Constraint, ABC):
    def boolean_and(self, other: BooleanConstraint):
        return And(self, other)

    def boolean_or(self, other: BooleanConstraint):
        return Or(self, other)

    def boolean_not(self):
        return Not(self)


class Value(Constraint, ABC):
    @abstractmethod
    def as_integer(self): ...

    @abstractmethod
    def bits(self): ...

    def possible_values(self) -> list[Value]:
        return [self]


class BitVector(Value):
    def __init__(self, value: int, bits: int):
        super().__init__()

        self.value = value
        self._bits = bits

    def bits(self):
        return self._bits

    def as_integer(self):
        return self.value

    def as_claripy_constraint(self) -> claripy.Base:
        pass

    def __repr__(self):
        return ("bitvec(0x{:0" + f"{math.ceil(self._bits / 4)}" + "x})").format(self.value)


class BoundedPointer(Value):
    def __init__(self, value: Address, lower: Address, upper: Address):
        super().__init__()
        self.value = value
        self.lower = lower
        self.upper = upper

    def as_integer(self):
        return self.value

    def as_claripy_constraint(self) -> claripy.Base:
        pass

    def __repr__(self) -> str:
        return f"ptr(0x{self.value:08x}: [0x{self.lower:08x}:0x{self.upper:08x}))"

    def bits(self):
        return 64


class SymbolicBitVector(Constraint):
    def __init__(self, value: int, bits: int):
        super().__init__()

        self.value = value
        self._bits = bits

    def as_integer(self):
        return self.value

    def bits(self):
        return self._bits

    def as_claripy_constraint(self) -> claripy.Base:
        return claripy.BVS(self.value, self.bits)

    def possible_values(self) -> list[Value]:
        raise NotImplemented


class SymbolicBoundedPointer(Constraint):
    def __init__(self, value: int):
        super().__init__()


class SignExtend(Constraint):
    def __init__(self, inner: Constraint, bits: int):
        super().__init__()

        self.inner = inner
        self.bits = bits

    def __repr__(self) -> str:
        return f"sext({self.inner} to {self.bits} bits)"

    def as_claripy_constraint(self) -> claripy.Base:
        return claripy.SignExt(self.bits, self.inner.as_claripy_constraint())

    def possible_values(self) -> list[Value]:
        def sign_extend(value, bits):
            sign_bit = 1 << (bits - 1)
            return (value & (sign_bit - 1)) - (value & sign_bit)
        return [BitVector(sign_extend(i.as_integer(), self.bits), self.bits) for i in self.inner.possible_values()]



class ZeroExtend(Constraint):
    def __init__(self, inner: Constraint, bits: int):
        super().__init__()

        self.inner = inner
        self.bits = bits

    def as_claripy_constraint(self) -> claripy.Base:
        return claripy.ZeroExt(self.bits, self.inner.as_claripy_constraint())

    def possible_values(self) -> list[Value]:
        return [BitVector(i.as_integer(), self.bits) for i in self.inner.possible_values()]

    def __repr__(self) -> str:
        return f"zext({self.inner} to {self.bits} bits)"


class Slice(Constraint):
    def __init__(self, inner: Constraint, start: int, end: int):
        super().__init__()

        self.inner = inner
        self.start = start
        self.end = end

    def as_claripy_constraint(self) -> claripy.Base:
        return claripy.Extract(self.end, self.start, self.inner.as_claripy_constraint())

    def possible_values(self) -> list[Value]:
        return [
            BitVector(int(BitAccess(i.as_integer())[0:31]), self.end + 1 - self.start)
            for i in self.inner.possible_values()
        ]

    def __repr__(self) -> str:
        return f"{self.inner}[{self.start}:{self.end}]"


class Concat(Constraint):
    def __init__(self, *constraints: Constraint):
        super().__init__()

        self.constraints = constraints

    def __repr__(self) -> str:
        return f"concat({self.constraints})"


class And(Constraint):
    def __init__(self, a: BooleanConstraint, b: BooleanConstraint):
        super().__init__()

        self.a = a
        self.b = b

    def as_claripy_constraint(self) -> claripy.Base:
        return claripy.And(self.a.as_claripy_constraint(), self.b.as_claripy_constraint())

    def __repr__(self) -> str:
        return f"({self.a} and {self.b})"


class Or(Constraint):
    def __init__(self, a: BooleanConstraint, b: BooleanConstraint):
        super().__init__()

        self.a = a
        self.b = b

    def as_claripy_constraint(self) -> claripy.Base:
        return claripy.Or(self.a.as_claripy_constraint(), self.b.as_claripy_constraint())

    def possible_values(self) -> list[Value]:
        pass

    def __repr__(self) -> str:
        return f"({self.a} or {self.b})"


class Not(BooleanConstraint):
    def __init__(self, a: BooleanConstraint):
        super().__init__()

        self.a = a

    def as_claripy_constraint(self) -> claripy.Base:
        return claripy.Or(self.a.as_claripy_constraint(), self.b.as_claripy_constraint())

    def __repr__(self) -> str:
        return f"not({self.a})"


class BitwiseXor(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b

    def __repr__(self) -> str:
        return f"({self.a} ^ {self.b})"

    def as_claripy_constraint(self) -> claripy.Base:
        return self.a.as_claripy_constraint() ^ self.b.as_claripy_constraint()

    def possible_values(self) -> list[Value]:
        res = []

        for (x, y) in itertools.product(self.a.possible_values(), self.b.possible_values()):
            if x.bits() != y.bits():
                raise ValueError("bits not equal")

            res.append(BitVector(x.as_integer() ^ y.as_integer(), x.bits()))

        return res


class BitwiseAnd(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b

    def __repr__(self) -> str:
        return f"({self.a} & {self.b})"

    def as_claripy_constraint(self) -> claripy.Base:
        return self.a.as_claripy_constraint() & self.b.as_claripy_constraint()

    def possible_values(self) -> list[Value]:
        res = []

        for (x, y) in itertools.product(self.a.possible_values(), self.b.possible_values()):
            if x.bits() != y.bits():
                raise ValueError("bits not equal")

            res.append(BitVector(x.as_integer() & y.as_integer(), x.bits()))

        return res


class BitwiseOr(BooleanConstraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b

    def __repr__(self) -> str:
        return f"({self.a} | {self.b})"

    def as_claripy_constraint(self) -> claripy.Base:
        return self.a.as_claripy_constraint() | self.b.as_claripy_constraint()

    def possible_values(self) -> list[Value]:
        res = []

        for (x, y) in itertools.product(self.a.possible_values(), self.b.possible_values()):
            if x.bits() != y.bits():
                raise ValueError("bits not equal")

            res.append(BitVector(x.as_integer() | y.as_integer(), x.bits()))

        return res


class BitwiseNot(Constraint):
    def __init__(self, a: Constraint):
        super().__init__()

        self.a = a

    def __repr__(self) -> str:
        return f"~({self.a})"

    def as_claripy_constraint(self) -> claripy.Base:
        return ~self.a.as_claripy_constraint()

    def possible_values(self) -> list[Value]:
        return [BitVector(~x.as_integer(), x.bits()) for x in self.a.possible_values()]


class Add(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b

    def as_claripy_constraint(self) -> claripy.Base:
        return self.a.as_claripy_constraint() + self.b.as_claripy_constraint()

    def possible_values(self) -> list[Value]:
        res = []

        for (x, y) in itertools.product(self.a.possible_values(), self.b.possible_values()):
            if x.bits() != y.bits():
                raise ValueError("bits not equal")

            res.append(BitVector(x.as_integer() + y.as_integer(), x.bits()))

        return res

    def __repr__(self) -> str:
        return f"({self.a} + {self.b})"


class Sub(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b

    def as_claripy_constraint(self) -> claripy.Base:
        return self.a.as_claripy_constraint() - self.b.as_claripy_constraint()

    def possible_values(self) -> list[Value]:
        pass

    def __repr__(self) -> str:
        return f"({self.a} - {self.b})"


class ShiftLeft(Constraint):
    def __init__(self, a: Constraint, b: Constraint, arithmetic: bool):
        super().__init__()

        self.a = a
        self.b = b
        self.arithmetic = arithmetic

    def as_claripy_constraint(self) -> claripy.Base:
        if self.arithmetic:
            return self.a.as_claripy_constraint() << self.b.as_claripy_constraint()
        else:
            raise ValueError("logical shift left not supported")

    def possible_values(self) -> list[Value]:
        res = []

        for (x, y) in itertools.product(self.a.possible_values(), self.b.possible_values()):
            res.append(BitVector(x.as_integer() << y.as_integer(), x.bits()))

        return res

    def __repr__(self) -> str:
        return f"({self.a} << {self.b})"


class ShiftRight(Constraint):
    def __init__(self, a: Constraint, b: Constraint, arithmetic: bool):
        super().__init__()

        self.a = a
        self.b = b
        self.arithmetic = arithmetic

    def __repr__(self) -> str:
        return f"({self.a} >> {self.b})"


class Eq(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b

    def as_claripy_constraint(self) -> claripy.Base:
        return self.a.as_claripy_constraint() == self.b.as_claripy_constraint()

    def possible_values(self) -> list[Value]:
        pass

    def __repr__(self) -> str:
        return f"({self.a} == {self.b})"


class Neq(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b

    def as_claripy_constraint(self) -> claripy.Base:
        return self.a.as_claripy_constraint() != self.b.as_claripy_constraint()

    def __repr__(self) -> str:
        return f"({self.a} != {self.b})"


class GreaterThan(BooleanConstraint):
    def __init__(self, a: Constraint, b: Constraint, signed=True):
        super().__init__()

        self.a = a
        self.b = b
        self.signed = signed

    def as_claripy_constraint(self) -> claripy.Base:
        return self.a.as_claripy_constraint() > self.b.as_claripy_constraint()

    def __repr__(self) -> str:
        return f"({self.a} > {self.b})"


class LessThan(BooleanConstraint):
    def __init__(self, a: Constraint, b: Constraint, signed=True):
        super().__init__()

        self.a = a
        self.b = b
        self.signed = signed

    def as_claripy_constraint(self) -> claripy.Base:
        return self.a.as_claripy_constraint() < self.b.as_claripy_constraint()

    def __repr__(self) -> str:
        return f"({self.a} < {self.b})"


