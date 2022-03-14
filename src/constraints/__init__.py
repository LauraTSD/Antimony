from __future__ import annotations

from abc import abstractmethod, ABC
from typing import Iterator

import claripy


class Constraint(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def as_claripy_constraint(self) -> claripy.Base: ...
    @abstractmethod
    def possible_values(self) -> list[Value]: ...

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


class BooleanConstraint(Constraint):
    def boolean_and(self, other: BooleanConstraint):
        return And(self, other)

    def boolean_or(self, other: BooleanConstraint):
        return Or(self, other)

    def boolean_not(self):
        return Not(self)


class Value(Constraint, ABC):
    @abstractmethod
    def as_integer(self): ...


class BitVector(Value):
    def __init__(self, value: int, bits: int):
        super().__init__()

        self.value = value
        self.bits = bits

    def as_integer(self):
        return self.value

    def as_claripy_constraint(self) -> claripy.Base:
        pass

    def possible_values(self) -> Iterator[Value]:
        pass


class BoundedPointer(Value):
    def __init__(self, value: int):
        super().__init__()


class SymbolicBitVector(Constraint):
    def __init__(self, value: int, bits: int):
        super().__init__()

        self.value = value
        self.bits = bits

    def as_integer(self):
        return self.value

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

class ZeroExtend(Constraint):
    def __init__(self, inner: Constraint, bits: int):
        super().__init__()

        self.inner = inner
        self.bits = bits


class Slice(Constraint):
    def __init__(self, inner: Constraint, start: int, end: int):
        super().__init__()

        self.inner = inner
        self.start = start
        self.end = end


class Concat(Constraint):
    def __init__(self, *constraints: Constraint):
        super().__init__()

        self.constraints = constraints


class And(Constraint):
    def __init__(self, a: BooleanConstraint, b: BooleanConstraint):
        super().__init__()

        self.a = a
        self.b = b


class Or(Constraint):
    def __init__(self, a: BooleanConstraint, b: BooleanConstraint):
        super().__init__()

        self.a = a
        self.b = b


class Not(BooleanConstraint):
    def __init__(self, a: BooleanConstraint):
        super().__init__()

        self.a = a


class BitwiseXor(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b


class BitwiseAnd(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b


class BitwiseOr(BooleanConstraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b


class BitwiseNot(Constraint):
    def __init__(self, a: Constraint):
        super().__init__()

        self.a = a


class Add(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b


class Sub(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b


class ShiftLeft(Constraint):
    def __init__(self, a: Constraint, b: Constraint, arithmetic: bool):
        super().__init__()

        self.a = a
        self.b = b
        self.arithmetic = arithmetic


class ShiftRight(Constraint):
    def __init__(self, a: Constraint, b: Constraint, arithmetic: bool):
        super().__init__()

        self.a = a
        self.b = b
        self.arithmetic = arithmetic


class Eq(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b


class Neq(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b


class GreaterThan(BooleanConstraint):
    def __init__(self, a: Constraint, b: Constraint, signed=True):
        super().__init__()

        self.a = a
        self.b = b
        self.signed = signed


class LessThan(BooleanConstraint):
    def __init__(self, a: Constraint, b: Constraint, signed=True):
        super().__init__()

        self.a = a
        self.b = b
        self.signed = signed


