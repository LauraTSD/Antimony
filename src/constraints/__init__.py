from __future__ import annotations

from abc import abstractmethod, ABC

from typing import

import claripy


class Primitive(ABC):
    @abstractmethod
    def as_integer(self): ...


class BitVector(Primitive):
    def __init__(self, value: int, bits: int):
        pass


class BoundedPointer(Primitive):
    def __init__(self, value: int):
        pass


class Constraint(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def as_clairpy_constraint(self) -> claripy.Base: ...
    @abstractmethod
    def possible_values(self) -> list[Primitive]: ...

    def sign_extend(self, bits: int) -> Constraint:
        return SignExtend(self, bits)

    def zero_extend(self, bits: int) -> Constraint:
        return ZeroExtend(self, bits)

    def slice(self, start: int, stop: int):
        return Slice(self, start, stop)

    def concat(self, *others: Constraint):
        return Concat(self, *others)

    def __and__(self, other: Constraint):
        return And(self, other)

    def __or__(self, other: Constraint):
        return Or(self, other)

    def __invert__(self):
        return Not(self)

    def __add__(self, other: Constraint):
        return Add(self, other)

    def __sub__(self, other: Constraint):
        return Add(self, other)


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
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b

class Or(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b


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

class BitwiseOr(Constraint):
    def __init__(self, a: Constraint, b: Constraint):
        super().__init__()

        self.a = a
        self.b = b

class BitwiseNot(Constraint):
    def __init__(self, a: Constraint):
        super().__init__()

        self.a = a

class Not(Constraint):
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
