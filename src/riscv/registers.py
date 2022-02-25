from enum import Enum


class RiscvRegister(Enum):
    X0 = Zero = 0  # read only
    X1 = Ra = 1
    X2 = Sp = 2
    X3 = Gp = 3
    X4 = Tp = 4  # not used in the symbolic store
    X5 = T0 = 5
    X6 = T1 = 6
    X7 = T2 = 7
    X8 = S0 = Fp = 8
    X9 = S1 = 9
    X10 = A0 = 10
    X11 = A1 = 11
    X12 = A2 = 12
    X13 = A3 = 13
    X14 = A4 = 14
    X15 = A5 = 15
    X16 = A6 = 16
    X17 = A7 = 17
    X18 = S2 = 18
    X19 = S3 = 19
    X20 = S4 = 20
    X21 = S5 = 21
    X22 = S6 = 22
    X23 = S7 = 23
    X24 = S8 = 24
    X25 = S9 = 25
    X26 = S10 = 26
    X27 = S11 = 27
    X28 = T3 = 28
    X29 = T4 = 29
    X30 = T5 = 30
    X31 = T6 = 31
