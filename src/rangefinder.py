from __future__ import annotations

import os
import claripy

class RangeFinder:
    variable: int
    constraints: List[Constraint]
    num_values = 100

    def __init__(self, variable=None, constraints=None):
        self.variable = variable
        self.constraints = constraints

    def find_values(self):
        s = claripy.Solver()
        num_values = 100

        for cons in self.constraints:
            s.add(cons)

        print(s.eval(self.variable, num_values))


a = claripy.BVS("sym_val", 32)
c1 = a < 40
c2 = a > 30
r = RangeFinder(a,  [c1, c2])
r.find_values()