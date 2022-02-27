import unittest
from src.program import Program


class Test(unittest.TestCase):
    def test_example_from_paper(self):
        program = Program.from_c_file("../example_programs/from_paper.c")

