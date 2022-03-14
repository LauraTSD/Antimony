import unittest

from src.riscv.instructions import Addi, Jal
from src.riscv.parse import parse_instruction
from src.riscv.registers import RiscvRegister


class Test(unittest.TestCase):
    def test_parse_add(self):
        "addi sp, sp, -16"
        instr = parse_instruction(0xff010113)
        self.assertIsInstance(instr, Addi)
        self.assertEqual(instr.rdest, RiscvRegister.Sp)
        self.assertEqual(instr.ra, RiscvRegister.Sp)
        self.assertEqual(instr.immediate, -16)

    def test_parse_jal(self):
        "jal ra, 0x103e8"
        instr = parse_instruction(0x038000ef)
        self.assertIsInstance(instr, Jal)
        self.assertEqual(instr.rdest, RiscvRegister.Ra)
        self.assertEqual(instr.immediate, +56)  # offset

