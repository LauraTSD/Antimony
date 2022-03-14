import unittest

from src.riscv.instructions import Addi, Jal, Bneq, Lui
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

    def test_parse_bne(self):
        "bneq ra, rb, -4"
        instr = parse_instruction(0b1111111_00110_00111_001_11101_1100011)
        self.assertIsInstance(instr, Bneq)
        self.assertEqual(instr.immediate, -4)

    def test_parse_lui(self):
        "lui ra, 109231"
        "shift with 12 -> 447410176"
        instr = parse_instruction(0b00011010101010101111_00111_0110111)
        self.assertIsInstance(instr, Lui)
        self.assertEqual(instr.immediate, 447410176)