import unittest

from src.program import Program, Symbol


class Test(unittest.TestCase):
    def test_find_entry(self):
        program = Program.from_c_file("../example_programs/from_paper.c", debug=True)
        self.assertIsNotNone(program.entry_point())

    def test_find_symbol(self):
        program = Program.from_c_string("int main(){}", debug=True)
        self.assertIsNotNone(program.address_of_symbol(Symbol("main")))

    def test_first_instr(self):
        program = Program.from_c_string("int main(){ return 1; }", debug=True)
        entry = program.entry_point()
        print(program.get_instruction_bytes(entry))
        """
        │   0x1048c <main>                  addi    sp,sp,-16                          │
        │   0x10490 <main+4>                sd      s0,8(sp)                           │
        │   0x10494 <main+8>                addi    s0,sp,16                           │
        │   0x10498 <main+12>               li      a5,1                               │
        │   0x1049c <main+16>               mv      a0,a5                              │
        │   0x104a0 <main+20>               ld      s0,8(sp)                           │
        │   0x104a4 <main+24>               addi    sp,sp,16                           │
        │   0x104a8 <main+28>               ret                                        │
        """