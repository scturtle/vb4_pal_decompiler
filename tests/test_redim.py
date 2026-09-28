"""Tests for Redim rendering in stack_ir.

VB4's Redim consumes 1 + dims*2 eval stack values: the array reference
(TOS) plus (lbound, ubound) per dimension.  Pop order (TOS first) is
array_ref, then the bounds in reverse push order.

Empirical anchor (pub_055 read_rng_subfile @00404D78, the only Redim in
this binary):  LitI4 0; FMemLdStr f0000; FMemLdRf f01F8; Redim dims=1 —
stack bottom→top = [0(lbound), tmp_file_size(ubound), rng_anim_data].

Rendered in VB source style: 'Redim arr(ubound)' when lbound is the
literal 0, else 'Redim arr(lbound To ubound)'.

Run:  .venv/bin/python -m unittest tests.test_redim -q
"""
import os
import sys
import unittest
from collections import namedtuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from stack_ir import StackMachine  # noqa: E402


Instr = namedtuple("Instr", "pos label operand")


def run(instrs):
    sm = StackMachine()
    sm.arg_map = {}
    for instr in instrs:
        sm.process(instr)
    sm.flush_leftovers(instrs[-1].pos if instrs else 0)
    return [s.text for s in sm.statements]


def redim1(lbound, ubound):
    """dims=1 Redim: push lbound, ubound, array_ref; then Redim."""
    return [
        Instr(0, "LitI2", "val=%s" % lbound),
        Instr(4, "LitI2", "val=%s" % ubound),
        Instr(8, "FLdRfVar", "mem=stack-134"),
        Instr(12, "Redim", "dims=1 desc=00000000 flags=0001,0000"),
    ]


class RedimTest(unittest.TestCase):
    def test_lbound_zero_renders_vb_style(self):
        # lbound=0: Redim rng_anim_data(tmp_file_size)
        out = run(redim1(0, "tmp_file_size"))
        self.assertEqual(out, ["Redim stack-134(tmp_file_size)"])

    def test_nonzero_lbound_renders_to_form(self):
        out = run(redim1(1, "N"))
        self.assertEqual(out, ["Redim stack-134(1 To N)"])

    def test_literal_bounds(self):
        out = run(redim1(0, "10"))
        self.assertEqual(out, ["Redim stack-134(10)"])

    def test_dims2_renders_both_dimensions(self):
        # dims=2: push (l1, u1, l2, u2, array_ref) per inferred order.
        ins = [
            Instr(0, "LitI2", "val=1"),
            Instr(4, "LitI2", "val=3"),
            Instr(8, "LitI2", "val=0"),
            Instr(12, "LitI2", "val=4"),
            Instr(16, "FLdRfVar", "mem=stack-134"),
            Instr(20, "Redim", "dims=2 desc=00000000 flags=0001,0000"),
        ]
        out = run(ins)
        # pop order: array_ref, u2, l2, u1, l1 -> dim1=(l1=1,u1=3), dim2=(l2=0,u2=4)
        self.assertEqual(out, ["Redim stack-134(1 To 3, 4)"])


if __name__ == "__main__":
    unittest.main()
