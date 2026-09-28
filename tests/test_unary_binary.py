"""Tests for unary/binary operator rendering in stack_ir.

Binary ops always build "(a <op> b)" (one paren pair per tree node) and
stores strip exactly one redundant outer pair.  Unary minus (UMi*) negates
the whole popped operand, so a compound operand must be re-parenthesized
when the stripped text exposes a depth-0 infix operator: in VB a prefix
minus binds tighter than + - * / \\ Mod and the logical/comparison
operators, so "-a + b" would read as "(-a) + b", not "-(a + b)".

Empirical anchors (real PAL.EXE sites):
  * 0041946E enemy_physical_attack:
      FLdI2 hitChance; LitI2 10; AddI2; UMiI2  ->  rngVal = -(hitChance + 10)
    (was rendered "-hitChance + 10" before the fix).
  * 0040D1CC / 0040D210 redraw_tile:
      tileX; 32; ModI2; UMiI2; 16; SubI2
      ->  xPixelOffset = -(tileX Mod 32) - 16
  * 004193AA rtcRandomNext * 0.85:
      UMiR8 over a call result then MulR8 -> -Rnd() * 0.85 (no parens:
      prefix minus already binds tighter than *).

Run:  .venv/bin/python -m unittest tests.test_unary_binary -q
  or: .venv/bin/python tests/test_unary_binary.py
"""
import os
import sys
import unittest
from collections import namedtuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from stack_ir import StackMachine, _has_top_level_binary_op  # noqa: E402


Instr = namedtuple("Instr", "pos label operand")

PARAM_MAP = {8: "Me", 12: "a0", 16: "a1", 20: "a2"}


def run(instrs, param_map=None, arg_map=None):
    sm = StackMachine()
    sm.param_map = dict(param_map or PARAM_MAP)
    sm.arg_map = arg_map or {}
    for instr in instrs:
        sm.process(instr)
    sm.flush_leftovers(instrs[-1].pos if instrs else 0)
    return [s.text for s in sm.statements]


def ld(i, off):
    """ILdI2 of a named ByRef param (param_map names stack+off)."""
    return Instr(4 * i, "ILdI2", "mem=stack+%d" % off)


def lit(i, val):
    return Instr(4 * i, "LitI2", "val=%s" % val)


def op(i, label):
    return Instr(4 * i, label, "-")


def store():
    return Instr(0xFFC, "FStI2", "mem=stack-100")


class UnaryMinusTest(unittest.TestCase):
    """UMi* negates the whole popped operand tree."""

    def test_negate_literal(self):
        self.assertEqual(run([lit(0, 1), op(1, "UMiI2"), store()]),
                         ["stack-100 = -1"])

    def test_negate_simple_var_no_parens(self):
        self.assertEqual(run([ld(0, 12), op(1, "UMiI2"), store()]),
                         ["stack-100 = -a0"])

    def test_negate_add_result(self):
        # Real anchor: enemy_physical_attack @0041946E.
        self.assertEqual(
            run([ld(0, 12), lit(1, 10), op(2, "AddI2"), op(3, "UMiI2"),
                 store()]),
            ["stack-100 = -(a0 + 10)"])

    def test_negate_mod_result_feeding_sub(self):
        # Real anchor: redraw_tile @0040D1CC.
        self.assertEqual(
            run([ld(0, 12), lit(1, 32), op(2, "ModI2"), op(3, "UMiI2"),
                 lit(4, 16), op(5, "SubI2"), store()]),
            ["stack-100 = -(a0 Mod 32) - 16"])

    def test_negate_chained_compound(self):
        # ((a0 + a1) * a2) negated: strip exposes "(a0 + a1) * a2" whose
        # depth-0 " * " forces outer parens around everything.
        self.assertEqual(
            run([ld(0, 12), ld(1, 16), op(2, "AddI2"), ld(3, 20),
                 op(4, "MulI2"), op(5, "UMiI2"), store()]),
            ["stack-100 = -((a0 + a1) * a2)"])

    def test_negate_preserves_inner_grouping(self):
        # ((a0 - a1) + a2) negated keeps the inner "(a0 - a1)" pair.
        self.assertEqual(
            run([ld(0, 12), ld(1, 16), op(2, "SubI2"), ld(3, 20),
                 op(4, "AddI2"), op(5, "UMiI2"), store()]),
            ["stack-100 = -((a0 - a1) + a2)"])

    def test_negate_call_result_no_parens(self):
        # Call text "Pal.Foo()" has balanced parens and no depth-0 op.
        out = run([Instr(0, "ImpAdCall", "call=Pal.Foo@0"), op(1, "UMiI2"),
                   store()],
                  arg_map={"Pal.Foo": 0})
        self.assertEqual(out, ["stack-100 = -Pal.Foo()"])

    def test_negate_array_element_no_parens(self):
        self.assertEqual(
            run([ld(0, 12),
                 Instr(1 * 4, "FMemLdRf", "mem=stack+8.f04DC"),
                 op(2, "Ary1LdRf"), op(3, "UMiI2"), store()]),
            ["stack-100 = -Me.f04DC(a0)"])

    def test_negated_operand_feeding_binary_mul(self):
        # p-code: push a; UMi; push b; Mul  ==  (-a) * b.  Rendered
        # "-a0 * a1", which VB parses as (-a0) * a1 -- correct without
        # extra parens because prefix minus binds tighter than *.
        self.assertEqual(
            run([ld(0, 12), op(1, "UMiI2"), ld(2, 16), op(3, "MulI2"),
                 store()]),
            ["stack-100 = -a0 * a1"])

    def test_negate_real_rnd_times_frac(self):
        # Real anchor: enemy_physical_attack @004193AA.
        #   LitVar_Missing; ImpAdCall rtcRandomNext; UMiR8;
        #   LitDate 0.85; MulR8; CI2R8; FStI2
        # ->  rngVal = -VB40032.rtcRandomNext() * 0.85
        out = run(
            [Instr(0x00, "LitVar_Missing", "mem=stack-168"),
             Instr(0x04, "ImpAdCall",
                   "call=VB40032.rtcRandomNext@0040100C"),
             Instr(0x08, "UMiR8", "-"),
             Instr(0x0C, "LitDate", "val=0.85"),
             Instr(0x10, "MulR8", "-"),
             Instr(0x14, "CI2R8", "-"),
             Instr(0x18, "FStI2", "mem=stack-100")],
            arg_map={"VB40032.rtcRandomNext": 1})
        self.assertEqual(out, ["stack-100 = -VB40032.rtcRandomNext() * 0.85"])

    def test_negate_comparison_result(self):
        # Synthetic but per the rendering contract: the whole comparison
        # "(a0 = 3)" is the negated operand tree.
        self.assertEqual(
            run([ld(0, 12), lit(1, 3), op(2, "EqI2"), op(3, "UMiI2"),
                 store()]),
            ["stack-100 = -(a0 = 3)"])

    def test_all_umi_labels_render_minus(self):
        for label in ("UMiI2", "UMiI4", "UMiR4", "UMiR8", "UMiUI1"):
            self.assertEqual(run([lit(0, 1), op(1, label), store()]),
                             ["stack-100 = -1"], label)


class UnaryOtherTest(unittest.TestCase):
    """Non-minus unary ops render "op (x)"."""

    def test_not_simple(self):
        self.assertEqual(run([ld(0, 12), op(1, "NotI2"), store()]),
                         ["stack-100 = Not (a0)"])

    def test_not_over_binary(self):
        self.assertEqual(
            run([ld(0, 12), lit(1, 1), op(2, "AndI2"), op(3, "NotI2"),
                 store()]),
            ["stack-100 = Not (a0 And 1)"])

    def test_fn_abs(self):
        self.assertEqual(run([ld(0, 12), op(1, "FnAbsI2"), store()]),
                         ["stack-100 = Abs (a0)"])


class BinaryOpTest(unittest.TestCase):
    """Every binary op table entry renders "(a <sym> b)"; stores strip the
    single redundant outer pair."""

    OPS = [
        ("AddI2", "+"), ("SubI2", "-"), ("MulI2", "*"), ("DivR4", "/"),
        ("IDvI2", "\\"), ("ModI2", "Mod"), ("ConcatStr", "&"),
        ("AndI4", "And"), ("OrI2", "Or"), ("XorI2", "Xor"),
        ("EqI2", "="), ("NeI2", "<>"), ("LtI2", "<"), ("LeI2", "<="),
        ("GtI2", ">"), ("GeI2", ">="),
    ]

    def test_op_table_symbols(self):
        for label, sym in self.OPS:
            self.assertEqual(
                run([ld(0, 12), ld(1, 16), op(2, label), store()]),
                ["stack-100 = a0 %s a1" % sym], label)

    def test_chain_strips_exactly_one_outer_pair(self):
        # ((a0 + (a1 * a2))) stored: inner "(a1 * a2)" keeps its parens,
        # only the outermost redundant pair is stripped.
        self.assertEqual(
            run([ld(0, 12), ld(1, 16), ld(2, 20), op(3, "MulI2"),
                 op(4, "AddI2"), store()]),
            ["stack-100 = a0 + (a1 * a2)"])

    def test_transparent_conversion_keeps_text(self):
        # CI4I2 is a no-op conversion: the operand text is unchanged, so
        # AddI4 folds directly over the named param.
        self.assertEqual(
            run([ld(0, 12), op(1, "CI4I2"),
                 Instr(8, "LitI4", "val=0"), op(3, "AddI4"), store()]),
            ["stack-100 = a0 + 0"])


class NegScannerUnitTest(unittest.TestCase):
    """Depth-0 contract of _has_top_level_binary_op.

    It only ever sees text produced by this module's own builders, where
    binary ops are rendered space-padded ("a + b") and calls/arrays use
    balanced parens.
    """

    def test_depth0_ops_detected(self):
        for text in ("a + b", "a - b", "a * b", "a / b", "a \\ b",
                     "a Mod b", "a And b", "a Or b", "a Xor b", "a & b",
                     "a = b", "a <> b", "a <= b", "x < y"):
            self.assertTrue(_has_top_level_binary_op(text), text)

    def test_parenthesized_or_simple_not_detected(self):
        for text in ("a", "-x", "(a + b)", "f(a, b)", "a(0)",
                     "Me.f04DC(i)", "-(a + b)"):
            self.assertFalse(_has_top_level_binary_op(text), text)

    def test_nested_depth_only(self):
        # "(a + b) * c": the " + " sits at depth 1 and must not match,
        # the " * " sits at depth 0 and must match.
        self.assertTrue(_has_top_level_binary_op("(a + b) * c"))
        # Fully grouped text has no depth-0 op left.
        self.assertFalse(_has_top_level_binary_op("((a + b) * (c + d))"))


if __name__ == "__main__":
    unittest.main()
