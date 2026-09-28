"""Tests for the ByRef/ByVal parameter classifier in word_disasm.py.

Run:  .venv/bin/python -m pytest tests/test_byref_classify.py
  or:  .venv/bin/python tests/test_byref_classify.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from word_disasm import classify_params  # noqa: E402


def ops(*pairs):
    """Build (label, operand) pairs from (label, stack_offset) shorthand."""
    out = []
    for label, offset in pairs:
        if offset < 0:
            out.append((label, "mem=stack%d" % offset))
        elif offset == 8:
            out.append((label, "mem=stack+8.f0004"))  # Me base, not a param
        else:
            out.append((label, "mem=stack+%d" % offset))
    return out


class ClassifyParamsTest(unittest.TestCase):
    def test_no_params(self):
        body = ops(("LitI2", 0))  # no stack slot
        self.assertEqual(classify_params(body), (0, []))

    def test_indirect_ops_are_byref(self):
        # I* family dereferences through the slot pointer (VB40032 handlers).
        # PAL.EXE real pattern: params read via ILdI2 -> ByRef.
        body = [
            ("ILdI2", "mem=stack+12"),
            ("FLdI4", "mem=stack+16"),
            ("IStI2", "mem=stack+12"),
            ("ILdI2", "mem=stack-134"),    # local, ignored
            ("FMemLdI2", "mem=stack+8.f0004"),  # Me base, excluded
        ]
        # a0: ILdI2 + IStI2 (indirect) -> ByRef; a1: FLdI4 (direct) -> ByVal
        self.assertEqual(classify_params(body), (2, ["ByRef", "ByVal"]))

    def test_family_byval(self):
        # Only direct F* frame access => ByVal.
        body = ops(("FLdI2", 12), ("FLdI4", 16))
        self.assertEqual(classify_params(body), (2, ["ByVal", "ByVal"]))

    def test_ref_op_marks_byref(self):
        # A single PopTmpLdAd2 / FLdRfVar on the slot marks ByRef.
        body = ops(("FLdRfVar", 12))
        self.assertEqual(classify_params(body), (1, ["ByRef"]))
        body = ops(("CVarRef", 12))
        self.assertEqual(classify_params(body), (1, ["ByRef"]))

    def test_indirect_variants_byref(self):
        body = ops(("IStI4", 12), ("ILdI4", 12), ("ILdR8", 12))
        self.assertEqual(classify_params(body), (1, ["ByRef"]))

    def test_gap_slots(self):
        # nargs derived from highest slot; missing intermediate stays ByVal.
        body = ops(("ILdI2", 12), ("FLdI2", 20))
        self.assertEqual(classify_params(body),
                         (3, ["ByRef", "ByVal", "ByVal"]))

    def test_me_base_excluded(self):
        body = ops(("FMemLdRf", 8), ("LitI2", 0))
        self.assertEqual(classify_params(body), (0, []))


if __name__ == "__main__":
    unittest.main(verbosity=2)
