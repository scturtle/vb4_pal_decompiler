"""Tests for the parameter arity detector in word_disasm.py.

Style review #9 retired the old ByRef/ByVal classification: under the
all-reference call ABI a param slot always holds a pointer, so callee-side
I*/F* usage cannot determine the modifier (it only distinguishes
"dereference for the value" from "forward the pointer").  classify_params
now recovers the ARITY only; modifiers come from the call-site push-idiom
voting (pseudo_code.collect_param_votes, see test_style_fixes.py).

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

    def test_arity_from_indirect_and_direct_ops(self):
        # Arity = highest param slot; the old I*->ByRef / F*-only->ByVal
        # modifier split is retired (#9), kinds are uniformly ByRef.
        body = [
            ("ILdI2", "mem=stack+12"),
            ("FLdI4", "mem=stack+16"),
            ("IStI2", "mem=stack+12"),
            ("ILdI2", "mem=stack-134"),    # local, ignored
            ("FMemLdI2", "mem=stack+8.f0004"),  # Me base, excluded
        ]
        self.assertEqual(classify_params(body), (2, ["ByRef", "ByRef"]))

    def test_arity_from_direct_family(self):
        self.assertEqual(classify_params(ops(("FLdI2", 12), ("FLdI4", 16))),
                         (2, ["ByRef", "ByRef"]))

    def test_arity_from_ref_ops(self):
        self.assertEqual(classify_params(ops(("FLdRfVar", 12))),
                         (1, ["ByRef"]))
        self.assertEqual(classify_params(ops(("CVarRef", 12))),
                         (1, ["ByRef"]))

    def test_gap_slots(self):
        # nargs derived from highest slot; missing intermediates still count.
        self.assertEqual(classify_params(ops(("ILdI2", 12), ("FLdI2", 20))),
                         (3, ["ByRef", "ByRef", "ByRef"]))

    def test_me_base_excluded(self):
        body = ops(("FMemLdRf", 8), ("LitI2", 0))
        self.assertEqual(classify_params(body), (0, []))


if __name__ == "__main__":
    unittest.main(verbosity=2)
