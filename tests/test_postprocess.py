"""Unit tests for pseudo_code._drop_empty_arms: the empty If/ElseIf
arm collapse (style pass; every rule is semantics-exact, see the
function docstring).  Statements are hand-built -- the pass is a pure
(stmts, label_at_stmt) -> (stmts, label_at_stmt) transform."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pseudo_code


class _S(object):
    """Minimal Stmt stand-in: (va, indent_delta, text)."""

    def __init__(self, va, delta, text, order=0):
        self.va = va
        self.indent_delta = delta
        self.text = text
        self.order = order


def _run(stmts, labels=None):
    new_stmts, new_labels = pseudo_code._drop_empty_arms(
        stmts, labels or {})
    return ([s.text for s in new_stmts], new_labels)


class DropEmptyArmsTest(unittest.TestCase):
    def test_bare_else_dropped(self):
        # Rule 1: "Else" directly before "End If" is dead.
        texts, _ = _run([
            _S(0x1000, +1, "If Me.f0004 = 1 Then"),
            _S(0x1002, 0, "stack-100 = 10"),
            _S(0x1004, 0, "Else"),
            _S(0x1006, -1, "End If"),
        ])
        self.assertEqual(texts, [
            "If Me.f0004 = 1 Then",
            "stack-100 = 10",
            "End If",
        ])

    def test_label_on_dropped_else_moves_to_next_stmt(self):
        texts, labels = _run([
            _S(0x1000, +1, "If Me.f0004 = 1 Then"),
            _S(0x1002, 0, "Else"),
            _S(0x1004, -1, "End If"),
            _S(0x1006, 0, "Exit Sub"),
        ], {1: [0x1234]})
        self.assertNotIn("Else", texts)
        # the jump to L_00001234 must still land (on the End If)
        self.assertEqual(labels, {1: [0x1234]})

    def test_empty_then_inverted(self):
        # Rule 2: "If c Then / Else <body>" -> "If Not (c) Then <body>".
        texts, _ = _run([
            _S(0x1000, +1, "If Me.f0004 = 1 Then"),
            _S(0x1002, 0, "Else"),
            _S(0x1004, 0, "stack-100 = 10"),
            _S(0x1006, -1, "End If"),
        ])
        self.assertEqual(texts, [
            "If Me.f0004 <> 1 Then",
            "stack-100 = 10",
            "End If",
        ])

    def test_empty_then_double_negation_collapses(self):
        # _wrap_not unwraps: "If Not (x) Then / Else <body>" -> "If x".
        texts, _ = _run([
            _S(0x1000, +1, "If Not (stack-138) Then"),
            _S(0x1002, 0, "Else"),
            _S(0x1004, 0, "stack-100 = 10"),
            _S(0x1006, -1, "End If"),
        ])
        self.assertEqual(texts[0], "If stack-138 Then")

    def test_ladder_all_arms_empty_collapses_to_conjunction(self):
        # Rule 3: pub_196's f06C4 shape.
        texts, _ = _run([
            _S(0x1000, +1, "If Me.f0004 = 2 Then"),
            _S(0x1008, 0, "ElseIf Me.f0004 = 1 Then"),
            _S(0x1010, 0, "Else"),
            _S(0x1012, 0, "stack-100 = 10"),
            _S(0x1014, -1, "End If"),
        ])
        self.assertEqual(texts, [
            "If (Me.f0004 <> 2) And (Me.f0004 <> 1) Then",
            "stack-100 = 10",
            "End If",
        ])

    def test_nested_if_is_not_a_ladder_leg(self):
        # A bare "If" right after an opener is the first statement of the
        # previous leg's then-arm (pub_196's Or-guard wraps the f06C4
        # ladder this way) -- it must NOT extend the ladder, or the outer
        # condition's polarity would be flipped into the conjunction.
        texts, _ = _run([
            _S(0x1000, +1, "If (Me.f0004 = 9) Or (Me.f0004 = 4) Then"),
            _S(0x1004, +1, "If Me.f0004 = 2 Then"),
            _S(0x100C, 0, "ElseIf Me.f0004 = 1 Then"),
            _S(0x1014, 0, "Else"),
            _S(0x1016, 0, "stack-100 = 10"),
            _S(0x1018, -1, "End If"),
            _S(0x101A, -1, "End If"),
        ])
        # outer guard untouched; inner ladder collapsed in place
        self.assertEqual(texts, [
            "If (Me.f0004 = 9) Or (Me.f0004 = 4) Then",
            "If (Me.f0004 <> 2) And (Me.f0004 <> 1) Then",
            "stack-100 = 10",
            "End If",
            "End If",
        ])

    def test_nonempty_arm_not_touched(self):
        # An If with content in the Then arm keeps its Else (whatever
        # the Else holds).
        texts, _ = _run([
            _S(0x1000, +1, "If Me.f0004 = 1 Then"),
            _S(0x1002, 0, "stack-100 = 10"),
            _S(0x1004, 0, "Else"),
            _S(0x1006, 0, "stack-100 = 20"),
            _S(0x1008, -1, "End If"),
        ])
        self.assertEqual(texts, [
            "If Me.f0004 = 1 Then",
            "stack-100 = 10",
            "Else",
            "stack-100 = 20",
            "End If",
        ])

    def test_ladder_with_content_arm_not_collapsed(self):
        # Rule 3 needs EVERY Then/ElseIf arm empty; a content arm
        # between legs breaks adjacency and blocks the collapse.
        texts, _ = _run([
            _S(0x1000, +1, "If Me.f0004 = 2 Then"),
            _S(0x1004, 0, "stack-100 = 5"),
            _S(0x1008, 0, "ElseIf Me.f0004 = 1 Then"),
            _S(0x1010, 0, "Else"),
            _S(0x1012, 0, "stack-100 = 10"),
            _S(0x1014, -1, "End If"),
        ])
        self.assertEqual(len(texts), 6)   # untouched


if __name__ == "__main__":
    unittest.main()
