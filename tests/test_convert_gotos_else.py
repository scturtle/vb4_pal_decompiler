"""Tests for _convert_gotos pattern-2 (GoTo/End If → Else) convergence guard.

Run:  .venv/bin/python -m pytest tests/test_convert_gotos_else.py
  or:  .venv/bin/python tests/test_convert_gotos_else.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import stack_ir        # noqa: E402
from pseudo_code import _convert_gotos  # noqa: E402


def S(va, delta, text, order):
    return stack_ir.Stmt(va, delta, text, order)


def texts(stmts):
    return [s.text for s in stmts]


# VAs mimic the real Sub_Main shape @0041AFA4-0041B10A:
#   outer If (BranchF→else_block) / inner If with Then-GoTo into the
#   outer Else / false path ends with GoTo to the join.
INNER_IF = 0x0041AFB4
INNER_GOTO = 0x0041AFB8        # Branch → else block start
INNER_ENDIF = 0x0041AFBC
FALSE_TAIL = 0x0041AFC6
THEN_EXIT = 0x0041AFCC          # Branch → join (outer Then end)
OUTER_ENDIF = 0x0041AFD0        # == inner GoTo target (Else block start)
ELSE_BODY = 0x0041B006
JOIN = 0x0041B10E


def goto_else_shape():
    """Raw stack_ir form of the Sub_Main save-load site before conversion."""
    stmts = [
        S(0x0041AF7A, +1, "If comTmp3 = 1 Then", 0),
        S(INNER_IF, +1, "If RPG_save_number = 0 Then", 1),
        S(INNER_GOTO, 0, "GoTo L_%08X" % OUTER_ENDIF, 2),
        S(INNER_ENDIF, -1, "End If", 3),
        S(FALSE_TAIL, 0, "redraw_flag = redraw_flag Or 2", 4),
        S(THEN_EXIT, 0, "GoTo L_%08X" % JOIN, 5),
        S(OUTER_ENDIF, -1, "End If", 6),
        S(ELSE_BODY, 0, "Call PlayAvi(3)", 7),
        S(JOIN, 0, "scrollStepX = 16", 8),
    ]
    # Labels: inner GoTo targets the outer End If (= Else block start,
    # the BranchF merge point of the outer If); the outer Then-exit GoTo
    # targets the join.  Both get labels, matching decompile_proc.
    label_at_stmt = {6: [OUTER_ENDIF], 8: [JOIN]}
    return stmts, label_at_stmt


class ConvertGotosElseTest(unittest.TestCase):
    def run_convert(self, stmts, labels):
        return _convert_gotos(stmts, labels, 0x0041AE00, 0x0041B400)

    def test_goto_into_enclosing_else_is_kept(self):
        # The would-be false branch ends with GoTo to a DIFFERENT target
        # (the join), so control never falls through to the Then's label.
        # Folding it into Else/End If would reroute the true path into the
        # false branch — the GoTo must survive (Sub_Main @0041AFB8).
        stmts, labels = goto_else_shape()
        out, out_labels = self.run_convert(stmts, labels)
        self.assertIn("GoTo L_%08X" % OUTER_ENDIF, texts(out))
        # The outer If/Else conversion (Then ends with GoTo to the join,
        # false branch falls through to it) is still performed, and the
        # inner GoTo's label survives on the Else marker statement.
        out_texts = texts(out)
        self.assertIn("Else", out_texts)
        self.assertIn("End If", out_texts)
        self.assertEqual(out_labels.get(out_texts.index("Else")),
                         [OUTER_ENDIF])

    def test_genuine_if_else_still_converted(self):
        # Classic shape: false branch falls through to the label → fold.
        stmts = [
            S(0x1000, +1, "If A Then", 0),
            S(0x1004, 0, "GoTo L_00001010", 1),
            S(0x1008, -1, "End If", 2),
            S(0x100A, 0, "B = 1", 3),
            S(0x1010, 0, "C = 2", 4),
        ]
        labels = {4: [0x1010]}
        out, out_labels = self.run_convert(stmts, labels)
        self.assertNotIn("GoTo L_00001010", texts(out))
        self.assertIn("Else", texts(out))
        # Label removed together with the fold.
        self.assertNotIn(4, out_labels)

    def test_false_branch_ending_exit_sub_is_kept(self):
        # False path leaves the proc before the label: not a join.
        stmts = [
            S(0x3000, +1, "If A Then", 0),
            S(0x3004, 0, "GoTo L_00003010", 1),
            S(0x3008, -1, "End If", 2),
            S(0x300A, 0, "B = 1", 3),
            S(0x300C, 0, "Exit Sub", 4),
            S(0x3010, 0, "C = 2", 5),
        ]
        labels = {5: [0x3010]}
        out, out_labels = self.run_convert(stmts, labels)
        self.assertIn("GoTo L_00003010", texts(out))
        self.assertNotIn("Else", texts(out))

    def test_false_branch_ending_end_is_kept(self):
        # Sub_Main @0041A992: retry-check If — false path runs End.
        stmts = [
            S(0x4000, +1, "If A Then", 0),
            S(0x4004, 0, "GoTo L_00004010", 1),
            S(0x4008, -1, "End If", 2),
            S(0x400A, 0, "End", 3),
            S(0x4010, 0, "C = 2", 4),
        ]
        labels = {4: [0x4010]}
        out, out_labels = self.run_convert(stmts, labels)
        self.assertIn("GoTo L_00004010", texts(out))
        self.assertNotIn("Else", texts(out))


if __name__ == "__main__":
    unittest.main()
