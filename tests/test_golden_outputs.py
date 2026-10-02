"""Golden-invariant checks on the committed CFG output.

These guard the specific semantic fixes to pub_167 / pub_186 / pub_196 / pub_197
against regressions in the real pipeline output (out/pal_pseudocode.txt).
They are fast (read the committed file, no re-run) and complementary to
the hash gate in input/output_hashes.json.

Run: .venv/bin/python -m unittest discover -s tests -q
"""
import os
import re
import unittest

OUT = os.path.join(os.path.dirname(__file__), "..", "out", "pal_pseudocode.txt")


def split_procs(path):
    """Split the pseudocode file on top-level Sub/Function headers."""
    procs = {}
    cur = None
    with open(path) as fh:
        for line in fh:
            m = re.match(r'^(?:Private )?(?:Sub|Function)\s+(\S+?)\(', line)
            if m:
                cur = m.group(1)
                procs[cur] = []
            if cur is not None:
                procs[cur].append(line)
    return procs


@unittest.skipUnless(os.path.exists(OUT), "out/pal_pseudocode.txt not present")
class GoldenFixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.procs = split_procs(OUT)

    def _proc(self, name):
        self.assertIn(name, self.procs, "proc %s missing from golden output" % name)
        return "".join(self.procs[name])

    # ---- pub_197: cross-leg GoTos into shared bodies survive ------------
    def test_pub197_cross_leg_gotos_survive(self):
        text = self._proc("pub_197_00420FC0")
        for target in ("L_00421140", "L_00423634", "L_004234FA", "L_00425278"):
            self.assertIn("GoTo %s" % target, text)
            # every GoTo target is emitted as a label at least once
            self.assertIn("%s:" % target, text)
        # the shared body's exit path is emitted
        self.assertIn("Exit Sub", text)

    # ---- pub_196 finding 1: else-arm void call not leaked to join -------
    def test_pub196_else_arm_call_inside_arm(self):
        text = self._proc("pub_196_0041D56C")
        # the sum!=0 else arm owns the hot call; it must not be rendered
        # as a common tail that also executes on the skipped paths.
        self.assertGreaterEqual(text.count("Call pub_164_0040F58C_hot(4, 0)"), 1)
        # the first occurrence sits between the f06C4(...4) test's Else and
        # the closing End If (the finding-1 else-arm, not a shared tail).
        idx = text.index("Call pub_164_0040F58C_hot(4, 0)")
        before = text[:idx]
        self.assertIn("(Me.f06C4(Me.f02C2, 1).f0000", before)

    # ---- pub_196 finding 2: L_0041EAAA labels the comparison, not the call
    def test_pub196_label_targets_comparison_not_call(self):
        text = self._proc("pub_196_0041D56C")
        # the two calls come before the label
        self.assertIn("Call pub_017_004037C4(", text)
        self.assertIn("L_0041EAAA:", text)
        self.assertLess(text.index("Call pub_017_004037C4("),
                        text.index("L_0041EAAA:"))
        # the label sits on the comparison (If Not ...) that follows.
        after = text[text.index("L_0041EAAA:"):]
        self.assertIn("If Me.f02C2 >= Me.f02D8 Then", after)

    # ---- pub_186: stack-198 = 1 restarts the OUTER loop -----------------
    def test_pub186_outer_restart_goto_survives_fold(self):
        text = self._proc("pub_186_00415B1C")
        # p-code 004160EC EqUI1 (m = 1); BranchF->004160F6 (m<>1 ->
        # epilogue); fall 004160F2 Branch->00415B1C (m=1 restarts the
        # OUTER loop).  That trampoline is the outer loop's latch — a
        # stop-set member — so the leaving-side fold once dropped its
        # GoTo and the m=1 path fell through to the innermost Loop
        # (wrong re-entry).  It must render as an explicit outer jump.
        #
        # The dispatch ladder flattens to Select Case (structural
        # chain, flavor B); the default leg jumps out-of-line to the
        # m = 1 test, so both edges must stay explicit THERE.
        flat = " ".join(text.split())
        self.assertIn("Case Else", flat)
        self.assertIn("GoTo L_004160E6", flat)
        after = " ".join(text[text.index("L_004160E6:"):].split())
        self.assertIn("If stack-198 <> 1 Then GoTo L_004160F6 "
                      "End If", after)
        # #18: the m = 1 dispatch test region renders INSIDE the outer
        # loop, address-ordered before the Loop close -- its fall-through
        # IS the loop's own backedge, so the explicit GoTo L_004160F2 and
        # the label are gone (the fold that once dropped it needed the
        # trampoline visible; the interior placement makes the edge the
        # Loop closer itself).
        self.assertEqual(after, "L_004160E6: If stack-198 <> 1 Then "
                         "GoTo L_004160F6 End If Loop End Sub")
        self.assertNotIn("L_004160F2", text)
        self.assertIn("L_004160F6:", text)
        # Nothing jumps the header directly, so the header needs no label.
        self.assertNotIn("L_00415B1C:", text)

    # ---- pub_167: case-9 join-exit fold polarity -------------------------
    def test_pub167_case9_fold_polarity(self):
        text = self._proc("pub_167_0040FF88")
        # p-code 0041027E LtI2 (f001E < stack-140); BranchF->0041028C
        # runs f001E=0 then joins 004102CE when the compare is FALSE;
        # the fall-through Branch->004102DC (ExitProcStr) exits when it
        # is TRUE.  The fold's Then arm is the BranchF-taken side, so it
        # must carry Not(...) — the old code inverted the two arms.
        # (The 004102CE edge now renders Exit Do — the post-latch
        # tramp-chain resolution hoists the shared advance-and-return
        # tail after the Loop; the polarity guard is unchanged.)
        flat = " ".join(text.split())
        self.assertIn("If Me.f07DC(a0).f001E >= stack-140 Then "
                      "Me.f07DC(a0).f001E = 0 Exit Do End If "
                      "Exit Sub", flat)
        # the shared tail renders once after the Loop, label-free; the
        # trailing Exit Sub is dropped at the implicit proc exit (#18:
        # it used to survive because the dangling unreachable marker
        # sat between it and End Sub)
        self.assertIn("Loop a1 = pub_009_0040345C(a1) End Sub", flat)
        self.assertNotIn("unreachable", flat)
        self.assertNotIn("L_004102CE", flat)

    # ---- pub_137: local diamond join folds after the End If --------
    def test_pub137_local_diamond_join_not_absorbed_into_else(self):
        # p-code 0040AFF6 BranchF->0040B018 (stack-144<>0 -> else);
        # the then side's 0040B00C BranchF->0040B014 trampoline Branches
        # to the merge 0040B020, while the else side (stack-146 =
        # stack-136) falls straight onto it.  Loop-top exits hide the
        # merge from compute_ipost (mid-body Exit Sub paths bypass it),
        # so the open-If/Else fallback used to absorb the merge into
        # the else arm and render the then side as a forward
        # "GoTo L_0040B020" into that arm's middle.  The local diamond
        # join now stops both arms at the merge and continues after
        # the End If: no label, no forward GoTo, the For loop sits at
        # the Do-body level.
        text = self._proc("pub_137_0040AF48")
        self.assertNotIn("L_0040B020", text)
        self.assertNotIn("GoTo L_0040B020", text)
        # The restart back edge renders as Continue Do (single-level
        # jump to the bare-latch Do's header): its label is gone too.
        self.assertNotIn("L_0040AF7C", text)
        flat = " ".join(text.split())
        self.assertIn(
            "If stack-144 = 0 Then "
            "stack-146 = pub_131_0040A344() "
            "If stack-146 < 0 Then Continue Do End If "
            "Else "
            "stack-146 = stack-136 "
            "End If "
            "For stack-148 = 0 To Me.f0266", flat)

    # ---- pub_102: proc-exit inside a loop renders Exit Sub, not Exit For
    def test_pub102_proc_exit_is_Exit_Sub_not_Exit_For(self):
        # The p-code branches to ExitProcStr (proc return) from inside the
        # second For loop; a naive renderer emitted Exit For (which would
        # wrongly continue after the loop under linear semantics).
        text = self._proc("pub_102_00407940")
        self.assertNotIn("Exit For", text)
        self.assertIn("Exit Sub", text)

    # ---- empty If/ElseIf arm collapse (_drop_empty_arms) -----------------
    def test_no_bare_else_pairs(self):
        # "Else" directly before "End If" is dead: the pass drops it
        # everywhere (pub_186's Case-2 guard, pub_189's Case-0 guard).
        for name in ("pub_186_00415B1C", "pub_189_00417834_hot",
                     "pub_196_0041D56C"):
            text = self._proc(name)
            self.assertNotRegex(
                text, r"Else\r?\n\s*End If",
                "bare Else/End If pair in %s" % name)

    def test_pub196_empty_arms_inverted_and_collapsed(self):
        text = self._proc("pub_196_0041D56C")
        # empty Then inverted: the f06E4-Or guard now guards its body
        self.assertIn(
            "If Not (Me.f06E4(Me.f0312, 2).f0000 Or "
            "Me.f06E4(Me.f0312, 1).f0000) Then", text)
        # the f06C4 ladder's two empty arms collapsed to one If
        self.assertIn(
            "If (Me.f06C4(Me.f0312, 2).f0000 <= 0) And "
            "(Me.f06C4(Me.f0312, 1).f0000 <= 0) Then", text)
        # the enclosing Or-guard kept its nested-If structure (a bare
        # If after an opener is a nested If, never a ladder leg)
        self.assertIn(
            "If (Me.f079C(stack-180, 9).f0000 > 0) Or "
            "(Me.f06C4(Me.f0312, 4).f0000 > 0) Then", text)

    def test_pub186_case2_guard_is_one_sided(self):
        # The f04DC guard's else arm is empty: no Else line, the shared
        # restart GoTo serves both the (empty) fall-out and the arm.
        text = self._proc("pub_186_00415B1C")
        idx = text.index("If Me.f04DC(stack-136 + 100) Then")
        end = text.index("End If", idx)
        arm = text[idx:end]
        self.assertNotIn("Else", arm)
        self.assertIn("If stack-134 > 0 Then", arm)


if __name__ == "__main__":
    unittest.main(verbosity=2)
