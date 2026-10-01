"""Tests for the CFG/dominator structurer (src/structuring.py).

Run:  .venv/bin/python tests/test_structuring.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import stack_ir
import structuring


def I(pos, label, operand="-", size=4, opcode=0):
    """Build one instruction."""
    class _I(object):
        pass
    ins = _I()
    ins.pos = pos
    ins.opcode = opcode
    ins.size = size
    ins.label = label
    ins.operand = operand
    return ins


def run(instrs, proc_start, proc_end, exit_addrs=None):
    machine = stack_ir.StackMachine()
    machine.exit_keyword = "Exit Sub"
    machine.arg_map = {}
    machine.param_map = {8: "Me"}
    stmts, label_at_stmt, stats = structuring.structure_proc(
        instrs, proc_start, proc_end, machine, exit_addrs or set(),
        "Exit Sub")
    texts = [s.text for s in stmts]
    return texts, label_at_stmt, stats, machine


class BuildCfgTest(unittest.TestCase):
    def test_leaders_and_edges(self):
        instrs = [
            I(0x1000, "FMemLdI2", "mem=stack+8.f0004", size=6),
            I(0x1006, "LitI2", "val=1", size=2),
            I(0x1008, "EqI2", size=2),
            I(0x100A, "BranchF", "to=00001014", size=4),
            I(0x100E, "LitI2", "val=5", size=2),
            I(0x1010, "FStI2", "mem=stack-100", size=4),
            I(0x1014, "ExitProcStr", size=2),
        ]
        blocks, by_start, entry = structuring.build_cfg(
            instrs, 0x1000, 0x1020)
        self.assertEqual([hex(b.start) for b in blocks],
                         ["0x1000", "0x100e", "0x1014"])
        self.assertEqual(entry.start, 0x1000)
        cond = blocks[0]
        self.assertEqual(cond.kind, "cond")
        self.assertEqual(cond.taken, by_start[0x1014])
        self.assertEqual(cond.fall, by_start[0x100E])
        # postdominator of the cond block is the exit block
        reachable, _ = structuring._reachability(blocks, entry)
        idom = structuring.compute_idom(blocks, entry, reachable)
        ipost = structuring.compute_ipost(blocks, reachable)
        self.assertEqual(ipost[cond], by_start[0x1014])


class IfThenTest(unittest.TestCase):
    def test_if_then(self):
        instrs = [
            I(0x1000, "FMemLdI2", "mem=stack+8.f0004", size=6),
            I(0x1006, "LitI2", "val=1", size=2),
            I(0x1008, "EqI2", size=2),
            I(0x100A, "BranchF", "to=00001014", size=4),
            I(0x100E, "LitI2", "val=5", size=2),
            I(0x1010, "FStI2", "mem=stack-100", size=4),
            I(0x1014, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1020)
        self.assertEqual(texts, [
            "If Me.f0004 = 1 Then",
            "stack-100 = 5",
            "End If",
            "Exit Sub",
        ])

    def test_if_else(self):
        instrs = [
            I(0x1000, "FMemLdI2", "mem=stack+8.f0004", size=6),
            I(0x1006, "LitI2", "val=1", size=2),
            I(0x1008, "EqI2", size=2),
            I(0x100A, "BranchF", "to=00001018", size=4),
            I(0x100E, "LitI2", "val=5", size=2),
            I(0x1010, "FStI2", "mem=stack-100", size=4),
            I(0x1014, "Branch", "to=0000101E", size=4),
            I(0x1018, "LitI2", "val=7", size=2),
            I(0x101A, "FStI2", "mem=stack-104", size=4),
            I(0x101E, "LitI2", "val=9", size=2),
            I(0x1020, "FStI2", "mem=stack-108", size=4),
            I(0x1024, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1030)
        self.assertEqual(texts, [
            "If Me.f0004 = 1 Then",
            "stack-100 = 5",
            "Else",
            "stack-104 = 7",
            "End If",
            "stack-108 = 9",
            "Exit Sub",
        ])

    def test_elseif_chain(self):
        # Two tests on the same variable sharing one merge point; each
        # arm is stack-balanced (as VB4 emits).
        instrs = [
            I(0x1000, "FMemLdI2", "mem=stack+8.f0004", size=6),
            I(0x1006, "LitI2", "val=0", size=2),
            I(0x1008, "EqI2", size=2),
            I(0x100A, "BranchF", "to=00001020", size=4),
            I(0x100E, "LitI2", "val=10", size=2),
            I(0x1010, "FStI2", "mem=stack-100", size=4),
            I(0x1014, "Branch", "to=00001034", size=4),
            I(0x1020, "FMemLdI2", "mem=stack+8.f0004", size=6),
            I(0x1026, "LitI2", "val=1", size=2),
            I(0x1028, "EqI2", size=2),
            I(0x102A, "BranchF", "to=00001034", size=4),
            I(0x102E, "LitI2", "val=11", size=2),
            I(0x1030, "FStI2", "mem=stack-104", size=4),
            I(0x1034, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1040)
        self.assertEqual(texts, [
            "If Me.f0004 = 0 Then",
            "stack-100 = 10",
            "ElseIf Me.f0004 = 1 Then",
            "stack-104 = 11",
            "End If",
            "Exit Sub",
        ])
        self.assertEqual(stats["gotos"], 0)


class LoopTest(unittest.TestCase):
    def test_while(self):
        # L: test; BranchF exit; body; Branch L; exit: ExitProc
        instrs = [
            I(0x1000, "FMemLdI2", "mem=stack+8.f0004", size=6),  # header
            I(0x1006, "LitI2", "val=1", size=2),
            I(0x1008, "EqI2", size=2),
            I(0x100A, "BranchF", "to=00001018", size=4),
            I(0x100E, "LitI2", "val=5", size=2),
            I(0x1010, "FStI2", "mem=stack-100", size=4),
            I(0x1014, "Branch", "to=00001000", size=4),  # back edge
            I(0x1018, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1020)
        self.assertEqual(texts, [
            "While Me.f0004 = 1",
            "stack-100 = 5",
            "Wend",
            "Exit Sub",
        ])
        self.assertEqual(stats["loops"], 1)

    def test_do_while(self):
        # L: body; cond; BranchT L (post-test)
        instrs = [
            I(0x1000, "LitI2", "val=5", size=2),
            I(0x1002, "FStI2", "mem=stack-100", size=4),
            I(0x1006, "FMemLdI2", "mem=stack+8.f0004", size=6),
            I(0x100C, "LitI2", "val=1", size=2),
            I(0x100E, "EqI2", size=2),
            I(0x1010, "BranchT", "to=00001000", size=4),
            I(0x1014, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1020)
        self.assertEqual(texts, [
            "Do",
            "stack-100 = 5",
            "Loop While Me.f0004 = 1",
            "Exit Sub",
        ])

    def test_for_next(self):
        # ForI2/NextI2 with the loop variable reference pushes.
        instrs = [
            I(0x1000, "LitI2", "val=0", size=2),            # start
            I(0x1002, "FLdRfVar", "mem=stack-138", size=4),  # var ref
            I(0x1006, "LitI2", "val=9", size=2),            # end
            I(0x1008, "ForI2", "ctl=stack-138 to=0000101E", size=6),
            I(0x100E, "LitI2", "val=1", size=2),            # body
            I(0x1010, "FStI2", "mem=stack-100", size=4),
            I(0x1014, "FLdRfVar", "mem=stack-138", size=4),  # Next var re-push
            I(0x1018, "NextI2", "ctl=stack-138 to=0000100E", size=6),
            I(0x101E, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1030)
        self.assertEqual(texts, [
            "For stack-138 = 0 To 9",
            "stack-100 = 1",
            "Next",
            "Exit Sub",
        ])

    def test_exit_for(self):
        instrs = [
            I(0x1000, "LitI2", "val=0", size=2),
            I(0x1002, "FLdRfVar", "mem=stack-138", size=4),
            I(0x1006, "LitI2", "val=9", size=2),
            I(0x1008, "ForI2", "ctl=stack-138 to=0000102A", size=6),
            I(0x100E, "FMemLdI2", "mem=stack+8.f0004", size=6),
            I(0x1014, "LitI2", "val=5", size=2),
            I(0x1016, "EqI2", size=2),
            I(0x1018, "BranchT", "to=0000102A", size=4),   # exit the loop
            I(0x101C, "LitI2", "val=1", size=2),
            I(0x101E, "FStI2", "mem=stack-100", size=4),
            I(0x1022, "FLdRfVar", "mem=stack-138", size=4),
            I(0x1026, "NextI2", "ctl=stack-138 to=0000100E", size=6),
            I(0x102A, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1040)
        self.assertEqual(texts, [
            "For stack-138 = 0 To 9",
            "If Me.f0004 = 5 Then",
            "Exit For",
            "End If",
            "stack-100 = 1",
            "Next",
            "Exit Sub",
        ])


class EdgeCaseTest(unittest.TestCase):
    def test_branch_to_exitproc_becomes_exit_sub(self):
        # BranchF whose target is the ExitProc instruction itself.
        instrs = [
            I(0x1000, "FMemLdI2", "mem=stack+8.f0004", size=6),
            I(0x1006, "LitI2", "val=1", size=2),
            I(0x1008, "EqI2", size=2),
            I(0x100A, "BranchF", "to=00001014", size=4),
            I(0x100E, "LitI2", "val=5", size=2),
            I(0x1010, "FStI2", "mem=stack-100", size=4),
            I(0x1014, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1020,
                                       exit_addrs={0x1014})
        self.assertEqual(texts, [
            "If Me.f0004 = 1 Then",
            "stack-100 = 5",
            "End If",
            "Exit Sub",
        ])

    def test_crossproc_branch_dangling_if(self):
        # BranchF into another proc: If over the fall-through region.
        instrs = [
            I(0x1000, "FMemLdI2", "mem=stack+8.f0004", size=6),
            I(0x1006, "LitI2", "val=1", size=2),
            I(0x1008, "EqI2", size=2),
            I(0x100A, "BranchF", "to=00500000", size=4),  # cross-proc
            I(0x100E, "LitI2", "val=5", size=2),
            I(0x1010, "FStI2", "mem=stack-100", size=4),
            I(0x1014, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1020)
        self.assertEqual(texts, [
            "If Me.f0004 = 1 Then",
            "stack-100 = 5",
            "Exit Sub",
            "End If",
        ])

    def test_irreducible_falls_back_to_gotos(self):
        # Two-entry cycle: entry->A, entry->B, A->B, B->A.  No single
        # header dominates the cycle, so it is irreducible.
        instrs = [
            I(0x1000, "BranchF", "to=0000100E", size=4),      # entry: fall A, taken B
            I(0x1004, "LitI2", "val=1", size=2),              # A body
            I(0x1006, "FStI2", "mem=stack-100", size=4),
            I(0x100A, "Branch", "to=0000100E", size=4),       # A -> B
            I(0x100E, "FMemLdI2", "mem=stack+8.f0004", size=6),
            I(0x1014, "LitI2", "val=0", size=2),
            I(0x1016, "EqI2", size=2),
            I(0x1018, "BranchF", "to=00001004", size=4),      # B -> A (taken)
            I(0x101C, "LitI2", "val=2", size=2),              # B fall: exit path
            I(0x101E, "FStI2", "mem=stack-104", size=4),
            I(0x1022, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1030)
        # Terminates, and the cycle bodies survive with explicit gotos.
        self.assertGreater(stats["irreducible"], 0)
        self.assertTrue(any("GoTo L_" in t for t in texts))
        joined = "\n".join(texts)
        self.assertIn("stack-100 = 1", joined)
        self.assertIn("stack-104 = 2", joined)

    def test_forward_goto_labels_target(self):
        # A forward GoTo over a block that has no other predecessors:
        # the skipped block is unreachable and lands in the unreachable
        # section; the target is emitted once with a label.
        instrs = [
            I(0x1000, "LitI2", "val=1", size=2),
            I(0x1002, "FStI2", "mem=stack-100", size=4),
            I(0x1006, "Branch", "to=00001010", size=4),
            I(0x100A, "LitI2", "val=2", size=2),       # no preds -> unreachable
            I(0x100C, "FStI2", "mem=stack-104", size=4),
            I(0x1010, "LitI2", "val=3", size=2),
            I(0x1012, "FStI2", "mem=stack-108", size=4),
            I(0x1016, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1020)
        self.assertIn("stack-100 = 1", texts)
        self.assertIn("GoTo L_00001010", texts)
        self.assertIn("stack-108 = 3", texts)
        # the label target is recorded and the skipped block is unreachable
        flat = [v for vs in labels.values() for v in vs]
        self.assertIn(0x1010, flat)
        self.assertGreaterEqual(stats["unreachable"], 1)


class SelectCaseRewriteTest(unittest.TestCase):
    def test_elseif_chain_becomes_select_case(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
        import pseudo_code
        stmts = [
            stack_ir.Stmt(0x1000, +1, "If (stack-170 = 0) Then", 1),
            stack_ir.Stmt(0x100E, 0, "stack-100 = 10", 2),
            stack_ir.Stmt(0x1020, 0, "ElseIf (stack-170 = 1) Then", 3),
            stack_ir.Stmt(0x102E, 0, "stack-104 = 11", 4),
            stack_ir.Stmt(0x1030, 0, "ElseIf (stack-170 = 2) Then", 5),
            stack_ir.Stmt(0x1038, 0, "stack-108 = 12", 6),
            stack_ir.Stmt(0x1040, -1, "End If", 7),
            stack_ir.Stmt(0x1044, 0, "Exit Sub", 8),
        ]
        new_stmts, labels = pseudo_code._select_case_from_elseif(stmts, {})
        self.assertEqual([s.text for s in new_stmts], [
            "Select Case stack-170",
            "Case 0",
            "stack-100 = 10",
            "Case 1",
            "stack-104 = 11",
            "Case 2",
            "stack-108 = 12",
            "End Select",
            "Exit Sub",
        ])
        # deltas: Select +1, first Case +1, rest 0, End Select -1
        self.assertEqual([s.indent_delta for s in new_stmts[:4]], [1, 1, 0, 0])


    def test_nopop_temp_slot_emits_no_statement(self):
        # check_save_file: rtcBstrFromAnsi(48+i) + FStStrNoPop temp +
        # LitStr '.RPG' + ConcatStr + FStStr filename.  FStStrNoPop is
        # lifetime plumbing (the slot is only freed by FFree1Str, never
        # read); emitting an assignment produced a phantom 'bstr = Chr(48+i)'
        # AND duplicated the call into the filename store.  The value must
        # re-enter the stack with its deferred effects intact so the single
        # call text lands in the consuming statement only.
        instrs = [
            I(0x1000, "LitI2", "val=48", size=2),
            I(0x1002, "FLdI2", "mem=stack-108", size=4),
            I(0x1006, "AddI2", size=2),
            I(0x1008, "ImpAdCallAd", "call=VB40032.rtcBstrFromAnsi@00401012", size=6),
            I(0x100E, "FStStrNoPop", "mem=stack-114", size=4),
            I(0x1012, "LitStr", "text='.RPG'", size=10),
            I(0x101C, "ConcatStr", size=2),
            I(0x101E, "FStStr", "mem=stack-110", size=4),
            I(0x1022, "FFree1Str", "mem=stack-114", size=4),
            I(0x1026, "ExitProcStr", size=2),
        ]
        machine = stack_ir.StackMachine()
        machine.arg_map = {"VB40032.rtcBstrFromAnsi": 1}
        machine.exit_keyword = "Exit Sub"
        for ins in instrs:
            machine.process(ins)
        machine.flush_leftovers(0x1026)
        texts = [s.text for s in machine.statements]
        # Exactly ONE statement: the call text rides the stack through the
        # temp slot into the consuming store (no phantom slot assignment,
        # no duplicated call, and the Chr render for rtcBstrFromAnsi).
        self.assertEqual(texts, [
            "stack-110 = Chr(48 + stack-108) & '.RPG'",
            "Exit Sub",
        ])

    def test_rtc_bstr_from_ansi_renders_chr(self):
        # Chr$(code) is implemented by VB40032!rtcBstrFromAnsi; all three
        # PAL.EXE call sites build Chr(48 + n) & ".RPG" save-slot names.
        machine = stack_ir.StackMachine()
        machine.arg_map = {"VB40032.rtcBstrFromAnsi": 1}
        machine.process(I(0x1000, "LitI2", "val=48", size=2))
        machine.process(I(0x1002, "ImpAdCallAd",
                          "call=VB40032.rtcBstrFromAnsi@00401012", size=6))
        machine.flush_leftovers(0x1008)
        texts = [s.text for s in machine.statements]
        self.assertEqual(texts, ["Call Chr(48)"])

    def test_do_loop_no_phantom_goto_after_visited_exit_block(self):
        # select_battle_action: the loop's post-latch block is rendered
        # inside the body by the "If Not (tmp = -2)" branch's taken side
        # (_emit_cond_exit's leaving-side walk), and its tail branches to
        # the return block.  The infinite Do...Loop has no reachable code
        # after Loop; the structurer used to return "next" to the already-
        # visited exit block, which degraded to a phantom GoTo + a label
        # glued inside the If.  Body must exceed _LATCH_PRED_MAX_BODY so
        # the general latch path (not the test-at-bottom path) runs.
        instrs = [
            I(0x4000, "LitI2", "val=0", size=2),
            I(0x4002, "FStI2", "mem=stack-100", size=4),
            # loop header 0x4006: tmp -= 1; an inner If/Else splits the
            # blocks (join = B3, a plain fall-chain block)
            I(0x4006, "FLdI2", "mem=stack-100", size=4),
            I(0x400A, "LitI2", "val=1", size=2),
            I(0x400C, "SubI2", size=2),
            I(0x400E, "FStI2", "mem=stack-100", size=4),
            I(0x4012, "FLdI2", "mem=stack-104", size=4),
            I(0x4016, "LitI2", "val=1", size=2),
            I(0x4018, "EqI2", size=2),
            I(0x401A, "BranchF", "to=00004028", size=4),
            # B1 (then arm): stack-106 = 1; branch to B3
            I(0x401E, "LitI2", "val=1", size=2),
            I(0x4020, "FStI2", "mem=stack-106", size=4),
            I(0x4024, "Branch", "to=0000402C", size=4),
            # B2 (else arm): stack-106 = 2; falls into B3
            I(0x4028, "LitI2", "val=2", size=2),
            I(0x402A, "FStI2", "mem=stack-106", size=4),
            # B3 0x402C: body fillers + the loop test
            I(0x402C, "FLdI2", "mem=stack-108", size=4),
            I(0x4030, "LitI2", "val=1", size=2),
            I(0x4032, "SubI2", size=2),
            I(0x4034, "FStI2", "mem=stack-108", size=4),
            I(0x4038, "FLdI2", "mem=stack-10C", size=4),
            I(0x403C, "LitI2", "val=1", size=2),
            I(0x403E, "SubI2", size=2),
            I(0x4040, "FStI2", "mem=stack-10C", size=4),
            # test tail: tmp = -2 ?  taken -> exit block 0x4056
            I(0x4044, "FLdI2", "mem=stack-100", size=4),
            I(0x4048, "LitI2", "val=2", size=2),
            I(0x404A, "UMiI2", size=2),
            I(0x404C, "EqI2", size=2),
            I(0x404E, "BranchF", "to=00004056", size=4),
            I(0x4052, "Branch", "to=00004006", size=4),   # latch trampoline
            # exit block 0x4056: x = 9; branch to the return block
            I(0x4056, "LitI2", "val=9", size=2),
            I(0x4058, "FStI2", "mem=stack-110", size=4),
            I(0x405C, "Branch", "to=00004060", size=4),
            # return block 0x4060: result slot = x; ExitProc
            I(0x4060, "FLdI2", "mem=stack-110", size=4),
            I(0x4064, "FStI2", "mem=stack-114", size=4),
            I(0x4068, "ExitProcI2", size=2),
        ]
        texts, labels, _stats, _m = run(instrs, 0x4000, 0x406A,
                                        exit_addrs=set())
        # The leaving-side branch renders the exit block inline...
        self.assertIn("If stack-100 <> -2 Then", texts)
        self.assertIn("stack-110 = 9", texts)
        self.assertIn("GoTo L_00004060", texts)
        # ...and the loop closes with NOTHING after it (no phantom GoTo
        # back to the visited exit block, no orphan label).
        self.assertNotIn("GoTo L_00004056", texts)
        self.assertNotIn(0x4056, labels)
        i = texts.index("Loop")
        self.assertEqual(texts[i + 1:], ["stack-114 = stack-110", "Exit Sub"])

    def test_join_arms_render_uniform_exit_statements(self):
        # query_midi_status: both If arms store the result slot then
        # converge on the bare ExitProc block (then arm via Branch, else
        # arm by falling through).  The branch-side arm always rendered
        # the exit inside the arm (feeding _fold_returns' "Return X"),
        # while the falling arm waited for the post-End If join walk --
        # two capture styles in one If/Else.  Both arms must render the
        # exit statement inside the arm so the fold applies uniformly.
        # (The else arm falls INTO the shared bare exit — one ExitProcI2
        # block, as in the real proc.  Two DISTINCT exit blocks would be
        # a different shape: the else arm's own terminator block makes
        # it a kind="term" side, and the term-side rule renders it as a
        # one-sided guard instead — covered by
        # test_term_side_renders_one_sided_guard.)
        instrs = [
            I(0x5000, "FLdI2", "mem=stack-100", size=4),
            I(0x5004, "LitI2", "val=1", size=2),
            I(0x5006, "EqI2", size=2),
            I(0x5008, "BranchF", "to=00005018", size=4),
            # then arm: result = 5; branch to bare exit 0x5020
            I(0x500C, "LitI2", "val=5", size=2),
            I(0x500E, "FStI2", "mem=stack-104", size=4),
            I(0x5012, "Branch", "to=00005020", size=4),
            # else arm: result = 7; falls through to the shared bare exit
            I(0x5018, "LitI2", "val=7", size=2),
            I(0x501A, "FStI2", "mem=stack-104", size=4),
            I(0x5020, "ExitProcI2", size=2),
        ]
        machine = stack_ir.StackMachine()
        machine.exit_keyword = "Exit Function"
        machine.result_slot = -104
        machine.result_name = "pub_106_00407E04"
        stmts, _labels, _stats = structuring.structure_proc(
            instrs, 0x5000, 0x5024, machine, {0x5020}, "Exit Function")[0:3]
        texts = [s.text for s in stmts]
        i = texts.index("If stack-100 = 1 Then")
        self.assertEqual(texts[i + 1], "pub_106_00407E04 = 5")
        self.assertEqual(texts[i + 2], "Exit Function")
        self.assertEqual(texts[i + 3], "Else")
        self.assertEqual(texts[i + 4], "pub_106_00407E04 = 7")
        self.assertEqual(texts[i + 5], "Exit Function")
        self.assertEqual(texts[i + 6], "End If")
        self.assertNotIn("GoTo L_00005020", texts)

    def test_own_exit_side_renders_term_guard_not_uniform_arms(self):
        # The uniform-exit rule above targets the REAL query_midi_status
        # shape: both arms converge on ONE shared bare exit, so the cond
        # has a join (that block) and _emit_if_else_chain folds the exit
        # into each arm.  A DIFFERENT shape gives one arm its OWN
        # ExitProc terminator: the cond then has NO join (two distinct
        # exits) and the term-side rule captures it — a one-sided guard
        # around the self-exiting arm, the other arm continuing flat.
        # Semantically exact (a term block ends every path through it),
        # and the uniform in-arm style does not apply (there is no
        # shared exit to fold).  Locks the boundary between the two
        # rules; checked not to occur in PAL.EXE (the 13-proc regen
        # contains no Return-fold changes).
        instrs = [
            I(0x5000, "FLdI2", "mem=stack-100", size=4),
            I(0x5004, "LitI2", "val=1", size=2),
            I(0x5006, "EqI2", size=2),
            I(0x5008, "BranchF", "to=00005018", size=4),
            # then arm: result = 5; branches to the bare exit 0x5020
            I(0x500C, "LitI2", "val=5", size=2),
            I(0x500E, "FStI2", "mem=stack-104", size=4),
            I(0x5012, "Branch", "to=00005020", size=4),
            # else arm: result = 7 + its OWN ExitProc terminator
            I(0x5018, "LitI2", "val=7", size=2),
            I(0x501A, "FStI2", "mem=stack-104", size=4),
            I(0x501E, "ExitProcI2", size=2),
            I(0x5020, "ExitProcI2", size=2),
        ]
        texts, _labels, _stats, _m = run(
            instrs, 0x5000, 0x5022, exit_addrs={0x5020})
        self.assertEqual(texts, [
            "If stack-100 <> 1 Then",
            "stack-104 = 7",
            "Exit Sub",
            "End If",
            "stack-104 = 5",
            "Exit Sub",
        ])

    def test_empty_stop_side_renders_one_sided_if(self):
        # produce_screen_map: inside a For loop, cond blocks whose taken
        # edge is the NextI2 latch (a stop-set member) used to open an
        # If/Else with a structurally empty Else arm (the innermost
        # condition handled its leaving fall side via _emit_cond_exit, the
        # outer ones degraded).  A side that IS a stop member carries no
        # code; the If must render one-sided.
        instrs = [
            # For preheader: start, var ref, end, ForI2 (taken = post-loop)
            I(0x6000, "LitI2", "val=0", size=2),
            I(0x6002, "FLdRfVar", "mem=stack-108", size=4),
            I(0x6006, "LitI2", "val=4", size=2),
            I(0x6008, "ForI2", "ctl=stack-110 to=00006040", size=6),
            # header A' 0x600E: If stack-100 > 0 Then B Else latch N
            I(0x600E, "FLdI2", "mem=stack-100", size=4),
            I(0x6012, "LitI2", "val=0", size=2),
            I(0x6014, "GtI2", size=2),
            I(0x6016, "BranchF", "to=00006030", size=4),
            # B 0x601A: If stack-100 < 1 Then D Else latch N
            I(0x601A, "FLdI2", "mem=stack-100", size=4),
            I(0x601E, "LitI2", "val=1", size=2),
            I(0x6020, "LtI2", size=2),
            I(0x6022, "BranchF", "to=00006030", size=4),
            # D 0x6026: leaving fall side (branch out of the loop)
            I(0x6026, "LitI2", "val=3", size=2),
            I(0x6028, "FStI2", "mem=stack-10C", size=4),
            I(0x602C, "Branch", "to=00006040", size=4),
            # N 0x6030: NextI2 latch (taken -> header, fall -> post-loop)
            I(0x6030, "FLdRfVar", "mem=stack-108", size=4),
            I(0x6034, "NextI2", "ctl=stack-110 to=0000600E", size=6),
            # post-loop 0x6040
            I(0x6040, "LitI2", "val=9", size=2),
            I(0x6042, "FStI2", "mem=stack-10C", size=4),
            I(0x6046, "ExitProcStr", size=2),
        ]
        texts, _labels, _stats, _m = run(
            instrs, 0x6000, 0x604A, exit_addrs={0x6046})
        self.assertIn("For stack-108 = 0 To 4", texts)
        # Both guards render one-sided; the innermost leaving side folds
        # its branch to the post-loop block into Exit For.
        self.assertIn("If stack-100 > 0 Then", texts)
        self.assertIn("If stack-100 < 1 Then", texts)
        self.assertIn("stack-10C = 3", texts)
        self.assertIn("Exit For", texts)
        # No structurally empty Else arm may appear.
        for k, t in enumerate(texts[:-1]):
            self.assertFalse(t == "Else" and texts[k + 1] == "End If",
                             "empty Else arm at %d" % k)


    def test_term_side_renders_one_sided_guard(self):
        # Sub_Main's InitInput/SetMode checks: a cond whose one side is a
        # terminator block (error handler: statements + End) and whose
        # other side carries on.  The old join=None path opened an
        # If/Else nesting the whole continuation an extra level inside
        # the Else arm.  A term side ends every path through it (no
        # branch edges), so guarding it one-sided and walking the other
        # side as the flat continuation is exact.
        instrs = [
            I(0x6000, "FLdI2", "mem=stack-100", size=4),
            I(0x6004, "BranchF", "to=00006014", size=4),
            # fall: error handler — statements + End (kind="term")
            I(0x6008, "LitI2", "val=1", size=2),
            I(0x600A, "FStI2", "mem=stack-104", size=4),
            I(0x600E, "End", size=2),
            # taken: main continuation, branches to a bare exit block
            I(0x6014, "LitI2", "val=2", size=2),
            I(0x6016, "FStI2", "mem=stack-108", size=4),
            I(0x601A, "Branch", "to=0000601E", size=4),
            I(0x601E, "ExitProcStr", size=2),
        ]
        texts, _labels, _stats, _m = run(
            instrs, 0x6000, 0x6020, exit_addrs={0x601E})
        self.assertEqual(texts, [
            "If stack-100 Then",
            "stack-104 = 1",
            "End",
            "End If",
            "stack-108 = 2",
            "Exit Sub",
        ])

    def test_continuation_region_deferred_out_of_loop_guard(self):
        # Sub_Main's InitCD retry loop: inside a Do loop, a cond whose
        # taken side leaves the loop into a region that runs into
        # ANOTHER loop (the game body) — a continuation, not a handler.
        # Inlining it under the exit guard nests the whole region and
        # drags the loop context into its walk (every join outside the
        # loop then reads as None and the region's conditionals degrade
        # to nested exit guards).  The side must render as a guarded
        # GoTo; the orphan/label pass emits the region flat afterwards.
        instrs = [
            # loop header 0x7000: store; test; BranchF -> continuation
            I(0x7000, "LitI2", "val=0", size=2),
            I(0x7002, "FStI2", "mem=stack-100", size=4),
            I(0x7006, "FLdI2", "mem=stack-100", size=4),
            I(0x700A, "BranchF", "to=00007024", size=4),
            # in-loop side 0x700E: store + closing test
            I(0x700E, "LitI2", "val=1", size=2),
            I(0x7010, "FStI2", "mem=stack-104", size=4),
            I(0x7014, "FLdI2", "mem=stack-104", size=4),
            I(0x7016, "BranchF", "to=0000701E", size=4),
            # latch 0x701A
            I(0x701A, "Branch", "to=00007000", size=4),
            # loop exit 0x701E (End block, target of the closing test)
            I(0x701E, "End", size=2),
            # continuation 0x7024: falls into its own infinite loop
            I(0x7024, "LitI2", "val=5", size=2),
            I(0x7026, "FStI2", "mem=stack-108", size=4),
            I(0x702A, "LitI2", "val=6", size=2),
            I(0x702C, "FStI2", "mem=stack-10C", size=4),
            I(0x7030, "Branch", "to=00007030", size=4),
        ]
        texts, labels, _stats, _m = run(instrs, 0x7000, 0x7034)
        # the guard holds a bare GoTo, not the inlined region
        i = texts.index("If Not (stack-100) Then")
        self.assertEqual(texts[i + 1], "GoTo L_00007024")
        self.assertEqual(texts[i + 2], "End If")
        # the in-loop side stays at loop level; the loop closes normally
        self.assertEqual(texts[i + 3], "stack-104 = 1")
        self.assertIn("Loop While stack-104", texts)
        # the deferred region is emitted FLAT after the loop's End,
        # with its label landing on its first statement
        j = texts.index("End")
        k = texts.index("stack-108 = 5")
        self.assertGreater(k, j)
        self.assertEqual(texts[k + 2], "Do")   # its own loop, flat
        self.assertEqual(labels.get(k), [0x7024])

    def test_infinite_sibling_nulls_bogus_join(self):
        # Sub_Main's SetMode check: the taken side runs into an infinite
        # loop (no path to the proc exit), the fall side is the error
        # handler.  compute_ipost only sees exit-reaching paths, so the
        # handler showed up as the "join" (as if the game side passed
        # through it).  The old fall-is-join rendering nested the whole
        # infinite region inside the guard.  The join must be nulled
        # (the sibling cannot reach it) and the term-side rule then
        # guards the handler, leaving the infinite region flat.
        instrs = [
            I(0x8000, "FLdI2", "mem=stack-100", size=4),
            I(0x8004, "BranchF", "to=00008014", size=4),
            # fall: error handler (statements + End)
            I(0x8008, "LitI2", "val=1", size=2),
            I(0x800A, "FStI2", "mem=stack-104", size=4),
            I(0x800E, "End", size=2),
            # taken: continuation falling into an infinite self-loop
            I(0x8014, "LitI2", "val=5", size=2),
            I(0x8016, "FStI2", "mem=stack-108", size=4),
            I(0x801A, "Branch", "to=0000801A", size=4),
        ]
        texts, _labels, _stats, _m = run(instrs, 0x8000, 0x801E)
        self.assertEqual(texts, [
            "If stack-100 Then",
            "stack-104 = 1",
            "End",
            "End If",
            "stack-108 = 5",
            "Do",
            "Loop",
        ])

    def test_loop_local_join_survives_infinite_body(self):
        # Inside an infinite loop NOTHING reaches the proc exit, so a
        # too-aggressive bogus-join test ("sibling cannot reach the
        # EXIT") would null every loop-local join whose block is a
        # direct successor, degrading the body to nested If/Else guards.
        # The precise test is reachability of the JOIN itself: each
        # cond's fall side flows into its join (the next cond / the
        # latch), so _refine_ipost_in_loops' joins are honest and render
        # as plain one-sided Ifs.  (Sub_Main's game loop: the inner Do's
        # header is the restart check whose fall side jumps to the outer
        # header; the game conds are interior blocks — each cond's
        # BranchF target is the next cond's block, which is what makes
        # them basic-block leaders — and each handler falls into its
        # join.)
        instrs = [
            # outer loop header 0x9000 (plain; back edge from 0x9014)
            I(0x9000, "LitI2", "val=1", size=2),
            I(0x9002, "FStI2", "mem=stack-104", size=4),
            # inner loop header 0x9006: body + restart test
            I(0x9006, "LitI2", "val=2", size=2),
            I(0x9008, "FStI2", "mem=stack-108", size=4),
            I(0x900C, "FLdI2", "mem=stack-100", size=4),
            I(0x9010, "BranchF", "to=00009018", size=4),
            # restart trampoline 0x9014: back edge to the outer header
            I(0x9014, "Branch", "to=00009000", size=4),
            # game cond1 0x9018: BranchF -> cond2 0x902C (the join)
            I(0x9018, "LitI2", "val=3", size=2),
            I(0x901A, "FStI2", "mem=stack-10C", size=4),
            I(0x901E, "FLdI2", "mem=stack-10C", size=4),
            I(0x9022, "BranchF", "to=0000902C", size=4),
            # handler1 0x9026: falls into the join
            I(0x9026, "LitI2", "val=4", size=2),
            I(0x9028, "FStI2", "mem=stack-110", size=4),
            # game cond2 0x902C: BranchF -> latch 0x9038 (the join)
            I(0x902C, "FLdI2", "mem=stack-10C", size=4),
            I(0x9030, "BranchF", "to=00009038", size=4),
            # handler2 0x9034: falls into the join
            I(0x9034, "LitI2", "val=5", size=2),
            I(0x9036, "FStI2", "mem=stack-114", size=4),
            # inner latch 0x9038: back edge to the inner header
            I(0x9038, "Branch", "to=00009006", size=4),
        ]
        texts, _labels, _stats, _m = run(instrs, 0x9000, 0x903C)
        self.assertEqual(texts, [
            "Do",
            "stack-104 = 1",
            "Do",
            "stack-108 = 2",
            "If stack-100 Then",
            "GoTo L_00009000",
            "End If",
            "stack-10C = 3",
            "If stack-10C Then",
            "stack-110 = 4",
            "End If",
            "If stack-10C Then",
            "stack-114 = 5",
            "End If",
            "Loop",
            "Loop",
        ])


class RegressionFixTest(unittest.TestCase):
    """Regression guards for the pub_186 / pub_196 / pub_197 fixes."""

    def test_flush_calls_above_emits_stranded_void_call_at_block_tail(self):
        # pub_196 finding 2: a discarded void call left on the stack at a
        # plain fall-through boundary used to be deferred and inserted
        # later, shifting the label positions of subsequent blocks.  The
        # fix flushes only trailing call values above a depth, leaving
        # non-call values untouched for the next block.
        import stack_ir as si
        m = stack_ir.StackMachine()
        # depth-0 baseline value stays put even though a call sits atop it.
        m.push("stack-134")          # non-call, below depth0
        depth0 = len(m.stack)         # == 1
        m.push("Foo()", is_call=True)  # stranded void call (the bug case)
        m.push("Bar()", is_call=True)
        m.flush_calls_above(0x1010, depth0)
        # The two trailing calls were emitted as Call statements; the
        # non-call baseline value is untouched.
        texts = [s.text for s in m.statements]
        self.assertEqual(texts, ["Call Foo()", "Call Bar()"])
        self.assertEqual(len(m.stack), 1)
        self.assertEqual(m.stack[0].text, "stack-134")

    def test_postprocess_keeps_goto_in_elseif_leg_after_exit_sub(self):
        # pub_197: a leg ending in Exit Sub opened a dead zone; without
        # treating 'ElseIf' as a structural marker the next leg's then-arm
        # GoTo (a cross-leg branch into a shared body) was wrongly deleted.
        import pseudo_code as pc
        stmts = [
            stack_ir.Stmt(0x1000, +1, "If (stack-170 = 0) Then", 1),
            stack_ir.Stmt(0x1010, 0, "Exit Sub", 2),
            stack_ir.Stmt(0x1020, 0, "ElseIf (stack-170 = 1) Then", 3),
            stack_ir.Stmt(0x1030, +1, "If (stack-172 = 1) Then", 4),
            stack_ir.Stmt(0x1040, 0, "GoTo L_00421140", 5),
            stack_ir.Stmt(0x1050, -1, "End If", 6),
            stack_ir.Stmt(0x1060, 0, "ElseIf (stack-170 = 2) Then", 7),
            stack_ir.Stmt(0x1070, 0, "stack-100 = 12", 8),
            stack_ir.Stmt(0x1080, -1, "End If", 9),
            stack_ir.Stmt(0x1090, 0, "Exit Sub", 10),
        ]
        label_at_stmt = {}
        new_stmts, _labels = pc._postprocess_stmts(
            stmts, label_at_stmt, 0x1000, 0x10A0, "Exit Sub",
            "Sub", None, stack_ir.StackMachine(), set())
        texts = [s.text for s in new_stmts]
        # The cross-leg GoTo inside the second leg's then-arm survives.
        self.assertIn("GoTo L_00421140", texts)
        self.assertIn("stack-100 = 12", texts)

    def test_join_exit_fold_f_empty_polarity(self):
        # pub_167 case 9: inside a loop, a cond whose fall side is a bare
        # trampoline to the shared proc exit and whose taken side carries
        # code.  _emit_if_join_exit renders the TAKEN side as the Then
        # arm — for BranchF that path runs when the condition is FALSE,
        # so the guard must be Not(cond).  The old ternary produced the
        # raw cond and swapped the two arms' semantics.
        instrs = [
            I(0x2000, "LitI2", "val=0", size=2),
            I(0x2002, "FStI2", "mem=stack-100", size=4),
            I(0x2006, "FLdI2", "mem=stack-100", size=4),
            I(0x200A, "LitI2", "val=1", size=2),
            I(0x200C, "EqI2", size=2),
            I(0x200E, "BranchF", "to=00002030", size=4),
            I(0x2012, "FLdI2", "mem=stack-104", size=4),
            I(0x2016, "LitI2", "val=5", size=2),
            I(0x2018, "LtI2", size=2),
            I(0x201A, "BranchF", "to=00002022", size=4),
            I(0x201E, "Branch", "to=00002046", size=4),
            I(0x2022, "LitI2", "val=0", size=2),
            I(0x2024, "FStI2", "mem=stack-104", size=4),
            I(0x2028, "Branch", "to=00002040", size=4),
            I(0x2030, "Branch", "to=00002050", size=4),
            I(0x2040, "LitI2", "val=9", size=2),
            I(0x2042, "FStI2", "mem=stack-10C", size=4),
            I(0x2046, "ExitProcStr", size=2),
            I(0x2050, "LitI2", "val=7", size=2),
            I(0x2052, "FStI2", "mem=stack-108", size=4),
            I(0x2056, "Branch", "to=00002000", size=4),
        ]
        texts, _labels, _stats, _m = run(instrs, 0x2000, 0x205A,
                                         exit_addrs={0x2046})
        # stack-104 >= 5 (compare FALSE) runs the taken arm's code; the
        # shared proc exit follows the End If (fold form).
        self.assertIn("If stack-104 >= 5 Then", texts)
        self.assertNotIn("If stack-104 < 5 Then", texts)
        i = texts.index("If stack-104 >= 5 Then")
        self.assertEqual(texts[i + 1], "stack-104 = 0")
        j = texts.index("End If", i)
        self.assertEqual(texts[j + 1], "Exit Sub")

    def test_ancestor_latch_departure_renders_goto(self):
        # pub_186: inside the innermost loop, a cond whose fall side is
        # the OUTER loop's latch trampoline (Branch -> outer header).  The
        # latch is a stop-set member (each loop adds its latch to stop),
        # so the membership test hid the departure; the ancestor check
        # that catches it was guarded by 'not f_out and not t_out' and
        # never ran.  The leaving-side walk then dropped the edge and the
        # stack-104 = 1 path fell through to the innermost Loop.
        instrs = [
            I(0x3000, "LitI2", "val=0", size=2),
            I(0x3002, "FStI2", "mem=stack-100", size=4),
            I(0x3006, "LitI2", "val=5", size=2),
            I(0x3008, "FStI2", "mem=stack-104", size=4),
            I(0x300C, "FLdI2", "mem=stack-100", size=4),
            I(0x3010, "LitI2", "val=0", size=2),
            I(0x3012, "EqI2", size=2),
            I(0x3014, "BranchF", "to=00003040", size=4),
            I(0x3018, "FLdI2", "mem=stack-104", size=4),
            I(0x301C, "LitI2", "val=1", size=2),
            I(0x301E, "EqI2", size=2),
            I(0x3020, "BranchF", "to=00003050", size=4),
            I(0x3024, "Branch", "to=00003000", size=4),
            I(0x3040, "Branch", "to=00003044", size=4),
            I(0x3044, "Branch", "to=00003006", size=4),
            I(0x3050, "LitI2", "val=9", size=2),
            I(0x3052, "FStI2", "mem=stack-10C", size=4),
            I(0x3054, "ExitProcStr", size=2),
        ]
        texts, labels, _stats, _m = run(instrs, 0x3000, 0x3058)
        # stack-104 = 1 must restart the OUTER loop explicitly (an Else
        # arm jumping to the outer header), not fall through to the
        # innermost Loop.
        i = texts.index("If stack-104 <> 1 Then")
        self.assertEqual(texts[i + 2], "Else")
        self.assertEqual(texts[i + 3], "GoTo L_00003000")
        self.assertEqual(texts[i + 4], "End If")
        # the outer-restart label attaches to the outer Do
        self.assertEqual(texts[0], "Do")
        self.assertEqual(labels.get(0), [0x3000])



class StructuralChainTest(unittest.TestCase):
    """The three structural-chain flavors: dispatch ladders whose join
    the postdominator pass cannot see.  PATH6 (join=None) needs BOTH
    opener sides inside the loop body (else the t_out/f_out
    classification handles the cond first) AND an arm-internal exit
    guard whose exit path bypasses the ladder's convergence (so no
    in-body block postdominates the opener and ipost reports the far
    loop exit, which gets nulled).  arm1 carries that guard -- the
    pub_189 corpus shape (its =-1 lane hides an Exit Do behind the
    restart).  The latch is always a separate bare branch block."""

    def test_flavor_a_join_chain(self):
        # Arms converge on J (leg2's skip side): arm1 departs, arm2
        # FALLS into J.  Flavor A renders the ladder with End If
        # anchored at J and J's code inline after it.
        instrs = [
            I(0x1000, "LitI2", "val=0", size=2),            # header
            I(0x1002, "FStI2", "mem=stack-100", size=4),
            I(0x1006, "FMemLdI2", "mem=stack+8.f0004", size=6),   # leg1
            I(0x100C, "LitI2", "val=1", size=2),
            I(0x100E, "EqI2", size=2),
            I(0x1010, "BranchF", "to=0000102C", size=4),
            I(0x1014, "LitI2", "val=10", size=2),           # arm1: code
            I(0x1016, "FStI2", "mem=stack-100", size=4),
            I(0x101A, "FMemLdI2", "mem=stack+8.f0004", size=6),  # guard
            I(0x1020, "LitI2", "val=5", size=2),
            I(0x1022, "EqI2", size=2),
            I(0x1024, "BranchT", "to=00001052", size=4),
            I(0x1028, "Branch", "to=00001000", size=4),     # restart
            I(0x102C, "FMemLdI2", "mem=stack+8.f0004", size=6),  # leg2
            I(0x1032, "LitI2", "val=2", size=2),
            I(0x1034, "EqI2", size=2),
            I(0x1036, "BranchF", "to=00001040", size=4),   # skip -> J
            I(0x103A, "LitI2", "val=20", size=2),          # arm2: falls to J
            I(0x103C, "FStI2", "mem=stack-100", size=4),
            I(0x1040, "FMemLdI2", "mem=stack+8.f0004", size=6),  # J guard
            I(0x1046, "LitI2", "val=9", size=2),
            I(0x1048, "EqI2", size=2),
            I(0x104A, "BranchF", "to=00001052", size=4),
            I(0x104E, "Branch", "to=00001000", size=4),    # latch
            I(0x1052, "LitI2", "val=9", size=2),           # loop exit
            I(0x1054, "FStI2", "mem=stack-104", size=4),
            I(0x1058, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x105A)
        self.assertEqual(texts, [
            "Do",
            "stack-100 = 0",
            "If Me.f0004 = 1 Then",
            "stack-100 = 10",
            "If Me.f0004 = 5 Then",
            "Exit Do",
            "End If",
            "GoTo L_00001000",
            "ElseIf Me.f0004 = 2 Then",
            "stack-100 = 20",
            "End If",
            "If Me.f0004 <> 9 Then",
            "Exit Do",
            "End If",
            "Loop",
            "stack-104 = 9",
            "Exit Sub",
        ])

    def test_flavor_b_departing_chain(self):
        # Every arm departs (exit / loop bottom) and the final skip
        # side leaves the loop too: the Else IS the departure (Exit Do).
        instrs = [
            I(0x1000, "LitI2", "val=0", size=2),            # header
            I(0x1002, "FStI2", "mem=stack-100", size=4),
            I(0x1006, "FMemLdI2", "mem=stack+8.f0004", size=6),   # leg1
            I(0x100C, "LitI2", "val=1", size=2),
            I(0x100E, "EqI2", size=2),
            I(0x1010, "BranchF", "to=0000102C", size=4),
            I(0x1014, "LitI2", "val=10", size=2),           # arm1: code
            I(0x1016, "FStI2", "mem=stack-100", size=4),
            I(0x101A, "FMemLdI2", "mem=stack+8.f0004", size=6),  # guard
            I(0x1020, "LitI2", "val=5", size=2),
            I(0x1022, "EqI2", size=2),
            I(0x1024, "BranchT", "to=00001048", size=4),
            I(0x1028, "Branch", "to=00001000", size=4),     # restart
            I(0x102C, "FMemLdI2", "mem=stack+8.f0004", size=6),  # leg2
            I(0x1032, "LitI2", "val=2", size=2),
            I(0x1034, "EqI2", size=2),
            I(0x1036, "BranchF", "to=00001048", size=4),   # skip -> exit
            I(0x103A, "LitI2", "val=20", size=2),          # arm2: to latch
            I(0x103C, "FStI2", "mem=stack-100", size=4),
            I(0x1040, "Branch", "to=00001044", size=4),
            I(0x1044, "Branch", "to=00001000", size=4),    # latch
            I(0x1048, "LitI2", "val=9", size=2),           # loop exit
            I(0x104A, "FStI2", "mem=stack-102", size=4),
            I(0x104E, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1050)
        self.assertEqual(texts, [
            "Do",
            "stack-100 = 0",
            "If Me.f0004 = 1 Then",
            "stack-100 = 10",
            "If Me.f0004 = 5 Then",
            "Exit Do",
            "End If",
            "GoTo L_00001000",
            "ElseIf Me.f0004 = 2 Then",
            "stack-100 = 20",
            "Else",
            "Exit Do",
            "End If",
            "Loop",
            "stack-102 = 9",
            "Exit Sub",
        ])

    def test_flavor_c_open_chain(self):
        # No provable join and nothing departs on the skip side: the
        # legs still flatten, and the skip side walks as the Else arm
        # (one nesting level instead of N).  BOTH arms carry an
        # exit guard (independent exits keep any single arm from
        # postdominating the opener, so PATH6 sees join=None).
        instrs = [
            I(0x1000, "LitI2", "val=0", size=2),            # header
            I(0x1002, "FStI2", "mem=stack-100", size=4),
            I(0x1006, "FMemLdI2", "mem=stack+8.f0004", size=6),   # leg1
            I(0x100C, "LitI2", "val=1", size=2),
            I(0x100E, "EqI2", size=2),
            I(0x1010, "BranchF", "to=0000102C", size=4),
            I(0x1014, "LitI2", "val=10", size=2),           # arm1: code
            I(0x1016, "FStI2", "mem=stack-100", size=4),
            I(0x101A, "FMemLdI2", "mem=stack+8.f0004", size=6),  # guard
            I(0x1020, "LitI2", "val=5", size=2),
            I(0x1022, "EqI2", size=2),
            I(0x1024, "BranchT", "to=00001060", size=4),
            I(0x1028, "Branch", "to=00001000", size=4),     # restart
            I(0x102C, "FMemLdI2", "mem=stack+8.f0004", size=6),  # leg2
            I(0x1032, "LitI2", "val=2", size=2),
            I(0x1034, "EqI2", size=2),
            I(0x1036, "BranchF", "to=00001052", size=4),   # skip -> else
            I(0x103A, "LitI2", "val=20", size=2),          # arm2: code
            I(0x103C, "FStI2", "mem=stack-100", size=4),
            I(0x1040, "FMemLdI2", "mem=stack+8.f0004", size=6),  # guard
            I(0x1046, "LitI2", "val=5", size=2),
            I(0x1048, "EqI2", size=2),
            I(0x104A, "BranchT", "to=00001060", size=4),
            I(0x104E, "Branch", "to=00001000", size=4),     # restart
            I(0x1052, "LitI2", "val=30", size=2),          # else: in-body
            I(0x1054, "FStI2", "mem=stack-102", size=4),
            I(0x1058, "Branch", "to=0000105C", size=4),
            I(0x105C, "Branch", "to=00001000", size=4),    # latch
            I(0x1060, "LitI2", "val=9", size=2),           # loop exit
            I(0x1062, "FStI2", "mem=stack-104", size=4),
            I(0x1066, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1068)
        self.assertEqual(texts, [
            "Do",
            "stack-100 = 0",
            "If Me.f0004 = 1 Then",
            "stack-100 = 10",
            "If Me.f0004 = 5 Then",
            "Exit Do",
            "End If",
            "GoTo L_00001000",
            "ElseIf Me.f0004 = 2 Then",
            "stack-100 = 20",
            "If Me.f0004 = 5 Then",
            "Exit Do",
            "End If",
            "GoTo L_00001000",
            "Else",
            "stack-102 = 30",
            "End If",
            "Loop",
            "stack-104 = 9",
            "Exit Sub",
        ])

    def test_around_loop_reach_is_not_flavor_a(self):
        # pub_196's scan-loop shape: an arm that skips to the loop
        # bottom only reaches the skip side by going around the Do
        # again (the next dispatch round).  That must NOT count as
        # "arm reaches the join" (the old bug: J got orphaned with an
        # extra GoTo + label); the skip side must walk as the Else.
        instrs = [
            I(0x1000, "LitI2", "val=0", size=2),            # header
            I(0x1002, "FStI2", "mem=stack-100", size=4),
            I(0x1006, "FMemLdI2", "mem=stack+8.f0004", size=6),   # leg1
            I(0x100C, "LitI2", "val=1", size=2),
            I(0x100E, "EqI2", size=2),
            I(0x1010, "BranchF", "to=0000102C", size=4),
            I(0x1014, "LitI2", "val=10", size=2),           # arm1: code
            I(0x1016, "FStI2", "mem=stack-100", size=4),
            I(0x101A, "FMemLdI2", "mem=stack+8.f0004", size=6),  # guard
            I(0x1020, "LitI2", "val=5", size=2),
            I(0x1022, "EqI2", size=2),
            I(0x1024, "BranchT", "to=00001060", size=4),
            I(0x1028, "Branch", "to=00001000", size=4),     # restart
            I(0x102C, "FMemLdI2", "mem=stack+8.f0004", size=6),  # leg2
            I(0x1032, "LitI2", "val=2", size=2),
            I(0x1034, "EqI2", size=2),
            I(0x1036, "BranchF", "to=00001052", size=4),   # skip -> J
            I(0x103A, "LitI2", "val=20", size=2),          # arm2: code
            I(0x103C, "FStI2", "mem=stack-100", size=4),
            I(0x1040, "FMemLdI2", "mem=stack+8.f0004", size=6),  # guard
            I(0x1046, "LitI2", "val=5", size=2),
            I(0x1048, "EqI2", size=2),
            I(0x104A, "BranchT", "to=00001060", size=4),
            I(0x104E, "Branch", "to=0000105C", size=4),     # skips J -> latch
            I(0x1052, "LitI2", "val=30", size=2),          # J: in-body
            I(0x1054, "FStI2", "mem=stack-102", size=4),
            I(0x1058, "Branch", "to=0000105C", size=4),    # J -> latch
            I(0x105C, "Branch", "to=00001000", size=4),    # latch
            I(0x1060, "LitI2", "val=9", size=2),           # loop exit
            I(0x1062, "FStI2", "mem=stack-104", size=4),
            I(0x1066, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1068)
        self.assertEqual(texts, [
            "Do",
            "stack-100 = 0",
            "If Me.f0004 = 1 Then",
            "stack-100 = 10",
            "If Me.f0004 = 5 Then",
            "Exit Do",
            "End If",
            "GoTo L_00001000",
            "ElseIf Me.f0004 = 2 Then",
            "stack-100 = 20",
            "If Me.f0004 = 5 Then",
            "Exit Do",
            "End If",
            "Else",
            "stack-102 = 30",
            "End If",
            "Loop",
            "stack-104 = 9",
            "Exit Sub",
        ])
        # no orphan: J's code appears exactly once, inside the Else
        self.assertEqual(texts.count("stack-102 = 30"), 1)


class TrampolineAndOutBodyChainTest(unittest.TestCase):
    """Fix A (bare-trampoline threading in _exit_stmt_for_target) and
    Fix B (out-of-body arms joining the structural chain).  Layout
    discipline copied from StructuralChainTest: the latch is a separate
    bare branch block and a branch-target leader, both opener sides
    start inside the loop body, and arm1 carries an internal Exit Do
    guard so no in-body block postdominates the opener."""

    def test_trampoline_threading_skips_hop_labels(self):
        # arm2 and the skip side jump through TWO bare trampolines
        # (0x1048 -> 0x104A -> 0x104C) to the labeled tail.  Threading
        # renders direct GoTos to the final landing; neither hop keeps
        # a label (no references remain), so they vanish entirely.
        instrs = [
            I(0x1000, "LitI2", "val=0", size=2),            # header
            I(0x1002, "FStI2", "mem=stack-100", size=4),
            I(0x1006, "FMemLdI2", "mem=stack+8.f0004", size=6),   # leg1
            I(0x100C, "LitI2", "val=1", size=2),
            I(0x100E, "EqI2", size=2),
            I(0x1010, "BranchF", "to=0000102C", size=4),
            I(0x1014, "LitI2", "val=10", size=2),           # arm1: code
            I(0x1016, "FStI2", "mem=stack-100", size=4),
            I(0x101A, "FMemLdI2", "mem=stack+8.f0004", size=6),  # guard
            I(0x1020, "LitI2", "val=5", size=2),
            I(0x1022, "EqI2", size=2),
            I(0x1024, "BranchT", "to=0000104C", size=4),
            I(0x1028, "Branch", "to=00001000", size=4),     # latch
            I(0x102C, "FMemLdI2", "mem=stack+8.f0004", size=6),  # leg2
            I(0x1032, "LitI2", "val=2", size=2),
            I(0x1034, "EqI2", size=2),
            I(0x1036, "BranchF", "to=00001048", size=4),   # skip -> hop1
            I(0x103A, "LitI2", "val=20", size=2),          # arm2: code
            I(0x103C, "FStI2", "mem=stack-100", size=4),
            I(0x1040, "Branch", "to=00001048", size=4),    # -> hop1
            I(0x1044, "Branch", "to=00001044", size=4),    # (dead; keeps 0x1044 a leader)
            I(0x1048, "Branch", "to=0000104A", size=4),    # hop1
            I(0x104A, "Branch", "to=0000104C", size=4),    # hop2
            I(0x104C, "LitI2", "val=9", size=2),           # tail
            I(0x104E, "FStI2", "mem=stack-104", size=4),
            I(0x1052, "ExitProcStr", size=2),
        ]
        texts, _labels, stats, _m = run(instrs, 0x1000, 0x1054)
        joined = "\n".join(texts)
        self.assertIn("GoTo L_0000104C", joined)
        self.assertNotIn("L_00001048", joined)   # hop1 unreferenced
        self.assertNotIn("L_0000104A", joined)   # hop2 unreferenced
        # the threaded jumps appear from the arm AND the Else side
        self.assertEqual(texts.count("GoTo L_0000104C"), 2)

    def test_out_of_body_arm_joins_chain(self):
        # pub_167's shape in miniature: the =3 lane physically lives
        # PAST the loop (no back-edge path), so its arm is out-of-body.
        # Fix B admits it: the ladder flattens to If/ElseIf/Else with
        # the out-of-body arm walked inline (leaving-side wrap).  The
        # opener keeps both sides in-body (arm1 restarts, leg2 reaches
        # the latch through arm2), and the latch has bare-branch preds
        # (not a closing test), so no Loop-Until bottom-test fires.
        instrs = [
            I(0x1000, "LitI2", "val=0", size=2),            # header
            I(0x1002, "FStI2", "mem=stack-100", size=4),
            I(0x1006, "FMemLdI2", "mem=stack+8.f0004", size=6),   # leg1
            I(0x100C, "LitI2", "val=1", size=2),
            I(0x100E, "EqI2", size=2),
            I(0x1010, "BranchF", "to=0000102C", size=4),
            I(0x1014, "LitI2", "val=10", size=2),           # arm1: code
            I(0x1016, "FStI2", "mem=stack-100", size=4),
            I(0x101A, "FMemLdI2", "mem=stack+8.f0004", size=6),  # guard
            I(0x1020, "LitI2", "val=5", size=2),
            I(0x1022, "EqI2", size=2),
            I(0x1024, "BranchT", "to=00001058", size=4),   # guard -> exit
            I(0x1028, "Branch", "to=00001054", size=4),    # restart via hop
            I(0x102C, "FMemLdI2", "mem=stack+8.f0004", size=6),  # leg2
            I(0x1032, "LitI2", "val=2", size=2),
            I(0x1034, "EqI2", size=2),
            I(0x1036, "BranchF", "to=0000103E", size=4),
            I(0x103A, "Branch", "to=00001054", size=4),    # arm2: restart
            I(0x103E, "FMemLdI2", "mem=stack+8.f0004", size=6),  # leg3
            I(0x1044, "LitI2", "val=3", size=2),
            I(0x1046, "EqI2", size=2),
            I(0x1048, "BranchF", "to=00001058", size=4),   # skip -> exit
            I(0x104C, "LitI2", "val=30", size=2),          # arm3: OUT of body
            I(0x104E, "FStI2", "mem=stack-100", size=4),
            I(0x1052, "Branch", "to=00001058", size=4),    # arm3 -> exit
            I(0x1054, "Branch", "to=00001000", size=4),    # latch
            I(0x1058, "LitI2", "val=9", size=2),           # loop exit
            I(0x105A, "FStI2", "mem=stack-104", size=4),
            I(0x105E, "ExitProcStr", size=2),
        ]
        texts, _labels, stats, _m = run(instrs, 0x1000, 0x1060)
        joined = "\n".join(texts)
        # the ladder flattened: all three legs joined, including the
        # leg whose arm lives outside the loop body
        self.assertIn("ElseIf Me.f0004 = 2 Then", joined)
        self.assertIn("ElseIf Me.f0004 = 3 Then", joined)
        # the out-of-body =3 lane renders INLINE inside its ElseIf arm
        self.assertIn("stack-100 = 30", joined)

class ReviewFixTest(unittest.TestCase):
    """Regressions for the structuring.py review fixes: While polarity
    for BranchT headers, the cross-proc taken edge with the fall side
    leaving the loop, latch labels for silently-consumed back-edge
    trampolines, and the top-level scanner boundary rules."""

    def test_while_brancht_header_negates_condition(self):
        # A While-shaped loop whose header tests BranchT: the body is
        # the FALL side (cond false -> repeat), so the While line must
        # display the NEGATED condition.  The old code printed the raw
        # condition text and inverted the loop shape.
        instrs = [
            I(0x1000, "FMemLdI2", "mem=stack+8.f0004", size=6),  # header
            I(0x1006, "LitI2", "val=1", size=2),
            I(0x1008, "EqI2", size=2),
            I(0x100A, "BranchT", "to=00001018", size=4),
            I(0x100E, "LitI2", "val=5", size=2),
            I(0x1010, "FStI2", "mem=stack-100", size=4),
            I(0x1014, "Branch", "to=00001000", size=4),  # back edge
            I(0x1018, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1020)
        self.assertEqual(texts, [
            "While Me.f0004 <> 1",
            "stack-100 = 5",
            "Wend",
            "Exit Sub",
        ])
        self.assertEqual(stats["loops"], 1)

    def test_while_branchf_header_keeps_condition(self):
        # Polarity guard: the BranchF twin of the test above must be
        # untouched by the fix (regression check for _cond_text routing).
        instrs = [
            I(0x1000, "FMemLdI2", "mem=stack+8.f0004", size=6),
            I(0x1006, "LitI2", "val=1", size=2),
            I(0x1008, "EqI2", size=2),
            I(0x100A, "BranchF", "to=00001018", size=4),
            I(0x100E, "LitI2", "val=5", size=2),
            I(0x1010, "FStI2", "mem=stack-100", size=4),
            I(0x1014, "Branch", "to=00001000", size=4),
            I(0x1018, "ExitProcStr", size=2),
        ]
        texts, _labels, _stats, _m = run(instrs, 0x1000, 0x1020)
        self.assertEqual(texts, [
            "While Me.f0004 = 1",
            "stack-100 = 5",
            "Wend",
            "Exit Sub",
        ])

    def test_crossproc_taken_with_fall_leaving_loop_renders_goto(self):
        # Inside a Do loop, a conditional whose taken edge leaves the
        # procedure while its fall side leaves the loop: BOTH sides
        # depart.  The old _emit_cond_exit returned ("next", None) and
        # silently dropped the cross-proc edge; it must render the
        # out-of-proc GoTo after the fall side's guard (mirroring the
        # uncond cross-proc treatment), and count it separately.
        instrs = [
            I(0x1000, "LitI2", "val=0", size=2),              # header
            I(0x1002, "FStI2", "mem=stack-100", size=4),
            I(0x1006, "FMemLdI2", "mem=stack+8.f0004", size=6),
            I(0x100C, "LitI2", "val=1", size=2),
            I(0x100E, "EqI2", size=2),
            I(0x1010, "BranchF", "to=00001026", size=4),  # -> latch path
            I(0x1014, "FMemLdI2", "mem=stack+8.f0004", size=6),
            I(0x101A, "LitI2", "val=2", size=2),
            I(0x101C, "EqI2", size=2),
            I(0x101E, "BranchF", "to=00002000", size=4),  # cross-proc
            I(0x1022, "Branch", "to=00001030", size=4),   # fall leaves body
            I(0x1026, "LitI2", "val=3", size=2),
            I(0x1028, "FStI2", "mem=stack-104", size=4),
            I(0x102C, "Branch", "to=00001000", size=4),   # latch
            I(0x1030, "ExitProcStr", size=2),
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x1032)
        self.assertEqual(texts, [
            "Do",
            "stack-100 = 0",
            "If Me.f0004 = 1 Then",
            "If Me.f0004 = 2 Then",
            "Exit Do",
            "End If",
            "GoTo L_00002000",
            "End If",
            "stack-104 = 3",
            "Loop",
            "Exit Sub",
        ])
        # the cross-proc GoTo is counted separately from in-proc gotos
        # and needs no label (the label machinery is per-proc)
        self.assertEqual(stats["cross_proc_gotos"], 1)
        self.assertEqual(stats["gotos"], 0)
        self.assertEqual(labels, {})

    def test_goto_to_consumed_latch_labels_the_loop_line(self):
        # A GoTo that targets a latch consumed as a silent back-edge
        # trampoline must resolve: the label lands on the rendered Loop
        # close.  The old bare visited.add left block_first_stmt unset,
        # so run()'s label pass re-walked the consumed latch, appended a
        # spurious self-GoTo, and never attached the label.
        instrs = [
            I(0x1000, "FMemLdI2", "mem=stack+8.f0004", size=6),  # header
            I(0x1006, "LitI2", "val=1", size=2),
            I(0x1008, "EqI2", size=2),
            I(0x100A, "BranchF", "to=00001018", size=4),  # taken -> latch
            I(0x100E, "LitI2", "val=5", size=2),          # exit side
            I(0x1010, "FStI2", "mem=stack-100", size=4),
            I(0x1014, "Branch", "to=00001018", size=4),   # GoTo latch
            I(0x1018, "Branch", "to=00001000", size=4),   # latch
        ]
        texts, labels, stats, _m = run(instrs, 0x1000, 0x101C)
        self.assertEqual(texts, [
            "Do",
            "Loop Until Me.f0004 = 1",
            "stack-100 = 5",
            "GoTo L_00001018",
        ])
        # The GoTo's label attaches to the Loop Until line -- the
        # rendered back edge the GoTo meant -- and the label pass does
        # NOT re-walk the consumed latch into a spurious self-GoTo (the
        # old code appended a second "GoTo L_00001018" whose label
        # never attached).  0x100E is the orphan pass's own label for
        # the side block: the test-at-bottom path renders only the
        # busy-wait test and never walks it, so the block holding the
        # GoTo is emitted by the orphan pass, which labels every block
        # it renders.
        self.assertEqual(stats["gotos"], 1)
        self.assertEqual(labels, {1: [0x1018], 2: [0x100E]})


class ConditionScannerTest(unittest.TestCase):
    """The shared top-level scanner (_scan_top_level) and its callers:
    word-boundary rules at position 0 and connector refusal in
    _invert_cmp (the 2-char "Or" used to slip through the old
    cond_text[i:i+3] slice test and get comparison-inverted)."""

    def test_top_level_splits_requires_left_boundary(self):
        # A word at position 0 has no LEFT word boundary at all: no
        # spurious empty-lhs split, even defensively.
        self.assertEqual(list(structuring._top_level_splits("And b", "And")),
                         [])
        self.assertEqual(list(structuring._top_level_splits("a And b", "And")),
                         [("a", "b")])
        # not a split inside a longer identifier (word-bounded)
        self.assertEqual(
            list(structuring._top_level_splits("aAndroid", "And")), [])
        # strings are opaque to the scan
        self.assertEqual(
            list(structuring._top_level_splits('f("And") = 1', "And")), [])
        self.assertEqual(
            list(structuring._top_level_splits("(x = 0) Or (y = 0)", "Or")),
            [("(x = 0)", "(y = 0)")])

    def test_invert_cmp_refuses_top_level_compounds(self):
        # "Or" is 2 chars: the old i:i+3 slice never matched it, so an
        # Or compound was comparison-inverted ("x <> 1 Or y = 2" -- wrong
        # polarity) instead of refused to "Not (...)".
        self.assertIsNone(structuring._invert_cmp("x = 1 Or y = 2"))
        self.assertIsNone(structuring._invert_cmp("x = 1 And y = 2"))
        self.assertIsNone(structuring._invert_cmp("x = 1 Xor y = 2"))
        self.assertIsNone(structuring._invert_cmp("x = 1 Eqv y = 2"))
        self.assertIsNone(structuring._invert_cmp("x = 1 Imp y = 2"))
        # a lone top-level comparison still inverts
        self.assertEqual(structuring._invert_cmp("x = 1"), "x <> 1")
        self.assertEqual(structuring._invert_cmp("x <= 1"), "x > 1")
        self.assertEqual(structuring._invert_cmp("(x = 0) <> (y = 0)"),
                         "(x = 0) = (y = 0)")
        # and _wrap_not keeps the honest Not for refused compounds
        self.assertEqual(structuring._wrap_not("x = 1 Or y = 2"),
                         "Not (x = 1 Or y = 2)")

    def test_has_top_cmp(self):
        self.assertTrue(structuring._has_top_cmp("x <= 1"))
        self.assertTrue(structuring._has_top_cmp("x = 1"))
        self.assertTrue(structuring._has_top_cmp("(x = 0) <> (y = 0)"))
        # comparisons nested under a top-level connector are NOT
        # top-level (De Morgan territory, not display polarity)
        self.assertFalse(structuring._has_top_cmp("(x = 0) Or (y = 0)"))
        self.assertFalse(structuring._has_top_cmp("x + 1"))

    def test_scan_top_level_skips_strings_and_groups(self):
        # Characters inside string literals and paren groups are never
        # yielded; a ')' that CLOSES back to depth 0 is (inert: callers
        # match words/operators at the yielded index).  A ')' or '=' in
        # a literal therefore cannot leak to depth 0.
        self.assertEqual(
            [i for i, _ch in structuring._scan_top_level('f("a)b") Or c')],
            [0, 7, 8, 9, 10, 11, 12])
        # a string containing ')' does not break the depth bookkeeping:
        # the top-level comparison still inverts
        self.assertEqual(structuring._invert_cmp('x = "a)b"'),
                         'x <> "a)b"')
        # an operator inside a literal / paren group is not top-level
        self.assertFalse(structuring._has_top_cmp('f("= 1")'))
        # the top-level Or is still seen (quote- and paren-aware)
        self.assertIsNone(structuring._invert_cmp('f("a)b") Or c'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
