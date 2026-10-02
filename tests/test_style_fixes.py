"""Unit tests for the style-review fix batch.

Covers (see STYLE_REVIEW.md items #1-#7):
  #1  decl_stream.scan_scalar_usage + set_scalars (module scalar Dims)
  #2  ByVal prefix in signatures
  #3  runtime mappings: Asc/Str render as VB builtins; rtcRandomNext/
      rtcGetTimer/rtcMsgBox/rtcRandomize/rtcDoEvents deliberately stay
      raw (follow-up decision, disasm traceability)
  #4  redundant tail Exit Sub/Exit Function removal
  #5  implicit CSng promotion drop on pure numeric literals
  #6  local frame-slot Dim inference (typed / Variant tie / fixed string /
      For loop variable via StackMachine.loop_var_types)
  #7  parameter As-type inference (pointee deref ops, CVarRef VT codes,
      CStr2Ansi marshaling)
  #9  call-site ABI voting: copy/body/forward push idioms -> ByRef/ByVal
      modifiers + pointee types (StackMachine.call_votes, _tally_votes,
      _propagate_forward_types); F* direct loads are pointer-width
      artifacts, never param type evidence
  #12 AryLock/AryUnlock lifecycle suppression (no statement, no phantom
      Dim)
  #13 CodeView label alias FMemLdStr->FMemLd4 (generic 4-byte module
      load; MS's own NB09 name, zero string consumers in PAL)
  #14 VCall receiver-chain register model ([ebp-0x50], never the eval
      stack) + two-pass Function/Sub result inference
  #15 Declare statement block + disasm Declare-table dump

Run:  .venv/bin/python -m unittest tests.test_style_fixes -q
"""
import os
import sys
import unittest
from collections import namedtuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import decl_stream
import pseudo_code
import stack_ir
from stack_ir import StackMachine  # noqa: E402


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


# ---------------------------------------------------------------------------
# #3 runtime builtins + #5 CSng literal drop
# ---------------------------------------------------------------------------

class RuntimeRenderTest(unittest.TestCase):
    def test_rnd_stays_raw(self):
        # rtcRandomNext (=Rnd) deliberately NOT mapped: the raw VB40032
        # name is kept for disasm traceability (follow-up decision).
        # The LitVar_Missing optional arg still filters out (RUNTIME_SPECS
        # supplies the arg count); 0 args render with empty parens.
        out = run([
            Instr(0x00, "LitVar_Missing", "mem=stack-152"),
            Instr(0x04, "ImpAdCall", "call=VB40032.rtcRandomNext@0040100C"),
            Instr(0x08, "FStFPR4", "mem=stack-168"),
        ], arg_map={"VB40032.rtcRandomNext": 1})
        self.assertEqual(out, ["stack-168 = VB40032.rtcRandomNext()"])

    def test_rnd_with_real_arg(self):
        out = run([
            Instr(0x00, "LitI2", "val=3"),
            Instr(0x04, "ImpAdCall", "call=VB40032.rtcRandomNext@0040100C"),
            Instr(0x08, "FStFPR4", "mem=stack-168"),
        ], arg_map={"VB40032.rtcRandomNext": 1})
        self.assertEqual(out, ["stack-168 = VB40032.rtcRandomNext(3)"])

    def test_timer_stays_raw(self):
        out = run([
            Instr(0x00, "ImpAdCall", "call=VB40032.rtcGetTimer@00401048"),
            Instr(0x04, "FStFPR4", "mem=stack-168"),
        ], arg_map={"VB40032.rtcGetTimer": 0})
        self.assertEqual(out, ["stack-168 = VB40032.rtcGetTimer()"])

    def test_randomize_stays_raw_call(self):
        # rtcRandomize (=Randomize) deliberately NOT mapped; its result
        # is unused everywhere in PAL, so the deferred effect flushes as
        # a "Call ..." statement at its origin.  CVarR4 is transparent
        # plumbing: the stack keeps the pre-conversion text (stack-168).
        out = run([
            Instr(0x00, "FLdFPR4", "mem=stack-168"),
            Instr(0x04, "CVarR4", "mem=stack-164"),
            Instr(0x08, "ImpAdCall", "call=VB40032.rtcRandomize@0040104E"),
        ], arg_map={"VB40032.rtcRandomize": 1})
        self.assertEqual(out, ["Call VB40032.rtcRandomize(stack-168)"])

    def test_doevents_stays_raw_call(self):
        out = run([
            Instr(0x00, "ImpAdCall", "call=VB40032.rtcDoEvents@0040103C"),
        ], arg_map={"VB40032.rtcDoEvents": 0})
        self.assertEqual(out, ["Call VB40032.rtcDoEvents()"])

    def test_msgbox_str_asc_mappings(self):
        base = {"VB40032.rtcMsgBox": 3, "VB40032.rtcStrFromVar": 1,
                "VB40032.rtcAnsiValueBstr": 1}
        out = run([
            Instr(0x00, "LitI2", "val=1"),
            Instr(0x04, "LitI2", "val=2"),
            Instr(0x08, "LitI2", "val=3"),
            Instr(0x0C, "ImpAdCall", "call=VB40032.rtcMsgBox@00401006"),
            Instr(0x10, "FStI2", "mem=stack-136"),
        ], arg_map=base)
        self.assertEqual(out, ["stack-136 = VB40032.rtcMsgBox(3, 2, 1)"])
        out = run([
            Instr(0x00, "FLdI4", "mem=stack+12"),
            Instr(0x04, "ImpAdCallAd", "call=VB40032.rtcStrFromVar@0040102A"),
            Instr(0x08, "FStStrNoPop", "mem=stack-140"),
            Instr(0x0C, "LitStr", "text='x'"),
            Instr(0x10, "ConcatStr", "-"),
            Instr(0x14, "FStStr", "mem=stack-136"),
        ], arg_map=base)
        self.assertEqual(out, ["stack-136 = Str(a0) & 'x'"])
        out = run([
            Instr(0x00, "LitStr", "text='A'"),
            Instr(0x04, "ImpAdCallAd",
                  "call=VB40032.rtcAnsiValueBstr@0040101E"),
            Instr(0x08, "FStI2", "mem=stack-136"),
        ], arg_map=base)
        self.assertEqual(out, ["stack-136 = Asc('A')"])

    def test_unknown_runtime_unchanged(self):
        out = run([
            Instr(0x00, "ImpAdCall", "call=VB40032.rtcMystery@0040FFFF"),
            Instr(0x04, "FStI4", "mem=stack-136"),
        ], arg_map={"VB40032.rtcMystery": 0})
        self.assertEqual(out, ["stack-136 = VB40032.rtcMystery()"])


class CsngLiteralDropTest(unittest.TestCase):
    def test_literal_promotion_dropped(self):
        # play_theurgy_anim @0040A64C: rtcRandomNext * CSng(6) ->
        # rtcRandomNext * 6 (rtcRandomNext stays raw; the CSng literal
        # promotion is still dropped).
        out = run([
            Instr(0x00, "ImpAdCall", "call=VB40032.rtcRandomNext@0040100C"),
            Instr(0x04, "LitI2", "val=6"),
            Instr(0x08, "FnCSngUI1", "-"),
            Instr(0x0C, "MulR4", "-"),
            Instr(0x10, "FnIntR8", "-"),
            Instr(0x14, "FStI2", "mem=stack-136"),
        ], arg_map={"VB40032.rtcRandomNext": 0})
        self.assertEqual(out, ["stack-136 = Int(VB40032.rtcRandomNext() * 6)"])

    def test_variable_promotion_kept(self):
        # Non-literal operands keep the explicit conversion (the deferred
        # half of review #5: needs expression type propagation).
        out = run([
            Instr(0x00, "FLdI2", "mem=stack-136"),
            Instr(0x04, "FnCSngUI1", "-"),
            Instr(0x08, "FStR4", "mem=stack-140"),
        ])
        self.assertEqual(out, ["stack-140 = CSng(stack-136)"])

    def test_zero_and_negative_literals(self):
        out = run([
            Instr(0x00, "LitI4", "val=0"),
            Instr(0x04, "FnCSngI4", "-"),
            Instr(0x08, "FStR4", "mem=stack-140"),
        ])
        self.assertEqual(out, ["stack-140 = 0"])


# ---------------------------------------------------------------------------
# #4 tail exit removal (pseudo_code._postprocess_stmts tail drop)
# ---------------------------------------------------------------------------

class _S(object):
    def __init__(self, va, delta, text, order=0):
        self.va = va
        self.indent_delta = delta
        self.text = text
        self.order = order


class TailExitTest(unittest.TestCase):
    def _post(self, stmts, labels, keyword="Sub", ret_type=None):
        machine = stack_ir.StackMachine()
        machine.exit_keyword = "Exit %s" % keyword
        if ret_type:
            machine.result_slot = -134
            machine.result_name = "f"
        return pseudo_code._postprocess_stmts(
            list(stmts), labels, 0x1000, 0x2000, keyword, "f", ret_type,
            machine, set())

    def test_tail_exit_sub_dropped(self):
        stmts = [_S(0x1004, 0, "Exit Sub")]
        out, _ = self._post(stmts, {})
        self.assertEqual([s.text for s in out], [])

    def test_tail_exit_function_dropped(self):
        stmts = [_S(0x1004, 0, "Exit Function")]
        out, _ = self._post(stmts, {}, keyword="Function", ret_type="Integer")
        self.assertEqual([s.text for s in out], [])

    def test_label_anchored_tail_exit_kept(self):
        # A live GoTo targets the exit (label survived _prune_labels):
        # the statement must stay or the jump has no target.
        stmts = [_S(0x1004, 0, "GoTo L_00001004"),
                 _S(0x1004, 0, "Exit Sub")]
        out, labels = self._post(stmts, {1: [0x1004]})
        self.assertEqual([s.text for s in out],
                         ["GoTo L_00001004", "Exit Sub"])

    def test_mid_body_exit_kept(self):
        # A Select no-match fallthrough barrier is never last (End Select
        # follows) -- but any non-last exit stays regardless.
        stmts = [_S(0x1002, 0, "Exit Sub"),
                 _S(0x1004, -2, "End Select")]
        out, _ = self._post(stmts, {})
        self.assertEqual([s.text for s in out], ["Exit Sub", "End Select"])

    def test_structural_last_stmt_not_dropped(self):
        stmts = [_S(0x1004, -1, "Wend")]
        out, _ = self._post(stmts, {})
        self.assertEqual([s.text for s in out], ["Wend"])


# ---------------------------------------------------------------------------
# #6 local Dim inference + #7 parameter As inference
# ---------------------------------------------------------------------------

class LocalDimTest(unittest.TestCase):
    def _machine(self, loop_vars=None, result_slot=None):
        m = stack_ir.StackMachine()
        m.loop_var_types = dict(loop_vars or {})
        m.result_slot = result_slot
        return m

    def test_typed_variant_and_fixed_string(self):
        instrs = [
            Instr(0x00, "LitI2", "val=10"),
            Instr(0x04, "FStI2", "mem=stack-136"),      # j: Integer
            Instr(0x08, "FLdRfVar", "mem=stack-196"),
            Instr(0x0C, "LdFixedStr", "len=32"),        # fixed string
            Instr(0x10, "LitI2", "val=1"),
            Instr(0x14, "FStI2", "mem=stack-140"),      # renders too
        ]
        stmts = [_S(0x20, 0, "stack-136 = 10"),
                 _S(0x24, 0, "Call f(stack-196, stack-140)")]
        lines = pseudo_code._local_dim_lines(instrs, stmts, self._machine())
        self.assertEqual(lines, [
            "    Dim stack-136 As Integer",
            "    Dim stack-140 As Integer",
            "    Dim stack-196 As String * 32",
        ])

    def test_conflicting_stores_render_variant(self):
        # pub_164 stack-168 shape: FStFPR4 then FStI4 on one offset --
        # a genuine tie, no As clause (VB4 default Variant).
        instrs = [
            Instr(0x00, "LitI2", "val=1"),
            Instr(0x04, "FStFPR4", "mem=stack-168"),
            Instr(0x08, "LitI2", "val=2"),
            Instr(0x0C, "FStI4", "mem=stack-168"),
        ]
        stmts = [_S(0x10, 0, "stack-168 = 1"),
                 _S(0x14, 0, "stack-168 = 2")]
        lines = pseudo_code._local_dim_lines(instrs, stmts, self._machine())
        self.assertEqual(lines, ["    Dim stack-168"])

    def test_loop_var_type_from_machine(self):
        # The For end expression is longer than any fixed look-back, so
        # the type comes from StackMachine.loop_var_types (recorded by
        # _loop_start when it pops the var ref), not from a scan.
        instrs = [Instr(0x00, "FLdRfVar", "mem=stack-134")]
        stmts = [_S(0x10, +1, "For stack-134 = 0 To Me.f0824(0).f0010")]
        m = self._machine(loop_vars={"stack-134": "Integer"})
        lines = pseudo_code._local_dim_lines(instrs, stmts, m)
        self.assertEqual(lines, ["    Dim stack-134 As Integer"])

    def test_result_slot_not_dimmed(self):
        # Function result slot renders as the proc name (substituted),
        # never as stack-134; a real local at -136 still Dims.
        instrs = [Instr(0x00, "LitI2", "val=1"),
                  Instr(0x04, "FStI2", "mem=stack-136")]
        stmts = [_S(0x10, 0, "f = stack-136")]
        lines = pseudo_code._local_dim_lines(
            instrs, stmts, self._machine(result_slot=-134))
        self.assertEqual(lines, ["    Dim stack-136 As Integer"])

    def test_unrendered_mechanism_slot_not_dimmed(self):
        # CStr2Ansi temps / For ctl slots never appear in statements.
        instrs = [Instr(0x00, "FLdRfVar", "mem=stack-144"),
                  Instr(0x04, "CStr2Ansi", "-")]
        stmts = [_S(0x10, 0, "Call f(a0)")]
        lines = pseudo_code._local_dim_lines(instrs, stmts, self._machine())
        self.assertEqual(lines, [])


class DerefParamTypeTest(unittest.TestCase):
    """#7/#9: pointee types come from DEREF evidence only.

    A param slot holds a POINTER under the all-reference ABI, so a direct
    F* load's suffix names the pointer WIDTH (FLdI4 stack+12 forwards the
    reference), never the pointee -- no As clause from F* for any param.
    """

    def _types(self, instrs, nargs=1):
        return pseudo_code._deref_param_types(
            [Instr(p, l, o) for p, l, o in instrs], nargs)

    def test_fldi4_pointer_width_is_no_evidence(self):
        # play_theurgy_anim a0 pre-#9: FLdI4 stack+12 -> "ByVal As Long"
        # was the width artifact; the real pointee (Integer) comes from
        # the forwarding chain, not from this load.
        self.assertEqual(
            self._types([(0x00, "FLdI4", "mem=stack+12")]), [None])

    def test_ildi4_three_way_ambiguous_no_type(self):
        # ILdI4 through a param may read a Long, fetch a BSTR or a UDT
        # pointer -- untyped, honestly.
        self.assertEqual(
            self._types([(0x00, "ILdI4", "mem=stack+12")]), [None])

    def test_fldstr_on_param_is_pointer_load(self):
        # FLdStr stack+12 loads the slot's 4-byte pointer, not a string
        # value; the look-back patterns below are the string proofs.
        self.assertEqual(
            self._types([(0x00, "FLdStr", "mem=stack+12")]), [None])

    def test_deref_i2(self):
        self.assertEqual(
            self._types([(0x00, "ILdI2", "mem=stack+12")]), ["Integer"])

    def test_deref_store_i2(self):
        # Assignment to a param writes through the pointer: Integer.
        self.assertEqual(
            self._types([(0x00, "IStI2", "mem=stack+12")]), ["Integer"])

    def test_deref_r8(self):
        self.assertEqual(
            self._types([(0x00, "ILdR8", "mem=stack+12")]), ["Double"])

    def test_string_via_cstr2ansi(self):
        # open_file a0: ILdI4 a0; FLdRfVar tmp; CStr2Ansi -> String.
        self.assertEqual(
            self._types([(0x00, "ILdI4", "mem=stack+12"),
                         (0x04, "FLdRfVar", "mem=stack-144"),
                         (0x08, "CStr2Ansi", "-")]),
            ["String"])

    def test_string_via_cvarref_vt_code(self):
        # trim_string a0: FLdI4 a0; CVarRef type=4008 (VT_BYREF|VT_BSTR).
        self.assertEqual(
            self._types([(0x00, "FLdI4", "mem=stack+12"),
                         (0x04, "CVarRef", "mem=stack-156 type=4008")]),
            ["String"])

    def test_cvarref_i2_code(self):
        self.assertEqual(
            self._types([(0x00, "FLdI4", "mem=stack+12"),
                         (0x04, "CVarRef", "mem=stack-220 type=4002")]),
            ["Integer"])

    def test_cvarref_unknown_code_no_type(self):
        self.assertEqual(
            self._types([(0x00, "FLdI4", "mem=stack+12"),
                         (0x04, "CVarRef", "mem=stack-220 type=4005")]),
            [None])


class ParamVoteTest(unittest.TestCase):
    """#9: call-site push-idiom voting at the stack-machine level."""

    def _votes(self, instrs, callee="pub_callee", nargs=1, proc="pub_caller"):
        sm = StackMachine()
        sm.param_map = dict(PARAM_MAP)
        sm.arg_map = {callee: nargs}
        sm.proc_name = proc
        sink = {}
        sm.call_votes = sink
        for instr in instrs:
            sm.process(instr)
        sm.flush_leftovers(instrs[-1].pos if instrs else 0)
        return sink

    def test_copy_idiom_votes_byval_with_type(self):
        # FLdI2 var + PopTmpLdAd2 = value copied into a temp -> ByVal,
        # typed by the copied variable's load suffix (pub_132's
        # startFrame: FMemLdI2 f0314 + PopTmpLdAd2).
        sink = self._votes([
            Instr(0x00, "FLdI2", "mem=stack-140"),
            Instr(0x04, "PopTmpLdAd2", "mem=stack-136"),
            Instr(0x08, "ImpAdCall", "call=pub_callee@0041C69C"),
        ])
        self.assertEqual(sink[(0x08, 0)],
                         ("pub_callee", "copy", "Integer",
                          "pub_caller", None))

    def test_module_load_copy(self):
        # The startFrame copy itself: a module scalar value load
        # materialized into a temp (0041A550).
        sink = self._votes([
            Instr(0x00, "FMemLdI2", "mem=stack+8.f0314"),
            Instr(0x04, "PopTmpLdAd2", "mem=stack-168"),
            Instr(0x08, "ImpAdCall", "call=pub_callee@0041C69C"),
        ])
        self.assertEqual(sink[(0x08, 0)][1:3], ("copy", "Integer"))

    def test_body_push_votes_byref(self):
        # FLdRfVar pushes the variable's own address (pub_132's magicIdx).
        sink = self._votes([
            Instr(0x00, "FLdRfVar", "mem=stack-134"),
            Instr(0x04, "ImpAdCall", "call=pub_callee@0041C69C"),
        ])
        self.assertEqual(sink[(0x04, 0)][1], "body")

    def test_param_forward_abstains_and_links(self):
        # FLdI4 stack+12 pushes the param slot's pointer onward: no
        # modifier vote, but an edge (caller param 0 -> callee arg 0)
        # for pointee propagation (pub_132.a0 -> pub_013.a0).
        sink = self._votes([
            Instr(0x00, "FLdI4", "mem=stack+12"),
            Instr(0x04, "ImpAdCall", "call=pub_callee@0041C69C"),
        ])
        self.assertEqual(sink[(0x04, 0)],
                         ("pub_callee", "forward", None,
                          "pub_caller", 0))

    def test_widening_conversion_is_not_a_copy(self):
        # FLdI2 var; CI4I2; PopTmpLdAd4 materializes a WIDENED temp
        # (the false ByVal that first hit pub_066.a3/pub_100.a2 at
        # 0041294A/00424D6C before the exclusion): abstain.
        sink = self._votes([
            Instr(0x00, "FLdI2", "mem=stack-150"),
            Instr(0x04, "CI4I2", "-"),
            Instr(0x08, "PopTmpLdAd4", "mem=stack-172"),
            Instr(0x0C, "ImpAdCall", "call=pub_callee@0041C69C"),
        ])
        self.assertEqual(sink[(0x0C, 0)][1], "expr")

    def test_expression_temp_abstains(self):
        sink = self._votes([
            Instr(0x00, "FLdI2", "mem=stack-140"),
            Instr(0x04, "LitI2", "val=5"),
            Instr(0x08, "AddI2", "-"),
            Instr(0x0C, "PopTmpLdAd2", "mem=stack-136"),
            Instr(0x10, "ImpAdCall", "call=pub_callee@0041C69C"),
        ])
        self.assertEqual(sink[(0x10, 0)][1], "expr")

    def test_literal_temp_abstains(self):
        sink = self._votes([
            Instr(0x00, "LitI2", "val=35"),
            Instr(0x04, "PopTmpLdAd2", "mem=stack-174"),
            Instr(0x08, "ImpAdCall", "call=pub_callee@0041C69C"),
        ])
        self.assertEqual(sink[(0x08, 0)][1], "expr")

    def test_arg_positions(self):
        # TOS = ARG1: pushed last.  [body, copy] -> pos 0 body, pos 1 copy.
        sink = self._votes([
            Instr(0x00, "FLdI2", "mem=stack-140"),
            Instr(0x04, "PopTmpLdAd2", "mem=stack-136"),
            Instr(0x08, "FLdRfVar", "mem=stack-134"),
            Instr(0x0C, "ImpAdCall", "call=pub_callee@0041C69C"),
        ], nargs=2)
        self.assertEqual(sink[(0x0C, 0)][1], "body")
        self.assertEqual(sink[(0x0C, 1)][1], "copy")

    def test_external_calls_do_not_vote(self):
        # Only internal (arg_map) callees vote: rtc*/Pal.*/Win32 skip.
        # rtcMsgBox takes 3 args (prompt/buttons/title) per RUNTIME_SPECS.
        sink = self._votes([
            Instr(0x00, "LitStr", "text='p'"),
            Instr(0x04, "LitI2", "val=1"),
            Instr(0x08, "LitStr", "text='t'"),
            Instr(0x0C, "ImpAdCall", "call=VB40032.rtcMsgBox@00401006"),
        ])
        self.assertEqual(sink, {})

    def test_reexecution_stays_idempotent(self):
        # The structurer re-walks paths; (va, pos) keyed votes must not
        # duplicate or flip.
        ins = [Instr(0x00, "FLdRfVar", "mem=stack-134"),
               Instr(0x04, "ImpAdCall", "call=pub_callee@0041C69C")]
        sm = StackMachine()
        sm.param_map = dict(PARAM_MAP)
        sm.arg_map = {"pub_callee": 1}
        sm.proc_name = "pub_caller"
        sink = {}
        sm.call_votes = sink
        for _ in range(3):
            for instr in ins:
                sm.process(instr)
            sm.flush_leftovers(0x04)
        self.assertEqual(len(sink), 1)


class VoteTallyTest(unittest.TestCase):
    """#9: pure vote tally + pointee propagation."""

    def _sink(self, *records):
        # records: (va, pos, callee, kind, hint, caller, src_param)
        return dict(((va, pos),
                     (callee, kind, hint, caller, src_param))
                    for va, pos, callee, kind, hint, caller, src_param
                    in records)

    def test_copy_wins_over_body(self):
        # pub_060.attack: copy x3 + body x2 -> ByVal (the compiler's
        # identity optimization makes body votes weaker than copies).
        sink = self._sink(
            (0x100, 0, "pub_x", "copy", "Integer", "pub_a", None),
            (0x200, 0, "pub_x", "copy", "Integer", "pub_b", None),
            (0x300, 0, "pub_x", "body", None, "pub_c", None),
            (0x400, 0, "pub_x", "body", None, "pub_d", None),
        )
        kinds, hints, _fw = pseudo_code._tally_votes(
            sink, {"pub_x": 1})
        self.assertEqual(kinds, {"pub_x": ["ByVal"]})
        self.assertEqual(hints, {("pub_x", 0): {"Integer": 2}})

    def test_no_votes_default_byref(self):
        kinds, hints, fw = pseudo_code._tally_votes({}, {"pub_x": 2})
        self.assertEqual(kinds, {"pub_x": ["ByRef", "ByRef"]})
        self.assertEqual(hints, {})
        self.assertEqual(fw, {})

    def test_expr_only_stays_byref(self):
        sink = self._sink((0x100, 0, "pub_x", "expr", None, "pub_a", None))
        kinds, _h, _f = pseudo_code._tally_votes(sink, {"pub_x": 1})
        self.assertEqual(kinds, {"pub_x": ["ByRef"]})

    def test_forward_edges_collected(self):
        sink = self._sink(
            (0x100, 0, "pub_callee", "forward", None, "pub_caller", 1),
        )
        _k, _h, fw = pseudo_code._tally_votes(sink, {"pub_callee": 1})
        self.assertEqual(fw, {("pub_callee", 0): {("pub_caller", 1)}})

    def test_pointee_propagation_both_directions(self):
        # pub_013.a0 typed Integer by its body's ILdI2; pub_132.a0 is
        # only ever forwarded to it -> pulls Integer through the edge.
        forwards = {("pub_013", 0): {("pub_132", 0)}}
        types = {("pub_013", 0): "Integer"}
        pseudo_code._propagate_forward_types(types, forwards)
        self.assertEqual(types[("pub_132", 0)], "Integer")

    def test_pointee_propagation_reverse_direction(self):
        # The caller side is typed (deref in its body) and the callee
        # side only forwarded: types flow backwards too.
        forwards = {("pub_callee", 0): {("pub_caller", 0)}}
        types = {("pub_caller", 0): "String"}
        pseudo_code._propagate_forward_types(types, forwards)
        self.assertEqual(types[("pub_callee", 0)], "String")

    def test_pointee_conflict_tie_stays_untyped(self):
        forwards = {("pub_c", 0): {("pub_a", 0), ("pub_b", 0)}}
        types = {("pub_a", 0): "Integer", ("pub_b", 0): "Long"}
        pseudo_code._propagate_forward_types(types, forwards)
        self.assertNotIn(("pub_c", 0), types)

    def test_chain_two_hops(self):
        # a -> b -> c chain: c typed, both others pull it.
        forwards = {("pub_b", 0): {("pub_a", 0)},
                    ("pub_c", 0): {("pub_b", 0)}}
        types = {("pub_c", 0): "Integer"}
        pseudo_code._propagate_forward_types(types, forwards)
        self.assertEqual(types[("pub_b", 0)], "Integer")
        self.assertEqual(types[("pub_a", 0)], "Integer")


class ParamSignatureTest(unittest.TestCase):
    """#2/#9: signatures spell out BOTH modifiers; the modifier and the
    As type come from the vote tables (no table -> VB4 default ByRef)."""

    def _sig(self, param_kinds=None, param_types=None):
        instrs = [Instr(0x00, "FLdI4", "mem=stack+12"),
                  Instr(0x04, "ExitProcStr", "-")]
        import word_disasm
        real_build = pseudo_code.build_instrs
        pseudo_code.build_instrs = (
            lambda pal, analysis, index: (0x00, 0x08, list(instrs)))
        try:
            base = pseudo_code._prepare_proc(
                None, {"method_stubs": {}}, 0, "pub_test",
                {"pub_test": 1}, param_kinds=param_kinds,
                param_types=param_types)
        finally:
            pseudo_code.build_instrs = real_build
        return base[3]

    def test_vote_tables_drive_the_signature(self):
        self.assertEqual(
            self._sig({"pub_test": ["ByVal"]}, {("pub_test", 0): "Integer"}),
            "Sub pub_test(ByVal a0 As Integer)")

    def test_default_is_byref(self):
        self.assertEqual(self._sig(), "Sub pub_test(ByRef a0)")

    def test_byref_with_type(self):
        self.assertEqual(
            self._sig({"pub_test": ["ByRef"]}, {("pub_test", 0): "String"}),
            "Sub pub_test(ByRef a0 As String)")


# ---------------------------------------------------------------------------
# #14: VCall receiver-chain register model + result inference
# ---------------------------------------------------------------------------

class VCallReceiverTest(unittest.TestCase):
    """#14: the receiver chain (ImpAdLdPr/MemLdRf/NewIfNull*/FStAdNoPop/
    FLdPrThis) walks the [ebp-0x50] register, never the eval stack
    (handler-verified).  VCall renders receiver.method(args) with the
    drain collecting exactly the pushed arguments -- no hardcoded "Me."
    prefix, no receiver-as-trailing-arg artifact."""

    def test_object_chain_sets_receiver(self):
        sm = StackMachine()
        sm.param_map = dict(PARAM_MAP)
        for i in (Instr(0x00, "ImpAdLdPr", "global=00000878"),
                  Instr(0x06, "MemLdRf", "mem=0000"),
                  Instr(0x0A, "NewIfNullPr", "descriptor=00000000")):
            sm.process(i)
        self.assertEqual(sm.receiver, "Me.f0878.f0000")
        self.assertEqual([e.text for e in sm.stack], [])

    def test_fldprthis_chain_renders_me_prefix(self):
        sm = StackMachine()
        sm.param_map = dict(PARAM_MAP)
        sm.process(Instr(0x00, "FLdPrThis", "-"))
        sm.process(Instr(0x02, "VCallHresult", "vcall=0038@00403180"))
        self.assertEqual([e.text for e in sm.stack],
                         ["Me.method_0038()"])

    def test_vcall_args_exclude_receiver(self):
        # Sub_Main 0041AA12 shape: one pushed ref, then the object chain.
        sm = StackMachine()
        sm.param_map = dict(PARAM_MAP)
        for i in (Instr(0x00, "FLdRfVar", "mem=stack-180"),
                  Instr(0x04, "ImpAdLdPr", "global=00000878"),
                  Instr(0x0A, "MemLdRf", "mem=0000"),
                  Instr(0x0E, "NewIfNullPr", "descriptor=00000000"),
                  Instr(0x14, "VCallHresult", "vcall=0038@00403180")):
            sm.process(i)
        self.assertEqual([e.text for e in sm.stack],
                         ["Me.f0878.f0000.method_0038(stack-180)"])

    def test_fstadnopop_chain_uses_last_receiver(self):
        # The 002C sites: obj1 chain + FStAdNoPop side-store, then the
        # obj2 chain -- the register ends at obj2, and neither object
        # ever reaches the eval stack.
        sm = StackMachine()
        sm.param_map = dict(PARAM_MAP)
        for i in (Instr(0x00, "ImpAdLdPr", "global=00000878"),
                  Instr(0x06, "MemLdRf", "mem=0000"),
                  Instr(0x0A, "NewIfNullAd", "descriptor=00000000"),
                  Instr(0x10, "FStAdNoPop", "mem=stack-320"),
                  Instr(0x14, "ImpAdLdPr", "global=0000087C"),
                  Instr(0x1A, "MemLdRf", "mem=0000"),
                  Instr(0x1E, "NewIfNullPr", "descriptor=00403244"),
                  Instr(0x24, "VCallHresult", "vcall=002C@00403170")):
            sm.process(i)
        self.assertEqual([e.text for e in sm.stack],
                         ["Me.f087C.f0000.method_002C()"])
        self.assertEqual(sm.statements, [])

    def test_udt_memldrf_keeps_eval_behavior(self):
        # Outside a receiver chain, MemLdRf still pops/pushes (the
        # Me-relative UDT-array member idiom, 135 sites).
        sm = StackMachine()
        sm.param_map = dict(PARAM_MAP)
        sm.process(Instr(0x00, "FLdI2", "mem=stack-136"))
        sm.process(Instr(0x04, "MemLdRf", "mem=0002"))
        self.assertEqual([e.text for e in sm.stack],
                         ["stack-136.f0002"])


class VCallModeInferenceTest(unittest.TestCase):
    """#14 pass 1: the VCallHresult handler pushes no result itself, so a
    speculatively pushed result that survives to a statement boundary was
    never consumed (Sub site, no push in pass 2), while one that gets
    popped (Function site) keeps the push."""

    def _run(self, instrs, arg_map):
        sm = StackMachine()
        sm.param_map = dict(PARAM_MAP)
        sm.arg_map = arg_map
        sm.vcall_sink = {}
        for i in instrs:
            sm.process(i)
        sm.settle_vcall_sites()
        return sm

    def test_unconsumed_result_marks_sub(self):
        # Sub_Main 0041AA12 shape: the vcall result feeds nothing -- the
        # next strict call consumes only its own argument.
        sm = self._run([
            Instr(0x00, "FLdRfVar", "mem=stack-180"),
            Instr(0x04, "ImpAdLdPr", "global=00000878"),
            Instr(0x0A, "MemLdRf", "mem=0000"),
            Instr(0x0E, "NewIfNullPr", "descriptor=00000000"),
            Instr(0x14, "VCallHresult", "vcall=0038@00403180"),
            Instr(0x1C, "FLdI4", "mem=stack-180"),
            Instr(0x20, "ImpAdCallAd", "call=Pal.InitDSound@004176C8"),
        ], {"Pal.InitDSound": 1})
        self.assertEqual(sm.vcall_sink, {0x14: False})

    def test_consumed_result_marks_function(self):
        # priv_163 0040F27A shape: EqI4 pops the vcall result -- Function.
        sm = self._run([
            Instr(0x00, "FLdI4", "mem=stack-208"),
            Instr(0x04, "FLdRfVar", "mem=stack-212"),
            Instr(0x08, "FLdPrThis", "-"),
            Instr(0x0A, "VCallHresult", "vcall=0038@00403180"),
            Instr(0x12, "FLdI4", "mem=stack-212"),
            Instr(0x16, "EqI4", "-"),
        ], {})
        self.assertEqual(sm.vcall_sink, {0x0A: True})

    def test_pass2_sub_site_emits_call_statement(self):
        sm = StackMachine()
        sm.param_map = dict(PARAM_MAP)
        sm.vcall_modes = {0x14: False}
        for i in (Instr(0x00, "FLdRfVar", "mem=stack-180"),
                  Instr(0x04, "ImpAdLdPr", "global=00000878"),
                  Instr(0x0A, "MemLdRf", "mem=0000"),
                  Instr(0x0E, "NewIfNullPr", "descriptor=00000000"),
                  Instr(0x14, "VCallHresult", "vcall=0038@00403180")):
            sm.process(i)
        self.assertEqual(len(sm.stack), 0)
        self.assertEqual([s.text for s in sm.statements],
                         ["Call Me.f0878.f0000.method_0038(stack-180)"])


# ---------------------------------------------------------------------------
# #15: Declare statement block
# ---------------------------------------------------------------------------

class _StubDec(object):
    def __init__(self, entries):
        self.entries = entries
        self.declare_va = 0x004106A0


class DeclareBlockTest(unittest.TestCase):
    """#15: render the parsed Declare table as VB statements.  With no
    call-site evidence (empty analysis) every function defaults to Sub
    and every typed param slot to As Any -- the variant census and the
    push-label vote upgrade them on the real binary."""

    def test_block_lines_shape(self):
        import declares as declares_mod
        dec = _StubDec([
            ("copymen", "Pal", 0, 0, 0x00E8),
            ("_hread", "kernel32", 0, 0, 0x0120),
            ("ShowCursor", "winmm", 0, 0, 0x08AC),
        ])
        import stack_ir
        import declare_specs
        # arity: copymen 3 / _hread 3 via the real spec tables
        lines = declares_mod.declare_block_lines(
            dec, {"paths": [], "entries": {}, "labels": {}})
        joined = "\n".join(lines)
        self.assertIn('Declare Sub Pal.copymen Lib "Pal" Alias "copymen" '
                      "(ByVal a0 As Any, ByVal a1 As Any, ByVal a2 As Any)",
                      lines)
        self.assertIn('Declare Sub kernel32._hread Lib "kernel32" '
                      'Alias "_hread" (ByVal a0 As Any, ByVal a1 As Any, '
                      "ByVal a2 As Any)", lines)
        self.assertIn('Declare Sub winmm.ShowCursor Lib "winmm" '
                      'Alias "ShowCursor" (ByVal a0 As Any)', lines)

    def test_classify_push(self):
        import declares as declares_mod
        self.assertEqual(declares_mod._classify_push("FLdI2"),
                         ("val", "Integer"))
        self.assertEqual(declares_mod._classify_push("LitI4"),
                         ("val", "Long"))
        self.assertEqual(declares_mod._classify_push("FLdRfVar"),
                         ("ref", None))
        self.assertEqual(declares_mod._classify_push("LitStr"),
                         ("str", "String"))
        self.assertIsNone(declares_mod._classify_push("Bogus"))


# ---------------------------------------------------------------------------
# #12/#13: lifecycle suppression + FMemLd4 label alias
# ---------------------------------------------------------------------------

class LifecycleSuppressionTest(unittest.TestCase):
    """#12: AryLock/AryUnlock are compiler lifecycle opcodes (pin/unpin
    movable array memory around bare-array pointer args to Declare
    functions); VB4 source cannot spell them, so no statement may be
    emitted and the locked temp slot must stay undeclared (#6 invariant
    then drops the phantom bare Dim)."""

    def test_arylock_pair_suppressed(self):
        # read_mkf_subfile shape: lock, Declare call, unlock.
        out = run([
            Instr(0x00, "FLdI2", "mem=stack-140"),
            Instr(0x04, "PopTmpLdAd2", "mem=stack-136"),
            Instr(0x08, "AryLock", "mem=stack-144"),
            Instr(0x0C, "ImpAdCall", "call=kernel32._hread@0041C0B0"),
            Instr(0x10, "AryUnlock", "mem=stack-144"),
        ], arg_map={"kernel32._hread": 1})
        self.assertEqual(out, ["Call kernel32._hread(stack-140)"])

    def test_arylock_no_stack_effect(self):
        # The pair must not push anything: a following strict call with a
        # full stack would mis-collect otherwise.
        sm = StackMachine()
        sm.param_map = dict(PARAM_MAP)
        sm.arg_map = {"pub_x": 1}
        sm.process(Instr(0x00, "AryLock", "mem=stack-144"))
        self.assertEqual(len(sm.stack), 0)
        sm.process(Instr(0x00, "LitI2", "val=1"))
        sm.process(Instr(0x04, "ImpAdCall", "call=pub_x@0041C69C"))
        sm.process(Instr(0x08, "AryUnlock", "mem=stack-144"))
        sm.flush_leftovers(0x08)
        self.assertEqual(len(sm.stack), 0)


class LabelAliasTest(unittest.TestCase):
    """#13: 0x584's CodeView label is MS's "FMemLdStr", but the handler
    (0x0F79F138) is a generic 4-byte module-field load (mov edx,[Me];
    push [Me+off]); PAL's 126 sites have zero string consumers.  The
    disasm displays the neutral alias FMemLd4/ImpAdLd4."""

    def test_strip_label_alias(self):
        import word_disasm
        self.assertEqual(word_disasm.strip_label("lblEX_FMemLdStr"),
                         "FMemLd4")
        self.assertEqual(word_disasm.strip_label("lblEX_ImpAdLdStr"),
                         "ImpAdLd4")
        self.assertEqual(word_disasm.strip_label("lblEX_FMemLdI2"),
                         "FMemLdI2")

    def test_fmemld4_loads_value(self):
        # The renamed label must stay a load (LOAD_LABELS): pushes the
        # 4-byte module slot value, no statement.
        out = run([
            Instr(0x00, "FMemLd4", "mem=stack+8.f02A4"),
            Instr(0x04, "FStI4", "mem=stack-136"),
        ])
        self.assertEqual(out, ["stack-136 = Me.f02A4"])

    def test_fmemld4_copy_abstains_on_type(self):
        # A 4-byte module load materialized into a temp votes copy
        # (ByVal) but carries NO type hint (Long/pointer/object are
        # indistinguishable at 4 bytes).
        sm = StackMachine()
        sm.param_map = dict(PARAM_MAP)
        sm.arg_map = {"pub_c": 1}
        sm.proc_name = "pub_caller"
        sink = {}
        sm.call_votes = sink
        for i in (Instr(0x00, "FMemLd4", "mem=stack+8.f02A4"),
                  Instr(0x04, "PopTmpLdAd2", "mem=stack-136"),
                  Instr(0x08, "ImpAdCall", "call=pub_c@0041C69C")):
            sm.process(i)
        sm.flush_leftovers(0x08)
        self.assertEqual(sink[(0x08, 0)],
                         ("pub_c", "copy", None, "pub_caller", None))


# ---------------------------------------------------------------------------
# #1 module scalar arbitration + coverage
# ---------------------------------------------------------------------------

class ScalarArbitrationTest(unittest.TestCase):
    def test_majority_store_wins(self):
        # f02A4 shape: 16 FMemStI4 vs 1 ImpAdStR4 -> Long.
        votes = {"store": [("Long", 1, False)] * 16 + [("Single", 2, True)],
                 "load": []}
        self.assertEqual(
            decl_stream._arbitrate_scalar_type(votes), "Long")

    def test_imp_evidence_loses_ties(self):
        # f01FC shape: FMemStI4 (regular) vs ImpAdStR4 (zero-init quirk).
        votes = {"store": [("Long", 1, False), ("Single", 2, True)],
                 "load": []}
        self.assertEqual(
            decl_stream._arbitrate_scalar_type(votes), "Long")

    def test_genuine_tie_is_variant(self):
        votes = {"store": [("Single", 1, False), ("Long", 2, False)],
                 "load": []}
        self.assertIsNone(decl_stream._arbitrate_scalar_type(votes))

    def test_load_only_evidence(self):
        # f02AA shape: FMemLdI2 only -> Integer.
        self.assertEqual(
            decl_stream._arbitrate_scalar_type(
                {"store": [], "load": [("Integer", 1, False)]}),
            "Integer")

    def test_set_scalars_footprints(self):
        # Record layout: fixed 1D covers [off, off+0x18); the dynamic
        # array's footprint is only 4 bytes (f01F8: max_subfile_size at
        # f01FC is a scalar); offsets >= data_size are form-control COM
        # slots and stay undeclared.
        stream = decl_stream.DeclStream(0x401A7C, 0xBC0, 0x878, [
            decl_stream.FieldDecl(0x01F8, decl_stream.KIND_DYNAMIC,
                                  payload="00" * 3),
            decl_stream.FieldDecl(0x020C, decl_stream.KIND_FIXED,
                                  c_dims=1, cb_elements=1,
                                  dims=[(256, 0)]),
        ])
        stream.set_scalars({
            0x01F8: {"store": [], "load": []},      # covered (dyn base)
            0x01FC: {"store": [("Long", 1, False)], "load": []},
            0x0210: {"store": [], "load": []},      # inside 0x18-byte desc
            0x0230: {"store": [("Integer", 1, False)], "load": []},
            0x0878: {"store": [], "load": []},      # beyond data area
        })
        self.assertEqual(stream.scalars, [(0x01FC, "Long"),
                                          (0x0230, "Integer")])


if __name__ == "__main__":
    unittest.main()
