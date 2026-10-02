"""stack_ir behaviour tests (added from the 2026 code review).

Pins:
  1. FStStrNoPop re-pushes its value with deferred call effects intact.
  2. _collect_args keeps a mid-list <missing> as an empty placeholder.
  3. _byref_call uses the same TOS=ARG1 (pop-order) convention as _call.
  4. parse_mem normalizes global= and mem=stack+8.fXXXX to Me.fXXXX.
  6. strip/_has_top_level_binary_op ignore operators inside string literals.
 16. LitI2_10 with no val= still pushes 10.
 17. rtcMidCharVar input_map renders Mid(source, start, length).
 18. A ByRef call whose output slot is never loaded still surfaces.
 19. checkpoint()/restore() leaves Expr.effects intact (no in-place edit).
 20. VCall args render in source order with the receiver last.
 21. GetRecOwner3 renders file_number before the array ref.
 23. A resolved ByRef alias stranded on the stack renders as Call CStr(x).
 24. FFree invalidates the result-slot alias under its substituted key.
 25. parse_lit/parse_lit_str/parse_target are total on None/malformed input.
 26. _field_ref never emits a separator-less raw ref for a non-hex head.
 27. CopyBytes omits the '-' no-operand sentinel (never renders ", -").
 28. _byref_call does not drain the stack when the output slot is absent.
 29. _redim tolerates a malformed dims= operand instead of raising.
 30. _collect_args(strict=True) raises on argument underflow, and _call
     enables strict for every known-arity call site.
 31. _opaque/_stmt emit no trailing space for a '-' operand.
 32. CALL_NORETURN renders as "Call name(args)" like every other call.
 33. strip boundary examples ("()", "(a)(b)", "(a + b)").
 34. _byref_call pads an argument underflow instead of raising IndexError.
 36. LitVarI2 with an empty val= pushes <missing>, not IndexError.
 37. FLdPrThis/FLdPr push Me, not the '-' no-operand sentinel.
 38. An invalid ByRef output slot surfaces the call instead of an alias.
 39. Function-style unary ops render Fn(x); Not keeps "Not (x)".
 40. A stranded <empty> (pop on an empty stack) is dropped, not emitted.
 41. A ByRef call with an absent output slot emits a diagnostic.
 42. ImpAdLd* with a None operand pushes "" instead of raising.
 43. Unary minus over an already-negated operand renders "-(-a0)".
 44. Array-load effects follow push (evaluation) order, not pop order.
 45. Branch/loop opcodes raise in StackMachine.process (structurer-only).

Linear If/branch structuring was removed from StackMachine (structuring.py
owns control flow); the tests that pinned it were deleted with it.

Run: .venv/bin/python -m unittest discover -s tests -q
"""
import os
import sys
import unittest
from collections import namedtuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from stack_ir import (  # noqa: E402
    StackMachine, parse_mem, strip, _has_top_level_binary_op,
    parse_lit, parse_lit_str, parse_target, parse_vcall_slot, _field_ref)

Instr = namedtuple("Instr", "pos label operand")


def machine(param_map=None, arg_map=None):
    sm = StackMachine()
    sm.param_map = dict(param_map or {8: "Me", 12: "a0"})
    sm.arg_map = arg_map or {}
    return sm


def run(instrs, **kw):
    sm = machine(**kw)
    for ins in instrs:
        sm.process(ins)
    sm.flush_leftovers(instrs[-1].pos if instrs else 0)
    return [s.text for s in sm.statements]


class NoPopEffectsTest(unittest.TestCase):
    def test_nopop_preserves_effects_for_unconsumed_value(self):
        # rtcBstrFromAnsi -> Chr(...) carries a deferred Call effect.
        # FStStrNoPop copies the BSTR ref into a frame slot but leaves the
        # value on the eval stack.  When that value is later concatenated and
        # the whole expression is discarded, the effect must still surface as
        # Call Chr(...).  Before the fix _store cleared the effects and the
        # discarded concat leaked as a bare expression statement.
        self.assertEqual(
            run([
                Instr(0x1000, "LitI2", "val=48"),
                Instr(0x1002, "ImpAdCallAd",
                      "call=VB40032.rtcBstrFromAnsi@00401012"),
                Instr(0x1008, "FStStrNoPop", "mem=stack-114"),
                Instr(0x100C, "LitStr", "text='.RPG'"),
                Instr(0x1016, "ConcatStr", "-"),
            ], arg_map={"VB40032.rtcBstrFromAnsi": 1}),
            ["Call Chr(48)"])


class MissingArgTest(unittest.TestCase):
    def test_middle_missing_keeps_placeholder(self):
        # source foo(1, <missing>, 3): reverse-push => push 3, missing, 1.
        self.assertEqual(
            run([
                Instr(0x1000, "LitI2", "val=3"),
                Instr(0x1002, "LitVar_Missing", "mem=stack-152"),
                Instr(0x1006, "LitI2", "val=1"),
                Instr(0x1008, "ImpAdCall", "call=foo@0"),
            ], arg_map={"foo": 3}),
            ["Call foo(1, , 3)"])

    def test_trailing_missing_dropped(self):
        self.assertEqual(
            run([
                Instr(0x1000, "LitVar_Missing", "mem=stack-152"),
                Instr(0x1004, "LitI2", "val=3"),
                Instr(0x1008, "ImpAdCall", "call=foo@0"),
            ], arg_map={"foo": 2}),
            ["Call foo(3)"])

    def test_all_missing_is_empty_arglist(self):
        self.assertEqual(
            run([
                Instr(0x1000, "LitVar_Missing", "mem=stack-152"),
                Instr(0x1004, "ImpAdCall", "call=foo@0"),
            ], arg_map={"foo": 1}),
            ["Call foo()"])


class ByrefCallOrderTest(unittest.TestCase):
    def test_mid_source_order(self):
        # Real sequence pub_068 (trim_string) @00405718-00405732.  P-code
        # push order is [1, stack-140, a0, &out]; TOS=ARG1, so ARG2=a0
        # (source), ARG3=stack-140 (start), ARG4=1 (length).  The loop
        # scans chars from the end (counter stack-140 decremented each
        # pass), so the source is Mid(a0, stack-140, 1) -- not the swapped
        # Mid(a0, 1, stack-140) an earlier input_map produced.
        self.assertEqual(
            run([
                Instr(0x1000, "LitVarI2", "mem=stack-188 val=1"),
                Instr(0x1004, "FLdI2", "mem=stack-140"),
                Instr(0x1008, "CI4I2", "-"),
                Instr(0x100A, "FLdI4", "mem=stack+12"),
                Instr(0x100E, "CVarRef", "mem=stack-156 type=4008"),
                Instr(0x1012, "FLdRfVar", "mem=stack-204"),
                Instr(0x1016, "ImpAdCall",
                      "call=VB40032.rtcMidCharVar@00401018"),
                Instr(0x101A, "FLdRfVar", "mem=stack-204"),
                Instr(0x101E, "FStStr", "mem=stack-136"),
            ]),
            ["stack-136 = Mid(a0, stack-140, 1)"])

    def test_left_source_order(self):
        # rtcLeftCharVar: ARG1=out, ARG2=source, ARG3=length; the same
        # pub_068 tail calls Left(a0, counter + 1).
        self.assertEqual(
            run([
                Instr(0x1000, "FLdI2", "mem=stack-140"),
                Instr(0x1002, "LitI2", "val=1"),
                Instr(0x1004, "AddI2", "-"),
                Instr(0x1006, "FLdI4", "mem=stack+12"),
                Instr(0x1008, "CVarRef", "mem=stack-172 type=4008"),
                Instr(0x100A, "FLdRfVar", "mem=stack-204"),
                Instr(0x100C, "ImpAdCall",
                      "call=VB40032.rtcLeftCharVar@0"),
                Instr(0x100E, "FLdRfVar", "mem=stack-204"),
                Instr(0x1010, "FStStr", "mem=stack-136"),
            ]),
            ["stack-136 = Left(a0, stack-140 + 1)"])

    def test_cstr_from_var_source_order(self):
        # Real sequence @0040ABFE (simplified): an accumulator string plus a
        # variant input -> CStr(variant), with the ByRef slot as ARG1.
        self.assertEqual(
            run([
                Instr(0x1000, "LitVarStr", "text='play cdtrack from'"),
                Instr(0x1010, "FMemLdRf", "mem=stack+8.f0248"),
                Instr(0x1014, "CVarRef", "mem=stack-240 type=4002"),
                Instr(0x1018, "FLdRfVar", "mem=stack-256"),
                Instr(0x101C, "ImpAdCall",
                      "call=VB40032.rtcVarStrFromVar@00401030"),
                Instr(0x1020, "FLdRfVar", "mem=stack-256"),
                Instr(0x1024, "AddVar", "mem=stack-288"),
                Instr(0x1028, "FStStr", "mem=stack-100"),
            ]),
            ["stack-100 = 'play cdtrack from' + CStr(Me.f0248)"])


class ParseMemTest(unittest.TestCase):
    def test_global_plain(self):
        self.assertEqual(parse_mem("global=00000334"), "Me.f0334")

    def test_global_with_suffix_is_robust(self):
        # A '.suffix' must not reach int(..., 16) (previously a ValueError).
        self.assertEqual(parse_mem("global=00000334.a0004"), "Me.f0334")

    def test_mem_stack8_normalizes(self):
        self.assertEqual(parse_mem("mem=stack+8.f0334"), "Me.f0334")

    def test_mem_stack8_keeps_suffix(self):
        self.assertEqual(parse_mem("mem=stack+8.f04DC.a0004"),
                         "Me.f04DC.a0004")


class QuoteAwareTest(unittest.TestCase):
    def test_strip_keeps_string_parens(self):
        self.assertEqual(strip('"(x)"'), '"(x)"')

    def test_strip_boundary_examples(self):
        self.assertEqual(strip("()"), "")
        self.assertEqual(strip("(a)(b)"), "(a)(b)")
        self.assertEqual(strip("(a + b)"), "a + b")
        self.assertEqual(strip('"(x)"'), '"(x)"')

    def test_has_binary_ignores_string(self):
        self.assertFalse(_has_top_level_binary_op('"a + b"'))
        self.assertTrue(_has_top_level_binary_op('"a + b" & c'))


class LitI2_10Test(unittest.TestCase):
    def test_liti2_10_without_val(self):
        self.assertEqual(
            run([
                Instr(0x1000, "LitI2_10", "-"),
                Instr(0x1002, "FStI2", "mem=stack-100"),
            ]),
            ["stack-100 = 10"])


class ParseMemRobustnessTest(unittest.TestCase):
    def test_malformed_global_is_passthrough(self):
        # A malformed global= operand must not raise and abort the proc.
        self.assertEqual(parse_mem("global=ZZZZ"), "global=ZZZZ")
        self.assertEqual(parse_mem("global="), "global=")


class ByrefCallDroppedTest(unittest.TestCase):
    def test_unread_output_slot_still_emits_call(self):
        # rtcVarStrFromVar writes its result to the ByRef output slot; if
        # that slot is never loaded the call must still surface as a
        # discarded Call instead of vanishing.
        self.assertEqual(
            run([
                Instr(0x1000, "LitI2", "val=5"),
                Instr(0x1002, "FLdRfVar", "mem=stack-204"),
                Instr(0x1006, "ImpAdCall",
                      "call=VB40032.rtcVarStrFromVar@0"),
            ]),
            ["Call CStr(5)"])

    def test_unread_output_slot_keeps_input_effects(self):
        # The ByRef call's input is itself a call; when the output slot is
        # never loaded both the input's deferred Call and the ByRef call
        # must surface.
        self.assertEqual(
            run([
                Instr(0x1000, "LitI2", "val=5"),
                Instr(0x1002, "ImpAdCall", "call=foo@0"),
                Instr(0x1006, "FLdRfVar", "mem=stack-204"),
                Instr(0x100A, "ImpAdCall",
                      "call=VB40032.rtcVarStrFromVar@0"),
            ], arg_map={"foo": 1}),
            ["Call foo(5)", "Call CStr(foo(5))"])


class CheckpointRollbackTest(unittest.TestCase):
    def test_effects_survive_restore(self):
        # A trial-process that consumes an Expr must not mutate its effects
        # in place; restore() shallow-copies the stack list, so in-place
        # mutation would survive the rollback.
        sm = machine()
        sm.push("foo()", is_call=True, effects=[(1, 0x100, "foo()")])
        cp = sm.checkpoint()
        sm.process(Instr(0x200, "FStI2", "mem=stack-100"))
        self.assertEqual(sm.stack, [])
        sm.restore(cp)
        self.assertEqual(len(sm.stack), 1)
        self.assertEqual(sm.stack[0].effects, [(1, 0x100, "foo()")])


class VCallOrderTest(unittest.TestCase):
    def test_args_source_order_receiver_last(self):
        # VCall pushes args left-to-right and the receiver last (TOS);
        # _collect_args(reverse=True) restores [arg1, arg2, receiver].
        self.assertEqual(
            run([
                Instr(0x1000, "LitI2", "val=1"),
                Instr(0x1002, "LitI2", "val=2"),
                Instr(0x1004, "FMemLdRf", "mem=stack+8.f0004"),
                Instr(0x1008, "VCallHresult", "vcall=0010@0"),
            ]),
            ["Call Me.method_0010(1, 2, Me.f0004)"])


class GetRecOwner3Test(unittest.TestCase):
    def test_renders_file_number_before_array_ref(self):
        # Real sequence @00414362: GetRecOwner3 pops (array_ref=top,
        # file_number=next) and VB renders `Get file_number, array_ref`.
        self.assertEqual(
            run([
                Instr(0x1000, "LitI2", "val=2"),
                Instr(0x1002, "FLdI2", "mem=stack-142"),
                Instr(0x1004, "CI4I2", "-"),
                Instr(0x1006, "FMemLdRf", "mem=stack+8.f0344"),
                Instr(0x100A, "Ary1LdRf", "-"),
                Instr(0x100C, "GetRecOwner3", "record-owner"),
            ]),
            ["Get 2, Me.f0344(stack-142)"])


class ResolvedAliasStrandedTest(unittest.TestCase):
    def test_stranded_byref_alias_renders_as_call(self):
        # A ByRef call's output slot is loaded (resolving the alias) but the
        # resulting expression is never consumed.  It must surface as
        # ``Call CStr(5)``; before the fix it leaked as a bare ``CStr(5)``
        # expression statement (is_call/own-effect were dropped).
        self.assertEqual(
            run([
                Instr(0x1000, "LitI2", "val=5"),
                Instr(0x1002, "FLdRfVar", "mem=stack-204"),
                Instr(0x1006, "ImpAdCall",
                      "call=VB40032.rtcVarStrFromVar@0"),
                Instr(0x100A, "FLdRfVar", "mem=stack-204"),
            ]),
            ["Call CStr(5)"])

    def test_stranded_byref_alias_keeps_input_effects(self):
        # Same, but the ByRef input is itself a call: both the input's
        # deferred Call and the ByRef call must surface.
        self.assertEqual(
            run([
                Instr(0x1000, "LitI2", "val=5"),
                Instr(0x1002, "ImpAdCall", "call=foo@0"),
                Instr(0x1006, "FLdRfVar", "mem=stack-204"),
                Instr(0x100A, "ImpAdCall",
                      "call=VB40032.rtcVarStrFromVar@0"),
                Instr(0x100E, "FLdRfVar", "mem=stack-204"),
            ], arg_map={"foo": 1}),
            ["Call foo(5)", "Call CStr(foo(5))"])


class FFreeAliasKeyTest(unittest.TestCase):
    def test_result_slot_alias_invalidated_under_substituted_key(self):
        # The Function result slot (stack-134) is renamed to the proc name
        # when an alias is recorded.  FFreeVar's stack=[...] list carries the
        # raw '-134'; invalidation must apply the same substitution or the
        # alias/pending call leaks.
        sm = machine()
        sm.result_slot = -134
        sm.result_name = "myfunc"
        sm.temp_aliases["myfunc"] = "CStr(x)"
        sm._alias_effects["myfunc"] = []
        sm._pending_byref["myfunc"] = (1, 0x100, "CStr(x)", [])
        sm.process(Instr(0x200, "FFreeVar", "byteLen=4 stack=[-134]"))
        self.assertNotIn("myfunc", sm.temp_aliases)
        self.assertNotIn("myfunc", sm._pending_byref)
        self.assertEqual([s.text for s in sm.statements], ["Call CStr(x)"])


class ParseRobustnessTest(unittest.TestCase):
    def test_parse_lit_none_returns_empty_string(self):
        self.assertEqual(parse_lit(None), "")
        self.assertEqual(parse_lit(""), "")

    def test_parse_lit_str_none_returns_empty_string(self):
        self.assertEqual(parse_lit_str(None), "")

    def test_parse_target_malformed_returns_none(self):
        self.assertIsNone(parse_target("to="))
        self.assertIsNone(parse_target("to=ZZ"))
        self.assertIsNone(parse_target(None))
        self.assertEqual(parse_target("to=00401234"), 0x401234)

    def test_field_ref_non_hex_head_is_dropped(self):
        # A separator-less raw ref would render 'addrstack+8.f0334'.
        self.assertEqual(_field_ref("mem=stack+8.f0334"), "")
        self.assertEqual(_field_ref("mem=0002"), ".f0002")
        self.assertEqual(_field_ref(None), "")


class CopyBytesOperandTest(unittest.TestCase):
    def test_no_operand_sentinel_omitted(self):
        # CopyBytes pops (dest=top, source=next).  A '-' operand (no byte
        # count) must not render as a trailing ", -".
        self.assertEqual(
            run([
                Instr(0x1000, "FLdI2", "mem=stack-100"),
                Instr(0x1002, "FLdI2", "mem=stack-104"),
                Instr(0x1004, "CopyBytes", "-"),
            ]),
            ["CopyBytes stack-104, stack-100"])

    def test_len_operand_appended(self):
        self.assertEqual(
            run([
                Instr(0x1000, "FLdI2", "mem=stack-100"),
                Instr(0x1002, "FLdI2", "mem=stack-104"),
                Instr(0x1004, "CopyBytes", "len=10"),
            ]),
            ["CopyBytes stack-104, stack-100, len=10"])


class ByrefCallStackIntegrityTest(unittest.TestCase):
    def test_missing_output_slot_leaves_stack_intact(self):
        # A spec whose out_index exceeds the stack must bail out BEFORE
        # popping; otherwise the two live values are silently discarded.
        sm = machine()
        sm.push("a")
        sm.push("b")
        spec = {"nargs": 4, "out_index": 3, "renderer": "Foo",
                "input_map": None}
        sm._byref_call("X", spec, 0x100)
        self.assertEqual([e.text for e in sm.stack], ["a", "b"])

    def test_arg_underflow_pads_instead_of_indexerror(self):
        # rtcVarStrFromVar (nargs=2, out_index=0) with only the output slot
        # on the stack used to raise IndexError from resolved[input_map[0]].
        # The missing arg is padded with <missing> and the call surfaces.
        self.assertEqual(
            run([
                Instr(0x1000, "FLdRfVar", "mem=stack-204"),
                Instr(0x1004, "ImpAdCall",
                      "call=VB40032.rtcVarStrFromVar@0"),
            ]),
            ["Call CStr(<missing>)"])

    def test_mid_arg_underflow_pads_all_inputs(self):
        # rtcMidCharVar (nargs=4, input_map=[0,1,2]) with two stack items.
        self.assertEqual(
            run([
                Instr(0x1000, "FLdI4", "mem=stack+12"),
                Instr(0x1004, "FLdRfVar", "mem=stack-204"),
                Instr(0x1008, "ImpAdCall",
                      "call=VB40032.rtcMidCharVar@0"),
            ]),
            ["Call Mid(a0, <missing>, <missing>)"])

    def test_invalid_output_slot_surfaces_call_without_alias(self):
        # A <missing> output slot cannot be resolved by a later load, so the
        # call must be emitted (not recorded as an unusable alias).
        sm = machine()
        sm.push("5")
        sm.push("<missing>")
        spec = {"nargs": 2, "out_index": 0, "renderer": "CStr",
                "input_map": [0]}
        sm._byref_call("X", spec, 0x100)
        self.assertEqual([s.text for s in sm.statements], ["Call CStr(5)"])
        self.assertNotIn("<missing>", sm.temp_aliases)
        self.assertEqual(sm._pending_byref, {})


class LitVarI2MalformedTest(unittest.TestCase):
    def test_empty_val_does_not_raise(self):
        sm = machine()
        sm.process(Instr(0x1000, "LitVarI2", "val="))
        self.assertEqual([e.text for e in sm.stack], ["<missing>"])

    def test_whitespace_val_does_not_raise(self):
        sm = machine()
        sm.process(Instr(0x1000, "LitVarI2", "val=   "))
        self.assertEqual([e.text for e in sm.stack], ["<missing>"])

    def test_normal_val_still_parsed(self):
        sm = machine()
        sm.process(Instr(0x1000, "LitVarI2", "mem=stack-188 val=1"))
        self.assertEqual([e.text for e in sm.stack], ["1"])

    def test_mem_only_falls_back_to_slot(self):
        sm = machine()
        sm.process(Instr(0x1000, "LitVarI2", "mem=stack-188"))
        self.assertEqual([e.text for e in sm.stack], ["stack-188"])


class FLdPrTest(unittest.TestCase):
    def test_fldprthis_sets_receiver_not_stack(self):
        # #14: FLdPrThis copies [ebp+8] into the [ebp-0x50] receiver
        # register (handler-verified) -- it never touches the eval stack.
        sm = machine()
        sm.process(Instr(0x1000, "FLdPrThis", "-"))
        self.assertEqual(sm.receiver, "Me")
        self.assertEqual([e.text for e in sm.stack], [])

    def test_fldprthis_vcall_uses_receiver(self):
        sm = machine()
        sm.process(Instr(0x1000, "FLdPrThis", "-"))
        sm.process(Instr(0x1004, "VCallHresult", "vcall=0038@00403180"))
        self.assertEqual([e.text for e in sm.stack], ["Me.method_0038()"])

    def test_fldpr_sets_receiver_not_stack(self):
        # #16: FLdPr loads the frame-slot object into the [ebp-0x50]
        # receiver register (handler: mov eax,[ebp+off]; mov
        # [ebp-0x50],eax) -- it never touches the eval stack.  All 3 PAL
        # uses feed a LateIdLdVar invoke.
        sm = machine()
        sm.process(Instr(0x1000, "FLdPr", "mem=stack-136"))
        self.assertEqual(sm.receiver, "stack-136")
        self.assertEqual([e.text for e in sm.stack], [])

    def test_fldpr_dash_falls_back_to_me(self):
        sm = machine()
        sm.process(Instr(0x1000, "FLdPr", "-"))
        self.assertEqual(sm.receiver, "Me")
        self.assertEqual([e.text for e in sm.stack], [])

    def test_late_id_ld_var_aliases_slot_for_inline_render(self):
        # #16: LateIdLdVar = zero-argument IDispatch::Invoke member get
        # (entry hardcodes ebx=0 -- the argument count; the worker issues
        # Invoke(obj, dispid, IID_NULL, ctx, 3, {NULL,0}, &slot, ...) so
        # the result VARIANT lands straight in the mem= slot).  The slot
        # is aliased so the consuming FLdRfVar renders the get inline.
        sm = machine()
        sm.process(Instr(0x1000, "FLdPr", "mem=stack-136"))
        sm.process(Instr(0x1004, "LateIdLdVar",
                         "mem=stack-152 id=00010001"))
        self.assertEqual([s.text for s in sm.statements], [])
        sm.process(Instr(0x1008, "FLdRfVar", "mem=stack-152"))
        self.assertEqual([e.text for e in sm.stack],
                         ["stack-136.lateid_00010001"])

    def test_late_id_ld_var_without_receiver_uses_me(self):
        self.assertEqual(
            run([Instr(0x2000, "LateIdLdVar", "mem=stack-152 id=00010000"),
                 Instr(0x2004, "FLdRfVar", "mem=stack-152")]),
            ["Me.lateid_00010000"])

    def test_late_id_ld_var_no_eval_effect(self):
        # Zero-argument get: the pending value below must survive for the
        # NEXT call's drain (the runtime pops nothing: add esp, ebx*16
        # with ebx=0; the continuation pushes &slot and PopAd discards
        # it -- net zero).
        sm = machine()
        sm.push("pending_result")
        sm.process(Instr(0x1000, "LateIdLdVar", "mem=stack-152 id=00010001"))
        self.assertEqual([e.text for e in sm.stack], ["pending_result"])

    def test_late_id_ld_var_second_get_overwrites_alias(self):
        # priv_092 reuses stack-152 (freed between sites): the second get
        # must replace the alias, not stack the renders.
        sm = machine()
        sm.process(Instr(0x1000, "FLdPr", "mem=stack-136"))
        sm.process(Instr(0x1004, "LateIdLdVar", "mem=stack-152 id=00010001"))
        sm.process(Instr(0x1008, "FLdPr", "mem=stack-156"))
        sm.process(Instr(0x100C, "LateIdLdVar", "mem=stack-152 id=00010000"))
        sm.process(Instr(0x1010, "FLdRfVar", "mem=stack-152"))
        self.assertEqual([e.text for e in sm.stack],
                         ["stack-156.lateid_00010000"])

    def test_pop_ad_is_silent_and_zero_effect(self):
        # #16: PopAd's handler is a bare `add esp,4` (native rebalance) --
        # no eval-stack effect, no statement.  Its 3 PAL uses are all the
        # LateIdLdVar idiom tail; PopAdLdVar (a different opcode) keeps
        # its plumbing role.
        sm = machine()
        sm.push("a")
        sm.process(Instr(0x1000, "PopAd", "-"))
        self.assertEqual([e.text for e in sm.stack], ["a"])
        self.assertEqual([s.text for s in sm.statements], [])

    def test_open_flags_render_vb4_syntax(self):
        # #17: flags u16 = mode | (access << 8) | (share << 12);
        # 0x0104 = For Random + Access Read (handler-verified).
        self.assertEqual(
            run([Instr(0x1000, "LitStr", "text='WORD.DAT'"),
                 Instr(0x1002, "LitI2", "val=2"),
                 Instr(0x1004, "LitI2", "val=10"),
                 Instr(0x1006, "Open", "flags=0104")]),
            ["Open 'WORD.DAT' For Random Access Read As #2 Len = 10"])

    def test_open_unknown_flags_stay_visible(self):
        # Unknown mode/access/share codes must not silently vanish.
        self.assertEqual(
            run([Instr(0x1000, "LitStr", "text='X'"),
                 Instr(0x1002, "LitI2", "val=1"),
                 Instr(0x1004, "LitI2", "val=0"),
                 Instr(0x1006, "Open", "flags=8107")]),
            ["Open 'X' For ?07 Access Read ' lock=8 As #1"])


class RedimMalformedTest(unittest.TestCase):
    def test_bad_dims_does_not_raise(self):
        self.assertEqual(
            run([Instr(0x1000, "Redim", "dims=ZZ flags=x")]),
            ["Redim dims=ZZ flags=x"])

    def test_empty_dims_does_not_raise(self):
        self.assertEqual(
            run([Instr(0x1000, "Redim", "dims=")]),
            ["Redim dims="])

    def test_absurd_dims_is_capped(self):
        # A corrupt operand must not make _redim pop ~2e8 <empty> Exprs;
        # the cap routes it to the raw-operand fallback (dims treated as 0).
        self.assertEqual(
            run([Instr(0x1000, "Redim", "dims=99999999 desc=x")]),
            ["Redim dims=99999999 desc=x"])


class ParseVcallSlotTest(unittest.TestCase):
    def test_empty_tail_is_none(self):
        # Regression: a bare "vcall="/"this.vcall=" prefix has no token;
        # the old ``split()[0]`` raised IndexError and aborted the proc.
        self.assertIsNone(parse_vcall_slot("vcall="))
        self.assertIsNone(parse_vcall_slot("this.vcall="))

    def test_valid_slots(self):
        self.assertEqual(parse_vcall_slot("vcall=0010@0"), "0010")
        self.assertEqual(parse_vcall_slot("this.vcall=0004"), "0004")

    def test_non_vcall_is_none(self):
        self.assertIsNone(parse_vcall_slot("call=foo@0"))
        self.assertIsNone(parse_vcall_slot(""))


class CheckpointDeepCopyTest(unittest.TestCase):
    def test_alias_effects_list_is_not_shared_with_snapshot(self):
        # _alias_effects values are lists; checkpoint() must not alias them
        # or an in-place probe edit would survive restore().
        sm = machine()
        sm._alias_effects["slot"] = ["effect"]
        cp = sm.checkpoint()
        sm._alias_effects["slot"].append("leaked")
        sm.restore(cp)
        self.assertEqual(sm._alias_effects["slot"], ["effect"])

    def test_pending_byref_nested_list_is_not_shared(self):
        sm = machine()
        sm._pending_byref["slot"] = (1, 0x100, "CStr(x)", ["eff"])
        cp = sm.checkpoint()
        sm._pending_byref["slot"][3].append("leaked")
        sm.restore(cp)
        self.assertEqual(sm._pending_byref["slot"][3], ["eff"])


class CollectArgsStrictTest(unittest.TestCase):
    def test_strict_raises_on_underflow(self):
        sm = machine()
        sm.push("x")
        with self.assertRaises(ValueError):
            sm._collect_args(3, strict=True)

    def test_non_strict_truncates(self):
        sm = machine()
        sm.push("x")
        self.assertEqual(sm._collect_args(3), "x")

    def test_known_arity_call_underflow_raises(self):
        # _call passes strict=True: a known arity that exceeds the eval stack
        # must raise, not silently truncate (pins the opt-in against revert).
        sm = machine(arg_map={"Pal.foo": 2})
        sm.push("only-one")
        with self.assertRaises(ValueError):
            sm.process(Instr(0x1000, "ImpAdCall", "call=Pal.foo@0"))


class LabelOperandRenderTest(unittest.TestCase):
    def test_opaque_no_trailing_space(self):
        self.assertEqual(run([Instr(0x1000, "Bogus", "-")]), ["# Bogus"])
        self.assertEqual(run([Instr(0x1000, "Bogus", "x=1")]),
                         ["# Bogus x=1"])

    def test_stmt_no_trailing_space(self):
        # AryLock is now a suppressed lifecycle opcode (#12: no statement);
        # the '-' sentinel trimming stays covered via the opaque fallback.
        self.assertEqual(run([Instr(0x1000, "AryLock", "-")]), [])
        self.assertEqual(run([Instr(0x1000, "Bogus", "-")]), ["# Bogus"])


class NoReturnCallTest(unittest.TestCase):
    def test_noreturn_renders_uniform_call_form(self):
        # ImpAdCallHresult is in CALL_NORETURN; it must render with the same
        # "Call name(args)" shape as every other call.
        self.assertEqual(
            run([
                Instr(0x1000, "LitI2", "val=7"),
                Instr(0x1002, "ImpAdCallHresult", "call=Pal.foo@0"),
            ], arg_map={"Pal.foo": 1}),
            ["Call Pal.foo(7)"])

    def test_noreturn_no_args(self):
        self.assertEqual(
            run([Instr(0x1000, "ImpAdCallHresult", "call=Pal.bar@0")],
                arg_map={"Pal.bar": 0}),
            ["Call Pal.bar()"])


class ReviewFixesTest(unittest.TestCase):
    """Regressions pinned from the stack_ir code review."""

    def test_stranded_empty_is_dropped(self):
        # pop() on an empty stack returns Expr("<empty>"); a flush must not
        # leak it as a bare "<empty>" statement.
        sm = machine()
        sm.push("<empty>")
        sm.flush_leftovers(0x100)
        self.assertEqual([s.text for s in sm.statements], [])

    def test_byref_absent_output_slot_emits_diagnostic(self):
        # The output slot is not even on the stack: leave the live values
        # alone, but do not silently drop the call.
        sm = machine()
        sm.push("a")
        sm.push("b")
        spec = {"nargs": 4, "out_index": 3, "renderer": "Foo",
                "input_map": None}
        sm._byref_call("X", spec, 0x100)
        self.assertEqual([e.text for e in sm.stack], ["a", "b"])
        self.assertEqual([s.text for s in sm.statements],
                         ["# Foo <stack underflow>"])

    def test_impadld_none_operand_does_not_raise(self):
        sm = machine()
        sm.process(Instr(0x1000, "ImpAdLdRf", None))
        self.assertEqual([e.text for e in sm.stack], [""])

    def test_double_negation_parenthesized(self):
        self.assertEqual(
            run([
                Instr(0x1000, "FLdI2", "mem=stack+12"),
                Instr(0x1004, "UMiI2", "-"),
                Instr(0x1008, "UMiI2", "-"),
                Instr(0x100C, "FStI2", "mem=stack-100"),
            ]),
            ["stack-100 = -(-a0)"])

    def test_ary_load_effects_in_push_order(self):
        # Stack bottom->top = [index, arrayref]; the index is evaluated first.
        sm = machine()
        sm.push("idx", effects=[(1, 0x100, "idx()")])
        sm.push("ary", effects=[(2, 0x104, "ary()")])
        sm.process(Instr(0x108, "Ary1LdRf", "-"))
        self.assertEqual(sm.stack[-1].text, "ary(idx)")
        self.assertEqual(sm.stack[-1].effects,
                         [(1, 0x100, "idx()"), (2, 0x104, "ary()")])

    def test_ary_n_load_effects_in_push_order(self):
        # dims=2: push i1, i2, arrayref; effects must be i1, i2, arrayref.
        sm = machine()
        sm.push("i1", effects=[(1, 0x100, "c1()")])
        sm.push("i2", effects=[(2, 0x104, "c2()")])
        sm.push("ary", effects=[(3, 0x108, "c3()")])
        sm.process(Instr(0x10C, "AryLdRf", "descriptor=0x0002"))
        self.assertEqual(sm.stack[-1].text, "ary(i1, i2)")
        self.assertEqual(sm.stack[-1].effects,
                         [(1, 0x100, "c1()"), (2, 0x104, "c2()"),
                          (3, 0x108, "c3()")])

class ControlFlowRejectedTest(unittest.TestCase):
    """StackMachine no longer structures control flow; the structurer owns it."""

    def test_branch_and_loop_opcodes_raise(self):
        for label, operand in (
                ("BranchF", "to=00001000"),
                ("BranchT", "to=00001000"),
                ("Branch", "to=00001000"),
                ("Gosub", "to=00001000"),
                ("ForI2", "ctl=stack-138 to=00001010"),
                ("NextI2", "ctl=stack-138 to=00001000")):
            sm = machine()
            with self.assertRaises(RuntimeError, msg=label):
                sm.process(Instr(0x1000, label, operand))


if __name__ == "__main__":
    unittest.main(verbosity=2)
