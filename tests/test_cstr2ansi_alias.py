"""Tests for the CStr2Ansi temp-alias resolution in stack_ir.py.

VB4 converts a String to ANSI into a frame temp before passing it to an
ANSI API:

    <push string>            ; e.g. a ByRef String param, a LitStr, ...
    FLdRfVar tempSlot        ; push &temp
    CStr2Ansi                ; temp = AnsiFromBstr(string)
    FLdI4 tempSlot           ; push temp (ANSI pointer)
    ImpAdCall/Call API

The decompiler used to render the API argument as the raw ``tempSlot``
(e.g. ``stack-136`` / ``tmp2``), which is never assigned in the emitted
pseudocode.  It now records an alias so the ``FLdI4`` load resolves to the
original VB string expression.

Run:  .venv/bin/python -m pytest tests/test_cstr2ansi_alias.py
  or: .venv/bin/python tests/test_cstr2ansi_alias.py
"""
import os
import sys
import unittest
from collections import namedtuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from stack_ir import StackMachine  # noqa: E402


Instr = namedtuple("Instr", "pos label operand")


def run(instrs, param_map=None, arg_map=None):
    sm = StackMachine()
    sm.param_map = param_map or {}
    sm.arg_map = arg_map or {}
    for instr in instrs:
        sm.process(instr)
    sm.flush_leftovers(instrs[-1].pos if instrs else 0)
    return [s.text for s in sm.statements]


class CStr2AnsiAliasTest(unittest.TestCase):
    def test_pub_016_draw_string(self):
        # Real PAL.EXE pub_016_0040375C_hot:
        #   draw_string(...) -> PAL_DrawString(
        #       Me.f02A4, x, y, shadow, color, wordData)
        # PAL_DrawString is a Declare-table (stdcall) target, so arguments
        # are pushed right-to-left and must NOT be reversed on collection.
        instrs = [
            Instr(0x0040375C, "FMemLd4", "mem=stack+8.f02A4"),
            Instr(0x00403762, "ILdI2", "mem=stack+28"),   # x  (a4)
            Instr(0x00403766, "ILdI2", "mem=stack+24"),   # y  (a3)
            Instr(0x0040376A, "ILdI2", "mem=stack+16"),   # shadow (a1)
            Instr(0x0040376E, "ILdI2", "mem=stack+12"),   # color  (a0)
            Instr(0x00403772, "ILdI4", "mem=stack+20"),   # wordData (a2)
            Instr(0x00403776, "FLdRfVar", "mem=stack-136"),
            Instr(0x0040377A, "CStr2Ansi", "-"),
            Instr(0x0040377C, "FLdI4", "mem=stack-136"),
            Instr(0x00403780, "ImpAdCall", "call=Pal.DrawString@00417150"),
        ]
        param_map = {8: "Me", 12: "a0", 16: "a1", 20: "a2", 24: "a3", 28: "a4"}
        out = run(instrs, param_map=param_map,
                  arg_map={"Pal.DrawString": 6})
        # stdcall push order: first source arg is at TOS, so the collected
        # order is the reverse of the push order.
        self.assertIn(
            "Call Pal.DrawString(a2, a0, a1, a3, a4, Me.f02A4)", out)
        self.assertNotIn("stack-136", "\n".join(out))

    def test_ansi_temp_resolves_to_literal(self):
        instrs = [
            Instr(0x00, "LitStr", "index=0000 byteLen=8 text='cmd'"),
            Instr(0x04, "FLdRfVar", "mem=stack-136"),
            Instr(0x08, "CStr2Ansi", "-"),
            Instr(0x0C, "FLdI4", "mem=stack-136"),
            Instr(0x10, "ImpAdCallAd", "call=kernel32.mciSendStringA@0"),
        ]
        out = run(instrs, arg_map={"kernel32.mciSendStringA": 1})
        self.assertEqual(out, ["Call kernel32.mciSendStringA('cmd')"])

    def test_cstr2uni_does_not_record_alias(self):
        # The post-call CStr2Uni epilogue must not leak an alias into a
        # later FLdI4 of the same slot.
        instrs = [
            Instr(0x00, "FLdI4", "mem=stack-136"),
            Instr(0x04, "FLdI4", "mem=stack+12"),
            Instr(0x08, "CStr2Uni", "-"),
            Instr(0x0C, "FLdI4", "mem=stack-136"),
        ]
        out = run(instrs, param_map={8: "Me", 12: "a0"})
        # Both FLdI4 loads are bare plumbing temps; flush drops them.
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()