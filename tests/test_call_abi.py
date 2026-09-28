"""Tests for call-argument ordering in stack_ir.

VB4 evaluates a call's arguments onto its p-code eval stack, and the
runtime hands them to the callee so that the *last* pushed value (the
eval-stack TOS) becomes the callee's first parameter (ARG1).  Popping
TOS-first therefore already yields source order, so stack_ir must NOT
reverse the collected items -- for internal `pub_*`/`priv_*` procedures,
for Declare-table stdcall targets (Pal.*, kernel32.*, ...) and for the
PE-imported VB40032.rtc* runtime helpers alike.

These tests pin that behaviour.

Run:  .venv/bin/python -m pytest tests/test_call_abi.py
  or: .venv/bin/python tests/test_call_abi.py
"""
import os
import sys
import unittest
from collections import namedtuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from stack_ir import StackMachine  # noqa: E402


Instr = namedtuple("Instr", "pos label operand")


def run(instrs, arg_map=None):
    sm = StackMachine()
    sm.arg_map = arg_map or {}
    for instr in instrs:
        sm.process(instr)
    sm.flush_leftovers(instrs[-1].pos if instrs else 0)
    return [s.text for s in sm.statements]


def call(target, *pushed):
    """Build a call that pushes *pushed* onto the eval stack in order."""
    ins = [Instr(i * 4, "LitI2", "val=%s" % v) for i, v in enumerate(pushed)]
    ins.append(Instr(len(pushed) * 4, "ImpAdCall", "call=%s@0" % target))
    return ins


class CallOrderTest(unittest.TestCase):
    def test_source_args_are_pushed_in_reverse(self):
        # Source `F(1, 2, 3)` pushes 3, 2, 1 (so ARG1 is pushed last and
        # sits at the eval-stack TOS).  Popping TOS-first yields (1, 2, 3)
        # for every call kind -- internal, Declare-table and VB40032.rtc*.
        for target in ("pub_000", "Pal.DrawString", "VB40032.rtcMsgBox"):
            ins = call(target, 3, 2, 1)
            self.assertEqual(run(ins, arg_map={target: 3}),
                             ["Call %s(1, 2, 3)" % target],
                             msg=target)

    def test_collected_order_is_pop_order(self):
        # Pushing (1, 2, 3) leaves 3 at the TOS, i.e. ARG1 == 3.
        out = run(call("pub_000", 1, 2, 3), arg_map={"pub_000": 3})
        self.assertEqual(out, ["Call pub_000(3, 2, 1)"])


if __name__ == "__main__":
    unittest.main()