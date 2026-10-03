"""Unit tests for the ByRef-slot ILdI4 consumer-flow pointee vote.

ILdI4 through a param slot is ambiguous in isolation (Long read / BSTR
pointer fetch / UDT pointer fetch), so the suffix tables abstain.  The
fetched value's first CONSUMER disambiguates (pseudo_code._ild_i4_flow_vote,
label "ILdI4Flow"):

  - I4 value ops (arithmetic/compare/logic, convert-from-I4, I4 stores,
    4-byte temp materialization) -> Long;
  - Len(BSTR) (FnLenStr) and the CStr2Ansi source operand -> String;
  - call arguments, array refs/bases, Mem* bases, array indexes (widened
    to I4 regardless of source type) and unmodeled/control-flow opcodes
    -> abstain.

Most fixtures are real PAL.EXE sites (VA in the comment).

Run:  .venv/bin/python -m unittest tests.test_ild_i4_flow -q
"""
import os
import sys
import unittest
from collections import namedtuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pseudo_code

Instr = namedtuple("Instr", "pos label operand")


def slot_votes(instrs, slot):
    """_slot_evidence votes for one slot, as (kind, vtype, label) triples."""
    instrs = [Instr(p, l, o) for p, l, o in instrs]
    votes = pseudo_code._slot_evidence(instrs).get(slot, {})
    return [(kind, vtype, label)
            for kind in ("store", "load", "for")
            for vtype, _va, _imp, label in votes.get(kind, [])]


def flow_type(instrs, nargs=1):
    """_deref_param_types over a fixture (the pass _deref evidence feeds)."""
    return pseudo_code._deref_param_types(
        [Instr(p, l, o) for p, l, o in instrs], nargs)


class IldI4ConsumerVoteTest(unittest.TestCase):
    # -- Long: I4 value-op consumers ------------------------------------

    def test_compare_votes_long(self):
        # pub_100 0040771A: If number < 0 -> ILdI4 a2; LitI4 0; LtI4.
        self.assertEqual(
            flow_type([(0x00, "ILdI4", "mem=stack+20"),
                       (0x04, "LitI4", "val=0"),
                       (0x08, "LtI4", "-")], nargs=3),
            [None, None, "Long"])

    def test_store_votes_long(self):
        # pub_100 00407742: num = number -> ILdI4 a2; FStI4 stack-144.
        self.assertEqual(
            flow_type([(0x00, "ILdI4", "mem=stack+20"),
                       (0x04, "FStI4", "mem=stack-144")], nargs=3),
            [None, None, "Long"])

    def test_binary_votes_long(self):
        # show_money 00407466: RPG_money = RPG_money + amount ->
        # ILdI4 a0; AddI4.
        self.assertEqual(
            flow_type([(0x00, "ILdI4", "mem=stack+12"),
                       (0x04, "AddI4", "-")]),
            ["Long"])

    def test_binary_second_operand_votes_long(self):
        # Either operand of an I4 binary op is an I4 use: the fetch sits
        # below the other operand (above == 1).
        self.assertEqual(
            flow_type([(0x00, "LitI4", "val=1"),
                       (0x04, "ILdI4", "mem=stack+12"),
                       (0x08, "AddI4", "-")]),
            ["Long"])

    def test_temp_materialization_votes_long(self):
        # ByVal arg copy into a 4-byte temp: the fetched I4 is a value.
        self.assertEqual(
            flow_type([(0x00, "ILdI4", "mem=stack+12"),
                       (0x04, "PopTmpLdAd4", "mem=stack-172")]),
            ["Long"])

    def test_convert_from_i4_votes_long(self):
        self.assertEqual(
            flow_type([(0x00, "ILdI4", "mem=stack+12"),
                       (0x04, "CR8I4", "-")]),
            ["Long"])

    # -- String: BSTR consumers ------------------------------------------

    def test_fnlenstr_votes_string(self):
        # trim_string 0040570C: strLen = Len(str) -> ILdI4 a0; FnLenStr.
        self.assertEqual(
            flow_type([(0x00, "ILdI4", "mem=stack+12"),
                       (0x04, "FnLenStr", "-")]),
            ["String"])

    def test_cstr2ansi_lookback_not_double_counted(self):
        # open_file 00404E0A: ILdI4 a0; FLdRfVar tmp; CStr2Ansi -> the
        # look-back pattern votes String for this exact fetch; the flow
        # walk must not add a second vote.
        votes = slot_votes([(0x00, "ILdI4", "mem=stack+12"),
                            (0x04, "FLdRfVar", "mem=stack-144"),
                            (0x08, "CStr2Ansi", "-")], 12)
        self.assertEqual(votes, [("store", "String", "CStr2Ansi")])

    def test_cstr2ansi_far_source_votes_string(self):
        # Complementarity contract: with a no-stack-effect op between the
        # fetch and the slot-ptr push, the look-back's fixed consumer-2
        # window misses the site but the flow walk still votes String
        # (synthetic fixture -- the walk vs look-back division of labor).
        votes = slot_votes([(0x00, "ILdI4", "mem=stack+12"),
                            (0x04, "FFree1Str", "mem=stack-140"),
                            (0x08, "FLdRfVar", "mem=stack-144"),
                            (0x0C, "CStr2Ansi", "-")], 12)
        self.assertIn(("load", "String", "ILdI4Flow"), votes)

    # -- Abstain: pointer / ABI / unknown consumers -----------------------

    def test_call_argument_abstains(self):
        # pub_?? 004051D0: ILdI4 a0; ImpAdCall _hread -- the fetched 4
        # bytes are a raw Declare ABI argument (pointer or Long, opaque).
        self.assertEqual(
            flow_type([(0x00, "ILdI4", "mem=stack+12"),
                       (0x04, "ImpAdCall",
                        "call=kernel32._hread@0041778C")]),
            [None])

    def test_array_descriptor_abstains(self):
        # pub_?? 00404C5A: ILdI4 a1; AryLock; Ary1LdRf -- the fetch feeds
        # an array reference (lifecycle/element address), not an I4 op.
        self.assertEqual(
            flow_type([(0x00, "ILdI4", "mem=stack+16"),
                       (0x04, "AryLock", "mem=stack-144"),
                       (0x08, "Ary1LdRf", "-")], nargs=2),
            [None, None])

    def test_array_index_abstains(self):
        # Indexes are widened to I4 regardless of source type (CI4I2
        # precedes Ary1Ld in PAL), so an I4 index use proves nothing.
        self.assertEqual(
            flow_type([(0x00, "ILdI4", "mem=stack+12"),
                       (0x04, "FMemLdRf",
                        "mem=stack+8.f080C  ; Single(0 To 31)"),
                       (0x08, "Ary1LdRf", "-")]),
            [None])

    def test_control_flow_stops_walk(self):
        # Branches/loops/terminators are unmodeled: the walk stops with
        # no vote instead of crossing a basic-block boundary.
        self.assertEqual(
            flow_type([(0x00, "ILdI4", "mem=stack+12"),
                       (0x04, "BranchF", "to=0040772C")]),
            [None])

    def test_window_exhaustion_abstains(self):
        # Eight pushes ride on top of the fetch without a consumer:
        # no vote.
        instrs = [(0x00, "ILdI4", "mem=stack+12")]
        instrs += [(0x04 + 2 * i, "LitI2", "val=%d" % i)
                   for i in range(pseudo_code._ILD_I4_FLOW_WINDOW)]
        self.assertEqual(flow_type(instrs), [None])

    def test_bare_fetch_still_ambiguous(self):
        # A lone ILdI4 with no consumer at all stays untyped (the
        # three-way ambiguity is honest without a disambiguating use).
        self.assertEqual(
            flow_type([(0x00, "ILdI4", "mem=stack+12")]), [None])

    # -- Scope guards ------------------------------------------------------

    def test_local_slot_not_walked(self):
        # I* never touches stack-N in PAL.EXE; the walk is param-only
        # (stack+8 is the Me base), so a local-slot ILdI4 adds no vote
        # even with an I4 consumer.
        votes = slot_votes([(0x00, "ILdI4", "mem=stack-144"),
                            (0x04, "FStI4", "mem=stack-140")], -144)
        self.assertEqual(votes, [])

    def test_me_base_not_walked(self):
        votes = slot_votes([(0x00, "ILdI4", "mem=stack+8"),
                            (0x04, "FStI4", "mem=stack-140")], 8)
        self.assertEqual(votes, [])

    def test_conflicting_uses_arbitrate(self):
        # One slot fetched twice: an I4 compare (Long) and a BSTR
        # marshal (String).  Store evidence wins arbitration (the
        # look-back's String vote), matching _arbitrate_slot_type.
        votes = slot_votes([(0x00, "ILdI4", "mem=stack+12"),
                            (0x04, "LitI4", "val=0"),
                            (0x08, "LtI4", "-"),
                            (0x0C, "ILdI4", "mem=stack+12"),
                            (0x10, "FLdRfVar", "mem=stack-144"),
                            (0x14, "CStr2Ansi", "-")], 12)
        kinds = {(kind, vtype) for kind, vtype, _label in votes}
        self.assertIn(("load", "Long"), kinds)
        self.assertIn(("store", "String"), kinds)
        # The filtered param arbitration picks the store-category String.
        self.assertEqual(flow_type([
            (0x00, "ILdI4", "mem=stack+12"),
            (0x04, "LitI4", "val=0"),
            (0x08, "LtI4", "-"),
            (0x0C, "ILdI4", "mem=stack+12"),
            (0x10, "FLdRfVar", "mem=stack-144"),
            (0x14, "CStr2Ansi", "-")]), ["String"])


if __name__ == "__main__":
    unittest.main()
