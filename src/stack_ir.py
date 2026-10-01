"""Stack-machine IR and expression tree building.

VB4 p-code is a stack machine: LitI2 pushes a constant, AddI2 pops two and
pushes one.  This module simulates the evaluation stack, folds instructions
into expression trees, and emits VB-style statements.

Control flow is owned by src/structuring.py, which builds the CFG and calls
StackMachine.process() only for straight-line instructions (For/Next go
through _loop_start/_loop_end for their stack bookkeeping).  Feeding a branch
or loop opcode to process() raises: a caller that bypassed the structurer
fails loudly instead of emitting a misplaced If/GoTo.
"""


import copy
import re

import declare_specs


# Compiled once: _subst_param runs for every load/store/loop instruction.
_STACK_POS_RE = re.compile(r'stack\+(\d+)')
_STACK_NEG_RE = re.compile(r'stack-(\d+)')

# Bound on a Redim's dimension count; a corrupt "dims=99999999" operand would
# otherwise pop tens of millions of <empty> values.
_REDIM_MAX_DIMS = 64


# ----------------------------------------------------------------------
# Operand parsing helpers
# ----------------------------------------------------------------------

def strip(expr_text):
    """Remove one redundant outer paren pair wrapping the whole string.

    Quote-aware: parens inside a "..." literal are ignored.  Examples:
    "()" -> "", "(a)(b)" -> "(a)(b)", "(a + b)" -> "a + b", '"(x)"' -> '"(x)"'.

    Assumes a '"' toggles string state; VB's doubled-quote escape (say ""hi"")
    briefly clears in_str between the two quotes, so a paren that straddles
    that gap could skew the depth count.  Operand texts here never contain a
    doubled quote, so the simple toggle is sufficient.
    """
    s = expr_text.strip()
    if len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        depth = 0
        in_str = False
        for k, ch in enumerate(s):
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and k < len(s) - 1:
                    return s
        return s[1:-1]
    return s


# Depth-0 infix ops that break under prefix negation (-a + b != -(a + b)).
# Every entry starts with a space because emitters render ops space-separated.
_NEG_PAREN_OPS = (
    " + ", " - ", " * ", " / ", " \\ ", " Mod ", " And ", " Or ", " Xor ",
    " Eqv ", " Imp ", " & ", " = ", " < ", " > ", " <= ", " >= ", " <> ",
)

def _has_top_level_binary_op(text):
    """True if text has a depth-0 infix operator (needs parens after -).

    All _NEG_PAREN_OPS entries start with a space, so a depth-0 space is the
    only possible operator start.  "^" (power) is handled separately.
    """
    depth = 0
    in_str = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            in_str = not in_str
        elif in_str:
            pass
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0:
            if ch == "^":
                return True
            if ch == " ":
                for op in _NEG_PAREN_OPS:
                    if text.startswith(op, i):
                        return True
        i += 1
    return False


def parse_mem(operand):
    """Normalize a mem=/global= operand to a readable reference.

    global=XXXXXXXX (ImpAd*) and mem=stack+8.fXXXX (FMem*) both address the
    form-module data block, so both render as Me.fXXXX (see docs/vb40032.md).
    """
    if operand and operand.startswith("global="):
        # Split off any '.suffix' (defensive; current binaries never emit one).
        token = operand[7:].split(".", 1)[0]
        try:
            return "Me.f%04X" % int(token, 16)
        except ValueError:
            # Malformed operand: pass it through rather than abort the proc.
            return operand
    if not operand or not operand.startswith("mem="):
        return operand
    ref = operand[4:]
    if ref.startswith("stack+8.f"):
        return "Me." + ref.split(".", 1)[1]
    parts = ref.split(".", 1)
    head = parts[0]
    if head and head[0] in "0123456789":
        result = "mem_" + head
        if len(parts) > 1:
            result += "." + parts[1]
        return result
    return ref


def parse_call(operand):
    """Parse call=NAME@ADDR -> name string."""
    if not operand or not operand.startswith("call="):
        return None
    body = operand[5:]
    if "@" in body:
        return body.rsplit("@", 1)[0]
    return body


def parse_target(operand):
    """Extract to=ADDR hex from a branch/loop operand."""
    if not operand or "to=" not in operand:
        return None
    tail = operand.split("to=", 1)[1].split()
    if not tail:
        return None
    token = tail[0].split(",")[0]
    try:
        return int(token, 16)
    except ValueError:
        return None


def parse_vcall_slot(operand):
    """Parse vcall=XXXX / this.vcall=XXXX -> slot hex string (None if absent)."""
    if not operand:
        return None
    for prefix in ("this.vcall=", "vcall="):
        if operand.startswith(prefix):
            tokens = operand[len(prefix):].split("@")[0].split()
            return tokens[0] if tokens else None
    return None


def parse_lit(operand):
    """Parse val=N / text='...' into a display literal."""
    if not operand:
        # Never return None: Expr.text is a string everywhere (e.g. .strip()).
        return ""
    if operand.startswith("val="):
        return operand[4:]
    if operand.startswith("text="):
        return operand[5:]
    return operand


def parse_lit_str(operand):
    """Extract the quoted string from a LitStr operand."""
    if not operand:
        return ""
    if "text=" in operand:
        return operand.split("text=", 1)[1]
    return repr(operand)


def _parse_dim_count(operand):
    """Extract dimension count from descriptor=0xNNNN."""
    if operand and "descriptor=" in operand:
        token = operand.split("descriptor=")[1].split()[0]
        try:
            return int(token, 16)
        except ValueError:
            return 0
    return 0


def _is_plumbing_temp(text):
    """True if a stranded stack value is a bare plumbing temp (FLdI4/
    FLdRfVar/LdFixedStr reference) that should not appear as a statement."""
    if not text:
        return True
    # Pure stack offsets: stack+8, stack-216
    if text.startswith("stack+") or text.startswith("stack-"):
        return "." not in text and "(" not in text
    # Pure mem_ refs
    if text.startswith("mem_"):
        return "(" not in text
    # LdFixedStr/StFixedStr length markers
    if text.startswith("len="):
        return True
    return False


def _field_ref(operand):
    """Render a MemLd/MemSt offset operand as '.fXXXX'.

    A trailing '.aNNNN' sub-offset is intentionally dropped: MemLd*/MemSt*
    only name the containing member.
    """
    if not operand or not operand.startswith("mem="):
        return ""
    ref = operand[4:]
    head = ref.split(".")[0]
    if head and head[0] in "0123456789":
        return ".f" + head
    # Non-numeric head: the caller concatenates addr + field, so a raw ref
    # would yield "addrstack+8.fXXXX".  Drop the field (unreachable for PAL).
    return ""


def _render_label(label, operand):
    """Render 'Label operand', omitting the '-' no-operand sentinel."""
    if operand and operand != "-":
        return "%s %s" % (label, operand)
    return label


# ----------------------------------------------------------------------
# Handler classification tables
# ----------------------------------------------------------------------

BINARY_OPS = {
    "AddI2": "+", "AddI4": "+", "AddR4": "+", "AddR8": "+", "AddCy": "+",
    "SubI2": "-", "SubI4": "-", "SubR4": "-", "SubR8": "-",
    "MulI2": "*", "MulI4": "*", "MulR4": "*", "MulR8": "*",
    "DivR4": "/", "DivR8": "/", "IDvI2": "\\", "IDvI4": "\\",
    "ModI2": "Mod", "ModI4": "Mod",
    "ConcatStr": "&",
    "OrI4": "Or", "OrI2": "Or", "OrUI1": "Or",
    "AndI4": "And", "AndI2": "And", "AndUI1": "And",
    "XorI4": "Xor", "XorI2": "Xor", "XorUI1": "Xor",
}

COMPARE_OPS = {
    "EqI2": "=", "EqI4": "=", "EqR4": "=", "EqR8": "=", "EqUI1": "=",
    "NeI2": "<>", "NeI4": "<>", "NeR8": "<>", "NeUI1": "<>",
    "LtI2": "<", "LtI4": "<", "LtR4": "<", "LtR8": "<", "LtUI1": "<",
    "LeI2": "<=", "LeI4": "<=", "LeR4": "<=", "LeR8": "<=", "LeUI1": "<=",
    "GtI2": ">", "GtI4": ">", "GtR4": ">", "GtR8": ">", "GtUI1": ">",
    "GeI2": ">=", "GeI4": ">=", "GeR4": ">=", "GeR8": ">=", "GeUI1": ">=",
}

UNARY_OPS = {
    "NotI4": "Not", "NotI2": "Not", "NotUI1": "Not",
    "UMiI2": "-", "UMiI4": "-", "UMiR8": "-", "UMiR4": "-", "UMiUI1": "-",
    "FnLenStr": "Len",
    "FnCSngUI1": "CSng", "FnCSngI2": "CSng", "FnCSngI4": "CSng", "FnCSngR8": "CSng",
    "FnIntI2": "Int", "FnIntI4": "Int", "FnIntR8": "Int", "FnIntUI1": "Int",
    "FnAbsI2": "Abs", "FnAbsI4": "Abs", "FnAbsR8": "Abs", "FnAbsUI1": "Abs",
    "FnSgnI2": "Sgn", "FnSgnI4": "Sgn", "FnSgnR8": "Sgn", "FnSgnUI1": "Sgn",
    "FnFixR8": "Fix", "FnFixR4": "Fix",
}

# Transparent conversions (text unchanged), pop 1/push 1 in process().
# CStr2Ansi / CStr2Uni are special-cased there and pop 2.
CONV_LABELS = {
    "CI4I2", "CI2I4", "CI4I4", "CR8I2", "CR8I4", "CR4I2", "CR4I4",
    "CBoolI4", "CBoolI2", "CI2UI1", "CI4UI1", "CUI1I2", "CUI1I4",
    "CCyI4", "CCyR8",
    "CI2R8", "CI4R8", "CR4R8", "CR8R4", "CI2R4", "CI4R4",
    "CStr2Ansi", "CStr2Uni",
}

LOAD_LABELS = {
    "LitI2", "LitI2_10", "LitI4", "LitR4", "LitR8",
    "LitStr", "LitVarStr", "LitDate",
    "FLdI2", "FLdI4", "FLdR4", "FLdR8", "FLdFPR4", "FLdFPR8", "FLdUI1",
    "ILdI2", "ILdI4", "ILdR8",
    "FMemLdI2", "FMemLdI4", "FMemLdR4", "FMemLdR8", "FMemLdStr",
    "LitVarI2", "LitVar_Missing",
    "FLdRfVar", "FLdZeroAd",
    # ByRef field loads: push the address reference (call/array base).
    "FMemLdRf", "FMemLdRfVar", "FLdRf",
    "ImpAdLdRf", "ImpAdLdPr",
    "ImpAdLdI2", "ImpAdLdI4", "ImpAdLdR4", "ImpAdLdR8", "ImpAdLdCy",
    "ImpAdLdStr", "ImpAdLdVar",
    "FLdPr", "FLdPrThis",
}

# Array element load: pop 2 (index + arrayref), push 1.
ARY_LOAD = {"Ary1LdI2", "Ary1LdI4", "Ary1LdRf", "Ary1LdPr", "Ary1LdR8",
            "Ary1LdUI1", "Ary1LdFPR4", "Ary1LdFPR8", "Ary1LdR4"}

# Multi-dimensional array load: descriptor gives dimension count.
ARY_N_LOAD = {"AryLdPr", "AryLdRf"}

# Array element store: pop 3 (value + index + arrayref).
ARY_STORE = {"Ary1StI2", "Ary1StI4", "Ary1StStrCopy", "Ary1StVar",
             "Ary1StR4", "Ary1StR8", "Ary1StUI1"}

# Member load/store via a computed address on the stack.
#   MemLd* : pop 1 (address), push addr.field
#   MemSt* : pop 2 (value + address), emit addr.field = value
MEM_LD = {"MemLdI2", "MemLdI4", "MemLdStr", "MemLdR8", "MemLdR4",
          "MemLdFPR4", "MemLdFPR8", "MemLdRf"}
MEM_ST = {"MemStI2", "MemStI4", "MemStR8", "MemStR4", "MemStFPR4",
          "MemStFPR8", "MemStUI1"}

STORE_LABELS = {
    "FStI2", "FStI4", "FStR4", "FStR8", "FStFPR4", "FStFPR8", "FStUI1",
    "IStI2", "IStI4",
    "FMemStI2", "FMemStI4", "FMemStR4",
    "FStStr", "FStStrCopy", "FStStrNoPop",
    "FStVarCopyObj",
    "ImpAdStI2", "ImpAdStI4", "ImpAdStR4", "ImpAdStR8",
}

STORE_NOPOP = {"FStStrNoPop"}

# SetLastSystemError ends a void Declare call: flush the eval stack so the
# discarded call result becomes a statement.  It is deliberately not a no-op
# (that emits hundreds of _opaque comments and misplaces void calls); it never
# drains a live condition.
FREE_LABELS = {
    "SetLastSystemError",
}

# FFree* free frame slots, not eval-stack items.  They must not flush the
# eval stack: it may hold a comparison result still needed by the next
# BranchF/Call (the root of 17 of the 22 "<empty>" conditions).
FFREE_LABELS = {
    "FFree1Str", "FFree1Var", "FFree1Ad", "FFree1R4", "FFree1R8",
    "FFreeStr", "FFreeVar", "FFreeAd",
    "FFree1UI1", "FFree1I2", "FFree1I4",
}

CALL_LABELS = {
    "ImpAdCall", "ImpAdCallI2", "ImpAdCallI4", "ImpAdCallHresult",
    "ImpAdCallFPR4", "ImpAdCallFPR8", "ImpAdCallCy", "ImpAdCallAd",
}

CALL_NORETURN = {"ImpAdCallHresult"}

# Runtime function arg counts, each verified from the p-code push sequence at
# its call sites.  Add an entry only with the proc/address that proves it.
# rtcMidCharVar(4)=Mid$, rtcLeftCharVar(3)=Left$, rtcStrFromVar(1)=Str$,
# rtcVarStrFromVar(2)=CStr$, rtcLeftTrimVar(2)=LTrim$, rtcAnsiValueBstr(1)=Asc,
# rtcRandomNext(1)=Rnd, rtcRandomize(1), rtcMsgBox(3), rtcDoEvents(0),
# rtcGetTimer(0), rtcBstrFromAnsi(1)=Chr (see RUNTIME_RENDER).
RUNTIME_SPECS = {
    "VB40032.rtcMidCharVar": 4,
    "VB40032.rtcLeftCharVar": 3,
    "VB40032.rtcStrFromVar": 1,
    "VB40032.rtcVarStrFromVar": 2,
    "VB40032.rtcLeftTrimVar": 2,
    "VB40032.rtcAnsiValueBstr": 1,
    "VB40032.rtcRandomNext": 1,
    "VB40032.rtcRandomize": 1,
    "VB40032.rtcMsgBox": 3,
    "VB40032.rtcDoEvents": 0,
    "VB40032.rtcGetTimer": 0,
    "VB40032.rtcBstrFromAnsi": 1,
}

# rtcBstrFromAnsi builds a BSTR from one ANSI code == Chr$(code); all three
# PAL.EXE sites build Chr(48 + n) & ".RPG" filenames.
RUNTIME_RENDER = {
    "VB40032.rtcBstrFromAnsi": "Chr",
}

# Runtime helpers with a ByRef output slot (pushed last via FLdRfVar).  The
# call records an alias so later loads of that slot render the VB expression.
# TOS=ARG1 (same convention as _call), so the output is ARG1 (out_index 0)
# and _byref_call does not reverse.
#   nargs/out_index/renderer; input_map maps VB arg position -> input index.
# Verified: rtcMidCharVar @00405718 pushes [1, stack-140, a0, &out] ->
# Mid(a0, stack-140, 1) (char scan), so input_map = [0, 1, 2].
RUNTIME_BYREF_SPECS = {
    "VB40032.rtcVarStrFromVar": {
        "nargs": 2, "out_index": 0, "renderer": "CStr",
        "input_map": [0]},
    "VB40032.rtcLeftTrimVar": {
        "nargs": 2, "out_index": 0, "renderer": "LTrim",
        "input_map": [0]},
    "VB40032.rtcMidCharVar": {
        "nargs": 4, "out_index": 0, "renderer": "Mid",
        "input_map": [0, 1, 2]},  # Mid(source, start, length)
    "VB40032.rtcLeftCharVar": {
        "nargs": 3, "out_index": 0, "renderer": "Left",
        "input_map": [0, 1]},  # Left(source, length)
}

# Win32 arg counts.  Keys follow the Lib string in PAL.EXE's Declare table
# (what the disassembler prints in call=NAME@ADDR): the binary says
# winmm.ShowCursor / kernel32.mciSendStringA even though the real DLLs are
# user32/winmm.  Do not "fix" them -- a mismatch silently loses the arity.
# _hread/_hwrite(h,buf,n)=3, _lclose(h)=1, _lcreat(path,attr)=2,
# _llseek(h,off,org)=3, _lopen(path,mode)=2, mciSendStringA=4, ShowCursor=1.
WIN32_SPECS = {
    "kernel32._hread": 3,
    "kernel32._hwrite": 3,
    "kernel32._lclose": 1,
    "kernel32._lcreat": 2,
    "kernel32._llseek": 3,
    "kernel32._lopen": 2,
    "kernel32.mciSendStringA": 4,
    "winmm.ShowCursor": 1,
}

# Call argument order (see _collect_args): the p-code pushes args so the TOS
# is ARG1, so popping TOS-first already yields source order (no reverse).
VCALL_LABELS = {"VCallHresult", "VCallI2", "VCallI4", "VCallAd",
                 "ThisVCallHresult", "ThisVCallI2", "ThisVCallI4",
                 "ThisVCallAd"}

TERMINATOR_LABELS = {
    "ExitProc", "ExitProcHresult", "ExitProcI2", "ExitProcStr",
    "End", "ExitProcCbHresult",
}

LOOP_START = {"ForI2", "ForStepI2", "ForI4", "ForStepI4"}
LOOP_END = {"NextI2", "NextStepI2", "NextI4", "NextStepI4"}

COND_BRANCH = {"BranchT", "BranchF", "BranchTVar", "BranchFVar",
                   "BranchTVarFree", "BranchFVarFree"}
UNCOND_BRANCH = {"Branch", "Gosub"}

# Fixed-length string buffer ops.
#   StFixedStr: pop source BSTR + buffer address, store (no output).
#   LdFixedStr: pop buffer address, push the fixed-string value.
FIXED_STR_STORE = {"StFixedStr"}
FIXED_STR_LOAD = {"LdFixedStr"}

# Statement-level ops with no stack effect (emit as-is).
STMT_LABELS = {
    "AryLock", "AryUnlock",
}

# Statement ops that pop eval-stack values (counts verified by handler
# disassembly; operand order documented in _stmt_pop).
STMT_POP_LABELS = {
    "Close": 1,
    "Erase": 1,
    "CopyBytes": 2,
    "Open": 3,
    "GetRecOwner3": 2,
}

# Variant binary ops: pop 2, push 1 (AddVar = numeric add or string concat).
VAR_BINARY_OPS = {
    "AddVar": "+",
    "EqVar": "=",
}

# Transparent plumbing: pop 1, push 1 (address/pointer manipulation).
PLUMBING = {
    "PopTmpLdAd2", "PopTmpLdAd4", "PopTmpLdAdStr", "PopTmpLdAd1",
    "PopFPR4", "PopFPR8", "PopAd", "PopAdLdVar",
    "FStAdNoPop",
    "NewIfNullPr", "NewIfNullAd", "NewIfNullObj", "NewIfNullVar",
    "CVarRef", "CVarI2", "CVarStr", "CVarR4", "CVarR8", "CVarI4",
    "CR4Var", "CI4Var", "CStrVarTmp",
    "LateIdLdVar",
    "HardType",
}


# ----------------------------------------------------------------------
# Stack machine
# ----------------------------------------------------------------------

class Expr(object):
    """An eval-stack expression.

    effects: deferred call side-effects as (order, va, text) triples embedded
    in this expression.  They are realised when the value is consumed by a
    store, condition, or outer call, and emitted as standalone "Call ..."
    statements when the value is flushed unconsumed.
    """
    __slots__ = ("text", "is_call", "effects")

    def __init__(self, text, is_call=False, effects=None):
        self.text = text
        self.is_call = is_call
        self.effects = effects or []

    def __repr__(self):
        return "Expr(%r)" % self.text


class Stmt(object):
    """An emitted statement with its source VA, indent change, and order."""

    __slots__ = ("va", "indent_delta", "text", "order")

    def __init__(self, va, indent_delta, text, order=0):
        self.va = va
        self.indent_delta = indent_delta   # +1 = open block, -1 = close
        self.text = text
        self.order = order   # monotonically increasing source order


class StackMachine(object):
    """Expression folder and statement emitter for one procedure.

    Walks straight-line instructions in order, maintaining the evaluation
    stack and emitting Stmt objects.  Control-flow opcodes are rejected (see
    the module docstring); structuring.py drives those and calls in here for
    the For/Next stack bookkeeping.
    """

    # Mutable state captured by checkpoint()/restore(); listed here so
    # rollback cannot drift.  Lists are shallow-copied (Expr is immutable
    # after construction); dicts are deep-copied.  arg_map/param_map/
    # exit_keyword/result_* are set once by _prepare_proc but included so
    # restore() is complete by construction.
    _SNAPSHOT_SCALARS = ("_source_order", "exit_keyword",
                         "result_slot", "result_name")
    _SNAPSHOT_LISTS = ("stack", "statements", "pending_loops")
    _SNAPSHOT_DICTS = ("temp_aliases", "_alias_effects", "_pending_byref",
                       "arg_map", "param_map")

    def __init__(self):
        self.stack = []
        self.statements = []
        # Loop-var ref text per open For, innermost last; _loop_end consumes
        # the NextI2 write-back from the top entry.
        self.pending_loops = []
        self.arg_map = {}  # proc name -> arg count
        self.param_map = {}  # stack offset -> param name (e.g. {12: "a0"})
        self.exit_keyword = "Exit Sub"  # Functions override to "Exit Function"
        self.result_slot = None  # Function result-slot offset (e.g. -134)
        self.result_name = None  # Function result slot renders as the proc name
        self._source_order = 0  # monotonic counter for statement ordering
        self.temp_aliases = {}  # frame slot -> alias expression text
        self._alias_effects = {}  # frame slot -> deferred effects for alias
        # ByRef calls whose output slot has not been loaded yet:
        # slot -> (order, va, call_text, effects); drained by
        # _flush_pending_byref so an unread call is not dropped.
        self._pending_byref = {}

    def _subst_param(self, text):
        """Replace stack+N references with parameter names where applicable,
        and the Function result slot (stack-N) with the proc name."""
        if not text:
            return text
        if self.param_map:
            def repl(m):
                off = int(m.group(1))
                return self.param_map.get(off, m.group(0))
            text = _STACK_POS_RE.sub(repl, text)
        if self.result_slot is not None and self.result_name:
            rslot, rname = self.result_slot, self.result_name
            def repl_neg(m):
                return rname if -int(m.group(1)) == rslot else m.group(0)
            text = _STACK_NEG_RE.sub(repl_neg, text)
        return text

    def _slot_key(self, operand):
        """Canonical frame-slot key for alias create/invalidate.

        _subst_param renames the Function result slot (stack-134) to the proc
        name, so raw text would not match the recorded alias.
        """
        return self._subst_param(parse_mem(operand))

    def _resolve_alias(self, slot):
        """Resolve a frame-slot alias -> (text, effects, is_call), or None.

        A pending ByRef call's own effect is appended after the input effects
        so a stranded alias renders as "Call CStr(x)".  Consuming the pending
        entry here prevents the discarded-call fallback from emitting it twice.
        """
        alias = self.temp_aliases.get(slot)
        if alias is None:
            return None
        effects = list(self._alias_effects.pop(slot, []))
        pending = self._pending_byref.pop(slot, None)
        is_call = False
        if pending is not None:
            order, va, text, _input_effects = pending
            effects.append((order, va, text))
            is_call = True
        del self.temp_aliases[slot]
        return alias, effects, is_call

    # -- stack helpers ------------------------------------------------------

    def push(self, text, is_call=False, effects=None):
        self.stack.append(Expr(text, is_call=is_call, effects=effects or []))

    def pop(self):
        if self.stack:
            return self.stack.pop()
        return Expr("<empty>")

    def emit(self, va, indent_delta, text):
        self._source_order += 1
        self.statements.append(
            Stmt(va, indent_delta, text, order=self._source_order))

    def _insert_stmt(self, _origin_order, va, indent_delta, text):
        """Insert a deferred statement at its original p-code address.

        Positions by instruction address (va), not by source order: a later
        flush can assign a higher order than an earlier normal statement,
        which would misplace the insert (verified: pub_148 leaked bufPtr
        below two earlier deferred calls).  _origin_order is accepted for
        call-site readability only.
        """
        self._source_order += 1
        new_stmt = Stmt(va, indent_delta, text, order=self._source_order)
        # Insert after the last statement whose address is <= va.  Statements
        # are emitted in address order apart from earlier inserts, so a
        # linear scan from the end is both correct and cheap.
        insert_idx = 0
        for i in range(len(self.statements) - 1, -1, -1):
            if self.statements[i].va <= va:
                insert_idx = i + 1
                break
        self.statements.insert(insert_idx, new_stmt)

    def checkpoint(self):
        """Snapshot all mutable emission state (used by the ElseIf-leg probe).

        CONTRACT: the snapshot must cover ALL mutable state — statements,
        stack, deferred calls, alias effects, bookkeeping scalars — so
        that restore() is a complete rollback.  structuring.py's
        _leg_is_pure_cond trial-processes a candidate leg and then
        restores, relying on no probe effects surviving (only the
        "DEFERRED calls are invisible" subtlety documented there, which
        is a property of deferral, not of an incomplete snapshot)."""
        snap = {name: getattr(self, name) for name in self._SNAPSHOT_SCALARS}
        for name in self._SNAPSHOT_LISTS:
            snap[name] = list(getattr(self, name))
        for name in self._SNAPSHOT_DICTS:
            # deepcopy, not dict(): _alias_effects values are lists, so a
            # shallow copy would share them with the live state and an
            # in-place probe edit would survive restore().
            snap[name] = copy.deepcopy(getattr(self, name))
        return snap

    def restore(self, cp):
        """Roll back to a checkpoint() snapshot (in place: callers hold
        references to self.statements / self.stack)."""
        for name in self._SNAPSHOT_SCALARS:
            setattr(self, name, cp[name])
        for name in self._SNAPSHOT_LISTS:
            getattr(self, name)[:] = cp[name]
        for name in self._SNAPSHOT_DICTS:
            target = getattr(self, name)
            target.clear()
            target.update(cp[name])

    def _flush_pending_byref(self, slot=None):
        """Emit a ByRef call whose output slot was never loaded.

        _byref_call records an alias but pushes nothing; an unread call would
        otherwise vanish.  Emitted as a discarded "Call <expr>" at its origin.
        """
        if slot is None:
            pending = list(self._pending_byref.values())
            self._pending_byref.clear()
        else:
            entry = self._pending_byref.pop(slot, None)
            pending = [entry] if entry is not None else []
        for origin_order, origin_va, call_text, effects in pending:
            # Inputs are evaluated before the call: surface their effects first.
            for eff_order, eff_va, eff_text in effects:
                self._insert_stmt(eff_order, eff_va, 0,
                                  "Call %s" % eff_text)
            self._insert_stmt(origin_order, origin_va, 0,
                              "Call %s" % call_text)

    def _emit_stranded(self, item, va):
        """Emit one stranded eval-stack value.

        Shared by the three flush paths: effects become "Call ..." statements
        at their origin, a bare call value becomes "Call <text>", and plumbing
        temps / empty / <missing> values are dropped.  Returns True if the item
        was consumed (effects realised or text emitted), not merely dropped.
        """
        if not item.text or item.text in ("<missing>", "<empty>"):
            return False
        if item.effects:
            for origin_order, origin_va, call_text in item.effects:
                self._insert_stmt(origin_order, origin_va, 0,
                                  "Call %s" % call_text)
            return True
        if not item.is_call and _is_plumbing_temp(item.text.strip()):
            return False
        stmt = item.text
        if item.is_call:
            stmt = "Call " + stmt
        self.emit(va, 0, stmt)
        return True

    def _realise_effects(self, items):
        """Insert each item's deferred Call effects at their origin.

        Only for callers that discard the operand text; callers that embed the
        text already realise the effect and must not call this (would duplicate).
        """
        for item in items:
            for origin_order, origin_va, call_text in item.effects:
                self._insert_stmt(origin_order, origin_va, 0,
                                  "Call %s" % call_text)

    def flush_leftovers(self, va):
        """Emit stranded stack values as statements (discarded results).

        Bare plumbing temps (stack-216, mem_*, len=) are dropped.  Deferred
        effects become "Call ..." statements inserted at their origin, so a
        call appears before later stores that consumed its result.
        """
        # A ByRef call whose output slot was never loaded is also a
        # discarded call; surface it here (at its own va).
        self._flush_pending_byref()
        items = self.stack[:]
        self.stack[:] = []
        for item in items:
            self._emit_stranded(item, va)

    def _flush_to_depth(self, va, depth):
        """Flush stack values above *depth* as discarded calls (closing an If)."""
        if len(self.stack) <= depth:
            return
        excess = self.stack[depth:]
        del self.stack[depth:]
        for item in excess:
            self._emit_stranded(item, va)

    def flush_calls_above(self, va, depth):
        """Flush only stranded CALL values above *depth* at a block boundary.

        Keeps the Call inside the block that produced it instead of shifting
        later label positions.
        """
        while len(self.stack) > depth:
            item = self.stack[depth]
            if not item.is_call and not item.effects:
                break  # non-call value: leave it for the next block
            self.stack.pop(depth)
            self._emit_stranded(item, va)

    # -- main dispatch ------------------------------------------------------

    def process(self, instr):
        label = instr.label
        operand = instr.operand
        va = instr.pos

        if label in BINARY_OPS:
            self._binary(BINARY_OPS[label])
        elif label in COMPARE_OPS:
            self._binary(COMPARE_OPS[label])
        elif label in VAR_BINARY_OPS:
            self._binary(VAR_BINARY_OPS[label])
        elif label in UNARY_OPS:
            self._unary(UNARY_OPS[label])
        elif label in CONV_LABELS:
            if label == "CStr2Ansi":
                # CStr2Ansi: pop 2 (slot ptr at TOS, source below), convert,
                # store ptr in the slot.  Alias the slot to the source so the
                # following FLdI4 renders the original string (VB passes a
                # String to an ANSI API implicitly).
                slot_ref = self.pop()
                src = self.pop()
                slot = strip(slot_ref.text)
                if slot and not slot.startswith("<"):
                    self.temp_aliases[slot] = strip(src.text)
                    if src.effects:
                        self._alias_effects[slot] = list(src.effects)
            elif label == "CStr2Uni":
                # CStr2Uni: pop 2 (ANSI ptr + dest slot ptr); the value only
                # feeds the string-free epilogue, so no alias.
                self.pop()
                self.pop()
            # else: transparent conversion (pop 1 push 1, text unchanged).
        elif label in PLUMBING:
            pass  # transparent pointer/address plumbing
        elif label in STMT_LABELS:
            self._stmt(label, operand, va)
        elif label in STMT_POP_LABELS:
            self._stmt_pop(label, operand, va)
        elif label == "Redim":
            self._redim(label, operand, va)
        elif label in LOAD_LABELS:
            self._load(label, operand)
        elif label in ARY_LOAD:
            self._ary_load(label)
        elif label in ARY_N_LOAD:
            self._ary_n_load(label, operand)
        elif label in MEM_LD:
            self._mem_ld(label, operand)
        elif label in STORE_LABELS:
            self._store(label, operand, va)
        elif label in FIXED_STR_STORE:
            self._fixed_str_store(label, operand, va)
        elif label in FIXED_STR_LOAD:
            self._fixed_str_load(label, operand, va)
        elif label in MEM_ST:
            self._mem_st(label, operand, va)
        elif label in ARY_STORE:
            self._ary_store(label, operand, va)
        elif label in CALL_LABELS:
            self._call(label, operand, va)
        elif label in VCALL_LABELS:
            self._vcall(label, operand, va)
        elif label in FREE_LABELS:
            self.flush_leftovers(va)
        elif label in FFREE_LABELS:
            # FFree* free frame slots, not eval-stack items: no stack effect,
            # no flush.  Just invalidate any aliases for the freed slots.
            if operand and "stack=[" in operand:
                # FFreeVar byteLen=N stack=[-248, -264, ...].  Cut at the
                # FIRST ']' (rstrip would strip a stray suffix into bogus keys).
                slots_part = operand.split("stack=[", 1)[1].split("]", 1)[0]
                for s in slots_part.split(","):
                    s = s.strip()
                    if s:
                        key = self._slot_key("stack" + s)
                        if key in self.temp_aliases:
                            del self.temp_aliases[key]
                        self._alias_effects.pop(key, None)
                        # A freed slot holding an unresolved ByRef call means
                        # the call result was discarded.
                        self._flush_pending_byref(key)
            elif operand and "mem=" in operand:
                key = self._slot_key(operand)
                if key in self.temp_aliases:
                    del self.temp_aliases[key]
                self._alias_effects.pop(key, None)
                self._flush_pending_byref(key)
        elif label in TERMINATOR_LABELS:
            self._terminator(label, va)
        elif label == "Return":
            self.emit(va, 0, "Return")
        elif (label in COND_BRANCH or label in UNCOND_BRANCH
              or label in LOOP_START or label in LOOP_END):
            # Control flow belongs to structuring.py, which handles these
            # opcodes itself and only calls in for straight-line instructions
            # (For/Next bookkeeping goes through _loop_start/_loop_end).
            # Reaching here means a caller bypassed the structurer.
            raise RuntimeError(
                "control-flow opcode %s @0x%08X reached "
                "StackMachine.process(); use structuring.structure_proc"
                % (label, va))
        else:
            self._opaque(label, operand, va)

    # -- handlers -----------------------------------------------------------

    def _binary(self, op):
        b = self.pop()
        a = self.pop()
        effects = list(a.effects) + list(b.effects)
        # Unconditional parens: the p-code operand tree is precedence-flat, so
        # wrapping every binary result guarantees the rendered grouping matches.
        self.push("(%s %s %s)" % (a.text, op, b.text), effects=effects)

    def _unary(self, op):
        a = self.pop()
        effects = list(a.effects)
        if op == "-":
            text = strip(a.text)
            if _has_top_level_binary_op(text) or text.startswith("-"):
                # UMi* negates the whole operand: -(a + b) != -a + b.
                # A leading '-' is parenthesized too: "--a" is valid VB but
                # reads as a typo, while "-(-a)" is unambiguous.
                self.push("-(" + text + ")", effects=effects)
            else:
                self.push("-" + text, effects=effects)
        elif op == "Not":
            self.push("Not (%s)" % strip(a.text), effects=effects)
        else:
            # Function-style unary ops render as Len(x), not "Len (x)".
            self.push("%s(%s)" % (op, strip(a.text)), effects=effects)

    def _load(self, label, operand):
        if label == "LitI2_10" and "val=" not in (operand or ""):
            # Dedicated push-10 opcode; never leak the '-' sentinel.
            self.push("10")
        elif label in ("LitI2", "LitI2_10", "LitI4", "LitR4", "LitR8", "LitDate"):
            self.push(parse_lit(operand))
        elif label in ("LitStr", "LitVarStr"):
            self.push(parse_lit_str(operand))
        elif label == "LitVar_Missing":
            self.push("<missing>")
        elif label == "LitVarI2":
            if operand and "val=" in operand:
                # An empty val= would make split() yield [] -> IndexError.
                token = operand.split("val=", 1)[1].strip()
                self.push(token.split()[0] if token else "<missing>")
            else:
                ref = self._subst_param(parse_mem(operand))
                self.push(ref if ref and ref != "-" else "<missing>")
        elif label == "FLdZeroAd":
            self.push("0")
        elif label == "FLdPrThis":
            # Push Me; the operand is the '-' sentinel, not a literal.
            self.push("Me")
        elif label == "FLdPr":
            # Push the frame-slot object pointer (Me on a malformed operand).
            if operand and operand != "-":
                self.push(self._subst_param(parse_mem(operand)))
            else:
                self.push("Me")
        elif label.startswith("ImpAdLd"):
            # ImpAdLd* push a form-module slot ref; global= already renders
            # Me.fXXXX, so it skips _subst_param (nothing to rewrite).
            # A missing operand must not reach startswith/parse_mem as None.
            operand = operand or ""
            if operand.startswith("global="):
                self.push(parse_mem(operand))
            else:
                self.push(self._subst_param(parse_mem(operand)))
        elif label == "FLdRfVar":
            slot = self._subst_param(parse_mem(operand))
            # Resolve a ByRef alias if this slot has one.
            resolved = self._resolve_alias(slot)
            if resolved is not None:
                text, effects, is_call = resolved
                self.push(text, is_call=is_call, effects=effects)
            else:
                self.push(slot)
        elif label in ("FLdI2", "FLdI4", "FLdR4", "FLdR8", "FLdUI1"):
            # Resolve a CStr2Ansi/ByRef alias if this slot has one.
            slot = self._subst_param(parse_mem(operand))
            resolved = self._resolve_alias(slot)
            if resolved is not None:
                text, effects, is_call = resolved
                self.push(text, is_call=is_call, effects=effects)
            else:
                self.push(slot)
        else:
            self.push(self._subst_param(parse_mem(operand)))

    def _ary_load(self, label):
        # Ary1Ld*: stack top = arrayref, below = index.
        ary = self.pop()
        idx = self.pop()
        # idx is the deeper operand (pushed first), so its deferred effects
        # precede the array ref's in evaluation order.
        effects = list(idx.effects) + list(ary.effects)
        self.push("%s(%s)" % (strip(ary.text), strip(idx.text)),
                  effects=effects)

    def _ary_n_load(self, label, operand):
        # AryLd* multi-dim; fall back to 2 dims (AryLdPr/Rf are always 2-D
        # here, and 0 dims would collapse to the bare array name).
        ndim = _parse_dim_count(operand)
        if ndim <= 0:
            ndim = 2
        ary = self.pop()
        indices = [self.pop() for _ in range(ndim)]
        indices.reverse()
        # indices are the deeper operands (pushed first); ary is TOS last.
        effects = []
        for x in indices:
            effects.extend(x.effects)
        effects.extend(ary.effects)
        idx_str = ", ".join(strip(x.text) for x in indices)
        self.push("%s(%s)" % (strip(ary.text), idx_str), effects=effects)

    def _ary_store(self, label, operand, va):
        # Ary1St*: stack top = arrayref, below = index, below = value.
        # The texts are embedded in the assignment, so effects are realised.
        ary = self.pop()
        idx = self.pop()
        val = self.pop()
        self.emit(va, 0, "%s(%s) = %s" % (
            strip(ary.text), strip(idx.text), strip(val.text)))

    def _mem_ld(self, label, operand):
        # MemLd*: pop 1 (address), push addr.field.
        addr = self.pop()
        field = _field_ref(operand)
        self.push("%s%s" % (strip(addr.text), field),
                  effects=list(addr.effects))

    def _mem_st(self, label, operand, va):
        # MemSt*: stack top = address, below = value; texts are embedded.
        addr = self.pop()
        val = self.pop()
        field = _field_ref(operand)
        self.emit(va, 0, "%s%s = %s" % (
            strip(addr.text), field, strip(val.text)))

    def _store(self, label, operand, va):
        dst = self._subst_param(parse_mem(operand))
        val = self.pop()
        # Save effects before the store realises them: the NoPop variant
        # re-pushes the value for its real consumer and must keep them.  Do
        # not clear val.effects in place -- a checkpoint snapshot may still
        # reference the popped Expr.
        saved_effects = list(val.effects)
        # The destination is being overwritten: drop its alias.
        if dst in self.temp_aliases:
            del self.temp_aliases[dst]
        self._alias_effects.pop(dst, None)
        # An unresolved ByRef call in the destination is discarded by the store.
        self._flush_pending_byref(dst)
        if label in STORE_NOPOP:
            # FStStrNoPop copies the BSTR ref into a frame slot for the
            # FFree1Str epilogue; the value stays on the eval stack for the
            # real consumer (slot never read back, all 29 PAL sites verified).
            # Emitting an assignment produced phantom statements and
            # duplicated the call text.  Re-push with effects intact.
            self.push(val.text, is_call=val.is_call, effects=saved_effects)
        else:
            self.emit(va, 0, "%s = %s" % (dst, strip(val.text)))

    def _fixed_str_store(self, label, operand, va):
        # StFixedStr: pop source BSTR + buffer address (silent store).
        src = self.pop()  # source string
        buf = self.pop()  # buffer address
        # No statement is emitted, so the discarded texts' effects must be
        # surfaced explicitly.
        self._realise_effects((src, buf))

    def _fixed_str_load(self, label, operand, va):
        # LdFixedStr: pop buffer address, push the fixed-string value.
        buf = self.pop()
        self.push(buf.text, effects=list(buf.effects))

    def _call(self, label, operand, va):
        name = parse_call(operand) or "<unknown>"
        byref_spec = RUNTIME_BYREF_SPECS.get(name)
        if byref_spec is not None:
            self._byref_call(name, byref_spec, va)
            return
        nargs = self.arg_map.get(name)
        if nargs is None:
            # Try runtime/Win32/Declare specs for external calls.
            nargs = RUNTIME_SPECS.get(name)
            if nargs is None:
                nargs = WIN32_SPECS.get(name)
            if nargs is None:
                nargs = declare_specs.DECLARE_SPECS.get(name)
        # Args push so TOS=ARG1, so popping TOS-first is already source order
        # (reverse=False) for internal, Declare, and rtc* calls alike.  strict:
        # a known arity larger than the eval stack is a p-code parse error, so
        # raise (per-proc error stub) instead of silently dropping args.  Never
        # fires on PAL.EXE (all 198 procs verified), so output is unchanged.
        args = self._collect_args(nargs, reverse=False, strict=True)
        disp = RUNTIME_RENDER.get(name, name)
        if label in CALL_NORETURN:
            # No-return call: same "Call name(args)" shape, no result push.
            self.emit(va, 0, "Call %s(%s)" % (disp, args))
        else:
            call_text = "%s(%s)" % (disp, args)
            # Deferred effect: if the result is never consumed,
            # flush_leftovers emits "Call name(args)" at its origin.
            self.push(call_text, is_call=True,
                      effects=[(self._source_order, va, call_text)])

    def _byref_call(self, name, spec, va):
        """Handle a ByRef runtime function (e.g. rtcVarStrFromVar).

        Inputs plus a ByRef output slot (pushed via FLdRfVar); the result is
        written to that slot.  Record an alias so later loads of the slot
        resolve to the VB expression (e.g. CStr(input)).
        """
        nargs = spec["nargs"]
        out_index = spec["out_index"]
        renderer = spec["renderer"]
        # Check the output slot is present BEFORE popping: a malformed operand
        # must not drain the eval stack and then bail out.  Surface the call
        # as a diagnostic so a truncated stack does not silently drop it.
        if len(self.stack) <= out_index:
            self.emit(va, 0, "# %s <stack underflow>" % renderer)
            return
        count = min(nargs, len(self.stack))
        items = [self.pop() for _ in range(count)]
        # Pad a short stack with <missing> so out_index/input_map stay total;
        # the call still surfaces rather than being silently dropped.
        while len(items) < nargs:
            items.append(Expr("<missing>"))
        out_item = items[out_index]
        out_slot = strip(out_item.text)
        # Input args = everything except the ByRef output.
        input_items = [items[i] for i in range(len(items)) if i != out_index]
        # Resolve any aliases in the input items (consuming them).
        resolved = []
        for item in input_items:
            t = strip(item.text)
            alias = self.temp_aliases.get(t)
            if alias is not None:
                resolved.append(alias)
                del self.temp_aliases[t]
                self._alias_effects.pop(t, None)
                self._pending_byref.pop(t, None)
            else:
                resolved.append(t)
        # Reorder to VB source order; the bounds check keeps a malformed spec
        # from raising IndexError.
        input_map = spec.get("input_map")
        if input_map:
            input_texts = [resolved[i] if i < len(resolved) else "<missing>"
                           for i in input_map]
        else:
            input_texts = resolved
        # Build the VB expression.
        if renderer in ("CStr", "LTrim"):
            expr = "%s(%s)" % (renderer, input_texts[0])
        elif renderer == "Left":
            expr = "Left(%s, %s)" % (input_texts[0], input_texts[1])
        elif renderer == "Mid":
            expr = "Mid(%s, %s, %s)" % (
                input_texts[0], input_texts[1], input_texts[2])
        else:
            expr = "%s(%s)" % (renderer, ", ".join(input_texts))
        all_effects = []
        for item in items:
            all_effects.extend(item.effects)
        # An absent/malformed output slot can never be resolved by a later
        # load, so surface the call as a discarded Call instead.
        if out_slot and not out_slot.startswith("<"):
            self.temp_aliases[out_slot] = expr
            if all_effects:
                self._alias_effects[out_slot] = all_effects
            # Keep the call pending until its output slot is loaded; a reused
            # slot flushes its previous call first so it is not lost.
            self._flush_pending_byref(out_slot)
            self._pending_byref[out_slot] = (
                self._source_order, va, expr, list(all_effects))
        else:
            self._realise_effects(items)
            self._insert_stmt(self._source_order, va, 0, "Call %s" % expr)

    def _vcall(self, label, operand, va):
        slot = parse_vcall_slot(operand) or "0"
        method = "method_%s" % slot
        # VCall is COM late dispatch with no static arg count, so it drains
        # the whole eval stack.  Unlike ImpAdCall it pushes args left-to-right
        # with the receiver last (TOS), so reverse=True restores source order.
        args = self._collect_args(reverse=True)
        # All VCall variants return a value; an unconsumed one flushes as a
        # discarded "Call" statement.
        call_text = "Me.%s(%s)" % (method, args)
        self.push(call_text, is_call=True,
                  effects=[(self._source_order, va, call_text)])

    def _collect_args(self, nargs=None, reverse=False, strict=False):
        """Collect argument list (oldest first).

        With nargs known, pop exactly that many (leaving accumulators and
        other pre-call values); otherwise drain the whole stack.  With strict,
        a known nargs larger than the stack raises instead of truncating.

        TOS is ARG1, so popping TOS-first already gives source order; only
        VCall passes reverse=True (it pushes args left-to-right).
        """
        if not self.stack:
            return ""
        if nargs is None:
            count = len(self.stack)
        else:
            if strict and nargs > len(self.stack):
                raise ValueError(
                    "call needs %d args but the eval stack holds %d"
                    % (nargs, len(self.stack)))
            count = min(nargs, len(self.stack))
        items = [self.pop() for _ in range(count)]
        if reverse:
            items.reverse()
        texts = [strip(x.text) for x in items]
        # Drop trailing <missing> (omitted optional args) but keep a <missing>
        # between real args as an empty placeholder (foo(a, , c)).
        while texts and texts[-1] == "<missing>":
            texts.pop()
        return ", ".join("" if t == "<missing>" else t for t in texts)

    def _terminator(self, label, va):
        self.flush_leftovers(va)
        if label.startswith("ExitProc"):
            self.emit(va, 0, self.exit_keyword)
        elif label == "End":
            self.emit(va, 0, "End")

    def _loop_start(self, label, _operand, va):
        loop_var = "?"
        # The loop variable always comes from the FLdRfVar pushed between
        # start and end, never from the operand (ForI2's first word is a hidden
        # per-loop control slot).
        #
        # Stack (bottom to top): [start, var_ref, end(, step)]; pop order is
        # step, end, var_ref, start.
        step = None
        if "Step" in label:
            step = self.pop()
        end_val = self.pop()
        # var_ref is the same expression the loop body reads and NextI2 writes
        # back to; accept whatever it renders as (slot or mapped member name).
        var_ref = self.pop()
        ref_text = strip(var_ref.text).lstrip('&')
        # Reject empty/<missing> and bare numbers (would emit "For 5 = ...").
        if ref_text and ref_text != "<missing>" and not ref_text.lstrip('-').isdigit():
            loop_var = ref_text
        start_val = self.pop()
        # Flush unconsumed calls made before the loop, so they precede the For.
        self.flush_leftovers(va)
        if "Step" in label:
            self.emit(va, +1, "For %s = %s To %s Step %s" % (
                loop_var, start_val.text, end_val.text, step.text))
        else:
            self.emit(va, +1, "For %s = %s To %s" % (
                loop_var, start_val.text, end_val.text))
        self.pending_loops.append(var_ref.text)

    def _loop_end(self, _label, _operand, va):
        if self.pending_loops:
            # VM write-back: right before NextI2 the loop-var reference is
            # re-pushed for NextI2 to store into.  Consume it first, before
            # flush_leftovers would emit it as an orphan statement.
            var_text = self.pending_loops[-1]
            if var_text is not None and self.stack and self.stack[-1].text == var_text:
                self.pop()
            # Flush discarded calls before Next so they stay inside the loop body.
            self.flush_leftovers(va)
            self.pending_loops.pop()
        self.emit(va, -1, "Next")

    def _stmt(self, label, operand, va):
        self.emit(va, 0, _render_label(label, operand))

    def _stmt_pop(self, label, operand, va):
        """Statement ops that pop eval-stack values.

        Close: pop 1 (file number); Erase: pop 1 (array ref);
        CopyBytes: pop 2 (dest=top, source=next); Open: pop 3
        (reclen, filenum, filename top-to-bottom); GetRecOwner3: pop 2
        (array_ref=top, file_number=next), rendered as `Get #n, var`.

        The operand texts are embedded in the statement, so their deferred
        effects are already realised (no _realise_effects call here).
        """
        npop = STMT_POP_LABELS[label]
        if npop == 1:
            arg = self.pop()
            self.emit(va, 0, "%s %s" % (label, arg.text))
        elif npop == 2:
            top = self.pop()
            nxt = self.pop()
            if label == "CopyBytes":
                # Operand carries the byte count (len=N); append it only when
                # present so the no-operand form never renders ", -".
                extra_op = (operand or "").strip()
                extra = ("" if not extra_op or extra_op == "-"
                         else ", " + extra_op)
                self.emit(va, 0, "CopyBytes %s, %s%s"
                          % (top.text, nxt.text, extra))
            elif label == "GetRecOwner3":
                self.emit(va, 0, "Get %s, %s" % (nxt.text, top.text))
        elif npop == 3:
            # Open: stack bottom->top = [filename, filenum, reclen]
            reclen = self.pop()
            filenum = self.pop()
            filename = self.pop()
            self.emit(va, 0, "Open %s, %s, %s" % (filename.text, filenum.text, reclen.text))

    def _redim(self, label, operand, va):
        """Redim consumes 1 + dims*2 eval-stack values.

        Pop order (TOS first) is array_ref, then per-dim bounds in reverse
        push order.  Verified by pub_055 read_rng_subfile @00404D78 (dims=1):
        stack bottom->top = [0(lbound), ubound, array_ref].  Rendered as
        'Redim arr(ubound)' when lbound is the literal 0, else 'Redim
        arr(lbound To ubound)'.
        """
        dims = 0
        if operand and operand.startswith("dims="):
            token = operand[5:].split()
            if token:
                try:
                    dims = int(token[0])
                except ValueError:
                    dims = 0
        if dims > _REDIM_MAX_DIMS:
            # Malformed/truncated operand: don't pop millions of values.
            dims = 0  # routes to the raw-operand fallback below
        npop = 1 + dims * 2
        pops = [self.pop() for _ in range(npop)]
        # pops[0] = array_ref; reverse the rest to get dim1..dimN (lbound, ubound).
        bounds = list(reversed(pops[1:]))
        if dims >= 1 and bounds:
            ary = strip(pops[0].text)
            parts = []
            for d in range(dims):
                lbound = bounds[d * 2]
                ubound = bounds[d * 2 + 1]
                if lbound.text == "0":
                    parts.append(strip(ubound.text))
                else:
                    parts.append("%s To %s" % (strip(lbound.text),
                                               strip(ubound.text)))
            self.emit(va, 0, "Redim %s(%s)" % (ary, ", ".join(parts)))
        else:
            # The emitted "Redim <operand>" drops every popped text, so its
            # deferred effects must be surfaced explicitly.
            self._realise_effects(pops)
            self.emit(va, 0, "%s %s" % (label,
                                        operand if operand != "-" else ""))

    def _opaque(self, label, operand, va):
        self.emit(va, 0, "# " + _render_label(label, operand))
