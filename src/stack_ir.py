"""Stack-machine IR and expression tree building.

VB4 p-code is a stack machine: LitI2 pushes a constant, AddI2 pops two and
pushes one.  This module simulates the evaluation stack and folds
instruction sequences into expression trees, then emits VB-style
statements.

The engine walks instructions linearly (like Semi VB Decompiler's
modPCode.bas and pcode2code).  Control-flow recovery uses the branch-target
stack approach: BranchF emits "If cond Then" and pushes the target; when
the walk reaches a pending target, "End If" is emitted.  For/Next are
recovered from the explicit loop-var and branch target operands.

Cross-procedure branch targets (most point into the proc-197 script
dispatcher) are rendered as GoTo label comments rather than intra-proc jumps.
"""


# ----------------------------------------------------------------------
# Operand parsing helpers
# ----------------------------------------------------------------------

def strip(expr_text):
    """Remove one redundant outer paren pair if it wraps the whole string."""
    s = expr_text.strip()
    if len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        depth = 0
        for k, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and k < len(s) - 1:
                    return s
        return s[1:-1]
    return s


def parse_mem(operand):
    """Parse a word-disassembler mem= operand into a readable variable reference."""
    if not operand or not operand.startswith("mem="):
        return operand
    ref = operand[4:]
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
    token = operand.split("to=")[1].split()[0].split(",")[0]
    try:
        return int(token, 16)
    except ValueError:
        return None


def parse_vcall_slot(operand):
    """Parse vcall=XXXX / this.vcall=XXXX -> slot hex string."""
    if not operand:
        return None
    for prefix in ("this.vcall=", "vcall="):
        if operand.startswith(prefix):
            return operand[len(prefix):].split("@")[0].split()[0]
    return None


def parse_lit(operand):
    """Parse val=N / text='...' into a display literal."""
    if not operand:
        return operand
    if operand.startswith("val="):
        return operand[4:]
    if operand.startswith("text="):
        return operand[5:]
    return operand


def parse_lit_str(operand):
    """Extract the quoted string from a LitStr operand."""
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
    # Pure mem_ / global_ refs
    if text.startswith("mem_") or text.startswith("global_"):
        return "(" not in text
    # LdFixedStr/StFixedStr length markers
    if text.startswith("len="):
        return True
    return False


def _field_ref(operand):
    """Render a MemLd/MemSt field offset as '.fXXXX'.

    Operands look like 'mem=0002' or 'mem=0002.a0004'.  The first hex word
    is the struct member offset.
    """
    if not operand or not operand.startswith("mem="):
        return ""
    ref = operand[4:]
    head = ref.split(".")[0]
    if head and head[0] in "0123456789":
        return ".f" + head
    return "" + ref


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

# Transparent conversions: pop 1, push 1 (result text unchanged).
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
    # ByRef field loads: push the address reference (used as call/array base).
    "FMemLdRf", "FMemLdRfVar", "FLdRf",
    "ImpAdLdRf", "ImpAdLdPr",
    "ImpAdLdI2", "ImpAdLdI4", "ImpAdLdR4", "ImpAdLdR8", "ImpAdLdCy",
    "ImpAdLdStr", "ImpAdLdVar",
    "FLdPr", "FLdPrThis",
}

# Array element load: pop 2 (index + arrayref), push 1 (arrayref(index)).
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

FREE_LABELS = {
    "SetLastSystemError",
}

# FFree* handlers free frame slots (mem=stack-N or byteLen=N stack=[...]),
# NOT eval-stack items.  They should not flush the eval stack, because the
# eval stack may hold comparison results or other values that are still
# needed by the next BranchF/Call.  Previously they were in FREE_LABELS and
# their flush_leftovers() call drained the eval stack, causing 17 of the 22
# <empty> occurrences (If <empty> Then after FFree1Var drained the condition).
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

# Runtime function arg counts, verified from p-code call patterns.
# rtcMidCharVar: 4 args (start, length, source, ByRef output) -> Mid$()
# rtcLeftCharVar: 3 args (length, source, ByRef output) -> Left$()
# rtcStrFromVar: 1 arg (variant) -> Str$()
# rtcVarStrFromVar: 2 args (variant, ByRef output) -> CStr()
# rtcLeftTrimVar: 2 args (source, ByRef output) -> LTrim$()
# rtcAnsiValueBstr: 1 arg (bstr) -> Asc()
# rtcRandomNext: 1 arg (optional seed, often missing) -> Rnd()
# rtcRandomize: 1 arg (seed) -> Randomize()
# rtcMsgBox: 3 args (prompt, buttons, title) -> MsgBox()
# rtcDoEvents: 0 args -> DoEvents()
# rtcGetTimer: 0 args -> Timer
# rtcBstrFromAnsi: 1 arg (ptr) -> StrConv()
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

# Runtime functions with a ByRef output parameter (last arg).
# When called, the output slot (a frame ref pushed via FLdRfVar) receives
# the function result.  We record an alias so that subsequent loads of
# that slot resolve to the VB expression (e.g. CStr(input)).
#   out_index: index of the ByRef output arg (0-based, from oldest/source order).
#   renderer: VB function name for display (e.g. "CStr", "LTrim").
#   nargs: total arg count (including the ByRef output).
#   input_map: list mapping VB arg position -> p-code arg index.
#     e.g. Mid$(source, start, length) has p-code args [start, length, source],
#     so input_map = [2, 0, 1] (VB arg0=source=p-code[2], VB arg1=start=p-code[0], etc.)
RUNTIME_BYREF_SPECS = {
    "VB40032.rtcVarStrFromVar": {
        "nargs": 2, "out_index": 1, "renderer": "CStr",
        "input_map": [0]},
    "VB40032.rtcLeftTrimVar": {
        "nargs": 2, "out_index": 1, "renderer": "LTrim",
        "input_map": [0]},
    "VB40032.rtcMidCharVar": {
        "nargs": 4, "out_index": 3, "renderer": "Mid",
        "input_map": [2, 0, 1]},  # Mid(source, start, length)
    "VB40032.rtcLeftCharVar": {
        "nargs": 3, "out_index": 2, "renderer": "Left",
        "input_map": [1, 0]},  # Left(source, length)
}

# Win32 API arg counts (verified from call patterns):
# _hread(hFile, buffer, count) = 3
# _hwrite(hFile, buffer, count) = 3
# _lclose(hFile) = 1
# _lcreat(path, attr) = 2
# _llseek(hFile, offset, origin) = 3
# _lopen(path, mode) = 2
# mciSendStringA(cmd, retBuf, retLen, hwnd) = 4
# ShowCursor(show) = 1
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

# Win32 library prefixes for Declare-table external stdcall targets.
# These functions use right-to-left argument push order (stdcall ABI):
# the last argument is pushed first (bottom of eval stack), the first
# argument is pushed last (TOS).  Therefore _collect_args must NOT reverse
# the popped items for these targets — the pop order (TOS→bottom) already
# gives the correct source-order argument list.
#
# Internal VB functions (pub_*/priv_*) and VB40032.rtc* are called via
# ImpAdCall with left-to-right push order (first arg at bottom, last at
# TOS), so _collect_args MUST reverse for those.
#
# Pal.* functions live in PAL.dll (Declare table, stdcall) but are often
# called via ImpAdCall which always uses VB internal convention
# (left-to-right).  When called via ImpAdCallAd they follow stdcall
# (right-to-left).  The call instruction label determines the convention.
WIN32_PREFIXES = (
    "kernel32.", "user32.", "gdi32.", "winmm.", "ole32.",
    "advapi32.", "comdlg32.", "shell32.", "ws2_32.", "wsock32.",
    "ntdll.", "msvcrt.", "crtdll.",
)


def _is_stdcall_target(name):
    """True if *name* is a Win32 API target that uses right-to-left
    argument push order (stdcall ABI).

    Win32 API targets (kernel32.*, user32.*, etc.) are external stdcall
    functions.  The VB4 compiler knows the target ABI and pushes arguments
    right-to-left regardless of the call instruction (ImpAdCall or
    ImpAdCallAd).  Therefore _collect_args must NOT reverse for these.

    Pal.* functions are also Declare-table stdcall functions, but when
    called via ImpAdCall they use left-to-right push order (confirmed by
    Pal.copymen via ImpAdCall).  When called via ImpAdCallAd, most have
    only 1 arg so reversal is a no-op.  To avoid risk, we only apply
    reverse=False to Win32 API prefixes, not Pal.*.

    Internal VB functions (pub_*/priv_*) and VB40032.rtc* always use
    left-to-right push order and need reversal.
    """
    if not name:
        return False
    if name.startswith(WIN32_PREFIXES):
        return True
    return False

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

# Statement-level ops that consume values from the eval stack.
# Confirmed by handler disassembly:
#   Close: pop 1 (file number); cmp [esp],0; jne → call(ret 4) / pop eax
#   Erase: pop 1 (array ref); xchg [esp],0; push; call(ret 8) cleans both
#   CopyBytes: pop 2 (dest, source); pop edi; pop esi; rep movs
#   Open: pop 3 (filename, file_number, record_length); call helper ret 0x10
#   GetRecOwner3: pop 2 (array_ref, file_number); call helper ret 0x0c
STMT_POP_LABELS = {
    "Close": 1,
    "Erase": 1,
    "CopyBytes": 2,
    "Open": 3,
    "GetRecOwner3": 2,
}

# Variant binary ops: pop 2 variants, push 1 result.
# AddVar = variant + (numeric add or string concat), EqVar = variant =.
# Confirmed by handler disassembly: AddVar calls helper then pushes result;
# EqVar pops 2, compares, pushes boolean.
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
    """An expression on the evaluation stack.

    ``effects`` tracks deferred call side-effects (origin_va, call_text)
    that are embedded in this expression.  When the expression is consumed
    by a store, condition, or outer call, the effects are considered
    realised (the call text appears in the consuming statement).  When the
    expression is flushed as a standalone leftover, its effects are emitted
    as independent ``Call ...`` statements at their original source order.
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
    """Linear stack-machine decompiler for one procedure.

    Walks instructions in order, maintaining an expression stack and a
    pending-If target stack.  Emits Stmt objects.
    """

    def __init__(self):
        self.stack = []
        self.statements = []
        self.pending_ifs = []  # [(target_va, is_crossproc, open_va), ...]
        self.if_stack_depths = []  # stack depth at each If open, for flush-on-close
        self.pending_loops = []  # [exit_target, ...] for Next/Loop end
        self.loop_starts = []  # VA where each For loop started
        self.completed_loop_starts = []  # VAs of loops that have finished
        self.proc_start = 0
        self.proc_end = 0
        self.arg_map = {}  # proc name -> arg count
        self.param_map = {}  # stack offset -> param name (e.g. {12: "a0"})
        self._after_goto = False
        self._source_order = 0  # monotonic counter for statement ordering
        self._insert_anchors = {}  # after_order -> last insert index (FIFO)
        self.temp_aliases = {}  # frame slot -> alias expression text
        self._alias_effects = {}  # frame slot -> deferred effects for alias

    def _subst_param(self, text):
        """Replace stack+N references with parameter names where applicable."""
        if not self.param_map or not text:
            return text
        import re as _re
        def repl(m):
            off = int(m.group(1))
            return self.param_map.get(off, m.group(0))
        return _re.sub(r'stack\+(\d+)', repl, text)

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

    def _insert_stmt(self, after_order, va, indent_delta, text):
        """Insert a statement after the statement with order == after_order.

        Used by flush_leftovers to place deferred ``Call ...`` statements
        at their original source position (before statements that were
        emitted later but consumed the call result).

        When multiple discarded calls share the same origin order (no emit
        between them), they are inserted in processing order (FIFO) by
        appending after any previously-inserted sibling.
        """
        self._source_order += 1
        new_stmt = Stmt(va, indent_delta, text, order=self._source_order)
        # Find insertion point: after the statement with order == after_order.
        # If we've already inserted at this anchor, append after the last
        # sibling to maintain FIFO order.
        anchor_key = after_order
        if anchor_key in self._insert_anchors:
            insert_idx = self._insert_anchors[anchor_key] + 1
        else:
            # Find the statement with order == after_order and insert
            # after it.  If no exact match (the call was processed before
            # any emit), insert before the first statement with order >
            # after_order, or at the beginning if none exists.
            #
            # IMPORTANT: previously-inserted statements may have order >
            # after_order (their order was assigned at insertion time).
            # We must NOT treat those as the "first statement with order >
            # after_order" insertion point — we keep scanning for the exact
            # match.  Only if no exact match is found do we use the
            # "first order > after_order" fallback.
            insert_idx = len(self.statements)  # default: append at end
            first_greater = None
            for i in range(len(self.statements)):
                if self.statements[i].order == after_order:
                    insert_idx = i + 1
                    break
                if first_greater is None and self.statements[i].order > after_order:
                    first_greater = i
            else:
                # No exact match found — use fallback.
                if first_greater is not None:
                    insert_idx = first_greater
        self.statements.insert(insert_idx, new_stmt)
        self._insert_anchors[anchor_key] = insert_idx

    def flush_leftovers(self, va):
        """Emit stranded stack values as statements (discarded results).

        Bare variable references (e.g. 'stack-216') are plumbing temps
        (FLdI4/FLdRfVar pushed for string conversions or ByRef calls) that
        were never consumed; they are not meaningful statements and are
        silently dropped.

        Expressions that carry deferred call effects (``Expr.effects``) are
        emitted as independent ``Call ...`` statements.  Each effect is
        inserted at the source-order position of its *origin* — the point
        where the call instruction was processed — rather than at the
        current flush position.  This ensures ``Call foo()`` appears before
        subsequent stores that consumed the call result.
        """
        while self.stack:
            item = self.stack.pop(0)
            if not item.text or item.text == "<missing>":
                continue
            stripped = item.text.strip()
            # If this item carries deferred call effects, emit each as an
            # independent Call at its original source position.
            if item.effects:
                for origin_order, origin_va, call_text in item.effects:
                    self._insert_stmt(origin_order, origin_va, 0, "Call %s" % call_text)
                continue
            # Skip bare plumbing temps (plain stack offsets, mem_ refs).
            if not item.is_call and _is_plumbing_temp(stripped):
                continue
            stmt = item.text
            if item.is_call:
                stmt = "Call " + stmt
            self.emit(va, 0, stmt)

    def _flush_to_depth(self, va, depth):
        """Flush stack values above *depth* as discarded-call statements.

        Used when closing an If: values pushed inside the If body that
        were not consumed must not flow into code after the End If.
        Each is emitted as a ``Call ...`` statement at its original source
        position (like flush_leftovers) so it appears inside the If body.
        """
        while len(self.stack) > depth:
            item = self.stack.pop(depth)  # remove first excess item
            if not item.text or item.text == "<missing>":
                continue
            stripped = item.text.strip()
            if item.effects:
                for origin_order, origin_va, call_text in item.effects:
                    self._insert_stmt(origin_order, origin_va, 0, "Call %s" % call_text)
                continue
            if not item.is_call and _is_plumbing_temp(stripped):
                continue
            stmt = item.text
            if item.is_call:
                stmt = "Call " + stmt
            self.emit(va, 0, stmt)

    def close_ifs(self, addr):
        """Close any pending If whose target <= addr (in-proc targets).

        Cross-proc If targets (target outside proc) are closed at the next
        control-flow boundary instead, since their End If lives in another
        procedure and will never be reached linearly.
        """
        while self.pending_ifs:
            tgt, is_cross, _ova = self.pending_ifs[-1]
            if is_cross:
                # Close cross-proc Ifs at control-flow boundaries only.
                break
            if tgt > addr:
                break
            self.pending_ifs.pop()
            # Flush values pushed inside this If that weren't consumed.
            # These are call results from the If body that would otherwise
            # flow into code after the End If, which is semantically wrong
            # (the value may not exist if the condition was false).
            if self.if_stack_depths:
                if_depth = self.if_stack_depths.pop()
                if len(self.stack) > if_depth:
                    self._flush_to_depth(addr, if_depth)
            self.emit(addr, -1, "End If")

    def close_ifs_before_loop_end(self, exit_tgt):
        """Close Ifs before emitting Next, including cross-proc Ifs.

        A cross-proc If whose false-branch target lands at or before the
        loop's exit point must be closed before the Next keyword, since its
        End If logically sits inside the loop body (before Next).

        However, a cross-proc If that was opened *before* the loop started
        encloses the loop, so its End If must come *after* Next — don't
        close it here.
        """
        loop_start_va = self.loop_starts[-1] if self.loop_starts else None
        while self.pending_ifs:
            tgt, is_cross, ova = self.pending_ifs[-1]
            if tgt > exit_tgt:
                break
            if loop_start_va is not None and ova < loop_start_va:
                # This If encloses the loop; its End If is after Next.
                break
            self.pending_ifs.pop()
            if self.if_stack_depths:
                if_depth = self.if_stack_depths.pop()
                if len(self.stack) > if_depth:
                    self._flush_to_depth(exit_tgt, if_depth)
            self.emit(exit_tgt, -1, "End If")

    def close_crossproc_ifs(self, one=False):
        """Close pending cross-proc Ifs (called at branch/terminator).

        If one=True, close only the innermost cross-proc If (used after a
        GoTo that ends an If body).
        """
        while self.pending_ifs:
            tgt, is_cross, _ova = self.pending_ifs[-1]
            if not is_cross:
                break
            self.pending_ifs.pop()
            if self.if_stack_depths:
                if_depth = self.if_stack_depths.pop()
                if len(self.stack) > if_depth:
                    self._flush_to_depth(0, if_depth)
            self.emit(0, -1, "End If")
            if one:
                break

    # -- main dispatch ------------------------------------------------------

    def process(self, instr):
        label = instr.label
        operand = instr.operand
        va = instr.pos

        # Close pending Ifs before processing (targets reached).
        self.close_ifs(va)
        # After an unconditional branch (GoTo), the next instruction is the
        # false-branch landing point of any open cross-proc If whose body
        # ended with that GoTo.  Close it here so End If appears before the
        # fallthrough code, not at the proc terminator.
        if self._after_goto:
            self._after_goto = False
            self.close_crossproc_ifs(one=True)

        if label in BINARY_OPS:
            self._binary(BINARY_OPS[label])
        elif label in COMPARE_OPS:
            self._binary(COMPARE_OPS[label])
        elif label in VAR_BINARY_OPS:
            self._binary(VAR_BINARY_OPS[label])
        elif label in UNARY_OPS:
            self._unary(UNARY_OPS[label])
        elif label in CONV_LABELS:
            if label in ("CStr2Ansi", "CStr2Uni"):
                # CStr2Ansi/CStr2Uni: pop 2 (ByRef string descriptor + frame
                # slot pointer), convert string to ANSI/Unicode, store the
                # pointer in the frame slot.  The pointer is loaded separately
                # by the subsequent FLdI4, so we pop 2 and push 0.
                self.pop()
                self.pop()
            else:
                pass  # transparent (pop 1 push 1, text unchanged)
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
            # FFree* free frame slots, not eval-stack items.
            # No stack effect, no flush — the eval stack may hold
            # results still needed by the next BranchF/Call.
            # Invalidate any aliases for freed slots.
            if operand and "stack=[" in operand:
                # FFreeVar byteLen=N stack=[-248, -264, ...]
                slots_part = operand.split("stack=[")[1].rstrip("]")
                for s in slots_part.split(","):
                    s = s.strip()
                    if s:
                        key = "stack" + s
                        if key in self.temp_aliases:
                            del self.temp_aliases[key]
                        self._alias_effects.pop(key, None)
            elif operand and "mem=" in operand:
                key = self._subst_param(parse_mem(operand))
                if key in self.temp_aliases:
                    del self.temp_aliases[key]
                self._alias_effects.pop(key, None)
            pass
        elif label in COND_BRANCH:
            self._cond_branch(label, operand, va)
        elif label in UNCOND_BRANCH:
            self._uncond_branch(label, operand, va)
        elif label in TERMINATOR_LABELS:
            self._terminator(label, va)
        elif label == "Return":
            self.emit(va, 0, "Return")
        elif label in LOOP_START:
            self._loop_start(label, operand, va)
        elif label in LOOP_END:
            self._loop_end(label, operand, va)
        else:
            self._opaque(label, operand, va)

    # -- handlers -----------------------------------------------------------

    def _binary(self, op):
        b = self.pop()
        a = self.pop()
        # Propagate deferred call effects from both operands.
        effects = list(a.effects) + list(b.effects)
        self.push("(%s %s %s)" % (a.text, op, b.text), effects=effects)

    def _unary(self, op):
        a = self.pop()
        # Propagate deferred call effects.
        effects = list(a.effects)
        if op == "-":
            self.push("-" + strip(a.text), effects=effects)
        else:
            self.push("%s (%s)" % (op, strip(a.text)), effects=effects)

    def _load(self, label, operand):
        if label in ("LitI2", "LitI2_10", "LitI4", "LitR4", "LitR8", "LitDate"):
            self.push(parse_lit(operand))
        elif label in ("LitStr", "LitVarStr"):
            self.push(parse_lit_str(operand))
        elif label == "LitVar_Missing":
            self.push("<missing>")
        elif label == "LitVarI2":
            if "val=" in operand:
                self.push(operand.split("val=")[1].split()[0])
            else:
                self.push(self._subst_param(parse_mem(operand)))
        elif label == "FLdZeroAd":
            self.push("0")
        elif label.startswith("ImpAdLd"):
            # ImpAdLd* push a global module-level reference.
            if operand.startswith("global="):
                self.push("global_" + operand[7:])
            else:
                self.push(self._subst_param(parse_mem(operand)))
        elif label == "FLdRfVar":
            slot = self._subst_param(parse_mem(operand))
            # If this slot has a recorded alias (from a ByRef runtime call),
            # resolve to the alias expression instead of the raw ref.
            alias = self.temp_aliases.get(slot)
            if alias is not None:
                effects = self._alias_effects.pop(slot, [])
                self.push(alias, effects=effects)
                # The alias is consumed; invalidate it so a later store to
                # the same slot isn't confused.
                del self.temp_aliases[slot]
            else:
                self.push(slot)
        else:
            self.push(self._subst_param(parse_mem(operand)))

    def _ary_load(self, label):
        # Ary1Ld*: stack top = arrayref, below = index.
        ary = self.pop()
        idx = self.pop()
        effects = list(ary.effects) + list(idx.effects)
        self.push("%s(%s)" % (strip(ary.text), strip(idx.text)),
                  effects=effects)

    def _ary_n_load(self, label, operand):
        # AryLd*: multi-dimensional.  descriptor=0xNNNN gives dim count.
        ndim = _parse_dim_count(operand) or 2
        ary = self.pop()
        indices = [self.pop() for _ in range(ndim)]
        indices.reverse()
        effects = list(ary.effects)
        for x in indices:
            effects.extend(x.effects)
        idx_str = ", ".join(strip(x.text) for x in indices)
        self.push("%s(%s)" % (strip(ary.text), idx_str), effects=effects)

    def _ary_store(self, label, operand, va):
        # Ary1St*: stack top = arrayref, below = index, below = value.
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
        # MemSt*: stack top = address, below = value.
        addr = self.pop()
        val = self.pop()
        field = _field_ref(operand)
        self.emit(va, 0, "%s%s = %s" % (
            strip(addr.text), field, strip(val.text)))

    def _store(self, label, operand, va):
        dst = self._subst_param(parse_mem(operand))
        val = self.pop()
        # The store consumes the value's deferred call effects — they are
        # now realised inside this assignment.  Clear effects so they are
        # not re-emitted by a later flush.
        val.effects = []
        # Invalidate any alias for the destination slot (it's being overwritten).
        if dst in self.temp_aliases:
            del self.temp_aliases[dst]
        self._alias_effects.pop(dst, None)
        if label in STORE_NOPOP:
            self.emit(va, 0, "%s = %s" % (dst, strip(val.text)))
            # For STORE_NOPOP, the value stays on the stack as a plain
            # reference (the assignment already emitted it).  Push without
            # effects to avoid duplicate Call emission.
            self.push(val.text)
        else:
            self.emit(va, 0, "%s = %s" % (dst, strip(val.text)))

    def _fixed_str_store(self, label, operand, va):
        # StFixedStr: pop source BSTR + buffer address (silent store).
        self.pop()  # source string
        self.pop()  # buffer address

    def _fixed_str_load(self, label, operand, va):
        # LdFixedStr: pop buffer address, push the fixed-string value.
        buf = self.pop()
        self.push(buf.text, effects=list(buf.effects))

    def _call(self, label, operand, va):
        name = parse_call(operand) or "<unknown>"
        # Check for ByRef runtime functions (rtcVarStrFromVar, etc.).
        byref_spec = RUNTIME_BYREF_SPECS.get(name)
        if byref_spec is not None:
            self._byref_call(name, byref_spec, va)
            return
        nargs = self.arg_map.get(name)
        if nargs is None:
            # Try runtime/Win32 specs for external calls.
            nargs = RUNTIME_SPECS.get(name)
            if nargs is None:
                nargs = WIN32_SPECS.get(name)
        # Determine argument push order convention.
        # Win32 API targets (kernel32.*, user32.*, etc.) use right-to-left
        # push order (stdcall ABI) regardless of call instruction.
        # All other targets (internal VB, Pal.*, VB40032.rtc*) use
        # left-to-right push order (VB internal convention).
        reverse = not _is_stdcall_target(name)
        args = self._collect_args(nargs, reverse=reverse)
        if label in CALL_NORETURN:
            if args:
                self.emit(va, 0, "%s %s" % (name, args))
            else:
                self.emit(va, 0, "Call %s" % name)
        else:
            call_text = "%s(%s)" % (name, args)
            # Record the call as a deferred effect so that if the result
            # is never consumed, flush_leftovers emits "Call name(args)"
            # at the original source position (not at flush time).
            self.push(call_text, is_call=True,
                      effects=[(self._source_order, va, call_text)])

    def _byref_call(self, name, spec, va):
        """Handle a ByRef runtime function (e.g. rtcVarStrFromVar).

        These functions take input args plus a ByRef output slot (pushed
        via FLdRfVar).  The function writes its result to the output slot.
        We record a temp alias so subsequent FLdRfVar loads of that slot
        resolve to the VB expression (e.g. CStr(input)).
        """
        nargs = spec["nargs"]
        out_index = spec["out_index"]
        renderer = spec["renderer"]
        # Pop args (TOS first).  These use VB internal convention
        # (left-to-right push), so we reverse to get source order.
        if not self.stack:
            return
        count = min(nargs, len(self.stack))
        items = [self.pop() for _ in range(count)]
        items.reverse()  # source order: [arg0, arg1, ..., argN-1]
        # The output slot is at out_index.
        if out_index >= len(items):
            return
        out_item = items[out_index]
        out_slot = strip(out_item.text)
        # Build input args (all except the ByRef output).
        input_items = [items[i] for i in range(len(items)) if i != out_index]
        # Resolve any aliases in input items.
        resolved = []
        for item in input_items:
            t = strip(item.text)
            alias = self.temp_aliases.get(t)
            if alias is not None:
                resolved.append(alias)
                # Consumed alias — invalidate.
                if t in self.temp_aliases:
                    del self.temp_aliases[t]
                self._alias_effects.pop(t, None)
            else:
                resolved.append(t)
        # Reorder inputs to VB source order using input_map.
        input_map = spec.get("input_map")
        if input_map:
            input_texts = [resolved[i] for i in input_map]
        else:
            input_texts = resolved
        # Build the VB expression.
        if renderer in ("CStr", "LTrim"):
            # Unary string functions.
            expr = "%s(%s)" % (renderer, input_texts[0])
        elif renderer == "Left":
            # Left$(source, length) — 2 input args.
            expr = "Left(%s, %s)" % (input_texts[0], input_texts[1])
        elif renderer == "Mid":
            # Mid$(source, start, length) — 3 input args.
            expr = "Mid(%s, %s, %s)" % (
                input_texts[0], input_texts[1], input_texts[2])
        else:
            expr = "%s(%s)" % (renderer, ", ".join(input_texts))
        # Collect any deferred effects from input items.
        all_effects = []
        for item in items:
            all_effects.extend(item.effects)
        # Record the alias for the output slot.
        self.temp_aliases[out_slot] = expr
        # Record the side effects alongside the alias so FLdRfVar can
        # propagate them when resolving.  We do NOT push a stack marker —
        # the alias will be resolved by the subsequent FLdRfVar load.
        if all_effects:
            self._alias_effects[out_slot] = all_effects

    def _vcall(self, label, operand, va):
        slot = parse_vcall_slot(operand) or "0"
        method = "method_%s" % slot
        args = self._collect_args()  # VCall arg counts unknown; drain all.
        # All VCall variants return a value (HRESULT, I2, I4, R4, R8, Ad).
        # Push the call result; when not consumed, flush_leftovers emits it
        # as a "Call" statement (discarded Sub-style return).
        call_text = "Me.%s(%s)" % (method, args)
        self.push(call_text, is_call=True,
                  effects=[(self._source_order, va, call_text)])

    def _collect_args(self, nargs=None, reverse=True):
        """Collect argument list (oldest first).

        If nargs is known, pop exactly that many items (leaving accumulators
        and other pre-call stack values for subsequent operations).
        Otherwise drain the whole stack.

        When reverse=True (default, internal VB calling convention), the
        p-code pushes arguments left-to-right (first arg at bottom, last
        arg at TOS).  Popping TOS-first and reversing restores source order.

        When reverse=False (stdcall convention for Win32 API and Declare-
        table targets via ImpAdCallAd), the p-code pushes arguments
        right-to-left (last arg at bottom, first arg at TOS).  Popping
        TOS-first already gives source order — no reversal needed.
        """
        if not self.stack:
            return ""
        if nargs is None:
            count = len(self.stack)
        else:
            count = min(nargs, len(self.stack))
        items = [self.pop() for _ in range(count)]
        if reverse:
            items.reverse()
        return ", ".join(strip(x.text) for x in items if x.text != "<missing>")

    def _cond_branch(self, label, operand, va):
        cond = self.pop()
        # Any values left under the condition are discarded call results.
        self.flush_leftovers(va)
        tgt = parse_target(operand)
        # Backward branch: BranchT/BranchF jumping to an earlier address
        # is a loop-back, not a forward If.  Emit as a self-contained
        # If...GoTo...End If so _convert_loops can detect and rewrite it.
        if tgt is not None and tgt <= va and self.proc_start <= tgt < self.proc_end:
            if label in ("BranchF", "BranchFVar", "BranchFVarFree"):
                self.emit(va, +1, "If Not (%s) Then" % strip(cond.text))
            else:
                self.emit(va, +1, "If %s Then" % strip(cond.text))
            self.emit(va, 0, "GoTo L_%08X" % tgt)
            self.emit(va, -1, "End If")
            self._after_goto = True
            return
        if tgt is not None:
            is_cross = not (self.proc_start <= tgt < self.proc_end)
            if is_cross:
                # Cross-proc If: before opening, close any pending cross-proc
                # Ifs whose target < tgt (strictly less = sequential).
                # Keep target == tgt (nested: both jump to same exit point)
                # and target > tgt (outer/nested).
                #
                # Exception 1: if we're inside a For loop, don't close a
                # cross-proc If that was opened *before* the loop started.
                # That If encloses the loop, so its End If must come after
                # Next, not before.  The If will be closed at loop end or
                # at the next control-flow boundary outside the loop.
                #
                # Exception 2: if a For loop has already completed and a
                # pending cross-proc If was opened *before* that loop started,
                # the If encloses the loop and all code after it.  Don't
                # close it via "strictly less" — its End If is at proc end.
                loop_start_va = self.loop_starts[-1] if self.loop_starts else None
                while self.pending_ifs:
                    ptgt, pcross, pova = self.pending_ifs[-1]
                    if pcross and ptgt < tgt:
                        if loop_start_va is not None and pova < loop_start_va:
                            # Exception 1: If encloses current loop.
                            break
                        # Exception 2: check completed loops
                        encloses_completed = any(
                            pova < cls for cls in self.completed_loop_starts
                        )
                        if encloses_completed:
                            # If encloses a completed loop; don't close.
                            break
                        self.pending_ifs.pop()
                        # Keep the parallel If-depth stack synchronized when
                        # this cross-proc If is closed early.
                        if self.if_stack_depths:
                            if_depth = self.if_stack_depths.pop()
                            if len(self.stack) > if_depth:
                                self._flush_to_depth(va, if_depth)
                        self.emit(va, -1, "End If")
                    else:
                        break
        else:
            is_cross = False
        if label in ("BranchF", "BranchFVar", "BranchFVarFree"):
            self.emit(va, +1, "If %s Then" % strip(cond.text))
        else:
            self.emit(va, +1, "If Not (%s) Then" % strip(cond.text))
        if tgt is not None:
            self.pending_ifs.append((tgt, is_cross, va))
            self.if_stack_depths.append(len(self.stack))

    def _uncond_branch(self, label, operand, va):
        tgt = parse_target(operand)
        if label == "Gosub":
            self.emit(va, 0, "GoSub L_%08X" % (tgt or 0))
        else:
            # Flush any discarded call results before emitting GoTo,
            # so they appear inside the If body (before the GoTo) rather
            # than after the End If.
            self.flush_leftovers(va)
            self.emit(va, 0, "GoTo L_%08X" % (tgt or 0))
            self._after_goto = True

    def _terminator(self, label, va):
        self.flush_leftovers(va)
        # Emit the terminator first, then close any open cross-proc Ifs.
        # This places Exit Sub / End inside the If body rather than after
        # the End If, matching VB semantics (Exit Sub is an early return
        # guarded by the condition).
        if label.startswith("ExitProc"):
            self.emit(va, 0, "Exit Sub")
        elif label == "End":
            self.emit(va, 0, "End")
        self.close_crossproc_ifs()

    def _loop_start(self, label, operand, va):
        loop_var = "?"
        exit_tgt = parse_target(operand)
        if " to=" in operand:
            head = operand.split(" to=")[0]
            if head.startswith("var="):
                head = head[4:]
            loop_var = parse_mem(head)
        # Flush any unconsumed call results BEFORE popping loop setup
        # values, so calls made before the loop appear before the loop,
        # not inside it. The step/end/var_ref/start values are on top and
        # will be popped next; flush only drains values underneath.
        # BUT: we must not flush the loop setup values themselves. Since
        # they are plain stack references, flush_leftovers skips them via
        # _is_plumbing_temp. However, call results underneath should be
        # emitted first.
        # Actually, we need to pop the loop values first, then flush, then
        # emit. Let's pop first, then flush.
        #
        # Stack layout (bottom to top):
        #   ForI2/ForI4:      [start, var_ref, end]
        #   ForStepI2/ForI4:  [start, var_ref, end, step]
        # Pop order (top to bottom): step, end, var_ref, start.
        if "Step" in label:
            step = self.pop()
        end_val = self.pop()
        # FLdRfVar pushed the loop-variable reference between start and end.
        # Use the var_ref's frame offset as the loop variable name, since
        # that's the variable actually referenced in the loop body.
        var_ref = self.pop()
        ref_text = strip(var_ref.text).lstrip('&')
        if ref_text.startswith('stack') or ref_text.startswith('mem_'):
            loop_var = ref_text
        start_val = self.pop()
        # Now flush any unconsumed call results that were on the stack
        # before the loop setup values. This ensures calls made before
        # the loop are emitted before the For statement.
        self.flush_leftovers(va)
        if "Step" in label:
            self.emit(va, +1, "For %s = %s To %s Step %s" % (
                loop_var, start_val.text, end_val.text, step.text))
        else:
            self.emit(va, +1, "For %s = %s To %s" % (
                loop_var, start_val.text, end_val.text))
        self.pending_loops.append(exit_tgt)
        self.loop_starts.append(va)

    def _loop_end(self, label, operand, va):
        tgt = parse_target(operand)
        # Before emitting Next, close any If whose target falls at or before
        # the loop's exit point (the If's false-branch skips to Next/after).
        if self.pending_loops:
            # Flush any unconsumed call results BEFORE closing Ifs and
            # emitting Next, so they appear inside the If body and inside
            # the loop body rather than after the loop.
            self.flush_leftovers(va)
            exit_tgt = self.pending_loops[-1]
            if exit_tgt is not None:
                self.close_ifs_before_loop_end(exit_tgt)
            self.pending_loops.pop()
            completed_start = self.loop_starts.pop()
            if completed_start is not None:
                self.completed_loop_starts.append(completed_start)
        self.emit(va, -1, "Next")
        if tgt is not None:
            self.close_ifs(tgt)

    def _stmt(self, label, operand, va):
        self.emit(va, 0, "%s %s" % (label, operand if operand != "-" else ""))

    def _stmt_pop(self, label, operand, va):
        """Statement ops that consume values from the eval stack.

        Close: pop 1 (file number)
        Erase: pop 1 (array reference)
        CopyBytes: pop 2 (dest=stack-top, source=next)
        Open: pop 3 (reclen, filenum, filename — top to bottom)
        GetRecOwner3: pop 2 (array_ref, file_number)
        """
        npop = STMT_POP_LABELS[label]
        if npop == 1:
            arg = self.pop()
            self.emit(va, 0, "%s %s" % (label, arg.text))
        elif npop == 2:
            top = self.pop()
            nxt = self.pop()
            if label == "CopyBytes":
                self.emit(va, 0, "CopyBytes %s, %s, %s" % (top.text, nxt.text, operand))
            elif label == "GetRecOwner3":
                self.emit(va, 0, "Get %s, %s" % (nxt.text, top.text))
        elif npop == 3:
            # Open: stack bottom→top = [filename, filenum, reclen]
            reclen = self.pop()
            filenum = self.pop()
            filename = self.pop()
            self.emit(va, 0, "Open %s, %s, %s" % (filename.text, filenum.text, reclen.text))

    def _redim(self, label, operand, va):
        """Redim consumes 1 + dims*2 eval stack values.

        Confirmed by handler disassembly:
          - Handler pushes 5 args (20 bytes), calls helper (cdecl, ret only),
            then add esp, 0x18 (24 bytes).  The extra 4 bytes = 1 eval
            stack value (array ref at top of stack).
          - Then add esp, edi*8 (edi=dims) cleans dims*2 more values
            (lbound + ubound per dimension).
          - RedimVar variant: 4 pushes + ret 0x14 (20 bytes, callee cleanup)
            = same 1 extra eval stack value + add esp, edi*8.
        For dims=1: pop 3 = array_ref + ubound + lbound.
        """
        dims = 0
        if operand and operand.startswith("dims="):
            dims = int(operand[5:].split()[0])
        npop = 1 + dims * 2
        for _ in range(npop):
            self.pop()
        self.emit(va, 0, "%s %s" % (label, operand if operand != "-" else ""))

    def _opaque(self, label, operand, va):
        self.emit(va, 0, "# %s %s" % (label, operand if operand != "-" else ""))
