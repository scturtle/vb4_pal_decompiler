"""VB-style pseudocode generation from structured word-pcode analysis.

Pipeline:
  word_disasm.analyze()  ->  StackMachine  ->  formatted VB pseudocode

This module consumes structured analysis rather than rendered text, runs the
stack-machine decompiler per procedure, and emits readable VB-style pseudocode.
"""
import re
import sys

import stack_ir
import structuring
import word_disasm


def _build_arg_counts(pal, analysis):
    """Map proc_index -> arg_count by scanning each proc's max stack+N.

    stack+8 is always the Me/object base.  stack+12 = arg1, stack+16 = arg2,
    etc.  arg_count = (max_stack_offset - 8) // 4.
    """
    arg_counts = {}
    entries = analysis["entries"]
    labels = analysis["labels"]
    for idx, (start, end, path) in enumerate(analysis["paths"]):
        max_off = 8
        for pos, opcode, size, _fallback in path:
            label = _label_for(entries, labels, opcode)
            operand = _operand_for(pal, analysis, pos, opcode, size, label,
                                    proc_start=start)
            for m in re.finditer(r'stack\+(\d+)', operand):
                off = int(m.group(1))
                if off > max_off:
                    max_off = off
        arg_counts[idx] = max(0, (max_off - 8) // 4)
    return arg_counts


def _label_for(entries, labels, opcode):
    target = entries.get(opcode, 0)
    return word_disasm.strip_label(labels.get(target, "<no CodeView label>"))


def _display_label(label):
    return "LitI2" if label == "LitI2_10" else label


def _operand_for(pal, analysis, pos, opcode, size, label, proc_start):
    """Render one instruction's operand, sharing the word-disassembler logic."""
    raw = pal.bytes_at(pos, size)
    operand = word_disasm.special_operand(opcode, raw)
    if operand is not None:
        return operand
    return word_disasm.format_operand(
        opcode, label, raw, proc_start,
        analysis["stub_names"], analysis["declares"], pal)


def build_instrs(pal, analysis, index):
    """Build a list of _Instr objects for one procedure."""
    start, end, path = analysis["paths"][index]
    entries = analysis["entries"]
    labels = analysis["labels"]
    instrs = []
    for pos, opcode, size, _fallback in path:
        raw_label = _label_for(entries, labels, opcode)
        display = _display_label(raw_label)
        operand = _operand_for(pal, analysis, pos, opcode, size, raw_label,
                                proc_start=start)
        instrs.append(_Instr(pos, opcode, size, display, operand))
    return start, end, instrs


class _Instr(object):
    __slots__ = ("pos", "opcode", "size", "label", "operand")

    def __init__(self, pos, opcode, size, label, operand):
        self.pos = pos
        self.opcode = opcode
        self.size = size
        self.label = label
        self.operand = operand


def _build_exit_addrs(analysis):
    """Build a set of all ExitProc* instruction addresses across all procs.

    Used to convert ``GoTo L_XXXX`` (where XXXX is an ExitProc instruction)
    into ``Exit Sub`` — the VB equivalent of branching to a proc exit.
    """
    entries = analysis["entries"]
    labels = analysis["labels"]
    exit_addrs = set()
    for _start, _end, path in analysis["paths"]:
        for pos, opcode, _size, _fb in path:
            target = entries.get(opcode, 0)
            label = labels.get(target, "")
            if label.startswith("lblEX_"):
                label = label[len("lblEX_"):]
            if label.startswith("ExitProc"):
                exit_addrs.add(pos)
    return exit_addrs


def proc_return_kind(labels):
    """Return 'Integer' if any instruction label is ExitProcI2 (VB4
    ``Function ... As Integer``), else None (Sub).

    VB4 p-code exit opcodes encode the proc's declared return type:
    ExitProcI2 for Integer functions; ExitProcStr is the plain Sub exit
    (word_probe.py: handler 0x37C/0x386/0x38A are plain-exit variants,
    the disassembler labels them all ExitProcStr); ExitProcHresult marks
    MethCallEngine COM stubs.  Exit types are uniform within a proc
    (verified on PAL.EXE: 0 mixed-type procs; 35 ExitProcI2 procs whose
    call sites all consume the result, 159 ExitProcStr procs whose call
    sites never do)."""
    for lab in labels:
        if lab == "ExitProcI2":
            return "Integer"
    return None


# ---------------------------------------------------------------------------
# Frame-slot type evidence (style review #6/#7)
# ---------------------------------------------------------------------------
# Direct F* loads/stores carry the slot's type in their suffix.  I*
# (indirect) ops only ever touch POSITIVE (parameter) slots in PAL.EXE
# (verified: no ILd*/ISt* on stack-N) where they dereference the caller's
# variable: ILdI2/IStI2 prove the poinee is Integer.  ILdI4/IStI4 are
# deliberately absent -- through a ByRef slot an I4 access may read a
# Long, fetch a BSTR pointer (ByRef String marshaled via CStr2Ansi) or
# fetch a UDT pointer, indistinguishable at the opcode level.
_SLOT_STORE_TYPES = {
    "FStI2": "Integer", "FStI4": "Long", "FStR4": "Single",
    "FStFPR4": "Single", "FStR8": "Double", "FStFPR8": "Double",
    "FStUI1": "Byte", "FStStr": "String", "FStStrCopy": "String",
    "IStI2": "Integer",
}
_SLOT_LOAD_TYPES = {
    "FLdI2": "Integer", "FLdI4": "Long", "FLdR4": "Single",
    "FLdFPR4": "Single", "FLdR8": "Double", "FLdFPR8": "Double",
    "FLdUI1": "Byte", "FLdStr": "String", "ILdI2": "Integer",
    "ILdR8": "Double",
}
_SLOT_RE = re.compile(r"mem=stack([+-]\d+)$")
_STACK_NEG_RE = re.compile(r"stack-(\d+)")

# CVarRef type=4000|VT codes observed in PAL.EXE (VT_BYREF|VT): the
# wrapped reference's element type.  Only the two observed codes are
# mapped; anything else is deliberately no evidence.
_CVARREF_TYPES = {"4002": "Integer", "4008": "String"}


def _slot_of(operand):
    """Signed frame offset of a mem=stackN operand, else None."""
    m = _SLOT_RE.match(operand or "")
    if not m:
        return None
    return int(m.group(1))


def _slot_evidence(instrs):
    """Collect per-slot type evidence from one proc's instructions.

    Returns {slot_offset: votes} with votes = {"store": [(type, va,
    imp, label)], "load": [...], "for": [...], "fixed_str": n}.  imp
    marks ImpAd* evidence (MethCallEngine event procs; the 5 ImpAdSt
    zero-inits are the only ImpAd stores in PAL.EXE and carry quirky
    suffixes, so they lose ties -- see docs/vb40032.md "ImpAd 与 FMem
    的同基址等价"); label names the proving opcode (or the look-back
    pattern name) and drives _param_types' ByRef filtering.

    Look-back patterns (the slot is not in the inspecting operand):
    - fixed-string buffers: FLdRfVar <slot> directly before LdFixedStr/
      StFixedStr len=N (a ``Dim s As String * N`` local);
    - ByRef String params: ILdI4 <param> whose value feeds CStr2Ansi
      (BSTR pointer fetch for ANSI marshaling) -- the value instruction
      is two before the CStr2Ansi;
    - CVarRef's Variant type code: ``FLdI4/ILdI4 <slot>`` directly before
      ``CVarRef ... type=4000|VT`` names the POINTEE type (4002=ByRef
      Integer, 4008=ByRef String; the 0x4000 flag is VT_BYREF).  Only
      the two codes observed in PAL.EXE are mapped.
    For-loop variable types are NOT scanned here: the end expression
    between the FLdRfVar and the For opcode is arbitrarily long, so
    pseudo_code takes them from StackMachine.loop_var_types (recorded
    when _loop_start pops the ref).
    """
    ev = {}

    def add(slot, kind, vtype, va, imp=False, label=None):
        votes = ev.setdefault(slot, {"store": [], "load": [], "for": [],
                                     "fixed_str": 0})
        votes[kind].append((vtype, va, imp, label))

    for i, ins in enumerate(instrs):
        lab = ins.label
        if lab in ("LdFixedStr", "StFixedStr") and i >= 1:
            prev = instrs[i - 1]
            if prev.label == "FLdRfVar":
                slot = _slot_of(prev.operand)
                if slot is not None:
                    try:
                        n = int((ins.operand or "").split("len=")[1])
                    except (ValueError, IndexError):
                        n = 0
                    if n:
                        votes = ev.setdefault(
                            slot, {"store": [], "load": [], "for": [],
                                   "fixed_str": 0})
                        votes["fixed_str"] = max(votes["fixed_str"], n)
        elif lab == "CStr2Ansi" and i >= 2:
            src = instrs[i - 2]
            if src.label in ("ILdI4", "FLdI4", "FLdStr", "FMemLd4"):
                slot = _slot_of(src.operand)
                if slot is not None:
                    # Definitive BSTR proof: the fetched pointer is
                    # marshaled as a string.
                    add(slot, "store", "String", src.pos,
                        imp=src.label.startswith("ImpAd"),
                        label="CStr2Ansi")
            continue
        elif lab == "CVarRef" and i >= 1:
            prev = instrs[i - 1]
            if prev.label in ("ILdI4", "FLdI4"):
                code = (ins.operand or "").split("type=")
                vtype = _CVARREF_TYPES.get(code[1]) if len(code) == 2 else None
                slot = _slot_of(prev.operand)
                if vtype is not None and slot is not None:
                    add(slot, "store", vtype, prev.pos, label="CVarRef")
            continue
        slot = _slot_of(ins.operand)
        if slot is None:
            continue
        imp = lab.startswith("ImpAd")
        if lab in _SLOT_STORE_TYPES:
            add(slot, "store", _SLOT_STORE_TYPES[lab], ins.pos, imp, lab)
        elif lab in _SLOT_LOAD_TYPES:
            add(slot, "load", _SLOT_LOAD_TYPES[lab], ins.pos, imp, lab)
    return ev


def _arbitrate_slot_type(votes):
    """Pick one VB type from _slot_evidence votes, or None.

    Priority: fixed-string size > unanimous-or-majority store evidence >
    For suffix > load suffix.  Store evidence defines the slot's content
    (loads may be raw pointer fetches: FLdI4 on a BSTR slot feeding a
    Declare).  ImpAd evidence loses ties (the known zero-init quirk).
    A genuine tie renders no As clause (VB4 default Variant) -- e.g.
    pub_164's stack-168 is one frame offset reused as a Single temp and
    then a Long pointer temp.
    """
    if not votes:
        return None
    if votes.get("fixed_str"):
        return "String * %d" % votes["fixed_str"]
    for kind in ("store", "for", "load"):
        items = votes.get(kind) or []
        if not items:
            continue
        counts = {}
        for vtype, _va, imp, _lbl in items:
            reg, imp_n = counts.get(vtype, (0, 0))
            counts[vtype] = (reg + (0 if imp else 1), imp_n + (1 if imp else 0))
        regular = dict((t, c[0]) for t, c in counts.items() if c[0])
        pool = regular or dict((t, c[0]) for t, c in counts.items())
        best = max(pool.values())
        winners = [t for t, c in pool.items() if c == best]
        if len(winners) == 1:
            return winners[0]
        return None   # tie: honest Variant
    return None


def _deref_param_types(instrs, nargs):
    """Per-parameter pointee type (or None) from callee-body evidence (#9).

    Under the all-reference ABI a param slot always holds a POINTER: a
    direct F* load's suffix names the POINTER WIDTH, not the pointee
    (FLdI4 stack+12 forwards the reference; its I4 is 4 bytes of address),
    so F* direct loads are no type evidence for ANY param.  Valid
    evidence: unambiguous derefs (ILdI2/IStI2/ILdR8) and the two look-back
    string proofs (CStr2Ansi marshaling; CVarRef VT_BYREF type codes).
    """
    ev = _slot_evidence(instrs)
    byref_ok = {"ILdI2", "IStI2", "ILdR8", "CStr2Ansi", "CVarRef"}
    types = []
    for i in range(nargs):
        slot = 12 + 4 * i
        votes = ev.get(slot)
        if not votes:
            types.append(None)
            continue
        filtered = {}
        for category in ("store", "load", "for"):
            kept = [item for item in (votes.get(category) or [])
                    if item[3] in byref_ok]
            if kept:
                filtered[category] = kept
        if votes.get("fixed_str"):
            filtered["fixed_str"] = votes["fixed_str"]
        types.append(_arbitrate_slot_type(filtered))
    return types


def _hint_majority(hints):
    """Pick the majority type from a {type: count} table, None on tie."""
    if not hints:
        return None
    best = max(hints.values())
    winners = [t for t, n in hints.items() if n == best]
    return winners[0] if len(winners) == 1 else None


def _tally_votes(sink, arg_map):
    """Tally one #9 vote sink into modifier + hint + edge tables (pure).

    sink: {(va, pos): (callee, kind, hint, caller, caller_param_idx)}
    arg_map: {proc_name: nargs}

    Returns (param_kinds, copy_hints, forwards):
      param_kinds: {name: ["ByRef"|"ByVal", ...]} -- ANY copy vote wins
        (a ByRef variable argument must pass the variable's own address,
        so a value-copy temp is definitive ByVal codegen); body votes
        lose (identity optimization on read-only ByVal params); no
        evidence defaults to ByRef (the VB4 source default).
      copy_hints: {(callee, pos): {type: count}} -- copy idioms type the
        param by the copied variable's load suffix.
      forwards: {(callee, pos): set((caller, caller_pos))} -- param-slot
        pointer forwarding edges for pointee propagation.
    """
    kinds_votes = {}
    copy_hints = {}
    forwards = {}
    for (_va, _pos), (callee, kind, hint, caller, src_param) in sink.items():
        kinds_votes.setdefault((callee, _pos), set()).add(kind)
        if kind == "copy" and hint:
            hints = copy_hints.setdefault((callee, _pos), {})
            hints[hint] = hints.get(hint, 0) + 1
        if kind == "forward" and src_param is not None:
            forwards.setdefault((callee, _pos), set()).add(
                (caller, src_param))
    param_kinds = {}
    for name, nargs in arg_map.items():
        if not nargs:
            continue
        param_kinds[name] = [
            "ByVal" if "copy" in kinds_votes.get((name, i), ())
            else "ByRef"
            for i in range(nargs)]
    return param_kinds, copy_hints, forwards


def _propagate_forward_types(param_types, forwards):
    """Fixpoint pointee-type propagation over forwarding edges (pure).

    An edge (caller, K) -> (callee, M) means the caller forwards its
    param K's pointer into the callee's param M: both slots name the
    same pointee, so types flow in BOTH directions (the callee side is
    often typed directly by its body's derefs while the caller side is
    only ever forwarded -- pub_132.a0 -> pub_013.a0's ILdI2).  Majority
    wins; ties stay untyped.  Mutates and returns param_types.
    """
    adj = {}
    for dst, srcs in forwards.items():
        adj.setdefault(dst, set()).update(srcs)
        for s in srcs:
            adj.setdefault(s, set()).add(dst)
    for _round in range(10):
        changed = False
        for node, neighbors in adj.items():
            if node in param_types:
                continue
            cands = {}
            for n in neighbors:
                t = param_types.get(n)
                if t:
                    cands[t] = cands.get(t, 0) + 1
            t = _hint_majority(cands)
            if t:
                param_types[node] = t
                changed = True
        if not changed:
            break
    return param_types


def collect_param_votes(pal, analysis, procs):
    """Pass 1 for style-review #9: call-site ABI vote collection.

    Runs the full decompile once with StackMachine vote recording enabled
    (text is discarded) and tallies the per-(callee, arg-position) push
    idioms into the modifier + pointee-type tables used by both the disasm
    params header and the pseudocode signatures:

      - kinds: ANY copy vote (a bare variable value load materialized into
        a temp via PopTmpLdAd*) proves ByVal -- a ByRef variable argument
        must pass the variable's own address, so the compiler copying the
        value into a temp is definitive ByVal codegen.  FLdRfVar/MemLdRf
        "body" votes are ByRef-compatible but also arise from the
        compiler's identity optimization on read-only ByVal params, so
        they lose to copies.  No evidence (leaf procs, MethCallEngine
        entries, VCall-only callers) defaults to ByRef, the VB4 source
        default.

      - types: callee-body dereference evidence first (direct, strongest);
        copy-vote load suffixes fill gaps (the copied variable's type);
        param-slot forwarding edges then propagate pointee types along the
        call graph to a fixpoint (both directions: a forwarded pair names
        one pointee), e.g. pub_132.magicIdx -> pub_013's ILdI2 -> Integer.

    Returns (param_kinds, param_types):
      param_kinds: {proc_name: ["ByRef"|"ByVal", ...]} indexed by position
      param_types: {(proc_name, pos): type-or-None}
    """
    sink = {}
    vcall_sink = {}
    decompile_all(pal, analysis, procs, votes_sink=sink,
                  vcall_sink=vcall_sink, quiet=True)

    arg_map = _build_arg_map(pal, analysis, procs)
    param_kinds, copy_hints, forwards = _tally_votes(sink, arg_map)

    # Pointee types: 1) callee-body dereference evidence (direct).
    param_types = {}
    for idx, (_ps, _pd, name) in enumerate(procs):
        nargs = arg_map.get(name, 0)
        if not nargs:
            continue
        try:
            _start, _end, instrs = build_instrs(pal, analysis, idx)
        except Exception:
            continue
        for i, t in enumerate(_deref_param_types(instrs, nargs)):
            if t:
                param_types[(name, i)] = t

    # 2) copy-vote load suffixes fill gaps (the copied variable's type).
    for key, hints in copy_hints.items():
        if key not in param_types:
            t = _hint_majority(hints)
            if t:
                param_types[key] = t

    # 3) Forwarding edges propagate pointee types to a fixpoint.
    _propagate_forward_types(param_types, forwards)

    return param_kinds, param_types, vcall_sink


def _build_arg_map(pal, analysis, procs):
    """Map proc name -> arg count (shared by the vote pass and rendering)."""
    arg_counts = _build_arg_counts(pal, analysis)
    return dict((name, arg_counts.get(idx, 0))
                for idx, (_ps, _pd, name) in enumerate(procs))


def _local_dim_lines(instrs, stmts, machine):
    """Dim lines for local frame slots that render in the output (#6).

    A slot "renders" when its stack-N name appears in a final statement:
    mechanism slots (For ctl, CStr2Ansi temps, FFree* areas,
    LitVar_Missing slots, ByRef-call alias out-slots) never do and stay
    undeclared.  The Function result slot renders as the proc name
    (_subst_param) and is declared by the signature's As clause.
    """
    rendered = set()
    for stmt in stmts:
        for m in _STACK_NEG_RE.finditer(stmt.text):
            rendered.add(-int(m.group(1)))
    rendered.discard(machine.result_slot)
    if not rendered:
        return []
    ev = _slot_evidence(instrs)
    # Loop variables: authoritative from the machine (ForI2/ForI4 popped
    # the very ref the rendered For names).
    for ref_text, vtype in machine.loop_var_types.items():
        if ref_text.startswith("stack-"):
            try:
                slot = -int(ref_text[len("stack-"):])
            except ValueError:
                continue
            ev.setdefault(slot, {"store": [], "load": [], "for": [],
                                 "fixed_str": 0})["for"].append(
                (vtype, 0, False, None))
    lines = []
    # Frame slots allocate downward (-134 first): descending numeric
    # order == declaration order.
    for slot in sorted(rendered, reverse=True):
        vtype = _arbitrate_slot_type(ev.get(slot))
        if vtype:
            lines.append("    Dim stack%d As %s" % (slot, vtype))
        else:
            # No type proof (ByRef-forwarded temp, mixed reuse): a bare
            # Dim declares Variant, which covers every observed use.
            lines.append("    Dim stack%d" % slot)
    return lines


def _prepare_proc(pal, analysis, index, name, arg_map, param_kinds=None,
                  param_types=None, votes_sink=None, vcall_sink=None,
                  vcall_modes=None):
    """Common per-procedure setup: instrs, signature, configured machine.

    Returns (start, end, instrs, sig, keyword, machine, ret_type, name).
    """
    start, end, instrs = build_instrs(pal, analysis, index)
    entry_stub = analysis["method_stubs"].get(end)

    # Param modifiers come from the call-site ABI vote table (#9,
    # collect_param_votes): under the all-reference ABI the callee's own
    # I*/F* usage cannot distinguish ByRef/ByVal, so the VOTE pass's
    # cross-call-site push idioms are authoritative.  No table (unit
    # tests / procs with no call sites) -> VB4 source default ByRef.
    # Every param gets an explicit modifier: a bare name means ByRef in
    # VB4, so omitting it on a ByVal slot would CHANGE the calling
    # convention on recompile (style review #2).
    nargs = (arg_map or {}).get(name, 0)
    kinds = (param_kinds or {}).get(name) or []
    types = [(param_types or {}).get((name, i)) for i in range(nargs)]
    params = []
    param_map = {8: "Me"}   # stack+8 is always the implicit object base
    for i in range(nargs):
        pname = "a%d" % i
        kind = kinds[i] if i < len(kinds) else "ByRef"
        text = ("ByVal " if kind == "ByVal" else "ByRef ") + pname
        if types[i]:
            text += " As " + types[i]   # pointee evidence (#7/#9)
        params.append(text)
        param_map[8 + 4 * (i + 1)] = pname

    ret_type = proc_return_kind([i.label for i in instrs])
    keyword = "Function" if ret_type else "Sub"
    sig = "%s %s(%s)" % (keyword, name, ", ".join(params))
    if ret_type:
        sig += " As %s" % ret_type
    if entry_stub:
        sig += "  ' MethCallEngine entry"

    machine = stack_ir.StackMachine()
    machine.arg_map = arg_map or {}
    machine.param_map = param_map
    machine.exit_keyword = "Exit %s" % keyword
    machine.proc_name = name
    machine.call_votes = votes_sink
    # #14: pass 1 records speculative-result liveness per VCall site;
    # pass 2 replays the collected modes (missing key = push, Function).
    machine.vcall_sink = vcall_sink
    machine.vcall_modes = vcall_modes
    if ret_type:
        # VB4 reserves the first local slot (stack-134) for the Function
        # result; render it as the proc name (VB "name = value" semantics).
        # Verified on PAL.EXE: all 35 ExitProcI2 procs store there, none use
        # it as a For-loop variable or pass it ByRef.
        machine.result_slot = -134
        machine.result_name = name
    return start, end, instrs, sig, keyword, machine, ret_type, name


def _prune_labels(stmts, label_at_stmt):
    """Drop labels that no GoTo/GoSub references anymore."""
    import re as _re
    live_refs = set()
    for stmt in stmts:
        for m in _re.finditer(r'Go(?:To|Sub) L_([0-9A-F]+)', stmt.text):
            live_refs.add(int(m.group(1), 16))
    pruned = {}
    for idx, labels in label_at_stmt.items():
        keep = [t for t in labels if t in live_refs]
        if keep:
            pruned[idx] = keep
    return stmts, pruned


def _fold_returns(stmts, label_at_stmt, name, ret_type, exit_keyword):
    """Return-statement rendering: fold "name = <expr>" + "Exit Function"
    pairs into "Return <expr>" — clearer for modern readers than VB's
    "name = value" idiom, and semantically identical (store to the
    result slot + exit).  Applied when the terminator IMMEDIATELY follows
    the assignment, anywhere in the body (covers both the tail return and
    early exits inside If blocks).  The terminator is dropped only when
    adjacent; otherwise the VB form stays (e.g. process_Battle stores the
    result then cleans up — a Return there would change control flow).
    """
    import re as _re
    if not (ret_type and stmts):
        return
    term_idx = len(stmts) - 1
    term = stmts[term_idx]
    if term.text == exit_keyword and term.indent_delta == 0:
        for j in range(term_idx - 1, -1, -1):
            stmt = stmts[j]
            if stmt.indent_delta != 0:
                break   # structural statement — not a plain assignment
            m2 = _re.match(r'%s\s*=\s*(.+)$' % _re.escape(name), stmt.text)
            if m2:
                stmt.text = 'Return %s' % m2.group(1)
                if term_idx == j + 1:
                    # adjacent pair — drop the redundant terminator
                    stmts.pop(term_idx)
                break
            if stmt.text.startswith(('Call ', 'GoTo ', 'Exit ', 'Return ')):
                break   # non-assignment statement before the store
            if stmt.text.endswith(':') or 'L_' in stmt.text:
                break
            # plain assignment to something else — keep scanning upward
            # (e.g. temp stores feeding the result); result store is the
            # LAST name= assignment.
            if _re.match(r'[A-Za-z_]\w*\s*=', stmt.text):
                continue
            break
    # Early-exit pattern inside the body: "name = <expr>" followed
    # directly by the terminator at ANY depth (e.g. inside If blocks).
    k = 0
    while k < len(stmts) - 1:
        s0, s1 = stmts[k], stmts[k + 1]
        if (s0.indent_delta == 0 and s1.text == exit_keyword
                and s1.indent_delta == 0
                and not label_at_stmt.get(k + 1)):
            m2 = _re.match(r'%s\s*=\s*(.+)$' % _re.escape(name), s0.text)
            if m2:
                # adjacency check via VA: consecutive emitted stmts
                s0.text = 'Return %s' % m2.group(1)
                del stmts[k + 1]
                # Keep label anchors glued to their statements: the
                # deletion shifts every later index down by one (a stale
                # anchor lands the label on the NEXT statement, changing
                # what GoTo L_xxx executes — observed in
                # select_battle_action's L_0040E01E).
                for idx in sorted(label_at_stmt, reverse=True):
                    if idx > k + 1:
                        labels = label_at_stmt.pop(idx)
                        label_at_stmt.setdefault(idx - 1, []).extend(
                            labels)
                # do not advance k; next pair may follow
                continue
        k += 1


def _render_proc(sig, keyword, stmts, label_at_stmt, dim_lines=()):
    """Render a statement list into the final pseudocode text."""
    lines = [sig]
    lines.extend(dim_lines)
    indent = 1
    for i, stmt in enumerate(stmts):
        labels_here = sorted(label_at_stmt.get(i, []))
        is_closer = (stmt.indent_delta < 0
                     or stmt.text == 'End Select')
        if is_closer:
            # A label on a LOOP closer (Loop/Wend/Next) is the latch's
            # back-edge (its VA == the closer's VA): jumping to it must
            # re-enter the loop, so it belongs BEFORE the closer.
            # Other closers: labels with VA == stmt.va are merge points
            # that belong AFTER the closer (at the outer level).
            # Labels with VA < stmt.va go before the closer.
            loop_close = (stmt.text.startswith('Loop')
                          or stmt.text == 'Wend'
                          or stmt.text.startswith('Next'))
            if loop_close:
                labels_before = labels_here
                labels_after = []
            else:
                labels_before = [t for t in labels_here if t < stmt.va]
                labels_after = [t for t in labels_here if t >= stmt.va]
        else:
            labels_before = labels_here
            labels_after = []
        # Labels are always at column 0 (VB convention for line labels).
        for tgt in labels_before:
            lines.append("L_%08X:" % tgt)
        if stmt.text == 'Else' or stmt.text.startswith('ElseIf '):
            # Else/ElseIf print at the opener's indent (one level less than
            # the body), but do not change the indent for the body.
            prefix = "    " * max(1, indent - 1)
            lines.append("%s%s" % (prefix, stmt.text))
        elif stmt.text == 'End Select':
            # End Select closes both the last Case body and the Select block.
            indent -= 2
            if indent < 1:
                indent = 1
            prefix = "    " * indent
            lines.append("%s%s" % (prefix, stmt.text))
        elif stmt.text.startswith('Case ') and stmt.indent_delta == 0:
            # Subsequent Case: print at Select level (one less than body),
            # keep indent unchanged for the body.
            prefix = "    " * max(1, indent - 1)
            lines.append("%s%s" % (prefix, stmt.text))
        elif stmt.indent_delta < 0:
            # Closing keyword (End If, Next): decrease first, then print
            # at the same indent as the matching opener.
            indent += stmt.indent_delta
            if indent < 1:
                indent = 1
            prefix = "    " * indent
            lines.append("%s%s" % (prefix, stmt.text))
        else:
            # Opener (If, For): print at current indent, then increase
            # so the body is indented one level deeper.
            prefix = "    " * indent
            lines.append("%s%s" % (prefix, stmt.text))
            indent += stmt.indent_delta
            if indent < 1:
                indent = 1
        for tgt in labels_after:
            lines.append("L_%08X:" % tgt)
    lines.append("End %s" % keyword)
    return "\n".join(lines)


def _split_top_compare(cond_text):
    """Split '(lhs op rhs)' at the top-level comparison operator.

    Returns (lhs, op, rhs) or None when there is no top-level compare.
    """
    s = cond_text.strip()
    if len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        depth = 0
        for k, ch in enumerate(s):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and k < len(s) - 1:
                    break
        else:
            s = s[1:-1]
    ops = ("<=", ">=", "<>", "=", "<", ">")
    depth = 0
    i = len(s) - 1
    while i >= 0:
        ch = s[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            depth -= 1
        elif depth == 0:
            for op in ops:
                if s.startswith(op, i):
                    lhs = s[:i].strip()
                    rhs = s[i + len(op):].strip()
                    if lhs and rhs:
                        return (lhs, op, rhs)
        i -= 1
    return None


def _select_case_from_elseif(stmts, label_at_stmt):
    """Rewrite If/ElseIf chains comparing one variable into Select Case.

    The structurer emits multi-way tests as If/ElseIf chains; when every
    leg's condition is a top-level comparison of the same variable, render
    the VB4 Select Case form.
    """
    import re as _re

    def parse_leg(text):
        for prefix in ("If ", "ElseIf "):
            if text.startswith(prefix) and text.endswith(" Then"):
                return _split_top_compare(text[len(prefix):-len(" Then")])
        return None

    patterns = []
    i = 0
    while i < len(stmts):
        s = stmts[i]
        if s.indent_delta != +1 or not s.text.startswith("If "):
            i += 1
            continue
        parsed = parse_leg(s.text)
        if parsed is None:
            i += 1
            continue
        var = parsed[0]
        legs = [i]
        j = i + 1
        depth = 1
        else_idx = None
        end_idx = None
        while j < len(stmts):
            t = stmts[j]
            if depth == 1 and t.text.startswith("ElseIf "):
                p2 = parse_leg(t.text)
                if p2 is not None and p2[0] == var:
                    legs.append(j)
                    j += 1
                    continue
                break
            if depth == 1 and t.text == "Else":
                else_idx = j
                j += 1
                continue
            if depth == 1 and t.text == "End If":
                end_idx = j
                break
            depth += t.indent_delta
            j += 1
        if end_idx is None or len(legs) < 2:
            # Advance by ONE, not past the scanned region: a failed
            # candidate is often a single If whose body spans the rest of
            # the proc (e.g. an early-exit If/Else wrapper); If/ElseIf
            # chains nested inside that body must still be considered.
            i += 1
            continue
        patterns.append((i, legs, else_idx, end_idx, var))
        i = end_idx + 1

    if not patterns:
        return stmts, label_at_stmt

    # Apply replacements from the last to the first (stable indices).
    for start, legs, else_idx, end_idx, var in reversed(patterns):
        new_stmts = []
        first_va = stmts[start].va
        new_stmts.append(stack_ir.Stmt(
            first_va, +1, "Select Case %s" % var, stmts[start].order))
        bounds = list(legs) + ([else_idx] if else_idx is not None else [])
        for k, leg in enumerate(legs):
            parsed = parse_leg(stmts[leg].text)
            _lhs, op, val = parsed
            if op == "=":
                case_text = "Case %s" % val
            else:
                case_text = "Case Is %s %s" % (op, val)
            delta = +1 if k == 0 else 0
            new_stmts.append(stack_ir.Stmt(
                stmts[leg].va, delta, case_text, stmts[leg].order))
            nxt = bounds[k + 1] if k + 1 < len(bounds) else end_idx
            new_stmts.extend(stmts[leg + 1:nxt])
        if else_idx is not None:
            new_stmts.append(stack_ir.Stmt(
                stmts[else_idx].va, 0, "Case Else", stmts[else_idx].order))
            new_stmts.extend(stmts[else_idx + 1:end_idx])
        new_stmts.append(stack_ir.Stmt(
            stmts[end_idx].va, -1, "End Select", stmts[end_idx].order))
        stmts = stmts[:start] + new_stmts + stmts[end_idx + 1:]

    # Each Select Case needs one MORE structural line than the If/ElseIf
    # chain it replaces (every leg gets its own Case, plus the Select
    # Case opener), so a conversion inserts exactly one statement right
    # after the chain's If header: every index > start shifts by +1.
    # Remap label anchors with that exact shift — rebuilding anchors by
    # VA order is not an option (the stmt list is not VA-ordered once
    # orphan regions are appended, and process_scripts' mid-block jump
    # targets such as L_00421140 must stay glued to their statement).
    if patterns:
        shift_after = [p[0] for p in patterns]  # chain starts (ascending)
        new_label_at = {}
        for idx, labels in label_at_stmt.items():
            new_idx = idx + sum(1 for s in shift_after if s < idx)
            new_label_at.setdefault(new_idx, []).extend(labels)
        label_at_stmt = new_label_at
    return stmts, label_at_stmt


def _decompile_cfg(base, exit_addrs, stats):
    """CFG/dominator-structured path (src/structuring.py)."""
    start, end, instrs, sig, keyword, machine, ret_type, name = base
    stmts, label_at_stmt, st = structuring.structure_proc(
        instrs, start, end, machine, exit_addrs, machine.exit_keyword)
    stats.update(st)
    # #14 pass-1 closeout: any tagged VCall result still on the eval
    # stack at proc end was never consumed -> Sub site.
    machine.settle_vcall_sites()
    stmts, label_at_stmt = _select_case_from_elseif(stmts, label_at_stmt)
    stmts, label_at_stmt = _postprocess_stmts(
        stmts, label_at_stmt, start, end, keyword, name, ret_type,
        machine, exit_addrs)
    dim_lines = _local_dim_lines(instrs, stmts, machine)
    return _render_proc(sig, keyword, stmts, label_at_stmt, dim_lines)


def decompile_proc(pal, analysis, index, name, arg_map=None, exit_addrs=None,
                   stats_out=None, param_kinds=None, param_types=None,
                   votes_sink=None, vcall_sink=None, vcall_modes=None):
    """Decompile one procedure into VB pseudocode text.

    Routes through the CFG/dominator structurer (src/structuring.py).
    StructureUnsupported propagates to the caller; decompile_all isolates
    per-proc failures and emits an error stub instead of aborting the run.
    """
    base = _prepare_proc(pal, analysis, index, name, arg_map,
                         param_kinds=param_kinds, param_types=param_types,
                         votes_sink=votes_sink, vcall_sink=vcall_sink,
                         vcall_modes=vcall_modes)
    start, end, instrs, sig, keyword, _machine, ret_type, _name = base
    if not instrs:
        return "%s\n    ' (empty procedure)\nEnd %s" % (sig, keyword)
    stats = stats_out if stats_out is not None else {}
    text = _decompile_cfg(base, exit_addrs, stats)
    if stats_out is not None:
        stats_out.setdefault("path", "cfg")
    return text


def _drop_empty_arms(stmts, label_at_stmt):
    """Collapse empty If/ElseIf ladder arms (pure style; semantics exact).

    Detection is on ADJACENT statements: labels render as line prefixes
    at _render_proc time, so adjacency in *stmts* is exact -- an arm is
    empty iff its opener line is immediately followed by the next
    opener (or the Else / End If).

    1. bare Else: "Else" directly before "End If" -- the else arm is
       empty; the dead Else line drops with zero semantic change.
    2. empty Then with content in Else: "If c Then" (or "ElseIf c Then")
       directly before "Else" and a non-empty arm: invert the condition
       (structurer._wrap_not collapses double negation) and drop the
       Else -- the condition is still evaluated exactly once.
    3. ladder whose every Then/ElseIf arm is empty and whose Else has
       content: "If c1 Then / ElseIf c2 Then / Else <body>" collapses to
       "If (Not c1) And (Not c2) Then <body>".  Every leg's true-edge
       jumps straight to the join, so the guarded body runs iff ALL
       legs fail -- the exact conjunction.  Re-evaluation order is safe:
    the chain machinery only admits side-effect-free legs as ElseIf
    (a leg whose condition carries a deferred call is rejected -- VB4
    has no short-circuit, see structuring's trial-process comment), so
    every leg condition is a pure read.
    """
    from structuring import _wrap_not

    n = len(stmts)
    drop = set()
    rewrite = {}

    def cond_of(text):
        if text.startswith('If '):
            return text[3:-5]
        return text[7:-5]              # "ElseIf "

    i = 0
    while i < n:
        t = stmts[i].text
        if not (t.startswith('If ') and t.endswith(' Then')):
            i += 1
            continue
        # Collect the ladder run: the head is a bare "If"; each further
        # leg MUST be an "ElseIf" line (indent_delta 0).  A bare "If "
        # right after an opener is a NESTED If -- the first statement of
        # the previous leg's then-arm -- never a ladder leg (pub_196's
        # dispatch guard wraps the f06C4 ladder exactly this way).
        legs = [i]
        j = i + 1
        while (j < n and stmts[j].text.startswith('ElseIf ')
               and stmts[j].text.endswith(' Then')
               and stmts[j].indent_delta == 0):
            legs.append(j)
            j += 1
        after = stmts[j].text if j < n else None
        if after == 'Else':
            body = stmts[j + 1].text if j + 1 < n else None
            if body is None or body == 'End If':
                pass                   # empty Else: rule 1 below
            elif len(legs) >= 2:
                # Rule 3: all Then/ElseIf arms empty, Else has content.
                neg = ' And '.join('(%s)' % _wrap_not(cond_of(stmts[k].text))
                                   for k in legs)
                rewrite[i] = 'If %s Then' % neg
                drop.update(legs[1:])
                drop.add(j)            # the Else
            else:
                # Rule 2: single If, empty Then, content in Else.
                rewrite[i] = 'If %s Then' % _wrap_not(cond_of(t))
                drop.add(j)            # the Else
        i = j

    # Rule 1: bare Else directly before End If (independent scan: this
    # shape is disjoint from rules 2/3, whose Else is followed by body).
    for i in range(n - 1):
        if stmts[i].text == 'Else' and stmts[i + 1].text == 'End If':
            drop.add(i)

    if not drop and not rewrite:
        return stmts, label_at_stmt

    new_stmts = []
    new_label_at = {}
    old_to_new = {}
    for i, stmt in enumerate(stmts):
        if i in drop:
            continue
        if i in rewrite:
            stmt = type(stmt)(stmt.va, stmt.indent_delta, rewrite[i],
                              order=stmt.order)
        old_to_new[i] = len(new_stmts)
        new_stmts.append(stmt)
    for idx, labels in label_at_stmt.items():
        if idx in old_to_new:
            new_label_at[old_to_new[idx]] = labels
        else:
            # Label sat on a dropped statement (an Else): attach it to
            # the next kept statement so the jump still lands.
            for j in range(idx + 1, len(stmts)):
                if j in old_to_new:
                    new_label_at.setdefault(old_to_new[j], []).extend(labels)
                    break
    return new_stmts, new_label_at


def _postprocess_stmts(stmts, label_at_stmt, start, end, keyword,
                       name, ret_type, machine, exit_addrs):
    """Shared linear-order cleanups (dead terminator removal, label
    re-mapping, Return folding) applied to the CFG structurer's output
    (whose statement order is linear within each region)."""
    import re as _re

    stmts, label_at_stmt = _drop_empty_arms(stmts, label_at_stmt)

    # Dead code elimination: after a terminator (GoTo, Exit Sub, Return),
    # remove unreachable GoTo/Exit Sub statements until the next structural
    # marker (End If, Next, Wend, Loop, End Select, Else, Case) or label.
    # The CFG path emits single-instruction branch trampolines from
    # unreachable regions as bare "GoTo" statements (no assigned
    # statement address); those are all dead by construction.
    structural_markers = {'End If', 'End Select', 'Next', 'Wend', 'Loop',
                          'Loop While', 'Else'}
    # An 'ElseIf' opener likewise ends the previous leg's dead zone: the
    # statements in a subsequent leg are reachable (when its condition
    # matches) even though the previous leg ended in a terminator.
    # Without this, GoTo/Exit terminators inside an else-if's then-arm
    # (e.g. cross-leg branches into a shared body) were wrongly deleted.
    def _is_marker(text):
        return (text in structural_markers
                or text.startswith('Case ')
                or text.startswith('Loop ')
                or text.startswith('ElseIf '))
    terminators = ('GoTo ', 'Exit Sub', 'Exit For', 'Exit Do',
                   'Continue ', 'Return')
    label_indices = set(label_at_stmt.keys())
    dead = set()
    in_dead_zone = False
    for i, stmt in enumerate(stmts):
        if i in dead:
            continue
        text = stmt.text.strip()
        if in_dead_zone:
            # Check if this is a structural marker or label target.
            is_marker = _is_marker(text)
            is_label_target = i in label_indices
            if is_marker or is_label_target:
                in_dead_zone = False
            elif text.startswith(terminators):
                # Dead GoTo/Exit Sub after a terminator.
                dead.add(i)
            # Other statements (assignments, calls) in the dead zone are
            # kept — they may produce output needed for structure balance.
        else:
            if text.startswith(terminators) and text != 'Return' \
                    and stmt.va == 0:
                # Addressless GoTo (unreachable trampoline rendering):
                # drop it and stay in the dead zone.
                dead.add(i)
                continue
            if text.startswith(terminators) and text != 'Return':
                in_dead_zone = True
            elif text == 'Return':
                in_dead_zone = True
    if dead:
        new_stmts = []
        new_label_at = {}
        old_to_new = {}
        for i, stmt in enumerate(stmts):
            if i in dead:
                continue
            new_idx = len(new_stmts)
            old_to_new[i] = new_idx
            new_stmts.append(stmt)
        for idx, labels in label_at_stmt.items():
            new_idx = old_to_new.get(idx)
            if new_idx is not None:
                new_label_at[new_idx] = labels
            else:
                # Label was on a dead stmt — find next alive stmt.
                for j in range(idx + 1, len(stmts)):
                    if j not in dead:
                        new_idx = old_to_new[j]
                        new_label_at.setdefault(new_idx, []).extend(labels)
                        break
        stmts = new_stmts
        label_at_stmt = new_label_at

    # Prune labels no longer referenced (dead-code elimination above can
    # remove every GoTo that targeted a label).
    stmts, label_at_stmt = _prune_labels(stmts, label_at_stmt)

    # Return-statement folding: "name = <expr>" + "Exit Function" →
    # "Return <expr>" (semantically identical: store to the result slot
    # + exit).  See _fold_returns for the full rationale.
    _fold_returns(stmts, label_at_stmt, name, ret_type, machine.exit_keyword)

    # Redundant tail exit (style review #4): the standard epilogue's
    # ExitProcStr renders "Exit Sub"/"Exit Function" as the FINAL
    # statement; End Sub/End Function already exits, so drop it when no
    # GoTo targets it.  A label on the statement means something jumps
    # here (a live GoTo survived _prune_labels above) and the exit must
    # stay.  Mid-body exits are never last: a fallthrough barrier (e.g.
    # a Select no-match leg) always precedes its closing End Select, so
    # dropping only the last statement cannot remove a barrier.
    if (stmts and stmts[-1].text == machine.exit_keyword
            and stmts[-1].indent_delta == 0
            and not label_at_stmt.get(len(stmts) - 1)):
        stmts.pop()
    return stmts, label_at_stmt


def decompile_all(pal, analysis, procs, param_kinds=None, param_types=None,
                  votes_sink=None, vcall_sink=None, vcall_modes=None,
                  quiet=False):
    """Decompile all procedures.  Returns full text.

    Each procedure is isolated: an exception in one proc emits an error
    stub instead of aborting the whole run, and a per-structuring summary
    is printed to stdout (path counts + goto stats).  votes_sink enables
    #9 call-idiom recording on every machine (pass 1); param_kinds /
    param_types inject the voted modifiers/pointee types (pass 2).  quiet
    suppresses the stdout summary (used by the vote pass, whose text is
    discarded).  #14: vcall_sink collects per-site speculative-result
    liveness (pass 1); vcall_modes replays it (pass 2).
    """
    arg_map = _build_arg_map(pal, analysis, procs)
    exit_addrs = _build_exit_addrs(analysis)
    out = []
    out.append("VB4 p-code decompilation (VB-style pseudocode)")
    out.append("Procedures: %d\n" % len(procs))
    path_counts = {}
    goto_total = 0
    audit_bad = []
    errors = []
    import traceback
    for idx, (_ps, _pd, name) in enumerate(procs):
        stats = {}
        try:
            text = decompile_proc(pal, analysis, idx, name,
                                  arg_map=arg_map, exit_addrs=exit_addrs,
                                  stats_out=stats,
                                  param_kinds=param_kinds,
                                  param_types=param_types,
                                  votes_sink=votes_sink,
                                  vcall_sink=vcall_sink,
                                  vcall_modes=vcall_modes)
            path = stats.get("path", "cfg")
        except Exception as e:  # per-proc isolation: keep decompiling
            path = "error"
            errors.append((name, e))
            tb = traceback.format_exc().rstrip("\n").splitlines()
            text = "' " + "=" * 66 + "\n"
            text += "' %s: DECOMPILATION FAILED: %s\n" % (name, e)
            for line in tb[1:]:
                text += "'   %s\n" % line.replace("\t", "    ")
            text += "' " + "=" * 66
        path_counts[path] = path_counts.get(path, 0) + 1
        goto_total += stats.get("gotos", 0)
        for v in stats.get("edge_audit", []) or []:
            audit_bad.append("%s: %s" % (name, v))
        out.append(text)
        out.append("")
    summary = ["Structurer summary: %s" % ", ".join(
        "%s=%d" % kv for kv in sorted(path_counts.items()))]
    if goto_total:
        summary.append("explicit gotos: %d" % goto_total)
    summary.append("edge audit: %s" % ("clean" if not audit_bad
                                       else "%d VIOLATIONS" % len(audit_bad)))
    if not quiet:
        print(" | ".join(summary))
        for v in audit_bad:
            print("  EDGE-AUDIT %s" % v, file=sys.stderr)
    return "\n".join(out)
