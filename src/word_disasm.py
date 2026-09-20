"""First-generation PAL VB4 word-pcode renderer.

The renderer intentionally prints raw operands instead of guessing their
individual formats.  Opcode names come from CodeView labels when the debug
VB40032 build is available; boundary recovery is supplied by word_probe.
"""
import re
import struct

from word_probe import (
    OP_ARYLDRF,
    OP_ARYLDPR,
    OP_FFREEVAR,
    OP_FFREESTR,
    OP_GETRECOWNER3,
    OP_LITSTR,
    OP_LITVARSTR,
    decode_proc,
    engine_bounds,
    find_dispatch_table,
    handler_deltas,
    load_word_table,
    load_engine_labels,
)
from proc_dsc import (
    PAL_END,
    PAL_START,
    STUB_END,
    STUB_START,
    find_method_stubs,
    find_procs,
)


def analyze(vb, pal, stub_names=None, declares=None):
    """Return word-dispatch analysis shared by the renderer and probes."""
    engine_start, engine_end = engine_bounds(vb)
    table = find_dispatch_table(vb, engine_start, engine_end)
    entries = load_word_table(vb, table, engine_start, engine_end)
    labels = load_engine_labels(vb, engine_start)
    candidates = {}
    cache = {}
    for opcode, handler in entries.items():
        candidates[opcode] = handler_deltas(
            vb, handler, table, engine_end, cache)

    procs = find_procs(pal, PAL_START, PAL_END)
    paths = []
    for start, end, _size in procs:
        _score, path = decode_proc(pal, entries, candidates, start, end)
        paths.append((start, end, path))
    method_stubs = find_method_stubs(pal, STUB_START, STUB_END)
    return {
        "table": table,
        "entries": entries,
        "labels": labels,
        "procs": procs,
        "paths": paths,
        "method_stubs": method_stubs,
        "stub_names": stub_names or {},
        "declares": declares,
    }


def resolve_lazy_declare(pal, target, declares):
    """Resolve PAL's lazy Declare thunk to its library/function table entry."""
    if declares is None or not pal.in_range(target + 0x13):
        return None
    # mov edx,[table]; add edx,slot; mov eax,[edx]; ...; jmp eax
    if (pal.r8(target) != 0x8B or pal.r8(target + 1) != 0x15
            or pal.r8(target + 6) != 0x81 or pal.r8(target + 7) != 0xC2):
        return None
    slot = pal.r32(target + 8)
    if slot % 4:
        return None
    index = slot // 4
    if not (0 <= index < len(declares.entries)):
        return None
    name, library, _name_ptr, _library_ptr, _sig_off = declares.entries[index]
    return "%s.%s" % (library, name)


def _s16(data):
    return int.from_bytes(data[:2], "little", signed=True)


def _u16(data):
    return int.from_bytes(data[:2], "little")


def _s32(data):
    return int.from_bytes(data[:4], "little", signed=True)


# Opcodes whose operand bytes are rendered with a dedicated format rather
# than the generic label-driven format_operand().  Kept here (and in
# word_probe.decode_proc for boundary recovery) so the renderer and the
# stack-machine decompiler share one source of truth.
_SPECIAL_OPCODES = (
    OP_GETRECOWNER3, OP_ARYLDPR, OP_ARYLDRF, OP_FFREEVAR, OP_FFREESTR,
    OP_LITVARSTR, OP_LITSTR,
)


def special_operand(opcode, raw):
    """Render the inline operand of a variable-length opcode.

    Returns the operand string for the handful of opcodes whose encoding is
    known structurally (inline payloads / strings), or None if `opcode` is
    not one of them.  Shared by format_proc() and pseudo_code._operand_for()
    so disassembly and pseudocode never disagree on these.
    """
    if opcode == OP_GETRECOWNER3 and len(raw) >= 4:
        payload_offset = int.from_bytes(raw[2:4], "little", signed=True)
        return "record-owner payload=%d bytes" % payload_offset
    if opcode in (OP_ARYLDPR, OP_ARYLDRF) and len(raw) >= 4:
        return "descriptor=0x%04X" % int.from_bytes(raw[2:4], "little")
    if opcode in (OP_FFREEVAR, OP_FFREESTR) and len(raw) >= 4:
        byte_length = int.from_bytes(raw[2:4], "little")
        offsets = [int.from_bytes(raw[i:i + 2], "little", signed=True)
                   for i in range(4, min(len(raw), 4 + byte_length), 2)]
        return "byteLen=%d stack=%s" % (byte_length, offsets)
    if opcode == OP_LITVARSTR and len(raw) >= 10:
        byte_length = int.from_bytes(raw[2:4], "little")
        string_bytes = raw[10:10 + max(0, byte_length - 6)]
        text = string_bytes.decode("utf-16le", "replace").rstrip("\x00")
        return 'byteLen=%d offset=%d text=%r' % (
            byte_length, int.from_bytes(raw[4:6], "little", signed=True), text)
    if opcode == OP_LITSTR and len(raw) >= 10:
        byte_length = int.from_bytes(raw[4:8], "little")
        string_bytes = raw[8:8 + byte_length]
        text = string_bytes.decode("utf-16le", "replace")
        return 'index=%04X byteLen=%d text=%r' % (
            int.from_bytes(raw[2:4], "little"), byte_length, text)
    return None


def format_operand(opcode, label, raw, branch_base, call_names, declares,
                   pal):
    """Render operands whose representation is established by the handler."""
    operand = raw[2:]
    if label.startswith("ImpAdCall") and len(operand) >= 4:
        target = int.from_bytes(operand[:4], "little")
        name = call_names.get(target)
        if name is None and declares is not None:
            name = declares.resolve(target)
        if name is None:
            name = resolve_lazy_declare(pal, target, declares)
        if name:
            name = name.replace("VB40032.DLL.", "VB40032.")
            return "call=%s@%08X" % (name, target)
        return "call=@%08X" % target
    if label.startswith(("ImpAdLd", "ImpAdSt")) and len(operand) >= 4:
        # These handlers add the inline dword to the p-code global base.
        return "global=%08X" % int.from_bytes(operand[:4], "little")
    if label.startswith("NewIfNull") and len(operand) >= 4:
        # The allocator receives this runtime type/class descriptor directly.
        return "descriptor=%08X" % int.from_bytes(operand[:4], "little")
    if label.startswith("ThisVCall") and len(operand) >= 2:
        text = "this.vcall=%04X" % _u16(operand)
        if len(operand) >= 6:
            text += "@%08X" % int.from_bytes(operand[2:6], "little")
        return text
    if label.startswith("VCall") and len(operand) >= 2:
        text = "vcall=%04X" % _u16(operand)
        if len(operand) >= 6:
            text += "@%08X" % int.from_bytes(operand[2:6], "little")
        return text
    if label == "LitVar_Missing" and len(operand) >= 2:
        return "mem=stack%+d" % _s16(operand)
    if label == "LitDate" and len(operand) >= 8:
        return "val=%g" % struct.unpack("<d", operand[:8])[0]
    if label == "LateIdLdVar" and len(operand) >= 6:
        return "mem=stack%+d id=%08X" % (
            _s16(operand), int.from_bytes(operand[2:6], "little"))
    if label == "Redim" and len(operand) >= 10:
        return "dims=%d desc=%08X flags=%04X,%04X" % (
            int.from_bytes(operand[:2], "little", signed=True),
            int.from_bytes(operand[2:6], "little"),
            _u16(operand[6:8]), _u16(operand[8:10]))
    if label == "Open" and len(operand) >= 2:
        return "flags=%04X" % _u16(operand)
    if label == "LitI2_10":
        return "val=%d" % ((opcode - 0x0292) // 2)
    if label == "LitI2" and len(operand) >= 2:
        return "val=%d" % _s16(operand)
    if label == "LitI4" and len(operand) >= 4:
        return "val=%d" % _s32(operand)
    if label.startswith("Branch") and len(operand) >= 2:
        displacement = _s16(operand)
        return "to=%08X" % (branch_base + displacement)
    if label in ("ForI2", "NextI2", "ForStepI2", "NextStepI2") and len(operand) >= 4:
        displacement = _s16(operand[2:])
        # operand[0:2] 是 For/Next 共享的逐循环隐藏控制槽（帧内临时），
        # 不是用户循环变量——真正的循环变量是 For 指令前压栈的 FLdRfVar
        # （start 与 end 之间），由 stack_ir._loop_start 从栈上取出使用。
        # 实证：pub_176 两个循环同用变量 i(-136)，控制槽却分别为 -160/-178；
        # 且每对 For/Next 操作数首字一致（pub_126: 72FF/72FF 等）。
        return "ctl=stack%+d to=%08X" % (
            _s16(operand), branch_base + displacement)
    if label in ("LitVarI2",) and len(operand) >= 4:
        return "mem=stack%+d val=%d" % (_s16(operand), _s16(operand[2:]))
    if label == "CVarRef" and len(operand) >= 4:
        return "mem=stack%+d type=%04X" % (_s16(operand), _u16(operand[2:]))
    if label.startswith(("FFree1", "AryLock", "AryUnlock", "CVarI2", "CVarStr",
                         "CVarR4", "AddVar", "EqVar")) and len(operand) >= 2:
        return "mem=stack%+d" % _s16(operand)
    if label in ("LdFixedStr", "StFixedStr", "CopyBytes") and len(operand) >= 2:
        return "len=%d" % _u16(operand)
    if label == "Gosub" and len(operand) >= 2:
        return "to=%08X" % (branch_base + _s16(operand))
    if label.startswith(("FLd", "FSt", "ILd", "ISt", "PopTmp")):
        if len(operand) >= 2:
            offset = _s16(operand)
            text = "stack%+d" % offset
            if len(operand) >= 4:
                text += ".f%04X" % _u16(operand[2:])
            return "mem=" + text
    if label.startswith("FMem") and len(operand) >= 4:
        return "mem=stack%+d.f%04X" % (
            _s16(operand), _u16(operand[2:]))
    if label.startswith("Mem") and len(operand) >= 2:
        text = "mem=%04X" % _u16(operand)
        if len(operand) >= 4:
            text += ".a%04X" % _u16(operand[2:])
        return text
    if not operand:
        return "-"
    if len(operand) == 2:
        return "u16=%04X" % _u16(operand)
    if len(operand) == 4:
        return "u32=%08X" % int.from_bytes(operand, "little")
    return operand.hex(" ").upper()


# ---------------------------------------------------------------------------
# Per-parameter ByRef/ByVal classification.
# ---------------------------------------------------------------------------
# A procedure's incoming argument slots are the positive frame offsets
# (stack+12, +16, +20, ...; stack+8 is the implicit Me/object base).  The
# opcode family the callee uses reveals whether a slot holds ByRef or ByVal:
#   - I* / indirect family (ILdI2, ILdI4, IStI2, IStI4, ...) dereferences
#     THROUGH the pointer stored in the slot: it reads/writes the caller's
#     variable.  That is the ByRef calling convention.
#   - F* / direct family (FLdI2, FLdI4, FStI2, FStI4, FLdR*, FLdUI1, ...)
#     accesses the frame slot directly (a local copy / ByVal Long value).
#   - reference-pushing ops (FLdRfVar / CVarRef / ImpAdLdRf / ...) push the
#     slot's address to forward a reference onward: also ByRef.
# Handlers in VB40032.DLL confirm the semantics, e.g.:
#   IStI2 (0x0422): mov eax,[ebp+off]; mov [eax],bx     -> indirect store
#   ILdI2 (0x0402): mov eax,[ebp+off]; mov ax,[eax]      -> indirect load
#   FLdI2 (0x03A2): mov ax,[eax+ebp]                    -> direct load
#   FStI2 (0x03C2): mov [eax+ebp],bx                    -> direct store
#   FLdRfVar (0x03B8): push ebp+off                     -> push address
_INDIRECT_PREFIXES = ("ILd", "ISt",)
_REF_OPS = frozenset({
    "FLdRfVar", "FLdRf", "CVarRef", "FLdZeroAd",
    "PopTmpLdAd2", "PopTmpLdAd4", "PopTmpLdAdStr", "PopTmpLdAd1",
    "ImpAdLdRf", "ImpAdLdPr", "FMemLdRf", "FMemLdRfVar",
})
_PARAM_SLOT = re.compile(r"mem=stack\+(\d+)")


def classify_params(ops):
    """Classify a procedure's parameter slots as ByRef/ByVal.

    ``ops`` is an iterable of ``(label, operand)`` pairs decoded from the
    procedure body.  Returns ``(nargs, kinds)`` where ``nargs`` is the number
    of parameters and ``kinds`` is a list of ``"ByRef"``/``"ByVal"`` strings
    indexed by parameter position (kinds[0] corresponds to a0 / stack+12).

    A slot is ByRef when any indirect (I*) or reference-pushing op touches
    it; otherwise (only direct F* frame access / untouched) it is ByVal.
    """
    slots = {}
    for label, operand in ops:
        m = _PARAM_SLOT.search(operand or "")
        if not m:
            continue
        n = int(m.group(1))
        if n >= 12 and (n - 8) % 4 == 0:
            slots.setdefault(n, set()).add(label)
    maxarg = max(((n - 12) // 4 + 1 for n in slots), default=0)
    kinds = []
    for i in range(maxarg):
        labels = slots.get(12 + 4 * i, set())
        indirect = any(lb.startswith(_INDIRECT_PREFIXES) for lb in labels)
        referenced = bool(labels & _REF_OPS)
        kinds.append("ByRef" if (indirect or referenced) else "ByVal")
    return maxarg, kinds


def format_proc(pal, analysis, index, name):
    """Render one procedure from the recovered word boundary path."""
    start, end, path = analysis["paths"][index]
    entries = analysis["entries"]
    labels = analysis["labels"]
    out = ["=" * 70]
    entry = analysis["method_stubs"].get(end)
    if entry:
        stub, entry_adjust = entry
        entry_text = "  entry=MethCallEngine stub=0x%08X entry_adjust=0x%X" % (
            stub, entry_adjust)
    else:
        entry_text = ""
    out.append("%s  ProcDsc=0x%08X  ProcSize=0x%X  codeStart=0x%08X%s" %
               (name, end, end - start, start, entry_text))
    out.append("=" * 70)

    # Decode every instruction once, then classify params from the body.
    decoded = []
    for pos, opcode, size, fallback in path:
        raw = pal.bytes_at(pos, size)
        target = entries.get(opcode, 0)
        label = labels.get(target, "<no CodeView label>")
        if label.startswith("lblEX_"):
            label = label[len("lblEX_"):]
        display_label = "LitI2" if label == "LitI2_10" else label
        operand = special_operand(opcode, raw)
        if operand is None:
            operand = format_operand(
                opcode, label, raw, start,  # per-proc branch base
                analysis["stub_names"], analysis["declares"], pal)
        byte_hex = raw.hex(" ").upper()
        decoded.append((pos, byte_hex, display_label, operand))

    nargs, kinds = classify_params([(d[2], d[3]) for d in decoded])
    if nargs:
        out.append("; params (%d): %s" % (
            nargs, ", ".join("%s a%d" % (k, i)
                              for i, k in enumerate(kinds))))

    decls = analysis.get("decls")
    for pos, byte_hex, display_label, operand in decoded:
        line = "%08X  %-24s %s  %s" % (
            pos, byte_hex, display_label, operand)
        if decls is not None:
            note = decls.annotate_operand(operand)
            if note:
                line += "  ; " + note
        out.append(line)
    return "\n".join(out)
