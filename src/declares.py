"""External Declare table + PE-import resolution (Stage 4).

The VB4 Declare table (78 entries, 12 bytes each) lives at file off 0xFAA0
(VA = ImageBase + .text.vaddr + (0xFAA0 - .text.raw)).  Each entry:
  +0x00 name_ptr (VA -> null-terminated ASCII function name)
  +0x04 sig_off  (unused for naming)
  +0x08 lib_ptr  (VA -> null-terminated UTF-16LE library name)
We build a VA -> "lib.func" map used by the disassembler's %x operand
(ImpAdCall* external calls).

This bypasses Semi's ReturnApiCall indirect-jump dance (File32(lAddress+12)...)
because the Declare table structure is already known and direct.

VB40032 is imported BY ORDINAL (e.g. #100 = ThunRTMain), so PE by-name
resolution can't name those calls.  We read VB40032.dll's own export
directory (declares.load_vb_runtime_dll) to get the ordinal->name map and
resolve ordinal imports to 'VB40032.<name>'.
"""
import pe as pemod


class Declares:
    def __init__(self, pe, declare_va, declare_count=78):
        self.pe = pe
        self.declare_va = declare_va
        self.va_map = {}      # call-site target VA -> "lib.func"
        self.entries = []     # parsed (name, lib) list
        self.vb_api = {}      # ordinal -> name (VB40032.dll, from DLL exports)
        self._parse_table(declare_va, declare_count)
        # merge PE by-name imports (Win32 APIs)
        for va, name in pe.imports.items():
            self.va_map[va] = name
        # resolve ordinal imports (VB40032 runtime calls); names arrive via
        # load_vb_runtime_dll(), before that they stay as "VB40032.#NNN"
        self._resolve_ordinal_imports()

    def _resolve_ordinal_imports(self):
        """Resolve PE ordinal imports via self.vb_api into self.va_map."""
        for va, (libname, ordinal) in self.pe.ordinal_imports.items():
            fname = self.vb_api.get(ordinal)
            if fname:
                self.va_map[va] = "%s.%s" % (libname, fname)
            else:
                self.va_map[va] = "%s.#%d" % (libname, ordinal)

    def load_vb_runtime_dll(self, dll_path):
        """Load VB40032.dll and resolve ordinal imports from its export table.

        Reads the DLL's own export directory (named exports only) to build
        the ordinal->name map, then (re)resolves all ordinal imports.
        """
        dll = pemod.PEImage(dll_path)
        self.vb_api = dict(dll.exports)
        self._resolve_ordinal_imports()

    def _parse_table(self, base_va, count):
        for i in range(count):
            va = base_va + i * 12
            name_ptr = self.pe.r32(va)
            sig_off = self.pe.r32(va + 4)
            lib_ptr = self.pe.r32(va + 8)
            if name_ptr == 0 and lib_ptr == 0:
                break
            if not self.pe.in_range(name_ptr):
                # past the real table -> stop
                break
            name = self.pe.cstr(name_ptr) if self.pe.in_range(name_ptr) else "<?>"
            lib = self.pe.wstr(lib_ptr) if self.pe.in_range(lib_ptr) else "<?>"
            self.entries.append((name, lib, name_ptr, lib_ptr, sig_off))

    def resolve(self, va):
        """Resolve an external-call target VA to 'lib.func', or None.

        Tries: (1) direct VA map (Declare/PE-import thunk entry-points),
        (2) if `va` is a `jmp [ptr]` (FF 25) thunk, follow the indirect
        pointer to the IAT slot and resolve that (by name or by ordinal via
        the VB40032.dll export table).
        """
        if va in self.va_map:
            return self.va_map[va]
        # FF 25 imm32  -> jmp dword ptr [imm32]; imm32 is the IAT slot VA
        if self.pe.in_range(va) and self.pe.r8(va) == 0xFF and self.pe.r8(va + 1) == 0x25:
            iat_va = self.pe.r32(va + 2)
            if iat_va in self.va_map:
                return self.va_map[iat_va]
        return None

    def resolve_by_sig(self, api_ref):
        """Resolve a VB4 ImpAdCall* api_ref (Declare signature-table offset)
        to 'lib.func', or None.

        VB4 has no constant pool: the u16 operand of ImpAdCall* is a direct
        offset into the Declare signature table.  Each Declare entry carries
        its own sig_off (sorted descending across the table); we pick the
        Declare with the largest sig_off <= api_ref.
        """
        if not self.entries:
            return None
        best = None
        for e in self.entries:
            so = e[4]
            if so <= api_ref and (best is None or so > best[4]):
                best = e
        if best is None:
            return None
        return "%s.%s" % (best[1], best[0])


def find_declare_table(pe):
    """Return (va, count) for the Declare table.

    Documented location: file off 0xFAA0.  Convert to VA via .text section.
    Count is determined by scanning until name_ptr==0 or out-of-range.
    """
    text = next((s for s in pe.sections if s.name == ".text"), None)
    if text is None:
        return None, 0
    rva = text.vaddr + (0xFAA0 - text.raw_off)
    va = pe.base + rva
    # count valid entries
    count = 0
    for i in range(256):
        name_ptr = pe.r32(va + i * 12)
        lib_ptr = pe.r32(va + i * 12 + 8)
        if name_ptr == 0 or not pe.in_range(name_ptr):
            break
        if lib_ptr == 0 or not pe.in_range(lib_ptr):
            break
        count += 1
    return va, count


# ---------------------------------------------------------------------------
# Style review #15: render the parsed table back out.
#
# Static ground truth (handler-verified): a Declare's sig_off is the offset
# of the function-pointer slot in the RUNTIME API table at [0x428004] --
# each call-site thunk is `mov edx,[0x428004]; add edx,<sig_off>;
# mov eax,[edx]; jmp eax`.  There is NO static parameter-type blob
# anywhere in PAL.EXE: parameter marshalling is compiled into the p-code
# call sites (typed pushes + inline CStr2Ansi conversions) and the return
# width into the ImpAdCall* variant.  So the Declare block below states
# name/lib/alias from the table, arity from the same spec table that
# drives strict arg collection, Function-vs-Sub from the call-site
# variant census (ImpAdCallAd => the site consumes a 4-byte result;
# plain ImpAdCall-only => Sub -- noting a Function called as a statement
# compiles to the void variant, so this is a lower bound), and per-param
# types from a corpus-wide push-label vote (unanimous or As Any).
# ---------------------------------------------------------------------------

# Push-label classes for the per-(declare, position) type vote.
_DECLARE_PUSH_TYPES = {
    # ByVal value pushes (label names the type).
    "LitI2": "Integer", "LitI2_10": "Integer", "FLdI2": "Integer",
    "ILdI2": "Integer", "FMemLdI2": "Integer", "ImpAdLdI2": "Integer",
    "LitI4": "Long", "FLdI4": "Long", "ILdI4": "Long",
    "FMemLdI4": "Long", "ImpAdLdI4": "Long", "FMemLd4": "Long",
    "ImpAdLd4": "Long", "LitVarI2": "Integer",
    "LitR4": "Single", "FLdR4": "Single", "FMemLdR4": "Single",
    "ImpAdLdR4": "Single",
    "LitR8": "Double", "FLdR8": "Double", "ILdR8": "Double",
    "FLdFPR4": "Single", "FLdFPR8": "Double",
    "FLdUI1": "Byte",
}
# pop1-push1 conversions: the delivered arg type is the conversion target.
_DECLARE_CONV_TYPES = {
    "CI4I2": "Integer", "CI2I4": "Long", "CBoolI4": "Long",
    "FnCSngUI1": "Single", "FnCSngI2": "Single", "FnCSngI4": "Single",
    "CR4Var": "Single", "CI4Var": "Long",
    "PopFPR4": "Single", "PopFPR8": "Double",
}
# Reference pushes: the argument is an lvalue's address (ByRef).
_DECLARE_REF_PUSHES = {
    "FLdRfVar", "FLdRf", "FMemLdRf", "FMemLdRfVar", "ImpAdLdRf",
    "FLdZeroAd", "Ary1LdRf", "AryLdRf", "Ary1LdPr",
    "PopTmpLdAd2", "PopTmpLdAd4",
}
# String delivery: ANSI-marshalled strings (ByVal String).
_DECLARE_STR_PUSHES = {
    "LitStr", "LitVarStr", "FLdStr", "ConcatStr", "CStrVarTmp",
}
# Opcodes with no eval-stack effect between the pushes and the call.
_DECLARE_SCAN_SKIP = {
    "ImpAdLdPr", "MemLdRf", "NewIfNullPr", "NewIfNullAd", "NewIfNullObj",
    "NewIfNullVar", "FStAdNoPop", "FLdPrThis", "FMemLdRf",
    "SetLastSystemError",
}


def _classify_push(label):
    """(kind, type) for one arg-delivery label, or None to abstain."""
    if label in _DECLARE_STR_PUSHES or label == "CStr2Ansi":
        return ("str", "String")
    if label in _DECLARE_CONV_TYPES:
        return ("val", _DECLARE_CONV_TYPES[label])
    if label in _DECLARE_PUSH_TYPES:
        return ("val", _DECLARE_PUSH_TYPES[label])
    if label in _DECLARE_REF_PUSHES:
        return ("ref", None)
    return None


def scan_declare_usage(analysis):
    """Vote per (lib.func, arg position) on the pushed argument type.

    Walks every decoded instruction stream backward from each external
    ImpAdCall* site: TOS is ARG1 (stdcall right-to-left push order, same
    collection order as stack_ir), so the k-th push found walking back is
    position k.  pop1-push1 conversions retarget the next counted push's
    type; CStr2Ansi delivers a ByVal String and consumes one extra source
    push; chain/plumbing no-effect opcodes are skipped.

    Returns {(lib, func, pos): (kind, type)} with kind in
    {"val", "str", "ref"} -- unanimous across sites, else ("any", None).
    """
    votes = {}
    entries = analysis["entries"]
    labels = analysis["labels"]

    def label_of(opcode):
        target = entries.get(opcode, 0)
        lab = labels.get(target, "")
        if lab.startswith("lblEX_"):
            lab = lab[len("lblEX_"):]
        if lab == "LitI2_10":
            lab = "LitI2"
        return lab

    import stack_ir
    import declare_specs
    for _start, _end, path in analysis["paths"]:
        n = len(path)
        for i in range(n):
            pos, opcode, _size, _fb = path[i]
            lab = label_of(opcode)
            if not lab.startswith("ImpAdCall"):
                continue
            # resolve the target name from the operand, as the disassembler
            # does: call=<name>@<thunk>
            text = _declare_call_text(analysis, pos, opcode, lab)
            if text is None:
                continue
            nargs = stack_ir.WIN32_SPECS.get(text)
            if nargs is None:
                nargs = declare_specs.DECLARE_SPECS.get(text)
            if not nargs:
                continue
            # walk backward collecting nargs deliveries
            deliveries = []
            j = i - 1
            pending_conv = None
            skip_source = 0
            while j >= 0 and len(deliveries) < nargs:
                blab = label_of(path[j][1])
                if blab in _DECLARE_SCAN_SKIP:
                    j -= 1
                    continue
                if blab in ("CStr2Ansi", "CStr2Uni"):
                    # The conversion stored its result in a frame temp; the
                    # temp load ALREADY counted above IS the delivery, so
                    # retro-type it as the ByVal String argument.  The
                    # conversion consumed the slot ref + the source push.
                    if deliveries and deliveries[-1][0] == "val":
                        deliveries[-1] = ("str", "String")
                    else:
                        deliveries.append(("str", "String"))
                    skip_source += 2
                    j -= 1
                    continue
                if blab in _DECLARE_CONV_TYPES and pending_conv is None:
                    pending_conv = _DECLARE_CONV_TYPES[blab]
                    j -= 1
                    continue
                cls = _classify_push(blab)
                if cls is None:
                    break  # unknown shape: stop, abstain the rest
                kind, typ = cls
                if pending_conv is not None:
                    kind, typ = "val", pending_conv
                    pending_conv = None
                if skip_source:
                    skip_source -= 1
                    j -= 1
                    continue
                deliveries.append((kind, typ))
                j -= 1
            if len(deliveries) < nargs:
                continue  # shape not a plain push run: abstain entirely
            for k, (kind, typ) in enumerate(deliveries):
                lib, _, func = text.partition(".")
                votes.setdefault((lib, func, k), []).append((kind, typ))
    out = {}
    for key, ballot in votes.items():
        kinds = {k for k, _t in ballot}
        types = {t for _k, t in ballot if t}
        if len(kinds) == 1 and len(types) <= 1:
            out[key] = (kinds.pop(), types.pop() if types else None)
        else:
            out[key] = ("any", None)
    return out


def _declare_call_text(analysis, pos, opcode, label):
    """Re-render the ImpAdCall* operand to 'lib.func' for one site."""
    # Reuse word_disasm.format_operand via a tiny shim: the operand bytes
    # are pal.bytes_at(pos, size).
    pal = analysis.get("pal")
    if pal is None:
        return None
    size = 2 + 4  # ImpAdCall* operands are a 4-byte thunk VA
    raw = pal.bytes_at(pos, size)
    import word_disasm
    operand = word_disasm.format_operand(
        opcode, label, raw, pos,
        analysis.get("stub_names"), analysis.get("declares"), pal)
    if operand and operand.startswith("call="):
        return operand[len("call="):].split("@")[0]
    return None


def declare_block_lines(dec, analysis):
    """VB4 Declare statement block (#15), one line per table entry.

    Order: as stored in the binary's table.  Names render lib-qualified
    (Pal.CopyMem) exactly like the call sites, so the remap layer renames
    both consistently; the Alias clause preserves the binary's own name.
    """
    votes = scan_declare_usage(analysis)
    import stack_ir
    import declare_specs

    # Function/Sub census from the call-site variant: any site whose
    # variant returns a value (ImpAdCallAd here) proves Function As Long.
    fn_kinds = {}
    entries = analysis["entries"]
    labels = analysis["labels"]
    pal = analysis.get("pal")
    if pal is not None:
        for _start, _end, path in analysis["paths"]:
            for pos, opcode, _size, _fb in path:
                target = entries.get(opcode, 0)
                lab = labels.get(target, "")
                if lab.startswith("lblEX_"):
                    lab = lab[len("lblEX_"):]
                if lab not in ("ImpAdCall", "ImpAdCallAd"):
                    continue
                text = _declare_call_text(analysis, pos, opcode, lab)
                if text:
                    fn_kinds.setdefault(text, set()).add(lab)

    lines = ["' ---- Declare table (0x%08X, %d entries) ----"
             % (dec.declare_va if hasattr(dec, "declare_va") else 0,
                len(dec.entries)),
             "' Return width is compiled into each call site (ImpAdCall*"
             " variant);", "' no static signature blob exists in the binary"
             " (sig_off = runtime", "' API-slot offset, handler-verified)."]
    seen = set()
    for name, lib, _np, _lp, sig in dec.entries:
        qual = "%s.%s" % (lib, name)
        if qual in seen:
            # duplicate table rows (same name, different sig slots)
            continue
        seen.add(qual)
        variants = fn_kinds.get(qual, set())
        is_func = any(v != "ImpAdCall" for v in variants)
        nargs = stack_ir.WIN32_SPECS.get(qual)
        if nargs is None:
            nargs = declare_specs.DECLARE_SPECS.get(qual)
        params = []
        for k in range(nargs or 0):
            kind, typ = votes.get((lib, name, k), ("any", None))
            if kind == "ref":
                params.append("ByRef a%d As Any" % k)
            elif kind in ("val", "str") and typ:
                params.append("ByVal a%d As %s" % (k, typ))
            else:
                params.append("ByVal a%d As Any" % k)
        head = "Declare Function %s" if is_func else "Declare Sub %s"
        text = head % qual + ' Lib "%s" Alias "%s" ' % (lib, name)
        text += "(%s)" % ", ".join(params)
        if is_func:
            # ImpAdCallAd sites consume the result as a 4-byte value.
            text += " As Long"
        lines.append(text)
    return lines


def table_dump_lines(dec):
    """Raw Declare-table dump for the disassembly output (#15)."""
    lines = ["==== Declares (Declare table) ====",
             "%-6s %-28s %-8s %-10s %s" % (
                 "idx", "name", "lib", "sig_off", "name_ptr/lib_ptr")]
    for i, (name, lib, nptr, lptr, sig) in enumerate(dec.entries):
        lines.append("%-6d %-28s %-8s 0x%08X  %08X/%08X" % (
            i, name, lib, sig, nptr, lptr))
    return lines
