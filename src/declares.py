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
