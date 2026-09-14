"""PE loader: flatten all sections into a VA-addressed image.

Port of LoadPE2 (modPCode.bas:389) plus the PE/section parsing from
modPeSkeleton.bas.  After load, `pe[va]` returns the byte at virtual address
`va`, and r16/r32/cstr/wstr read little-endian integers and strings by VA.
"""
import struct

IMAGE_DIRECTORY_ENTRY_EXPORT = 0   # index of Export Table in DataDirectory
IMAGE_DIRECTORY_ENTRY_IMPORT = 1  # index of Import Table in DataDirectory


class Section:
    __slots__ = ("name", "vaddr", "vsize", "raw_off", "raw_size", "flags")

    def __init__(self, name, vaddr, vsize, raw_off, raw_size, flags):
        self.name = name
        self.vaddr = vaddr        # VirtualAddress (RVA)
        self.vsize = vsize        # VirtualSize
        self.raw_off = raw_off    # PointerToRawData
        self.raw_size = raw_size  # SizeOfRawData

    def rva_to_off(self, rva):
        if self.vaddr <= rva < self.vaddr + max(self.vsize, self.raw_size):
            return self.raw_off + (rva - self.vaddr)
        return None


class PEImage:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        self._parse()
        self._build_image()
        self._load_imports()
        self._load_exports()

    # ---- parsing -------------------------------------------------------
    def _parse(self):
        d = self.data
        if d[:2] != b"MZ":
            raise ValueError("not an MZ image")
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if d[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("not a PE image")
        # COFF header
        coff = e_lfanew + 4
        num_sections = struct.unpack_from("<H", d, coff + 2)[0]
        size_of_opt = struct.unpack_from("<H", d, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic != 0x10b:
            raise ValueError("only PE32 (32-bit) supported")
        self.image_base = struct.unpack_from("<I", d, opt + 28)[0]
        self.entry_point = struct.unpack_from("<I", d, opt + 16)[0]
        # DataDirectory array starts at opt + 96 for PE32
        self.num_rvas_off = opt + 92
        num_rvas = struct.unpack_from("<I", d, opt + 92)[0]
        self.data_dirs = []
        for i in range(num_rvas):
            rva, size = struct.unpack_from("<II", d, opt + 96 + i * 8)
            self.data_dirs.append((rva, size))
        # Section table
        sec_off = opt + size_of_opt
        self.sections = []
        for i in range(num_sections):
            base = sec_off + i * 40
            name = d[base:base + 8].rstrip(b"\x00").decode("latin1")
            vsize, vaddr, raw_size, raw_off = struct.unpack_from("<IIII", d, base + 8)
            flags = struct.unpack_from("<I", d, base + 36)[0]
            self.sections.append(Section(name, vaddr, vsize, raw_off, raw_size, flags))

    def _build_image(self):
        base = self.image_base
        # total virtual size = max end across sections
        end = 0
        for s in self.sections:
            end = max(end, s.vaddr + s.vsize)
        self.pe_size = end
        # flat image keyed by VA (offset = VA - base)
        self.img = bytearray(end)
        for s in self.sections:
            if s.raw_size == 0:
                continue
            off = s.vaddr
            self.img[off:off + s.raw_size] = self.data[s.raw_off:s.raw_off + s.raw_size]
        self.base = base
        self.lo = base
        self.hi = base + end

    # ---- VA helpers -----------------------------------------------------
    def _idx(self, va):
        return va - self.base

    def in_range(self, va):
        return self.base <= va < self.hi

    def r8(self, va):
        return self.img[va - self.base]

    def r16(self, va):
        return struct.unpack_from("<H", self.img, va - self.base)[0]

    def r32(self, va):
        return struct.unpack_from("<I", self.img, va - self.base)[0]

    def cstr(self, va):
        """Null-terminated ASCII string (Semi FileZ)."""
        out = bytearray()
        i = va - self.base
        while i < len(self.img) and self.img[i] != 0:
            out.append(self.img[i])
            i += 1
        return out.decode("latin1")

    def wstr(self, va):
        """Null-terminated UTF-16LE string (Semi FileW)."""
        if va <= 0:
            return ""
        out = []
        i = va - self.base
        while i + 1 < len(self.img):
            ch = self.img[i] | (self.img[i + 1] << 8)
            if ch == 0:
                break
            out.append(ch)
            i += 2
        return "".join(chr(c) for c in out)

    def bytes_at(self, va, n):
        return bytes(self.img[va - self.base:va - self.base + n])

    def rva_to_off(self, rva):
        for s in self.sections:
            o = s.rva_to_off(rva)
            if o is not None:
                return o
        return None

    # ---- imports --------------------------------------------------------
    def _load_imports(self):
        """Read the PE import directory into self.imports: {va -> 'lib.func'}.

        Mirrors LoadPE2's ImpTab loop.  VB40032 is imported by ordinal in
        PAL.EXE so its names won't resolve here, but Win32 by-name imports
        will, which is what we need.
        """
        self.imports = {}
        self.ordinal_imports = {}  # IAT slot VA -> (libname, ordinal)
        if IMAGE_DIRECTORY_ENTRY_IMPORT >= len(self.data_dirs):
            return
        idata_rva, idata_size = self.data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT]
        if idata_rva == 0:
            return
        off = self.rva_to_off(idata_rva)
        if off is None:
            return
        d = self.data
        i = 0
        while True:
            base = off + i * 20
            if base + 20 > len(d):
                break
            lookup_rva, _, chain, name_rva, addr_rva = struct.unpack_from("<IIIII", d, base)
            if lookup_rva == 0 and name_rva == 0:
                break
            libname = self.cstr(self.base + name_rva) if name_rva else ""
            # walk the lookup/thunk table
            thunk_rva = lookup_rva if lookup_rva else addr_rva
            if thunk_rva:
                toff = self.rva_to_off(thunk_rva)
                slot_va = self.base + addr_rva
                j = 0
                while toff is not None and toff + 4 <= len(d):
                    entry = struct.unpack_from("<I", d, toff)[0]
                    if entry == 0:
                        break
                    if not (entry & 0x80000000):  # by name
                        hint_va = self.base + entry
                        fname = self.cstr(hint_va + 2)
                        self.imports[slot_va] = "%s.%s" % (libname, fname)
                    else:  # by ordinal
                        self.ordinal_imports[slot_va] = (libname, entry & 0xFFFF)
                    toff += 4
                    slot_va += 4
                    j += 1
            i += 1

    # ---- exports --------------------------------------------------------
    def _load_exports(self):
        """Read the PE export directory into self.exports: {ordinal -> name}.

        Only named exports are recorded.  Ordinal-only exports (no name)
        are skipped, since a name is required to resolve import-by-ordinal
        references in the importing image.  This lets us derive the
        VB40032.dll ordinal->name map directly from the DLL's own export
        table, instead of a hand-maintained vbXapi.txt file.
        """
        self.exports = {}
        if IMAGE_DIRECTORY_ENTRY_EXPORT >= len(self.data_dirs):
            return
        exp_rva, _ = self.data_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT]
        if exp_rva == 0:
            return
        off = self.rva_to_off(exp_rva)
        if off is None:
            return
        d = self.data
        # IMAGE_EXPORT_DIRECTORY: Base@+16, NumberOfNames@+24,
        # AddressOfNames@+32, AddressOfNameOrdinals@+36
        base_ord = struct.unpack_from("<I", d, off + 16)[0]
        n_names = struct.unpack_from("<I", d, off + 24)[0]
        names_rva = struct.unpack_from("<I", d, off + 32)[0]
        ords_rva = struct.unpack_from("<I", d, off + 36)[0]
        names_off = self.rva_to_off(names_rva)
        ords_off = self.rva_to_off(ords_rva)
        if names_off is None or ords_off is None:
            return
        for i in range(n_names):
            nrva = struct.unpack_from("<I", d, names_off + i * 4)[0]
            bias = struct.unpack_from("<H", d, ords_off + i * 2)[0]
            no = self.rva_to_off(nrva)
            if no is None:
                continue
            end = d.find(b"\x00", no)
            if end < 0:
                end = len(d)
            name = d[no:end].decode("latin1")
            if name:
                self.exports[base_ord + bias] = name
