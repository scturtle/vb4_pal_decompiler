"""
VB4 ProcDsc (CodeInfo) locator and reader.

Empirically validated on PAL.EXE and the Microsoft CALLDLLS32 VB4-32 PCode
sample (from JellyBins.Instances).  Both share the same ProcDsc layout, which
differs from the field labels in Semi's modPCode4.bas.

ProcDscInfo layout (30 bytes), all little-endian words:
    +0x00  word   varies  (0x04..0x1C)  -- NOT `table` (modPCode4 mislabel)
    +0x02  word   FrameSize (0..0x144)
    +0x04  word   ProcSize  (0x08..0x671E)  -- p-code byte length
    +0x06  word   varies (0x1C..0x44)
    +0x08  8 bytes  ALL ZERO  (signature anchor)
    +0x10  word   varies (0x0C..0x34)
    +0x12  word   ZERO
    +0x14..+0x19  small/zero
    +0x1A  word   varies
    +0x1C  word   varies

Proc layout:  [ p-code code (ProcSize bytes) ][ ProcDscInfo (30 bytes) ]
    pc = ProcDsc_addr - ProcSize
    code ends exactly at ProcDsc_addr.

Signature used to locate ProcDsc by scanning (no table lookup):
    +0x08..+0x0F == 0          (8 zero bytes)
    word@+0x04 (ProcSize) in [0x08, 0x6800]
    word@+0x06           in [0x1C, 0x48]
    word@+0x12 == 0
    word@+0x18 == 0

On PAL.EXE this yields 197 ProcDscs, zero overlap, covering pc range
0x403190-0x41D56C (~103 KB of p-code, 74% of the region).  All 41 inline
strings (5E 07) fall inside a located proc (was 20/41 with ExitProc splitting).

NOTE: ExitProc opcodes (0x13..0x18) are NOT procedure ends -- a single proc
may contain several ExitProcs (early-exit / error handlers).  The proc end is
the ProcDsc boundary.  Using ExitProc to split inflates the proc count (PAL
showed 653; real ~197).
"""

# ProcDsc signature constraints
PROC_SIZE_MIN = 0x08
PROC_SIZE_MAX = 0x6800
W6_MIN = 0x1C
W6_MAX = 0x48
PROCDSC_SIZE = 30

# PAL.EXE scan regions (shared by main.py / word_probe / word_disasm so the
# p-code and native-stub scans agree on one set of bounds).
#   p-code region:  proc bodies + their trailing ProcDsc.
#   stub region:    native entry thunks (push proc desc -> ProcCallEngine /
#                   MethCallEngine), slightly below the p-code region.
PAL_START = 0x403000
PAL_END = 0x428000
STUB_START = 0x401000
STUB_END = 0x427000


def is_proc_dsc(pe, va):
    """Return ProcSize if `va` looks like a ProcDsc start, else 0."""
    if not pe.in_range(va) or not pe.in_range(va + PROCDSC_SIZE):
        return 0
    # +8..+0F : 8 zero bytes
    if pe.r32(va + 0x08) != 0 or pe.r32(va + 0x0C) != 0:
        return 0
    if pe.r16(va + 0x12) != 0 or pe.r16(va + 0x18) != 0:
        return 0
    procsize = pe.r16(va + 0x04)
    if not (PROC_SIZE_MIN <= procsize <= PROC_SIZE_MAX):
        return 0
    w6 = pe.r16(va + 0x06)
    if not (W6_MIN <= w6 <= W6_MAX):
        return 0
    # pc must be in range
    pc = va - procsize
    if not pe.in_range(pc) or not pe.in_range(va - 1):
        return 0
    return procsize


def find_procs(pe, lo, hi):
    """Scan [lo, hi) for ProcDsc signatures.

    Returns a sorted list of (pc, proc_dsc_addr, proc_size) tuples with no
    overlap.  A located proc occupies [pc, proc_dsc_addr).
    """
    found = []
    va = lo
    while va < hi:
        psz = is_proc_dsc(pe, va)
        if psz:
            found.append((va - psz, va, psz))
            va += PROCDSC_SIZE
        else:
            va += 1
    found.sort()
    # Drop overlapping ones (keep earliest); empirically zero overlaps on PAL.
    out = []
    last_end = -1
    for pc, pd, psz in found:
        if pc >= last_end:
            out.append((pc, pd, psz))
            last_end = pd
    return out


def find_stubs_pal(pe, lo=0x401000, hi=0x427000):
    """Locate PAL native entry thunks that load a ProcDsc address.

    Stub form: 5A A1 00 80 42 00 8D 88 00 00 00 00 51 52 BA <ProcDsc u32> E9
    Returns list of (stub_va, proc_dsc_va).
    """
    stubs = []
    va = lo
    while va < hi:
        if (pe.r8(va) == 0x5A and pe.r8(va + 1) == 0xA1
                and pe.r8(va + 6) == 0x8D and pe.r8(va + 7) == 0x88
                and pe.r8(va + 0x0E) == 0xBA and pe.r8(va + 0x13) == 0xE9):
            pd = pe.r32(va + 0x0F)
            stubs.append((va, pd))
            va += 0x14
        else:
            va += 1
    return stubs


def find_stubs_calldlls32(pe, lo=0x401000, hi=0x407000):
    """Locate CALLDLLS32-style native entry thunks.

    Stub form: 33 C9 BA <ProcDsc u32> A1 <mem u32> E9 <rel32>
    Returns list of (stub_va, proc_dsc_va).
    """
    stubs = []
    va = lo
    while va < hi:
        if (pe.r8(va) == 0x33 and pe.r8(va + 1) == 0xC9
                and pe.r8(va + 2) == 0xBA and pe.r8(va + 7) == 0xA1
                and pe.r8(va + 12) == 0xE9):
            stubs.append((va, pe.r32(va + 3)))
            va += 13
        else:
            va += 1
    return stubs


def find_method_stubs(pe, lo=STUB_START, hi=STUB_END):
    """Locate PAL callbacks that enter VB40032.MethCallEngine.

    Private/event procedures use a different native stub from public p-code
    procedures: mov ecx,entry_adjust; cmp ax,...; mov edx,ProcDsc;
    mov eax,[obj]; jmp [MethCallEngine].  Return {ProcDsc: (stub, adjust)}.
    """
    out = {}
    va = lo
    while va + 0x1D < hi:
        if (pe.r8(va) == 0xB9 and pe.r8(va + 5) == 0x66
                and pe.r8(va + 6) == 0x3D and pe.r8(va + 9) == 0xBA
                and pe.r8(va + 14) == 0xA1 and pe.r8(va + 19) == 0xE9):
            entry_adjust = pe.r32(va + 1)
            proc_dsc = pe.r32(va + 10)
            out[proc_dsc] = (va, entry_adjust)
            va += 0x19
        else:
            va += 1
    return out


def stubs_to_procs(pe, lo, hi):
    """Return {proc_dsc_va: stub_va} for whichever stub form is present.

    Tries PAL form first, then CALDLLS32 form.
    """
    out = {}
    for sva, pd in find_stubs_pal(pe, lo, hi):
        out[pd] = sva
    if not out:
        for sva, pd in find_stubs_calldlls32(pe, lo, hi):
            out[pd] = sva
    return out
