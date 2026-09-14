"""Stable structural names for VB4 procedures."""

from collections import Counter


CALL_HOT = 8


def build_call_counts(pe, stub_va_set, pcode_lo, pcode_hi):
    """Count p-code references to native procedure-entry stubs."""
    counts = Counter()
    for offset in range(len(pe.img) - 3):
        target = int.from_bytes(pe.img[offset:offset + 4], "little")
        source_va = pe.base + offset
        if target in stub_va_set and pcode_lo <= source_va < pcode_hi:
            counts[target] += 1
    return counts


def name_procs(pe, raw_procs, stub_map, a_sub_main, pcode_lo, pcode_hi):
    """Return ``(code_start, proc_dsc, structural_name)`` procedure records."""
    counts = build_call_counts(pe, set(stub_map.values()), pcode_lo, pcode_hi)
    sub_main_pd = next(
        (pd for pd, stub in stub_map.items() if stub == a_sub_main), None)

    procs = []
    for index, (code_start, proc_dsc, _size) in enumerate(raw_procs):
        stub = stub_map.get(proc_dsc)
        if proc_dsc == sub_main_pd:
            name = "Sub_Main"
        elif stub:
            suffix = "_hot" if counts.get(stub, 0) >= CALL_HOT else ""
            name = "pub_%03d_%08X%s" % (index, code_start, suffix)
        else:
            name = "priv_%03d_%08X" % (index, code_start)
        procs.append((code_start, proc_dsc, name))
    return procs


def summarize(raw_procs, stub_map, a_sub_main, call_counts):
    """Return the procedure-naming summary printed by the main command."""
    sub_main_pd = next(
        (pd for pd, stub in stub_map.items() if stub == a_sub_main), None)
    public_count = sum(pd in stub_map for _pc, pd, _size in raw_procs)
    lines = [
        "Naming: Sub_Main = program entry (aSubMain -> thunk[0])",
        "        pub_NNN  = public (has native entry thunk)  [%d]" % public_count,
        "        priv_NNN = private helper (no thunk)        [%d]" %
        (len(raw_procs) - public_count),
    ]
    if sub_main_pd is not None:
        for index, (code_start, proc_dsc, _size) in enumerate(raw_procs):
            if proc_dsc == sub_main_pd:
                lines.append("        Sub Main = proc[%d] pc=0x%06X" %
                             (index, code_start))
                break
    lines.append("        _hot suffix = called from >= %d p-code sites" % CALL_HOT)
    return "\n".join(lines)
