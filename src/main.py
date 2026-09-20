"""PAL.EXE VB4 p-code disassembler - entry point.

Pipeline:
  1. Load PE (pe.py).
  2. Parse VB4 header (vb4_header.py) for project metadata (forms, exe name).
  3. Build external-call resolver (declares.py): Declare table + PE imports
     + VB40032.dll exports (VB40032 ordinal imports).
  4. Enumerate VB4 procedures via ProcDsc signature scan (proc_dsc.find_procs):
     each proc is [pc, ProcDsc_addr) with pc = ProcDsc_addr - ProcSize.
  5. Render pal_disasm.txt from VB40032's word-pcode dispatcher and CodeView
     handler labels.
"""
import argparse
import os
import sys

import pe as pemod
import vb4_header
import declares
import proc_dsc
from proc_dsc import PAL_END, PAL_START, STUB_END, STUB_START
import naming
import word_disasm
import pseudo_code
import decl_stream


# Paths are relative to the standalone project, not the caller's cwd.
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
DEFAULT_EXE = os.path.join(PROJECT, "input", "PAL.EXE")
DEFAULT_VB4DLL = os.path.join(PROJECT, "input", "VB40032.DLL")
DEFAULT_OUTDIR = os.path.join(PROJECT, "out")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Disassemble PAL.EXE VB4 word-pcode and emit VB-style pseudocode.")
    parser.add_argument("exe", nargs="?", default=DEFAULT_EXE,
                        help="PAL.EXE path (default: input/PAL.EXE)")
    parser.add_argument("--vb4dll", default=DEFAULT_VB4DLL,
                        help="VB40032.DLL path (default: input/VB40032.DLL)")
    parser.add_argument("--out-dir", default=DEFAULT_OUTDIR,
                        help="output directory (default: out)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    exe = os.path.abspath(args.exe)
    vb4dll = os.path.abspath(args.vb4dll)
    outdir = os.path.abspath(args.out_dir)
    print("Loading PE: %s" % exe)
    img = pemod.PEImage(exe)

    # VB4 header / project metadata
    a_sub_main = 0
    try:
        hdr_va = vb4_header.find_header_va(img)
        if hdr_va:
            hdr = vb4_header.VB4Header(img, hdr_va)
            a_sub_main = getattr(hdr, "a_sub_main", 0)
            print("VB4 header VA: 0x%08X  exe=%r project=%r forms=%d  aSubMain=0x%08X" % (
                hdr_va, getattr(hdr, "exe_name", ""),
                getattr(hdr, "project_title", ""),
                getattr(hdr, "form_count", 0), a_sub_main))
    except Exception as e:
        print("VB4 header parse skipped: %s" % e)

    # External calls
    dec_va, dec_count = declares.find_declare_table(img)
    dec = declares.Declares(img, dec_va, dec_count)
    dec.load_vb_runtime_dll(vb4dll)
    print("Declare table @0x%08X (%d entries); resolved %d VAs" % (
        dec_va, dec_count, len(dec.va_map)))

    # Enumerate procedures via ProcDsc signature scan (precise boundaries).
    raw = proc_dsc.find_procs(img, PAL_START, PAL_END)
    # Native entry stubs -> ProcDsc (names entry-point procs).
    stub_map = proc_dsc.stubs_to_procs(img, STUB_START, STUB_END)
    # C3: structural procedure naming (Sub Main / pub / priv).
    procs = naming.name_procs(
        img, raw, stub_map, a_sub_main, PAL_START, PAL_END)
    print("Procedures (ProcDsc scan): %d  (entry stubs: %d)" % (
        len(procs), len(stub_map)))
    print(naming.summarize(
        raw, stub_map, a_sub_main,
        naming.build_call_counts(
            img, set(stub_map.values()), PAL_START, PAL_END)))

    os.makedirs(outdir, exist_ok=True)
    out_path = os.path.join(outdir, "pal_disasm.txt")
    # The runtime-facing view uses VB40032's 16-bit threaded dispatcher and
    # CodeView labels.
    word_vb = pemod.PEImage(vb4dll)
    # Word ImpAdCall operands point at PAL's native entry stubs.  Associate
    # those addresses with the named ProcDsc targets to retain the call graph.
    stub_names = {}
    for _ps, pd, proc_name in procs:
        stub = stub_map.get(pd)
        if stub is not None:
            stub_names[stub] = proc_name
    analysis = word_disasm.analyze(
        word_vb, img, stub_names=stub_names, declares=dec)

    # VB4 声明流：模块级数组的真实边界（内嵌 SAFEARRAY 描述符模板）。
    decls = decl_stream.load(img)
    if decls is not None:
        decls.resolve_types(decl_stream.scan_element_usage(img, analysis))
        analysis["decls"] = decls
        print("Declaration stream @0x%08X: %d records, instance data 0x%X" % (
            decls.va, len(decls.records), decls.data_size))
    else:
        print("Declaration stream: not found; module declarations omitted")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("VB4 word-pcode disassembly (VB40032 threaded dispatch)\n")
        f.write("Procedures: %d\n" % len(procs))
        f.write("Dispatch table: 0x%08X\n" % analysis["table"])
        f.write("CodeView engine labels: %d\n" % len(analysis["labels"]))
        f.write("Word opcode entries: %d\n" % len(analysis["entries"]))
        if decls is not None:
            f.write("\n")
            f.write("\n".join(decls.table_lines()))
        f.write("\n\n")
        for idx, (_start, _end, _path) in enumerate(analysis["paths"]):
            f.write(word_disasm.format_proc(
                img, analysis, idx, procs[idx][2]))
            f.write("\n\n")
    print("Wrote %s" % out_path)
    print("Word procedures rendered: %d / %d" %
          (len(analysis["paths"]), len(procs)))

    # Convert the structured word analysis to VB-style pseudocode.
    pseudo_path = os.path.join(outdir, "pal_pseudocode.txt")
    with open(pseudo_path, "w", encoding="utf-8") as f:
        if decls is not None:
            f.write("\n".join(decls.decl_block_lines()))
            f.write("\n")
        f.write(pseudo_code.decompile_all(img, analysis, procs))
    print("Wrote %s" % pseudo_path)


if __name__ == "__main__":
    main()
