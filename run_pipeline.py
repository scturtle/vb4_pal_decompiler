#!/usr/bin/env python3
"""Run the complete PAL.EXE -> pal_code.txt decompilation pipeline."""

import argparse
import subprocess
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parent
DEFAULT_EXE = PROJECT / "input" / "PAL.EXE"
DEFAULT_VB4DLL = PROJECT / "input" / "VB40032.DLL"
DEFAULT_MAPPING = PROJECT / "input" / "mapping.json"
DEFAULT_HASHES = PROJECT / "input" / "output_hashes.json"
DEFAULT_OUT = PROJECT / "out"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Decompile a VB4 p-code executable into readable VB-style code.")
    parser.add_argument("--exe", type=Path, default=DEFAULT_EXE,
                        help="input PAL executable (default: input/PAL.EXE)")
    parser.add_argument("--vb4dll", type=Path, default=DEFAULT_VB4DLL,
                        help="VB4 runtime DLL (default: input/VB40032.DLL)")
    parser.add_argument("--mapping", type=Path, default=DEFAULT_MAPPING,
                        help="readable-name mapping (default: input/mapping.json)")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT,
                        help="output directory (default: out)")
    parser.add_argument("--hashes", type=Path, default=DEFAULT_HASHES,
                        help="expected output hashes (default: input/output_hashes.json)")
    return parser.parse_args(argv)


def require_file(path):
    if not path.is_file():
        raise SystemExit("required input not found: %s" % path)


def run(command):
    print("+ %s" % " ".join(str(part) for part in command), flush=True)
    subprocess.run(command, check=True, cwd=PROJECT)


def main(argv=None):
    args = parse_args(argv)
    exe = args.exe.resolve()
    vb4dll = args.vb4dll.resolve()
    mapping = args.mapping.resolve()
    hashes = args.hashes.resolve()
    out_dir = args.out_dir.resolve()
    for path in (exe, vb4dll, mapping, hashes):
        require_file(path)
    out_dir.mkdir(parents=True, exist_ok=True)

    run([
        sys.executable,
        str(PROJECT / "src" / "main.py"),
        str(exe),
        "--vb4dll", str(vb4dll),
        "--out-dir", str(out_dir),
    ])
    run([
        sys.executable,
        str(PROJECT / "src" / "remap.py"),
        str(mapping),
        str(out_dir / "pal_pseudocode.txt"),
        str(out_dir / "pal_code.txt"),
    ])
    run([
        sys.executable,
        str(PROJECT / "src" / "check_outputs.py"),
        "--out-dir", str(out_dir),
        "--hashes", str(hashes),
    ])
    print("完成: %s" % (out_dir / "pal_code.txt"))


if __name__ == "__main__":
    main()
