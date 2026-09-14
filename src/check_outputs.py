#!/usr/bin/env python3
"""Verify generated PAL text files against recorded SHA-256 hashes."""

import argparse
import hashlib
import json
from pathlib import Path


PROJECT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = PROJECT / "out"
DEFAULT_HASHES = PROJECT / "input" / "output_hashes.json"
OUTPUT_FILES = ("pal_disasm.txt", "pal_pseudocode.txt", "pal_code.txt")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Check generated PAL output hashes.")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--hashes", type=Path, default=DEFAULT_HASHES)
    parser.add_argument("--update", action="store_true",
                        help="replace recorded hashes with the current output")
    return parser.parse_args(argv)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv=None):
    args = parse_args(argv)
    if args.update:
        files = {}
        for name in OUTPUT_FILES:
            path = args.out_dir / name
            if not path.is_file():
                raise SystemExit("missing %s" % path)
            files[name] = sha256(path)
        args.hashes.write_text(
            json.dumps({"algorithm": "sha256", "files": files}, indent=2) + "\n",
            encoding="utf-8")
        print("Updated %s" % args.hashes)
        return

    expected = json.loads(args.hashes.read_text(encoding="utf-8"))
    failures = []
    for name, want in expected["files"].items():
        path = args.out_dir / name
        if not path.is_file():
            failures.append("missing %s" % path)
            continue
        got = sha256(path)
        if got != want:
            failures.append("%s: expected %s, got %s" % (name, want, got))
        else:
            print("PASS %-24s %s" % (name, got))
    if failures:
        for failure in failures:
            print("FAIL " + failure)
        raise SystemExit(1)
    print("All output hashes match.")


if __name__ == "__main__":
    main()
