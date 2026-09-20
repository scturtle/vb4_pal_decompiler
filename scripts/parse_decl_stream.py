"""解码 PAL.EXE 窗体模块的 VB4 声明流（declaration stream）。

用法: uv run python scripts/parse_decl_stream.py [--json] [--va 0x401A7C]

声明流的定位与记录格式见 ``src/decl_stream.py`` 模块文档。本脚本只解析
EXE（不做 p-code 使用侧扫描），元素类型走 cbElements 回退；流水线
（src/main.py）输出的类型带使用侧证据，更精确。
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
sys.path.insert(0, SRC)

import pe as pemod          # noqa: E402
import decl_stream          # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=os.path.join(
        os.path.dirname(HERE), "input", "PAL.EXE"))
    ap.add_argument("--va", type=lambda x: int(x, 0), default=None,
                    help="声明流 VA（缺省先试已知 VA，再全文扫描）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args()

    pe = pemod.PEImage(args.exe)
    stream = decl_stream.load(pe, args.va)
    if stream is None:
        raise SystemExit("declaration stream not found")

    names = {}
    mapping_path = os.path.join(os.path.dirname(HERE), "input", "mapping.json")
    if os.path.exists(mapping_path):
        names = json.load(open(mapping_path)).get("globals", {})

    stream.resolve_types(None)
    if args.json:
        recs = []
        for r in stream.records:
            recs.append({
                "offset": r.off, "name": names.get(r.name, r.name),
                "kind": r.kind, "cDims": r.c_dims, "flags": r.flags,
                "cbElements": r.cb_elements,
                "dims": [list(d) for d in r.dims],
                "vbBounds": r.vb_bounds(),
                "elemType": r.elem_type,
                "head": r.head, "payload": r.payload,
            })
        print(json.dumps({
            "va": stream.va, "length": stream.length,
            "data_size": stream.data_size, "records": recs,
        }, ensure_ascii=False, indent=1))
        return

    print("声明流 @ 0x%08X, len=0x%X, 实例数据区=0x%X, 记录=%d" % (
        stream.va, stream.length, stream.data_size, len(stream.records)))
    print("%-6s %-26s %-5s %-4s %-4s %-24s %s" % (
        "off", "name", "kind", "cDim", "cbE", "bounds(源码顺序)", "元素类型"))
    for r in stream.records:
        nm = names.get(r.name, "?")
        if r.kind == decl_stream.KIND_FIXED:
            print("0x%04X %-26s 5     %-4d %-4d %-24s %s x %d" % (
                r.off, nm, r.c_dims, r.cb_elements,
                "(%s)" % r.vb_bounds(), r.elem_type, r.total_elements()))
        else:
            print("0x%04X %-26s 0x%03X payload=%s" % (
                r.off, nm, r.kind, r.payload))


if __name__ == "__main__":
    main()
