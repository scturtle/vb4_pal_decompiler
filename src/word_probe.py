"""Exploratory VB4 word-pcode boundary probe.

This is deliberately separate from disasm.py.  VB40032 dispatches 16-bit
opcode words and threaded handlers consume the next opcode themselves.  The
probe uses handler CFGs to collect likely ESI advances, then chooses a path
that reaches each ProcDsc boundary.  It is evidence for boundary recovery,
not yet a complete semantic decoder.
"""
import collections
import functools
import struct
import sys
from pathlib import Path

import capstone
import pefile

from pe import PEImage
from proc_dsc import PAL_END, PAL_START, find_procs
ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "input"

# These PAL opcodes dispatch straight to an ExitProc/End runtime handler.
# The handler returns to the native caller rather than doing the usual next
# word dispatch, so handler_deltas() has no sequential tail to discover.
TERMINATOR_OPCODES = {
    0x02BC,  # ExitProcHresult
    0x0370,  # End
    0x037A,  # ExitProcI2
    0x037C,  # ExitProcStr variant
    0x0386,  # ExitProcStr variant
    0x038A,  # ExitProcStr
}

# Word opcodes with inline variable-length operands.  These are modeled in
# decode_proc() for boundary recovery and in word_disasm.special_operand()
# for rendering; the shared constants keep the two in sync.
OP_GETRECOWNER3 = 0x02D4   # [payload_offset:i16] then resume
OP_ARYLDPR = 0x02FC        # AryLdPr: [descriptor:u16]
OP_ARYLDRF = 0x02FE        # AryLdRf: [descriptor:u16]
OP_FFREEVAR = 0x0744       # FFreeVar: [count:u16][count frame offsets]
OP_FFREESTR = 0x0746       # FFreeStr: same layout
OP_LITVARSTR = 0x076C      # [byteLen:u16][offset:i16][UTF-16 text]
OP_LITSTR = 0x075E         # [index:u16][byteLen:u32][UTF-16 text][term:u16]
OP_BRANCH = 0x03E6         # unconditional Branch: [disp:i16]
OP_NEWIFNULL_RF = 0x05CA   # NewIfNullRf: [descriptor:u32]
OP_NEWIFNULL_AD = 0x05CC   # NewIfNullAd: [descriptor:u32]
OP_NEWIFNULL_PR = 0x05CE   # NewIfNullPr: [descriptor:u32]


S_LABEL32 = 0x0209


def load_engine_labels(vb, engine_start):
    """Return {VA: name} for engine.obj6 CodeView label records."""
    data = vb.data
    marker = data.find(b"engine.obj6")
    if marker < 0:
        return {}
    record = data.find(b"\x16\x00\x09\x02", marker)
    if record < 0:
        return {}

    labels = {}
    pos = record
    while pos + 4 <= len(data):
        length, record_type = struct.unpack_from("<HH", data, pos)
        end = pos + 2 + length
        if length < 2 or end > len(data) or length > 0x400:
            break
        if record_type == S_LABEL32 and length >= 12:
            offset = struct.unpack_from("<I", data, pos + 4)[0]
            segment = struct.unpack_from("<H", data, pos + 8)[0]
            name = data[pos + 12:end].split(b"\0", 1)[0]
            if segment == 2 and name:
                labels[engine_start + offset] = name.decode(
                    "latin1", "replace")
        pos = end
    return labels


def engine_bounds(vb):
    """Return the VA interval of the ENGINE section."""
    section = next(s for s in vb.sections if s.name == "ENGINE")
    return vb.base + section.vaddr, vb.base + section.vaddr + section.vsize


def find_dispatch_table(vb, engine_start, engine_end):
    """Find the word-dispatch table from an indexed JMP in ENGINE."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    raw = vb.bytes_at(engine_start, engine_end - engine_start)
    for ins in md.disasm(raw, engine_start):
        if ins.mnemonic != "jmp" or not ins.operands:
            continue
        mem = ins.operands[0]
        if mem.type != capstone.x86.X86_OP_MEM:
            continue
        address = mem.mem
        if address.base or address.index != capstone.x86.X86_REG_EAX or address.scale != 2:
            continue
        table = address.disp
        targets = [vb.r32(table + opcode * 2) for opcode in (0, 2, 4, 6)]
        if all(engine_start <= target < engine_end for target in targets):
            return table
    raise RuntimeError("VB4 word dispatch table not found")


def load_word_table(vb, table, engine_start, engine_end):
    """Return encoded word opcode -> handler VA for the main dispatcher."""
    out = {}
    for opcode in range(0, 0x2000, 2):
        target = vb.r32(table + opcode * 2)
        if engine_start <= target < engine_end:
            out[opcode] = target
        elif out:
            # The real table is contiguous and is followed by zero/data.
            break
    return out


def handler_deltas(vb, handler, table, engine_end, ins_cache):
    """Find ESI advances before threaded re-dispatches from one handler.

    The handler receives ESI immediately after its own 2-byte opcode.  Its
    terminal dispatch reads the next opcode and generally advances ESI again.
    The resulting add/sub value is therefore the byte distance to the next
    opcode boundary in the file stream.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    def instruction(va):
        if va not in ins_cache:
            raw = vb.bytes_at(va, min(16, vb.hi - va))
            decoded = list(md.disasm(raw, va))
            if decoded:
                ins_cache[va] = decoded[0]
        return ins_cache.get(va)

    queue = [(handler, 0)]
    seen = set()
    deltas = set()
    while queue and len(seen) < 1000:
        va, delta = queue.pop()
        state = (va, delta)
        if state in seen:
            continue
        seen.add(state)
        ins = instruction(va)
        if ins is None:
            continue
        text = ins.op_str.lower()
        if ins.mnemonic == "jmp" and ("%x" % table) in text:
            deltas.add(delta)
            continue
        if ins.mnemonic == "ret":
            continue

        new_delta = delta
        if ins.mnemonic in ("add", "sub") and ins.op_str.startswith("esi, "):
            try:
                value = int(ins.op_str.split(",", 1)[1], 0)
                new_delta += value if ins.mnemonic == "add" else -value
            except ValueError:
                pass

        if ins.mnemonic.startswith("j"):
            if ins.mnemonic != "jmp":
                queue.append((va + ins.size, new_delta))
            if ins.operands[0].type == capstone.x86.X86_OP_IMM:
                target = ins.operands[0].imm
                # Backedges are runtime-counted loops over operands.  The
                # forward path still exposes the normal re-dispatch tail;
                # following the backedge would make static analysis diverge.
                if ins.mnemonic == "jmp" or target > va:
                    queue.append((target, new_delta))
        elif ins.mnemonic != "jmp":
            queue.append((va + ins.size, new_delta))
    return tuple(sorted(d for d in deltas if d > 0))


def decode_proc(pal, table, candidates, start, end):
    """Choose a candidate-size path ending exactly at ProcDsc."""
    best = {end: (0, [])}
    for pos in range(end - 2, start - 2, -2):
        opcode = pal.r16(pos)
        sizes = list(candidates.get(opcode, ()))
        if opcode in TERMINATOR_OPCODES:
            # ExitProc/End return to native code; their p-code encoding is
            # the opcode word alone and has no threaded-dispatch tail.
            sizes = [2]
        elif opcode == OP_BRANCH and pos + 4 <= end:
            # Unconditional Branch consumes its signed word displacement.
            # Its handler jumps directly to the target and therefore does not
            # expose the usual sequential ESI delta in handler_deltas().
            sizes = [4]
        elif opcode in (OP_ARYLDPR, OP_ARYLDRF) and pos + 4 <= end:
            # AryLdPr/AryLdRf pass a word element/type descriptor to the
            # helper before dispatching the following opcode.
            sizes = [4]
        elif opcode == OP_GETRECOWNER3 and pos + 4 <= end:
            # GetRecOwner3 skips a signed inline record-owner payload and
            # resumes dispatch at start + 4 + payload offset.
            payload_offset = int.from_bytes(
                pal.bytes_at(pos + 2, 2), "little", signed=True)
            if payload_offset >= 0 and pos + 4 + payload_offset <= end:
                sizes = [payload_offset + 4]
        elif opcode in (OP_FFREEVAR, OP_FFREESTR) and pos + 4 <= end:
            # FFreeVar/FFreeStr read a byte count, divide it by two, and loop
            # over that many 16-bit frame offsets.  The count is the payload
            # size before the following opcode.
            payload_size = pal.r16(pos + 2)
            sizes = [payload_size + 4]
        elif opcode in (OP_NEWIFNULL_RF, OP_NEWIFNULL_AD, OP_NEWIFNULL_PR) and pos + 6 <= end:
            # NewIfNull{Rf,Ad,Pr} passes the dword at ESI to the allocator,
            # then dispatches the word at ESI+4.
            sizes = [6]
        elif opcode == OP_LITVARSTR and pos + 4 <= end:
            # LitVarStr is inline.  Its handler reads a word byte-count at
            # ESI, stores the text pointer, then resumes at opcode position
            # (start + 4 + byte_count).
            byte_length = pal.r16(pos + 2)
            sizes = [byte_length + 4]
        elif opcode == OP_LITSTR and pos + 8 <= end:
            # LitStr is inline: [opcode][index][byte length][UTF-16 data]
            # followed by a two-byte terminator.
            byte_length = pal.r32(pos + 4)
            sizes = [byte_length + 10]
        sizes = [s for s in sizes if s >= 2 and pos + s <= end]
        fallback = not sizes
        if fallback and pos + 2 <= end:
            sizes = [2]
        choices = []
        for size in sizes:
            tail = best.get(pos + size)
            if tail is None:
                continue
            score, path = tail
            score += 1 - (10 if fallback else 0)
            choices.append((score, [(pos, opcode, size, fallback)] + path))
        if choices:
            best[pos] = max(choices, key=lambda item: item[0])
    return best.get(start, (-10**9, []))


def main():
    vb = PEImage(str(INPUT / "VB40032.DLL"))
    pal = PEImage(str(INPUT / "PAL.EXE"))
    engine_start, engine_end = engine_bounds(vb)
    table = find_dispatch_table(vb, engine_start, engine_end)
    table_entries = load_word_table(vb, table, engine_start, engine_end)
    labels = load_engine_labels(vb, engine_start)
    cache = {}
    candidates = {}
    for opcode, handler in table_entries.items():
        if engine_start <= handler < engine_end:
            candidates[opcode] = handler_deltas(
                vb, handler, table, engine_end, cache)

    procs = find_procs(pal, PAL_START, PAL_END)
    paths = []
    for start, end, _size in procs:
        score, path = decode_proc(pal, table_entries, candidates, start, end)
        paths.append((score, path, start, end))

    rows = [row for _score, path, _start, _end in paths for row in path]
    fallback = [row for row in rows if row[3]]
    ff = [row for row in rows if row[1] & 0xFF == 0xFF]
    sizes = collections.Counter(row[2] for row in rows)
    known_opcode_counts = collections.Counter(
        row[1] for row in rows if not row[3])
    named_targets = sum(target in labels for target in table_entries.values())
    print("CodeView engine labels:", len(labels))
    print("table entries with exact labels:", named_targets, "/", len(table_entries))
    print("dispatch table:", "0x%08X" % table)
    print("procedures:", len(procs))
    print("word rows:", len(rows))
    print("paths reaching ProcDsc:", sum(bool(path) for _s, path, _a, _b in paths))
    print("fallback rows:", len(fallback))
    print("opcode boundary low-byte FF:", len(ff))
    print("instruction sizes:", dict(sorted(sizes.items())))
    print("common labeled word opcodes:")
    for opcode, count in known_opcode_counts.most_common(12):
        target = table_entries.get(opcode, 0)
        print("  %04X %-24s %d" %
              (opcode, labels.get(target, "<internal>"), count))

    for score, path, start, end in paths:
        if start == 0x403324:
            print("example:", hex(start), "..", hex(end), "score", score)
            for pos, opcode, size, used_fallback in path:
                mark = " fallback" if used_fallback else ""
                print("  %08X  %04X  size=%d%s" %
                      (pos, opcode, size, mark))
            break


if __name__ == "__main__":
    main()
