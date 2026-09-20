"""VB4 窗体模块声明流（declaration stream）解析。

VB4 把窗体/模块级变量的声明（数组的真实边界）静态存放在 EXE 的声明流里。
PAL.EXE 只有一个窗体模块（Pal.frm），其声明流位于 .text 的
0x00401A7C（长度 0xBC0，74 条记录），实例数据区 0x878 字节。

流头（12 字节）::

    u16 len          流长度（0x0BC0）
    u16 data_size    窗体实例数据区大小（0x0878；含内联描述符槽位）
    u16 n1           记录数（74）
    u16 n2           73
    u16 0            0
    u16 0xFF8C       0xFF8C

记录自 +0xC 开始，``[tag{u16 字段偏移, u16 kind}]``：

- ``kind=0x0005`` 固定数组：12 字节头（非初值/名字线索，尾部字节偶有变化）
  + 归零的 SAFEARRAY 描述符模板
  ``{u16 cDims, u16 flags=0x12(STATIC|FIXEDSIZE), u32 cbElements,
  u32 cLocks=0, u32 pvData=0, 每维 {u32 cElements, u32 lbound}}``；
- ``kind=0x0105`` 动态数组（tag + 6 字节 payload，运行期 ReDim 定界）；
- ``kind=0x0004`` 对象引用（tag + 6 字节 payload）。

标量字段没有记录；相邻字段偏移相减得到的只是描述符槽位大小
（1D=0x18 / 2D=0x20 / 3D=0x28 字节），真正的元素个数在本流中。

描述符布局与维度顺序由 VB40032.DLL 的 ExDerefAry1/ExDerefAry handler
反汇编证实：``+0x00 cDims, +0x02 flags, +0x04 cbElements, +0x0C pvData,
+0x10 起每维 {cElements, lbound}``；元素地址 = idx1 + idx2*bounds[1].cE
（列主序），先弹出的下标对 bounds[0] —— 即描述符 bounds[0] 对应源码里
**最后**一个下标，渲染 VB Dim 时按逆序还原。

元素类型无法只靠描述符区分（cbE=4 可能是 Long/Single/UDT；cbE=8 可能是
Double/UDT），由使用侧 opcode 推断：FMemLdRf 之后紧跟 Ary1Ld/Ary1St 的
标量后缀（I2/UI1/R4/...）给出标量元素类型；Ary*Pr/Rf 之后紧跟 MemLd/St
时，字段偏移 >0 说明元素是 UDT；紧跟 LdFixedStr 说明是定长字符串。
"""
import struct

KIND_FIXED = 0x0005
KIND_DYNAMIC = 0x0105
KIND_OBJECT = 0x0004

DEFAULT_STREAM_VA = 0x00401A7C

# Ary1Ld*/Ary1St* 直接标量元素访问的标签后缀。
_SCALAR_SUFFIX = {
    "I2": "Integer", "I4": "Long", "UI1": "Byte",
    "R4": "Single", "R8": "Double", "Cy": "Currency",
}

# Ary*Pr/Rf 之后紧跟的 MemLd*/MemSt* 标签 → 标量类型（元素仅 +0 字段时）。
_MEM_SCALAR = {
    "MemLdI2": "Integer", "MemStI2": "Integer",
    "MemLdI4": "Long", "MemStI4": "Long",
    "MemLdUI1": "Byte", "MemStUI1": "Byte",
    "MemLdR4": "Single", "MemStR4": "Single",
    "MemLdR8": "Double", "MemStR8": "Double",
    "MemLdCy": "Currency", "MemStCy": "Currency",
}

# 使用侧证据缺失时按 cbElements 的保守回退（String*N 等 UDT 形态除外）。
_CB_ELEMENTS_FALLBACK = {1: "Byte", 2: "Integer", 4: "Long", 8: "Double"}


class FieldDecl(object):
    """单条声明记录。"""

    def __init__(self, off, kind, head=None, c_dims=0, flags=0,
                 cb_elements=0, dims=None, payload=""):
        self.off = off
        self.kind = kind
        self.head = head or ""
        self.c_dims = c_dims
        self.flags = flags
        self.cb_elements = cb_elements
        self.dims = dims or []          # [(cElements, lbound), ...] 描述符顺序
        self.payload = payload          # kind 0x0105 / 0x0004 的 6 字节 hex
        self.elem_type = None           # resolve_types() 之后有效

    @property
    def name(self):
        return "Me.f%04X" % self.off

    def vb_bounds(self):
        """VB 源码顺序的边界串；描述符 bounds[0] 是源码最后一个下标。"""
        parts = ["%d To %d" % (lb, lb + ce - 1)
                 for ce, lb in reversed(self.dims)]
        return ", ".join(parts)

    def total_elements(self):
        n = 1
        for ce, _lb in self.dims:
            n *= ce
        return n


class DeclStream(object):
    """一个窗体模块的声明流解析结果。"""

    def __init__(self, va, length, data_size, records):
        self.va = va
        self.length = length
        self.data_size = data_size
        self.records = records
        self.by_offset = dict((r.off, r) for r in records)

    # -- 类型解析 -----------------------------------------------------------

    def resolve_types(self, usage):
        """usage = scan_element_usage() 的结果；None 时全部走回退。"""
        for rec in self.records:
            if rec.kind != KIND_FIXED:
                continue
            rec.elem_type = self._elem_type(rec, usage)

    @staticmethod
    def _elem_type(rec, usage):
        u = (usage or {}).get(rec.off)
        if u:
            fixed_str = u.get("fixed_str")
            if fixed_str:
                return "String * %d" % fixed_str
            mems = u.get("mem") or set()
            if mems:
                offsets = set(o for o, _l in mems)
                if offsets - set([0]):
                    # 元素内多个字段 → UDT（字段名由 struct_fields 映射）。
                    return "UDT(%d B)" % rec.cb_elements
                types = set(_MEM_SCALAR[l] for _o, l in mems
                            if l in _MEM_SCALAR)
                if len(types) == 1:
                    return types.pop()
            direct = set()
            for label in u.get("ary") or ():
                for suf, t in _SCALAR_SUFFIX.items():
                    if (label.startswith(("Ary1Ld", "Ary1St"))
                            and label.endswith(suf)):
                        direct.add(t)
            if len(direct) == 1:
                return direct.pop()
        return _CB_ELEMENTS_FALLBACK.get(
            rec.cb_elements, "UDT(%d B)" % rec.cb_elements)

    # -- 渲染 ---------------------------------------------------------------

    def decl_block_lines(self):
        """pal_pseudocode.txt 顶部的模块级声明块（VB 风格 Dim）。"""
        lines = [
            "' " + "-" * 74,
            "' 模块级声明（VB4 声明流 @ 0x%08X，%d 条记录，实例数据区 0x%X 字节）"
            % (self.va, len(self.records), self.data_size),
            "' 数组边界来自 EXE 内嵌 SAFEARRAY 描述符模板（src/decl_stream.py）；",
            "' kind=0x0005 固定数组 / 0x0105 动态数组（运行期 ReDim）/ 0x0004 对象引用。",
            "' 描述符 bounds[0] 对应源码最后一个下标（ExDerefAry 列主序），此处已按源码顺序还原。",
            "' 元素类型由访问 opcode 推断（Ary1Ld/St 后缀、MemLd/St 字段偏移、LdFixedStr）。",
            "' " + "-" * 74,
        ]
        for rec in self.records:
            if rec.kind == KIND_FIXED:
                lines.append("Dim %s(%s) As %s"
                             % (rec.name, rec.vb_bounds(), rec.elem_type))
            elif rec.kind == KIND_DYNAMIC:
                lines.append("Dim %s() ' 动态数组（kind=0x0105，payload=%s，"
                             "运行期 ReDim 定界）" % (rec.name, rec.payload))
            elif rec.kind == KIND_OBJECT:
                lines.append("Dim %s ' 对象引用（kind=0x0004，payload=%s）"
                             % (rec.name, rec.payload))
        lines.append("")
        return lines

    def table_lines(self):
        """pal_disasm.txt 头部的技术表格。"""
        lines = [
            "Module-level declarations (VB4 declaration stream @ 0x%08X)"
            % self.va,
            "  stream len=0x%X instance_data=0x%X records=%d"
            % (self.length, self.data_size, len(self.records)),
            "  kinds: 0x0005=fixed array, 0x0105=dynamic array, 0x0004=object ref",
            "  descriptor template: {cDims, flags=0x12, cbElements, cLocks=0,",
            "    pvData=0, per-dim {cElements, lbound}}; bounds[0] is the LAST",
            "    source subscript (column-major, per ExDerefAry pop order).",
            "  +off    kind    type            bounds (source order)              elements",
        ]
        for rec in self.records:
            if rec.kind == KIND_FIXED:
                lines.append("  +0x%04X %-7s %-16s %-34s %d x %d B"
                             % (rec.off, "Array", rec.elem_type,
                                "(%s)" % rec.vb_bounds(),
                                rec.total_elements(), rec.cb_elements))
            elif rec.kind == KIND_DYNAMIC:
                lines.append("  +0x%04X %-7s payload=%s (ReDim at runtime)"
                             % (rec.off, "Dyn", rec.payload))
            elif rec.kind == KIND_OBJECT:
                lines.append("  +0x%04X %-7s payload=%s"
                             % (rec.off, "ObjRef", rec.payload))
        return lines

    def annotate_operand(self, operand):
        """为 `mem=stack+8.fXXXX`（Me 字段）返回声明注释，无则 None。"""
        prefix = "mem=stack+8.f"
        if not operand.startswith(prefix):
            return None
        hexoff = operand[len(prefix):len(prefix) + 4]
        if len(hexoff) < 4:
            return None
        try:
            off = int(hexoff, 16)
        except ValueError:
            return None
        rec = self.by_offset.get(off)
        if rec is None:
            return None
        if rec.kind == KIND_FIXED:
            return "%s(%s)" % (rec.elem_type, rec.vb_bounds())
        if rec.kind == KIND_DYNAMIC:
            return "dynamic array (ReDim at runtime)"
        if rec.kind == KIND_OBJECT:
            return "object reference"
        return None


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------

def _parse_at(pe, va):
    """严格解析 va 处的声明流；结构不符返回 None。"""
    try:
        head = pe.bytes_at(va, 12)
        length = struct.unpack_from("<H", head, 0)[0]
        data_size = struct.unpack_from("<H", head, 2)[0]
        n_records = struct.unpack_from("<H", head, 4)[0]
    except Exception:
        return None
    if not (0x40 <= length <= 0x2000 and length % 2 == 0):
        return None
    if not (0x40 <= data_size <= 0x10000):
        return None
    if not (1 <= n_records <= 0x400):
        return None
    try:
        b = pe.bytes_at(va, length)
    except Exception:
        return None

    def u16(p):
        return struct.unpack_from("<H", b, p)[0]

    def u32(p):
        return struct.unpack_from("<I", b, p)[0]

    pos = 0xC
    records = []
    last_off = -1
    while pos < length - 4:
        off, kind = u16(pos), u16(pos + 2)
        pos += 4
        if off <= last_off or off >= data_size:
            return None
        last_off = off
        if kind == KIND_FIXED:
            if pos + 12 + 4 + 4 + 8 > length:
                return None
            head12 = b[pos:pos + 12].hex()
            pos += 12
            c_dims, flags = u16(pos), u16(pos + 2)
            pos += 4
            if not (1 <= c_dims <= 8):
                return None
            cb_elements = u32(pos)
            pos += 4
            if not (1 <= cb_elements <= 0x10000):
                return None
            if u32(pos) != 0 or u32(pos + 4) != 0:  # cLocks / pvData 模板恒 0
                return None
            pos += 8
            dims = []
            for _ in range(c_dims):
                if pos + 8 > length:
                    return None
                c_elements, lbound = u32(pos), u32(pos + 4)
                if not (1 <= c_elements <= 0x100000) or abs(lbound) > 0x100000:
                    return None
                dims.append((c_elements, lbound))
                pos += 8
            records.append(FieldDecl(off, kind, head=head12, c_dims=c_dims,
                                     flags=flags, cb_elements=cb_elements,
                                     dims=dims))
        elif kind in (KIND_DYNAMIC, KIND_OBJECT):
            if pos + 6 > length:
                return None
            payload = b[pos:pos + 6].hex()
            pos += 6
            records.append(FieldDecl(off, kind, payload=payload))
        else:
            return None
    if pos != length or len(records) != n_records:
        return None
    return DeclStream(va, length, data_size, records)


def find_stream(pe):
    """在 .text 里扫描并验证声明流；找到返回 DeclStream，否则 None。"""
    found = []
    for sec in pe.sections:
        if sec.name != ".text":
            continue
        va = pe.base + sec.vaddr
        end = va + sec.vsize - 12
        while va < end:
            if 0x40 <= pe.r16(va) <= 0x2000 and (pe.r16(va) & 1) == 0:
                stream = _parse_at(pe, va)
                if stream is not None:
                    found.append(stream)
            va += 2
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        # 位置歧义：优先已知 VA。
        for stream in found:
            if stream.va == DEFAULT_STREAM_VA:
                return stream
    return None


def load(pe, va=None):
    """解析声明流；va 缺省先试已知 VA，再全文扫描。"""
    for candidate in [va or DEFAULT_STREAM_VA]:
        if candidate:
            stream = _parse_at(pe, candidate)
            if stream is not None:
                return stream
    return find_stream(pe)


# ---------------------------------------------------------------------------
# 使用侧元素类型扫描
# ---------------------------------------------------------------------------

def scan_element_usage(pal, analysis):
    """扫描全部过程，收集每个 Me.fXXXX 数组字段的元素访问证据。

    返回 {field_off: {"ary": {label,...}, "mem": {(offset,label),...},
    "fixed_str": n}}。模式（均为相邻指令）：

    - ``FMemLdRf mem=stack+8.fXXXX`` 之后紧跟 ``Ary1Ld*/Ary1St*``（直接
      标量元素访问）或 ``Ary*Pr/Rf``（元素引用）；
    - ``Ary*Pr/Rf`` 之后紧跟 ``MemLd*/MemSt*``（元素内字段访问，mem=XXXX
      是字段偏移）或 ``LdFixedStr/StFixedStr``（定长字符串元素）。
    """
    import word_disasm

    entries = analysis["entries"]
    labels = analysis["labels"]

    def label_of(opcode):
        target = entries.get(opcode, 0)
        label = labels.get(target, "")
        if label.startswith("lblEX_"):
            label = label[len("lblEX_"):]
        if label == "LitI2_10":
            label = "LitI2"
        return label

    usage = {}
    for start, end, path in analysis["paths"]:
        decoded = []
        for pos, opcode, size, _fallback in path:
            label = label_of(opcode)
            raw = pal.bytes_at(pos, size)
            operand = word_disasm.special_operand(opcode, raw)
            if operand is None:
                operand = word_disasm.format_operand(
                    opcode, label, raw, start,
                    analysis["stub_names"], analysis["declares"], pal)
            decoded.append((label, operand))
        for i in range(len(decoded) - 1):
            operand = decoded[i][1]
            nxt = decoded[i + 1][0]
            if not operand.startswith("mem=stack+8.f"):
                continue
            if not nxt.startswith(("Ary1Ld", "Ary1St", "AryLd", "ArySt")):
                continue
            try:
                off = int(operand[14:18], 16)
            except ValueError:
                continue
            slot = usage.setdefault(off, {"ary": set(), "mem": set(),
                                          "fixed_str": 0})
            slot["ary"].add(nxt)
            if not (nxt.endswith(("Pr", "Rf")) and i + 2 < len(decoded)):
                continue
            label2, operand2 = decoded[i + 2]
            if label2.startswith("Mem") and operand2.startswith("mem="):
                try:
                    mem_off = int(operand2[4:8], 16)
                except ValueError:
                    continue
                slot["mem"].add((mem_off, label2))
            elif label2 in ("LdFixedStr", "StFixedStr") and \
                    operand2.startswith("len="):
                try:
                    slot["fixed_str"] = max(
                        slot["fixed_str"], int(operand2.split("len=")[1]))
                except ValueError:
                    pass
    return usage
