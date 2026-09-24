"""
struct_types.py — UDT 字段类型推断与 Type 声明渲染

VB4 p-code 里结构体（UDT）字段访问固定为三段式（相邻指令）::

    FMemLdRf  mem=stack+8.fXXXX  ; UDT(30 B)(0 To 4)   ← 模块级数组引用
    Ary1LdPr / AryLdPr descriptor=N                    ← 取元素引用
    MemLdI2  mem=0012                                   ← 元素内字段访问

``Mem*`` 的标量后缀给出字段类型（I2=Integer、UI1=Byte、R4=Single、
I4=Long、R8=Double、Cy=Currency）；``MemLdRf`` 只取字段地址传 ByRef，不
给出类型。字段访问证据由 decl_stream.scan_element_usage() 在分析阶段
收集；本模块据此推断每个 UDT 的字段表（无证据字段默认 Integer，与元素
大小的空洞补 fXXXX 占位），在 pal_pseudocode.txt 声明块里渲染为槽位级
匿名类型 ``UDT_fXXXX``。remap 阶段（pal_code.txt）只做名称替换：
``UDT_fXXXX`` → 帕斯卡结构体名（to_pascal）、``fXXXX`` → struct_fields
语义字段名。
"""

from collections import Counter

# MemLd*/MemSt* 标签 → VB 标量类型（MemLdRf 除外：只取地址传 ByRef）。
MEM_SCALAR_TYPE = {
    "MemLdI2": "Integer", "MemStI2": "Integer",
    "MemLdI4": "Long", "MemStI4": "Long",
    "MemLdUI1": "Byte", "MemStUI1": "Byte",
    "MemLdR4": "Single", "MemStR4": "Single",
    "MemLdR8": "Double", "MemStR8": "Double",
    "MemLdCy": "Currency", "MemStCy": "Currency",
}

# VB 标量类型的字节宽度（用于按元素大小补齐空洞字段）。
TYPE_SIZE = {
    "Integer": 2, "Long": 4, "Single": 4, "Double": 8, "Currency": 8,
    "Byte": 1,
}


def to_pascal(name):
    """snake_case/小驼峰 → 帕斯卡命名（首字母大写）。

    npc_display_data → NpcDisplayData；poison_status_struct →
    PoisonStatusStruct；playerExp → PlayerExp。
    """
    return "".join(p[:1].upper() + p[1:] for p in name.split("_") if p)


def field_type(labels):
    """把一个字段的访问标签集合（可迭代）解析成 VB 类型。

    有标量后缀证据（MemLd/StI2 等）时取证据类型；只有 MemLdRf（取地址
    传 ByRef）或无证据时默认 Integer。类型冲突时按出现次数取众数，平票
    时按固定顺序保证稳定输出。
    """
    types = Counter()
    for label in labels:
        vb_type = MEM_SCALAR_TYPE.get(label)
        if vb_type is not None:
            types[vb_type] += 1
    if not types:
        return "Integer"
    if len(types) == 1:
        return types.most_common(1)[0][0]
    order = {t: i for i, t in enumerate(
        ("Integer", "Long", "Single", "Double", "Byte", "Currency"))}
    return sorted(types.items(), key=lambda kv: (-kv[1], order[kv[0]]))[0][0]


def build_udt_fields(size, mem_pairs):
    """由字段访问证据 + 元素大小推断 UDT 字段表。

    mem_pairs: {(字段偏移, 访问标签)} 集合（scan_element_usage 的
    ``mem``）。返回按偏移升序的 [(offset, "fXXXX", vb_type)]；无证据的
    空洞按 2 字节 Integer 补占位，剩余 1 字节补 Byte（末尾才可能出现）。
    """
    by_offset = {}
    for offset, label in mem_pairs:
        by_offset.setdefault(offset, []).append(label)
    fields = [(offset, "f%04X" % offset, field_type(labels))
              for offset, labels in sorted(by_offset.items())]
    return _fill_gaps(fields, size)


def _fill_gaps(fields, size):
    """按元素大小补齐未覆盖的偏移空洞，生成 fXXXX 占位字段。

    fields: [(offset, name, vb_type)]，须按 offset 升序且互不重叠。
    """
    result = []
    next_off = 0
    for offset, name, vb_type in fields:
        while next_off < offset:
            if offset - next_off == 1:
                result.append((next_off, "f%04X" % next_off, "Byte"))
                next_off += 1
            else:
                result.append((next_off, "f%04X" % next_off, "Integer"))
                next_off += 2
        result.append((offset, name, vb_type))
        next_off = offset + TYPE_SIZE.get(vb_type, 2)
    if size is not None:
        while next_off < size:
            if size - next_off == 1:
                result.append((next_off, "f%04X" % next_off, "Byte"))
                next_off += 1
            else:
                result.append((next_off, "f%04X" % next_off, "Integer"))
                next_off += 2
    return result


def type_block_lines(name, fields):
    """渲染 VB ``Type ... End Type`` 声明块。"""
    lines = ["Type %s" % name]
    for _offset, fname, vb_type in fields:
        lines.append("    %s As %s" % (fname, vb_type))
    lines.append("End Type")
    return lines
