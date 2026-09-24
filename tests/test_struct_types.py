"""Tests for struct_types / decl_stream / remap 的 UDT 推断与重命名分层。

数据结构在伪代码阶段推断（decl_stream.scan_element_usage 状态机 +
struct_types.build_udt_fields → 槽位级匿名类型 UDT_fXXXX 的 Type 块），
remap 阶段只做名称替换（remap_struct_decls）。

Run:  uv run python -m pytest tests/test_struct_types.py
  or: uv run python tests/test_struct_types.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import struct_types      # noqa: E402
import decl_stream       # noqa: E402
import remap             # noqa: E402


class ToPascalTests(unittest.TestCase):
    def test_snake_to_pascal(self):
        self.assertEqual(struct_types.to_pascal("npc_display_data"), "NpcDisplayData")
        self.assertEqual(struct_types.to_pascal("poison_status_struct"),
                         "PoisonStatusStruct")
        self.assertEqual(struct_types.to_pascal("enemy_pos_data"), "EnemyPosData")

    def test_camel_first_letter_uppercased(self):
        self.assertEqual(struct_types.to_pascal("playerExp"), "PlayerExp")
        self.assertEqual(struct_types.to_pascal("levelupMagic"), "LevelupMagic")


class FieldTypeTests(unittest.TestCase):
    def test_scalar_suffixes(self):
        self.assertEqual(struct_types.field_type(["MemLdI2", "MemStI2"]), "Integer")
        self.assertEqual(struct_types.field_type(["MemStUI1"]), "Byte")
        self.assertEqual(struct_types.field_type(["MemLdR4", "MemStR4"]), "Single")

    def test_ref_only_and_empty_default_integer(self):
        self.assertEqual(struct_types.field_type(["MemLdRf"]), "Integer")
        self.assertEqual(struct_types.field_type([]), "Integer")

    def test_conflict_majority(self):
        self.assertEqual(struct_types.field_type(
            ["MemLdI2", "MemLdI2", "MemLdR4"]), "Integer")


class BuildUdtFieldsTests(unittest.TestCase):
    def test_single_evidence_and_gap_absorbed(self):
        # playerExp 形态：f0000 是 Single（4 字节），offset 2 被其吸收，
        # f0004/f0006 为 Integer，总大小 8。
        fields = struct_types.build_udt_fields(
            8, {(0, "MemLdR4"), (0, "MemStR4"), (4, "MemStI2"), (6, "MemLdI2")})
        self.assertEqual(fields, [(0, "f0000", "Single"),
                                  (4, "f0004", "Integer"),
                                  (6, "f0006", "Integer")])

    def test_tail_gap_filled(self):
        # enemy_battle_data 形态：证据到 offset 0x1A，尾部 0x1C 补占位。
        mems = {(off, "MemLdI2") for off in range(0, 0x1B, 2)}
        fields = struct_types.build_udt_fields(30, mems)
        self.assertEqual(fields[-1], (0x1C, "f001C", "Integer"))
        self.assertEqual(len(fields), 15)
        self.assertEqual(sum(struct_types.TYPE_SIZE[t] for _o, _n, t in fields), 30)

    def test_no_evidence_all_placeholders(self):
        # battle_role_data_copy 形态：零证据，按元素大小生成占位字段。
        fields = struct_types.build_udt_fields(10, set())
        self.assertEqual(fields,
                         [(0, "f0000", "Integer"), (2, "f0002", "Integer"),
                          (4, "f0004", "Integer"), (6, "f0006", "Integer"),
                          (8, "f0008", "Integer")])


class ScanUsageTests(unittest.TestCase):
    def scan(self, seq):
        usage = {}
        decl_stream._scan_usage(seq, usage)
        return usage

    def test_fmem_chain(self):
        usage = self.scan([
            ("LitI2", "val=3"),                       # 下标压栈（不断链）
            ("FMemLdRf", "mem=stack+8.f05B4"),
            ("Ary1LdPr", "-"),
            ("MemLdI2", "mem=0002"),
            ("MemStI2", "mem=0002"),
        ])
        self.assertEqual(usage[0x5B4]["ary"], {"Ary1LdPr"})
        self.assertEqual(usage[0x5B4]["mem"],
                         {(2, "MemLdI2"), (2, "MemStI2")})

    def test_impad_base_normalized(self):
        usage = self.scan([
            ("ImpAdLdRf", "global=000003BC"),
            ("AryLdPr", "descriptor=0x0002"),
            ("MemStUI1", "mem=0000"),
        ])
        self.assertEqual(usage[0x3BC]["mem"], {(0, "MemStUI1")})

    def test_scalar_ary_consumes_ref(self):
        usage = self.scan([
            ("FMemLdRf", "mem=stack+8.f04DC"),
            ("Ary1LdI2", "-"),
            ("MemLdI2", "mem=0000"),    # 引用已被标量 load 消费，不得归属
        ])
        self.assertEqual(usage[0x4DC]["ary"], {"Ary1LdI2"})
        self.assertEqual(usage[0x4DC]["mem"], set())

    def test_ref_break_by_local_ref(self):
        usage = self.scan([
            ("FMemLdRf", "mem=stack+8.f05B4"),
            ("Ary1LdPr", "-"),
            ("FLdRfVar", "mem=stack-134"),
            ("MemStI2", "mem=0004"),
        ])
        # 槽位条目存在（Ary 已记录），但断链后的字段访问不归属它。
        self.assertEqual(usage[0x5B4]["ary"], {"Ary1LdPr"})
        self.assertEqual(usage[0x5B4]["mem"], set())

    def test_memldr_f_nested_stop(self):
        usage = self.scan([
            ("FMemLdRf", "mem=stack+8.f0824"),
            ("Ary1LdPr", "-"),
            ("MemLdRf", "mem=0000"),
            ("MemStI2", "mem=0002"),    # 嵌套引用内的访问，不归属外层
        ])
        self.assertEqual(usage[0x824]["mem"], {(0, "MemLdRf")})

    def test_fixed_str(self):
        usage = self.scan([
            ("FMemLdRf", "mem=stack+8.f0344"),
            ("Ary1LdPr", "-"),
            ("LdFixedStr", "len=10"),
        ])
        self.assertEqual(usage[0x344]["fixed_str"], 10)


class DeclBlockTests(unittest.TestCase):
    def _decls(self, recs, usage):
        ds = decl_stream.DeclStream(0x401A7C, 0xBC0, 0x878, recs)
        ds.usage = usage
        for rec in recs:
            rec.elem_type = decl_stream.DeclStream._elem_type(rec, usage)
        return ds

    def test_udt_type_block_emitted(self):
        rec = decl_stream.FieldDecl(
            0x374, decl_stream.KIND_FIXED, cb_elements=10, dims=[(12, 0)])
        usage = {0x374: {"ary": {"Ary1LdPr"}, "mem": {(8, "MemLdI2")}, "fixed_str": 0}}
        lines = self._decls([rec], usage).decl_block_lines()
        # UDT 元素展开为 Type 块 + 命名 As 子句。
        self.assertIn("Type UDT_f0374", lines)
        self.assertIn("    f0008 As Integer", lines)
        self.assertIn("End Type", lines)
        self.assertIn("Dim Me.f0374(0 To 11) As UDT_f0374", lines)

    def test_scalar_decl_unchanged(self):
        rec = decl_stream.FieldDecl(
            0x4DC, decl_stream.KIND_FIXED, cb_elements=2, dims=[(256, 0)])
        usage = {0x4DC: {"ary": {"Ary1LdI2"}, "mem": set(), "fixed_str": 0}}
        lines = self._decls([rec], usage).decl_block_lines()
        self.assertIn("Dim Me.f04DC(0 To 255) As Integer", lines)
        self.assertFalse([l for l in lines if l.startswith("Type ")])


MAPPING = {
    "globals": {"Me.f05B4": "enemy_battle_data",
                "Me.f0704": "poison_status",
                "Me.f0724": "enemy_poison_status",
                "Me.f0584": "battle_role_data_copy"},
    "var_to_struct": {"enemy_battle_data": "enemy_battle_data",
                      "poison_status": "poison_status_struct",
                      "enemy_poison_status": "poison_status_struct"},
    "struct_fields": {
        "enemy_battle_data": {"2": "x", "18": "hp"},
        "poison_status_struct": {"0": "poisonID", "2": "poisonScript"},
    },
}


def decl_lines(*blocks):
    """拼接声明块行：每个块是 (type块行们..., Dim 行)。"""
    out = []
    for block in blocks:
        out.extend(block)
    return [l + "\n" for l in out]


class RemapStructDeclsTests(unittest.TestCase):
    def test_rename_and_field_names(self):
        lines = decl_lines(
            ("Type UDT_f05B4",
             "    f0002 As Integer",
             "    f0012 As Integer",
             "    f001C As Integer",
             "End Type",
             "",
             "Dim enemy_battle_data(0 To 4) As UDT_f05B4"),
        )
        out = remap.remap_struct_decls(lines, MAPPING)
        self.assertEqual(out, [
            "Type EnemyBattleData\n",
            "    x As Integer\n",
            "    hp As Integer\n",
            "    f001C As Integer\n",     # 无命名的占位字段保持 fXXXX
            "End Type\n",
            "\n",
            "Dim enemy_battle_data(0 To 4) As EnemyBattleData\n",
        ])

    def test_shared_struct_dedup(self):
        lines = decl_lines(
            ("Type UDT_f0704",
             "    f0000 As Integer",
             "End Type",
             "",
             "Dim poison_status(0 To 4, 0 To 15) As UDT_f0704",
             "",
             "Type UDT_f0724",
             "    f0000 As Integer",
             "End Type",
             "",
             "Dim enemy_poison_status(0 To 4, 0 To 15) As UDT_f0724"),
        )
        out = remap.remap_struct_decls(lines, MAPPING)
        texts = [l.rstrip("\n") for l in out]
        self.assertEqual(texts.count("Type PoisonStatusStruct"), 1)
        # 重复块连同前后空行一起丢弃，两个 Dim 都指向保留块。
        self.assertIn("Dim poison_status(0 To 4, 0 To 15) As PoisonStatusStruct", texts)
        self.assertIn("Dim enemy_poison_status(0 To 4, 0 To 15) As PoisonStatusStruct", texts)
        # 被丢块的字段行不留残余。
        self.assertNotIn("    f0000 As Integer", texts)

    def test_unmapped_struct_falls_back_to_var_pascal(self):
        lines = decl_lines(
            ("Type UDT_f0584",
             "    f0000 As Integer",
             "End Type",
             "",
             "Dim battle_role_data_copy(0 To 7) As UDT_f0584"),
        )
        out = remap.remap_struct_decls(lines, MAPPING)
        texts = [l.rstrip("\n") for l in out]
        self.assertIn("Type BattleRoleDataCopy", texts)
        self.assertIn("    f0000 As Integer", texts)
        self.assertIn("Dim battle_role_data_copy(0 To 7) As BattleRoleDataCopy", texts)

    def test_body_lines_untouched(self):
        lines = ["    x = enemy_battle_data(i).f0012 + 1\n"]
        out = remap.remap_struct_decls(lines, MAPPING)
        self.assertEqual(out, lines)


if __name__ == "__main__":
    unittest.main()
