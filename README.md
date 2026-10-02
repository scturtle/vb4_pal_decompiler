# VB4 PAL Decompiler

独立的 `PAL.EXE -> pal_code.txt` VB4 p-code 逆向工程项目。核心解码依赖带 NB09
CodeView 信息的 `VB40032.DLL`，详细逆向结论统一见 `docs/vb40032.md`。

## 运行

```bash
uv sync
uv run run_pipeline.py
```

流水线：扫描 ProcDsc 恢复过程边界 → 用 `VB40032.DLL` 恢复 word-pcode →
解析模块声明流，补出数组边界、标量与 UDT 字段类型（`src/decl_stream.py`、
`src/struct_types.py`）→ 栈机 + CFG 结构化器生成 VB 风格伪代码：参数
ByRef/ByVal 与 pointee 类型由调用点压栈习语投票推断（全引用 ABI，
两遍流水线），过程头部发射局部 `Dim` 块（`src/stack_ir.py`、
`src/pseudo_code.py`、`src/structuring.py`）→ 按 `input/mapping.json` 重映射名称（仅替换，
无推断）→ 校验 `out/pal_*.txt` 的 SHA-256。

可覆盖输入输出路径（自定义输出目录时同时指定 hash 文件）：

```bash
uv run run_pipeline.py \
  --exe input/PAL.EXE \
  --vb4dll input/VB40032.DLL \
  --mapping input/mapping.json \
  --out-dir out \
  --hashes input/output_hashes.json
```

也可单独执行 `src/main.py`、`src/remap.py`、`src/check_outputs.py`、
`src/word_probe.py`。

有意改变输出内容后，检查 diff 无误再更新基准：

```bash
uv run src/check_outputs.py --update
```

输出是可读、可核验的 VB 风格伪代码，不保证能直接重新编译。VB4 EXE 不保留原始
过程名表，因此无法映射的过程使用结构性名称；虚调用和部分事件名保留 slot 占位名。
