# VB4 PAL Decompiler

独立的 `PAL.EXE -> pal_code.txt` VB4 p-code 逆向工程项目。核心解码依赖带 NB09
CodeView 信息的 `VB40032.DLL`，详细逆向结论统一见 `docs/vb40032.md`。

## 目录

- `input/PAL.EXE`：待分析的 VB4-32 p-code 程序
- `input/VB40032.DLL`：word-pcode dispatcher 与 CodeView handler 名称来源
- `input/mapping.json`：匿名过程、变量和 PAL API 的可读名称映射
- `input/output_hashes.json`：三个文本产物的 SHA-256 基准
- `src/`：运行代码和名称映射
- `docs/vb40032.md`：VB40032/PAL p-code 逆向说明
- `out/`：反汇编、伪代码和最终代码

## 运行

在项目根目录执行：

```bash
uv sync
uv run run_pipeline.py
```

流水线按顺序执行：

1. 扫描 ProcDsc，恢复 PAL 的过程边界；
2. 使用 `VB40032.DLL` 恢复 16-bit word-pcode 指令；
3. 用栈机生成 VB 风格伪代码；
4. 使用 `input/mapping.json` 重映射名称；
5. 校验 `out/pal_*.txt` 的 SHA-256。

可覆盖输入和输出路径。使用自定义输出目录时，同时指定对应的 hash 文件：

```bash
uv run run_pipeline.py \
  --exe input/PAL.EXE \
  --vb4dll input/VB40032.DLL \
  --mapping input/mapping.json \
  --out-dir out \
  --hashes input/output_hashes.json
```

也可单独执行：

```bash
uv run src/main.py
uv run src/remap.py
uv run src/check_outputs.py
uv run src/word_probe.py
```

有意改变输出内容后，检查 diff 无误再更新基准：

```bash
uv run src/check_outputs.py --update
```

输出是可读、可核验的 VB 风格伪代码，不保证能直接重新编译。VB4 EXE 不保留原始
过程名表，因此无法映射的过程使用结构性名称；虚调用和部分事件名保留 slot 占位名。
