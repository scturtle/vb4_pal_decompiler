#!/usr/bin/env python3
"""
remap.py — 将 VB4 p-code 伪代码中的匿名标识符替换为可读名称

用法：python3 remap.py [mapping.json] [pal_pseudocode.txt] [pal_code.txt]

读取 mapping.json 中的 functions/globals/global_refs/pal_funcs/params/
stack_vars/struct_fields/var_to_struct 映射，将 pal_pseudocode.txt 转换为可读的
pal_code.txt。
"""

import json
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# 结构体字段上下文敏感替换
# ---------------------------------------------------------------------------
# STRUCT_FIELDS: key = (变量名/结构体类型, 偏移) → 字段名
#   当代码中出现 varname(args).fXXXX 时，根据 varname 查找对应的字段名。
#   由 load_struct_mappings() 从 mapping.json 的 struct_fields 节加载。
# VAR_TO_STRUCT: 变量名 → 结构体类型 的映射（用于查找字段）
#   由 load_struct_mappings() 从 mapping.json 的 var_to_struct 节加载。
STRUCT_FIELDS: dict[tuple[str, int], str] = {}
VAR_TO_STRUCT: dict[str, str] = {}


def load_struct_mappings(mapping: dict) -> None:
    """从 mapping.json 加载 struct_fields / var_to_struct 到模块级全局变量。

    struct_fields 在 JSON 中为 {结构体类型: {偏移字符串: 字段名}}，
    加载后转换为 {(结构体类型, 偏移): 字段名} 以便查找。
    """
    global STRUCT_FIELDS, VAR_TO_STRUCT

    STRUCT_FIELDS = {}
    for struct_type, fields in mapping.get("struct_fields", {}).items():
        for offset_str, field_name in fields.items():
            STRUCT_FIELDS[(struct_type, int(offset_str))] = field_name

    VAR_TO_STRUCT = dict(mapping.get("var_to_struct", {}))


def build_struct_field_pattern() -> re.Pattern:
    """构建匹配 varname(...).fXXXX 的正则表达式
    仅匹配不包含嵌套括号的简单模式；嵌套模式由 replace_struct_fields_in_line 处理"""
    var_names = "|".join(re.escape(v) for v in VAR_TO_STRUCT.keys())
    return re.compile(
        rf"\b(?P<var>{var_names})\s*\((?P<args>[^()]*)\)\.f(?P<offset>[0-9A-Fa-f]{{4}})\b"
    )


def replace_struct_field(m: re.Match) -> str:
    """将 varname(args).fXXXX 替换为 varname(args).fieldName
    对于 word_array 类型，.f0000 映射为空字符串，表示去除 .f0000"""
    var = m.group("var")
    args = m.group("args")
    offset_str = m.group("offset")
    offset = int(offset_str, 16)  # 偏移量是十六进制
    struct_type = VAR_TO_STRUCT.get(var, var)
    field = STRUCT_FIELDS.get((struct_type, offset))
    if field is not None:
        if field == "":
            # word_array: strip .f0000 entirely
            return f"{var}({args})"
        return f"{var}({args}).{field}"
    return m.group(0)


def replace_struct_fields_in_line(line: str) -> str:
    """使用括号匹配替换所有 varname(...).fXXXX 模式，支持任意深度嵌套"""
    # 迭代处理：每轮处理最内层（不含嵌套括号）的模式
    for _ in range(10):
        new_line = _replace_struct_fields_once(line)
        if new_line == line:
            break
        line = new_line
    return line


def _replace_struct_fields_once(line: str) -> str:
    """处理一轮结构体字段替换"""
    result = []
    i = 0
    n = len(line)
    var_names_set = VAR_TO_STRUCT.keys()

    while i < n:
        # 寻找可能的变量名起始位置
        # 快速跳过：查找下一个可能匹配的字符
        if line[i].isalpha() or line[i] == '_':
            # 尝试匹配变量名
            j = i
            while j < n and (line[j].isalnum() or line[j] == '_'):
                j += 1
            word = line[i:j]

            if word in var_names_set:
                # 跳过空白
                k = j
                while k < n and line[k] == ' ':
                    k += 1
                if k < n and line[k] == '(':
                    # 用括号匹配找到对应的闭括号
                    depth = 0
                    args_start = k + 1
                    m = k + 1
                    while m < n:
                        if line[m] == '(':
                            depth += 1
                        elif line[m] == ')':
                            if depth == 0:
                                break
                            depth -= 1
                        m += 1

                    if m < n:
                        args = line[args_start:m]
                        # 检查后面是否跟着 .fXXXX
                        p = m + 1
                        if p < n and line[p] == '.':
                            q = p + 1
                            if q < n and line[q] == 'f' and q + 4 < n:
                                offset_str = line[q + 1:q + 5]
                                # 偏移量是十六进制（如 001C, 001E 等）
                                try:
                                    offset = int(offset_str, 16)
                                except ValueError:
                                    offset = None
                                if offset is not None:
                                    # 确保后面不是字母/数字（词边界）
                                    end = q + 5
                                    if end >= n or not (line[end].isalnum() or line[end] == '_'):
                                        var = word
                                        struct_type = VAR_TO_STRUCT.get(var, var)
                                        field = STRUCT_FIELDS.get((struct_type, offset))
                                        if field is not None:
                                            if field == "":
                                                result.append(f"{var}({args})")
                                            else:
                                                result.append(f"{var}({args}).{field}")
                                            i = end
                                            continue
        
        result.append(line[i])
        i += 1

    return ''.join(result)


# ---------------------------------------------------------------------------
# 映射加载与规则构建
# ---------------------------------------------------------------------------

def load_mapping(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_replace_map(mapping: dict) -> list[tuple[re.Pattern, callable]]:
    """构建替换规则列表，按优先级排序"""
    rules = []

    # 1. Pal.dll 函数名替换
    pal_funcs = mapping.get("pal_funcs", {})
    if pal_funcs:
        for orig, new in pal_funcs.items():
            pattern = re.compile(r"\b" + re.escape(orig) + r"\b")
            rules.append((pattern, lambda m, _n=new: _n))

    # 2. global_ref 替换 (global_0000XXXX → name)
    global_refs = mapping.get("global_refs", {})
    if global_refs:
        for orig, new in global_refs.items():
            pattern = re.compile(r"\b" + re.escape(orig) + r"\b")
            rules.append((pattern, lambda m, _n=new: _n))

        # 对 ImpAdSt 的部分输出会保留为 `global=0000XXXX`，而不是
        # `global_0000XXXX`；这仍然是同一个绝对地址，需一并重映射。
        for orig, new in global_refs.items():
            offset = orig.removeprefix("global_")
            pattern = re.compile(r"\bglobal=" + re.escape(offset) + r"\b")
            rules.append((pattern, lambda m, _n=new: _n))

    # 3. 函数名替换 (pub_NNN / priv_NNN → readable name)
    #    需要处理带后缀的形式，如 pub_168_0041030C_hot
    func_map = mapping.get("functions", {})
    if func_map:
        for orig, new in func_map.items():
            # 匹配 pub_NNN 后跟 _XXXX 或 _hot 等后缀
            pattern = re.compile(r"\b" + re.escape(orig) + r"(?:_\w+)?\b")
            rules.append((pattern, lambda m, _n=new: _n))

    # 4. 全局变量替换 (Me.fXXXX → name)
    globals_map = mapping.get("globals", {})
    if globals_map:
        for orig, new in globals_map.items():
            # Me.fXXXX → name
            pattern = re.compile(re.escape(orig) + r"\b")
            rules.append((pattern, lambda m, _n=new: _n))

    # 5. 结构体字段替换（最后执行，需要迭代）
    # 5. 结构体字段替换（最后执行，使用括号匹配支持任意嵌套深度）
    # build_struct_field_pattern 仍保留用于 build_replace_map 的兼容性
    struct_pattern = build_struct_field_pattern()
    rules.append((struct_pattern, replace_struct_field))

    return rules


def apply_rules_to_line(line: str, rules: list[tuple[re.Pattern, callable]]) -> str:
    """对单行应用所有替换规则。
    最后使用括号匹配的结构体字段替换以处理任意深度嵌套。"""
    # 先应用非结构体字段规则
    for pattern, replacement in rules[:-1]:
        line = pattern.sub(replacement, line)
    # 结构体字段替换：使用括号匹配，迭代处理嵌套
    line = replace_struct_fields_in_line(line)
    return line


def extract_base_name(full_name: str) -> str:
    """pub_168_0041030C_hot → pub_168,  priv_003_004032A4 → priv_003,  Sub_Main → Sub_Main"""
    for prefix in ("pub_", "priv_"):
        if full_name.startswith(prefix):
            parts = full_name.split("_")
            if len(parts) >= 2:
                return parts[0] + "_" + parts[1]
            return full_name
    return full_name


# 匹配 Sub/Function 定义行
# 例: Sub pub_168_0041030C(a0)
#     Sub priv_003_004032A4()  ' MethCallEngine entry
SUB_DEF_RE = re.compile(
    r"""^(?P<indent>\s*)
        (?P<keyword>Sub|Function)\s+
        (?P<name>(?:pub_|priv_|Sub_)\w+)
        (?P<params>\([^)]*\))?
        (?P<rest>.*)$""",
    re.VERBOSE,
)

# 匹配 End Sub / End Function
END_SUB_RE = re.compile(r"^\s*(End\s+Sub|End\s+Function)\b")


def process_line(line: str, mapping: dict, rules: list, current_func: dict) -> str:
    """
    逐行处理：
    - Sub/Function 定义行：替换函数名 + 参数名
    - End Sub/Function 行：清除当前函数上下文
    - 其他行：应用全部替换规则 + 替换当前函数的参数名
    """
    func_map = mapping.get("functions", {})
    params_map = mapping.get("params", {})
    stack_vars_map = mapping.get("stack_vars", {})

    m = SUB_DEF_RE.match(line)
    if m:
        indent = m.group("indent")
        keyword = m.group("keyword")
        full_name = m.group("name")
        params_str = m.group("params") or "()"
        rest = m.group("rest").rstrip()

        base = extract_base_name(full_name)
        readable = func_map.get(base, full_name)

        # 记录当前函数的参数映射
        current_func.clear()
        current_func["base"] = base
        if base in params_map:
            current_func["param_names"] = params_map[base]
        else:
            current_func["param_names"] = None
        if base in stack_vars_map:
            current_func["stack_vars"] = stack_vars_map[base]
        else:
            current_func["stack_vars"] = None

        # 替换参数列表中的 a0, a1, ... 为有意义的名称
        new_params = params_str
        if base in params_map:
            param_names = params_map[base]
            orig_params = [p.strip() for p in params_str[1:-1].split(",") if p.strip()]
            if len(orig_params) == len(param_names):
                new_params = "(" + ", ".join(param_names) + ")"

        if readable != full_name:
            new_line = f"{indent}{keyword} {readable}{new_params}"
            if "'" in rest:
                existing_comment = rest[rest.index("'") + 1:].strip()
                if existing_comment:
                    new_line += f"  '{existing_comment}"
        else:
            new_line = f"{indent}{keyword} {full_name}{new_params}"
            if "'" in rest:
                existing_comment = rest[rest.index("'") + 1:].strip()
                if existing_comment:
                    new_line += f"  '{existing_comment}"
        return new_line + "\n"

    # 检查 End Sub / End Function
    if END_SUB_RE.match(line):
        current_func.clear()
        return apply_rules_to_line(line, rules)

    # 非 Sub/Function 行：应用全部替换规则
    result = apply_rules_to_line(line, rules)

    # 替换当前函数的参数名 a0/a1/... → 有意义的名称
    param_names = current_func.get("param_names")
    if param_names:
        for i, pname in enumerate(param_names):
            orig = f"a{i}"
            if orig != pname:
                result = re.sub(r"\b" + orig + r"\b", pname, result)

    # 替换当前函数的 stack-XXX → 有意义的名称
    stack_vars = current_func.get("stack_vars")
    if stack_vars:
        for stack_name, var_name in stack_vars.items():
            if stack_name != var_name:
                result = re.sub(r"\b" + re.escape(stack_name) + r"\b", var_name, result)

    return result


def main():
    args = sys.argv[1:]
    project = Path(__file__).resolve().parent.parent
    mapping_path = args[0] if len(args) > 0 else str(project / "input" / "mapping.json")
    input_path = args[1] if len(args) > 1 else str(project / "out" / "pal_pseudocode.txt")
    output_path = args[2] if len(args) > 2 else str(project / "out" / "pal_code.txt")

    if not Path(mapping_path).exists():
        print(f"Error: mapping file not found: {mapping_path}", file=sys.stderr)
        sys.exit(1)
    if not Path(input_path).exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    mapping = load_mapping(mapping_path)
    load_struct_mappings(mapping)

    with open(input_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    rules = build_replace_map(mapping)

    stats = {
        "functions": len(mapping.get("functions", {})),
        "globals (Me.f)": len({k: v for k, v in mapping.get("globals", {}).items() if k.startswith("Me.")}),
        "global_refs": len(mapping.get("global_refs", {})),
        "pal_funcs": len(mapping.get("pal_funcs", {})),
        "params": len(mapping.get("params", {})),
        "stack_vars": len(mapping.get("stack_vars", {})),
        "struct_fields": len(STRUCT_FIELDS),
        "var_to_struct": len(VAR_TO_STRUCT),
    }
    print(f"Loaded mapping: {stats}")

    current_func = {}
    output_lines = [process_line(line, mapping, rules, current_func) for line in lines]

    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(output_lines)

    print(f"Output written to: {output_path}")
    print(f"  Input:  {len(lines)} lines")
    print(f"  Output: {len(output_lines)} lines")


if __name__ == "__main__":
    main()
