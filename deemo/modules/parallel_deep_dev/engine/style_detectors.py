"""
创建: 2025-07-28
修改:
  2025-08-01 - docstring 检测补全实现，修正辅助函数整合
  2025-08-03 - 加权统计函数从 style_normalizer 迁移
代码风格检测器 — 从 Python 源文件提取 8 维风格特征向量。

从 style_normalizer.py 分离，保持单文件可管理性。
每个检测函数独立可测，不依赖外部状态。
"""

from __future__ import annotations

import ast
import re
import statistics


def detect_quote_style(source: str) -> str:
    single_count = len(re.findall(r"(?<!\\)'", source))
    double_count = len(re.findall(r'(?<!\\)"', source))
    if single_count > double_count * 1.5:
        return "single"
    elif double_count > single_count * 1.5:
        return "double"
    return "mixed"


def detect_import_style(tree: ast.Module, source: str) -> str:
    import_lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            import_lines.append(node.lineno)
    if not import_lines:
        return "unknown"
    if len(import_lines) <= 2:
        return "grouped"
    if max(import_lines) <= 30:
        return "grouped"
    total_lines = len(source.split("\n"))
    spread = max(import_lines) - min(import_lines)
    if total_lines > 0 and spread > total_lines * 0.5:
        return "separate"
    return "mixed"


def detect_naming_style(tree: ast.Module) -> str:
    snake = 0
    camel = 0
    for node in ast.walk(tree):
        name = ""
        if isinstance(node, ast.FunctionDef):
            name = node.name
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            name = node.id
        if not name:
            continue
        if "_" in name and name == name.lower():
            snake += 1
        elif any(c.isupper() for c in name) and "_" not in name:
            camel += 1
    if snake > camel * 2:
        return "snake_case"
    elif camel > snake * 2:
        return "camelCase"
    return "mixed" if snake + camel > 0 else "unknown"


def detect_docstring_style(tree: ast.Module, source: str = "") -> str:
    """检测文档字符串引号风格。

    通过检查源码中首个模块级字符串表达式的原始文本来判断
    使用的是三重双引号、三重单引号、还是单行引号。
    若 source 为空字符串，回退到仅基于 AST 的保守检测。"""
    doc = ast.get_docstring(tree)
    if doc is None:
        return "none"
    if not source:
        return "triple_double"  # 无源码时保守默认
    # 在源码中定位第一个字符串表达式
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str) and node.lineno > 0:
                # 读取对应行的原始文本
                lines = source.split("\n")
                if node.lineno <= len(lines):
                    line = lines[node.lineno - 1].strip()
                    if '"""' in line:
                        return "triple_double"
                    if "'''" in line:
                        return "triple_single"
                    if line.startswith('"') or line.startswith("'"):
                        return "single_line_double" if '"' in line[:3] else "single_line_single"
                break
    return "triple_double"  # 默认


def detect_indent(source: str) -> int:
    for line in source.split("\n"):
        stripped = line.lstrip()
        if stripped and not stripped.startswith("#"):
            leading = len(line) - len(stripped)
            if leading > 0:
                return leading
    return 4


def has_trailing_commas(source: str) -> bool:
    return bool(re.search(r',\s*[\]\)}]', source))


def max_line_len(source: str) -> int:
    lengths = [len(line) for line in source.split("\n") if line.strip()]
    return max(lengths) if lengths else 80


def blank_lines_between_funcs(source: str) -> int:
    lines = source.split("\n")
    gaps: list[int] = []
    in_func = False
    blank_count = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("def ") and not stripped.startswith("#"):
            if in_func and blank_count > 0:
                gaps.append(blank_count)
            in_func = True
            blank_count = 0
        elif stripped == "":
            blank_count += 1
    return statistics.mode(gaps) if gaps else 1


# ---------------------------------------------------------------------------
# 自动修正辅助函数
# ---------------------------------------------------------------------------

def normalize_quotes(source: str, target: str) -> str:
    """将引号统一为目标风格。保守模式：仅处理不含冲突引号的字符串。"""
    if target == "double":
        return re.sub(r"(?<!\\)'([^'\"\n]*)'", r'"\1"', source)
    elif target == "single":
        return re.sub(r'(?<!\\)"([^"\'\n]*)"', r"'\1'", source)
    return source


def tabs_to_spaces(source: str, spaces: int) -> str:
    return source.replace("\t", " " * spaces)


# ---------------------------------------------------------------------------
# 加权统计 — 用于共识计算
# ---------------------------------------------------------------------------

def weighted_mode(values: list[str], weights: list[float] | None, default: str) -> str:
    if weights is None:
        from collections import Counter
        c = Counter(values)
        return c.most_common(1)[0][0] if c else default
    from collections import defaultdict
    wc: dict[str, float] = defaultdict(float)
    for v, w in zip(values, weights):
        wc[v] += w
    return max(wc, key=wc.get) if wc else default


def weighted_median(values: list[int], weights: list[float] | None, default: int) -> int:
    if not values:
        return default
    if weights is None:
        import statistics
        return int(statistics.median(values))
    paired = sorted(zip(values, weights), key=lambda x: x[0])
    cumsum = 0.0
    target = sum(weights) / 2.0
    for v, w in paired:
        cumsum += w
        if cumsum >= target:
            return v
    return values[-1]


def weighted_mode_bool(values: list[bool], weights: list[float] | None) -> bool:
    if weights is None:
        return sum(values) > len(values) / 2
    true_w = sum(w for v, w in zip(values, weights) if v)
    false_w = sum(w for v, w in zip(values, weights) if not v)
    return true_w > false_w
