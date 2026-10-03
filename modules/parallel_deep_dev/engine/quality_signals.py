"""
创建: 2024-09-02
代码质量信号计算 — 四维轻量指标，零 API 开销。

四个信号分别捕获不同的退化模式：
  - 重复度：N-gram 滑动窗口重复率 → 捕获 copy-paste 循环
  - 符号密度：每 KB 函数/类定义数 → 捕获空洞填充
  - 结构熵：AST 节点类型 Shannon 熵 → 捕获结构单一化
  - 注释比：注释行占比 → 捕获占位符填充

全部基于静态分析，不需要 LLM 调用或外部依赖。
"""


import ast
import math
from collections import Counter

_NGRAM_SIZE: int = 5
_REPETITION_WINDOW: int = 200


def compute_repetition(source: str) -> float:
    """字符级 5-gram 滑动窗口重复率。

    去除空白后，在 200-字符窗口内检测重复 N-gram 的比例。
    返回 0.0（无重复）到 1.0（完全重复）。"""
    text = source.replace(" ", "").replace("\n", "")
    if len(text) < _NGRAM_SIZE * 2:
        return 0.0

    ngrams: list[str] = [
        text[i:i + _NGRAM_SIZE]
        for i in range(len(text) - _NGRAM_SIZE + 1)
    ]
    if not ngrams:
        return 0.0

    seen: set[str] = set()
    repeat_count = 0
    window = min(_REPETITION_WINDOW, len(ngrams))

    for i, ng in enumerate(ngrams):
        start = max(0, i - window)
        recent = set(ngrams[start:i])
        if ng in recent or ng in seen:
            repeat_count += 1
        if i >= window:
            seen.add(ngrams[i - window])

    return repeat_count / len(ngrams)


def compute_symbol_density(source: str) -> float:
    """每千字节定义的顶层符号数（函数 + 类）。"""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0.0

    sym_count = sum(
        1 for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    kb_size = max(len(source.encode("utf-8")) / 1024.0, 0.001)
    return sym_count / kb_size


def compute_structure_entropy(source: str) -> float:
    """AST 节点类型分布的 Shannon 熵——低熵表示结构单一。"""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0.0

    counter: Counter[str] = Counter()
    for node in ast.walk(tree):
        counter[node.__class__.__name__] += 1

    total = sum(counter.values())
    if total == 0:
        return 0.0

    entropy = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def compute_comment_ratio(source: str) -> float:
    """注释行占比——过高暗示占位填充或未完成的代码。"""
    lines = source.split("\n")
    if not lines:
        return 0.0

    comment_lines = 0
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''"):
            comment_lines += 1

    return comment_lines / len(lines)
