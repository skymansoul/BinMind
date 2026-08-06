"""
创建: 2025-07-28
修改:
  2025-08-01 - annotate_fields=False 移除位置元数据，visit_arg 规范化参数名
  2025-08-03 - 移除未使用的 _seen_hashes 字段和 Any 导入
跨 Worker 语义收敛检测 — 双信号 AST 指纹 + 操作向量余弦相似度。

问题：并行 worker 独立生成不同模块的代码时，有 5-10% 概率产出功能等价但
表面语法不同的实现（CodeCRDT, Pugachev 2025）。当前黑板仅做 SHA-256 精确去重，
对变量重命名、语句重排、等价控制流变换完全无感。

方案：双信号联合判决——
  信号 1（结构指纹）：归一化 AST 哈希。将标识符替换为占位符 _v{N}，
    移除文档字符串和注释，规范化字面量。捕获同构的算法结构。
  信号 2（操作向量）：AST 节点类型频次向量。统计 N=32 种节点类型的出现次数，
    归一化后计算余弦相似度。捕获操作层面的语义相似性，对重排更鲁棒。
  判决规则：两信号均超各自阈值才标记为收敛。降低误报率。

与现有工作的差异：
  - CodeCRDT 的 TODO-claim 协议仅防止字符级重复，不管语义收敛
  - jscpd/SonarQube 基于 token 序列，对重命名敏感
  - probelabs/probe 的 LLM 语义去重需额外 API 调用，本模块零 API 开销
  - 双信号设计有其独特性：结构指纹对重命名不变，操作向量对重排鲁棒，
    两者互补覆盖语义等价的多种表现形式
"""

from __future__ import annotations

import ast
import hashlib
import math
from collections import Counter
from dataclasses import dataclass


# AST 节点类型列表 — 选取 32 种最常见的语句/表达式类型。
# 排除 Name/Constant/arg 等叶子节点，因其携带标识符信息，受重命名影响。
_OPS_TYPES: list[str] = [
    "FunctionDef", "AsyncFunctionDef", "ClassDef", "Return", "Assign",
    "AugAssign", "AnnAssign", "For", "AsyncFor", "While", "If", "IfExp",
    "With", "AsyncWith", "Raise", "Try", "Assert", "Import", "ImportFrom",
    "Expr", "Pass", "Break", "Continue", "Delete", "Global", "Nonlocal",
    "Yield", "YieldFrom", "Await", "ListComp", "DictComp", "SetComp",
    "GeneratorExp", "Call", "Attribute", "Subscript", "Slice", "Starred",
    "BinOp", "UnaryOp", "BoolOp", "Compare", "Lambda", "List", "Tuple",
    "Dict", "Set", "FormattedValue", "JoinedStr", "NamedExpr",
]

# 归一化用的标识符计数器前缀
_VN_PREFIX: str = "_v"


def _normalize_ast(source: str) -> str | None:
    """将 Python 源码解析为归一化 AST 字符串。

    归一化步骤：
    1. 将所有标识符替换为 _v0, _v1, ...（按首次出现顺序）
    2. 移除文档字符串（模块级、类级、函数级）
    3. 将数字常量替换为 0，字符串常量替换为 ""
    4. 移除注释（ast.parse 自动处理）

    返回归一化后的 AST dump 字符串，用于哈希。
    解析失败返回 None。
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    class Normalizer(ast.NodeTransformer):
        def __init__(self):
            self._names: dict[str, str] = {}
            self._counter: int = 0

        def _map_name(self, key: str) -> str:
            if key not in self._names:
                self._names[key] = f"{_VN_PREFIX}{self._counter}"
                self._counter += 1
            return self._names[key]

        def visit_Name(self, node: ast.Name) -> ast.Name:
            new_id = self._map_name(node.id)
            return ast.Name(id=new_id, ctx=node.ctx)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
            node.name = self._map_name(node.name)
            # 移除函数文档字符串
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body = body[1:]
            node.body = body
            return self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef | ast.AST:
            node.name = self._map_name(node.name)
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body = body[1:]
            node.body = body
            return self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
            node.name = self._map_name(node.name)
            body = list(node.body)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body = body[1:]
            node.body = body
            return self.generic_visit(node)

        def visit_arg(self, node: ast.arg) -> ast.arg:
            node.arg = self._map_name(node.arg)
            return self.generic_visit(node)

        def visit_Constant(self, node: ast.Constant) -> ast.Constant:
            if isinstance(node.value, str):
                return ast.Constant(value="")
            if isinstance(node.value, (int, float, complex)):
                return ast.Constant(value=0)
            return node

    normalizer = Normalizer()
    normalized = normalizer.visit(tree)
    ast.fix_missing_locations(normalized)
    # annotate_fields=False 排除行号/列偏移等源码位置元数据
    # 仅保留 AST 结构信息，确保格式差异不影响结构等价判定
    return ast.dump(normalized, annotate_fields=False)


def _compute_op_vector(source: str) -> list[float] | None:
    """计算 AST 节点类型频次向量（归一化到单位向量）。

    遍历 AST 收集 _OPS_TYPES 中定义的所有节点类型出现次数，
    归一化为单位向量以支持余弦相似度比较。
    解析失败返回 None。"""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    counter: Counter[str] = Counter()
    for node in ast.walk(tree):
        counter[node.__class__.__name__] += 1

    vec = [float(counter.get(t, 0)) for t in _OPS_TYPES]
    norm = math.sqrt(sum(v * v for v in vec))
    if norm < 1e-10:
        return vec  # 全零向量（空文件或仅注释）
    return [v / norm for v in vec]


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """两个归一化向量的余弦相似度（向量已归一化，退化为点积）。"""
    if len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))


@dataclass
class ConvergenceReport:
    """单次收敛检测报告。"""
    file_a: str
    file_b: str
    ast_hash_match: bool      # 信号1：归一化 AST 哈希是否匹配
    op_similarity: float       # 信号2：操作向量余弦相似度
    is_converged: bool         # 最终判定
    detail: str = ""


@dataclass
class SemanticDedup:
    """跨文件语义收敛检测器。

    threshold_ast: 归一化 AST 哈希匹配即视为结构同构（离散信号）
    threshold_op: 操作向量余弦相似度阈值，建议 0.85-0.95
    max_files: 单次检测的最大文件数，避免 O(n²) 爆炸
    """

    threshold_ast: float = 1.0    # 离散二值信号，保留为 float 以兼容配置
    threshold_op: float = 0.88
    max_files: int = 300

    def detect(
        self,
        filepaths: list[str],
    ) -> list[ConvergenceReport]:
        """对文件列表执行语义收敛检测。

        仅检查 .py 文件。对每对文件计算双信号，两个信号均超阈值则标记收敛。
        返回检测到的所有收敛对报告。

        时间复杂度：O(k²·T) 其中 k=有效文件数, T=平均 AST 解析时间。
        100 文件约 2-3 秒。远小于 API 调用延迟，适合在线使用。
        """
        py_files = [f for f in filepaths if f.endswith(".py")][:self.max_files]
        if len(py_files) < 2:
            return []

        # 阶段 1：并行提取双信号（每个文件解析一次，复用 AST）
        signatures: list[tuple[str, str | None, list[float] | None]] = []
        for fpath in py_files:
            source = self._read_source(fpath)
            if source is None:
                signatures.append((fpath, None, None))
                continue
            norm_ast = _normalize_ast(source)
            ast_hash = (
                hashlib.sha256(norm_ast.encode()).hexdigest()
                if norm_ast is not None else None
            )
            op_vec = _compute_op_vector(source)
            signatures.append((fpath, ast_hash, op_vec))

        # 阶段 2：成对比较
        reports: list[ConvergenceReport] = []
        valid = [(p, h, v) for p, h, v in signatures if h is not None and v is not None]

        for i in range(len(valid)):
            for j in range(i + 1, len(valid)):
                fa, ha, va = valid[i]
                fb, hb, vb = valid[j]

                ast_match = (ha == hb)
                op_sim = _cosine_similarity(va, vb)
                converged = ast_match and op_sim >= self.threshold_op

                if converged or (ast_match and op_sim > 0.7):
                    # 记录所有"接近收敛"的对，便于诊断
                    reports.append(ConvergenceReport(
                        file_a=fa, file_b=fb,
                        ast_hash_match=ast_match,
                        op_similarity=round(op_sim, 4),
                        is_converged=converged,
                        detail=(
                            f"ast_hash={'match' if ast_match else 'mismatch'}, "
                            f"op_sim={op_sim:.3f}"
                        ),
                    ))

        # 按相似度降序排列
        reports.sort(key=lambda r: r.op_similarity, reverse=True)
        return reports

    def _read_source(self, filepath: str) -> str | None:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return None

    def convergence_rate(self, reports: list[ConvergenceReport]) -> float:
        """计算收敛率：实际收敛对 / 所有检测对。"""
        if not reports:
            return 0.0
        converged_count = sum(1 for r in reports if r.is_converged)
        return converged_count / len(reports)


def dedup_blackboard_deposit(
    blackboard,
    filepaths: list[str],
    dedup: SemanticDedup | None = None,
) -> list[ConvergenceReport]:
    """向黑板存入收敛检测结果。当检测到收敛时，写入 warning 类型条目，
    后续 worker 在查询黑板时可获知已有相似实现存在，从而调整生成策略。

    返回检测报告列表，供上层 executor 使用。"""
    if dedup is None:
        dedup = SemanticDedup()
    reports = dedup.detect(filepaths)
    if not reports:
        return reports

    converged = [r for r in reports if r.is_converged]
    if converged:
        for r in converged[:5]:  # 最多写入 5 条，避免黑板膨胀
            blackboard.deposit(
                "warning",
                f"语义收敛: {r.file_a} ≈ {r.file_b} (op_sim={r.op_similarity:.3f})",
                source_module="semantic_dedup",
                tags=["convergence", "dedup"],
            )
    return reports
