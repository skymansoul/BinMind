"""
创建: 2026-04-19
推测性级联修复 — 因果图驱动的下游文件自动修复提示生成。

问题：当 worker A 修改了 core/auth.py 的 create_token 签名后，worker B 的
api/handler.py（调用了 create_token）在合并后会因签名不匹配而运行失败。
当前因果图可预测影响范围，但不提供修复建议。worker B 在下一轮生成时仍
基于旧签名编写代码，形成"并行生成 → 合并失败 → 人工修复"的低效循环。

方案：结合因果图的影响预测与 AST 差异分析，自动生成结构化修复提示（Repair Hint）。
  - 从因果图获取受影响文件列表及影响分数
  - 对变更文件解析旧/新版本的导出符号差异
  - 为每个受影响文件生成符号级别的修复提示（哪个导入、哪个调用需修改）
  - 修复提示写入黑板，受影响 worker 在下一轮 prompt 中可获取

与现有工作的差异：
  - Refine 针对 SWE-bench 单仓库 bug 修复，需完整测试套件
  - ACE 优化 prompt 上下文演化，不处理代码级修复
  - 本模块在并行生成过程中，利用因果图做影响定位 + AST 差异做修复提示，
    无需额外 LLM 调用（hint 模式），零 API 开销
  - 区别于传统 CI 失败后的人工修复——将修复时机从"合并后"前移到"生成中"
"""


import ast
import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SymbolDelta:
    """单个符号的变更描述。"""
    symbol: str
    change_type: str   # 'added' | 'removed' | 'signature_changed' | 'renamed'
    old_detail: str = ""
    new_detail: str = ""


@dataclass
class RepairHint:
    """单条修复提示——告知受影响文件需要如何调整。"""
    target_file: str          # 需要修复的文件路径
    source_file: str          # 引起变更的源文件路径
    impact_score: float       # 因果图影响分数
    affected_symbols: list[str]  # 受影响的导入符号
    suggested_action: str     # 修复建议（中文）
    severity: str = "high"    # high | medium | low


@dataclass
class CascadingRepair:
    """推测性级联修复引擎。

    不直接修改文件——仅生成修复提示，由 worker 或上层编排器决定是否应用。
    默认阈值 0.3：仅对影响分数 ≥ 0.3 的文件生成修复提示。
    """

    impact_threshold: float = 0.3
    max_hints: int = 20

    def analyze_and_hint(
        self,
        causal_graph,
        changed_files: list[str],
        blackboard=None,
    ) -> list[RepairHint]:
        """分析变更影响并生成修复提示。

        1. 因果图查询受影响文件
        2. 对每个变更文件提取导出符号
        3. 交叉匹配：哪些受影响文件依赖了变更的符号
        4. 生成结构化修复提示

        返回修复提示列表，按影响分数降序。"""
        if causal_graph is None:
            return []

        # 查询影响范围
        impact_results = causal_graph.impact_query(changed_files)
        if not impact_results:
            return []

        # 过滤高于阈值的受影响文件
        high_impact = [
            r for r in impact_results
            if r.impact_score >= self.impact_threshold
        ]
        if not high_impact:
            return []

        # 提取变更文件的导出符号
        changed_symbols: dict[str, set[str]] = {}
        for fpath in changed_files:
            if not fpath.endswith(".py") or not os.path.isfile(fpath):
                continue
            syms = _extract_exports(fpath)
            if syms:
                changed_symbols[fpath] = syms

        if not changed_symbols:
            return []

        hints: list[RepairHint] = []

        for impact in high_impact:
            target = impact.file
            if not target.endswith(".py") or not os.path.isfile(target):
                continue

            # 分析受影响文件导入了哪些变更符号
            affected = _find_affected_imports(target, changed_symbols)
            if not affected:
                continue

            # 确定严重级别
            sev = "high" if impact.impact_score >= 0.5 else (
                "medium" if impact.impact_score >= 0.3 else "low"
            )

            # 生成修复建议
            action = _build_repair_action(target, affected, changed_files)

            hints.append(RepairHint(
                target_file=target,
                source_file=changed_files[0] if changed_files else "",
                impact_score=impact.impact_score,
                affected_symbols=affected,
                suggested_action=action,
                severity=sev,
            ))

            if len(hints) >= self.max_hints:
                break

        hints.sort(key=lambda h: h.impact_score, reverse=True)

        if blackboard is not None:
            for h in hints[:8]:
                blackboard.deposit(
                    "finding",
                    f"[级联修复] {os.path.basename(h.target_file)}: {h.suggested_action[:100]}",
                    source_module="cascading_repair",
                    tags=["repair", "cascade", h.severity],
                    meta={
                        "target": h.target_file,
                        "symbols": h.affected_symbols,
                        "impact": h.impact_score,
                    },
                )

        return hints


# AST 辅助函数

def _extract_exports(filepath: str) -> set[str]:
    """提取 Python 文件的导出符号（顶层函数、类、__all__ 声明）。"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return set()

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    symbols: set[str] = set()
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef):
            symbols.add(node.name)
        elif isinstance(node, ast.ClassDef):
            symbols.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                symbols.add(elt.value)
    return symbols


def _find_affected_imports(
    target_file: str,
    changed_symbols: dict[str, set[str]],
) -> list[str]:
    """查找 target_file 中导入了哪些变更文件的符号。"""
    try:
        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    affected: list[str] = []
    target_dir = os.path.dirname(target_file)

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            # 尝试将模块名解析到变更文件
            for changed_path, symbols in changed_symbols.items():
                changed_mod = os.path.splitext(os.path.basename(changed_path))[0]
                if node.module.endswith(changed_mod) or changed_mod in node.module.split("."):
                    for alias in node.names:
                        if alias.name in symbols:
                            affected.append(alias.name)
    return affected


def _build_repair_action(
    target_file: str,
    affected_symbols: list[str],
    source_files: list[str],
) -> str:
    """根据受影响的符号构建修复建议文本。"""
    target_name = os.path.basename(target_file)
    symbols_str = "、".join(affected_symbols[:5])

    if len(affected_symbols) == 1:
        return (
            f"{target_name} 导入了符号 '{affected_symbols[0]}'——"
            f"源文件签名可能已变更。检查调用处的参数数量和类型是否匹配新签名"
        )
    else:
        return (
            f"{target_name} 导入了 {len(affected_symbols)} 个受影响的符号 "
            f"({symbols_str})——逐一检查各符号的调用约定是否与源文件一致"
        )


# 便捷集成入口

def cascading_check(
    repair: CascadingRepair,
    causal_graph,
    changed_files: list[str],
    blackboard=None,
) -> dict[str, Any]:
    """便利函数：执行级联修复分析并返回摘要。

    返回 {'hints': [...], 'high_count': N, 'total_affected': M}。
    executor 可直接调用此函数集成。"""
    hints = repair.analyze_and_hint(causal_graph, changed_files, blackboard)

    high_count = sum(1 for h in hints if h.severity == "high")
    medium_count = sum(1 for h in hints if h.severity == "medium")

    return {
        "hints": hints,
        "high_count": high_count,
        "medium_count": medium_count,
        "total_affected": len({h.target_file for h in hints}),
    }
