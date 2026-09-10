"""
GAPSBV 四维度分析函数 + 共享数据类型 — 仿射关系/守卫条件/StridedInterval/分配器语义。

每个维度独立分析伪代码中的堆溢出风险, 返回 DimensionResult。
共享数据类型 (GapsbvVerdict, DimensionResult, GapsbvReport) 也在此定义,
以避免 gapsbv_pipeline ↔ gapsbv_dimensions 循环导入。
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List

from analysis.affine_relation_tracker import AffineRelationTracker
from analysis.guard_condition_inferrer import GuardConditionInferrer


class GapsbvVerdict(Enum):
    """GAPSBV 判定结果."""
    OVERFLOW = "OVERFLOW"         # 确认溢出
    SAFE = "SAFE"                 # 确认安全 (被某个维度过滤)
    CONDITIONAL = "CONDITIONAL"   # 依赖变量范围
    UNCERTAIN = "UNCERTAIN"       # 信息不足, 保留供人工审核


@dataclass
class DimensionResult:
    """单个维度的判定结果."""
    name: str
    weight: float
    verdict: str          # SAFE / OVERFLOW / CONDITIONAL / UNCERTAIN
    confidence: float     # 0.0 ~ 1.0
    reason: str = ""


@dataclass
class GapsbvReport:
    """GAPSBV 完整检测报告."""
    verdict: str                          # 最终判定
    confidence: float                     # 融合置信度
    dimensions: List[DimensionResult] = field(default_factory=list)
    affine_relations: int = 0            # 发现的仿射关系数
    guard_conditions: int = 0            # 提取的守卫条件数
    alloc_sites: int = 0                 # 分配点数
    active_filters: List[str] = field(default_factory=list)


def _resolve_macros(pseudocode: str) -> str:
    """展开 #define 宏 — 将 BUF_SIZE=64 替换为字面量, 使守卫模式可匹配.

    支持的宏定义语法:
      #define NAME value
      #define NAME 0xHEX
      #define NAME expression  (仅取第一个token作为值)
    """
    import re
    macros: Dict[str, str] = {}
    define_pat = re.compile(r'#define\s+(\w+)\s+(.+)')
    for line in pseudocode.splitlines():
        m = define_pat.match(line.strip())
        if m:
            name, value = m.group(1), m.group(2).strip()
            value = re.sub(r'/\*.*?\*/', '', value).strip()
            value = re.sub(r'//.*$', '', value).strip()
            token = value.split()[0] if value.split() else value
            macros[name] = token
    if not macros:
        return pseudocode
    # 按行替换, 跳过 #define 行自身 (防止 #define SIZE 128 → #define 128 128)
    result_lines = []
    for line in pseudocode.splitlines():
        stripped = line.strip()
        if stripped.startswith('#define') or stripped.startswith('# undef'):
            result_lines.append(line)
            continue
        for name in sorted(macros, key=len, reverse=True):
            line = re.sub(r'\b' + re.escape(name) + r'\b', macros[name], line)
        result_lines.append(line)
    return '\n'.join(result_lines)


def dim1_affine_relations(pseudocode: str, guard_bounds: dict) -> DimensionResult:
    """维度1: 仿射关系分析 — 追踪 alloc-write 之间的符号等式关系. (权重 0.35)

    malloc(n*4+8) vs memcpy(n*8) → diff=4n-8 → 对 n>2 有 OVERFLOW.
    保守约束: 当 alloc 和 write 使用相同的不可信变量 (atoi/argv/getenv) 时,
    降级 SAFE → CONDITIONAL.
    """
    import re
    untrusted_vars: set = set()
    untrusted_patterns = [
        r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?atoi\s*\(',
        r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?atol\s*\(',
        r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?strtol\s*\(',
        r'scanf\s*\([^,]*,\s*&\s*(\w+)',
        r'fgets\s*\((\w+)',
        r'recv\s*\([^,]+,\s*(\w+)',
        r'read\s*\([^,]+,\s*(\w+)',
        r'(\w+)\s*=\s*argv\[',
        r'(\w+)\s*=\s*getenv\s*\(',
    ]
    for pat in untrusted_patterns:
        for m in re.finditer(pat, pseudocode):
            untrusted_vars.add(m.group(1))

    tracker = AffineRelationTracker()
    relations = tracker.track_alloc_write_relation(pseudocode)

    if not relations:
        return DimensionResult("AffineRelation", 0.35, "UNCERTAIN", 0.0,
                               "no alloc-write pairs found")

    safe_rels = [r for r in relations if r.verdict == "SAFE"]
    overflow_rels = [r for r in relations if r.verdict == "OVERFLOW"]
    conditional_rels = [r for r in relations if r.verdict == "CONDITIONAL"]

    # 降级 SAFE → CONDITIONAL 当共享变量来自不可信输入
    downgraded = []
    verified_safe = []
    for r in safe_rels:
        if r.shared_vars & untrusted_vars:
            downgraded.append(r)
        else:
            verified_safe.append(r)

    # OVERFLOW优先: 任一对溢出则整体不可判安全
    # 安全保守: 文件含多函数时, 只要存在溢出对就应保留
    # 通过溢出→安全→条件→不确定的优先级链
    if overflow_rels:
        reason_parts = [f"{len(overflow_rels)} overflow"]
        if verified_safe:
            reason_parts.append(f"{len(verified_safe)} safe (other pairs)")
            reason_parts.append("; ".join(r.condition for r in overflow_rels[:2]))
        else:
            reason_parts.append("; ".join(r.condition for r in overflow_rels[:3]))
        return DimensionResult("AffineRelation", 0.35, "OVERFLOW", 0.85,
                               ": ".join(reason_parts[:1]) + " — " + reason_parts[-1])
    elif verified_safe:
        return DimensionResult("AffineRelation", 0.35, "SAFE", 0.90,
                               f"{len(verified_safe)} relation(s) proved safe: "
                               + "; ".join(r.condition for r in verified_safe[:3]))
    elif downgraded:
        return DimensionResult("AffineRelation", 0.35, "CONDITIONAL", 0.40,
                               f"{len(downgraded)} relation(s) use untrusted "
                               "variables — cannot prove safety")
    elif conditional_rels:
        return DimensionResult("AffineRelation", 0.35, "CONDITIONAL", 0.50,
                               "conditional overflow (depends on variable values)")
    else:
        return DimensionResult("AffineRelation", 0.35, "UNCERTAIN", 0.0,
                               "all relations unknown (no shared variables)")


def dim2_guard_analysis(pseudocode: str) -> DimensionResult:
    """维度2 (路径约束): 守卫条件分析 — 提取 if(var OP const) 并推断变量边界. (权重 0.20)

    消除 heap_guard_protected 类 FP:
      malloc(64) + if(idx < 64) buf[idx] = ... → SAFE

    关键保守约束:
      1. 守卫变量必须同时出现在写入偏移中
      2. 守卫必须证界 hi < alloc_size
      3. strcpy/gets/sprintf 等无界写入绝不可被守卫过滤

    先展开 #define 宏 (BUF_SIZE→64), 再提取守卫条件.
    """
    import re
    expanded = _resolve_macros(pseudocode)
    inferrer = GuardConditionInferrer()
    guards = inferrer.extract_guards(expanded)

    if not guards:
        return DimensionResult("GuardAnalysis", 0.20, "UNCERTAIN", 0.0,
                               "no guard conditions found")

    bounds = inferrer.get_all_bounds()
    guard_count = sum(len(g.conditions) for g in guards)

    if not bounds:
        return DimensionResult("GuardAnalysis", 0.20, "UNCERTAIN", 0.1,
                               f"{guard_count} condition(s) but no usable bounds")

    # 提取堆写入中使用的索引/偏移变量
    write_vars: set = set()
    for m in re.finditer(r'(\w+)\s*\[(\w+)\]\s*=', expanded):
        write_vars.add(m.group(2))
    for m in re.finditer(r'(?:memcpy|memmove)\s*\([^,]+?\s*\+\s*(\w+)', expanded):
        write_vars.add(m.group(1))
    # 同时提取 memcpy/memmove 的 size 参数中的变量
    # memcpy(dst, src, len) → len 是写入大小, 也受守卫约束
    for m in re.finditer(
            r'(?:memcpy|memmove|memset)\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)',
            expanded):
        write_vars.add(m.group(1))

    # 无界写入检测 — 绝不可被守卫过滤
    unbounded_writes = bool(re.search(
        r'\b(?:strcpy|strcat|gets|sprintf)\s*\(', expanded))

    has_malloc = 'malloc(' in expanded or 'calloc(' in expanded
    has_guarded_write = False
    guard_var = ""
    guarded_alloc_sz = 0

    alloc_sizes = re.findall(r'(?:malloc|calloc)\s*\(\s*(\d+)', expanded)
    for alloc_str in alloc_sizes:
        alloc_sz = int(alloc_str)
        for var, (_, hi) in bounds.items():
            if (var in write_vars or var == '_') and hi is not None and hi < alloc_sz:
                has_guarded_write = True
                guard_var = var
                guarded_alloc_sz = alloc_sz
                break

    if unbounded_writes and has_malloc:
        return DimensionResult("GuardAnalysis", 0.20, "CONDITIONAL", 0.20,
                               f"{guard_count} guard condition(s) but unbounded write "
                               "(strcpy/gets/sprintf) — cannot prove safety")
    elif has_guarded_write:
        return DimensionResult("GuardAnalysis", 0.20, "SAFE", 0.85,
                               f"guard bounds write ({guard_var} < {guarded_alloc_sz}) "
                               f"within allocation ({guard_count} conditions)")
    elif has_malloc and guard_count > 0:
        return DimensionResult("GuardAnalysis", 0.20, "CONDITIONAL", 0.30,
                               f"{guard_count} guard condition(s) present but "
                               "cannot prove write bounds")
    else:
        return DimensionResult("GuardAnalysis", 0.20, "UNCERTAIN", 0.0,
                               f"{guard_count} conditions, no allocation context")


def dim3_strided_interval(pseudocode: str) -> DimensionResult:
    """维度3: StridedInterval 分析 — 使用 s[lo,hi] 域进行边界检查. (权重 0.25)

    委托给 gapsbv_dimensions_late.py 中的完整实现.
    """
    from analysis.gapsbv_dimensions_late import dim3_strided_interval as _impl
    return _impl(pseudocode)


def dim4_allocator_semantics(pseudocode: str) -> DimensionResult:
    """维度4: 分配器语义 — 应用 glibc/ptmalloc2 request2size 和 alignment. (权重 0.20)

    委托给 gapsbv_dimensions_late.py 中的完整实现.
    """
    from analysis.gapsbv_dimensions_late import dim4_allocator_semantics as _impl
    return _impl(pseudocode)


__all__ = [
    '_resolve_macros',
    'dim1_affine_relations', 'dim2_guard_analysis',
    'dim3_strided_interval', 'dim4_allocator_semantics',
]
