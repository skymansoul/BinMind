# analysis/constraint_simplifier — 分配-拷贝约束简化器
# 将 alloc_size 与 copy_size 的关系抽象为三种约束类型,
# 用于判断堆溢出条件是否成立。无需符号执行。
#
# 约束类型:
#   ALLOC_GT_COPY  — 分配足够大, 安全
#   ALLOC_EQ_COPY  — 恰好相等, 条件安全 (取决于 size 来源)
#   ALLOC_LT_COPY  — 分配小于写入, 溢出条件成立
#   ALLOC_UNKNOWN  — 无法确定关系

from enum import Enum
from typing import Dict, List, Set, Optional


class ConstraintType(Enum):
    ALLOC_GT_COPY = 1
    ALLOC_EQ_COPY = 2
    ALLOC_LT_COPY = 3
    ALLOC_UNKNOWN = 4


# 常见常量分配大小 (推测为编译期固定值)
_COMMON_ALLOC_SIZES: Set[int] = {64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}

# malloc参数恒为 sizeof(type) 的模式 → 安全
_SAFE_ALLOC_PATTERNS: Set[str] = {"sizeof", "offsetof", "alignof"}


def classify_constraint(
    alloc_func: str,
    write_func: str,
    strings: List[str],
    imports: Dict = None,
) -> ConstraintType:
    """分析 alloc-write 对的约束关系。

    判定逻辑:
    1. alloc_func 为 calloc → ALLOC_GT_COPY (calloc 不适合溢出场景, 因为初始化)
    2. 字符串中存在 sizeof 模式 → ALLOC_GT_COPY (开发者用 sizeof 控制大小)
    3. alloc_func 为 malloc 且无可控 size 证据 → ALLOC_EQ_COPY (默认等量分配)
    4. write_func 有输入源 + alloc_func 无可控 size → ALLOC_LT_COPY (溢出高风险)
    5. 无法确定 → ALLOC_UNKNOWN
    """
    text = " ".join(s[1] if isinstance(s, tuple) else str(s) for s in (strings or []))

    # calloc 分配+清零 → 攻击者难以利用
    if "calloc" in alloc_func.lower():
        return ConstraintType.ALLOC_GT_COPY

    # sizeof 模式 → 分配大小由编译器控制
    if any(p in text for p in _SAFE_ALLOC_PATTERNS):
        return ConstraintType.ALLOC_GT_COPY

    # malloc(size) 中 size 是常量且 > copy 预期值 → 安全
    for sz in _COMMON_ALLOC_SIZES:
        if str(sz) in text and sz >= 4096:
            return ConstraintType.ALLOC_GT_COPY

    # 存在 recv/read 输入 + memcpy 写入 → 写入大小可能来自外部 → 溢出
    has_input = any(kw in text.lower() for kw in ["recv", "read", "fgets", "fread"])
    has_mem_write = any(kw in write_func.lower() for kw in ["memcpy", "strcpy", "sprintf"])
    if has_input and has_mem_write:
        return ConstraintType.ALLOC_LT_COPY

    # realloc 场景: 原始大小被截断 → 溢出
    if "realloc" in alloc_func.lower() and "atoi" in text.lower():
        return ConstraintType.ALLOC_LT_COPY

    return ConstraintType.ALLOC_UNKNOWN


def compute_overflow_score(constraint: ConstraintType,
                           taint_confidence: float = 0.0) -> float:
    """将约束类型 + 污点置信度 → 0-1 溢出风险评分。"""
    base = {
        ConstraintType.ALLOC_GT_COPY: 0.05,
        ConstraintType.ALLOC_EQ_COPY: 0.30,
        ConstraintType.ALLOC_LT_COPY: 0.85,
        ConstraintType.ALLOC_UNKNOWN: 0.45,
    }.get(constraint, 0.45)

    # 污点调制: 有污染路径 → 提升; 无 → 保持
    if taint_confidence > 0.5:
        base = min(1.0, base + 0.15)
    elif taint_confidence > 0.3:
        base = min(1.0, base + 0.05)

    return round(base, 2)
