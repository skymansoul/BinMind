"""
包含: 判定枚举, 候选数据类, 管线报告, 以及公共函数/常量集。
"""


from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class UafVerdict(Enum):
    """UAF级联判定结果."""
    SAFE = "SAFE"                    # 可证明安全, 过滤
    LIKELY_FP = "LIKELY_FP"         # 强FP信号, 降级
    UNCERTAIN = "UNCERTAIN"         # 无法判定, 保留
    LIKELY_TP = "LIKELY_TP"         # 强TP信号, 升级
    CONFIRMED = "CONFIRMED"         # 可证明UAF, 确认


class EscapeLevel(Enum):
    """悬垂指针逃逸范围."""
    NONE = 0       # 未使用
    STACK = 1      # 仅在栈上传递
    HEAP = 2       # 写入堆对象字段
    GLOBAL = 3     # 赋值给全局变量
    VTABLE = 4     # 通过虚表/函数指针间接调用


@dataclass
class UafCandidate:
    """UAF候选 — 贯穿级联各阶段."""
    ptr_name: str = ""
    func_name: str = ""
    alloc_lineno: int = 0
    free_lineno: int = 0
    use_lineno: int = 0
    alloc_func: str = "malloc"
    use_text: str = ""
    confidence: float = 0.50
    verdict: UafVerdict = UafVerdict.UNCERTAIN
    verdict_reason: str = ""
    escape_level: EscapeLevel = EscapeLevel.NONE
    aliases: Set[str] = field(default_factory=set)
    phases_passed: List[str] = field(default_factory=list)


@dataclass
class CascadeReport:
    """级联管线执行报告."""
    total_input: int = 0
    phase0_filtered: int = 0
    phase1_filtered: int = 0
    phase2_filtered: int = 0
    phase3_downgraded: int = 0
    final_tp: int = 0
    final_fp: int = 0
    total_time_ms: float = 0.0
    per_candidate: List[Dict[str, Any]] = field(default_factory=list)


# 公共常量: 内存管理函数集 (Phase 0/1/2 及 extractor 共用)

# 释放函数集
_FREE_SET = {'free', 'kfree', 'delete', 'delete[]', 'realloc'}
# 分配函数集
_ALLOC_SET = {'malloc', 'calloc', 'realloc', 'strdup', 'strndup',
              'memalign', 'aligned_alloc', 'new', 'new[]'}
# 使用标记函数
_USE_SET = {'memcpy', 'memmove', 'strcpy', 'strncpy', 'strcat', 'strncat',
            'printf', 'fprintf', 'sprintf', 'snprintf', 'puts', 'fwrite',
            'send', 'write', 'fread', 'fgets', 'gets', 'memset', 'bzero'}


__all__ = [
    'UafVerdict', 'EscapeLevel', 'UafCandidate', 'CascadeReport',
    '_FREE_SET', '_ALLOC_SET', '_USE_SET',
]
