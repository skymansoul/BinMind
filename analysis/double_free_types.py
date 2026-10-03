"""
双释放源级检测类型定义 — DFSV (Double-Free Source Verifier) 共用类型.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class DfVerdict(Enum):
    VULN = "VULN"           # 同一指针两次free, 中间无realloc
    SAFE = "SAFE"           # 可证安全 (不同指针 / 有realloc / NULL置位)
    UNCERTAIN = "UNCERTAIN"


@dataclass
class FreeSite:
    """free()调用点."""
    line: int
    var: str              # free的参数表达式文本 (如 p, g_alias, r->name)
    base_var: str         # 基础变量名 (如 p, g_alias, name)
    func: str = ""        # 所在函数 (跨函数分析用)


@dataclass
class AliasRecord:
    """指针别名记录: target在同一作用域内是source的别名."""
    source: str           # 原始指针变量
    target: str           # 别名变量
    line: int             # 别名建立行
    kind: str = "assign"  # assign | field | global | memcpy


@dataclass
class DfResult:
    """DFSV判定结果."""
    verdict: DfVerdict
    free_line: int = 0
    var_name: str = ""
    paired_line: int = 0    # 配对的另一个free行
    paired_var: str = ""    # 配对的另一个free变量
    confidence: float = 0.0
    reason: str = ""


__all__ = ['DfVerdict', 'FreeSite', 'AliasRecord', 'DfResult']
