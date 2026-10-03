"""ALPR UAF 共享类型 — 生命周期溯源数据类型与判定枚举.

用途: UAF(use-after-free)误报削减的溯源侧基础。

设计决策:
  - 溯源标签为何是字符串而非结构化对象: free/use 配对只需比较
    标签等价性, 字符串哈希满足要求且便于调试输出。
  - 标签集合: alloc@<addr>(分配点), argN(函数参数), stack(栈地址),
    const(常量), unknown(无法确定)。
  - 经典 UAF 判定只承认 alloc@ 标签匹配; arg/unknown 标签的 use
    归入 LIKELY 保留, 保证召回不因标签不精确而受损。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class UafVerdict(Enum):
    SAFE_REBOUND = 'safe_rebound'   # 指针已重绑定新分配, use 非已释放对象
    CONFIRMED = 'confirmed'         # use 溯源 == free 溯源, 经典 UAF
    LIKELY = 'likely'               # 溯源未知/别名, 保守保留
    UNCERTAIN = 'uncertain'


class UseKind(Enum):
    READ = 'read'
    WRITE = 'write'
    CALL_VIA = 'call_via'


@dataclass
class FreeRecord:
    """一次 free 调用."""
    addr: int
    func_name: str
    ptr_reg: str        # 承载被释放指针的寄存器
    freed_label: str    # free 点的指针溯源标签
    is_double_free: bool = False


@dataclass
class UafUse:
    """一次对已释放指针的潜在使用."""
    addr: int
    func_name: str
    ptr_reg: str
    use_label: str
    use_kind: UseKind
    free_addr: int = 0
    freed_label: str = ''
    gap: int = 0        # free 到 use 的指令间隔


@dataclass
class UafVerdictRecord:
    """一次 use 的 ALPR 最终判定."""
    func_name: str
    use_addr: int
    ptr_reg: str
    use_kind: UseKind
    freed_label: str
    use_label: str
    verdict: UafVerdict
    reasoning: str
    confidence: float = 0.5
    fp_probability: float = 0.5


@dataclass
class FuncLifetimeResult:
    """单函数生命周期分析结果."""
    name: str
    frees: List[FreeRecord] = field(default_factory=list)
    uses: List[UafUse] = field(default_factory=list)
    verdicts: List[UafVerdictRecord] = field(default_factory=list)
