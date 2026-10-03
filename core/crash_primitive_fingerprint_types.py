"""崩溃原语指纹: 类型定义与常量。"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional


class RegisterControl(Enum):
    CONTROLLED = auto()       # 攻击者可直接控制寄存器值
    PARTIALLY = auto()        # 攻击者可部分影响 (经偏移)
    UNCONTROLLED = auto()     # 寄存器值不可控
    ZERO = auto()             # 寄存器为 NULL/0
    UNKNOWN = auto()          # 信息不足


class PrimitiveType(Enum):
    RIP_CONTROL = "rip_control"
    PARTIAL_RIP = "partial_rip"
    ARBITRARY_READ = "arbitrary_read"
    ARBITRARY_WRITE = "arbitrary_write"
    STACK_PIVOT = "stack_pivot"
    HEAP_CORRUPTION = "heap_corruption"
    UAF = "use_after_free"
    DOUBLE_FREE = "double_free"
    INFO_LEAK = "info_leak"
    NULL_DEREF = "null_deref"
    UNKNOWN = "unknown"


@dataclass
class RegisterAnalysis:
    """单个寄存器的可控性分析。"""
    name: str
    value: int = 0
    control: RegisterControl = RegisterControl.UNKNOWN
    is_writable_address: bool = False     # 值是否指向可写内存区域
    points_to_stack: bool = False         # 值是否落在栈范围内
    points_to_heap: bool = False          # 值是否落在堆范围内
    contains_pattern: Optional[str] = None  # 如 "0x41414141" (AAAA pattern)


@dataclass
class HeapOperationSequence:
    """从崩溃上下文中提取的堆操作序列, 用于 UAF/双重释放检测。"""
    operations: List[str] = field(default_factory=list)  # ["alloc(0x40)", "free", "use", ...]
    freed_chunks: List[int] = field(default_factory=list)  # 已释放的内存地址
    alloc_sizes: List[int] = field(default_factory=list)   # 分配大小序列
    glibc_version_hint: str = ""        # 从crash输出中猜测的glibc版本
    tcache_bin_hint: Optional[int] = None  # 涉及tcache的bin编号


@dataclass
class CrashFingerprint:
    """完整崩溃指纹, 含多维可利用性信号。"""
    crash_type: str
    registers: Dict[str, RegisterAnalysis] = field(default_factory=dict)
    heap_ops: Optional[HeapOperationSequence] = None
    faulting_instruction: str = ""
    faulting_address: int = 0
    stack_trace: List[str] = field(default_factory=list)
    # 多维评分 (0.0~1.0)
    rip_control_score: float = 0.0
    stack_control_score: float = 0.0
    heap_control_score: float = 0.0
    info_leak_score: float = 0.0
    overall_exploitability: float = 0.0
    # 推荐的利用策略
    recommended_primitives: List[PrimitiveType] = field(default_factory=list)
    recommended_strategy: str = ""
    # 附加上下文 (如 fingerprint_crash 写入的 heap_context)
    metadata: Dict[str, Any] = field(default_factory=dict)


# 已知寄存器值模式到利用策略提示的映射, 源自 AutoPwn 样本分析。
_VALUE_PATTERNS = {
    r'^0x41{4,}': ('user_controlled', 'pattern fill, RIP likely controllable'),
    r'^0x0+$': ('null_deref', 'NULL deref, usually not exploitable unless mmap_min_addr=0'),
    r'^0x7f[0-9a-f]{10,}': ('libc_range', 'address in libc range, potential info leak'),
    r'^0x7e[0-9a-f]{10,}': ('stack_probable', 'likely stack address'),
}
