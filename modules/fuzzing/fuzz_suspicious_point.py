"""可疑点引导的模糊测试种子加权与检测模块。

实现FuzzingBrain V2 的SP抽象: 从二进制字节流检测
危险函数调用、循环边界、格式字符串、整数溢出等可疑位置, 计算严重性加权分数,
引导种子能量分配。轻量级字节近似, 不依赖外部反汇编器。
"""

import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

import logging

_log = logging.getLogger(__name__)

# 可疑点类型与严重性

class SPDangerType(Enum):
    """可疑点类型 -- FuzzingBrain V2 Table 1分类。"""
    DANGER_FUNC = "danger_func"          # 危险函数调用
    LOOP_BOUNDARY = "loop_boundary"      # 循环边界
    MEMORY_ALLOC = "memory_alloc"        # 内存分配
    FORMAT_STRING = "format_string"      # 格式字符串
    INTEGER_OVERFLOW = "integer_overflow" # 整数溢出
    BRANCH_CONDITION = "branch_condition" # 分支条件
    TAINT_SINK = "taint_sink"            # 污点汇聚点
    ARRAY_INDEX = "array_index"          # 数组索引
    CAST_RISK = "cast_risk"              # 类型转换风险

# 危险函数严重性评分 [1,10], 综合CWE出现频率与可利用性
_DANGER_FUNC_SCORES: dict = {
    "system": 9, "execve": 9, "execvp": 9, "popen": 8,
    "memcpy": 7, "memmove": 6, "strcpy": 8, "strncpy": 6,
    "sprintf": 8, "snprintf": 5, "vsprintf": 8,
    "gets": 10, "scanf": 7, "fscanf": 7, "sscanf": 6,
    "read": 5, "recv": 6, "recvfrom": 6,
    "strcat": 7, "strncat": 5,
    "malloc": 4, "calloc": 4, "realloc": 5, "free": 6,
    "alloca": 5, "mmap": 4, "VirtualAlloc": 4,
    "CreateProcess": 8, "WinExec": 8, "ShellExecute": 7,
    "LoadLibrary": 6, "dlopen": 6, "dlsym": 5,
    "suid": 8, "setuid": 7, "chmod": 6, "chown": 6,
    # 内核危险函数
    "copy_from_user": 8, "copy_to_user": 8,
    "__memcpy": 7, "__copy_from_user": 8,
    # PQC相关
    "OQS_KEM_encaps": 5, "OQS_KEM_decaps": 7,
}

# 各危险类型的基础权重系数
_DEFAULT_TYPE_WEIGHTS = {
    SPDangerType.DANGER_FUNC: 1.0,
    SPDangerType.LOOP_BOUNDARY: 0.7,
    SPDangerType.MEMORY_ALLOC: 0.6,
    SPDangerType.FORMAT_STRING: 0.9,
    SPDangerType.INTEGER_OVERFLOW: 0.8,
    SPDangerType.BRANCH_CONDITION: 0.5,
    SPDangerType.TAINT_SINK: 1.0,
    SPDangerType.ARRAY_INDEX: 0.7,
    SPDangerType.CAST_RISK: 0.4,
}

# 调用指令搜索窗口 (字节)
_SEARCH_WINDOW = 64

# 预编译危险函数正则: call/jmp/invoke + 函数名
_DANGER_FUNC_PATTERN = re.compile(
    rb'(call|jmp|invoke).*?(' +
    b'|'.join(re.escape(f.encode()) for f in _DANGER_FUNC_SCORES.keys()) +
    b')',
    re.IGNORECASE,
)

@dataclass
class SuspiciousPoint:
    """FuzzingBrain V2的SP节点: 二进制中一个潜在漏洞位置。

    持有类型、严重性、可达性估计与上下文信息。
    """
    address: int                    # 文件偏移或虚拟地址
    danger_type: SPDangerType       # 危险分类
    danger_func: str = ""           # 关联函数名 (DANGER_FUNC类)
    severity: float = 0.0           # 严重性 [0, 10]
    reachability_score: float = 0.5 # 可达性估计 [0, 1]
    context_depth: int = 0          # 调用上下文深度
    evidence: List[str] = field(default_factory=list)  # 检测证据链
    weight: float = 0.0             # 综合权重

    def compute_weight(self):
        """综合权重 = (严重性/10) * 类型权重 * sqrt(可达性), sqrt平滑极端值。"""
        type_w = _DEFAULT_TYPE_WEIGHTS.get(self.danger_type, 0.5)
        reach_factor = self.reachability_score ** 0.5
        self.weight = (self.severity / 10.0) * type_w * reach_factor

# 可疑点检测器

class SuspiciousPointDetector:
    """FuzzingBrain V2风格的可疑点检测器, 字节级近似实现。

    检测链路:
      1. 字节扫描: 搜索危险函数调用
      2. 函数级分析: x86操作码模式识别循环/分支
      3. 上下文富化: 通过段标记(PLT/GOT/.text)估计可达性与深度

    FuzzingBrain V2完整版依赖Ghidra/IDA反汇编; 本模块提供无外部依赖的
    轻量近似。完整版可在platform/中用capstone实现。
    """

    def __init__(self):
        # 编译调用前缀正则: x86 call + ARM bl指令前缀
        self._re_danger = re.compile(
            rb'(?:\xe8|\xff\x15|\xff\x14\x85|bl\x20?)'
            rb'.{0,4}('
            + b'|'.join(
                re.escape(f.encode())[:8]  # 取函数名前8字节前缀
                for f in _DANGER_FUNC_SCORES.keys()
            )
            + b')',
            re.IGNORECASE,
        )

    def detect(self, data: bytes, base_address: int = 0) -> List[SuspiciousPoint]:
        """从二进制数据检测所有可疑点, 按权重降序返回。

        data:         二进制文件原始字节
        base_address: 基址偏移, 默认0
        """
        points: List[SuspiciousPoint] = []

        # 策略1: 危险函数调用
        points.extend(self._detect_danger_funcs(data, base_address))
        # 策略2: 循环边界 (x86操作码启发式)
        points.extend(self._detect_loop_boundaries(data, base_address))
        # 策略3: 格式字符串
        points.extend(self._detect_format_strings(data, base_address))
        # 策略4: 整数溢出 (mul+alloc模式)
        points.extend(self._detect_integer_overflow(data, base_address))

        # 计算权重并降序排列
        for p in points:
            p.compute_weight()

        return sorted(points, key=lambda p: p.weight, reverse=True)

    def _detect_danger_funcs(
        self, data: bytes, base_addr: int
    ) -> List[SuspiciousPoint]:
        """策略1: 遍历已知危险函数库, 全文匹配检测。

        通过PLT/GOT/.text段标记启发式估计可达性,
        通过函数序言计数估计上下文深度。
        """
        points = []

        for func_name, base_severity in _DANGER_FUNC_SCORES.items():
            func_bytes = func_name.encode()
            offset = 0
            while True:
                idx = data.find(func_bytes, offset)
                if idx < 0:
                    break

                # 搜索调用指令前缀 (_SEARCH_WINDOW内)
                ctx_start = max(0, idx - _SEARCH_WINDOW)
                ctx = data[ctx_start:idx + len(func_bytes)]

                # PLT/GOT段 -> 高可达性
                reachability = 0.5
                if b'.plt' in data[max(0, idx-256):idx] or b'.got' in data[max(0, idx-256):idx]:
                    reachability = 0.9
                elif b'.text' in data[max(0, idx-4096):idx]:
                    reachability = 0.7

                # 函数序言计数 (push rbp; mov rbp,rsp) 估计深度
                prologue_count = data[max(0, idx-512):idx].count(b'\x55\x48\x89\xe5')
                depth = min(prologue_count, 10)

                sp = SuspiciousPoint(
                    address=base_addr + idx,
                    danger_type=SPDangerType.DANGER_FUNC,
                    danger_func=func_name,
                    severity=float(base_severity),
                    reachability_score=reachability,
                    context_depth=depth,
                    evidence=[
                        f"危险函数调用: {func_name}",
                        f"偏移: 0x{idx:x}",
                        f"可达性: {reachability:.2f}",
                        f"上下文深度: {depth}",
                    ],
                )
                points.append(sp)
                offset = idx + 1

        return points

    def _detect_loop_boundaries(
        self, data: bytes, base_addr: int
    ) -> List[SuspiciousPoint]:
        """策略2: 循环边界检测 -- 基于x86条件跳转指令模式。

        识别: cmp/jl/jle/jg/jge (for循环), test/jz/jnz (while循环),
        dec/jnz (计数循环)。
        """
        points = []
        # x86条件跳转操作码
        cond_jumps = [
            b'\x7c', b'\x7e', b'\x7f', b'\x7d',  # jl, jle, jg, jge
            b'\x74', b'\x75',                      # jz, jnz
            b'\x0f\x8c', b'\x0f\x8e', b'\x0f\x8f', b'\x0f\x8d',  # 近跳转
        ]

        for jmp_op in cond_jumps:
            offset = 0
            while True:
                idx = data.find(jmp_op, offset)
                if idx < 0:
                    break

                # 条件跳转前搜索cmp/test指令
                pre_bytes = data[max(0, idx-8):idx]
                has_cmp = b'\x83\xf8' in pre_bytes or b'\x83\xfa' in pre_bytes or b'\x3b' in pre_bytes
                has_test = b'\x85' in pre_bytes or b'\xf6' in pre_bytes

                if has_cmp or has_test:
                    sp = SuspiciousPoint(
                        address=base_addr + idx,
                        danger_type=SPDangerType.LOOP_BOUNDARY,
                        severity=5.0,
                        reachability_score=0.8,
                        context_depth=1,
                        evidence=[
                            f"循环边界模式 (条件跳转) @ 0x{idx:x}",
                            f"cmp={has_cmp}, test={has_test}",
                        ],
                    )
                    points.append(sp)

                offset = idx + 2

        return points

    def _detect_format_strings(
        self, data: bytes, base_addr: int
    ) -> List[SuspiciousPoint]:
        """策略3: 格式字符串漏洞 -- 搜索printf系列附近的格式说明符。

        扫描调用后128字节内的可打印字符串, %n/%hn为写入说明符, 危险级别更高。
        """
        points = []
        printf_funcs = [b'printf', b'sprintf', b'fprintf', b'vprintf',
                       b'snprintf', b'vsprintf', b'vfprintf']

        # 格式说明符正则
        fmt_pattern = re.compile(rb'%[-+0 #]*\d*\.?\d*[hlL]?[sduxXnfFeEgGaAcp]')

        for func in printf_funcs:
            offset = 0
            while True:
                idx = data.find(func, offset)
                if idx < 0:
                    break

                # 调用后128字节内搜索格式字符串
                post_bytes = data[idx:idx + 128]
                fmt_matches = fmt_pattern.findall(post_bytes)

                if fmt_matches:
                    has_dangerous_n = any(b'%n' in m or b'%hn' in m for m in fmt_matches)
                    severity = 8.0 if has_dangerous_n else 6.0

                    sp = SuspiciousPoint(
                        address=base_addr + idx,
                        danger_type=SPDangerType.FORMAT_STRING,
                        danger_func=func.decode("ascii", errors="replace"),
                        severity=severity,
                        reachability_score=0.7,
                        context_depth=0,
                        evidence=[
                            f"格式字符串调用: {func.decode('ascii', errors='replace')}",
                            f"格式说明符: {[m.decode('ascii', errors='replace') for m in fmt_matches[:3]]}",
                            f"含%n: {has_dangerous_n}",
                        ],
                    )
                    points.append(sp)

                offset = idx + 1

        return points

    def _detect_integer_overflow(
        self, data: bytes, base_addr: int
    ) -> List[SuspiciousPoint]:
        """策略4: 整数溢出 -- mul/imul后紧跟malloc的模式。

        x86: mul操作码后64字节内出现分配函数, 暗示乘积作为分配大小。
        每种mul模式最多检测3处以控制误报。
        """
        points = []

        # mul操作码模式
        mul_ops = [b'\xf7\xe0', b'\x0f\xaf']  # mul eax
        alloc_funcs = [b'malloc', b'calloc', b'realloc']

        for mul_op in mul_ops:
            offset = 0
            count = 0
            while count < 3:
                idx = data.find(mul_op, offset)
                if idx < 0:
                    break

                # mul后64字节内搜索分配函数
                post = data[idx:idx + 64]
                alloc_hit = any(af in post for af in alloc_funcs)
                if alloc_hit:
                    sp = SuspiciousPoint(
                        address=base_addr + idx,
                        danger_type=SPDangerType.INTEGER_OVERFLOW,
                        severity=7.0,
                        reachability_score=0.6,
                        context_depth=1,
                        evidence=[
                            f"潜在整数溢出: mul @ 0x{idx:x}",
                            f"后接内存分配调用",
                        ],
                    )
                    points.append(sp)
                    count += 1

                offset = idx + 2

        return points

# 种子加权

def compute_suspicious_weight(
    seed_data: bytes,
    suspicious_points: List[SuspiciousPoint],
    base_weight: float = 0.1,
) -> float:
    """基于可疑点覆盖率为种子计算加权分数, 用于能量分配。

    对每个SP, 用地址低16位作为特征标记匹配种子数据。
    累加所有匹配SP的权重, 上限1.0。

    FuzzingBrain V2的SP Fuzzer以此分配种子能量:
    覆盖更多可疑点的种子获得更多变异轮次。
    """
    if not suspicious_points:
        return base_weight

    total_sp_weight = 0.0

    for sp in suspicious_points:
        # 地址低16位作特征标记 (完整实现应用基本块哈希)
        marker = struct.pack("<H", sp.address & 0xFFFF)
        if marker in seed_data:
            total_sp_weight += sp.weight

    return min(1.0, base_weight + total_sp_weight)

def prioritize_seeds_by_suspicious_points(
    seeds: list,
    suspicious_points: List[SuspiciousPoint],
) -> list:
    """按可疑点覆盖率降序排列种子, 排前者分配更多变异能量。"""
    scored = [
        (seed, compute_suspicious_weight(
            seed.data if hasattr(seed, 'data') else seed,
            suspicious_points,
        ))
        for seed in seeds
    ]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [seed for seed, _ in scored]

# 便捷入口

def detect_suspicious_points(
    data: bytes, base_address: int = 0
) -> List[SuspiciousPoint]:
    """一行入口: 从二进制数据检测全部可疑点。"""
    return SuspiciousPointDetector().detect(data, base_address)

__all__ = [
    "SPDangerType",
    "SuspiciousPoint",
    "SuspiciousPointDetector",
    "compute_suspicious_weight",
    "prioritize_seeds_by_suspicious_points",
    "detect_suspicious_points",
]
