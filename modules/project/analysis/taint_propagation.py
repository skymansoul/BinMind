# 轻量级污点传播: 输入→分配参数→写入参数的数据流追踪
# 技术问题: 堆溢出检测不仅需要知道写入大小, 还需要知道写入大小
#   是否受外部输入控制. 若memcpy(n)的n来自不可信输入且n可能很大,
#   则溢出风险远高于n是编译期常量的情况.
#   传统方案只标记"memcpy危险"不区分输入可控性→大量误报
# 解决手段: 双层污点分析 (与binary_taint_tracer.py互补):
#   层1: 输入→分配参数: 若malloc(size)的size受输入控制,
#         分配大小可能被攻击者调小, 导致合法的写入也溢出
#   层2: 输入→写入参数: 若memcpy(dst, src, n)的n受输入控制,
#         写入量可能被攻击者调大, 直接溢出
#   层3: 净化检测: 检查n在到达memcpy前是否经过边界检查
#   与binary_taint_tracer.py的关系: 该模块处理汇编级别的通用污点,
#     本模块专注于堆溢出检测所需的特定污点链路,
#     使用更轻量的标记传播机制
#
#   Schwartz et al. "All You Ever Wanted to Know About Dynamic Taint
#     Analysis" (IEEE S&P 2010) — 污点传播规则定义
#   STEROIDS (NDSS 2016) — 针对内存损坏的污点强化方案
#   TaintInduce (USENIX 2021) — 规约导向的污点规则学习
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple
from .value_range import ValueRange


class TaintSource(Enum):
    USER_INPUT = auto()          # read/recv/fgets等直接输入
    NETWORK = auto()             # 网络来源
    FILE = auto()                # 文件读取
    ENV_VAR = auto()             # 环境变量
    ARGV = auto()                # 命令行参数
    INDIRECT = auto()            # 间接控制 (通过其他变量传播)
    UNKNOWN = auto()


@dataclass
class TaintTag:
    """污点标记: 记录值的污染来源和传播路径."""
    source: TaintSource
    source_func: str = ""        # 污点引入的函数名
    source_arg: int = 0          # 函数参数索引 (0-based)
    propagation_depth: int = 0   # 传播跳数
    sanitized: bool = False      # 是否经过净化
    sanitizer_func: str = ""     # 净化函数名
    confidence: float = 1.0      # 污点置信度


class TaintTracker:
    """轻量级污点追踪器.

    专用于堆溢出检测场景: 追踪输入→malloc参数 和 输入→memcpy参数 两条链路.
    同时检测净化操作 (边界检查/长度限制).
    """

    # 输入源函数
    _INPUT_SOURCES = {
        "read": TaintSource.USER_INPUT, "recv": TaintSource.NETWORK,
        "recvfrom": TaintSource.NETWORK, "fgets": TaintSource.FILE,
        "fread": TaintSource.FILE, "scanf": TaintSource.USER_INPUT,
        "gets": TaintSource.USER_INPUT, "getenv": TaintSource.ENV_VAR,
        "recvmsg": TaintSource.NETWORK, "pread": TaintSource.FILE,
        "readlink": TaintSource.FILE, "__isoc99_scanf": TaintSource.USER_INPUT,
        "fscanf": TaintSource.FILE, "getc": TaintSource.FILE,
        "fgetc": TaintSource.FILE, "getchar": TaintSource.USER_INPUT,
        "argv": TaintSource.ARGV,
        # 字符串→数值转换: 返回值继承输入的污点属性
        # 若输入来自用户/网络/文件, 转换结果也是不可信的
        "atoi": TaintSource.INDIRECT, "atol": TaintSource.INDIRECT,
        "atoll": TaintSource.INDIRECT, "strtol": TaintSource.INDIRECT,
        "strtoul": TaintSource.INDIRECT, "strtod": TaintSource.INDIRECT,
        "strtof": TaintSource.INDIRECT, "strtold": TaintSource.INDIRECT,
        "strtoll": TaintSource.INDIRECT, "strtoull": TaintSource.INDIRECT,
        "sscanf": TaintSource.INDIRECT,
    }

    # 写入函数 (堆溢出的危险sink)
    _HEAP_WRITE_SINKS = {
        "memcpy", "memmove", "strcpy", "strcat", "sprintf",
        "snprintf", "strncpy", "bcopy", "memccpy", "stpcpy",
        "wmemset", "wmemcpy", "__memcpy_chk", "__memmove_chk",
        "read_input_into_buffer", "recv_into_buf",
    }

    # 净化函数: 对输入做长度限制
    _SANITIZERS = {
        "strlen": "length_check", "strnlen": "length_check",
        "snprintf": "format_bounds", "strncpy": "size_bound",
        "memchr": "bounds_scan", "check_length": "explicit_check",
        "validate_size": "explicit_check",
    }

    # 分配函数
    _ALLOC_FUNCTIONS = {"malloc", "calloc", "realloc", "_malloc",
                        "HeapAlloc", "g_malloc", "kmalloc"}

    def __init__(self):
        # 寄存器/变量名 → 污点标记
        self._tainted_vars: Dict[str, TaintTag] = {}
        # 内存地址 → 污点标记
        self._tainted_mem: Dict[int, TaintTag] = {}
        # 调用返回值的污点状态
        self._ret_taint: Dict[str, Optional[TaintTag]] = {}

    def mark_input_source(self, func_name: str, call_site: str,
                          ret_reg: str = "rax"):
        """标记输入函数的返回值为污点."""
        source = self._INPUT_SOURCES.get(func_name)
        if source is None:
            return
        tag = TaintTag(source=source, source_func=func_name)
        self._tainted_vars[ret_reg] = tag
        self._ret_taint[call_site] = tag

    def propagate_assign(self, dst: str, src: str):
        """赋值传播: dst = src — 传递污点."""
        if src in self._tainted_vars:
            tag = self._tainted_vars[src]
            new_tag = TaintTag(
                source=tag.source,
                source_func=tag.source_func,
                source_arg=tag.source_arg,
                propagation_depth=tag.propagation_depth + 1,
                sanitized=tag.sanitized,
                sanitizer_func=tag.sanitizer_func,
                confidence=tag.confidence * 0.99)
            self._tainted_vars[dst] = new_tag

    def propagate_arith(self, dst: str, src1: str, src2: str = ""):
        """算术传播: dst = src1 op src2 — 任一污点则结果污点."""
        tags = []
        if src1 in self._tainted_vars:
            tags.append(self._tainted_vars[src1])
        if src2 and src2 in self._tainted_vars:
            tags.append(self._tainted_vars[src2])
        if tags:
            # 合并: 取传播深度最小的 (最"原始"的污点源)
            best = min(tags, key=lambda t: t.propagation_depth)
            new_tag = TaintTag(
                source=best.source, source_func=best.source_func,
                source_arg=best.source_arg,
                propagation_depth=best.propagation_depth + 1,
                sanitized=all(t.sanitized for t in tags),
                sanitizer_func=best.sanitizer_func,
                confidence=best.confidence * 0.98)
            self._tainted_vars[dst] = new_tag

    def propagate_store(self, addr: int, src_reg: str):
        """内存存储传播."""
        if src_reg in self._tainted_vars:
            self._tainted_mem[addr] = self._tainted_vars[src_reg]

    def propagate_load(self, dst_reg: str, addr: int):
        """内存加载传播."""
        if addr in self._tainted_mem:
            self._tainted_vars[dst_reg] = self._tainted_mem[addr]

    def detect_sanitization(self, func_name: str, args: List[str]):
        """检测是否对污点变量进行了净化."""
        if func_name in self._SANITIZERS:
            for arg in args:
                arg_clean = arg.strip().strip('[]')
                if arg_clean in self._tainted_vars:
                    tag = self._tainted_vars[arg_clean]
                    tag.sanitized = True
                    tag.sanitizer_func = func_name
                    tag.confidence *= 0.7  # 净化降低危险置信度

    def detect_bound_check(self, cmp_var: str, bound_value: int):
        """检测比较指令: cmp var, bound — 推断边界检查."""
        if cmp_var in self._tainted_vars:
            tag = self._tainted_vars[cmp_var]
            tag.sanitized = True
            tag.sanitizer_func = f"cmp_bound_{bound_value}"
            tag.confidence *= 0.6

    def is_tainted(self, var: str) -> bool:
        """检查变量是否被污点污染."""
        return var in self._tainted_vars and not self._tainted_vars[var].sanitized

    def get_taint(self, var: str) -> Optional[TaintTag]:
        return self._tainted_vars.get(var)

    def check_malloc_input_controlled(self, size_reg: str) -> Optional[TaintTag]:
        """检查malloc参数是否受输入控制 (影响分配大小)."""
        tag = self._tainted_vars.get(size_reg)
        if tag and not tag.sanitized:
            return tag
        return None

    def check_write_input_controlled(self, size_reg: str) -> Optional[TaintTag]:
        """检查memcpy等写入大小参数是否受输入控制."""
        tag = self._tainted_vars.get(size_reg)
        if tag and not tag.sanitized:
            return tag
        return None

    def is_sink_function(self, func_name: str) -> bool:
        return func_name in self._HEAP_WRITE_SINKS

    def is_alloc_function(self, func_name: str) -> bool:
        return func_name in self._ALLOC_FUNCTIONS

    def is_input_source(self, func_name: str) -> bool:
        return func_name in self._INPUT_SOURCES

    def summary(self) -> Dict:
        active = sum(1 for t in self._tainted_vars.values() if not t.sanitized)
        sanitized = sum(1 for t in self._tainted_vars.values() if t.sanitized)
        return {
            "tainted_vars": len(self._tainted_vars),
            "tainted_mem_locs": len(self._tainted_mem),
            "active_taints": active,
            "sanitized_taints": sanitized,
            "input_controlled_mallocs": sum(
                1 for v, t in self._tainted_vars.items()
                if not t.sanitized and t.source != TaintSource.UNKNOWN),
        }
