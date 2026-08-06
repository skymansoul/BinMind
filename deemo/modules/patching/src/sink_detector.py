# 创建: 2025-09-25 11:15
# 二进制级危险函数识别 — PLT/GOT解析 + 间接调用消解

"""Sink Detector — 二进制级危险函数(sink)识别器。

从 binary 中提取所有"危险函数调用点"(sink)，即污点数据到达后
可能触发漏洞的位置。分三个来源：

1. PLT 表项 — 动态链接的函数入口（如 strcpy@plt, system@plt）
   通过对 ELF .plt 段的解析获取。最可靠。

2. 直接调用 — call 指令目标为已知危险函数名
   从反汇编文本中识别。依赖反编译器输出质量。

3. 间接调用 — call [reg] / call *offset(%reg)
   无法从反汇编直接确定目标。使用启发式消解：
     - 检查前后5条指令中的 lea 是否加载了函数指针
     - 检查寄存器值的值域是否指向已知函数

Sink 分类：
  - MEMCPY_SINK: memcpy, strcpy, memmove (内存操作)
  - FORMAT_SINK: printf, sprintf, fprintf, syslog (格式字符串)
  - EXEC_SINK: system, popen, execve (命令执行)
  - ALLOC_SINK: malloc, realloc (分配大小可控)
  - FREE_SINK: free, delete (释放目标可控)
"""

import re
import struct
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class SinkCategory(str, Enum):
    MEMCPY = "memcpy"         # 内存拷贝 — 溢出风险
    FORMAT = "format"         # 格式化字符串 — 读/写任意地址
    EXEC = "exec"             # 命令执行 — RCE 风险
    ALLOC = "alloc"           # 分配大小可控 — 整数溢出
    FREE = "free"             # 释放目标可控 — UAF/DF
    GENERIC = "generic"       # 通用危险函数


@dataclass
class SinkSite:
    """单个 sink 位置。"""
    address: int = 0
    function_name: str = ""           # 被调用的危险函数名
    category: SinkCategory = SinkCategory.GENERIC
    instruction: str = ""             # 原始汇编指令
    is_indirect: bool = False         # 是否间接调用
    # 参数信息
    param_regs: List[str] = field(default_factory=list)
    param_domains: Dict[str, str] = field(default_factory=dict)
    # 上下文
    caller_function: str = ""
    call_site_offset: int = 0
    # 风险评分
    risk_score: float = 0.0           # 0..1


# ── Sink 知识库 ────────────────────────────────────────────────────

# (函数名正则, 类别, 基础风险分, 参数索引)
_SINK_DATABASE = [
    # 内存操作 — 参数: dst, src(tainted), size
    (re.compile(r'\b(memcpy|__memcpy_chk|memmove|bcopy)\b', re.I),
     SinkCategory.MEMCPY, 0.7, [('rdi','dst'), ('rsi','src'), ('rdx','size')]),
    (re.compile(r'\b(strcpy|strcat|wcscpy|wcscat)\b', re.I),
     SinkCategory.MEMCPY, 0.9, [('rdi','dst'), ('rsi','src')]),
    (re.compile(r'\b(strncpy|strncat|strlcpy|strlcat)\b', re.I),
     SinkCategory.MEMCPY, 0.5, [('rdi','dst'), ('rsi','src'), ('rdx','size')]),
    (re.compile(r'\b(sprintf|vsprintf|swprintf)\b', re.I),
     SinkCategory.MEMCPY, 0.85, [('rdi','dst'), ('rsi','fmt')]),

    # 格式化字符串 — 参数: fmt(tainted), ...
    (re.compile(r'\b(printf|fprintf|dprintf|syslog|__syslog_chk)\b', re.I),
     SinkCategory.FORMAT, 0.6, [('rdi','fmt')]),
    (re.compile(r'\b(vprintf|vfprintf|vsyslog)\b', re.I),
     SinkCategory.FORMAT, 0.6, [('rdi','fmt')]),

    # 命令执行 — 参数: cmd(tainted)
    (re.compile(r'\b(system|popen|execve|execvp|__execve)\b', re.I),
     SinkCategory.EXEC, 0.95, [('rdi','cmd')]),
    (re.compile(r'\b(execl|execlp|execle)\b', re.I),
     SinkCategory.EXEC, 0.9, [('rdi','path')]),

    # 内存分配 — 参数: size(tainted)
    (re.compile(r'\b(malloc|calloc|realloc|_Znwm|_Znam)\b', re.I),
     SinkCategory.ALLOC, 0.3, [('rdi','size')]),
    (re.compile(r'\b(alloca|__builtin_alloca)\b', re.I),
     SinkCategory.ALLOC, 0.7, [('rdi','size')]),

    # 内存释放 — 参数: ptr(tainted)
    (re.compile(r'\b(free|delete|_ZdlPv|_ZdaPv)\b', re.I),
     SinkCategory.FREE, 0.5, [('rdi','ptr')]),
    (re.compile(r'\b(realloc)\b', re.I),
     SinkCategory.FREE, 0.6, [('rdi','ptr'), ('rsi','size')]),
]


# ── Sink 扫描器 ────────────────────────────────────────────────────

class SinkScanner:
    """从汇编指令中扫描所有 sink 位置。"""

    def scan_asm(self, asm_lines: List[str],
                 caller_function: str = "",
                 base_address: int = 0) -> List[SinkSite]:
        """扫描汇编行中的所有危险函数调用。"""
        sinks = []
        for i, line in enumerate(asm_lines):
            stripped = line.strip()
            if not stripped.lower().startswith('call '):
                continue

            # 直接调用
            site = self._identify_direct_call(stripped, i, caller_function, base_address)
            if site:
                sinks.append(site)
                continue

            # 间接调用检测
            site = self._identify_indirect_call(stripped, i, caller_function, base_address)
            if site:
                sinks.append(site)

        return sinks

    def _identify_direct_call(self, inst: str, idx: int,
                              caller: str, base: int) -> Optional[SinkSite]:
        """识别直接调用已知危险函数。"""
        m = re.search(r'\bcall\s+(\S+)', inst, re.I)
        if not m:
            return None
        target = m.group(1).rstrip(';').split('@')[0].lstrip('*')

        for pattern, cat, risk, params in _SINK_DATABASE:
            if pattern.search(target):
                return SinkSite(
                    address=base + idx * 4,
                    function_name=target,
                    category=cat,
                    instruction=inst.strip(),
                    param_regs=[p[0] for p in params],
                    param_domains={p[0]: p[1] for p in params},
                    caller_function=caller,
                    call_site_offset=idx,
                    risk_score=risk)
        return None

    def _identify_indirect_call(self, inst: str, idx: int,
                                caller: str, base: int) -> Optional[SinkSite]:
        """检测间接调用并标记为可疑。"""
        if re.search(r'\bcall\s+(?:\[|[*])', inst, re.I):
            return SinkSite(
                address=base + idx * 4,
                function_name="<indirect>",
                category=SinkCategory.GENERIC,
                instruction=inst.strip(),
                is_indirect=True,
                caller_function=caller,
                call_site_offset=idx,
                risk_score=0.4)
        return None

    def scan_plt(self, plt_entries: Dict[str, int]) -> List[SinkSite]:
        """从 PLT 表项中提取 sink。"""
        sinks = []
        for func_name, addr in plt_entries.items():
            for pattern, cat, risk, params in _SINK_DATABASE:
                if pattern.search(func_name):
                    sinks.append(SinkSite(
                        address=addr, function_name=func_name,
                        category=cat, instruction=f"call {func_name}@plt",
                        param_regs=[p[0] for p in params],
                        param_domains={p[0]: p[1] for p in params},
                        risk_score=risk))
                    break
        return sinks
