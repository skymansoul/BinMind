# 格式说明符解析器, 区分危险格式字符串 (%n) 与只读格式字符串 (%s/%d)
# 方法论依据: 格式字符串漏洞的可利用性取决于格式说明符类型
# %n (写入) > %s (内存读取) > %d/%x (信息泄露) > 纯文本 (无害)
# 本模块不替代 format_string_detector, 作为其下游增强, 提供利用性评级

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple

class FormatRisk(Enum):
    WRITE_CAPABLE = "write_capable"     # 包含 %n → 可写内存
    MEMORY_READ = "memory_read"         # 包含 %s → 可读内存
    INFO_LEAK = "info_leak"             # 包含 %d/%x/%p → 信息泄露
    HARMLESS = "harmless"               # 纯文本或无格式符

@dataclass
class FormatAnalysis:
    risk_level: FormatRisk
    specifier_count: int
    has_width_arg: bool                 # %*d → 从参数取宽度
    has_precision_arg: bool             # %.*s → 从参数取精度
    detected_specs: List[str]           # 检测到的格式符列表
    write_enabled: bool                 # 是否存在 %n
    estimated_exploitability: float     # [0,1] 利用难度

# 格式符分类
_WRITE_SPECS = {'n', 'hn', 'hhn', 'ln'}        # 写入内存
_READ_SPECS = {'s', 'S', 'ls'}                   # 读内存
_LEAK_SPECS = {'d', 'i', 'u', 'x', 'X', 'p',    # 信息泄露
               'o', 'f', 'e', 'g', 'c', 'ld', 'lu', 'lx', 'lld', 'llu', 'llx'}

# 格式符正则: %[flags][width][.precision][length]specifier
_FMT_SPEC_RE = re.compile(
    r'%(?:[+\- #0])?'            # flags
    r'(?:\*|\d+)?'               # width
    r'(?:\.(?:\*|\d+))?'         # precision
    r'(?:hh|h|l|ll|j|z|t|L)?'   # length modifier
    r'([a-zA-Z%])'               # specifier
)

class FormatSpecAnalyzer:
    """格式说明符分析器, 评估格式字符串的可利用性

    用法:
      analyzer = FormatSpecAnalyzer()
      result = analyzer.analyze("Hello %s, your balance is %d")
      # → FormatRisk.INFO_LEAK, write_enabled=False
    """

    def analyze(self, format_string: str) -> FormatAnalysis:
        """分析格式字符串的风险等级"""
        specs = []
        has_write = False; has_read = False; has_leak = False
        has_width_arg = False; has_precision_arg = False

        for m in _FMT_SPEC_RE.finditer(format_string):
            spec = m.group(1)
            if spec == '%': continue  # %% → 转义
            specs.append(spec)

            if spec in _WRITE_SPECS:
                has_write = True
            elif spec in _READ_SPECS:
                has_read = True
            elif spec in _LEAK_SPECS:
                has_leak = True

            # 检测可变宽度/精度 (消耗额外参数, 增加利用面)
            full_match = m.group(0)
            if '*' in full_match.split('.')[0] if '.' in full_match else '*' in full_match:
                has_width_arg = True
            if '.*' in full_match:
                has_precision_arg = True

        # 风险定级
        if has_write:
            risk = FormatRisk.WRITE_CAPABLE
        elif has_read:
            risk = FormatRisk.MEMORY_READ
        elif has_leak:
            risk = FormatRisk.INFO_LEAK
        else:
            risk = FormatRisk.HARMLESS

        # 利用性估计: %n + 可变宽度 > %s > %d > 纯文本
        exploitability = 0.0
        if has_write:
            exploitability = 0.90
            if has_width_arg: exploitability = 0.95
        elif has_read:
            exploitability = 0.60
        elif has_leak:
            exploitability = 0.35
        else:
            exploitability = 0.05

        return FormatAnalysis(
            risk_level=risk,
            specifier_count=len(specs),
            has_width_arg=has_width_arg,
            has_precision_arg=has_precision_arg,
            detected_specs=specs,
            write_enabled=has_write,
            estimated_exploitability=exploitability,
        )

    def quick_scan(self, format_string: str) -> Tuple[FormatRisk, float]:
        """快速扫描, 返回 (risk, exploitability)"""
        analysis = self.analyze(format_string)
        return analysis.risk_level, analysis.estimated_exploitability
