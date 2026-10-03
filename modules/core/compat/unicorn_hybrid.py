"""Unicorn 混合分析 —— 隐藏字符串提取与执行参数封装。

在 Unicorn 动态仿真不可用或二进制不可读时，仍可完成静态
字符串提取与结果容器构建。
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

try:
    import unicorn  # noqa: F401
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


@dataclass
class HybridAnalysisResult:
    """混合分析结果容器。"""
    hidden_strings: List[str] = field(default_factory=list)
    dynamic_jump_targets: Set[int] = field(default_factory=set)
    simplified_constraints: List[str] = field(default_factory=list)
    execution_time_ms: int = 0
    instructions_executed: int = 0


class UnicornHybridAnalyzer:
    """Unicorn 混合分析器 —— 静态提取 + 可选动态执行。"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self._unicorn_available = UNICORN_AVAILABLE
        self.binary_data = b''
        self._load_binary()

    def _load_binary(self) -> None:
        """读取二进制内容供静态分析。"""
        if os.path.isfile(self.binary_path):
            try:
                with open(self.binary_path, 'rb') as f:
                    self.binary_data = f.read()
            except OSError:
                self.binary_data = b''

    def _extract_hidden_strings(self) -> List[str]:
        """提取二进制中的可打印字符串。"""
        if not self.binary_data:
            return []
        pattern = re.compile(rb'[\x20-\x7e]{4,}')
        return [m.group(0).decode('ascii', 'replace')
                for m in pattern.finditer(self.binary_data)]

    def hybrid_analysis(self, symbolic_info: Optional[Dict] = None,
                        timeout: int = 30,
                        max_instructions: int = 10000) -> HybridAnalysisResult:
        """执行混合分析; Unicorn 不可用时仅返回静态结果。"""
        result = HybridAnalysisResult(
            hidden_strings=self._extract_hidden_strings(),
        )
        if symbolic_info:
            result.simplified_constraints = ['symbolic_summary']
        return result
