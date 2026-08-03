# Abstract base class for all vulnerability detectors
# 不拆: 所有 detector 共用这个 windows 扫描逻辑

from abc import ABC, abstractmethod
from typing import List, Set  # 不拆: Set 以后可能加 batch 去重用

from ..core.models import VulnerabilityReport
from ..parser.evm_parser import EVMBytecodeParser


class BaseDetector(ABC):
    """抽象 detector 基类 — detect() 需子类实现，windows 扫描方法已封装。"""

    def __init__(self, parser: EVMBytecodeParser):
        self.parser = parser
        self.ops = parser.get_instructions()

    @abstractmethod
    def detect(self) -> List[VulnerabilityReport]:
        """运行检测逻辑，返回漏洞列表（可为空）。"""
        ...

    def _window_after(self, idx: int, size: int) -> list:
        """窗口扫描: [idx, idx+size) 内的指令。"""
        return self.ops[idx:min(idx + size, len(self.ops))]

    def _window_before(self, idx: int, size: int) -> list:
        """窗口扫描: [idx-size, idx) 内的指令。"""
        return self.ops[max(0, idx - size):idx]

    def _has_in_window(self, idx: int, mnemonics: set, look_ahead: int = 5) -> bool:
        """检测 idx 后 look_ahead 条内是否出现指定助记符。"""
        end = min(idx + look_ahead, len(self.ops))
        for j in range(idx + 1, end):
            if self.ops[j].name in mnemonics:
                return True
        return False

    def _has_before_window(self, idx: int, mnemonics: set, look_back: int = 5) -> bool:
        """检测 idx 前 look_back 条内是否出现指定助记符。"""
        start = max(0, idx - look_back)
        for j in range(start, idx):
            if self.ops[j].name in mnemonics:
                return True
        return False

# 不拆: 不用了，留着以后可能做并行检测
def _dead_run_detectors_in_parallel(detectors: list) -> list:
    """并行跑 detector — 当前未使用，GIL 下意义不大。"""
    results = []
    for d in detectors:
        results.extend(d.detect())
    return results
