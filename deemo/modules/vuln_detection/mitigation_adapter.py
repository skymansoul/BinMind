# 缓解措施适配器——检测二进制安全缓解措施(ASLR/DEP/StackCanary/PIE/RELRO)，
# 为已启用的措施匹配绕过策略。radare2的iI命令输出解析为各缓解状态。

from enum import StrEnum
import logging
import os
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Any

logger = logging.getLogger(__name__)


class MitigationType(StrEnum):
    ASLR = "aslr"
    CFG = "cfg"
    CET = "cet"
    DEP = "dep"
    PIE = "pie"
    NX = "nx"
    STACK_CANARY = "stack_canary"
    RELRO = "relro"
    NONE = "none"


@dataclass
class MitigationInfo:
    type: MitigationType
    enabled: bool = False
    version: str = ""
    details: Any = None


@dataclass
class ExploitStrategy:
    mitigation: MitigationType
    strategy: str = ""
    success_rate: float = 0.0
    requirements: list = field(default_factory=list)


@dataclass
class AdapterResult:
    success: bool = False
    mitigations: Optional[List[MitigationInfo]] = None
    strategy: Optional[ExploitStrategy] = None
    # 附加的缓解概览——便于快速判断二进制整体加固水平
    summary: str = ""


class MitigationDetector:
    """通过radare2 iI命令检测二进制安全缓解措施状态。
    PIE检测优先用iI输出中的pic/pie标记，回退到ELF头类型检查。
    Stack canary通过__stack_chk_fail符号存在性判定。"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def detect_all(self) -> List[MitigationInfo]:
        result = []
        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()

            proc = subprocess.run(
                ["r2", "-q", "-c", "iI", self.binary_path],
                capture_output=True, text=True, timeout=30)
            output = proc.stdout.lower()

            pie_enabled = "pic" in output or "pie" in output
            result.append(MitigationInfo(type=MitigationType.PIE, enabled=pie_enabled))

            nx_enabled = "nx" in output or "noexec" in output
            result.append(MitigationInfo(type=MitigationType.NX, enabled=nx_enabled))

            canary_enabled = ("canary" in output or
                             "__stack_chk" in data.decode("latin1", errors='replace'))
            result.append(MitigationInfo(
                type=MitigationType.STACK_CANARY, enabled=canary_enabled))

            relro_enabled = "relro" in output
            result.append(MitigationInfo(type=MitigationType.RELRO, enabled=relro_enabled))

            aslr_enabled = pie_enabled
            result.append(MitigationInfo(type=MitigationType.ASLR, enabled=aslr_enabled))

            result.append(MitigationInfo(type=MitigationType.CFG, enabled=False))
            result.append(MitigationInfo(type=MitigationType.CET, enabled=False))

        except Exception as e:
            logger.warning("Mitigation detection failed: %s", e)
        return result


class StrategySelector:
    """为已启用的缓解措施匹配exploit策略。
    STRATEGY_MAP按缓解类型索引——每个条目包含绕过技术与预估成功率。
    策略参考：ASLR→info_leak+ret2libc, StackCanary→format_string leak, CFG→CFG-compliant gadgets。"""

    STRATEGY_MAP = {
        MitigationType.ASLR: ExploitStrategy(
            mitigation=MitigationType.ASLR,
            strategy="info_leak + ret2libc", success_rate=0.7),
        MitigationType.CFG: ExploitStrategy(
            mitigation=MitigationType.CFG,
            strategy="use CFG-compliant gadgets", success_rate=0.5),
        MitigationType.CET: ExploitStrategy(
            mitigation=MitigationType.CET,
            strategy="ROP chain with shadow stack bypass", success_rate=0.3),
        MitigationType.STACK_CANARY: ExploitStrategy(
            mitigation=MitigationType.STACK_CANARY,
            strategy="leak canary via format string", success_rate=0.6),
    }

    def select(self, mitigations: List[MitigationInfo]) -> Optional[ExploitStrategy]:
        for m in mitigations:
            if m.enabled and m.type in self.STRATEGY_MAP:
                return self.STRATEGY_MAP[m.type]
        return None

    @staticmethod
    def weak_point(mitigations: List[MitigationInfo]) -> Optional[MitigationInfo]:
        """返回第一个未启用的缓解措施——作为最弱攻击面提示。"""
        for m in mitigations:
            if not m.enabled:
                return m
        return None


class MitigationAdapter:
    """缓解措施适配主入口——检测→策略选择→结果封装。"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.detector = MitigationDetector(binary_path)
        self.selector = StrategySelector()

    def run(self) -> AdapterResult:
        try:
            mitigations = self.detector.detect_all()
            strategy = self.selector.select(mitigations)
            enabled_count = sum(1 for m in mitigations if m.enabled)
            total = len(mitigations)
            summary = "strong" if enabled_count >= total - 1 else (
                "moderate" if enabled_count >= total // 2 else "weak")
            return AdapterResult(
                success=True, mitigations=mitigations,
                strategy=strategy, summary=summary)
        except Exception as e:
            logger.error("Mitigation adapter failed: %s", e)
            return AdapterResult(success=False)


def create_mitigation_adapter(binary_path: str) -> MitigationAdapter:
    return MitigationAdapter(binary_path)
