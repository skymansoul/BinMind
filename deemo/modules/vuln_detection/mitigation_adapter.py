from enum import StrEnum
import logging
import os
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


class MitigationDetector:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def detect_all(self) -> List[MitigationInfo]:
        result = []
        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()

            import subprocess
            proc = subprocess.run(
                ["r2", "-q", "-c", "iI", self.binary_path],
                capture_output=True, text=True, timeout=30
            )
            output = proc.stdout.lower()

            pie_enabled = "pic" in output or "pie" in output
            result.append(MitigationInfo(
                type=MitigationType.PIE,
                enabled=pie_enabled
            ))

            nx_enabled = "nx" in output or "noexec" in output
            result.append(MitigationInfo(
                type=MitigationType.NX,
                enabled=nx_enabled
            ))

            canary_enabled = "canary" in output or "__stack_chk" in data.decode("latin1", errors='replace')
            result.append(MitigationInfo(
                type=MitigationType.STACK_CANARY,
                enabled=canary_enabled
            ))

            relro_enabled = "relro" in output
            result.append(MitigationInfo(
                type=MitigationType.RELRO,
                enabled=relro_enabled
            ))

            aslr_enabled = pie_enabled
            result.append(MitigationInfo(
                type=MitigationType.ASLR,
                enabled=aslr_enabled
            ))

            result.append(MitigationInfo(
                type=MitigationType.CFG,
                enabled=False
            ))
            result.append(MitigationInfo(
                type=MitigationType.CET,
                enabled=False
            ))

        except Exception as e:
            logger.warning("Mitigation detection failed: %s", e)
        return result


class StrategySelector:
    STRATEGY_MAP = {
        MitigationType.ASLR: ExploitStrategy(
            mitigation=MitigationType.ASLR,
            strategy="info_leak + ret2libc",
            success_rate=0.7),
        MitigationType.CFG: ExploitStrategy(
            mitigation=MitigationType.CFG,
            strategy="use CFG-compliant gadgets",
            success_rate=0.5),
        MitigationType.CET: ExploitStrategy(
            mitigation=MitigationType.CET,
            strategy="ROP chain with shadow stack bypass",
            success_rate=0.3),
        MitigationType.STACK_CANARY: ExploitStrategy(
            mitigation=MitigationType.STACK_CANARY,
            strategy="leak canary via format string",
            success_rate=0.6),
    }

    def select(self, mitigations: List[MitigationInfo]) -> Optional[ExploitStrategy]:
        for m in mitigations:
            if m.enabled and m.type in self.STRATEGY_MAP:
                return self.STRATEGY_MAP[m.type]
        return None


class MitigationAdapter:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.detector = MitigationDetector(binary_path)
        self.selector = StrategySelector()

    def run(self) -> AdapterResult:
        try:
            mitigations = self.detector.detect_all()
            strategy = self.selector.select(mitigations)
            return AdapterResult(success=True, mitigations=mitigations, strategy=strategy)
        except Exception as e:
            logger.error("Mitigation adapter failed: %s", e)
            return AdapterResult(success=False)


def create_mitigation_adapter(binary_path: str) -> MitigationAdapter:
    return MitigationAdapter(binary_path)
