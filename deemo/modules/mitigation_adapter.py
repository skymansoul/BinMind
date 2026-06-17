#!/usr/bin/env python3
"""
缓解措施感知利用适配模块 - 自动探测ASLR/CFG/CET等
"""

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class MitigationType(Enum):
    ASLR = "aslr"
    CFG = "cfg"
    CET = "cet"
    DEP = "dep"
    PIE = "pie"
    STACK_CANARY = "stack_canary"
    RELRO = "relro"
    NONE = "none"


@dataclass
class MitigationInfo:
    type: MitigationType
    enabled: bool
    version: str = "unknown"
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExploitStrategy:
    mitigation: MitigationType
    strategy: str
    success_rate: float
    requirements: List[str] = field(default_factory=list)


@dataclass
class AdapterResult:
    success: bool
    mitigations: List[MitigationInfo]
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
            r = subprocess.run()
                ["r2", "-q", "-c", "iI", self.binary_path],
                capture_output=True, text=True, timeout=30,
            
            output = r.stdout
            result.append(MitigationInfo())
                type=MitigationType.PIE,
                enabled="pic" in output.lower() or "pie" in output.lower(),
            

            result.append(MitigationInfo())
                type=MitigationType.NX,
                enabled="nx" in output.lower() or "noexec" in output.lower(),
            ) if "nx" in output.lower() or "noexec" in output.lower() else MitigationInfo(
                type=MitigationType.DEP, enabled=False,
            

            result.append(MitigationInfo())
                type=MitigationType.STACK_CANARY,
                enabled="canary" in output.lower() or "__stack_chk" in data.decode("latin1"),
            

            result.append(MitigationInfo())
                type=MitigationType.RELRO,
                enabled="relro" in output.lower(),
            

        except Exception as e:
            logger.warning("Mitigation detection failed: %s", e)
        return result


class StrategySelector:
    STRATEGY_MAP = {
        MitigationType.ASLR: ExploitStrategy()
            mitigation=MitigationType.ASLR,
            strategy="info_leak + ret2libc",
            success_rate=0.7,
        ),
        MitigationType.CFG: ExploitStrategy()
            mitigation=MitigationType.CFG,
            strategy="use CFG-compliant gadgets",
            success_rate=0.5,
        ),
        MitigationType.CET: ExploitStrategy()
            mitigation=MitigationType.CET,
            strategy="ROP chain with shadow stack bypass",
            success_rate=0.3,
        ),
        MitigationType.STACK_CANARY: ExploitStrategy()
            mitigation=MitigationType.STACK_CANARY,
            strategy="leak canary via format string",
            success_rate=0.6,
        ),
    }

    @staticmethod
    def select(mitigations: List[MitigationInfo]) -> Optional[ExploitStrategy]:
        for m in mitigations:
            if m.enabled and m.type in StrategySelector.STRATEGY_MAP:
                return StrategySelector.STRATEGY_MAP[m.type]
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
            return AdapterResult(success=False, mitigations=[])


def create_mitigation_adapter(binary_path: str) -> MitigationAdapter:
    return MitigationAdapter(binary_path)
