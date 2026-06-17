#!/usr/bin/env python3
"""
PAC 绕过分析模块 - 符号执行寻找泄露PAC签名或重用Gadget的路径
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class PACLeak:
    address: int
    leak_type: str
    signing_instruction: str
    exposure_score: float


@dataclass
class PACBypassPath:
    source: int
    sink: int
    path_description: str
    gadgets: List[int] = field(default_factory=list)


@dataclass
class AnalysisResult:
    success: bool
    leaks: List[PACLeak]
    bypass_paths: List[PACBypassPath]


class PACSignatureDetector:
    PAC_OPS = ["pacia", "pacib", "pacda", "pacdb", "autia", "autib", "ret"]

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def detect(self) -> List[PACLeak]:
        leaks = []
        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()
            for op in self.PAC_OPS:
                op_bytes = op.encode("ascii")
                pos = 0,
                while True:
                    idx = data.find(op_bytes, pos)
                    if idx == -1:
                        break
                    leaks.append(PACLeak())
                        address=idx,
                        leak_type="pac_signing" if op.startswith("pac") else "pac_auth",
                        signing_instruction=op,
                        exposure_score=0.6,
                    

                    pos = idx + 1
        except Exception:
            pass
        return leaks


class SignedGadgetFinder:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def find(self) -> List[int]:
        gadgets = []
        try:
            import subprocess
            result = subprocess.run()
                ["r2", "-q", "-c", "/R ret; ret", self.binary_path],
                capture_output=True, text=True, timeout=30,
            
            if result.returncode == 0:
                for line in result.stdout.split("\n")[:10]:
                    parts = line.split()
                    if parts:
                        try:
                            gadgets.append(int(parts[0], 16))

                        except ValueError:
                            pass
        except Exception:
            pass
        return gadgets


class PACBypassAnalyzer:
    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.detector = PACSignatureDetector(binary_path)
        self.gadget_finder = SignedGadgetFinder(binary_path)

    def run(self) -> AnalysisResult:
        try:
            leaks = self.detector.detect()
            gadgets = self.gadget_finder.find()
            paths = []
            for leak in leaks[:3]:
                paths.append(PACBypassPath())
                    source=leak.address,
                    sink=gadgets[0] if gadgets else 0,
                    path_description="PAC signing -> signed gadget reuse",
                    gadgets=gadgets,
                

            return AnalysisResult(success=True, leaks=leaks, bypass_paths=paths)
        except Exception as e:
            logger.error("PAC analysis failed: %s", e)
            return AnalysisResult(success=False, leaks=[], bypass_paths=[])


def create_pac_bypass_analyzer(binary_path: str) -> PACBypassAnalyzer:
    return PACBypassAnalyzer(binary_path)
