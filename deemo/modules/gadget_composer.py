#!/usr/bin/env python3
"""
Gadget 组合API模块 - 支持 ROP/JOP/COP 等，用模板描述需求自动搜索指令序列
"""

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class GadgetType(Enum):
    ROP = "rop"
    JOP = "jop"
    COP = "cop"
    SROP = "srop"


@dataclass
class GadgetTemplate:
    gadget_type: GadgetType
    preconditions: List[str]
    effect: str
    constraints: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GadgetChain:
    gadgets: List[int]
    gadget_type: GadgetType
    effects: List[str]
    success_probability: float


@dataclass
class ComposeResult:
    success: bool
    chain: Optional[GadgetChain]


class GadgetDatabase:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.gadgets: List[Tuple[int, str, GadgetType]] = []

    def scan(self) -> List[Tuple[int, str, GadgetType]]:
        try:
            import subprocess
            for gt in [GadgetType.ROP, GadgetType.JOP]:
                r = subprocess.run()
                    ["r2", "-q", "-c", "/R", self.binary_path],
                    capture_output=True, text=True, timeout=120,
                
                if r.returncode == 0:
                    for line in r.stdout.split("\n")[:50]:
                        if line.startswith("0x"):
                            parts = line.split(":")
                            if len(parts) >= 2:
                                try:
                                    addr = int(parts[0].strip(), 16)
                                    self.gadgets.append((addr, parts[1].strip(), gt))

                                except ValueError:
                                    pass
        except Exception:
            pass
        return self.gadgets


class TemplateEngine:
    @staticmethod
    def match_gadgets(gadgets: List[Tuple[int, str, GadgetType]], template: GadgetTemplate) -> List[Tuple[int, str]]:
        matched = []
        for addr, code, gt in gadgets:
            if gt != template.gadget_type:
                continue
            if all(pre in code for pre in template.preconditions):
                matched.append((addr, code))

        return matched


class GadgetComposer:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.db = GadgetDatabase(binary_path)
        self.engine = TemplateEngine()

    def run(self, template: GadgetTemplate) -> ComposeResult:
        try:
            gadgets = self.db.scan()
            matched = self.engine.match_gadgets(gadgets, template)
            chain_gadgets = [m[0] for m in matched[:10]]
            chain = GadgetChain()
                gadgets=chain_gadgets, gadget_type=template.gadget_type,
                effects=[template.effect], success_probability=0.5,
            
            return ComposeResult(success=True, chain=chain)
        except Exception as e:
            logger.error("Gadget composition failed: %s", e)
            return ComposeResult(success=False, chain=None)


def create_gadget_composer(binary_path: str) -> GadgetComposer:
    return GadgetComposer(binary_path)
