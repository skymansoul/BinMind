# coding: utf-8
#
"""
UAF 指针来源归因 (UAF-PROV) 管线。

流程:
  1. 反汇编 (objdump) → 函数级指令解析
  2. 每函数: 站点扫描 → free 点 / 解引用点 (均解析到对象身份)
  3. free 之后的解引用配对 → 生命周期判定 (R1–R5)
  4. 报告: 每 free→use 对的判定规则与证据链

判定语义:
  UAF        同一对象 free 后使用, 无重分配 → 告警
  SAFE       不同对象 / 已重分配 → 滤除 (误报削减来源)
  SUSPICIOUS 无法归因 → 保守保留
"""

import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..heapver.insn import Instruction, parse_disasm

from .provenance import ProvenanceResolver, FreeSite, DerefSite
from .sites import SiteScanner
from .lifetime import (
    LifetimeVerifier, UafPairVerdict, UAF, SAFE, SUSPICIOUS,
)


@dataclass
class UAFReport:
    binary_path: str = ""
    n_functions: int = 0
    n_frees: int = 0
    n_derefs: int = 0
    n_pairs: int = 0
    n_uaf: int = 0
    n_safe: int = 0
    n_suspicious: int = 0
    fp_reduction_pct: float = 0.0
    elapsed_ms: float = 0.0
    pairs: List[UafPairVerdict] = field(default_factory=list)
    per_rule: Dict[str, int] = field(default_factory=dict)

    @property
    def findings(self) -> List[UafPairVerdict]:
        return [p for p in self.pairs if p.is_finding]

    @property
    def detected(self) -> bool:
        return len(self.findings) > 0


class UafProvenancePipeline:
    """UAF-PROV 管线."""
    # TODO: 跨函数 free/use 依赖调用图, 当前仅函数内配对

    def __init__(self):
        self._prov = ProvenanceResolver()
        self._scanner = SiteScanner(self._prov)
        self._lifetime = LifetimeVerifier()

    def analyze(self, text: str, binary_path: str = "") -> UAFReport:
        t0 = time.time()
        rep = UAFReport(binary_path=binary_path)
        functions = parse_disasm(text)
        rep.n_functions = len(functions)

        for fn in functions:
            insns = fn.insns
            frees, derefs = self._scanner.scan_function(insns, fn.name)
            if not frees:
                continue
            for f in frees:
                for d in derefs:
                    if d.idx <= f.idx:
                        continue
                    rep.n_pairs += 1
                    v = self._lifetime.decide(fn.name, f, d, insns)
                    rep.per_rule[v.rule] = rep.per_rule.get(v.rule, 0) + 1
                    rep.pairs.append(v)
                    if v.verdict == UAF:
                        rep.n_uaf += 1
                    elif v.verdict == SAFE:
                        rep.n_safe += 1
                    else:
                        rep.n_suspicious += 1

        rep.n_frees = self._prov.stats()["freed_resolved"]
        rep.n_derefs = self._prov.stats()["deref_resolved"]
        total = rep.n_pairs + rep.n_safe
        rep.fp_reduction_pct = round(rep.n_safe / max(1, total) * 100, 1)
        rep.elapsed_ms = round((time.time() - t0) * 1000, 1)
        return rep

    def analyze_binary(self, binary_path: str) -> UAFReport:
        text = _disassemble(binary_path)
        if not text:
            return UAFReport(binary_path=binary_path)
        return self.analyze(text, binary_path)

    def stats(self) -> dict:
        return {"prov": self._prov.stats(),
                "scanner": self._scanner.stats(),
                "lifetime": self._lifetime.stats()}


def _disassemble(binary_path: str) -> str:
    for tool in ("objdump", "llvm-objdump"):
        try:
            proc = subprocess.run(
                [tool, "-d", "-M", "intel", binary_path],
                capture_output=True, text=True, timeout=30)
            if proc.returncode == 0 and len(proc.stdout) > 100:
                return proc.stdout
        except Exception:
            continue
    return ""


__all__ = ["UafProvenancePipeline", "UAFReport"]
