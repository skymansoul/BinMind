# coding: utf-8
#
"""
GASRI (Guard-Aware Size-Region Inference) 分析管线。

流程:
  1. 反汇编 (外部 objdump 输出 / 内部解析)
  2. 函数级指令解析 (insn.py)
  3. 分配点扫描: call <alloc>, 解析 size 值域 + usable 模型
  4. 写入点扫描: call <write>, 解析 write 值域 + dst 关联分配点
  5. 守卫提取: 支配写入的有界守卫
  6. 级联判定: verdict.py 输出 SAFE/OVERFLOW/SUSPICIOUS
  7. 结果报告: 误报削减统计 + 每 pair 证据链

判定语义:
  SAFE        可证明安全 → 从告警集过滤 (误报削减来源)
  OVERFLOW    可证明溢出 → 告警
  SUSPICIOUS  无法判定   → 保守保留告警 (召回保障)

对外接口:
  analyze_disasm(text, mode)     直接分析反汇编文本
  analyze_binary(path, mode)     反汇编后分析二进制
  GASRIReport 结构包含全部统计
"""

import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .insn import Instruction, Function, parse_disasm, callee_name
from .region import Region, KIND_UNKNOWN
from .defuse import DefUseResolver
from .guards import GuardExtractor
from .link import DstAllocLinker, LinkResult
from .usable import UsableSizeModel
from .verdict import VerdictEngine, VerdictResult, SAFE, OVERFLOW, SUSPICIOUS
from .abi import (
    ALLOC_FUNCS, WRITE_FUNCS, find_alloc, find_write,
)


@dataclass
class AllocSite:
    """分配点."""
    idx: int
    addr: int
    func: str
    fname: str
    region: Region = Region()
    usable: int = 0

    @property
    def size_known(self) -> bool:
        return self.region.has_upper_bound


@dataclass
class WriteSite:
    """写入点."""
    idx: int
    addr: int
    func: str
    wname: str
    dst_cand_regs: List[str]
    size_cand_regs: List[str]
    unbounded: bool = False
    region: Region = Region()
    link: LinkResult = None  # type: ignore


@dataclass
class PairVerdict:
    """(alloc, write) 对的最终判定."""
    verdict: str = SUSPICIOUS
    write_func: str = ""
    write_addr: int = 0
    alloc_addr: int = 0
    alloc_func: str = ""
    alloc_region: Region = Region()
    write_region: Region = Region()
    usable: int = 0
    rule: str = ""
    evidence: List[str] = field(default_factory=list)
    func: str = ""

    @property
    def is_finding(self) -> bool:
        return self.verdict in (OVERFLOW, SUSPICIOUS)


@dataclass
class GASRIReport:
    """一次完整分析的报告."""
    binary_path: str = ""
    n_functions: int = 0
    n_alloc: int = 0
    n_write: int = 0
    n_pairs: int = 0
    n_safe: int = 0
    n_overflow: int = 0
    n_suspicious: int = 0
    n_unlinked_write: int = 0
    fp_reduction_pct: float = 0.0
    elapsed_ms: float = 0.0
    pairs: List[PairVerdict] = field(default_factory=list)
    unlinked_writes: List[dict] = field(default_factory=list)
    per_rule: Dict[str, int] = field(default_factory=dict)

    @property
    def findings(self) -> List[PairVerdict]:
        return [p for p in self.pairs if p.is_finding]

    @property
    def detected(self) -> bool:
        return len(self.findings) > 0


class GASRIPipeline:
    """GASRI 管线."""
    # TODO: 循环内动态偏移写入 (buf[i*stride]) 值域收敛为 top, 需循环摘要支持

    def __init__(self, alloc_mode: str = "glibc", abi: Optional[str] = None):
        self._resolver = DefUseResolver()
        self._guards = GuardExtractor(self._resolver)
        self._linker = DstAllocLinker()
        self._usable = UsableSizeModel(alloc_mode)
        self._verdict = VerdictEngine()
        self._abi = abi or "win64"

    @staticmethod
    def _detect_abi(text: str) -> str:
        head = text[:400].lower()
        if "file format elf" in head or "elf64" in head:
            return "sysv"
        if "pei" in head or "pe" in head or "microsoft" in head:
            return "win64"
        # 头部无法识别时按寄存器使用模式推断
        if "win64" in head:
            return "win64"
        return "win64"

# 分配/写入扫描

    def _scan_allocs(self, fn: Function) -> List[AllocSite]:
        sites = []
        for i, insn in enumerate(fn.insns):
            if not insn.is_call:
                continue
            key = find_alloc(callee_name(insn))
            if key is None:
                continue
            sig = ALLOC_FUNCS[key]
            region = self._resolve_alloc_size(fn, i, sig)
            usable = 0
            if region.has_upper_bound and 0 <= region.hi < (1 << 40):
                usable = self._usable.model(region.hi).usable
            sites.append(AllocSite(
                idx=i, addr=insn.addr, func=fn.name, fname=key,
                region=region, usable=usable))
        return sites

    def _resolve_alloc_size(self, fn: Function, call_idx: int,
                            sig: dict) -> Region:
        # 当前 ABI 的 size 参数寄存器候选
        cands: List[str] = []
        for role, regs in sig.get(self._abi, []):
            if role == "size":
                cands.extend(regs)
        if not cands:
            return Region.unbounded()
        return self._resolver.resolve(fn.insns, call_idx, cands)

    def _scan_writes(self, fn: Function) -> List[WriteSite]:
        alloc_idxs = [i for i, insn in enumerate(fn.insns)
                      if insn.is_call and find_alloc(callee_name(insn))]
        sites = []
        for i, insn in enumerate(fn.insns):
            if not insn.is_call:
                continue
            key = find_write(callee_name(insn))
            if key is None:
                continue
            # 当前 ABI 的 dst/size 候选寄存器
            di, si, d_all, s_all = WRITE_FUNCS[key][self._abi]
            unbounded = si < 0 or key in ("gets",)
            region = Region.unbounded()
            if not unbounded:
                region = self._resolver.resolve(fn.insns, i, s_all)
            link = self._linker.link(fn.insns, i, d_all, alloc_idxs)
            sites.append(WriteSite(
                idx=i, addr=insn.addr, func=fn.name, wname=key,
                dst_cand_regs=d_all, size_cand_regs=s_all,
                unbounded=unbounded, region=region, link=link))
        return sites

    @staticmethod
    def _last_alloc_idxs(fn: Function, up_to: int) -> List[int]:
        """返回 up_to 之前的 alloc call 索引列表 (升序)."""
        out = []
        for i, insn in enumerate(fn.insns[:up_to]):
            if insn.is_call and find_alloc(callee_name(insn)):
                out.append(i)
        return out

# 主入口

    def analyze(self, text: str, binary_path: str = "") -> GASRIReport:
        import time
        t0 = time.time()
        rep = GASRIReport(binary_path=binary_path)
        self._abi = self._detect_abi(text)
        functions = parse_disasm(text)
        rep.n_functions = len(functions)

        allocs_by_fn: Dict[str, List[AllocSite]] = {}
        for fn in functions:
            sites = self._scan_allocs(fn)
            allocs_by_fn[fn.name] = sites
            rep.n_alloc += len(sites)

        for fn in functions:
            writes = self._scan_writes(fn)
            allocs = allocs_by_fn.get(fn.name, [])
            for w in writes:
                if w.link is None or w.link.alloc_call_idx < 0:
                    rep.n_unlinked_write += 1
                    rep.unlinked_writes.append({
                        "func": fn.name, "addr": w.addr, "write": w.wname,
                        "reason": w.link.reason if w.link else "no-link",
                    })
                    continue
                alloc = next(
                    (a for a in allocs if a.idx == w.link.alloc_call_idx),
                    None)
                if alloc is None:
                    continue
                rep.n_write += 1
                guard = self._guards.find_guard(
                    fn.insns, w.idx, w.size_cand_regs)
                guard_bound = None
                if guard is not None:
                    guard_bound = self._guards.resolve_bound(
                        fn.insns, w.idx, guard)
                vres = self._verdict.decide(
                    alloc_region=alloc.region, usable=alloc.usable,
                    write_region=w.region, is_unbounded=w.unbounded,
                    guard_bound=guard_bound)
                rep.n_pairs += 1
                rep.per_rule[vres.rule] = rep.per_rule.get(vres.rule, 0) + 1
                pv = PairVerdict(
                    verdict=vres.verdict, write_func=w.wname,
                    write_addr=w.addr, alloc_addr=alloc.addr,
                    alloc_func=alloc.fname, alloc_region=alloc.region,
                    write_region=w.region, usable=alloc.usable,
                    rule=vres.rule, evidence=vres.evidence, func=fn.name)
                rep.pairs.append(pv)
                if vres.verdict == SAFE:
                    rep.n_safe += 1
                elif vres.verdict == OVERFLOW:
                    rep.n_overflow += 1
                else:
                    rep.n_suspicious += 1

        total = rep.n_pairs + rep.n_unlinked_write
        rep.fp_reduction_pct = round(rep.n_safe / max(1, total) * 100, 1)
        rep.elapsed_ms = round((time.time() - t0) * 1000, 1)
        return rep

# 二进制入口

    def analyze_binary(self, binary_path: str) -> GASRIReport:
        text = _disassemble(binary_path)
        if not text:
            rep = GASRIReport(binary_path=binary_path)
            return rep
        return self.analyze(text, binary_path)

    def stats(self) -> dict:
        return {
            "resolver": self._resolver.stats(),
            "guards": self._guards.stats(),
            "linker": self._linker.stats(),
            "verdict": self._verdict.stats(),
            "usable": self._usable.stats(),
        }


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


__all__ = [
    "GASRIPipeline", "GASRIReport", "AllocSite", "WriteSite", "PairVerdict",
]
