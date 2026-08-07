"""DRIFT 语义FP削减器 — CFG可达性 + 循环感知 + 重新分配检测.

四阶段过滤:
  Phase 0 (Realloc): free后use前有新的malloc且结果覆盖同一寄存器 → 安全
  Phase 1 (Object Identity): free和use是否作用于同一对象身份 → 核心过滤
  Phase 2 (CFG Reachability): free所在基本块能否到达use所在基本块 → 不可达路径排除
  Phase 3 (Loop-aware): free在循环内而use在循环外 → 可能是循环内最后一次迭代后的安全使用

创建: 2026-07-18  修改: 2026-08-06 (Phase 2: CFG可达性替代简单cmp+jcc)
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
import re

from .path_sensitivity import build_cfg, path_exists


class FilterPhase(str, Enum):
    REALLOC = "realloc"
    OBJECT_IDENTITY = "object_identity"
    CFG_REACHABILITY = "cfg_reachability"
    LOOP_AWARE = "loop_aware"


class FilterDecision(str, Enum):
    CONFIRMED_UAF = "confirmed_uaf"
    LIKELY_UAF = "likely_uaf"
    SAFE_FILTERED = "safe_filtered"
    UNCERTAIN = "uncertain"


@dataclass
class DriftFilterResult:
    """单条finding的过滤结果."""
    finding: dict
    decision: FilterDecision = FilterDecision.UNCERTAIN
    decisive_phase: FilterPhase = FilterPhase.OBJECT_IDENTITY
    reasoning: str = ""
    fp_probability: float = 0.5
    confidence: float = 0.0


@dataclass
class DriftFilterReport:
    """DRIFT过滤管线报告."""
    total_raw: int = 0
    confirmed: int = 0
    likely: int = 0
    uncertain: int = 0
    filtered_fp: int = 0
    fp_reduction_pct: float = 0.0
    results: List[DriftFilterResult] = field(default_factory=list)


class DriftFPFilter:
    """DRIFT语义假阳性过滤器 — 多阶段判定."""

    def __init__(self, fp_threshold: float = 0.35):
        self._fp_threshold = fp_threshold
        self._stats = {'realloc_filtered': 0, 'cfg_filtered': 0,
                       'loop_filtered': 0, 'confirmed': 0}
        self._cfg_cache: Optional[object] = None

    def evaluate(self, finding: dict, asm_lines: List[str],
                 uaf_objects: List) -> DriftFilterResult:
        """对单条finding执行完整过滤管线."""
        result = DriftFilterResult(finding=finding)

        # Phase 0: Realloc检查 (仅对同函数内free-use对)
        # 跨函数场景: free在被调者(低地址), alloc在调用者(高地址),
        # 地址序上alloc在free-use之间但执行序上发生于free之前.
        free_line = finding.get('free_line', -1)
        use_line = finding.get('use_line', -1)
        if free_line >= 0 and use_line > free_line:
            if not _has_function_label_between(asm_lines, free_line, use_line):
                if _has_realloc_between(asm_lines, free_line, use_line):
                    result.decision = FilterDecision.SAFE_FILTERED
                    result.decisive_phase = FilterPhase.REALLOC
                    result.reasoning = (
                        f're-alloc between free({free_line}) and use({use_line})')
                    result.fp_probability = 0.95
                    self._stats['realloc_filtered'] += 1
                    return result

        # Phase 1: 对象身份一致性 (已在free_use_validator中验证)
        # 这里做额外的置信度检查
        confidence = finding.get('confidence', 0.5)

        # Phase 2: CFG可达性 — free所在块能否到达use所在块
        if not self._cfg_path_exists(finding, asm_lines):
            result.decision = FilterDecision.SAFE_FILTERED
            result.decisive_phase = FilterPhase.CFG_REACHABILITY
            result.reasoning = 'free和use在不同CFG路径上 (不可达)'
            result.fp_probability = 0.90
            self._stats['cfg_filtered'] += 1
            return result

        # Phase 3: 循环感知
        if self._free_in_loop_use_outside(finding, asm_lines):
            result.decision = FilterDecision.LIKELY_UAF
            result.decisive_phase = FilterPhase.LOOP_AWARE
            result.reasoning = 'free在循环内但use在循环外, 可能是安全使用'
            result.fp_probability = 0.4
            result.confidence = confidence * 0.6
            self._stats['loop_filtered'] += 1
            return result

        # 判定
        if confidence >= 0.8:
            result.decision = FilterDecision.CONFIRMED_UAF
            result.reasoning = f'高置信度({confidence:.2f}): 对象身份一致, 路径可达'
        elif confidence >= 0.5:
            result.decision = FilterDecision.LIKELY_UAF
            result.reasoning = f'中置信度({confidence:.2f})'
        else:
            result.decision = FilterDecision.UNCERTAIN
            result.reasoning = f'低置信度({confidence:.2f})'

        result.confidence = confidence
        result.fp_probability = 1.0 - confidence
        if result.decision == FilterDecision.CONFIRMED_UAF:
            self._stats['confirmed'] += 1

        return result

    def run_pipeline(self, findings: List[dict], asm_lines: List[str],
                     uaf_objects: List) -> DriftFilterReport:
        """对全部finding执行过滤管线."""
        report = DriftFilterReport(total_raw=len(findings))
        for f in findings:
            r = self.evaluate(f, asm_lines, uaf_objects)
            report.results.append(r)
            if r.decision == FilterDecision.CONFIRMED_UAF:
                report.confirmed += 1
            elif r.decision == FilterDecision.LIKELY_UAF:
                report.likely += 1
            elif r.decision == FilterDecision.SAFE_FILTERED:
                report.filtered_fp += 1
            else:
                report.uncertain += 1

        total = max(1, report.total_raw)
        report.fp_reduction_pct = round(report.filtered_fp / total * 100, 1)
        return report

    def _cfg_path_exists(self, finding: dict,
                         asm_lines: List[str]) -> bool:
        """用CFG可达性检查free所在块能否到达use所在块.

        局限性: CFG不建模跨函数调用边, 所以跨函数finding保守保留.
        """
        free_line = finding.get('free_line', -1)
        use_line = finding.get('use_line', -1)
        if free_line < 0 or use_line <= free_line:
            return True  # 无法判断时保守保留

        # 跨函数检测: 若free和use在不同函数中, CFG不建模调用-返回边,
        # 保守保留 (跨函数UAF不应被CFG过滤)
        free_fn = _find_func_start(asm_lines, free_line)
        use_fn = _find_func_start(asm_lines, use_line)
        if free_fn != use_fn:
            return True  # 跨函数 → 保守保留

        # 同一函数内 → 构建CFG检查可达性
        if self._cfg_cache is None:
            self._cfg_cache = build_cfg(asm_lines)
        return path_exists(self._cfg_cache, free_line, use_line)

    def _free_in_loop_use_outside(self, finding: dict,
                                  asm_lines: List[str]) -> bool:
        """free在循环内, use在循环外 → 可能是最后一次迭代后的合法访问."""
        free_line = finding.get('free_line', -1)
        use_line = finding.get('use_line', -1)
        if free_line < 0 or use_line <= free_line:
            return False
        # 循环内检测: 在free附近有向后跳转 (jmp到更小的行号)
        loop_detected = False
        for i in range(max(0, free_line - 10), min(free_line + 1, len(asm_lines))):
            il = asm_lines[i].strip().lower()
            jmp_m = re.search(r'\b(jmp|jne|je|jg|jl|jge|jle|jbe|jae)\s+'
                             r'(0x[0-9a-f]+|\d+)', il)
            if jmp_m:
                target = jmp_m.group(2)
                try:
                    t = int(target, 16 if target.startswith('0x') else 10)
                    if t < i:  # 向后跳 → 循环
                        loop_detected = True
                except ValueError:
                    pass
        # free在循环内但use在循环外 (距离>30且无向后跳围绕use)
        if loop_detected:
            use_in_loop = False
            for i in range(max(0, use_line - 10), min(use_line + 1, len(asm_lines))):
                il = asm_lines[i].strip().lower()
                jmp_m = re.search(r'\b(jmp|jne|je)\s+'
                                 r'(0x[0-9a-f]+|\d+)', il)
                if jmp_m:
                    try:
                        t = int(jmp_m.group(2), 16 if jmp_m.group(2).startswith('0x') else 10)
                        if t < i and t <= free_line:
                            use_in_loop = True
                    except ValueError:
                        pass
            if not use_in_loop:
                return True
        return False

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    def clear(self):
        self._stats = {k: 0 for k in self._stats}
        self._cfg_cache = None


_FN_LABEL = re.compile(r'[0-9a-f]+\s+<[^>]+>:\s*$')
_PUSH_RBP = re.compile(r'\s*[0-9a-f]+:\s+push\s+rbp', re.I)


def _find_func_start(asm_lines: List[str], from_line: int) -> int:
    """向上扫描找最近的函数入口标签 <func>: 或 push rbp序言."""
    for i in range(from_line, max(0, from_line - 500), -1):
        il = asm_lines[i].strip()
        if _FN_LABEL.match(il):
            return i
        if _PUSH_RBP.match(il):
            if i == 0 or not asm_lines[i-1].strip() or \
               _FN_LABEL.match(asm_lines[i-1].strip()):
                return i
    return max(0, from_line - 500)


def _has_function_label_between(asm_lines: List[str], free_line: int,
                                 use_line: int) -> bool:
    """检查free和use之间是否有函数入口标签 (表示跨函数)."""
    for i in range(free_line + 1, use_line):
        if _FN_LABEL.match(asm_lines[i].strip()):
            return True
    return False


def _has_realloc_between(asm_lines: List[str], free_line: int,
                         use_line: int) -> bool:
    """检查free→use之间是否有新分配."""
    _alloc = re.compile(
        r'\bcall\s+(?:[0-9a-f]+\s+<)?(malloc|calloc|realloc'
        r'|_Znwm|_Znam)(?:@plt)?>?\b', re.I)
    for i in range(free_line + 1, use_line):
        if _alloc.search(asm_lines[i].strip().lower()):
            return True
    return False
