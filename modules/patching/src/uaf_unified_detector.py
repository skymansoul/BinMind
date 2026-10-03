# UAF统一检测器 — 双引擎+路径验证+DoubleFree+严重度分类
"""统一UAF检测器 — 整合前向+后向双引擎 + 路径可行性 + DoubleFree。

Phase 1: PointerLifecycleTracker前向追踪 → 函数内UAF
Phase 2: DemandDrivenUAFAnalyzer后向分析 → 全局指针UAF
Phase 3: UAFPathVerifier路径验证 → 消除不可达路径FP
Phase 4: DoubleFree检测 → 同指针双重释放
Phase 5: 严重度分类 → CRITICAL/HIGH/MEDIUM/LOW/NONE

此模块替代旧版单一前向UAF检测, 为UAF二级创新深挖的核心集成点。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional

_log = logging.getLogger(__name__)


@dataclass
class UAFSeverity:
    """UAF严重度分类。"""
    level: str = "NONE"
    score: float = 0.0
    reason: str = ""


@dataclass
class DoubleFreeAlert:
    """双重释放告警。"""
    alloc_line: int = -1
    first_free_line: int = -1
    second_free_line: int = -1
    allocated_by: str = ""
    confidence: float = 0.0


@dataclass
class UnifiedUAFReport:
    """统一UAF检测报告 (整合前向+后向+DoubleFree)。"""
    function_name: str = ""
    forward_uaf_count: int = 0
    forward_findings: List[str] = field(default_factory=list)
    demand_uaf_paths: int = 0
    demand_confirmed: int = 0
    demand_filtered: int = 0
    double_free_alerts: List[DoubleFreeAlert] = field(default_factory=list)
    total_confirmed: int = 0
    total_filtered: int = 0
    severity: UAFSeverity = field(default_factory=UAFSeverity)
    phase_contributions: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'function': self.function_name,
            'forward_uaf': self.forward_uaf_count,
            'demand_paths': self.demand_uaf_paths,
            'demand_confirmed': self.demand_confirmed,
            'demand_filtered': self.demand_filtered,
            'double_free': len(self.double_free_alerts),
            'total_confirmed': self.total_confirmed,
            'severity': self.severity.level,
            'severity_score': self.severity.score,
            'forward_findings': self.forward_findings[:10],
            'phase_contributions': self.phase_contributions,
        }


# UnifiedUAFDetector

class UnifiedUAFDetector:
    """统一UAF检测器 — 前向+后向双引擎 + 路径验证 + DoubleFree。

    用法:
        detector = UnifiedUAFDetector()
        report = detector.detect(asm_lines, function_name)
    """

    def __init__(self):
        from .uaf_analyzer import PointerLifecycleTracker
        self._forward = PointerLifecycleTracker()
        self._demand = None
        self._verifier = None

    @property
    def _demand_analyzer(self):
        if self._demand is None:
            from .uaf_demand_driven import DemandDrivenUAFAnalyzer
            self._demand = DemandDrivenUAFAnalyzer()
        return self._demand

    @property
    def _path_verifier(self):
        if self._verifier is None:
            # 优先v2 (NULL矛盾+值范围+约束交集), 回退v1
            try:
                from .uaf_path_verifier_v2 import filter_uaf_paths_v2
                self._verifier = filter_uaf_paths_v2
            except ImportError:
                from .uaf_path_verifier import filter_uaf_paths
                self._verifier = filter_uaf_paths
        return self._verifier

    @property
    def _pointer_engine(self):
        if not hasattr(self, '_ptr_engine'):
            from .uaf_pointer_engine import UafPointerEngine
            self._ptr_engine = UafPointerEngine()
        return self._ptr_engine

    def detect(self, asm_lines: List[str],
               function_name: str = "") -> UnifiedUAFReport:
        report = UnifiedUAFReport(function_name=function_name)
        # Phase 1: 前向追踪
        fwd = self._forward.analyze(asm_lines, function_name)
        report.forward_uaf_count = fwd.uaf_count
        report.forward_findings = fwd.findings
        # Phase 2: 后向demand-driven
        dd = self._demand_analyzer.analyze(asm_lines, function_name)
        report.demand_uaf_paths = len(dd.uaf_paths)
        # Phase 3: 路径验证
        result = self._path_verifier(dd, asm_lines)
        if len(result) == 3:
            verified, fp_pct, _ = result  # v2返回3元组
        else:
            verified, fp_pct = result     # v1返回2元组
        vc = sum(1 for p in verified if p.path_feasible and not p.realloc_on_path)
        fc = sum(1 for p in verified if not p.path_feasible or p.realloc_on_path)
        report.demand_confirmed, report.demand_filtered = vc, fc
        # Phase 4: DoubleFree
        df = self._detect_double_free(asm_lines)
        report.double_free_alerts = df
        # Phase 5: 汇总 + 严重度
        report.total_confirmed = (report.forward_uaf_count + vc
                                - self._est_overlap(fwd, vc))
        report.total_filtered = fc + fwd.false_positive_candidates
        report.severity = self._classify(report)
        report.phase_contributions = {
            'forward': f'前向: {fwd.uaf_count}UAF',
            'demand': f'后向: {len(dd.uaf_paths)}路径',
            'path_verify': f'过滤{fc}FP, 削减{round(fp_pct,1)}%',
            'double_free': f'DoubleFree: {len(df)}',
        }
        # Phase 6: 新指针引擎增强 (UafPointerEngine入口)
        try:
            ptr_objs = self._pointer_engine.trace_forward(asm_lines)
            ptr_uafs = self._pointer_engine.find_uaf_in_forward(asm_lines, ptr_objs)
            extra_confirmed = len(ptr_uafs)
            if extra_confirmed:
                report.total_confirmed += extra_confirmed
            report.phase_contributions['ptr_engine'] = (
                f'指针引擎: +{extra_confirmed}UAF (跨别名)')
        except Exception:
            report.phase_contributions['ptr_engine'] = '指针引擎: N/A (fallback)'
        return report

    def _detect_double_free(self, asm: List[str]) -> List[DoubleFreeAlert]:
        alerts = []
        allocs, pairs = {}, set()
        for i, line in enumerate(asm):
            m = re.search(r'\bcall\s+(?:[0-9a-f]+\s+<)?(malloc|calloc|realloc|_Znwm)(?:@plt)?>?\b', line, re.I)
            if m:
                allocs[i] = m.group(1).lower()
                continue
            m = re.search(r'\bcall\s+(?:[0-9a-f]+\s+<)?(free|delete|_ZdlPv)(?:@plt)?>?\b', line, re.I)
            if not m:
                continue
            recent = max((a for a in allocs if a < i), default=-1)
            if recent < 0:
                continue
            pair = (recent, i)
            for ex in pairs:
                if ex[0] == recent and ex[1] != i:
                    alerts.append(DoubleFreeAlert(alloc_line=recent,
                        first_free_line=ex[1], second_free_line=i,
                        allocated_by=allocs[recent], confidence=0.85))
            pairs.add(pair)
        return alerts

    @staticmethod
    def _est_overlap(fwd, vc: int) -> int:
        return max(0, int(min(fwd.uaf_count if fwd else 0, vc) * 0.2))

    @staticmethod
    def _classify(report) -> UAFSeverity:
        total = report.total_confirmed + len(report.double_free_alerts)
        df = len(report.double_free_alerts)
        if total == 0:
            return UAFSeverity(level="NONE", score=0.0)
        score = min(report.total_confirmed * 0.15, 0.4) + df * 0.25
        if report.forward_uaf_count > 0 and report.demand_confirmed > 0:
            score += 0.15
        if df > 0:
            score += 0.1
        if score >= 0.8:
            return UAFSeverity(level="CRITICAL", score=score,
                reason=f"{total}个(含{df}DoubleFree), 双重验证")
        elif score >= 0.5:
            return UAFSeverity(level="HIGH", score=score)
        elif score >= 0.3:
            return UAFSeverity(level="MEDIUM", score=score)
        return UAFSeverity(level="LOW", score=score)
