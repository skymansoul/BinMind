"""
自动化补丁影响分析模块

功能:
    1. 对比补丁前后二进制, 定位修复点
    2. 分析数据流/控制流变化对所有调用者的影响
    3. 评估补丁是否引入新危险函数调用或移除安全检查
    4. 输出风险评分

核心技术:
    - 二进制 diff (radare2 cDiff / 自研)
    - 函数指纹 (Capstone 标准化)
    - 跨函数影响传播 (调用图 BFS)
    - 危险函数白名单 + 新增/移除检测
"""

import logging
import os
import json
import hashlib
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class ChangeKind(Enum):
    """变更类型"""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


@dataclass
class FunctionFingerprint:
    """函数指纹"""
    name: str
    address: int
    size: int
    instr_count: int
    calls: List[str] = field(default_factory=list)
    blocks: int = 0
    has_loop: bool = False
    calls_dangerous: List[str] = field(default_factory=list)
    has_security_check: bool = False
    raw_hash: str = ""


@dataclass
class PatchChange:
    """单个函数的变更"""
    func_name: str
    kind: ChangeKind
    before: Optional[FunctionFingerprint] = None
    after: Optional[FunctionFingerprint] = None
    diff_summary: str = ""
    risk_delta: int = 0
    impact_callers: List[str] = field(default_factory=list)


@dataclass
class PatchImpactReport:
    """补丁影响报告"""
    binary_before: str
    binary_after: str
    changes: List[PatchChange] = field(default_factory=list)
    new_dangerous_calls: List[str] = field(default_factory=list)
    removed_security_checks: List[str] = field(default_factory=list)
    overall_risk_score: int = 0
    risk_level: str = "low"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'binary_before': self.binary_before,
            'binary_after': self.binary_after,
            'changes': [
                {
                    'func_name': c.func_name,
                    'kind': c.kind.value,
                    'diff_summary': c.diff_summary,
                    'risk_delta': c.risk_delta,
                    'impact_callers': c.impact_callers
                }
                for c in self.changes
            ],
            'new_dangerous_calls': self.new_dangerous_calls,
            'removed_security_checks': self.removed_security_checks,
            'overall_risk_score': self.overall_risk_score,
            'risk_level': self.risk_level,
            'metadata': self.metadata
        }


class FunctionFingerprinter:
    """函数指纹提取 (基于 r2)"""

    DANGEROUS = {
        "strcpy", "strcat", "sprintf", "gets", "scanf", "vsprintf",
        "system", "execve", "popen", "execl", "execlp",
        "memcpy", "memmove",
        "free", "malloc", "realloc", "calloc"
    }

    SECURITY_CHECK_PATTERNS = [
        r"if\s*\(.*len\s*[<>=]",
        r"if\s*\(.*size\s*[<>=]",
        r"if\s*\(.*null\s*\)?\s*[!=]=\s*null",
        r"__stack_chk_fail",
        r"bounds_check",
        r"canary"
    ]

    def __init__(self, r2_path: str = "r2"):
        self.r2_path = r2_path

    def fingerprint(self, binary_path: str, func_name: str) -> Optional[FunctionFingerprint]:
        try:
            import subprocess
            cmd = [self.r2_path, '-q', '-c', f'pdf @ {func_name}; afi @ {func_name}; q',
                   binary_path]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            output = result.stdout
            return self._parse(output, func_name)
        except Exception as e:
            logger.warning(f"函数指纹提取失败 {func_name}: {e}")
            return None

    def _parse(self, output: str, func_name: str) -> FunctionFingerprint:
        calls: List[str] = []
        calls_dangerous: List[str] = []
        instr_count = 0
        blocks = 0
        has_loop = False
        for line in output.split("\n"):
            stripped = line.strip()
            if "call " in stripped or "call sym." in stripped or "call 0x" in stripped:
                m = re.search(r"call\s+(?:sym\.)?(\w+)", stripped)
                if m:
                    name = m.group(1)
                    calls.append(name)
                    if name in self.DANGEROUS:
                        calls_dangerous.append(name)
            instr_count += 1
            if stripped.startswith("0x") and (":" in stripped):
                blocks += 1
            if "jmp" in stripped and ("0x" in stripped) and stripped.count("0x") > 1:
                has_loop = True
        security = any(re.search(p, output, re.IGNORECASE)
                       for p in self.SECURITY_CHECK_PATTERNS)
        raw_hash = hashlib.sha256(output.encode("utf-8")).hexdigest()[:16]
        return FunctionFingerprint(
            name=func_name,
            address=0,
            size=0,
            instr_count=instr_count,
            calls=calls,
            blocks=blocks,
            has_loop=has_loop,
            calls_dangerous=calls_dangerous,
            has_security_check=security,
            raw_hash=raw_hash
        )


class PatchImpactAnalyzer:
    """补丁影响分析器"""

    def __init__(self, r2_path: str = "r2"):
        self.fp = FunctionFingerprinter(r2_path)

    def _list_functions(self, binary_path: str) -> List[str]:
        try:
            import subprocess
            result = subprocess.run(
                [self.fp.r2_path, '-q', '-c', 'afl;q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            funcs = []
            for line in result.stdout.split("\n"):
                # 格式: 0x...  N  func_name
                m = re.search(r"0x[0-9a-f]+\s+\d+\s+(\S.*)", line)
                if m:
                    funcs.append(m.group(1).strip())
            return funcs
        except Exception as e:
            logger.warning(f"函数列表获取失败: {e}")
            return []

    def _build_call_graph(self, binary_path: str,
                          funcs: List[str]) -> Dict[str, Set[str]]:
        """调用图: caller -> set(callees)"""
        g: Dict[str, Set[str]] = defaultdict(set)
        for fn in funcs:
            fp = self.fp.fingerprint(binary_path, fn)
            if not fp:
                continue
            for c in fp.calls:
                if c in funcs:
                    g[fn].add(c)
        return g

    def _propagate_impact(self, changed_funcs: List[str],
                          call_graph: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        """反向传播: 哪些 caller 受到变更影响"""
        impact: Dict[str, Set[str]] = {fn: set() for fn in changed_funcs}
        # 反向图
        reverse: Dict[str, Set[str]] = defaultdict(set)
        for caller, callees in call_graph.items():
            for c in callees:
                reverse[c].add(caller)
        for fn in changed_funcs:
            queue = deque(reverse.get(fn, []))
            while queue:
                cur = queue.popleft()
                impact[fn].add(cur)
                for nxt in reverse.get(cur, []):
                    if nxt not in impact[fn]:
                        queue.append(nxt)
        return impact

    def _score_change(self, before: Optional[FunctionFingerprint],
                      after: Optional[FunctionFingerprint]) -> Tuple[int, str]:
        """风险评分: -10 ~ +10, 越大越危险"""
        score = 0
        reasons: List[str] = []
        if before is None and after is not None:
            # 新增函数
            score += 2
            reasons.append("新增函数")
            score += len(after.calls_dangerous) * 3
            if after.calls_dangerous:
                reasons.append(f"调用危险函数: {after.calls_dangerous}")
        elif after is None and before is not None:
            # 删除函数
            score -= 1
            reasons.append("删除函数")
        else:
            # 修改
            if before and after:
                new_danger = set(after.calls_dangerous) - set(before.calls_dangerous)
                removed_danger = set(before.calls_dangerous) - set(after.calls_dangerous)
                score += len(new_danger) * 4
                score -= len(removed_danger) * 4
                if new_danger:
                    reasons.append(f"新增危险调用: {list(new_danger)}")
                if removed_danger:
                    reasons.append(f"移除危险调用: {list(removed_danger)}")
                if before.has_security_check and not after.has_security_check:
                    score += 6
                    reasons.append("移除了安全检查")
                elif not before.has_security_check and after.has_security_check:
                    score -= 6
                    reasons.append("新增了安全检查")
        return score, "; ".join(reasons)

    def analyze(self, binary_before: str, binary_after: str) -> PatchImpactReport:
        logger.info(f"[patch-impact] 开始分析: {binary_before} -> {binary_after}")
        funcs_a = set(self._list_functions(binary_before))
        funcs_b = set(self._list_functions(binary_after))

        # 完整调用图 (以 after 为准, 因为它代表当前状态)
        all_funcs = list(funcs_a | funcs_b)
        cg = self._build_call_graph(binary_after, all_funcs)

        added = funcs_b - funcs_a
        removed = funcs_a - funcs_b
        common = funcs_a & funcs_b

        changes: List[PatchChange] = []
        for fn in added:
            fp = self.fp.fingerprint(binary_after, fn)
            score, summary = self._score_change(None, fp)
            changes.append(PatchChange(
                func_name=fn, kind=ChangeKind.ADDED,
                after=fp, diff_summary=summary, risk_delta=score
            ))
        for fn in removed:
            fp = self.fp.fingerprint(binary_before, fn)
            score, summary = self._score_change(fp, None)
            changes.append(PatchChange(
                func_name=fn, kind=ChangeKind.REMOVED,
                before=fp, diff_summary=summary, risk_delta=score
            ))
        for fn in common:
            fb = self.fp.fingerprint(binary_before, fn)
            fa = self.fp.fingerprint(binary_after, fn)
            if not fb or not fa:
                continue
            if fb.raw_hash == fa.raw_hash:
                kind = ChangeKind.UNCHANGED
            else:
                kind = ChangeKind.MODIFIED
            score, summary = self._score_change(fb, fa)
            if kind == ChangeKind.UNCHANGED and score == 0:
                continue
            changes.append(PatchChange(
                func_name=fn, kind=kind,
                before=fb, after=fa, diff_summary=summary, risk_delta=score
            ))

        # 影响传播
        changed = [c.func_name for c in changes if c.kind != ChangeKind.UNCHANGED]
        impact = self._propagate_impact(changed, cg)
        for c in changes:
            c.impact_callers = sorted(list(impact.get(c.func_name, set())))

        # 汇总
        new_danger_calls: List[str] = []
        removed_checks: List[str] = []
        for c in changes:
            if c.kind == ChangeKind.ADDED and c.after and c.after.calls_dangerous:
                new_danger_calls.extend(c.after.calls_dangerous)
            if "移除了安全检查" in c.diff_summary:
                removed_checks.append(c.func_name)
        total_score = sum(c.risk_delta for c in changes)
        if total_score >= 15:
            level = "critical"
        elif total_score >= 8:
            level = "high"
        elif total_score >= 3:
            level = "medium"
        elif total_score >= 0:
            level = "low"
        else:
            level = "info"

        return PatchImpactReport(
            binary_before=binary_before,
            binary_after=binary_after,
            changes=changes,
            new_dangerous_calls=sorted(set(new_danger_calls)),
            removed_security_checks=sorted(set(removed_checks)),
            overall_risk_score=total_score,
            risk_level=level,
            metadata={
                'added_funcs': len(added),
                'removed_funcs': len(removed),
                'common_funcs': len(common),
                'modified_funcs': sum(1 for c in changes if c.kind == ChangeKind.MODIFIED)
            }
        )


def analyze_patch_impact(binary_before: str,
                         binary_after: str) -> Dict[str, Any]:
    analyzer = PatchImpactAnalyzer()
    report = analyzer.analyze(binary_before, binary_after)
    return {'success': True, 'report': report.to_dict()}
