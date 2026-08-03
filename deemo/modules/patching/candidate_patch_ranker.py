"""
AgentRepair — 候选补丁排序器

三维加权排序：
    rank = w_verify * verify_score + w_static * static_score + w_scale * scale_score
验证结果权重最高 — 测试反馈优先。
改动规模越小越优 — 最小化补丁副作用面。
（参考 Agentic Program Repair [arXiv:2507.18755]；SynthFix [arXiv:2604.17184]）

边界条件：
  - validations 接受 ValidationResult 对象或状态字符串，缺失按 skipped 处理；
  - 稳定降序，同分保持原始顺序（rank 从 1 编号）；
  - 静态分以 0.5 为基线：命中正向安全模式加分，命中负向危险模式减分，
    裁剪至 [0, 1]。
"""
import re
from dataclasses import dataclass, field

# 正向模式 — 命中则静态分上浮
_POSITIVE_PATTERNS = [
    r'\b(strncpy|strlcpy|snprintf|vsnprintf|strcpy_s|sprintf_s)\s*\(',
    r'__builtin_(add|sub|mul)_overflow',
    r'(==|!=)\s*NULL',
    r'if\s*\([^\n]*[<>]=?',
    r'INT_MAX|SIZE_MAX|SSIZE_MAX',
    r'\bsizeof\s*\(',
    r'printf\s*\(\s*"',
]

# 负向模式 — 命中则静态分下浮
_NEGATIVE_PATTERNS = [
    r'\b(strcpy|strcat|sprintf|gets)\s*\(',
    r'\b(system|popen)\s*\(',
    r'\bfree\s*\(\s*\w+\s*\)\s*;',
    r'\bmalloc\s*\([^)]*\)\s*;',
]

# 验证状态 → 分值（skipped 赋中性 0.5，与无验证信息时置信一致）
_VALIDATION_SCORES = {
    'pass': 1.0,
    'warning': 0.6,
    'fail': 0.0,
    'skipped': 0.5,
}


@dataclass
class RankedCandidate:
    """排序结果中的单条候选条目。"""
    rank: int = 0
    candidate_id: str = ""
    patch_diff: str = ""
    description: str = ""
    route: str = ""
    family: str = ""
    static_score: float = 0.0
    change_scale: float = 1.0
    validation_status: str = "skipped"
    validation_score: float = 0.0
    rank_score: float = 0.0

    def to_dict(self):
        return {
            'rank': self.rank,
            'candidate_id': self.candidate_id,
            'route': self.route,
            'family': self.family,
            'static_score': round(self.static_score, 4),
            'change_scale': round(self.change_scale, 4),
            'validation_status': self.validation_status,
            'validation_score': round(self.validation_score, 4),
            'rank_score': round(self.rank_score, 4),
            'description': self.description,
            'patch_diff': self.patch_diff,
        }


class CandidatePatchRanker:
    """候选补丁排序器 — 静态分 + 规模分 + 验证分三维加权。"""

    _DEFAULT_WEIGHTS = {'verification': 0.5, 'static': 0.3, 'scale': 0.2}

    def __init__(self, weights=None):
        # 权重可配置；默认验证权重最高 — 反馈优先原则
        self._weights = weights or dict(self._DEFAULT_WEIGHTS)

    def rank(self, candidates, validations=None):
        """候选列表排序，返回 RankedCandidate 列表（降序）。

        candidates: dict 或带同名属性的对象（兼容 RepairCandidate）；
        validations: {candidate_id: ValidationResult | status_str}，可为空。
        """
        ranked = []
        for cand in candidates:
            cid = self._get(cand, 'candidate_id', '')
            patch = self._get(cand, 'patch_diff', '')
            desc = self._get(cand, 'description', '')
            route = self._get(cand, 'route', '')
            fam = self._get(cand, 'family', '')
            vstatus = self._validation_status(
                (validations or {}).get(cid) if validations else None)
            vscore = self._validation_score(vstatus)
            static = self._static_score(patch)
            scale = self._change_scale(patch)
            rank_score = (self._weights.get('verification', 0.5) * vscore
                          + self._weights.get('static', 0.3) * static
                          + self._weights.get('scale', 0.2) * scale)
            ranked.append(RankedCandidate(
                candidate_id=cid, patch_diff=patch, description=desc,
                route=route, family=fam,
                static_score=static, change_scale=scale,
                validation_status=vstatus, validation_score=vscore,
                rank_score=rank_score,
            ))
        # 稳定降序：同分保持原始顺序
        ranked.sort(key=lambda r: r.rank_score, reverse=True)
        for i, r in enumerate(ranked):
            r.rank = i + 1
        return ranked

    def summarize(self, ranked):
        """排序摘要文本 — 供报告合成器引用。"""
        if not ranked:
            return "no candidates ranked"
        lines = ["候选补丁排序（共 %d 条）:" % len(ranked)]
        for r in ranked:
            lines.append("  #%d %s route=%s status=%s score=%.3f%s" % (
                r.rank, r.candidate_id, r.route, r.validation_status,
                r.rank_score, (' :: ' + r.description) if r.description else ''))
        return '\n'.join(lines)

    # -- 评分原语 -------------------------------------------------------

    def _static_score(self, patch_diff):
        """静态分 — 基于补丁新增行的安全模式密度。"""
        blob = '\n'.join(
            l[1:] for l in patch_diff.split('\n')
            if l.startswith('+') and not l.startswith('+++'))
        if not blob.strip():
            return 0.5
        pos = sum(1 for p in _POSITIVE_PATTERNS if re.search(p, blob))
        neg = sum(1 for p in _NEGATIVE_PATTERNS if re.search(p, blob))
        score = 0.5 + pos * 0.15 - neg * 0.25
        return max(0.0, min(1.0, score))

    def _change_scale(self, patch_diff):
        """规模分 — 变更行越少越优，1/(1+n) 平滑递减。"""
        changed = sum(
            1 for l in patch_diff.split('\n')
            if (l.startswith('+') or l.startswith('-'))
            and not l.startswith('+++') and not l.startswith('---'))
        return 1.0 / (1.0 + changed)

    @staticmethod
    def _validation_status(val):
        """验证状态归一化为字符串。"""
        if val is None:
            return 'skipped'
        if isinstance(val, str):
            return val
        st = getattr(val, 'status', None)
        return st.value if hasattr(st, 'value') else (st or 'skipped')

    @staticmethod
    def _validation_score(status):
        """验证状态字符串 → 数值分值。"""
        return _VALIDATION_SCORES.get(status, 0.5)

    @staticmethod
    def _get(obj, key, default):
        """dict 或对象属性取值 — 兼容两种候选表示。"""
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)


def rank_candidates(candidates, validations=None, weights=None):
    """一步完成候选排序的便捷入口。"""
    ranker = CandidatePatchRanker(weights=weights)
    return ranker.rank(candidates, validations)
