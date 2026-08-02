# 2026-07-25
"""Patch diff minimizer — Dilipa [NDSS 2026] inspired diff reduction.

Dilipa 提出通过 AST-based IR 将源代码编辑映射回二进制 micropatch 的机制。
本模块实现其外围功能：对 patch diff 输出做最小化处理和语义分组，
消除冗余变更并提取安全关键变更。

核心操作:
  - 空行/空白变更移除
  - 连续变更合并 (hunk coalescing)
  - 语义分组 (将同一安全检查的多行变更归组)
  - 关键变更提取 (滤出仅影响安全属性的变更)
"""

import re, os, logging, difflib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

__lg = logging.getLogger(__name__)


class ChangeKind:
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    WHITESPACE = "whitespace"    # 仅空白变更 — 可忽略
    COMMENT = "comment"          # 仅注释变更 — 可忽略
    SECURITY = "security"        # 安全关键变更
    REFACTOR = "refactor"        # 重构变更 — 非安全


@dataclass
class DiffHunk:
    """单个 diff hunk — 连续的变更行组。"""
    header: str = ""             # @@ -a,b +c,d @@ context
    original_start: int = 0
    original_count: int = 0
    patch_start: int = 0
    patch_count: int = 0
    added_lines: List[str] = field(default_factory=list)
    removed_lines: List[str] = field(default_factory=list)
    context_lines: List[str] = field(default_factory=list)
    kind: str = ChangeKind.MODIFIED
    is_security_related: bool = False
    security_tags: List[str] = field(default_factory=list)


@dataclass
class MinimizedDiff:
    """最小化后的 diff 结果。"""
    original_diff_size: int = 0
    minimized_diff_size: int = 0
    reduction_ratio: float = 0.0
    original_hunks: int = 0
    kept_hunks: int = 0
    hunks: List[DiffHunk] = field(default_factory=list)
    security_only_diff: str = ""
    # Dilipa 风格: 从 diff 中提取的安全检查片段
    security_snippets: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'original_diff_size': self.original_diff_size,
            'minimized_diff_size': self.minimized_diff_size,
            'reduction_ratio': round(self.reduction_ratio, 4),
            'original_hunks': self.original_hunks,
            'kept_hunks': self.kept_hunks,
            'security_snippets': self.security_snippets[:10],
        }


# ── 安全关键模式 ──────────────────────────────────────────────────────
# 参考 Dilipa 的 lifted-C 安全检查分类

_SECURITY_LINE_PATTERNS = [
    # bounds check
    (r'\bif\s*\(.*\b(?:len|size|length|index|count|max)\b.*[<>=!]', 0.70),
    # NULL check
    (r'\bif\s*\(.*\b(?:NULL|null|nullptr)\b', 0.85),
    (r'\b(?:assert|CHECK|ASSERT|verify)\s*\(', 0.75),
    # overflow check
    (r'\bif\s*\(.*\b(?:overflow|OVERFLOW|INT_MAX|SIZE_MAX|UINT_MAX)\b', 0.80),
    # safe function replacement
    (r'\b(?:strncpy|snprintf|strlcpy|strlcat|memcpy_s|memset_s)\s*\(', 0.75),
    # nullification after free
    (r'\b\w+\s*=\s*(?:NULL|null|nullptr)\s*;.*\bfree\b', 0.80),
    (r'\bfree\s*\([^)]+\)\s*;.*\b\w+\s*=\s*(?:NULL|null|nullptr)', 0.80),
    # format string fix
    (r'printf\s*\(\s*"%s"', 0.90),
    # input validation
    (r'\b(?:validate|sanitize|escape|reject)\s*\(', 0.70),
]


class DiffMinimizer:
    """Dilipa 风格 diff 最小化器。

    对 unified diff 输出进行多阶段最小化：
    Stage 1: noise removal (whitespace/comments-only changes)
    Stage 2: hunk coalescing (merge adjacent small hunks)
    Stage 3: semantic grouping (classify each hunk)
    Stage 4: security-only extraction (Dilipa core)
    """

    def __init__(self, keep_security_only: bool = False):
        self._keep_security_only = keep_security_only
        self._security_patterns = [(re.compile(p, re.IGNORECASE), w)
                                   for p, w in _SECURITY_LINE_PATTERNS]

    # ============================================================
    # minimize: 主入口
    # ============================================================
    def minimize(self, diff_text: str) -> MinimizedDiff:
        """最小化 unified diff 文本。"""
        _result = MinimizedDiff()
        _result.original_diff_size = len(diff_text)

        # Stage 1: 解析 hunks
        _hunks = self._parse_diff(diff_text)
        _result.original_hunks = len(_hunks)

        if not _hunks:
            _result.minimized_diff_size = 0
            _result.kept_hunks = 0
            return _result

        # Stage 2: 移除噪声 hunks (仅空白/注释变更)
        _filtered = self._remove_noise_hunks(_hunks)

        # Stage 3: 合并相邻 hunks
        _merged = self._coalesce_hunks(_filtered)

        # Stage 4: 语义标记
        for _h in _merged:
            self._classify_hunk(_h)

        # 如果设置了仅保留安全变更
        if self._keep_security_only:
            _merged = [_h for _h in _merged if _h.is_security_related]

        _result.hunks = _merged
        _result.kept_hunks = len(_merged)

        # 重建最小化后的 diff
        _min_diff = self._rebuild_diff(_merged)
        _result.minimized_diff_size = len(_min_diff)

        if _result.original_diff_size > 0:
            _result.reduction_ratio = 1.0 - (
                _result.minimized_diff_size / _result.original_diff_size)

        # 提取安全检查片段
        _result.security_snippets = self._extract_security_snippets(_merged)

        # 安全相关的 diff 子集
        _sec_hunks = [_h for _h in _merged if _h.is_security_related]
        _result.security_only_diff = self._rebuild_diff(_sec_hunks)

        return _result

    # ── diff 解析 ─────────────────────────────────────────────────────

    def _parse_diff(self, diff_text: str) -> List[DiffHunk]:
        """解析 unified diff 为 hunk 列表。"""
        _hunks = []
        _current = None
        _lines = diff_text.split('\n')

        _i = 0
        while _i < len(_lines):
            _line = _lines[_i]
            # 检测 hunk header: @@ -a,b +c,d @@
            _m = re.match(r'^@@\s+-(\d+),?(\d*)\s+\+(\d+),?(\d*)\s+@@(.*)', _line)
            if _m:
                if _current is not None:
                    _hunks.append(_current)
                _current = DiffHunk(
                    header=_line,
                    original_start=int(_m.group(1)),
                    original_count=int(_m.group(2) or 1),
                    patch_start=int(_m.group(3)),
                    patch_count=int(_m.group(4) or 1),
                )
            elif _current is not None:
                if _line.startswith('+') and not _line.startswith('+++'):
                    _current.added_lines.append(_line[1:])
                elif _line.startswith('-') and not _line.startswith('---'):
                    _current.removed_lines.append(_line[1:])
                elif _line.startswith(' '):
                    _current.context_lines.append(_line[1:])
            _i += 1

        if _current is not None:
            _hunks.append(_current)

        return _hunks

    # ── 噪声移除 ──────────────────────────────────────────────────────

    def _remove_noise_hunks(self, hunks: List[DiffHunk]) -> List[DiffHunk]:
        """过滤仅包含空白/注释变更的 hunks。"""
        _filtered = []
        for _h in hunks:
            # 检查变更是否仅限空白
            _added_content = [l for l in _h.added_lines if l.strip()]
            _removed_content = [l for l in _h.removed_lines if l.strip()]

            # 所有变更行都是空白或注释 → 噪声
            _all_noise = True
            for _l in _added_content + _removed_content:
                _stripped = _l.strip()
                if _stripped and not _stripped.startswith(('#', '//', '/*', '*', '*/')):
                    _all_noise = False
                    break

            if _all_noise and _added_content or _all_noise and _removed_content:
                _h.kind = ChangeKind.WHITESPACE if not _added_content and not _removed_content else ChangeKind.COMMENT

            _filtered.append(_h)

        return _filtered

    # ── hunk 合并 ─────────────────────────────────────────────────────

    def _coalesce_hunks(self, hunks: List[DiffHunk],
                        max_gap: int = 10) -> List[DiffHunk]:
        """合并间距小于 max_gap 行的相邻 hunks。"""
        if len(hunks) <= 1:
            return hunks

        _merged = []
        _cur = hunks[0]
        _i = 1
        while _i < len(hunks):
            _nxt = hunks[_i]
            _gap = _nxt.original_start - (_cur.original_start + _cur.original_count)
            if _gap < max_gap and _gap >= 0:
                # 合并
                _cur.added_lines.extend(_nxt.added_lines)
                _cur.removed_lines.extend(_nxt.removed_lines)
                _cur.original_count += _gap + _nxt.original_count
                _cur.patch_count += _gap + _nxt.patch_count
                _cur.security_tags.extend(_nxt.security_tags)
            else:
                _merged.append(_cur)
                _cur = _nxt
            _i += 1
        _merged.append(_cur)
        return _merged

    # ── 语义分类 ──────────────────────────────────────────────────────

    def _classify_hunk(self, hunk: DiffHunk):
        """根据变更内容标记 hunk 的语义类别。"""
        _all_added = '\n'.join(hunk.added_lines)

        # 安全检查检测
        _max_security_score = 0.0
        for _pat, _weight in self._security_patterns:
            if _pat.search(_all_added):
                _max_security_score = max(_max_security_score, _weight)
                _tag = _pat.pattern[:40]
                if _tag not in hunk.security_tags:
                    hunk.security_tags.append(_tag)

        if _max_security_score >= 0.70:
            hunk.is_security_related = True
            hunk.kind = ChangeKind.SECURITY
        elif _max_security_score >= 0.40:
            hunk.kind = ChangeKind.MODIFIED
        elif not hunk.added_lines and not hunk.removed_lines:
            hunk.kind = ChangeKind.WHITESPACE
        else:
            hunk.kind = ChangeKind.REFACTOR

    # ── diff 重建 ─────────────────────────────────────────────────────

    def _rebuild_diff(self, hunks: List[DiffHunk]) -> str:
        """从 hunk 列表重建 unified diff 文本。"""
        _lines = []
        for _h in hunks:
            _lines.append(_h.header)
            for _l in _h.context_lines:
                _lines.append(' ' + _l)
            for _l in _h.removed_lines:
                _lines.append('-' + _l)
            for _l in _h.added_lines:
                _lines.append('+' + _l)
        return '\n'.join(_lines)

    # ── 安全片段提取 ─────────────────────────────────────────────────

    def _extract_security_snippets(self, hunks: List[DiffHunk]) -> List[str]:
        """从安全关键 hunks 中提取独立的检查代码片段。Dilipa 风格的
        lifted-C snippet 提取。"""
        _snippets = []
        for _h in hunks:
            if not _h.is_security_related:
                continue
            for _l in _h.added_lines:
                _stripped = _l.strip()
                # 提取完整的 if 语句或函数调用
                if _stripped and len(_stripped) > 5:
                    _snippets.append(_stripped)
        return _snippets


# ── 便捷函数 ──────────────────────────────────────────────────────────

def minimize_patch_diff(diff_text: str,
                        security_only: bool = False) -> Dict:
    _minimizer = DiffMinimizer(keep_security_only=security_only)
    _result = _minimizer.minimize(diff_text)
    return {'success': True, 'result': _result.to_dict()}
