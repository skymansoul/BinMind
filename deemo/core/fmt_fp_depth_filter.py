"""格式串 FP 深度过滤器 — 经三种正交分析抑制误报: 格式串所有权、缓冲区写回检测、调用点上下文评分。
所有权检查区分字面量与污点格式串 (字面量→SAFE 过滤, 用户可控→KEEP 保留);
写回检查解析 snprintf→printf 误报链; 加权决策替代二值安全判定。"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# 正则模式 ───────────────────────────────────────────────────────────

_PRINTF_CALL = re.compile(
    r'\b(?:printf|fprintf|sprintf|snprintf|syslog|dprintf)\s*\(')
_FORMAT_LITERAL = re.compile(
    r'(?:printf|fprintf|syslog|dprintf)\s*\(\s*"([^"]*)"')
_SNPRINTF_BUF = re.compile(
    r'snprintf\s*\(\s*(\w[\w.]*)\s*,\s*(\w[\w.]*|sizeof\([^)]+\))\s*,')
_PRINTF_FMT_ARG = re.compile(
    r'(?:printf|fprintf|syslog|dprintf)\s*\(\s*(\w[\w.]*)\s*[,)]')
_TAINTED_SRC = re.compile(r'\b(?:fgets|gets|scanf|recv|read|getenv|argv|'
                           r'fread|memcpy)\s*\(')
_ERROR_PATH = re.compile(r'\b(?:error|err|warn|debug|log|trace|assert)\b',
                          re.IGNORECASE)


@dataclass
class FmtDepthDecision:
    """格式串 FP 过滤判定。"""
    line: int; line_text: str = ''
    is_literal: bool = False
    is_writeback: bool = False
    is_error_path: bool = False
    ownership_score: float = 0.50
    verdict: str = 'REVIEW'
    confidence: float = 0.50


class FmtFpDepthFilter:
    """三检查格式串 FP 深度过滤器。"""

    def __init__(self):
        self.stats: Dict[str, Any] = {}

    def filter(self, ir_lines: List[str],
               candidates: List[Dict]) -> List[FmtDepthDecision]:
        """对每个候选执行所有权 + 写回 + 上下文检查。"""
        decisions = []
        for cand in candidates:
            line = cand.get('line', 0)
            text = cand.get('text', ir_lines[line] if line < len(ir_lines) else '')
            dec = FmtDepthDecision(line=line, line_text=str(text))

            # 检查 1: 格式串所有权
            dec.is_literal, dec.ownership_score = self._check_ownership(
                ir_lines, line, text)

            # 检查 2: snprintf 写回模式
            dec.is_writeback = self._check_writeback(ir_lines, line, text)

            # 检查 3: 错误/调试路径上下文
            dec.is_error_path = self._check_error_path(ir_lines, line, text)

            # 加权决策
            dec.verdict, dec.confidence = self._decide(dec)
            decisions.append(dec)

        self.stats = {
            'total': len(candidates),
            'suppressed': sum(1 for d in decisions if d.verdict == 'SUPPRESS'),
            'review': sum(1 for d in decisions if d.verdict == 'REVIEW'),
            'kept': sum(1 for d in decisions if d.verdict == 'KEEP'),
        }
        return decisions

    # 检查 1: 格式串所有权 ───────────────────────────

    def _check_ownership(self, ir_lines: List[str], line: int,
                         text: str) -> Tuple[bool, float]:
        """字面量格式串安全, 污点格式串危险。"""
        m = _FORMAT_LITERAL.search(text)
        if m:
            return True, 0.05  # 字面量 → 基本确定安全

        # 检查格式参数是否被污点化
        pm = _PRINTF_FMT_ARG.search(text)
        if pm:
            fmt_var = pm.group(1)
            if fmt_var in ('fmt', 'format', 'buf', 'msg', 'errmsg',
                           'str', 'string', 'output'):
                # 用户可控 → 可疑
                for i in range(max(0, line - 30), line):
                    if _TAINTED_SRC.search(ir_lines[i]):
                        return False, 0.85  # 已污点 → 保留

        return False, 0.50  # 无法判定

    # 检查 2: snprintf 写回 ────────────────────────────────

    @staticmethod
    def _check_writeback(ir_lines: List[str], line: int,
                         text: str) -> bool:
        """检测 snprintf→printf 链: 格式串经间接但安全的方式传入。
        模式: snprintf(buf,sz,fmt,...); printf(buf) — printf 的格式参数来自使用固定 fmt 的 snprintf。"""
        # 取 printf 的格式参数
        pm = _PRINTF_FMT_ARG.search(text)
        if not pm:
            return False
        fmt_arg = pm.group(1)
        if not fmt_arg:
            return False
        # 向前扫描向该参数写入的 snprintf
        for i in range(max(0, line - 10), line):
            sm = _SNPRINTF_BUF.search(ir_lines[i])
            if sm and sm.group(1) == fmt_arg:
                return True
        return False

    # 检查 3: 错误/调试上下文 ────────────────────────────────

    @staticmethod
    def _check_error_path(ir_lines: List[str], line: int,
                          text: str) -> bool:
        """错误/调试路径中的格式串 → 降低可利用性。"""
        if _ERROR_PATH.search(text):
            return True
        for i in range(max(0, line - 3), line):
            if _ERROR_PATH.search(ir_lines[i]):
                return True
        return False

    # 决策 ───────────────────────────────────────────────────

    @staticmethod
    def _decide(dec: FmtDepthDecision) -> Tuple[str, float]:
        """加权决策: 所有权(0.50) + 写回(0.30) + 错误路径(0.20)。"""
        score = dec.ownership_score * 0.50
        if dec.is_writeback:
            score += 0.30
        if dec.is_error_path:
            score += 0.20

        if score >= 0.60:
            return 'SUPPRESS', round(score, 2)
        elif score <= 0.25:
            return 'KEEP', round(score, 2)
        return 'REVIEW', round(score, 2)


def filter_fmt_candidates(
    ir_lines: List[str], candidates: List[Dict],
) -> Tuple[List[FmtDepthDecision], Dict[str, Any]]:
    """便捷入口: 过滤格式串候选。"""
    engine = FmtFpDepthFilter()
    decisions = engine.filter(ir_lines, candidates)
    return decisions, engine.stats


__all__ = ['FmtDepthDecision', 'FmtFpDepthFilter', 'filter_fmt_candidates']
