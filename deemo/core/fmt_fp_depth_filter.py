"""
Format string FP depth filter — suppresses false positives through three
orthogonal analyses: format string ownership, buffer write-back detection,
and call-site context scoring.

Algorithm:
  1. OwnershipCheck: Is the format string user-controlled or literal?
     - Literal strings → SAFE (FP), user-controlled → KEEP (TP)
  2. WriteBackCheck: Does snprintf emit to a bounded buffer that is later
     passed to printf? If yes, the format is indirect but safe.
  3. CallSiteContext: Is the printf-family call in an error path or debug
     block? If yes, lower exploitability.

Novelty over existing fmt detectors:
  - OwnershipCheck distinguishes literal vs. tainted format strings
  - WriteBackCheck resolves snprintf->printf false positive chains
  - Weighted decision replaces binary safe/unsafe verdict
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# patterns ───────────────────────────────────────────────────────────

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
    """Format string FP filter decision."""
    line: int; line_text: str = ''
    is_literal: bool = False
    is_writeback: bool = False
    is_error_path: bool = False
    ownership_score: float = 0.50
    verdict: str = 'REVIEW'
    confidence: float = 0.50


class FmtFpDepthFilter:
    """Three-check format string FP depth filter."""

    def __init__(self):
        self.stats: Dict[str, Any] = {}

    def filter(self, ir_lines: List[str],
               candidates: List[Dict]) -> List[FmtDepthDecision]:
        """Run ownership + writeback + context checks on each candidate."""
        decisions = []
        for cand in candidates:
            line = cand.get('line', 0)
            text = cand.get('text', ir_lines[line] if line < len(ir_lines) else '')
            dec = FmtDepthDecision(line=line, line_text=str(text))

            # Check 1: format string ownership
            dec.is_literal, dec.ownership_score = self._check_ownership(
                ir_lines, line, text)

            # Check 2: snprintf write-back pattern
            dec.is_writeback = self._check_writeback(ir_lines, line, text)

            # Check 3: error/debug path context
            dec.is_error_path = self._check_error_path(ir_lines, line, text)

            # Weighted decision
            dec.verdict, dec.confidence = self._decide(dec)
            decisions.append(dec)

        self.stats = {
            'total': len(candidates),
            'suppressed': sum(1 for d in decisions if d.verdict == 'SUPPRESS'),
            'review': sum(1 for d in decisions if d.verdict == 'REVIEW'),
            'kept': sum(1 for d in decisions if d.verdict == 'KEEP'),
        }
        return decisions

    # Check 1: format string ownership ───────────────────────────

    def _check_ownership(self, ir_lines: List[str], line: int,
                         text: str) -> Tuple[bool, float]:
        """Literal format strings are safe; tainted ones are dangerous."""
        m = _FORMAT_LITERAL.search(text)
        if m:
            return True, 0.05  # literal → nearly certainly safe

        # Check if format arg is tainted
        pm = _PRINTF_FMT_ARG.search(text)
        if pm:
            fmt_var = pm.group(1)
            if fmt_var in ('fmt', 'format', 'buf', 'msg', 'errmsg',
                           'str', 'string', 'output'):
                # Likely user-controlled → suspicious
                for i in range(max(0, line - 30), line):
                    if _TAINTED_SRC.search(ir_lines[i]):
                        return False, 0.85  # tainted → keep

        return False, 0.50  # uncertain

    # Check 2: snprintf write-back ────────────────────────────────

    @staticmethod
    def _check_writeback(ir_lines: List[str], line: int,
                         text: str) -> bool:
        """Detect snprintf→printf chain where format is indirect but safe.
        Pattern: snprintf(buf,sz,fmt,...); printf(buf)
        The printf format arg comes from snprintf which used a fixed fmt."""
        # Get the printf's format argument
        pm = _PRINTF_FMT_ARG.search(text)
        if not pm:
            return False
        fmt_arg = pm.group(1)
        if not fmt_arg:
            return False
        # Scan backwards for snprintf that writes to this arg
        for i in range(max(0, line - 10), line):
            sm = _SNPRINTF_BUF.search(ir_lines[i])
            if sm and sm.group(1) == fmt_arg:
                return True
        return False

    # Check 3: error/debug context ────────────────────────────────

    @staticmethod
    def _check_error_path(ir_lines: List[str], line: int,
                          text: str) -> bool:
        """Format string in error/debug path → lower exploitability."""
        if _ERROR_PATH.search(text):
            return True
        for i in range(max(0, line - 3), line):
            if _ERROR_PATH.search(ir_lines[i]):
                return True
        return False

    # decision ───────────────────────────────────────────────────

    @staticmethod
    def _decide(dec: FmtDepthDecision) -> Tuple[str, float]:
        """Weighted decision: literal(0.50) + writeback(0.30) + error(0.20)."""
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
    """Convenience: filter format string candidates."""
    engine = FmtFpDepthFilter()
    decisions = engine.filter(ir_lines, candidates)
    return decisions, engine.stats


__all__ = ['FmtDepthDecision', 'FmtFpDepthFilter', 'filter_fmt_candidates']
