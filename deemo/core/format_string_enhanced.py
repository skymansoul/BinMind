"""增强格式字符串检测 — FORMAT (恶意参数追踪的流来源解析), 五阶段管道对标 GAPSBV/TARPS.
Stage 1 调用点检测 → Stage 2 来源追踪(5跳回溯至 fgets/argv/recv/getenv) → Stage 3 安全包装过滤 → Stage 4 格式说明符分析(%n任意写/%x信息泄露/%s任意读) → Stage 5 置信度评分(综合来源+说明符→0-1分);
参考: scut/team teso, 2001; CWE-134."""

from __future__ import annotations
import re, time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple


# 数据类型与常量 ─────────────────────────────────────────────────────

@dataclass
class FmtCandidate:
    """格式字符串漏洞候选"""
    fmt_func: str                         # 'printf' | 'sprintf' | 'syslog' ...
    fmt_arg: str                          # 变量名 (如 'buf', 'argv[1]')
    src_line: int = 0
    verdict: str = 'UNCERTAIN'            # CONFIRMED | FILTERED | UNCERTAIN
    confidence: float = 0.5
    source_type: str = 'unknown'          # user_input | constant | safe_wrapper
    source_detail: str = ''
    has_percent_n: bool = False
    has_percent_x: bool = False
    has_percent_s: bool = False
    stage_results: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        return (f'[{self.verdict}] {self.fmt_func}({self.fmt_arg}) '
                f'src={self.source_type} %n={self.has_percent_n} '
                f'%x={self.has_percent_x} conf={self.confidence:.2f}')


_INPUT_SOURCES = {'fgets', 'gets', 'scanf', 'fscanf', 'recv', 'recvfrom',
                  'read', 'getenv', 'argv', 'argc'}
_C_KW = frozenset(['if','for','while','do','else','return','goto',
                    'break','continue','case','default','switch'])
_PERCENT_N_RE = re.compile(r'%n|%hn|%hhn')
_PERCENT_X_RE = re.compile(r'%[xXp]')
_PERCENT_S_RE = re.compile(r'%s')

# Stage 1 正则构件
_ARG_VAR = r'(\w[\w\[\]\']*)'     # 变量名 (允许 argv[1])
_NOT_QUOTE = r'(?!")'             # 负前瞻: 非字符串字面量
_SKIP_ARG = r'[^,]+,\s*'          # 跳过一个逗号分隔的参数

_FMT_PATTERNS: List[Tuple[str, 're.Pattern']] = [
    # (函数名, 正则) — group 1 = 格式参数变量
    ('printf',   re.compile(rf'\bprintf\s*\(\s*{_NOT_QUOTE}{_ARG_VAR}[^)]*\)')),
    ('fprintf',  re.compile(rf'\b(?:fprintf|dprintf)\s*\(\s*{_SKIP_ARG}{_NOT_QUOTE}{_ARG_VAR}[^)]*\)')),
    ('syslog',   re.compile(rf'\bsyslog\s*\(\s*{_SKIP_ARG}{_NOT_QUOTE}{_ARG_VAR}[^)]*\)')),
    ('sprintf',  re.compile(rf'\bsprintf\s*\(\s*{_SKIP_ARG}{_NOT_QUOTE}{_ARG_VAR}[^)]*\)')),
    ('snprintf', re.compile(rf'\bsnprintf\s*\(\s*{_SKIP_ARG}{_SKIP_ARG}{_NOT_QUOTE}{_ARG_VAR}[^)]*\)')),
]


# FORMAT 检测器 ──────────────────────────────────────────────────────

class EnhancedFmtDetector:
    """五阶段FORMAT增强检测器。detect(ir_lines) → List[FmtCandidate]"""

    def __init__(self):
        self.stats: Dict[str, Any] = {}

    # 公开 API ────────────────────────────────────────────────────────

    def detect(self, ir_lines: List[str]) -> List[FmtCandidate]:
        t0 = time.time()
        self.stats = dict.fromkeys(
            ['stage1_calls','stage2_user_input','stage3_safe_wrappers',
             'stage4_specifiers','stage5_confirmed','stage5_filtered'], 0)

        # Stage 1: 格式化调用点检测
        raw_calls = self._detect_format_calls(ir_lines)
        self.stats['stage1_calls'] = len(raw_calls)
        if not raw_calls:
            self.stats['elapsed'] = round(time.time() - t0, 4)
            return []

        def_use = self._build_def_use(ir_lines)
        candidates: List[FmtCandidate] = []

        for call in raw_calls:
            arg = call['fmt_arg']
            src_type, src_detail = self._trace_source(arg, def_use, ir_lines)
            cand = FmtCandidate(fmt_func=call['fmt_func'], fmt_arg=arg,
                                src_line=call['line'], source_type=src_type,
                                source_detail=src_detail)

            # Stage 3: 安全包装过滤
            if self._is_safe_wrapper(call, def_use, ir_lines):
                cand.stage_results['safe_wrapper'] = True
                cand.verdict = 'FILTERED'
                cand.confidence = 0.10
                cand.source_type = 'safe_wrapper'
                self.stats['stage3_safe_wrappers'] += 1
                candidates.append(cand)
                continue

            # Stage 4: 格式说明符分析
            spec = self._analyze_specifiers(arg, def_use, ir_lines)
            cand.has_percent_n = spec['n']; cand.has_percent_x = spec['x']
            cand.has_percent_s = spec['s']; cand.stage_results['specifiers'] = spec
            if any(spec.values()):
                self.stats['stage4_specifiers'] += 1

            # Stage 5: 置信度评分
            cand.confidence = self._score(cand, src_type, spec)
            if cand.confidence >= 0.60:
                cand.verdict = 'CONFIRMED'; self.stats['stage5_confirmed'] += 1
            elif cand.confidence >= 0.30:
                cand.verdict = 'UNCERTAIN'
            else:
                cand.verdict = 'FILTERED'; self.stats['stage5_filtered'] += 1

            if src_type == 'user_input':
                self.stats['stage2_user_input'] += 1
            cand.source_type = src_type
            candidates.append(cand)

        candidates.sort(key=lambda c: -c.confidence)
        self.stats['elapsed'] = round(time.time() - t0, 4)
        return candidates

    # 阶段 1 ──────────────────────────────────────────────────────────

    def _detect_format_calls(self, ir_lines: List[str]) -> List[Dict[str, Any]]:
        calls = []
        for i, line in enumerate(ir_lines):
            s = line.strip()
            for func_name, pat in _FMT_PATTERNS:
                for m in pat.finditer(s):
                    arg = m.group(1)
                    if arg and arg not in _C_KW:
                        calls.append({'fmt_func': func_name, 'fmt_arg': arg,
                                     'line': i, 'line_text': s})
        return calls

    # 阶段 2 ──────────────────────────────────────────────────────────

    def _build_def_use(self, ir_lines: List[str]) -> Dict[str, int]:
        du: Dict[str, int] = {}
        _assn = re.compile(r'(\w[\w.]*)\s*=\s*(.+)')
        for i, line in enumerate(ir_lines):
            m = _assn.match(line.strip())
            if m:
                var = m.group(1)
                if var not in _C_KW:
                    du[var] = i
        return du

    def _trace_source(self, var: str, du: Dict[str, int],
                      ir_lines: List[str]) -> Tuple[str, str]:
        base = var.split('[')[0]
        if base == 'argv':
            return ('user_input', 'argv as format')

        visited, cur = {var}, var
        for _ in range(5):
            if cur not in du:
                return ('unknown', f'{cur}: unresolved')
            idx = du[cur]
            line = ir_lines[idx].strip()
            m = re.match(r'\w[\w.]*\s*=\s*(.+)', line)
            if not m:
                return ('unknown', f'{cur}: no RHS')
            rhs = m.group(1).rstrip(';').strip()

            for src in _INPUT_SOURCES:
                if rhs.startswith(src) or src in rhs:
                    return ('user_input', f'{src} at L{idx}')
                if 'argv' in rhs and '[' in rhs:
                    return ('user_input', f'argv at L{idx}')

            if rhs.startswith('"') or rhs.startswith("'"):
                return ('constant', f'literal at L{idx}')
            if 'snprintf' in rhs and '"%s"' in rhs:
                return ('safe_wrapper', f'snprintf("%s") at L{idx}')

            alias_m = re.match(r'^(\w[\w.]*)$', rhs)
            if alias_m:
                a = alias_m.group(1)
                if a in visited:
                    return ('unknown', f'cycle: {cur}->{a}')
                visited.add(a); cur = a; continue

            fn_m = re.match(r'(\w+)\s*\(', rhs)
            if fn_m:
                fn = fn_m.group(1)
                return ('user_input', f'{fn}() at L{idx}') if fn in _INPUT_SOURCES \
                    else ('unknown', f'{fn}(): unresolved')
            return ('unknown', f'{cur} <- {rhs[:40]}')
        return ('unknown', f'{var}: max hops')

    # 阶段 3 ──────────────────────────────────────────────────────────

    def _is_safe_wrapper(self, call: Dict, du: Dict[str, int],
                         ir_lines: List[str]) -> bool:
        arg = call['fmt_arg']
        if arg in du:
            line = ir_lines[du[arg]].strip()
            if 'safe' in line.lower() or '"%s"' in line:
                return True
        return False

    # 阶段 4 ──────────────────────────────────────────────────────────

    def _analyze_specifiers(self, var: str, du: Dict[str, int],
                            ir_lines: List[str]) -> Dict[str, bool]:
        r = {'n': False, 'x': False, 's': False}
        if var not in du:
            return r
        line = ir_lines[du[var]].strip()
        for s in re.findall(r'"([^"]*)"', line):
            if _PERCENT_N_RE.search(s): r['n'] = True
            if _PERCENT_X_RE.search(s): r['x'] = True
            if _PERCENT_S_RE.search(s): r['s'] = True
        if any(src in line for src in _INPUT_SOURCES):
            r['x'] = r['n'] = r['s'] = True
        return r

    # 阶段 5 ──────────────────────────────────────────────────────────

    def _score(self, cand: FmtCandidate, src_type: str,
               spec: Dict[str, bool]) -> float:
        if src_type == 'user_input':   base = 0.70
        elif src_type == 'constant':   base = 0.05
        elif src_type == 'safe_wrapper': base = 0.10
        else:                          base = 0.50
        if spec.get('n'): base += 0.15
        if spec.get('x'): base += 0.08
        if spec.get('s'): base += 0.05
        if cand.fmt_func in ('sprintf', 'snprintf'):
            base += 0.02
        return max(0.05, min(0.95, base))

    # 工具函数 ────────────────────────────────────────────────────────

    def summary_table(self, candidates: List[FmtCandidate]) -> str:
        hdr = (f"{'Verdict':12s} {'Call':25s} {'Source':12s} "
               f"{'%n':5s} {'%x':5s} {'Conf':6s}")
        rows = [hdr, "-" * 70]
        for c in candidates:
            rows.append(f"{c.verdict:12s} {c.fmt_func}({c.fmt_arg}):25s "
                        f"{c.source_type:12s} "
                        f"{'Y' if c.has_percent_n else '-':5s} "
                        f"{'Y' if c.has_percent_x else '-':5s} "
                        f"{c.confidence:.2f}")
        return '\n'.join(rows)


def detect_format_string_enhanced(
    ir_lines: List[str],
) -> Tuple[List[FmtCandidate], Dict[str, Any]]:
    """便捷函数: (candidates, stats)"""
    d = EnhancedFmtDetector()
    return d.detect(ir_lines), d.stats


__all__ = ['FmtCandidate', 'EnhancedFmtDetector', 'detect_format_string_enhanced']
