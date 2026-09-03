"""
F-SCORE 格式字符串误报削减 — 6阶段级联验证管道。
Stage F: 格式字面量 | Stage S: sanitizer | Stage C: 编译器守护
Stage O: 输出上下文 | Stage R: 引用追溯 | Stage E: 可利用性评估
原则: 仅编译期字面量可证安全→FILTER。用户可控无危险符→降级,不删除。
参考: scut/team teso, gcc -Wformat-security, CWE-134
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class FmtVerdict(Enum):
    SAFE_LITERAL = "safe_literal"
    SAFE_SANITIZED = "safe_sanitized"
    LIKELY_FP = "likely_fp"
    CONFIRMED = "confirmed"
    UNCERTAIN = "uncertain"


@dataclass
class FmtVerifyResult:
    func_name: str; fmt_func: str; fmt_arg: str
    verdict: FmtVerdict; confidence: float; reason: str
    is_literal: bool = False; is_user_controlled: bool = False
    output_target: str = "stdout"
    dangerous_specs: List[str] = field(default_factory=list)
    stage: str = ""


@dataclass
class FmtVerifyStats:
    total: int = 0; safe_literal: int = 0; safe_sanitized: int = 0
    likely_fp: int = 0; confirmed: int = 0; uncertain: int = 0


# 格式函数 => {fmt_pos, output}
_FMT = {'printf':(0,'stdout'),'fprintf':(1,'file'),'dprintf':(1,'fd'),
    'sprintf':(1,'buffer'),'snprintf':(2,'buffer'),'syslog':(1,'syslog'),
    'vsyslog':(1,'syslog'),'err':(1,'stderr'),'errx':(1,'stderr'),
    'warn':(0,'stderr'),'warnx':(0,'stderr'),'setproctitle':(0,'proc')}

_USER_SRC = {'argv','getenv','read','fread','recv','recvfrom','recvmsg',
    'fgets','gets','scanf','fscanf','sscanf','getc','fgetc','getchar'}

_SANITIZERS = {'safe_printf','safe_fprintf','checked_sprintf',
    'log_printf','debug_printf','trace_printf','format_and_print','print_formatted'}

_LITERAL_RE = re.compile(r'"([^"\\]|\\.)*"')
_QUOTE_RE = re.compile(r"'([^'\\]|\\.)*'")


class FmtVerifier:
    """F-SCORE 6阶段格式字符串验证器。"""

    def verify(self, findings: List[dict],
               code: str = "", func_name: str = "") -> Tuple[List[dict], FmtVerifyStats]:
        stats = FmtVerifyStats(total=len(findings))
        refined = []
        _map = {FmtVerdict.SAFE_LITERAL: 'safe_literal',
                FmtVerdict.SAFE_SANITIZED: 'safe_sanitized',
                FmtVerdict.LIKELY_FP: 'likely_fp',
                FmtVerdict.CONFIRMED: 'confirmed',
                FmtVerdict.UNCERTAIN: 'uncertain'}
        for f in findings:
            r = self._verify_one(f, code, func_name)
            setattr(stats, _map[r.verdict], getattr(stats, _map[r.verdict]) + 1)
            f['fmt_verdict'] = r.verdict.value
            f['fmt_stage'] = r.stage; f['fmt_reason'] = r.reason
            f['confidence'] = r.confidence
            if r.verdict in (FmtVerdict.SAFE_LITERAL, FmtVerdict.SAFE_SANITIZED):
                f['severity'] = 'Info'
            elif r.verdict == FmtVerdict.CONFIRMED:
                f['severity'] = 'Critical'
                if r.dangerous_specs: f['dangerous_specs'] = r.dangerous_specs
            elif r.verdict == FmtVerdict.LIKELY_FP:
                f['severity'] = 'Low'
            refined.append(f)
        return refined, stats

    def _verify_one(self, f: dict, code: str, _fn: str) -> FmtVerifyResult:
        fmt_func = f.get('fmt_func', f.get('format_func', ''))
        fmt_arg = f.get('arg', f.get('format_arg', ''))
        # F→S→C cascade (early-exit on clear verdict)
        for stage_fn in [self._chk_literal, self._chk_sanitized, self._chk_compiler]:
            r = stage_fn(code, fmt_func, fmt_arg, f)
            if r: return r
        # 源代码缺失时依赖二进制级提取结果做 fallback 判定
        if not code:
            r = self._binary_fallback(f, fmt_func, fmt_arg)
            if r: return r
        # O: output context
        output = _FMT.get(fmt_func, (0, 'stdout'))[1]
        # R: reference trace
        is_user = self._trace_user(code, fmt_arg)
        # E: exploitability
        return self._assess(fmt_func, fmt_arg, code, is_user, output)

    def _binary_fallback(self, f: dict, func: str, arg: str) -> Optional[FmtVerifyResult]:
        """源代码不可用时,从 finding 的二进制级分析字段做降级判定."""
        fmt_str = f.get('fmt_string', '')
        taint = f.get('taint_source', f.get('fmt_source', ''))
        if not fmt_str and not taint:
            return None
        has_dangerous = bool(re.search(r'%[0-9]*\$*\*?\d*[hn]', fmt_str))
        if isinstance(taint, str) and taint.upper() in ('TAINTED', 'PARAM', 'USER'):
            if has_dangerous:
                return FmtVerifyResult(
                    func_name=f.get('function', ''), fmt_func=func, fmt_arg=arg,
                    verdict=FmtVerdict.CONFIRMED, confidence=0.85,
                    is_user_controlled=True, dangerous_specs=['%n'] if '%n' in fmt_str else [],
                    reason=f"binary: taint={taint}, dangerous specs in '{fmt_str[:30]}'",
                    stage='B')
            return FmtVerifyResult(
                func_name=f.get('function', ''), fmt_func=func, fmt_arg=arg,
                verdict=FmtVerdict.LIKELY_FP, confidence=0.60,
                is_user_controlled=True,
                reason=f"binary: taint={taint}, no dangerous specs", stage='B')
        if isinstance(taint, str) and taint.upper() in ('SAFE', 'RDATA', 'LITERAL'):
            return FmtVerifyResult(
                func_name=f.get('function', ''), fmt_func=func, fmt_arg=arg,
                verdict=FmtVerdict.SAFE_LITERAL, confidence=0.90,
                is_literal=True,
                reason=f"binary: source={taint}, .rdata literal", stage='B')
        return None

    # Stage F: LITERAL ──────────────────────────

    def _chk_literal(self, code, func, arg, f) -> Optional[FmtVerifyResult]:
        if not code or not func: return None
        pat = re.compile(re.escape(func) + r'\s*\((.*?)\)', re.DOTALL)
        for m in pat.finditer(code):
            args = self._split(m.group(1))
            pos = _FMT.get(func, (0,))[0]
            if pos < len(args):
                val = args[pos].strip()
                if _LITERAL_RE.match(val) or _QUOTE_RE.match(val):
                    return FmtVerifyResult(
                        func_name=f.get('function',''), fmt_func=func, fmt_arg=val,
                        verdict=FmtVerdict.SAFE_LITERAL, confidence=0.99,
                        is_literal=True, reason=f"literal: {val[:40]}", stage='F')
        return None

    # Stage S: SANITIZED ────────────────────────

    def _chk_sanitized(self, code, func, arg, f) -> Optional[FmtVerifyResult]:
        if not code: return None
        for sn in _SANITIZERS:
            if sn in code and func == 'printf':
                return FmtVerifyResult(
                    func_name=f.get('function',''), fmt_func=func, fmt_arg=arg,
                    verdict=FmtVerdict.SAFE_SANITIZED, confidence=0.90,
                    reason=f"wrapper: {sn}", stage='S')
        return None

    # Stage C: COMPILER_GUARD ───────────────────

    def _chk_compiler(self, code, func, arg, f) -> Optional[FmtVerifyResult]:
        if not code: return None
        if re.search(r'__attribute__\s*\(\s*\(\s*format\s*\(', code):
            return FmtVerifyResult(
                func_name=f.get('function',''), fmt_func=func, fmt_arg=arg,
                verdict=FmtVerdict.LIKELY_FP, confidence=0.65,
                reason="compiler-guarded: __attribute__((format))", stage='C')
        return None

    # Stage R: REFERENCE_TRACE ──────────────────

    def _trace_user(self, code: str, arg: str) -> bool:
        if not code or not arg: return False
        # 直接赋值: arg = recv(...)
        for src in _USER_SRC:
            if re.search(rf'{re.escape(arg)}\s*=.*\b{src}\b', code): return True
        # 间接传播: 函数参数作为格式串传入,且函数被以用户输入调用
        # 检测 void f(char *x){...printf(x)...} 且 f(user_input) 的调用链
        fn_def = re.search(
            rf'\b\w+\s+\w+\s*\(\s*(?:void\s*\*)?\s*({re.escape(arg)})\s*[,)]', code)
        if fn_def:
            # 该参数在函数体内直接传入 printf 类函数则视为可控
            if re.search(rf'{re.escape(arg)}\s*[,)]', code):
                return True
        # 检测函数定义中 printf(参数名) 模式,且存在以用户输入调用该函数
        fmt_call_pat = re.compile(
            r'\b(?:printf|fprintf|sprintf|snprintf|syslog)\s*\(\s*(\w+)\s*[,)]')
        for m in fmt_call_pat.finditer(code):
            param = m.group(1)
            if param == arg:
                return True
            # 参数名出现在函数签名中,且函数以用户输入被调用
            sig = re.search(rf'\b\w+\s+\w+\s*\([^)]*\b{re.escape(param)}\b', code)
            if sig:
                call_pat = re.compile(rf'\b{re.escape(sig.group(0).split()[1])}\s*\(\s*(\w+)')
                for cm in call_pat.finditer(code):
                    if cm.group(1) in _USER_SRC or \
                       re.search(rf'{re.escape(cm.group(1))}\s*=.*\b{"|".join(_USER_SRC)}\b', code):
                        return True
        return False

    # Stage E: EXPLOITABILITY ───────────────────

    def _assess(self, func, arg, code, is_user, output) -> FmtVerifyResult:
        dangerous, conf = [], 0.5
        fmt_content = self._extract_fmt(code, func)
        if fmt_content:
            try:
                from analysis.format_spec_scorer import FormatSpecAnalyzer
                specs = FormatSpecAnalyzer.parse_format_string(fmt_content)
                dangerous = [s.raw for s in specs if s.risk.value >= 3]
                if not dangerous and specs:
                    # 用户可控但无危险符→降级为可能误报,而非直接判安全
                    if is_user:
                        return FmtVerifyResult(
                            func_name="", fmt_func=func, fmt_arg=arg,
                            verdict=FmtVerdict.LIKELY_FP, confidence=0.70,
                            is_user_controlled=True,
                            reason=f"user-controlled, no dangerous: {[s.raw for s in specs[:3]]}",
                            stage='E')
                    return FmtVerifyResult(
                        func_name="", fmt_func=func, fmt_arg=arg,
                        verdict=FmtVerdict.SAFE_LITERAL, confidence=0.95,
                        reason=f"no dangerous: {[s.raw for s in specs[:3]]}",
                        stage='E', is_literal=True)
                if dangerous: conf = 0.90
            except ImportError:
                # 优先尝试 fmt_spec_parser 作为本地 fallback
                try:
                    from analysis.fmt_spec_parser import parse_format_specs, detect_format_danger
                    specs = parse_format_specs(fmt_content)
                    dangerous = [s for s in specs if detect_format_danger(s)]
                except ImportError:
                    # 最小 fallback: 直接字符串搜索 %n
                    if '%n' in fmt_content:
                        dangerous = ['%n']
                if dangerous: conf = 0.90

        if is_user and not fmt_content: conf = 0.85

        sev = {'stdout':'info_leak','stderr':'info_leak','file':'log_injection',
               'fd':'log_injection','buffer':'buffer_overflow',
               'syslog':'privilege_escalation','proc':'proc_title_spoof'}.get(output,'?')

        if is_user or dangerous:
            return FmtVerifyResult(
                func_name="", fmt_func=func, fmt_arg=arg,
                verdict=FmtVerdict.CONFIRMED if (is_user and dangerous) else FmtVerdict.LIKELY_FP,
                confidence=conf, is_user_controlled=is_user,
                output_target=output, dangerous_specs=dangerous,
                reason=f"exploit: user={is_user}, dangerous={dangerous} → {sev}", stage='E')

        return FmtVerifyResult(
            func_name="", fmt_func=func, fmt_arg=arg,
            verdict=FmtVerdict.UNCERTAIN, confidence=0.40,
            reason=f"insufficient info → {sev}", stage='E')

    # helpers ───────────────────────────────────

    def _extract_fmt(self, code, func) -> str:
        m = re.search(re.escape(func) + r'\s*\(\s*"((?:[^"\\]|\\.)*)"', code)
        if m:
            return m.group(1)
        # 非字面量分支: printf(var) 模式提取变量名作为格式串标识
        m = re.search(re.escape(func) + r'\s*\(\s*(\w+)\s*[,)]', code)
        if m:
            return m.group(1)
        return ""

    @staticmethod
    def _split(s: str) -> List[str]:
        d=0; args=[]; cur=[]
        for ch in s:
            if ch=='(' : d+=1; cur.append(ch)
            elif ch==')': d-=1; cur.append(ch)
            elif ch==',' and d==0: args.append(''.join(cur).strip()); cur=[]
            else: cur.append(ch)
        if cur: args.append(''.join(cur).strip())
        return args


def verify_fmt_candidates(findings: List[dict], code: str = "",
                          func_name: str = "") -> Tuple[List[dict], FmtVerifyStats]:
    """F-SCORE 格式字符串验证便捷入口。"""
    return FmtVerifier().verify(findings, code, func_name)
