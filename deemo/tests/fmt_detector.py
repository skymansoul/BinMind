"""
FSCS 格式字符串检测器 — 分析 printf/sprintf/fprintf 家族调用,
判断格式串来源 (CONSTANT/EXTERNAL_INPUT/STACK_VAR) 及是否含 %n 写原语。

判定: EXTERNAL_INPUT 且 (含 %n 或直接作为格式串参数) → 检出。
"""
import re
from typing import Any, Dict, List, Optional, Tuple


# 格式串函数调用: func(fmt_str, ...)
# 含 syslog (系统日志) 和 v* 变参函数
_FMT_CALL_RE = re.compile(
    r'(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf'
    r'|dprintf|syslog)\s*\(([^;]+)\)\s*;',
    re.IGNORECASE,
)

# 格式说明符解析: %[flags][width][.precision][length]specifier
_FMT_SPEC_RE = re.compile(
    r'%(?:[0+\- #]*)?(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|l|ll|j|z|t|L)?'
    r'([diouxXeEfFgGaAcspn%])',
)

# 用户输入来源函数
_INPUT_SOURCE_RE = re.compile(
    r'(argv\[|getenv\s*\(|scanf\s*\(|fgets\s*\(|read\s*\('
    r'|recv\s*\(|getopt\s*\()',
)

# 变量赋值模式: char fmt[N] = "..."; 或 const char *fmt = "...";
_VAR_ASSIGN_RE = re.compile(
    r'(?:const\s+)?char\s*\*?\s*(\w+)\s*=\s*"([^"]*)"',
)

# 以下 regex 已迁移至 fmt_detector_helpers.py
# _STRNCPY_ARGV_RE, _DIRECT_ARGV_RE, _SPRINTF_ARGV_FMT_RE, _SNPRINTF_TAINT_RE
# _FUNC_CALL_ARGV_RE, _FUNC_DEF_PARAM_RE, _GLOBAL_ASSIGN_RE

from tests.fmt_detector_helpers import (  # noqa: E402
    _find_user_controlled_fmt_vars,
    _classify_fmt_arg,
    _scan_fmt_specs,
)


class FmtFinding:
    """格式串检测发现。"""
    def __init__(self, func: str, line_no: int, line: str,
                 arg_source: str, has_pct_n: bool,
                 has_positional: bool, risk: str):
        self.func = func
        self.line_no = line_no
        self.line = line
        self.arg_source = arg_source
        self.has_pct_n = has_pct_n
        self.has_positional = has_positional
        self.risk = risk

    def __repr__(self):
        return (f"FmtFinding({self.func}@{self.line_no} "
                f"src={self.arg_source} n={self.has_pct_n} risk={self.risk})")


def detect_format_string(source: str) -> Dict[str, Any]:
    """对 C 源码执行 FSCS 格式串检测。

    返回: {detected, findings: [{func, line_no, arg_source, risk, ...}], ...}
    """
    findings: List[FmtFinding] = []

    # 预处理: 提取 argv[] 直接作为格式串的变量名
    direct_fmt_vars = _find_user_controlled_fmt_vars(source)

    # 预提取: 编译时常量格式串变量 → 标记为safe
    var_constants = {}
    for line in source.splitlines():
        m = _VAR_ASSIGN_RE.search(line.strip())
        if m:
            var_constants[m.group(1)] = m.group(2)

    lines = source.splitlines()
    for i, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line or line.startswith('//') or line.startswith('/*'):
            continue
        line_no = i + 1

        # 多行调用合并: 如果行含 printf( 但未闭合, 合并后续行
        effective_line = line
        if re.search(r'(?:printf|fprintf|sprintf|snprintf|vprintf|vfprintf|'
                      r'vsprintf|vsnprintf|dprintf|syslog)\s*\(', line, re.IGNORECASE):
            if ');' not in line:
                # 合并后续行直到找到 );
                for j in range(i + 1, min(i + 10, len(lines))):
                    nl = lines[j].strip()
                    effective_line += ' ' + nl
                    if ');' in nl:
                        break

        # 检测所有格式串函数调用 (使用合并后的行)
        for m in _FMT_CALL_RE.finditer(effective_line):
            func = m.group(1).lower()
            args_str = m.group(2)
            args = _parse_fmt_args(args_str)
            if len(args) < 2 and func != 'printf':
                continue  # 非格式串调用

            # 识别格式串参数位置:
            # printf(fmt, ...) → fmt = args[0]
            # vprintf(fmt, ap) → fmt = args[0]
            # vfprintf(fp, fmt, ap) → fmt = args[1]
            # fprintf(fp, fmt, ...) → fmt = args[1]
            # sprintf(buf, fmt, ...) → fmt = args[1]
            # vsprintf(buf, fmt, ap) → fmt = args[1]
            # snprintf(buf, size, fmt, ...) → fmt = args[2]
            # vsnprintf(buf, size, fmt, ap) → fmt = args[2]
            # syslog(prio, fmt, ...) → fmt = args[1]
            if func in ('printf', 'vprintf'):
                fmt_arg_idx = 0
            elif func in ('snprintf', 'vsnprintf'):
                fmt_arg_idx = 2  # buf, size, fmt
            elif func == 'syslog':
                fmt_arg_idx = 1  # priority, fmt
            else:
                fmt_arg_idx = 1  # fprintf, sprintf, dprintf, vfprintf, vsprintf 等
            if fmt_arg_idx >= len(args):
                fmt_arg_idx = len(args) - 1 if args else 0
            fmt_arg = args[fmt_arg_idx].strip()

            # 判定格式串来源
            arg_source, has_pct_n, has_positional = _classify_fmt_arg(
                fmt_arg, line, source, direct_fmt_vars, var_constants)

            # 风险评估
            risk = _assess_risk(arg_source, has_pct_n, has_positional)

            findings.append(FmtFinding(
                func=func, line_no=line_no, line=line,
                arg_source=arg_source, has_pct_n=has_pct_n,
                has_positional=has_positional, risk=risk,
            ))

    # 汇总判定
    high_risk = [f for f in findings if f.risk in ('CRITICAL', 'HIGH', 'MEDIUM')]

# 后处理: DFA+污点验证精化
    # 调用 analysis/fmt_taint_bridge 对 CONSTANT 格式串做 DFA 危险等级验证
    # 对 EXTERNAL_INPUT 做污点传播可达性验证
    try:
        from analysis.fmt_taint_bridge import refine_fmt_findings
        fdicts = [
            {'line_no': f.line_no, 'line': f.line,
             'arg_source': f.arg_source, 'func': f.func,
             'risk': f.risk, 'has_pct_n': f.has_pct_n}
            for f in findings
        ]
        bridge_result = refine_fmt_findings(fdicts, source)
        # 应用过滤: _verdict='SAFE' 的从 high_risk 中移除
        for i, f in enumerate(findings):
            if i < len(fdicts) and fdicts[i].get('_verdict') == 'SAFE':
                f.risk = 'SAFE'
                if f in high_risk:
                    high_risk.remove(f)
    except ImportError:
        pass  # 桥接模块不可用 → 保持原有行为

    detected = len(high_risk) > 0

    return {
        'detected': detected,
        'findings': [
            {'func': f.func, 'line_no': f.line_no,
             'arg_source': f.arg_source, 'has_pct_n': f.has_pct_n,
             'risk': f.risk} for f in findings
        ],
        'count': len(findings),
        'high_risk': len(high_risk),
    }


def _assess_risk(source: str, has_n: bool, has_pos: bool) -> str:
    """五级风险评估: SAFE→INFO_LEAK→MEDIUM→HIGH→CRITICAL。"""
    if source == 'CONSTANT' and not has_n:
        return 'SAFE'
    if source == 'EXTERNAL_INPUT' and has_n:
        return 'CRITICAL'  # 任意地址写
    if source == 'EXTERNAL_INPUT' and has_pos:
        return 'HIGH'  # 泄露任意栈位置
    if source == 'EXTERNAL_INPUT':
        return 'MEDIUM'  # 信息泄露/拒绝服务
    if source == 'STACK_VAR' and has_n:
        return 'HIGH'  # 可能来自用户构造的格式串
    if has_pos:
        return 'MEDIUM'
    return 'SAFE'


def _parse_fmt_args(args_str: str) -> List[str]:
    """解析格式串函数的逗号分隔参数 (处理嵌套括号/引号)。"""
    args = []
    depth = 0
    in_str = False
    current = []
    for ch in args_str:
        if ch == '"' and (not current or current[-1] != '\\'):
            in_str = not in_str
        if not in_str:
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
        if ch == ',' and depth == 0 and not in_str:
            args.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        args.append(''.join(current).strip())
    return args
