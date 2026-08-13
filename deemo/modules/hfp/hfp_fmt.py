"""
格式化字符串检测器 — 伪 IR 级参数验证.

在 HFP 伪 IR 上验证格式化字符串调用的安全性, 三类判定:
  1. 用户可控格式化串: fmt 参数源自外部输入 (read/recv/scanf/
     argv 等) → 格式串注入漏洞 (CWE-134)
  2. 静态格式串但参数缺失: 说明符数量 > 可用实参 → 栈读取
     (信息泄露/崩溃)
  3. %n 写入: 格式串含 %n 且 fmt 可控或参数可写 → 任意写
格式化函数的实参来自翻译器 handle_call 的 ABI 寄存器提取
(前 4 个), 超出部分标 '?'. 判定基于污点来源与说明符计数.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .hfp_taint import TaintLevel, TaintState, run_taint, taint_of_var

_RE_FMT_CALL = re.compile(
    r'(printf|fprintf|sprintf|snprintf|dprintf|vprintf|vfprintf|'
    r'vsprintf|vsnprintf|syslog)\s*\(', re.IGNORECASE)
_RE_SPECIFIER = re.compile(r'%[-+ #0-9.*]*[diouxXeEfgGcspn]')
_RE_N_SPEC = re.compile(r'%[-+ #0-9.*]*n')

# 外部输入源: fmt 若源自这些函数返回值/参数即用户可控
_INPUT_FUNCS = ('read', 'recv', 'recvfrom', 'scanf', 'fscanf', 'sscanf',
                'fgets', 'getenv', 'getc', 'fread', 'argv', 'atoi',
                'strtol', 'strtoul')

# 既有检测器 (deemo/core/format_string_detector.py) 的模式匹配
# 语义: printf(buf) 危险, printf("...", args) 安全 — 本模块在
# 伪 IR 上以污点+说明符计数实现同等级验证, 支持二进制输入


@dataclass
class FmtFinding:
    """格式化字符串漏洞判定."""
    call_line: int
    func: str
    fmt_arg: str
    verdict: str          # VULN / LEAK / SAFE
    reason: str
    confidence: float = 0.0


def _EXT_INPUT_VARS(ir_lines: List[str]) -> set:
    """收集翻译器标注的 ext_input 伪变量 (argv 间接读)."""
    out = set()
    for line in ir_lines:
        m = re.match(r'(\w+)\s*=\s*ext_input\(\)', line)
        if m:
            out.add(m.group(1))
    return out


def _fmt_operands(line: str) -> List[str]:
    """解析 fmt 调用的实参列表 (按顶层逗号切分)."""
    m = _RE_FMT_CALL.search(line)
    if not m:
        return []
    depth = 0
    parts: List[str] = []
    cur = ''
    for i in range(m.end(), len(line)):
        c = line[i]
        if c == '(':
            depth += 1
            cur += c
        elif c == ')':
            if depth == 0:
                if cur.strip():
                    parts.append(cur.strip())
                break
            depth -= 1
            cur += c
        elif c == ',' and depth == 0:
            parts.append(cur.strip())
            cur = ''
        else:
            cur += c
    return parts


def _count_specifiers(fmt: str) -> int:
    """统计格式说明符数量 (% 后跟转换字符)."""
    if not fmt:
        return 0
    return len(_RE_SPECIFIER.findall(fmt))


def _has_n_specifier(fmt: str) -> bool:
    return bool(_RE_N_SPEC.search(fmt))


def _fmt_is_static(fmt: str) -> bool:
    """静态格式串: 不含控制字符, 是引号字符串字面量."""
    if not fmt:
        return False
    stripped = fmt.strip('\'"')
    return bool(stripped) and stripped == fmt.strip() and \
        not re.search(r'[\\\x00-\x1f]', stripped)


def fmt_extract_call(translator, name: str) -> None:
    """翻译器委托: 提取格式化调用实参生成伪 IR 行.

    实参按 ABI 寄存器取前 4 个, 超出部分标 '?'. 由 asm_handlers
    的 handle_call 调用, 保持 hfp_fmt 的自包含 (翻译器对象经
    鸭子类型访问 regs/arg_regs/ir).
    """
    args = [translator.regs.get(r) for r in translator.arg_regs]
    fmt = args[0] if args else None
    fmt_name = fmt if isinstance(fmt, str) else \
        (str(fmt) if fmt is not None else '?')
    rest = ', '.join(str(a) if a is not None else '?'
                     for a in args[1:])
    translator.ir.append(
        f'{name}({fmt_name}{", " + rest if rest else ""})')


def detect_format_string_hfp(ir_lines: List[str]) -> List[FmtFinding]:
    """伪 IR 级格式化字符串检测: 返回 finding 列表."""
    taint = run_taint(ir_lines)
    findings: List[FmtFinding] = []

    for i, line in enumerate(ir_lines):
        m = _RE_FMT_CALL.search(line)
        if not m:
            continue
        func = m.group(1).lower()
        operands = _fmt_operands(line)
        if not operands:
            continue
        fmt_arg = operands[0]

        # 判定 0: fmt 是拷贝目标 (strcpy/strncpy/memcpy 的 dst) —
        # 栈缓冲区接收用户输入后直接作格式串. 全文件扫描:
        # 函数块按地址排序, 拷贝可能在 printf 所在块之后.
        # fmt='?' (未解析, 如 .rodata 静态串地址) 不适用 — 避免
        # 与未知 dst 的 '?' 误匹配
        if fmt_arg != '?' and _is_copy_target(fmt_arg, ir_lines):
            findings.append(FmtFinding(
                call_line=i, func=func, fmt_arg=fmt_arg,
                verdict='VULN',
                reason=f'fmt 是拷贝目标 ({fmt_arg}): 用户输入经拷贝'
                       f'后作格式串',
                confidence=0.88))
            continue

        # 判定 1: 用户可控格式化串 — fmt 是外部输入变量
        fmt_var = fmt_arg if re.fullmatch(r'\w+', fmt_arg) else None
        fmt_taint = None
        if fmt_var:
            fmt_taint = taint_of_var(taint, fmt_var)
        if fmt_taint and fmt_taint.level in (
                TaintLevel.EXTERNAL, TaintLevel.MIXED):
            findings.append(FmtFinding(
                call_line=i, func=func, fmt_arg=fmt_arg,
                verdict='VULN',
                reason=f'fmt 可控 ({fmt_taint.src_expr}): 格式串注入',
                confidence=0.92))
            continue
        # 判定 1b: fmt 是 ext_input() 伪变量 — 翻译器标注的
        # argv 间接读 (argv[i]) 外部输入
        if fmt_var and fmt_var in _EXT_INPUT_VARS(ir_lines):
            findings.append(FmtFinding(
                call_line=i, func=func, fmt_arg=fmt_arg,
                verdict='VULN',
                reason=f'fmt 来自 argv 间接 ({fmt_var}): 格式串注入',
                confidence=0.90))
            continue

        # 判定 2: %n 写入 — fmt 含 %n 且 fmt 来自内部变量
        if fmt_var and _has_n_specifier(fmt_arg):
            findings.append(FmtFinding(
                call_line=i, func=func, fmt_arg=fmt_arg,
                verdict='VULN',
                reason='%n 写入: 可任意写内存',
                confidence=0.85))
            continue

        # 判定 3: 静态格式串 + 参数缺失 — 说明符数 > 实参数
        if _fmt_is_static(fmt_arg):
            n_spec = _count_specifiers(fmt_arg)
            n_args = len(operands) - 1
            if n_spec > n_args:
                findings.append(FmtFinding(
                    call_line=i, func=func, fmt_arg=fmt_arg,
                    verdict='LEAK',
                    reason=f'{n_spec} 个说明符但仅 {n_args} 个实参: '
                           f'栈读取泄露',
                    confidence=0.75))
                continue
            if n_spec == n_args:
                continue  # 安全: 说明符与实参匹配

        # 其余: fmt 不可解析或参数匹配 — 保守 SAFE
        findings.append(FmtFinding(
            call_line=i, func=func, fmt_arg=fmt_arg,
            verdict='SAFE',
            reason='fmt 静态或参数匹配, 无注入面',
            confidence=0.10))

    findings.sort(key=lambda f: -f.confidence)
    return findings


def _is_copy_target(fmt_arg: str, prior_lines: List[str]) -> bool:
    """fmt 参数是否为 strcpy/strncpy/memcpy 的拷贝目标.

    拷贝目标的 dst 是栈地址元组或变量, 若此前存在
      copy(dst, src, n) 或 copy(dst, src)
    且 dst 与 fmt_arg 一致, 则 fmt 是用户输入缓冲.
    dst 可能是元组 repr (含逗号), 用括号平衡取顶层参数.
    """
    if not fmt_arg:
        return False
    for line in prior_lines:
        m = re.search(
            r'(strcpy|strncpy|memcpy|sprintf|vsprintf)\s*\(', line,
            re.IGNORECASE)
        if not m:
            continue
        dst = _first_arg(line[m.end():])
        if dst == fmt_arg:
            return True
    return False


def _first_arg(rest: str) -> str:
    """取调用剩余部分的第一个顶层参数 (括号平衡)."""
    depth = 0
    for i, c in enumerate(rest):
        if c == '(':
            depth += 1
        elif c == ')':
            if depth == 0:
                return rest[:i].strip()
            depth -= 1
        elif c == ',' and depth == 0:
            return rest[:i].strip()
    return rest.strip()


def detect_from_asm(asm_text: str) -> List[FmtFinding]:
    """反汇编文本 → 伪 IR → fmt findings."""
    from .hfp_scan import asm_to_pseudo_ir
    ir = asm_to_pseudo_ir(asm_text)
    return detect_format_string_hfp(ir)