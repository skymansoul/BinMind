# core/taint_crossfunc.py - 跨函数污点传播验证
#
# 函数内污点验证在 helper 函数调用处断链 (x = get_len(input) 后 x+n 溢出),
# 本模块构造"参数/局部变量→返回值"的函数摘要, 在调用图上按 worklist
# 求不动点, 对断链告警做跨函数溯源。只升级不降级: 函数内结论不变,
# 仅在断链处补充证据。
#
# 方法参照: Reps et al. 图可达性 IFDS 框架 (POPL 1995);
#           Arzt et al. FlowDroid 的 worklist 摘要传播 (PLDI 2014)。
#
# 启用方式: ENABLE_TAINTTRACK=1, 管线污点阶段自动调用。
import re
from typing import Dict, List, Set

# 与 int_overflow_taint._INT_TAINT_SOURCES 保持一致, 追加 argv/getenv
_TAINT_SOURCES = {
    'atoi', 'atol', 'atoll', 'strtol', 'strtoul', 'strtoll', 'strtoull',
    'scanf', 'fscanf', 'sscanf', 'getchar', 'fgetc', 'getc',
    'recv', 'recvfrom', 'read', 'fread',
    'ntohl', 'ntohs', 'strlen', 'getenv',
}

_EXCLUDED_OPS = {'int', 'long', 'size_t', 'unsigned', 'char', 'short',
                 'uint32_t', 'uint64_t', 'int32_t', 'int64_t'}

_SIG_RE = re.compile(r'^\s*[\w\s\*]+?\s+(\w[\w\d_]*)\s*\(([^)]*)\)\s*\{?\s*$', re.M)
_KEYWORDS = {'if', 'while', 'for', 'switch', 'return', 'sizeof', 'else'}
_DECL_ASSIGN_RE = re.compile(
    r'(?:int\w*|uint\w*|size_t|ssize_t|long|short|char|void|unsigned|bool)\s+\*?\s*(\w+)\s*=\s*([^;]+);')
_ASSIGN_RE = re.compile(r'(\w[\w\d_]*)\s*=\s*([^;]+);')
_RETURN_RE = re.compile(r'return\s+([^;]+);')
_CALL_RE = re.compile(r'(\w[\w\d_]*)\s*\(([^)]*)\)')


def _split_functions(pseudocode: str) -> Dict[str, str]:
    """按签名行切分函数。返回 {函数名: 函数体}。

    花括号风格(r2/ghidra)按括号配平; 无花括号风格(IDA 缩进伪代码)
    按缩进级别切分: 签名行之后缩进更深的行属于函数体。
    """
    funcs: Dict[str, str] = {}
    if '{' in pseudocode:
        for m in _SIG_RE.finditer(pseudocode):
            name = m.group(1)
            if name in _KEYWORDS:
                continue
            brace = pseudocode.find('{', m.end())
            if brace < 0:
                continue
            depth, end = 0, brace
            for k in range(brace, len(pseudocode)):
                ch = pseudocode[k]
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        end = k
                        break
            funcs[name] = pseudocode[brace + 1:end]
        return funcs

    lines = pseudocode.splitlines()
    i, n = 0, len(lines)
    while i < n:
        m = _SIG_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        if name in _KEYWORDS:
            i += 1
            continue
        sig_indent = len(lines[i]) - len(lines[i].lstrip())
        j = i + 1
        body = []
        while j < n:
            ln = lines[j]
            if ln.strip():
                ind = len(ln) - len(ln.lstrip())
                if ind <= sig_indent:
                    break
            body.append(ln)
            j += 1
        funcs[name] = '\n'.join(body)
        i = j
    return funcs


def _assign_map(body: str) -> Dict[str, str]:
    assigns: Dict[str, str] = {}
    for m in _DECL_ASSIGN_RE.finditer(body):
        assigns[m.group(1)] = m.group(2).strip()
    for m in _ASSIGN_RE.finditer(body):
        assigns[m.group(1)] = m.group(2).strip()
    return assigns


def _rhs_tainted(rhs: str, tainted_vars: Set[str],
                 ret_taint: Dict[str, bool]) -> bool:
    """判定右侧表达式是否可达污染源(函数内)。"""
    if any(s in rhs for s in _TAINT_SOURCES) or 'argv' in rhs:
        return True
    for v in tainted_vars:
        if re.search(r'\b' + re.escape(v) + r'\b', rhs):
            return True
    for m in _CALL_RE.finditer(rhs):
        g, args = m.group(1), m.group(2)
        if not ret_taint.get(g, False):
            continue
        if not args.strip():
            return True
        arg_tok = set(re.findall(r'\w[\w\d_]*', args))
        if arg_tok & (tainted_vars | _TAINT_SOURCES | {'argv'}):
            return True
    return False


def _body_tainted_vars(body: str, ret_taint: Dict[str, bool]) -> Set[str]:
    """函数体内可达污染源的变量集 (赋值不动点, 内层至多 6 轮)。"""
    tainted: Set[str] = set()
    assigns = _assign_map(body)
    for _ in range(6):
        added = False
        for v, rhs in assigns.items():
            if v in tainted:
                continue
            if _rhs_tainted(rhs, tainted, ret_taint):
                tainted.add(v)
                added = True
        if not added:
            break
    return tainted


def _compute_summaries(funcs: Dict[str, str], passes: int = 8) -> Dict[str, bool]:
    """worklist 摘要传播: 计算每个函数'返回值是否可达污染源'。

    参照 Arzt et al. FlowDroid (PLDI 2014) 的思路: 摘要变化仅沿反向
    调用边传播, 只重算摘要发生变化的被调函数的调用方, 替代原"每轮
    重算全部函数"的定点迭代。单调格上收敛结果与原实现一致。
    passes 参数保留为弹出次数上限 (兼容原签名, 防环)。
    """
    ret_taint: Dict[str, bool] = {}
    callers: Dict[str, Set[str]] = {}
    for name, body in funcs.items():
        for m in _CALL_RE.finditer(body):
            callee = m.group(1)
            if callee in funcs and callee != name:
                callers.setdefault(callee, set()).add(name)

    def _summarize(name: str) -> bool:
        tainted = _body_tainted_vars(funcs[name], ret_taint)
        return any(
            _rhs_tainted(ret_expr, tainted, ret_taint)
            for ret_expr in _RETURN_RE.findall(funcs[name])
        )

    worklist = list(funcs)
    queued = set(worklist)
    max_pops = passes * len(funcs) * 2
    pops = 0
    while worklist and pops < max_pops:
        name = worklist.pop()
        queued.discard(name)
        pops += 1
        new_rt = _summarize(name)
        if ret_taint.get(name, False) != new_rt:
            ret_taint[name] = new_rt
            for caller in callers.get(name, ()):
                if caller not in queued:
                    queued.add(caller)
                    worklist.append(caller)
    return ret_taint


def verify_crossfunc_taint(pseudocode: str, findings: List[Dict]) -> List[Dict]:
    """对函数内验证未确认的告警做跨函数溯源; 只升级不降级。

    pseudocode 为多个函数体的拼接文本(管线在污点阶段自行拼接)。
    """
    funcs = _split_functions(pseudocode)
    if not funcs:
        return findings
    ret_taint = _compute_summaries(funcs)

    tainted_by_func: Dict[str, Set[str]] = {}
    for name, body in funcs.items():
        tainted_by_func[name] = _body_tainted_vars(body, ret_taint)

    for f in findings:
        if f.get('taint_verified'):
            continue
        expr = f.get('expression', '')
        operands = [o for o in re.findall(r'\b(\w+)\b', expr)
                    if o not in _EXCLUDED_OPS]
        for op in operands:
            owner = next(
                (name for name, tainted in tainted_by_func.items()
                 if op in tainted),
                None,
            )
            if owner:
                f['confidence'] = max(0.75, f.get('confidence', 0.5))
                f['taint_verified'] = True
                srcs = f.get('taint_sources', [])
                tag = f'{op}←crossfunc:{owner}'
                if tag not in srcs:
                    srcs.append(tag)
                f['taint_sources'] = srcs
                break
    return findings
