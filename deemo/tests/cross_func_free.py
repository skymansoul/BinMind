"""
跨函数释放追踪 — 检测被调函数内部对参数的 free() 调用, 发现 UAF 盲区。

模式: void cleanup(T *p) { free(p); }
调用: cleanup(data); ... data->field = 0; → UAF (现有检测器漏检)

与 _build_global_alias_map 互补: 前者追踪 p→g_var 别名, 本模块追踪函数内 free(p)。
"""
import re
from typing import Dict, List


# 函数参数直接用 free(param) 释放
# void cleanup(T *p) { free(p); }
_FREE_PARAM_RE = re.compile(
    r'free\s*\(\s*(\w+)\s*\)\s*;',
)


def build_cross_func_free_map(source: str) -> Dict[str, List[int]]:
    """预扫描: 找到内部调用 free(param) 的函数, 返回 {func_name: [param_index, ...]}。

    例: void cleanup(T *p) { free(p); } → {'cleanup': [0]}
    """
    fmap: Dict[str, List[int]] = {}
    lines = source.splitlines()

    current_func = None
    current_params: List[str] = []
    brace_depth = 0
    in_func = False

    for i, raw_line in enumerate(lines):
        line = raw_line.strip()

# 函数签名检测
        fm = re.match(
            r'(?:void|int|static\s+(?:void|int))\s*'
            r'(\w+)\s*\(([^)]*)\)\s*\{?', line)
        if fm and not in_func:
            current_func = fm.group(1)
            params_str = fm.group(2)
            current_params = _extract_param_names(params_str)
            if '{' in line:
                in_func = True
                brace_depth = line.count('{') - line.count('}')
            continue

# 函数体开始 (签名和 { 分两行)
        if current_func and not in_func:
            if '{' in line:
                in_func = True
                brace_depth = line.count('{') - line.count('}')
            continue

# 函数体内
        if in_func and current_func:
            brace_depth += line.count('{') - line.count('}')

            if brace_depth <= 0:
                in_func = False
                current_func = None
                current_params = []
                brace_depth = 0
                continue

            # 检测 free(param) — param 必须是本函数参数
            fm = _FREE_PARAM_RE.search(line)
            if fm:
                freed_var = fm.group(1)
                if freed_var in current_params:
                    idx = current_params.index(freed_var)
                    if idx not in fmap.get(current_func, []):
                        fmap.setdefault(current_func, []).append(idx)

    return fmap


def _extract_param_names(params_str: str) -> List[str]:
    """从函数签名参数字符串提取参数名列表。"""
    names = []
    if not params_str.strip():
        return names
    for part in params_str.split(','):
        part = part.strip()
        if part == '...' or part == 'void':
            continue
        tokens = part.split()
        name = tokens[-1].lstrip('*')
        if name and re.match(r'^[a-zA-Z_]\w*$', name):
            names.append(name)
    return names


def detect_cross_func_frees(source: str, cross_func_free_map: Dict[str, List[int]],
                             free_records: list, alias_map: dict) -> None:
    """检测跨函数 free 调用, 追加虚拟 free 记录到 free_records。

    对每个 func(ptr) 调用:
      - 如果 func 内部 free 其参数, 则 ptr 视为在调用处被 free
      - 记录 {'ptr_var': ptr, 'line_no': call_line, 'cross_func_free': func}
    """
    lines = source.splitlines()

    for m in re.finditer(r'(\w+)\s*\(([^;()\n]*)\)\s*;', source):
        callee = m.group(1)
        if callee not in cross_func_free_map:
            continue

        args_str = m.group(2)
        args = _parse_call_args(args_str)
        line_no = source[:m.start()].count('\n') + 1

        # 跳过注释和字符串字面量中的匹配
        matched_line = lines[line_no - 1].strip() if line_no <= len(lines) else ''
        if matched_line.startswith(('//', '/*', '*', '#')):
            continue
        if matched_line.startswith(('模式', '调用', '与', '例', '注', '说')):
            continue

        for param_idx in cross_func_free_map[callee]:
            if param_idx >= len(args):
                continue
            ptr_expr = args[param_idx].strip()
            base_ptr = _extract_base_name(ptr_expr)

            # 避免重复: 此调用行是否已有 free 记录
            dup = any(r.get('ptr_var') == base_ptr and r.get('line_no') == line_no
                     for r in free_records)
            if not dup:
                free_records.append({
                    'ptr_var': base_ptr,
                    'ptr_expr': ptr_expr,
                    'line_no': line_no,
                    'line': lines[line_no - 1].strip() if line_no <= len(lines) else '',
                    'cross_func_free': callee,
                })


def _parse_call_args(args_str: str) -> List[str]:
    """解析函数调用参数 (处理嵌套括号和引号)。"""
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


def _extract_base_name(ptr_expr: str) -> str:
    """提取基指针名: arr[i]→arr, p->field→p。"""
    m = re.match(r'(\w+)\[', ptr_expr)
    if m: return m.group(1)
    m = re.match(r'(\w+)\s*->', ptr_expr)
    if m: return m.group(1)
    return ptr_expr.strip()
