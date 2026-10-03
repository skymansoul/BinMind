"""
跨函数堆写入追踪 — 检测被调函数内部对堆指针参数的写入操作。

模式: void f(T *p, size_t n) { memset(p, 0, n); }
调用: f(heap_ptr, 64) → heap_ptr 被写入 64 字节, 现有扫描器漏检。

从 source_scanner 的跨函数分配追踪扩展, 补齐跨函数写入盲区。
"""
import re
from typing import Any, Dict, List, Tuple


# 函数体内的写入操作 (参数作为目标)
# memset(param, ...) / memcpy(param, ...) / strcpy(param, ...) / *param = ...
# 支持参数的成员/偏移: memcpy(rf->regs + offset, ...) / memset(ptr->field, ...)
_PARAM_WRITE_RE = re.compile(
    r'(memcpy|memmove|memset|strcpy|strncpy|strcat|strncat|sprintf|snprintf)'
    r'\s*\(\s*([^,]+?)\s*,',
    re.IGNORECASE,
)

# 函数定义: void/int/static func_name(T1 p1, T2 p2, ...) {
_FUNC_SIG_RE = re.compile(
    r'(?:void|int|char|size_t|long|short|float|double|uint\w+_t|int\w+_t'
    r'|unsigned(?:\s+(?:int|char|short|long))?'
    r'|static\s+(?:void|int|char|size_t))'
    r'\s*\*?\s*(\w+)\s*\(([^)]*)\)\s*\{?',
)

# 调用点: func_name(arg1, arg2, ...);
_CALL_SITE_RE = re.compile(
    r'(\w+)\s*\(([^;]*)\)\s*;',
)


def build_param_write_map(source: str) -> Dict[str, List[Tuple[int, str, str]]]:
    """预扫描: 构建函数→参数写入映射。

    返回: {func_name: [(param_index, write_func, size_arg_expr), ...]}
    例: {'init_buffer': [(0, 'memset', 'sz')]}  — 第0个参数被memset写入, 大小=参数sz
    """
    pmap: Dict[str, List[Tuple[int, str, str]]] = {}
    lines = source.splitlines()

    current_func = None
    current_params: List[str] = []
    brace_depth = 0
    in_func = False

    for i, raw_line in enumerate(lines):
        line = raw_line.strip()

# 函数签名检测
        fm = _FUNC_SIG_RE.match(line)
        if fm and not in_func:
            current_func = fm.group(1)
            params_str = fm.group(2)
            # 解析参数名 (从 "char *buf, size_t sz" 提取 ["buf", "sz"])
            current_params = _extract_param_names(params_str)
            if '{' in line:
                in_func = True
                brace_depth = line.count('{') - line.count('}')
            continue

# 函数体开始
        if current_func and not in_func:
            if '{' in line:
                in_func = True
                brace_depth = line.count('{') - line.count('}')
            continue

# 函数体内
        if in_func and current_func:
            brace_depth += line.count('{') - line.count('}')

            # 检查是否结束
            if brace_depth <= 0:
                in_func = False
                current_func = None
                current_params = []
                brace_depth = 0
                continue

            # 检测参数写入: memset(param, ...) / memcpy(param->field + off, ...)
            wm = _PARAM_WRITE_RE.search(line)
            if wm:
                func = wm.group(1).lower()
                target_expr = wm.group(2).strip()
                # 提取基指针名: rf->regs + offset → rf
                target = _extract_base_ptr_local(target_expr)
                if target in current_params:
                    param_idx = current_params.index(target)
                    # 提取 size 参数 (memset的第三个参数, strcpy无size)
                    size_src = ''
                    if func in ('memset', 'memcpy', 'memmove', 'strncpy',
                               'strncat', 'snprintf'):
                        # 尝试提取第三个参数 (支持结构体成员表达式)
                        args_match = re.search(
                            rf'{func}\s*\(\s*[^,]+,\s*[^,]+,\s*(\w[\w\d_]*(?:\s*->\s*\w[\w\d_]*)?(?:\s*\.\\s*\w[\w\d_]*)?)',
                            line, re.IGNORECASE)
                        if args_match:
                            size_src = args_match.group(1).strip()
                            # 如果size参数名在函数参数列表中, 追踪它
                            base = _extract_base_ptr_local(size_src)
                            if base in current_params:
                                size_src = size_src  # 保持参数名引用
                    elif func in ('strcpy', 'strcat', 'sprintf'):
                        size_src = 'unbounded'

                    existing = [e for e in pmap.get(current_func, [])
                               if e[0] == param_idx]
                    if not existing:
                        pmap.setdefault(current_func, []).append(
                            (param_idx, func, size_src))

    return pmap


def _extract_base_ptr_local(expr: str) -> str:
    """从表达式提取基指针: rf->regs + offset → rf, buf → buf。"""
    expr = expr.strip()
    # ptr->field / ptr.field
    m = re.match(r'(\w+)\s*(?:->|\.)\s*\w', expr)
    if m:
        return m.group(1)
    # ptr[idx]
    m = re.match(r'(\w+)\s*\[', expr)
    if m:
        return m.group(1)
    # ptr + offset / ptr - offset
    m = re.match(r'(\w+)\s*[+\-]', expr)
    if m:
        return m.group(1)
# ptr
    m = re.match(r'\*(\w+)', expr)
    if m:
        return m.group(1)
    return expr


def _extract_param_names(params_str: str) -> List[str]:
    """从函数签名参数字符串提取参数名列表。

    'char *buf, size_t sz' → ['buf', 'sz']
    'int fd, const char *fmt, ...' → ['fd', 'fmt']
    """
    names = []
    if not params_str.strip():
        return names
    # 按逗号分割 (简单处理, 不处理嵌套<>)
    for part in params_str.split(','):
        part = part.strip()
        if part == '...' or part == 'void':
            continue
        # 取最后一个单词作为参数名
        tokens = part.split()
        # 去除 * 前缀
        name = tokens[-1].lstrip('*')
        if name and re.match(r'^[a-zA-Z_]\w*$', name):
            names.append(name)
    return names


def detect_cross_func_writes(source: str, alloc_list: List[Dict],
                              findings: List[Dict],
                              param_write_map: Dict) -> None:
    """检测跨函数堆写入: 匹配 f(heap_ptr, ...) 调用, 其中 f 内部写入参数。

    将检测到的写入追加到 findings 列表。
    """
    lines = source.splitlines()

    for m in _CALL_SITE_RE.finditer(source):
        callee = m.group(1)
        if callee not in param_write_map:
            continue

        args_str = m.group(2)
        args = _parse_call_args(args_str)
        writes = param_write_map[callee]
        line_no = source[:m.start()].count('\n') + 1
        line_text = lines[line_no - 1].strip() if line_no <= len(lines) else ''

        for param_idx, write_func, size_src in writes:
            if param_idx >= len(args):
                continue
            ptr_expr = args[param_idx].strip()

            # 提取基指针名
            base_ptr = _extract_base_ptr(ptr_expr)

            # 检查此指针是否有分配记录
            alloc = _find_alloc(alloc_list, base_ptr, line_no)
            if not alloc:
                continue

            # 解析写入大小
            write_size = 0
            size_expr = ''
            if size_src == 'unbounded':
                write_size = 999999
                size_expr = 'unbounded'
            elif size_src and size_src in args:
                # size 参数来自调用参数列表
                size_expr = args[args.index(size_src)] if size_src in args else ''
            elif size_src:
                # size_src 是被调函数参数名, 查找调用中对应位置的值
                size_expr = size_src

            if write_size == 0 and size_expr:
                write_size = _eval_size_simple(size_expr)

            findings.append({
                'type': 'write',
                'func': write_func,
                'ptr': base_ptr,
                'ptr_full': ptr_expr,
                'write_size': write_size,
                'size_expr': size_expr,
                'line_no': line_no,
                'line': line_text,
                'cross_func': callee,
            })


def _parse_call_args(args_str: str) -> List[str]:
    """解析函数调用的参数列表 (处理嵌套括号和引号)。"""
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


def _extract_base_ptr(ptr_expr: str) -> str:
    """提取基指针名: arr[i]→arr, p->field→p, *p→p。"""
    m = re.match(r'(\w+)\[', ptr_expr)
    if m: return m.group(1)
    m = re.match(r'(\w+)\s*->', ptr_expr)
    if m: return m.group(1)
    return ptr_expr.strip()


def _find_alloc(alloc_list: List[Dict], ptr: str, line_no: int) -> dict:
    """查找指针的最近分配 (line_no 之前)。"""
    best = None
    for a in alloc_list:
        if a['ptr_var'] == ptr and a['line_no'] < line_no:
            if best is None or a['line_no'] > best['line_no']:
                best = a
    return best


def _eval_size_simple(expr: str) -> int:
    """简易数值求值 (仅支持数字和 sizeof(type))。"""
    expr = expr.strip()
    if expr.isdigit():
        return int(expr)
    # sizeof(type) 或 sizeof(expr)
    sm = re.match(r'sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)', expr)
    if sm:
        type_name = sm.group(1).split()[0].rstrip('*')
        sizes = {'char': 1, 'short': 2, 'int': 4, 'long': 8,
                 'float': 4, 'double': 8, 'size_t': 8, 'void': 1}
        return sizes.get(type_name, 4)
    # 十六进制常量
    if expr.startswith('0x') or expr.startswith('0X'):
        try:
            return int(expr, 16)
        except ValueError:
            pass
    return 0
