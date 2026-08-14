"""
循环边界标量写检测 — 为循环体内数组写合成memcpy IR。
若无此处理，循环内标量写无IR可见尺寸 → TOP区间 → 本可检测的溢出被判UNCERTAIN。
"""

from __future__ import annotations
import re
from typing import Dict, List, Optional

from .symbolic_range import AffineInterval, PathCondition

_SIMPLE_FOR = re.compile(
    r'for\s*\(\s*(?:size_t|int|unsigned(?:\s+int)?)\s+'
    r'(\w[\w.]*)\s*=\s*\d+\s*;'
    r'\s*\1\s*(?:<=?)\s*(\w[\w.]*|\d+)\s*;',
    re.DOTALL)

_RE_MALLOC_BUF = re.compile(
    r'(\w[\w.\->]*)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(malloc|calloc|realloc)\s*\(')


def detect_loop_writes(code: str, alloc_sites: list, write_sites: list) -> None:
    """检测循环内数组写入, 将循环次数作为write_size添加到write_sites.

    这是 path_sensitive_vrf 的关键补充:
    - malloc(N) + for(i<N) arr[i]=x → write_size=N (通过循环边界推断)
    - calloc(M, sizeof(T)) + for(i<10) arr[i]=x → write_size=10
    无此函数时, 循环内的标量写没有memcpy IR, write_size=TOP → UNCERTAIN.
    """
    # 快速逃逸: 代码中无for/while循环则跳过
    if 'for' not in code and 'while' not in code:
        return

    lines = code.splitlines()
    # 收集已分配的缓冲区变量 + 元素类型推断
    alloc_bufs: Dict[str, int] = {}  # var_name → allocation_size (if constant)
    _elem_size_map = {'int': 4, 'long': 8, 'char': 1, 'short': 2,
                      'float': 4, 'double': 8, 'size_t': 8, 'unsigned': 4,
                      'uint32_t': 4, 'uint64_t': 8, 'void': 1}
    _elem_sizes: Dict[str, int] = {}  # var_name → element_size
    for line in lines:
        m = _RE_MALLOC_BUF.search(line)
        if m:
            var = m.group(1)
            # 尝试提取常量分配大小
            sz_m = re.search(r'(?:malloc|calloc)\s*\(\s*(\d+)', line)
            if not sz_m:
                sz_m = re.search(r'calloc\s*\(\s*(\d+)\s*,\s*sizeof', line)
            if sz_m:
                alloc_bufs[var] = int(sz_m.group(1))
            # 推断元素类型
            _type_m = re.search(
                r'(int|char|short|long|float|double|size_t|unsigned(?:\s+int)?|'
                r'uint32_t|uint64_t|void)\s*\*\s*' + re.escape(var), line)
            if _type_m:
                _type_str = _type_m.group(1).replace(' ', '')
                _elem_sizes[var] = _elem_size_map.get(_type_str, 4)
        # 也匹配纯声明: int *arr; (无初始化)
        _decl_m = re.search(
            r'(int|char|short|long|float|double|size_t|unsigned(?:\s+int)?|'
            r'uint32_t|uint64_t)\s*\*\s*(\w+)\s*[;,=]', line)
        if _decl_m:
            _type_str = _decl_m.group(1).replace(' ', '')
            _decl_var = _decl_m.group(2)
            if _decl_var not in _elem_sizes:
                _elem_sizes[_decl_var] = _elem_size_map.get(_type_str, 4)

    # 扫描循环内的数组写入
    in_loop = False
    loop_bound_val: Optional[int] = None
    loop_var: Optional[str] = None
    brace_depth = 0
    loop_start_ln = 0

    for i, line in enumerate(lines):
        stripped = line.strip()

        # 检测 for 循环头
        fm = re.search(
            r'for\s*\(\s*(?:int|size_t|unsigned(?:\s+int)?)\s+'
            r'(\w+)\s*=\s*(\d+)\s*;'
            r'\s*\1\s*(<|<=)\s*(\w+|\d+)\s*;',
            stripped)
        if fm:
            in_loop = True
            loop_var = fm.group(1)
            loop_bound_val = int(fm.group(4)) if fm.group(4).isdigit() else None
            if fm.group(3) == '<=' and loop_bound_val is not None:
                loop_bound_val += 1  # <= N → N+1 iterations
            brace_depth = 0
            loop_start_ln = i
            if '{' in stripped:
                # 多行循环体: for(...) { ... }
                continue
            # 无花括号循环: for(...) body_stmt (同行或下一行)
            # 找到 for 头的闭合 ')' 之后的内容
            _close_paren = stripped.rfind(')')
            if _close_paren > 0:
                _after_paren = stripped[_close_paren + 1:].strip()
                if _after_paren and not _after_paren.startswith('{'):
                    # 同行有循环体语句: for(...) arr[i]=x;
                    _check_single_line_loop(
                        stripped, alloc_bufs, alloc_sites, write_sites, i,
                        loop_bound_val, _elem_sizes)
                    in_loop = False
            # else: 无花括号 + 同行无循环体 → 下一行是循环体
            continue

        if not in_loop:
            continue

        # 在循环体内
        brace_delta = stripped.count('{') - stripped.count('}')
        brace_depth += brace_delta

        # 检测数组写: buf[expr] = ...
        aw = re.search(r'(\w[\w.]*)\s*\[([^\]]*)\]\s*=', stripped)
        if aw:
            buf_var = aw.group(1)
            _add_loop_write_site(
                buf_var, alloc_bufs, alloc_sites, write_sites, i,
                loop_bound_val, stripped, _elem_sizes)

        # 循环结束条件
        if brace_depth <= 0:
            if '}' in stripped:
                in_loop = False
            elif loop_start_ln >= 0 and '{' not in lines[loop_start_ln]:
                # 无花括号循环: for(...) 的下一行是循环体, 处理完即结束
                # 循环体只有一条语句 (当前行), 下一行退出循环
                in_loop = False
            loop_bound_val = None
            loop_var = None


def _check_single_line_loop(line: str, alloc_bufs: Dict[str, int],
                             alloc_sites: list, write_sites: list,
                             lineno: int, bound: Optional[int],
                             elem_sizes: Dict[str, int] = None) -> None:
    """处理单行循环体: for(...) arr[i]=x;"""
    aw = re.search(r'(\w[\w.]*)\s*\[([^\]]*)\]\s*=', line)
    if aw:
        buf_var = aw.group(1)
        _add_loop_write_site(buf_var, alloc_bufs, alloc_sites, write_sites,
                             lineno, bound, line.strip()[:80], elem_sizes)


def _add_loop_write_site(buf_var: str, alloc_bufs: Dict[str, int],
                          alloc_sites: list, write_sites: list,
                          lineno: int, bound: Optional[int],
                          detail: str,
                          elem_sizes: Dict[str, int] = None) -> None:
    """将循环写添加为WriteSite, 乘以元素类型大小."""
    # 检查buf是否匹配已知分配变量
    matched_alloc = False
    for alloc in alloc_sites:
        if alloc.var_name == buf_var or buf_var in alloc.var_name:
            matched_alloc = True
            break
    if not matched_alloc and buf_var not in alloc_bufs:
        return  # 不是堆分配的目标, 跳过

    # 推断元素大小 (默认4=int)
    elem_size = 4
    if elem_sizes and buf_var in elem_sizes:
        elem_size = elem_sizes[buf_var]

    # 推断write_size — 循环次数 × 元素大小
    if bound is not None and bound > 0:
        total_bytes = bound * elem_size
        ws = AffineInterval(lo=total_bytes, hi=total_bytes)
    else:
        # 符号上界: 保守估计
        ws = AffineInterval(lo=elem_size, hi=2 ** 31 - 1)

    write_sites.append(type('WriteSite', (),
                            {'var_name': buf_var,
                             'write_size': ws,
                             'write_call': f"memcpy({buf_var}, <loop_body>, {bound or '?'})",
                             'path_cond': PathCondition(),
                             'block_id': 0,
                             'lineno': lineno})())


def add_loop_write_hints(c_source: str, ir_lines: List[str]) -> List[str]:
    """检测循环内标量写并追加合成memcpy IR行：逐行扫描检测for循环后
    的数组写，对C源码模式比多行正则更稳健。"""
    enhanced = list(ir_lines)

    # 剥离注释
    s = re.sub(r'/\*.*?\*/', '', c_source, flags=re.DOTALL)
    s = re.sub(r'//[^\n]*', '', s)

    # 该缓冲区已有合成memcpy则跳过
    existing_syn_bufs = set()
    for l in enhanced:
        if 'loop_write' in l:
            wm = re.search(r'(?:memcpy|memmove|strncpy)\s*\(\s*(\w[\w.]*)', l)
            if wm:
                existing_syn_bufs.add(wm.group(1))

    # 为仿射跟踪生成唯一合成变量名
    _syn_counter = [0]
    def _fresh_syn_var() -> str:
        _syn_counter[0] += 1
        return f'_syn_loop_{_syn_counter[0]}'

    lines = s.splitlines()
    in_loop = False
    loop_bound: Optional[str] = None
    loop_body_bufs: Dict[str, str] = {}  # buf_var -> bound_expr

    for i, line in enumerate(lines):
        stripped = line.strip()

        # 检测for循环头
        fm = _SIMPLE_FOR.search(stripped)
        if fm:
            in_loop = True
            bound_var = fm.group(2)
            has_lte = '<=' in stripped
            if has_lte and bound_var.isdigit():
                loop_bound = str(int(bound_var) + 1)
            elif has_lte:
                loop_bound = f'{bound_var}+1'
            else:
                loop_bound = bound_var
            continue

        # 循环结束
        if in_loop and stripped == '}':
            for buf_var, bound_expr in loop_body_bufs.items():
                if buf_var not in existing_syn_bufs and bound_expr:
                    _emit_syn_memcpy(enhanced, buf_var, bound_expr,
                                     _fresh_syn_var())
            in_loop = False
            loop_bound = None
            loop_body_bufs.clear()
            continue

        # 循环内: 查找数组写
        if in_loop and loop_bound:
            aw = re.search(
                r'(\w[\w.]*)\s*\[([^\]]*)\]\s*=',
                stripped)
            if aw:
                buf_var = aw.group(1)
                index_expr = aw.group(2).strip()
                # 接受数值与符号偏移（宏已展开）
                offset_m = re.match(r'(\w+)\s*\+', index_expr)
                if offset_m:
                    offset = offset_m.group(1)
                    loop_body_bufs[buf_var] = f'{loop_bound}+{offset}'
                else:
                    loop_body_bufs[buf_var] = loop_bound

    # 阶段2: 字符串迭代循环中的指针解引用写
    # 检测CVE-2021-3156: malloc(strlen(X)+K)但*ptr++写溢出
    from core.ptr_deref_detector import detect_ptr_deref_overflow
    detect_ptr_deref_overflow(s, enhanced, existing_syn_bufs, _fresh_syn_var)

    return enhanced


def _emit_syn_memcpy(enhanced: List[str], buf_var: str,
                     bound_expr: str, fresh_var: str) -> None:
    """输出合成memcpy IR；将'user_size+1+16'分解为 _syn_N_base=user_size+1;
    _syn_N=_syn_N_base+16; memcpy(buf,*, _syn_N); 仿射分析器链接:
    write_sz = alloc_sz + 1 → 判定溢出。"""
    if bound_expr.isdigit():
        enhanced.append(
            f'memcpy({buf_var}, <loop_body>, {bound_expr});'
            f'  /* loop_write */')
        return

    # 分解: 找到表达式末尾的'+const'用于仿射跟踪
    # 例如 'user_size+1+16' → base='user_size+1', offset=16
    # 不加尾注释 — 仿射分析器正则严格匹配
    parts = bound_expr.rsplit('+', 1)
    if len(parts) == 2 and parts[1].strip().isdigit():
        base_expr = parts[0].strip()
        offset = parts[1].strip()
        enhanced.append(f'{fresh_var}_base = {base_expr};')
        enhanced.append(f'{fresh_var} = {fresh_var}_base + {offset};')
    else:
        enhanced.append(f'{fresh_var} = {bound_expr};')

    enhanced.append(
        f'memcpy({buf_var}, <loop_body>, {fresh_var});'
        f'  /* loop_write */')


__all__ = ['add_loop_write_hints', 'detect_loop_writes']
