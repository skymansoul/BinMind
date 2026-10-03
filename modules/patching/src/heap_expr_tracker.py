# 堆溢出表达式追踪 — 汇编级表达式构建
"""从objdump反汇编构建alloc/write的符号表达式,
支持 O(n) 窗口内寄存器回溯 + 栈槽追踪 + strlen↔strcpy off-by-one 检测。
"""

import re
from typing import Optional, Tuple, List
from .heap_expr_engine import (
    ExprKind, Expr, const_expr, taint_expr,
    add_expr, sub_expr, mul_expr, compare_for_overflow, _extract_const_offset)


# 汇编级表达式构建

# 用户输入源函数
_SOURCE_FUNCS = re.compile(
    r'\b(strlen|atoi|strtoul|strtol|read|recv|recvfrom|fgets|scanf|getenv|'
    r'fread|getc|gets|wcstombs|mbstowcs|g_ascii_strtoull|strtouq)\b', re.I)

# 算术指令
_ARITH_PAT = re.compile(
    r'\b(add|sub|inc|dec|shl|shr|sal|sar|imul|mul)\s+(\w+),\s*(0x[0-9a-f]+|\d+)', re.I)
_LEA_ARITH = re.compile(
    r'\blea\s+(\w+),\s*\[(\w+)\s*([+\-])\s*(\w+)\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]', re.I)


def build_alloc_expr(asm: List[str], lowered: List[str],
                     call_idx: int) -> Tuple[int, bool, Optional[Expr]]:
    """从malloc调用点回溯, 构建alloc size表达式。

    返回: (size_int, is_tainted, optional_expr)
    - 若size为常量: size_int=常量值, is_tainted=False, expr=ConstExpr
    - 若size来自用户输入: size_int=0, is_tainted=True, expr=Expr树
    - 若无法确定: size_int=0, is_tainted=False, expr=None
    """
    # 找malloc前的mov rcx/rdi/mov ecx/edi (size参数)
    for j in range(call_idx - 1, max(call_idx - 12, -1), -1):
        l = lowered[j]
        # mov rcx/rdi/ecx/edi, imm — 必须在寄存器匹配之前, 否则0x80被\w+误认为寄存器
        m = re.search(r'\bmov\s+(rcx|rdi|ecx|edi),?\s*(0x[0-9a-f]+|\d+)', l)
        if m:
            v = int(m.group(2), 16) if m.group(2).lower().startswith('0x') else int(m.group(2))
            return v, False, const_expr(v)
        # mov rcx/rdi, reg — 排除内存操作数(qword/dword/ptr)
        m = re.search(r'\bmov\s+(rcx|rdi|ecx|edi),?\s*(\w+)', l)
        if m and m.group(2) not in ('qword', 'dword', 'ptr', 'rbp', 'rsp', 'rip'):
            # \w+也匹配0x80等十六进制数, 排除后再追溯
            if re.match(r'^(?:0x[0-9a-f]+|\d+)$', m.group(2)):
                v = int(m.group(2), 16) if m.group(2).lower().startswith('0x') else int(m.group(2))
                return v, False, const_expr(v)
            return _trace_reg_expr(asm, lowered, j, m.group(2))
        # movsxd rcx, eax (符号扩展, size_t转换)
        m = re.search(r'\bmovsxd\s+(rcx|rdi),?\s*(\w+)', l)
        if m:
            return _trace_reg_expr(asm, lowered, j, m.group(2))
    return 0, False, None


def build_write_expr(asm: List[str], lowered: List[str],
                     call_idx: int, func_name: str = "") -> Tuple[int, bool, Optional[Expr]]:
    """从memcpy/strcpy等调用点回溯, 构建write size表达式。

    返回: (size_int, is_tainted, optional_expr)
    """
    # 找size寄存器: MS x64=r8, SysV=rdx
    reg_for_size = None
    size_line = call_idx

    # 有效x86-64寄存器名
    _valid_reg = re.compile(
        r'^(r[a-z0-9]+|e[a-z0-9]+|[abcd]x|[abcd]l|[sd]il?|'
        r'r8[dwb]?|r9[dwb]?|r1[0-5][dwb]?)$', re.I)

    for j in range(call_idx - 1, max(call_idx - 8, -1), -1):
        l = lowered[j]
        m = re.search(r'\bmov\s+(r8|rdx),?\s*(\w+)', l)
        if m and _valid_reg.match(m.group(2)):
            reg_for_size = m.group(2)
            size_line = j
            break
        m = re.search(r'\bmov\s+(r8|rdx),?\s*(0x[0-9a-f]+|\d+)', l)
        if m:
            v = int(m.group(2), 16) if m.group(2).lower().startswith('0x') else int(m.group(2))
            return v, False, const_expr(v)
        # lea size_reg, [src+imm] (O2常用, 如 lea r8,[rdi+0x1] = strlen+1)
        m = re.search(r'\blea\s+(r8|rdx),?\s*\[(\w+)\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]', l)
        if m:
            src_reg = m.group(2)
            op = m.group(3)
            v = int(m.group(4), 16) if m.group(4).lower().startswith('0x') else int(m.group(4))
            inner_val, inner_tainted, inner_expr = _trace_reg_expr(
                asm, lowered, j, src_reg)
            if inner_expr:
                new_expr = (add_expr(inner_expr, v) if op == '+'
                            else sub_expr(inner_expr, v))
                new_val = inner_val + v if op == '+' else max(0, inner_val - v)
                return new_val, (inner_tainted or new_expr.has_taint()), new_expr
            return v, True, taint_expr(f"lea_size_{src_reg}")

    if reg_for_size:
        return _trace_reg_expr(asm, lowered, size_line, reg_for_size)

    # strcpy/gets等无显式size → 检查strlen↔strcpy off-by-one
    if func_name and _is_unbounded_write(func_name):
        return 0x7FFFFFFF, True, taint_expr("unbounded_write")

    return 0, False, None


# 寄存器名规范化
# x86-64: ecx/rcx/cx/cl 是同一物理寄存器的不同宽度视图。
# mov ecx, imm 会零扩展到 rcx → 追溯 rcx 时应同时匹配 ecx。

# 任意寄存器名 → 规范基名 (64-bit canonical)
_REG_NORM = {}
for _full, _subs in [
    ('rax', ['eax', 'ax', 'al', 'ah']),
    ('rcx', ['ecx', 'cx', 'cl', 'ch']),
    ('rdx', ['edx', 'dx', 'dl', 'dh']),
    ('rbx', ['ebx', 'bx', 'bl', 'bh']),
    ('rsp', ['esp', 'sp', 'spl']),
    ('rbp', ['ebp', 'bp', 'bpl']),
    ('rsi', ['esi', 'si', 'sil']),
    ('rdi', ['edi', 'di', 'dil']),
]:
    for _r in [_full] + _subs:
        _REG_NORM[_r] = _full
for _i in range(8, 16):
    _base = f'r{_i}'
    for _r in [_base, f'r{_i}d', f'r{_i}w', f'r{_i}b']:
        _REG_NORM[_r] = _base


def _norm_reg(r: str) -> str:
    return _REG_NORM.get(r.lower(), r.lower())


def _same_reg(a: str, b: str) -> bool:
    """寄存器名等价判断 (忽略宽度差异)。"""
    return _norm_reg(a) == _norm_reg(b)


def _reg_dest_re(reg: str) -> str:
    """为dest操作数生成匹配所有别名宽度的正则片段。"""
    base = _norm_reg(reg)
    # 根据base生成所有已知别名
    alias_map = {
        'rax': r'(?:rax|eax|ax|al)',
        'rcx': r'(?:rcx|ecx|cx|cl)',
        'rdx': r'(?:rdx|edx|dx|dl)',
        'rbx': r'(?:rbx|ebx|bx|bl)',
        'rsp': r'(?:rsp|esp|sp)',
        'rbp': r'(?:rbp|ebp|bp)',
        'rsi': r'(?:rsi|esi|si)',
        'rdi': r'(?:rdi|edi|di)',
    }
    if base in alias_map:
        return alias_map[base]
    # r8-r15: 加上 rNd/rNw/rNb 别名
    m = re.match(r'r(\d+)', base)
    if m:
        n = m.group(1)
        return rf'(?:r{n}|r{n}d|r{n}w|r{n}b)'
    return re.escape(reg)


# 栈槽存储模式: mov [rbp/rsp ± N], reg
_STACK_STORE = re.compile(
    r'\bmov\s+(?:qword\s+ptr\s+|dword\s+ptr\s+|word\s+ptr\s+|byte\s+ptr\s+)?'
    r'\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\w+)\]\s*,?\s*(\w+)', re.I)
# 栈槽加载模式: mov reg, [rbp/rsp ± N] (含qword/dword ptr)
_STACK_LOAD = re.compile(
    r'\bmov\s+(\w+),?\s*(?:qword\s+ptr\s+|dword\s+ptr\s+|word\s+ptr\s+|byte\s+ptr\s+)?'
    r'\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\w+)\]', re.I)


def _trace_reg_expr(asm: List[str], lowered: List[str],
                    from_idx: int, reg: str) -> Tuple[int, bool, Optional[Expr]]:
    """回溯寄存器值, 同时构建int值和Expr表达式。"""
    reg_re = _reg_dest_re(reg)
    for j in range(from_idx - 1, max(from_idx - 20, -1), -1):
        l = lowered[j]

        # mov reg, imm → 常量
        m = re.search(r'\bmov\s+' + reg_re + r',?\s*(0x[0-9a-f]+|\d+)', l)
        if m and not re.search(r'ptr\s+\[', l):  # 排除 mov reg, [mem] 误匹配
            v = int(m.group(1), 16) if m.group(1).lower().startswith('0x') else int(m.group(1))
            # jmp-jump-over-then-tainted-def 检测:
            # 模式: movsxd reg, tainted_src; jmp .L; mov reg, imm
            # 当前行=fallback常量, 前一行=jmp, 再前一行=tainted mov → 取tainted分支
            if j > 1:
                prev_line = lowered[j - 1]
                if re.search(r'\bjmp\b', prev_line):
                    tainted = _try_tainted_before_jmp(asm, lowered, j - 1, reg)
                    if tainted:
                        return tainted
            return v, False, const_expr(v)

        # movsxd reg, eax → 符号扩展 (dest只能是64-bit, 不展开别名)
        m = re.search(r'\bmovsxd\s+' + reg_re + r',?\s*(\w+)', l)
        if m:
            return _trace_reg_expr(asm, lowered, j, m.group(1))

        # cdqe / cdq / cqo: eax→rax 符号扩展 → 视为同一值继续追溯
        if re.search(r'\bcdqe\b', l) and _same_reg(reg, 'rax'):
            return _trace_reg_expr(asm, lowered, j, 'eax')

        # movzx reg, al/ax 等零扩展
        m = re.search(r'\bmovzx\s+' + reg_re + r',?\s*(\w+)', l)
        if m:
            return _trace_reg_expr(asm, lowered, j, m.group(1))

        # lea reg, [src + const] / lea reg, [src - const] → src ± const
        m = re.search(r'\blea\s+' + reg_re + r',?\s*\[(\w+)\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]', l)
        if m:
            src = m.group(1)
            op = m.group(2)
            v = int(m.group(3), 16) if m.group(3).lower().startswith('0x') else int(m.group(3))
            inner_val, inner_tainted, inner_expr = _trace_reg_expr(asm, lowered, j, src)
            if inner_expr:
                new_expr = add_expr(inner_expr, v) if op == '+' else sub_expr(inner_expr, v)
                new_val = (inner_val + v) if op == '+' else max(0, inner_val - v)
                return new_val, (inner_tainted or new_expr.has_taint()), new_expr

        # cmova/ae/g/ge → min(reg, const) 上界约束 (cap_value)
        # cmovl/le/b/be → max(reg, const) 下界约束 (floor_value)
        # 模式: mov bound_reg, imm; cmp reg, bound_reg; cmovX reg, bound_reg
        m = re.search(r'\bcmov(a|ae|g|ge)\s+' + reg_re + r',?\s*(\w+)', l)
        if m:
            bound_reg = m.group(2)
            cap = _find_cmov_bound(lowered, j, bound_reg)
            if cap > 0:
                inner_val, inner_tainted, inner_expr = _trace_reg_expr(
                    asm, lowered, j, reg)
                if inner_expr:
                    inner_expr.cap_value = cap
                    return inner_val, inner_tainted, inner_expr
        m = re.search(r'\bcmov(l|le|b|be)\s+' + reg_re + r',?\s*(\w+)', l)
        if m:
            bound_reg = m.group(2)
            floor = _find_cmov_bound(lowered, j, bound_reg)
            if floor > 0:
                inner_val, inner_tainted, inner_expr = _trace_reg_expr(
                    asm, lowered, j, reg)
                if inner_expr:
                    inner_expr.floor_value = floor
                    return inner_val, inner_tainted, inner_expr

        # mov reg, src_reg → 继续追溯
        m = re.search(r'\bmov\s+' + reg_re + r',?\s*(\w+)', l)
        if m and not re.search(r'\[', l):  # 排除内存操作
            src = m.group(1)
            if _norm_reg(src) in ('rbp', 'rsp', 'rip'):
                continue
            if src in ('ptr', 'qword', 'dword', 'word', 'byte'):
                continue
            # 立即数来源 (mov reg, imm 形态被上面imm分支命中, 此处兜底)
            if re.match(r'^(?:0x[0-9a-f]+|\d+)$', src, re.I):
                v = int(src, 16) if src.lower().startswith('0x') else int(src)
                return v, False, const_expr(v)
            return _trace_reg_expr(asm, lowered, j, src)

        # mov reg, [rbp+N] / [rsp+N] (N>0) → 函数参数, 外部控制
        # 标签包含具体栈偏移, 避免不同参数被误判为同源
        m = re.search(r'\bmov\s+' + reg_re + r',?\s*(?:qword\s+ptr\s+|dword\s+ptr\s+'
                      r'|word\s+ptr\s+|byte\s+ptr\s+)?'
                      r'\[(rbp|rsp)\s*\+\s*(\w+)\]', l)
        if m:
            base_reg = m.group(1)
            offset = m.group(2)
            return 0, True, taint_expr(f"arg_[{base_reg}+{offset}]")

        # mov reg, [rbp-N] / [rsp-N] → 栈局部 → 找存储到该槽的值
        m = _STACK_LOAD.search(l)
        if m and _same_reg(m.group(1), reg):
            slot = f'{m.group(2)}{m.group(3)}{m.group(4)}'
            inner = _trace_stack_slot_store(asm, lowered, j, slot)
            if inner:
                return inner
            # 找不到写入源 (store距离过远或跨基本块)
            # 视为局部污点, 避免继续扫描到无关常量
            return 0, True, taint_expr(f"local_{slot}")

        # imul reg, reg, imm → MUL (如 imul eax, eax, 0xc8)
        m = re.search(r'\bimul\s+' + reg_re + r',?\s*' + reg_re + r',?\s*(0x[0-9a-f]+|\d+)', l)
        if m:
            # reg_re为非捕获组, immediate位于group(1)
            v = int(m.group(1), 16) if m.group(1).lower().startswith('0x') else int(m.group(1))
            inner_val, inner_tainted, inner_expr = _trace_reg_expr(asm, lowered, j, reg)
            if inner_expr:
                return inner_val * v, (inner_tainted or inner_expr.has_taint()), mul_expr(inner_expr, v)

        # shl/sal reg, imm → *2^imm (如 shl eax, 2 → *4)
        m = re.search(r'\bsh[lr]\s+' + reg_re + r',?\s*(0x[0-9a-f]+|\d+)', l)
        if m:
            v = int(m.group(1), 16) if m.group(1).lower().startswith('0x') else int(m.group(1))
            inner_val, inner_tainted, inner_expr = _trace_reg_expr(asm, lowered, j, reg)
            if inner_expr:
                factor = 1 << v
                return inner_val * factor, (inner_tainted or inner_expr.has_taint()), mul_expr(inner_expr, factor)

        # add reg, reg → *2 (同寄存器自加, 编译器用此代替lea shl)
        m = re.search(r'\badd\s+' + reg_re + r',?\s*(\w+)', l)
        if m and _same_reg(reg, m.group(1)):
            inner_val, inner_tainted, inner_expr = _trace_reg_expr(asm, lowered, j, reg)
            if inner_expr:
                return inner_val * 2, (inner_tainted or inner_expr.has_taint()), mul_expr(inner_expr, 2)

        # add/sub reg, const → 算术运算
        m = re.search(r'\b(add|sub)\s+' + reg_re + r',?\s*(0x[0-9a-f]+|\d+)', l)
        if m:
            op = m.group(1)
            v = int(m.group(2), 16) if m.group(2).lower().startswith('0x') else int(m.group(2))
            inner_val, inner_tainted, inner_expr = _trace_reg_expr(asm, lowered, j, reg)
            if inner_expr:
                new_expr = add_expr(inner_expr, v) if op == 'add' else sub_expr(inner_expr, v)
                new_val = (inner_val + v) if op == 'add' else max(0, inner_val - v)
                return new_val, (inner_tainted or new_expr.has_taint()), new_expr

        # call source_func → reg=rax由外部输入确定
        # 标签含行号, 区分不同调用点 (line 120 strlen vs line 200 atoi)
        if _SOURCE_FUNCS.search(l) and j < from_idx:
            call_line = j
            if _same_reg(reg, 'rax'):
                is_strlen = bool(re.search(r'\bstrlen\b', l))
                label = f"strlen@{call_line}" if is_strlen else f"source_call@{call_line}"
                return 0, True, taint_expr(label)
            for k in range(j + 1, from_idx + 1):
                if re.search(r'\bmov\s+' + reg_re + r',?\s*(?:rax|eax)', lowered[k]):
                    is_strlen = bool(re.search(r'\bstrlen\b', l))
                    label = f"strlen@{call_line}" if is_strlen else f"source_call@{call_line}"
                    return 0, True, taint_expr(label)

# Fallback: 调用约定参数寄存器, 未找到具体来源 → 视为污点
    _PARAM_REGS_MS = {'rcx', 'ecx', 'rdx', 'edx', 'r8', 'r8d', 'r9', 'r9d'}
    _PARAM_REGS_SYSV = {'rdi', 'edi', 'rsi', 'esi', 'rdx', 'edx', 'rcx', 'ecx', 'r8', 'r8d', 'r9', 'r9d'}
    _all_params = _PARAM_REGS_MS | _PARAM_REGS_SYSV
    if reg.lower() in _all_params:
        return 0, True, taint_expr(f"param_{_norm_reg(reg)}")

    return 0, False, None


def _trace_stack_slot_store(asm: List[str], lowered: List[str],
                             from_idx: int, slot: str
                             ) -> Optional[Tuple[int, bool, Optional[Expr]]]:
    """追溯写入栈槽slot的值的来源。窗口扩展到40行以覆盖长计算链。
    支持立即数写入(mov [slot], imm)与寄存器写入两种形态。
    """
    for j in range(from_idx - 1, max(from_idx - 40, -1), -1):
        m = _STACK_STORE.search(lowered[j])
        if m:
            stored_slot = f'{m.group(1)}{m.group(2)}{m.group(3)}'
            if stored_slot == slot:
                src = m.group(4)
                # 立即数写入 → 直接返回常量
                if re.match(r'^(?:0x[0-9a-f]+|\d+)$', src, re.I):
                    v = int(src, 16) if src.lower().startswith('0x') else int(src)
                    return v, False, const_expr(v)
                return _trace_reg_expr(asm, lowered, j, src)
    return None


def _find_cmov_bound(lowered: List[str], cmov_idx: int,
                     bound_reg: str) -> int:
    """cmova reg, bound_reg → 查找bound_reg的常量值作为上界。

    模式: mov bound_reg, imm; cmp reg, bound_reg; cmova reg, bound_reg
    """
    bound_re = _reg_dest_re(bound_reg)
    for k in range(cmov_idx - 1, max(cmov_idx - 5, -1), -1):
        l = lowered[k]
        m = re.search(r'\bmov\s+' + bound_re + r',?\s*(0x[0-9a-f]+|\d+)', l)
        if m:
            v = int(m.group(1), 16) if m.group(1).lower().startswith('0x') else int(m.group(1))
            return v
    return 0


def _try_tainted_before_jmp(asm: List[str], lowered: List[str],
                             jmp_idx: int, reg: str
                             ) -> Optional[Tuple[int, bool, Optional[Expr]]]:
    """检查jmp指令之前的定义是否为污点源。

    模式:
      movsxd reg, tainted_src   ← 污点定义
      jmp .L2                    ← jmp_idx
      mov reg, imm               ← fallback常量(当前行)

    若jmp之前的指令定义了reg且该定义追溯为污点, 返回污点表达式。
    """
    reg_re = _reg_dest_re(reg)
    for k in range(jmp_idx - 1, max(jmp_idx - 4, -1), -1):
        l = lowered[k]
        # mov reg, tainted_src_reg (非imm, 非内存)
        m = re.search(r'\bmov\s+' + reg_re + r',?\s*(\w+)', l)
        if m and not re.search(r'ptr\s+\[', l):
            src = m.group(1)
            if _norm_reg(src) in ('rbp', 'rsp', 'rip'):
                continue
            if src in ('ptr', 'qword', 'dword', 'word', 'byte'):
                continue
            # 追溯src, 若为污点→返回
            val, tainted, expr = _trace_reg_expr(asm, lowered, k, src)
            if tainted and expr and expr.has_taint():
                return val, tainted, expr
            return None
        # movsxd reg, tainted_src
        m = re.search(r'\bmovsxd\s+' + reg_re + r',?\s*(\w+)', l)
        if m:
            val, tainted, expr = _trace_reg_expr(asm, lowered, k, m.group(1))
            if tainted and expr and expr.has_taint():
                return val, tainted, expr
            return None
        break  # 只检查紧邻jmp的前一条
    return None


def _is_unbounded_write(func_name: str) -> bool:
    """无显式size参数的写入函数。"""
    return bool(re.search(
        r'\b(strcpy|strcat|gets|sprintf|wcscpy|mbscpy)\b', func_name, re.I))


# strlen↔strcpy off-by-one 检测

def detect_strlen_strcpy_off_by_one(
        asm: List[str], lowered: List[str],
        alloc_line: int, write_line: int) -> bool:
    """检测模式: alloc = strlen(src), write = strcpy(dst, same_src)。

    alloc处: call strlen; mov rcx, rax; call malloc
    write处: call strcpy(dst, src) — 其中src与strlen的src相同
    """
    # 从alloc回溯找strlen调用
    strlen_line = -1
    strlen_src_reg = ""
    for j in range(alloc_line - 1, max(alloc_line - 15, -1), -1):
        if re.search(r'\bstrlen\b', lowered[j]):
            strlen_line = j
            break

    if strlen_line < 0:
        return False

    # 找strlen的源参数 (MS: rcx, SysV: rdi)
    for j in range(strlen_line - 1, max(strlen_line - 5, -1), -1):
        m = re.search(r'\bmov\s+(rcx|rdi),?\s*(\[rbp[+\-]\w+\]|\w+)', lowered[j])
        if m:
            strlen_src_reg = m.group(2)
            break

    if not strlen_src_reg:
        return False

    # 检查write是否为strcpy
    line_at_write = asm[write_line].strip().lower()
    if not re.search(r'\bstrcpy\b', line_at_write):
        return False

    # 找strcpy的src参数 (MS: rdx, SysV: rsi)
    for j in range(write_line - 1, max(write_line - 8, -1), -1):
        m = re.search(r'\bmov\s+(rdx|rsi),?\s*(' + re.escape(strlen_src_reg) + r')',
                      lowered[j])
        if m:
            return True

    return False
