"""
IODS 整数溢出检测器 — 多模式算术溢出/截断/符号混淆识别 (CWE-190)。

检测策略:
  1. 用户输入变量追踪 (argv / atoi / scanf / getenv / recv / fgets)
  2. 分配上下文中的乘法/加法/移位溢出 → 分配大小可能回绕
  3. 窄化截断 (wider→narrower 类型转换)
  4. 有符号/无符号符号混淆影响边界检查
  5. unsigned 循环计数器 + 用户控制上界 → 回绕风险
"""
import re
from typing import Any, Dict, List, Set

from tests.int_overflow_helpers import (
    _find_user_input_vars,
    _find_alloc_vars,
    _find_arith_result_vars,
    _arith_uses_user_var,
    _extract_vars,
    _find_cross_func_arith,
    _detect_advanced_patterns,
)

# 分配调用
_ALLOC_RE = re.compile(
    r'(?:malloc|calloc|realloc|alloca)\s*\(', re.IGNORECASE,
)

# 复合: malloc(n * sizeof(T) + offset)
_ALLOC_EXPR_RE = re.compile(
    r'(?:malloc|calloc|realloc|alloca)\s*\(\s*(.+?)\s*\)', re.IGNORECASE,
)

# 窄化截断
_NARROW_ASSIGN_RE = re.compile(
    r'(?:unsigned\s+)?(?:short|char|int8_t|int16_t|uint8_t|uint16_t'
    r'|uint32_t|unsigned\s+int)\s+(\w+)\s*='
)

# 符号混淆
_SIGNED_INPUT_RE = re.compile(
    r'(?:int|long|short)\s+(\w+)\s*=\s*(?:atoi|atol|strtol|atoll|strtoll)',
)
_SIGNED_TO_UNSIGNED_RE = re.compile(
    r'\(\s*(?:size_t|unsigned(?:\s+int)?|uint\w+_t)\s*\)\s*(\w+)',
)

# ── unsigned 循环 (含 unsigned char/short/int/long/size_t) ──
_UNSIGNED_LOOP_RE = re.compile(
    r'for\s*\(\s*(?:unsigned(?:\s+(?:char|short|int|long))?|size_t)\s+\w+\s*=',
)
_NARROW_LOOP_RE = re.compile(
    r'(?:unsigned\s+(?:char|short)|uint8_t|uint16_t)\s+(\w+)\s*;',
)


def detect_int_overflow(source: str) -> Dict[str, Any]:
    """对 C 源码执行 IODS 整数溢出检测。

    返回: {detected, findings: [{type, var, line_no, desc}], count}
    """
    lines = source.splitlines()
    findings: List[Dict] = []

# 收集用户输入变量
    user_vars = _find_user_input_vars(source)

# 收集分配调用中用到的变量
    alloc_vars = _find_alloc_vars(source)

# 收集算术运算结果变量 (乘法/加法/移位)
    arith_vars = _find_arith_result_vars(source)

# 跨函数算术追踪 — 找返回算术表达式的函数
    cross_func_arith = _find_cross_func_arith(source)
    # 扩展 arith_vars 和 user_vars 的跨函数连接
    for func_name, info in cross_func_arith.items():
        arith_vars.update(_extract_vars(info.get('return_expr', '')))
        # 函数被调用时, 其返回值的接收者继承该函数的算术风险
        for m in re.finditer(
                rf'(\w+)\s*=\s*{func_name}\s*\(', source):
            arith_vars.add(m.group(1))

    for i, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line or line.startswith('//') or line.startswith('/*'):
            continue
        line_no = i + 1

# 模式1: 分配参数来自用户输入
        am = _ALLOC_EXPR_RE.search(line)
        if am:
            alloc_args = am.group(1)
            alloc_vars_in_expr = _extract_vars(alloc_args)
            for v in alloc_vars_in_expr:
                if v in user_vars:
                    findings.append({
                        'type': 'user_input_to_alloc',
                        'var': v, 'line_no': line_no, 'line': line,
                        'desc': f'malloc 参数直接使用用户输入 {v}',
                    })
                # 用户输入经过算术运算后进入分配
                if v in arith_vars and _arith_uses_user_var(v, arith_vars, user_vars, source):
                    findings.append({
                        'type': 'arith_overflow_to_alloc',
                        'var': v, 'line_no': line_no, 'line': line,
                        'desc': f'分配参数 {v} 由用户输入经算术运算得到, 可能溢出',
                    })

# 模式2: 乘法表达式涉及用户输入
        for vm in re.finditer(r'(\w+)\s*=\s*(.+?)\s*\*\s*(.+?)\s*;', line):
            lhs = vm.group(1)
            rhs_left = vm.group(2).strip()
            rhs_right = vm.group(3).strip()
            rhs_vars = _extract_vars(f'{rhs_left} {rhs_right}')
            if rhs_vars & user_vars:
                findings.append({
                    'type': 'mul_overflow', 'var': lhs,
                    'line_no': line_no, 'line': line,
                    'desc': f'{lhs} = {rhs_left} * {rhs_right}, 操作数来自用户输入',
                })

# 模式3: 加法表达式涉及用户输入
        for vm in re.finditer(r'(\w+)\s*=\s*(.+?)\s*\+\s*(.+?)\s*;', line):
            lhs = vm.group(1)
            rhs_left = vm.group(2).strip()
            rhs_right = vm.group(3).strip()
            rhs_vars = _extract_vars(f'{rhs_left} {rhs_right}')
            if rhs_vars & user_vars:
                findings.append({
                    'type': 'add_wrap', 'var': lhs,
                    'line_no': line_no, 'line': line,
                    'desc': f'{lhs} = {rhs_left} + {rhs_right}, 操作数来自用户输入',
                })

# 模式4: 移位表达式
        for vm in re.finditer(r'(\w+)\s*=\s*(.+?)\s*<<\s*(.+?)\s*;', line):
            lhs = vm.group(1)
            rhs_left = vm.group(2).strip()
            rhs_right = vm.group(3).strip()
            rhs_vars = _extract_vars(f'{rhs_left} {rhs_right}')
            if rhs_vars & user_vars:
                findings.append({
                    'type': 'shift_overflow', 'var': lhs,
                    'line_no': line_no, 'line': line,
                    'desc': f'{lhs} = {rhs_left} << {rhs_right}, 移位可能溢出',
                })

# 模式5: 窄化截断
        nm = _NARROW_ASSIGN_RE.search(line)
        if nm:
            narrow_var = nm.group(1)
            # 检查是否来自更宽类型的值
            if re.search(rf'{narrow_var}\s*=\s*\([^)]+\)', line):
                findings.append({
                    'type': 'narrow_truncation', 'var': narrow_var,
                    'line_no': line_no, 'line': line,
                    'desc': f'{narrow_var} 被显式窄化, 可能截断高位',
                })

# 模式6: 有符号/无符号混淆
        sm = _SIGNED_INPUT_RE.search(line)
        if sm:
            signed_var = sm.group(1)
            # 检查后续是否与 size_t / unsigned 比较
            if re.search(rf'{signed_var}\s*[<>]', source):
                findings.append({
                    'type': 'sign_mismatch', 'var': signed_var,
                    'line_no': line_no, 'line': line,
                    'desc': f'int 变量 {signed_var} 来自用户输入, 与无符号量比较时符号歧义',
                })

# 模式7: unsigned 循环带用户控制边界
        ul = _UNSIGNED_LOOP_RE.search(line)
        if ul:
            loop_var_m = re.search(
                r'for\s*\(\s*(?:unsigned(?:\s+\w+)?|size_t)\s+(\w+)', line)
            if loop_var_m:
                findings.append({
                    'type': 'unsigned_loop_wrap', 'var': loop_var_m.group(1),
                    'line_no': line_no, 'line': line,
                    'desc': 'unsigned 循环计数器可能回绕',
                })

        # ── 模式8: 窄类型循环计数器 (unsigned char/short 永远<大边界) ──
        nl = _NARROW_LOOP_RE.search(line)
        if nl:
            findings.append({
                'type': 'narrow_loop_counter', 'var': nl.group(1),
                'line_no': line_no, 'line': line,
                'desc': f'{nl.group(1)} 类型过窄, 循环可能无限/回绕',
            })

# 模式9: 有符号→无符号强制转换
        for vm in _SIGNED_TO_UNSIGNED_RE.finditer(line):
            cast_var = vm.group(1)
            if cast_var in user_vars:
                findings.append({
                    'type': 'signed_to_unsigned_cast',
                    'var': cast_var, 'line_no': line_no, 'line': line,
                    'desc': f'{cast_var} 被强转为无符号类型, 负值会变巨大',
                })

# 模式10: 分配参数含内联算术表达式
        # malloc(a + b) / malloc(a * b) — 操作数可能溢出
        am2 = _ALLOC_EXPR_RE.search(line)
        if am2:
            expr = am2.group(1)
            if '+' in expr or '*' in expr or '<<' in expr:
                expr_vars = _extract_vars(expr)
                if expr_vars & user_vars:
                    findings.append({
                        'type': 'alloc_with_arith',
                        'line_no': line_no, 'line': line,
                        'desc': f'分配表达式 {expr.strip()} 含用户输入, 内联算术可能溢出',
                    })

# 模式11: int←long long / int←size_t 窄化
        nc = re.search(r'int\s+(\w+)\s*=\s*\(int\)\s*(.+?)\s*;', line)
        if nc:
            narrow_var = nc.group(1)
            findings.append({
                'type': 'narrow_to_int', 'var': narrow_var,
                'line_no': line_no, 'line': line,
                'desc': f'{narrow_var} 从更宽类型截断为int',
            })

# 模式12: 结构体字段乘法溢出
        # total = spec->count * spec->elem_size;
        sfm = re.search(
            r'(\w+)\s*=\s*(\w+)\s*->\s*(\w+)\s*\*\s*(\w+)\s*->\s*(\w+)\s*;', line)
        if sfm:
            findings.append({
                'type': 'struct_field_mul', 'var': sfm.group(1),
                'line_no': line_no, 'line': line,
                'desc': f'{sfm.group(1)} = a->field * b->field, 结构体字段乘法可能溢出',
            })

        # ── 模式13: 数组索引加法溢出 — if (idx + N < M) arr[idx + N]
        aio = re.search(
            r'if\s*\(\s*(\w+)\s*\+\s*(\d+)\s*[<>]\s*(\w+)\s*\)', line)
        if aio:
            idx_var = aio.group(1)
            if idx_var in user_vars:
                findings.append({
                    'type': 'array_idx_overflow', 'var': idx_var,
                    'line_no': line_no, 'line': line,
                    'desc': f'{idx_var}+{aio.group(2)} 可能溢出绕过边界检查',
                })

        # ── 模式14: 返回常量导致上界溢出 malloc(parse_result + 1)
        # 匹配 malloc(var + N) / malloc(var * N) 其中 var 不是已知安全变量
        am3 = re.search(
            r'malloc\s*\(\s*(\w+)\s*([\+\*])\s*(\d+)\s*\)', line)
        if am3:
            v = am3.group(1)
            op = am3.group(2)
            num = int(am3.group(3))
            # 排除明显安全的模式 (argc是int, sizeof是关键字)
            if num > 0 and v not in ('argc', 'sizeof'):
                findings.append({
                    'type': 'alloc_expr_overflow',
                    'var': v, 'line_no': line_no, 'line': line,
                    'desc': f'malloc({v} {op} {num}) 表达式可能溢出',
                })

# 模式15-17: 高级检测 (函数参数算术/大常量乘法/跨函数算术)
        _detect_advanced_patterns(
            line, line_no, user_vars, arith_vars, cross_func_arith, findings)

# 后处理: IOSV 值范围+守卫验证精化
    # 调用 analysis/int_overflow_bridge 对 regex findings 做 VRP+守卫二次验证
    # IOSV SAFE (有守卫/值范围证明不溢出) → 过滤
    # IOSV VULN (范围超INT32_MAX) → 确认增强
    try:
        from analysis.int_overflow_bridge import refine_int_overflow_findings
        bridge_result = refine_int_overflow_findings(findings, source)
        # 应用过滤: _filtered=True 的从 findings 中移除
        findings = [f for f in findings if not f.get('_filtered')]
    except ImportError:
        pass  # 桥接模块不可用 → 保持原有行为

    detected = len(findings) > 0
    return {
        'detected': detected,
        'findings': findings,
        'count': len(findings),
        'user_vars': sorted(user_vars),
    }

