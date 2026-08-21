# analysis/int_overflow_cross_func.py — 整数溢出跨函数常量传播 + 位移溢出
# INT-SHIFT v1.0 的 F1=0.973 有1个FN, 根因是:
#   1. 跨函数调用时的常量参数传播: init(N) → malloc(N*4) 其中N在调用方是常量
#   2. 位移溢出: x << N 当 N 使结果超出类型边界 (1<<31 对int32是未定义)
#   3. 函数指针/回调中的乘法溢出 — 调用方传入的size参数未被追踪
#
# 无需 LLVM IR; 直接在 C 源码级做调用图 + 常量传播。
#

from __future__ import annotations
import re
from typing import Dict, List, Tuple, Set, Optional
from .value_range_analyzer import ValueRange

def _extract_call_sites(code: str) -> List[Dict]:
    """提取所有函数调用点: func(arg1, arg2, ...)"""
    calls = []
    for m in re.finditer(r'(\w+)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)', code):
        func_name = m.group(1)
        args_str = m.group(2)
        # 跳过关键字/控制流
        if func_name in ("if", "while", "for", "switch", "return", "sizeof",
                          "__builtin", "__attribute__", "defined"):
            continue
        args = [a.strip() for a in args_str.split(',') if a.strip()]
        # 清理每个参数的嵌套括号
        cleaned_args = []
        for a in args:
            depth = 0
            clean = []
            for ch in a:
                if ch == '(': depth += 1
                elif ch == ')': depth -= 1
                elif depth == 0: clean.append(ch)
            cleaned_args.append(''.join(clean).strip())
        calls.append({
            "func": func_name,
            "args": cleaned_args,
            "pos": m.start(),
            "line": code[:m.start()].count('\n') + 1,
        })
    return calls

def propagate_constants(code: str) -> Dict[str, int]:
    """从函数调用中推断常量参数。
    模式: func(CONSTANT) → 对应函数签名 void func(int sz) → sz==CONSTANT
    也处理: #define MAX 256; func(MAX)
    """
    constants: Dict[str, int] = {}

    # 从 #define 提取宏常量
    for m in re.finditer(r'#define\s+(\w+)\s+(\d+)\s*', code):
        try:
            constants[m.group(1)] = int(m.group(2))
        except ValueError:
            pass

    # 从函数调用中提取常量参数
    for m in re.finditer(r'(\w+)\s*\(\s*(\d+)\s*[,)]', code):
        func_name = m.group(1)
        const_val = int(m.group(2))
        # 标记: 此函数被以常量调用
        param_key = f"{func_name}:arg1"
        if param_key not in constants:
            constants[param_key] = const_val

    # 带变量名的调用: func(sz_var) 但 sz_var = CONST 在同一函数中
    for m in re.finditer(r'(\w+)\s*\(\s*(\w+)\s*\)', code):
        func_name = m.group(1)
        arg_var = m.group(2)
        if arg_var in constants:
            param_key = f"{func_name}:{arg_var}"
            if param_key not in constants:
                constants[param_key] = constants[arg_var]

    return constants

def detect_shift_overflow(code: str, func: str = "") -> List[Dict]:
    """检测位移溢出模式:
    1. 1 << N 当 N >= 31 (对int32) — 符号位溢出
    2. var << CONST 当 CONST 使结果超出类型边界
    3. 1ULL << N 安全 (明确使用64位) — 不报告
    """
    findings = []
    # 安全的位移类型后缀
    safe_suffixes = {"ULL", "UL", "LL", "L", "ull", "ul", "ll", "l"}

    for m in re.finditer(r'(\w+|\d+)\s*<<\s*(\w+|\d+)', code):
        lhs, rhs = m.group(1), m.group(2)

        # 排除 1ULL << N 等显式64位移位
        ctx_before = code[max(0, m.start()-10):m.start()]
        if any(s in ctx_before for s in safe_suffixes):
            continue

        try:
            shift_amount = int(rhs)
        except ValueError:
            shift_amount = None

        try:
            lhs_val = int(lhs)
        except ValueError:
            lhs_val = None

        if shift_amount is not None and shift_amount >= 31:
            if lhs_val == 1:
                findings.append({
                    "type": "integer-overflow",
                    "subtype": "shift_overflow",
                    "function": func,
                    "expr": f"{lhs}<<{shift_amount}",
                    "severity": "High",
                    "cwe": "CWE-190",
                    "confidence": 0.88,
                    "description": (
                        f"位移溢出: 1<<{shift_amount}={1<<shift_amount} "
                        f"超出int32范围→符号位/环绕风险"
                    ),
                })
            elif lhs_val is not None and (lhs_val << shift_amount) > 2147483647:
                findings.append({
                    "type": "integer-overflow",
                    "subtype": "shift_overflow",
                    "function": func,
                    "expr": f"{lhs}<<{shift_amount}",
                    "severity": "Medium",
                    "cwe": "CWE-190",
                    "confidence": 0.75,
                    "description": (
                        f"位移溢出: {lhs}<<{shift_amount}={lhs_val<<shift_amount} "
                        f"超出int32范围"
                    ),
                })

        # 变量移位: var << N, N未知 → 警告但低置信
        if shift_amount is None and lhs != "1":
            findings.append({
                "type": "integer-overflow",
                "subtype": "shift_overflow",
                "function": func,
                "expr": f"{lhs}<<{rhs}",
                "severity": "Low",
                "cwe": "CWE-190",
                "confidence": 0.30,
                "description": f"位移表达式: {lhs}<<{rhs} — 位移量未知, 潜在溢出",
            })

    return findings

def detect_cross_func_mult_overflow(code: str, func: str = "",
                                     constants: Dict[str, int] = None) -> List[Dict]:
    """跨函数乘法溢出检测。
    利用调用方的常量参数缩小被调用函数中的值范围, 发现间接溢出。

    场景: main(){ init(256); }
          void init(int N) { buf = malloc(N * 4); }  ← N已知为256
    由于 v1/v2 只看 init() 内部, N 的范围是 TOP → 无法判定溢出。
    本函数将调用方常量传播到被调方, 将 TOP 缩小为精确值。
    """
    if constants is None:
        constants = propagate_constants(code)
    findings = []

    for m in re.finditer(r'(?:malloc|calloc|realloc)\s*\(\s*(\w+)\s*\*\s*(\w+)\s*\)', code):
        nv, mv = m.group(1), m.group(2)
        n_const = constants.get(nv) or constants.get(f"{func}:{nv}")
        m_const = constants.get(mv) or constants.get(f"{func}:{mv}")

        if n_const is not None and m_const is not None:
            prod = n_const * m_const
            if prod > 2147483647:
                findings.append({
                    "type": "integer-overflow",
                    "subtype": "cross_func_mult",
                    "function": func,
                    "expr": f"{nv}(={n_const})*{mv}(={m_const})={prod}",
                    "severity": "High",
                    "cwe": "CWE-190",
                    "confidence": 0.85,
                    "description": (
                        f"跨函数常量乘法溢出: {nv}={n_const}, {mv}={m_const}, "
                        f"乘积{prod}超出int32范围"
                    ),
                })
        elif n_const is not None:
            # 单边常量: N(已知) * M(未知), 可以估算边界
            if n_const > 65535:  # N > 65535 → 即使M=1也可能接近边界
                findings.append({
                    "type": "integer-overflow",
                    "subtype": "cross_func_mult_partial",
                    "function": func,
                    "expr": f"{nv}(={n_const})*{mv}",
                    "severity": "Medium",
                    "cwe": "CWE-190",
                    "confidence": 0.55,
                    "description": (
                        f"部分常量乘法: {nv}={n_const}(已知), "
                        f"{mv}(未知)→需运行时验证"
                    ),
                })

    # 跨函数间接乘法: sz = n * M; ... malloc(sz), n来自调用方常量
    mul_map: Dict[str, Tuple[str, str]] = {}
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)\s*;', code):
        mul_map[m.group(1)] = (m.group(2), m.group(3))
    for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\d+)\s*;', code):
        mul_map[m.group(1)] = (m.group(2), m.group(3))
    for m in re.finditer(r'(\w+)\s*=\s*(\d+)\s*\*\s*(\w+)\s*;', code):
        mul_map[m.group(1)] = (m.group(2), m.group(3))

    for m in re.finditer(r'(?:malloc|calloc|realloc)\s*\(\s*(\w+)\s*\)', code):
        sz_var = m.group(1)
        if sz_var not in mul_map:
            continue
        a, b = mul_map[sz_var]
        a_const = constants.get(a) or constants.get(f"{func}:{a}")
        b_const = constants.get(b) or constants.get(f"{func}:{b}")

        if a_const is not None and b_const is not None:
            prod = a_const * b_const
            if prod > 2147483647:
                findings.append({
                    "type": "integer-overflow",
                    "subtype": "cross_func_indirect_mult",
                    "function": func,
                    "expr": f"{sz_var}={a}(={a_const})*{b}(={b_const})→malloc",
                    "severity": "High",
                    "cwe": "CWE-190",
                    "confidence": 0.82,
                    "description": (
                        f"跨函数间接乘法溢出: {a}={a_const}, {b}={b_const}, "
                        f"{sz_var}={prod}超出int32范围"
                    ),
                })

    return findings

def detect_int_overflow_cross_func(code: str, func: str = "") -> List[Dict]:
    """跨函数整数溢出检测主入口。
    整合: 常量传播 + 位移溢出 + 跨函数乘法。
    """
    findings = []
    constants = propagate_constants(code)

    # 位移溢出
    findings.extend(detect_shift_overflow(code, func))

    # 跨函数乘法溢出
    findings.extend(detect_cross_func_mult_overflow(code, func, constants))

    findings.sort(key=lambda f: f["confidence"], reverse=True)
    return findings
