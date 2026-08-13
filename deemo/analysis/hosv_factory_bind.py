"""
工厂函数返回指针绑定. 目标模式:

  void* mat(int r, int c) { return calloc(r, c); }
  int main() { char* p = mat; strcpy(p, "t"); }

原 HOSV 只关联同函数内的 `var = malloc(...)` 分配点与写入. 当分配
发生在工厂函数内部、通过返回值传播时, find_writes 无法把 main 中的
strcpy(p) 关联到 mat 的 calloc, 导致漏检. 同时 calloc(r,c) 的整数
回绕 (r*c 溢出) 使分配不足.

实现:
  1. 识别工厂函数: 函数体内含 malloc/calloc/realloc 且 return 该指针
  2. 构建 (factory, alloc_func, size_expr) 摘要
  3. 调用点: `p = factory(...)` → 绑定 p 到工厂分配摘要
  4. 对后续 p 的写入做跨函数关联判定
  5. calloc 双参数: 检查 nmemb*esize 回绕 (乘法溢出)
"""


import re
from typing import Dict, List, Optional, Tuple

from analysis.hosv_ext_types import ExtAlloc, ExtResult
from analysis.heap_overflow_src_patterns import (
    _is_comment_or_empty,
)

_FACTORY_RETURN_RE = re.compile(
    r'return\s+(\w[\w]*)\s*;')
_FACTORY_ALLOC_RE = re.compile(
    r'(\w[\w]*)\s*=\s*(?:\(\s*\w[\w]*\s*\*\s*\)\s*)?'
    r'(malloc|calloc|realloc)\s*\(([^)]*)\)')
_CALL_ALLOC_RE = re.compile(
    r'(?:[\w\s\*]+?\s+)?(\w[\w]*)\s*=\s*'
    r'(?:\(\s*[\w\s\*]+?\s*\)\s*)?'          # 可选的类型cast
    r'(\w[\w]*)\s*\(([^)]*)\)\s*;?')
_CALLOC_PRODUCT_RE = re.compile(
    r'calloc\s*\(\s*(\w+|\d+)\s*,\s*(\w+|\d+)\s*\)')

class FactorySummary:
    """工厂函数摘要 — 函数名 → 内部分配的 (func, size_expr, alloc_var)."""
    def __init__(self) -> None:
        self._map: Dict[str, Tuple[str, str, str]] = {}

    def add(self, factory: str, alloc_func: str,
            size_expr: str, alloc_var: str) -> None:
        self._map[factory] = (alloc_func, size_expr, alloc_var)

    def get(self, factory: str) -> Optional[Tuple[str, str, str]]:
        return self._map.get(factory)

def build_factory_summaries(lines: List[str],
                            valid_lines: Optional[set] = None
                            ) -> FactorySummary:
    """扫描所有函数, 提取含 malloc 返回的工厂函数摘要.

    支持两种形态:
      a) var = malloc(...); ... return var;
      b) return malloc(...); / return calloc(...);  (直接返回)
    """
    summary = FactorySummary()
    funcs = _split_functions(lines)
    for fname, body_lines, fstart in funcs:
        alloc_var = None
        alloc_func = ""
        size_expr = ""
        direct_alloc = None
        for i, text in enumerate(body_lines):
            t = text.strip()
            if _is_comment_or_empty(t):
                continue
            m = _FACTORY_ALLOC_RE.search(t)
            if m:
                alloc_var, alloc_func, size_expr = \
                    m.group(1), m.group(2), m.group(3)
            # 直接返回: return malloc(...) 或 return calloc(...)
            dm = re.search(
                r'return\s+(?:\(\s*\w[\w]*\s*\*\s*\)\s*)?'
                r'(malloc|calloc|realloc)\s*\(([^)]*)\)', t)
            if dm:
                direct_alloc = (dm.group(1), dm.group(2))
            rm = _FACTORY_RETURN_RE.search(t)
            if rm and rm.group(1) == alloc_var and alloc_var:
                summary.add(fname, alloc_func, size_expr, alloc_var)
                break
        if direct_alloc and not summary.get(fname):
            # 直接返回形态: 合成分配变量名 = "<return>"
            f, sz = direct_alloc
            summary.add(fname, f, sz, "@ret")
    return summary

def _split_functions(lines: List[str]) -> List[Tuple[str, List[str], int]]:
    """按顶层函数签名切分: 返回 [(name, body_lines, start_line_idx)].

    支持单行函数体 (signature + body 同行) 与多行函数体.
    仅跟踪从签名行开始的括号平衡, 遇到下一个签名前先提交已收集函数.
    """
    funcs = []
    cur_name = ""
    cur_body: List[str] = []
    cur_start = 0
    brace = 0
    in_func = False
    for i, raw in enumerate(lines):
        m = re.match(
            r'^[\w\s\*]+?([A-Za-z_]\w*)\s*\([^;]*\)\s*\{', raw)
        if m and not in_func:
            # 新函数签名
            if cur_name and cur_body:
                funcs.append((cur_name, cur_body, cur_start))
            cur_name = m.group(1)
            cur_start = i
            cur_body = [raw]
            brace = raw.count('{') - raw.count('}')
            in_func = True
            if brace <= 0:
                # 单行函数体
                funcs.append((cur_name, cur_body, cur_start))
                cur_name = ""
                cur_body = []
                in_func = False
            continue
        if in_func:
            cur_body.append(raw)
            brace += raw.count('{') - raw.count('}')
            if brace <= 0:
                funcs.append((cur_name, cur_body, cur_start))
                cur_name = ""
                cur_body = []
                in_func = False
    if in_func and cur_name and cur_body:
        funcs.append((cur_name, cur_body, cur_start))
    return funcs

def collect_factory_binds(lines: List[str], summary: FactorySummary,
                          valid_lines: Optional[set] = None
                          ) -> List[Tuple[int, str, str, str]]:
    """收集调用点绑定: (call_line, target_var, factory, args_str).

    支持单行多语句 (分号分隔), 逐语句匹配 `target = factory(args)`.
    """
    binds = []
    for i, line in enumerate(lines, start=1):
        if valid_lines and i not in valid_lines:
            continue
        text = line.strip()
        if _is_comment_or_empty(text):
            continue
        for stmt in text.split(';'):
            stmt = stmt.strip()
            if not stmt:
                continue
            m = _CALL_ALLOC_RE.search(stmt)
            if not m:
                continue
            target, callee, args = m.group(1), m.group(2), m.group(3)
            if summary.get(callee):
                binds.append((i, target, callee, args))
    return binds

def _eval_arg_const(arg: str, lines: List[str],
                    call_line: int) -> Optional[int]:
    """解析调用实参为常量 (数字或可回溯的常量赋值)."""
    a = arg.strip()
    if re.match(r'^\d+$', a):
        return int(a)
    for j in range(call_line - 2, -1, -1):
        t = lines[j].strip()
        am = re.search(rf'\b{re.escape(a)}\s*=\s*(\d+)\s*;', t)
        if am:
            return int(am.group(1))
    return None

def verify_factory(alloc: ExtAlloc, call_line: int, args: str,
                   lines: List[str]) -> Optional[ExtResult]:
    """验证工厂分配是否整数回绕 (calloc) 或大小不足.

    calloc 回绕判定基于调用点实参: nmemb * esize 溢出 size_t.
    如 mat: 65536*65536 = 2^32 溢出 32-bit size_t → 0.

    TODO: 64-bit size_t 平台仅当乘积 >= 2^64 才回绕, 当前对 32-bit
    判定为保守假设. 后续按目标平台字长配置区分.
    """
    if alloc.func == 'calloc':
        parts = [p.strip() for p in args.split(',')]
        if len(parts) == 2:
            a = _eval_arg_const(parts[0], lines, call_line)
            b = _eval_arg_const(parts[1], lines, call_line)
            if a is not None and b is not None:
                if a > 0 and b > 0 and a > (2 ** 63) // b:
                    return ExtResult(
                        verdict="VULN", alloc_line=alloc.line,
                        write_line=call_line, var_name=alloc.var,
                        alloc_size=-1, write_size=-1, confidence=0.85,
                        kind="calloc_wraparound",
                        reason=("'%s': calloc(%d, %d) nmemb*size overflows "
                                "size_t → undersized heap object"
                                % (alloc.var, a, b)))
                if a > 0 and b > 0 and a > (2 ** 31) // b:
                    # 32-bit size_t 平台回绕 (如 x86)
                    return ExtResult(
                        verdict="VULN", alloc_line=alloc.line,
                        write_line=call_line, var_name=alloc.var,
                        alloc_size=-1, write_size=-1, confidence=0.80,
                        kind="calloc_wraparound",
                        reason=("'%s': calloc(%d, %d) wraps on 32-bit size_t "
                                "→ undersized heap object"
                                % (alloc.var, a, b)))
                return ExtResult(
                    verdict="SAFE", alloc_line=alloc.line,
                    write_line=call_line, var_name=alloc.var,
                    alloc_size=a * b, write_size=-1, confidence=0.90,
                    kind="calloc_product",
                    reason="'%s': calloc(%d, %d) = %dB (no wraparound)"
                           % (alloc.var, a, b, a * b))
    return None

__all__ = [
    'FactorySummary', 'build_factory_summaries',
    'collect_factory_binds', 'verify_factory',
    '_split_functions', '_eval_arg_const',
]
