"""
强化版源码级候选提取器 — 支持8种堆写入模式的(alloc, write)候选对提取.

在原有bvf_candidate_extractor基础上新增3种核心写入模式:
  6. 数组索引写入: buf[i]=val / buf[idx]=c / buf[out++]=x
  7. 指针算术写入: *(ptr+off)=val / ptr[n]=c
  8. sprintf/snprintf写入: sprintf(buf,fmt,...) / snprintf(buf,sz,fmt,...)

原有5种(memcpy/strcpy/strncpy/memset/memmove)逻辑保持不变.
与bvf_candidate_extractor.py并行存在, 不删除原文件.

辅助函数已拆至 source_level_candidate_extractor_patterns.py
"""

import re
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.heap_overflow_detector import (
    HeapAllocSite, HeapStore, HeapOverflowCandidate,
)

# 正则常量从拆分模块导入, 保持定义唯一
from core.source_level_candidate_extractor_patterns import (
    _mvar_re, _cvar_re, _rvar_re,
    _lib_write_re, _sprintf_re,
    _array_write_re, _ptr_deref_re,
    _sizeof_re,
)
from core.source_level_candidate_extractor_patterns import (
    _estimate_sizeof,
    _parse_size_expr,
    _try_eval_const_expr,
    _split_args,
    _parse_dst,
    _extract_var_from_decl,
)
from core.source_level_candidate_extractor_writes import (
    _extract_alloc_sites,
    _extract_lib_writes,
    _extract_sprintf_writes,
    _extract_array_index_writes,
    _extract_ptr_deref_writes,
)

# 辅助正则 — 仅供主文件使用的偏移匹配
_offset_re = re.compile(r'(\w+)\s*\+\s*(\d+)')


def extract_candidates_from_code(code: str) -> tuple:
    """从C源码提取(alloc, write)候选对 — 支持8种写入模式.

    返回 (candidates, ir_lines).
    与bvf_candidate_extractor.extract_candidates_from_code接口兼容.
    """
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'//[^\n]*', '', code)
    lines = code.strip().split('\n')
    ir = [l.strip() for l in lines if l.strip()]

    code_joined = ' '.join(ir)
    struct_defs = {}
    for sm in re.finditer(
        r'typedef\s+struct\s*\{([^}]*)\}\s*(\w+)', code_joined):
        struct_defs[sm.group(2)] = sm.group(1)

    alloc_sites = _extract_alloc_sites(ir, struct_defs)
    candidates = []

    for i, line in enumerate(ir):
        if line.startswith('#') or line.startswith('/*') or \
           line.startswith('//'):
            continue

        # 模式1-5: 库函数写入
        _extract_lib_writes(line, i, alloc_sites, ir, candidates)

        # 模式6: 数组索引写入
        _extract_array_index_writes(line, i, alloc_sites, candidates)

        # 模式7: 指针算术写入
        _extract_ptr_deref_writes(line, i, alloc_sites, candidates)

        # 模式8: sprintf/snprintf写入
        _extract_sprintf_writes(line, i, alloc_sites, ir, candidates)

    return candidates, ir


__all__ = ['extract_candidates_from_code']
