"""检测上下文构建 — 从 heap_overflow_detector 分离以.

创建: 2025-03-03
用途: 为 SemanticFPFilter 构建特征提取所需的上下文 dict.
"""

from __future__ import annotations

import re as _re
from typing import Dict, List, Optional

from .interval_domain import DEFAULT_ALLOCATOR
from .malloc_size_inferrer import MallocSite
from .path_guard_collector import PathGuard


def build_context(instructions: List[str], access_idx: int,
                  site: MallocSite, offset: int,
                  guards: Optional[List[PathGuard]] = None,
                  function_name: str = '') -> dict:
    """构建语义特征提取所需的上下文.

    function_name: 当前分析函数名, 用于 alloc_site_in_same_fn 判定.
    site.func_name 与 function_name 比较是否同一函数.
    """
    ctx: dict = {
        'allocator_alignment': DEFAULT_ALLOCATOR.alignment,
        'in_loop_body': False, 'in_error_cleanup': False,
        'guarded_by_bounds_check': False, 'has_size_guard': False,
        'caller_is_trusted': False, 'alloc_site_in_same_fn': True,
        'is_memcpy_like': False, 'is_write': True,
    }

    # 循环体检测: 反向扫描跳转指令目标 < 当前地址 → 循环
    for w in instructions[max(0, access_idx - 15):access_idx + 1]:
        wl = w.strip().lower()
        if any(x in wl for x in ('jmp', 'jne', 'je', 'jg', 'jl',
                                  'jge', 'jle', 'jbe', 'jae', 'jb', 'ja')):
            m = _re.search(r'(0x[0-9a-f]+)', wl)
            if m and int(m.group(1), 16) < access_idx:
                ctx['in_loop_body'] = True

    # 边界检查守卫: 访问前 10 条指令内 cmp + jcc
    pre_text = ' '.join(instructions[max(0, access_idx - 10):access_idx])
    if ('cmp' in pre_text and
            any(x in pre_text for x in ('jg', 'ja', 'jge', 'jae', 'jb', 'jbe'))):
        ctx['guarded_by_bounds_check'] = True

    # size 上界守卫: malloc 前 cmp reg, const → jcc
    pre_alloc = instructions[max(0, site.insn_addr - 20):site.insn_addr]
    for j, ins in enumerate(pre_alloc):
        m = _re.match(r'cmp\s+(\w+),\s*(0x[0-9a-f]+|\d+)', ins.strip().lower())
        if m:
            for k in range(j + 1, min(j + 4, len(pre_alloc))):
                if any(x in pre_alloc[k].lower()
                       for x in ('jbe', 'jae', 'jb', 'ja', 'jle', 'jge')):
                    ctx['has_size_guard'] = True; break

    # 路径守卫增强: guards 中是否有 size_param_reg 的约束
    if guards:
        for g in guards:
            if g.reg in ('rcx', 'rdi', 'rdx', 'r8') and \
               abs(g.insn_addr - site.insn_addr) < 20:
                ctx['has_size_guard'] = True; break

    if any(x in pre_text for x in ('goto err', 'goto fail', 'goto cleanup')):
        ctx['in_error_cleanup'] = True

    il = (instructions[access_idx].lower()
          if access_idx < len(instructions) else '')
    ctx['is_memcpy_like'] = any(x in il for x in ('rep movs', 'rep stos'))

    # 动态判定: 调用者是否为已知可信函数 (_CRT_/__security_/__report_)
    ctx['caller_is_trusted'] = _is_trusted_caller(function_name)

    # 动态判定: 分配点是否在同一函数内
    if function_name and site.func_name:
        ctx['alloc_site_in_same_fn'] = (site.func_name == function_name
                                        or site.func_name == 'malloc')
    else:
        ctx['alloc_site_in_same_fn'] = True
    return ctx


# 已知可信调用者前缀 — CRT安全初始化/运行时报错处理
_TRUSTED_PREFIXES = (
    '_CRT_', '__security_', '__report_',
    '__acrt_', '__mingw_', '_initterm',
)


def _is_trusted_caller(function_name: str) -> bool:
    """判定函数是否属于已知可信调用者."""
    if not function_name:
        return False
    fn_lower = function_name.lower()
    return any(fn_lower.startswith(p.lower()) for p in _TRUSTED_PREFIXES)


# CRT/编译器内部函数模式 — 用于过滤噪声
_CRT_FN_PATTERNS = [
    'duplicate_ppstrings', '__tmain', '_tmain', 'CRTStartup',
    '__mingw_', '___w64_mingwthr', '__acrt_', '__set_', '__get_',
    '__p__', '_initterm', '_amsg_exit', '_pei386_', '_fpreset',
    '_configthreadlocale', '__do_global', '__security_init',
    'atexit', '_cexit', 'pre_c_init', '_setargv',
    '__mingw_setusermatherr', 'check_managed_app',
    '__Balloc', '__multadd', '__i2b', '__mult', '__pow5mult',
    '__lshift', '__diff', '__ulp', '__b2d', '__d2b', '__strcp',
    '__any_on', '__gethex', '__hexdig', '__hexnan', '__match',
    '__ratio', '__cmp', '__copybits', '__increment', '__bias',
    '__trailz', '__lo0bits', '__hi0bits',
    '__gcc_', '__gxx_', '__cxa_', '__seh_',
    '__mingw', '__mingw_', '__msvcrt', '__crt', '__chkstk',
]


def is_user_function(function_name: str, only_user_code: bool = True) -> bool:
    """判断函数是否为用户代码 (非 CRT/编译器生成)."""
    if not only_user_code:
        return True
    if not function_name:
        return True
    fn_lower = function_name.lower()
    if fn_lower.startswith('__'):
        return False
    for pattern in _CRT_FN_PATTERNS:
        pl = pattern.lower()
        if fn_lower == pl or fn_lower.startswith(pl):
            return False
    return True
