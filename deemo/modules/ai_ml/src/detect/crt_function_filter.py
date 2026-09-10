# CRT/编译器内部函数过滤器-消除MinGW/MSVC/GCC运行时函数的系统性误报
# 这些函数出现在每个编译后的二进制中, 但不包含用户代码的漏洞
# 过滤策略: 函数名前缀/模式匹配, 覆盖主流编译器(MinGW/GCC/MSVC/Clang)
# 独立模块-不改动任何现有检测逻辑, 仅在管线入口处预过滤

from __future__ import annotations

import re
from typing import List, Set

# MinGW-w64 CRT函数前缀/精确名
_MINGW_CRT_PREFIXES = [
    '__mingw_', '__acrt_', '__p__', '__getmainargs', '__set_app_type',
    '__native_', '__report_', '__write_memory', '__gcc_',
    '___w64_mingwthr_', '__mingwthr_', '__tlregdtor', '__dyn_tls',
    '_pei386_', '__chkstk', '__security',
]

_MINGW_CRT_EXACT = {
    # CRT startup
    'mainCRTStartup', 'WinMainCRTStartup', 'wmainCRTStartup',
    '__tmainCRTStartup', '_tmainCRTStartup',
    # 内部函数
    'duplicate_ppstrings', 'check_managed_app', 'safe_flush',
    'mark_section_writable', 'restore_modified_sections',
    'do_pseudo_reloc', '_pei386_runtime_relocator',
    '_setargv', '__main', '_matherr', '_commode',
    'atexit', '_fpreset', '__do_global_dtors', '__do_global_ctors',
    '_set_invalid_parameter_handler', '_amsg_exit',
    '_initterm', '_initterm_e', '_configthreadlocale',
    '__acrt_iob_func', '_fmode', '__setusermatherr',
    '_gnu_exception_handler', '__mingw_oldexcpt_handler',
    '__mingw_initltssuo_force', '__mingw_initltsdyn_force',
    '__mingw_initltsdrot_force',
    # MSVC
    '_RTC_InitBase', '_RTC_Shutdown', '_RTC_CheckStackVars',
    '__security_init_cookie', '__report_gsfailure',
    '__scrt_common_main_seh', '__scrt_common_main',
    # GCC
    '_GLOBAL__sub_I_', '__static_initialization_and_destruction',
    '__cxx_global_var_init', '_Z41__static_initialization_and_destruction',
    'register_tm_clones', 'deregister_tm_clones',
    '__libc_csu_init', '__libc_csu_fini', '_start', '_dl_relocate_static_pie',
    'frame_dummy', '__do_global_dtors_aux',
}

# GCC/Clang常见内部函数前缀
_GCC_CRT_PREFIXES = [
    '__cxa_', '__gxx_', '__gnu_', '__gcc_',
    '_GLOBAL__', '_Z41__', '_ZSt',
]

# 含'.'的标签——全是内部/调试符号
_INTERNAL_LABEL = re.compile(r'\.')

# 主过滤函数
def is_crt_function(func_name: str) -> bool:
    """判断函数名是否为CRT/编译器内部函数。True=内部函数应跳过。"""
    if not func_name:
        return True

    # 含 '.' → 内部标签 (如 .l_start, .weak.xxx)
    if _INTERNAL_LABEL.search(func_name):
        return True

    # 精确匹配
    if func_name in _MINGW_CRT_EXACT:
        return True

    # 前缀匹配
    for prefix in _MINGW_CRT_PREFIXES + _GCC_CRT_PREFIXES:
        if func_name.startswith(prefix):
            return True

    # 双下划线开头 → 编译器内部
    if func_name.startswith('__'):
        return True

    return False


def filter_crt_functions(func_names: List[str]) -> List[str]:
    """过滤列表中的CRT/内部函数, 仅返回用户函数名"""
    return [n for n in func_names if not is_crt_function(n)]


def is_user_function(func_name: str) -> bool:
    """is_crt_function的反向-True=用户代码函数"""
    return not is_crt_function(func_name)
