"""
栈溢出策略推荐与 exploit 参数构建。

"""


from typing import Any, Dict, Optional


def recommend_strategy(
    analysis: Dict[str, Any],
    binfo: Optional[Dict[str, Any]],
    libc_info: Optional[Dict[str, Any]],
) -> str:
    """基于分析结果推荐利用策略。"""
    if not analysis.get('overflowable'):
        return 'no-overflow-detected'

    has_canary = analysis.get('has_canary', False)

    if not has_canary:
        return 'direct-ret-overwrite'

    if analysis.get('canary_leak_path'):
        return 'canary-leak-then-overwrite'

    return 'brute-force-or-alternative'


def build_exploit_params(
    analysis: Dict[str, Any],
    binfo: Optional[Dict[str, Any]],
    libc_info: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """构建 exploit 生成所需的参数集。"""
    params: Dict[str, Any] = {
        'offset': analysis.get('padding', 64),
        'has_canary': analysis.get('has_canary', False),
        'strategy': analysis.get('strategy', 'unknown'),
    }

    if libc_info and libc_info.get('symbols'):
        syms = libc_info['symbols']
        if 'system' in syms:
            params['system_offset'] = syms['system']
        if 'str_bin_sh' in syms:
            params['binsh_offset'] = syms['str_bin_sh']

    if binfo:
        params['arch'] = binfo.get('arch', 'x86-64')
        params['bits'] = binfo.get('bits', 64)

    return params
