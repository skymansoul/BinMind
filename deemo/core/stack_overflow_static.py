"""
栈溢出静态回退分析 - 反向污点追踪 + 缓冲区大小估算。

"""


import logging
import re
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

# 危险函数调用的常见缓冲区大小模式（用于静态估算）
DIRTY_CALLS = {
    'gets', 'strcpy', 'strcat', 'sprintf', 'scanf', 'read',
    'fgets', 'recv', 'recvfrom', 'getline',
}


def static_overflow_analysis(
    binary_path: str,
    func_name: str,
    binfo: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    静态回退分析-反向污点追踪 + 缓冲区大小估算。

    与旧版区别: 不再仅靠函数名正则匹配判断危险调用。
    对每个危险调用做反向def-use链追踪, 验证参数是否来自用户输入源。
    若参数来自安全源(常量字符串/snprintf格式化), 不标记为危险。
    """
    result: Dict[str, Any] = {'overflowable': False, 'padding': 0, 'insights': []}

    try:
        from core.decompiler import decompile_function
        decomp = decompile_function(binary_path, func_name)
        pseudocode = decomp.get('pseudocode', '')

        if not pseudocode:
            return result

        # 污点追踪 - 验证危险调用的参数是否来自用户输入
        try:
            from core.taint_source_tracker import trace_taint_source, is_arg_tainted
            call_sigs = []
            for call in DIRTY_CALLS:
                for m in re.finditer(rf'({call})\s*\(\s*([^,)]+)', pseudocode):
                    call_sigs.append((call, m.group(2).strip()))

            taint_result = trace_taint_source(pseudocode, func_name, call_sigs)
            tainted_calls = {k for k, v in taint_result.items()
                           if v.get('tainted')}
            if tainted_calls:
                result['overflowable'] = True
                result['insights'].append(
                    f"Taint tracking: {len(tainted_calls)} dangerous call(s) "
                    f"with user-controlled buffer"
                )
                result['insights'].append(
                    f"Tainted calls: {', '.join(sorted(tainted_calls)[:3])}"
                )
            else:
                result['overflowable'] = False  # 即使有危险函数, 参数未受污染
                result['insights'].append(
                    "Taint tracking: dangerous calls found but args not user-controlled"
                )
        except ImportError:
            # 回退: 简单关键字匹配
            for call in DIRTY_CALLS:
                if call in pseudocode:
                    result['overflowable'] = True
                    result['insights'].append(
                        f"Static pattern: dangerous call to {call} detected (taint tracker unavailable)"
                    )

        # 估算缓冲区大小
        if result['overflowable']:
            buf_matches = re.findall(
                r'char\s+\w+\s*\[(\d+)\]', pseudocode
            )
            if buf_matches:
                max_buf = max(int(m) for m in buf_matches)
                bits = binfo.get('bits', 64) if binfo else 64
                saved_rbp = 8 if bits == 64 else 4
                result['padding'] = max_buf + saved_rbp
                result['insights'].append(
                    f"Estimated padding: {max_buf}B buffer + {saved_rbp}B saved rbp = {result['padding']}"
                )
            else:
                result['padding'] = 72
                result['insights'].append(
                    "No local buffer declaration found, using default padding=72"
                )

    except Exception as e:
        _log.debug("Static overflow analysis failed: %s", e)

    return result
