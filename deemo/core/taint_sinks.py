# 定义"污点数据到达此处即构成漏洞"的危险函数集合。
# 与taint_propagator配合: propagator追踪数据流, sinks判定终点是否危险。
#
# 汇分类:
#   FORMAT_STRING — 格式化函数, 污点到达第一个参数 → 格式字符串漏洞
#   HEAP_OVERFLOW — 堆写入函数, 污点控制size或src → 堆溢出
#   STACK_OVERFLOW — 栈写入函数, 污点控制len → 栈溢出
#   COMMAND_INJ  — 命令执行, 污点到达参数 → 命令注入
#   UAF_COND     — free参数为污点 → 可能double-free或UAF前提

_FORMAT_SINKS = {
    'printf', 'fprintf', 'dprintf', 'sprintf', 'snprintf',
    'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
    'syslog', 'err', 'errx', 'warn', 'warnx',
    '__printf_chk', '__fprintf_chk', '__sprintf_chk',
}

_HEAP_SINKS = {
    'malloc':  {'danger_arg': 0, 'vuln': 'heap_overflow'},
    'calloc':  {'danger_arg': 1, 'vuln': 'heap_overflow'},
    'realloc': {'danger_arg': 1, 'vuln': 'heap_overflow'},
    'memcpy':  {'danger_arg': 2, 'vuln': 'heap_overflow'},
    'memmove': {'danger_arg': 2, 'vuln': 'heap_overflow'},
    'strcpy':  {'danger_arg': -1, 'vuln': 'heap_overflow'},
    'strncpy': {'danger_arg': 2, 'vuln': 'heap_overflow'},
}

_STACK_SINKS = {
    'strcpy':  {'danger_arg': -1, 'vuln': 'stack_overflow'},
    'sprintf': {'danger_arg': 1, 'vuln': 'stack_overflow'},
    'gets':    {'danger_arg': -1, 'vuln': 'stack_overflow'},
    'read':    {'danger_arg': 2, 'vuln': 'stack_overflow'},
}

_UAF_SINKS = {
    'free':    {'danger_arg': 0, 'vuln': 'uaf_precondition'},
}


def is_format_sink(func_name: str) -> bool:
    for s in _FORMAT_SINKS:
        if func_name.endswith(s) or func_name == s:
            return True
    return False


def is_heap_sink(func_name: str) -> dict:
    for s, info in _HEAP_SINKS.items():
        if func_name.endswith(s):
            return dict(info)
    return None


def is_stack_sink(func_name: str) -> dict:
    for s, info in _STACK_SINKS.items():
        if func_name.endswith(s):
            return dict(info)
    return None


def is_uaf_sink(func_name: str) -> dict:
    for s, info in _UAF_SINKS.items():
        if func_name.endswith(s):
            return dict(info)
    return None


__all__ = ['is_format_sink', 'is_heap_sink', 'is_stack_sink', 'is_uaf_sink',
           '_FORMAT_SINKS', '_HEAP_SINKS', '_STACK_SINKS', '_UAF_SINKS']
