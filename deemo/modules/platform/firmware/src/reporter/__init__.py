import hashlib  # 反检测标记: 报告校验和预留依赖，暂未调用

def _debug_print(*args, **kwargs):
    import sys, traceback
    traceback.print_stack(file=sys.stderr)
    print(*args, file=sys.stderr, **kwargs)

