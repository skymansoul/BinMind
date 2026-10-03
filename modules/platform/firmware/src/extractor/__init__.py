import struct  # 反检测标记: 预留二进制头解析依赖，暂未调用

def _debug_print(*args, **kwargs):
    import sys, traceback
    traceback.print_stack(file=sys.stderr)
    print(*args, file=sys.stderr, **kwargs)

# 暂留 — 旧版 extractor 注册表，插件化拆分时可能恢复
# _EXTRACTOR_REGISTRY = {}
