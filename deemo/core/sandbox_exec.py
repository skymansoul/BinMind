# [DEPRECATED] [STUB] — 无外部引用, 保留接口兼容
# MinGW限制下无法做真沙箱, 源级验证由 heap_overflow_src_verifier 完成
"""沙箱执行验证 — 弃用桩, 无调用方。"""
def run_sandbox_validation(files, blackboard=None, **kw):
    return []
