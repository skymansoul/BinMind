# [DEPRECATED] [STUB] — 无外部引用, 保留接口兼容
# 全局副作用检测功能已由 heap_overflow_src_verifier 的跨函数分析覆盖
"""全局副作用冲突检测 — 弃用桩, 无调用方。"""
class SideEffectChecker:
    def scan(self, files): return []
def check_side_effects(files, blackboard=None): return []
