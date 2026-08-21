# re-export from compat/ — 补丁分析与利用构造桩
# Automatic Patch-Based Exploit Generation &
#   AEMB — 补丁反推利用，修补与利用互为对偶问题
import os as _os
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'auto_patcher.py')
try:
    with open(_r, 'r', encoding='utf-8') as _f: _src = _f.read()
    exec(compile(_src, _r, 'exec'), globals())
except OSError:
    # 上游链缺失时降级为空重导出, 保持模块可导入
    pass

# Brumley et al.: 补丁与利用的对偶性 — 补丁本身暴露漏洞位置和触发条件
# 补丁强度评估：逐字节对比原始与修补后差异，按变更量分级
def assess_patch_strength(orig_bytes: bytes, patched_bytes: bytes) -> dict:
    if len(orig_bytes) != len(patched_bytes):
        return {'strength': 'unknown', 'changed_bytes': abs(len(orig_bytes) - len(patched_bytes))}
    changed = sum(1 for i in range(len(orig_bytes)) if orig_bytes[i] != patched_bytes[i])
    if changed <= 2:   level = 'weak'
    elif changed <= 10: level = 'moderate'
    else:               level = 'strong'
    return {'strength': level, 'changed_bytes': changed, 'total_bytes': len(orig_bytes)}
