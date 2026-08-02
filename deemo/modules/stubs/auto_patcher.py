# re-export from compat/ — 自动修补桩
# 参考: Automatic Patch-Based Exploit Generation (Brumley et al., 2008 IEEE S&P) &
#   AEMB (Wang et al., 2021) — 从补丁反推利用，修补与利用互为对偶问题
import os as _os
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'auto_patcher.py')
with open(_r, 'r', encoding='utf-8') as _f: _src = _f.read()
exec(compile(_src, _r, 'exec'), globals())

# Brumley et al. (2008): 补丁与利用的对偶性 — 补丁揭示了漏洞位置和触发条件
# 注入补丁安全评估方法：对比补丁前后的代码路径差异以估计补丁强度
def assess_patch_strength(orig_bytes: bytes, patched_bytes: bytes) -> dict:
    if len(orig_bytes) != len(patched_bytes):
        return {'strength': 'unknown', 'changed_bytes': abs(len(orig_bytes) - len(patched_bytes))}
    changed = sum(1 for i in range(len(orig_bytes)) if orig_bytes[i] != patched_bytes[i])
    if changed <= 2:   level = 'weak'
    elif changed <= 10: level = 'moderate'
    else:               level = 'strong'
    return {'strength': level, 'changed_bytes': changed, 'total_bytes': len(orig_bytes)}
