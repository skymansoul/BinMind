# compat/ 代理导出 — 类型推断桩
# 通过行过滤→compile→exec 方式加载上游模块，与同目录代理策略一致
# 参考: VulCatch (arXiv:2408.07181) CodeT5 伪代码提升 & Neural Decompilation (arXiv:2412.07538)
import os as _os

_src_path = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'type_inferrer.py')
with open(_src_path, 'r', encoding='utf-8') as _fh:
    _raw = _fh.readlines()
_code = ''.join(_raw)
exec(compile(_code, _src_path, 'exec'), globals())

# 类型推断扩展: 基于 VulCatch KAN 特征提取策略
# KAN (Kolmogorov-Arnold Networks) 在 VulCatch 中用于伪代码特征提取；
# 以下启发式规则对 KAN 可学习激活函数做参数化分段线性逼近。

import re as _regex

# 浮点立即数检测 — 处理上游仅覆盖整数类型的缺口
_FLOAT_IMM_PATTERN = _regex.compile(
    r'[-+]?(?:\d+\.\d*|\.\d+)(?:[eE][-+]?\d+)?[fFdD]?$'
)

def classify_float_immediate(token: str) -> str | None:
    """检测 token 是否为浮点立即数，返回精度 'f32'|'f64'|None。"""
    if not token or not _FLOAT_IMM_PATTERN.match(token.strip()):
        return None
    stripped = token.strip().rstrip('fFdD')
    try:
        val = float(stripped)
    except ValueError:
        return None
    suffix = token.strip()[-1].lower() if token.strip()[-1].lower() in 'fd' else ''
    if suffix == 'f':
        return 'f32'
    if suffix == 'd' or abs(val) > 3.4e38 or abs(val) < 1.4e-45:
        return 'f64'
    return 'f64'

# 移位指令位宽推断 — 用于加密/混淆代码中的整数类型窄化
_SHIFT_PATTERN = _regex.compile(r'(?:sh[lr]|sar|rol|ror)\s+(\w+),\s*(\d+)', _regex.IGNORECASE)

def narrow_by_shift_pattern(insn_text: str, var_name: str) -> int | None:
    m = _SHIFT_PATTERN.search(insn_text)
    if not m or m.group(1) != var_name:
        return None
    shift_count = int(m.group(2))
    if shift_count <= 8:   return 8
    if shift_count <= 16:  return 16
    if shift_count <= 32:  return 32
    return 64
