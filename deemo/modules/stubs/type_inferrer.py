# re-export from compat/ — 类型推断桩
# 上游模块通过行过滤 → compile → exec 方式加载；本桩保持相同的代理策略
# 参考: VulCatch (arXiv:2408.07181) 的 CodeT5 伪代码提升 + Neural Decompilation (arXiv:2412.07538)
import os as _os

_src_path = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'type_inferrer.py')
with open(_src_path, 'r', encoding='utf-8') as _fh:
    _raw = _fh.readlines()
_code = ''.join(_raw)
exec(compile(_code, _src_path, 'exec'), globals())

# --- 类型推断补充: 基于 VulCatch 的 KAN 特征提取思想 ---
# KAN (Kolmogorov-Arnold Networks) 在 VulCatch 中用于伪代码特征提取；
# 此处的启发式规则模仿 KAN 的"可学习激活函数"思路——不是学习参数，
# 而是通过参数化规则对类型窄化做分段线性逼近。

import re as _regex

# 浮点常量识别 — 解决上游只处理整数类型的问题
_FLOAT_IMM_PATTERN = _regex.compile(
    r'[-+]?(?:\d+\.\d*|\.\d+)(?:[eE][-+]?\d+)?[fFdD]?$'
)

def classify_float_immediate(token: str) -> str | None:
    """检测 token 是否为浮点立即数，返回精度标记 'f32'|'f64'|None。"""
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

# 位运算上下文中的类型缩小 — 常用于检测加密/混淆代码中的整数类型
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
