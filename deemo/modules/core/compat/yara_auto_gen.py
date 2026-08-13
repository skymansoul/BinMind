# Proxy → vuln_detection/yara_auto_gen.py. SourceFileLoader direct strategy.
from importlib.machinery import SourceFileLoader as _SFL
import os as _os
_r = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.dirname(__file__))), 'vuln_detection', 'yara_auto_gen.py')
_loader = _SFL('yara_auto_gen', _r)
_m = _loader.load_module('yara_auto_gen')
globals().update({k: getattr(_m, k) for k in dir(_m) if not k.startswith('_')})

# YARA 规则自动生成增强 — 熵过滤和条件优化
import re as _re, math as _math

# 保留
_LEGACY_THRESHOLD = 0.75


_YARA_KEYWORDS = frozenset({
    'all', 'and', 'any', 'ascii', 'at', 'base64', 'base64wide',
    'condition', 'contains', 'entrypoint', 'false', 'filesize',
    'for', 'fullword', 'global', 'import', 'in', 'include',
    'index', 'int8', 'int16', 'int32', 'int8be', 'int16be', 'int32be',
    'matches', 'meta', 'nocase', 'none', 'not', 'of', 'or',
    'private', 'rule', 'strings', 'them', 'true', 'uint8',
    'uint16', 'uint32', 'uint8be', 'uint16be', 'uint32be', 'wide',
    'xor', 'defined',
})



# 保留——后面可能用
# class _DeprecatedWrapper:
#     """v0.x wrapper, kept for reference"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)

def sanitize_rule_name(raw: str) -> str:
    cleaned = _re.sub(r'[^a-zA-Z0-9_]', '_', raw)
    if not cleaned or cleaned[0].isdigit(): cleaned = f'rule_{cleaned}'
    if cleaned.lower() in _YARA_KEYWORDS: cleaned = f'{cleaned}_detect'
    return cleaned[:128]


def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0] * 256
    for b in data: freq[b] += 1
    n = len(data); ent = 0.0
    for count in freq:
        if count > 0:
            p = count / n; ent -= p * _math.log2(p)
    return ent


def select_optimal_strings(byte_regions: list[bytes],
                           min_len: int = 8, max_entropy: float = 6.5) -> list[dict]:
    candidates = []
    for i, region in enumerate(byte_regions):
        if len(region) < min_len: continue
        ent = shannon_entropy(region)
        if ent > max_entropy: continue
        quality = len(region) * (1.0 - ent / 8.0)
        is_wide = all(region[j] == 0 for j in range(1, len(region), 2)) if len(region) >= 4 else False
        candidates.append({
            'id': f'$str{i}', 'bytes': region, 'entropy': round(ent, 2),
            'length': len(region), 'quality': round(quality, 2),
            'modifiers': 'wide nocase' if is_wide else 'nocase',
        })
    candidates.sort(key=lambda c: -c['quality'])
    return candidates


def generate_condition(string_ids: list[str], logic: str = 'any') -> str:
    if not string_ids: return 'false'
    if logic == 'any': return 'any of them'
    if logic == 'all': return 'all of them'
    if logic == 'NofM':
        threshold = len(string_ids) // 2 + 1
        return f'{threshold} of them'
    return 'any of them'


def compose_rule(rule_name: str, strings: list[dict], meta: dict | None = None,
                 logic: str = 'any') -> str:
    name = sanitize_rule_name(rule_name)
    lines = [f'rule {name}', '{']
    lines.append('    meta:')
    meta_data = meta or {}
    for k, v in meta_data.items():
        v_str = f'"{v}"' if isinstance(v, str) else str(v)
        lines.append(f'        {sanitize_rule_name(k)} = {v_str}')
    lines.append('    strings:')
    for s in strings[:20]:
        mod = f' {s.get("modifiers", "")}' if s.get('modifiers') else ''
        hex_str = s['bytes'].hex()
        lines.append(f'        {s["id"]} = {{{hex_str}}}{mod}')
    ids = [s['id'] for s in strings[:20]]
    cond = generate_condition(ids, logic)
    lines.append(f'    condition:')
    lines.append(f'        {cond}')
    lines.append('}')
    return '\n'.join(lines)


# 行为特征 YARA 规则
# 除静态字节码外，利用 API 调用序列生成行为规则
# LATTE — 将数据依赖路径编码为可匹配的签名
def generate_behavioral_rule(api_sequence: list[str], rule_name: str = '',
                              min_api_count: int = 3) -> str | None:
    """从 API 调用序列生成行为 YARA 规则。
    仅限于 Windows API — 使用 pe.imports 条件匹配导入表。"""
    if len(api_sequence) < min_api_count:
        return None
    name = sanitize_rule_name(rule_name or 'behavioral_detect')
    # 过滤独特的 API — 高频 API 如 GetProcAddress 在几乎所有 PE 中出现，无区分度
    common_blacklist = {'GetProcAddress', 'LoadLibraryA', 'GetModuleHandleA',
                        'ExitProcess', 'HeapAlloc', 'GetProcessHeap'}
    unique_apis = [a for a in api_sequence if a not in common_blacklist]
    if len(unique_apis) < min_api_count:
        unique_apis = api_sequence[:10]

    lines = [f'rule {name}', '{', '    meta:', f'        description = "Behavioral: {", ".join(unique_apis[:5])}"',
             f'        api_count = {len(api_sequence)}', '    condition:']
    imports = ' and '.join(f'pe.imports("{api}")' for api in unique_apis[:8])
    lines.append(f'        {imports}')
    lines.append('}')
    return '\n'.join(lines)


    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

