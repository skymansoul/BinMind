"""
传染图度量函数 — 导入重叠、符号亲密度、加固比。

以控制单文件行数。包含
  - _normalize_import_name: 导入名归一化
  - _find_family / _family_set: 敏感函数族分类
  - compute_import_overlap: Jaccard 导入重叠度
  - compute_symbol_proximity: 危险函数家族共现亲密度
  - compute_hardening_ratio: NX/PIE/Canary/RELRO/FORTIFY 五维加固分
  - DEFAULT_WEIGHTS / _SENSITIVE_FAMILIES: 常量和配置

修改记录:
创建 2026-07-17
"""

import math
from typing import Any, Dict, FrozenSet, List, Optional, Set

DEFAULT_WEIGHTS = (0.35, 0.30, 0.25, 0.10)

_SENSITIVE_FAMILIES: Dict[str, FrozenSet[str]] = {
    'mem_corruption': frozenset({
        'memcpy', 'strcpy', 'sprintf', 'gets', 'scanf', 'strcat',
        'memmove', 'bcopy', 'read', 'fgets', 'recv', 'recvfrom'}),
    'format_string': frozenset({
        'printf', 'fprintf', 'sprintf', 'snprintf', 'vsprintf',
        'syslog', 'vwprintf'}),
    'command_exec': frozenset({
        'system', 'popen', 'execve', 'execvp', 'CreateProcess',
        'WinExec', 'ShellExecute'}),
    'crypto': frozenset({
        'RSA_', 'AES_', 'SHA', 'MD5_', 'HMAC', 'EVP_',
        'BN_', 'EC_', 'DH_'}),
    'file_ops': frozenset({
        'open', 'fopen', 'read', 'write', 'close', 'unlink',
        'rename', 'chmod', 'access', 'stat'}),
}


def _normalize_import_name(name: str) -> str:
    n = name.lower().lstrip('_')
    if n.startswith('imp_'): n = n[4:]
    return n


def _find_family(imp_name: str) -> Optional[str]:
    n = _normalize_import_name(imp_name)
    for family, members in _SENSITIVE_FAMILIES.items():
        for m in members:
            if m.lower() in n: return family
    return None


def _family_set(imports: List[str]) -> Set[str]:
    families = set()
    for imp in imports:
        f = _find_family(imp)
        if f: families.add(f)
    return families


def compute_import_overlap(imports_a: List[str], imports_b: List[str]) -> float:
    set_a = {_normalize_import_name(i) for i in imports_a}
    set_b = {_normalize_import_name(i) for i in imports_b}
    if not set_a or not set_b: return 0.0
    return len(set_a & set_b) / len(set_a | set_b)


def compute_symbol_proximity(imports_a: List[str], imports_b: List[str]) -> float:
    fam_a, fam_b = _family_set(imports_a), _family_set(imports_b)
    if not fam_a or not fam_b: return 0.0
    isect, union = fam_a & fam_b, fam_a | fam_b
    family_sim = len(isect) / len(union) if union else 0.0
    boost = 0.0
    for pair, bonus in [({'mem_corruption','command_exec'},0.15),
                        ({'mem_corruption','format_string'},0.10),
                        ({'command_exec','file_ops'},0.08)]:
        if pair.issubset(isect): boost = max(boost, bonus)
    return min(family_sim + boost, 1.0)


def compute_hardening_ratio(checksec: Dict[str, Any]) -> float:
    s = 0.0
    if checksec.get('NX', False): s += 0.2
    if checksec.get('PIE', False): s += 0.2
    if checksec.get('Canary', False): s += 0.2
    if 'full' in checksec.get('RELRO', '').lower(): s += 0.2
    if checksec.get('FORTIFY', False): s += 0.2
    return s


def _effective_coverage_ratio(imports: List[str], sensitive_only: bool = True) -> float:
    n = len(imports)
    if n == 0: return 0.0
    if sensitive_only:
        return min(len(_family_set(imports)) / 8.0, 1.0)
    return min(math.log2(n + 1) / math.log2(100), 1.0)
