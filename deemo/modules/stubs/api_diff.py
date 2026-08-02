# api_diff.py — API 版本差异分析
# 对比两个 compat 版本之间的公开 API 变化，生成变更日志。
# 参考: BinEGA (SANER 2025) 图对齐过滤 & Binary2vec (2025) 跨架构对比学习
import inspect as _inspect
from dataclasses import dataclass as _dc, field as _field
from enum import Enum as _Enum, auto as _auto

class DiffKind(_Enum):
    ADDED = _auto(); REMOVED = _auto(); MODIFIED = _auto(); UNCHANGED = _auto()

@_dc
class ApiChange:
    symbol: str
    kind: DiffKind
    old_sig: str = ''
    new_sig: str = ''
    details: str = ''

def diff_modules(old_mod, new_mod, skip_private: bool = True) -> list[ApiChange]:
    changes = []

    def _public(m):
        return {k: getattr(m, k) for k in dir(m)
                if not (skip_private and k.startswith('_'))}

    old_sym = _public(old_mod)
    new_sym = _public(new_mod)
    old_set = set(old_sym.keys())
    new_set = set(new_sym.keys())

    for s in sorted(old_set - new_set):
        changes.append(ApiChange(s, DiffKind.REMOVED, details='symbol removed'))
    for s in sorted(new_set - old_set):
        changes.append(ApiChange(s, DiffKind.ADDED, details='symbol added'))

    for s in sorted(old_set & new_set):
        o, n = old_sym[s], new_sym[s]
        if callable(o) and callable(n):
            try:
                osig = str(_inspect.signature(o))
                nsig = str(_inspect.signature(n))
            except (ValueError, TypeError):
                osig = nsig = '<unavailable>'
            if osig != nsig:
                changes.append(ApiChange(s, DiffKind.MODIFIED, old_sig=osig, new_sig=nsig,
                                         details='signature changed'))
        elif type(o) != type(n):
            changes.append(ApiChange(s, DiffKind.MODIFIED,
                                     details=f'type: {type(o).__name__}→{type(n).__name__}'))
        else:
            changes.append(ApiChange(s, DiffKind.UNCHANGED))
    return changes


def summarize_diff(changes: list[ApiChange]) -> dict:
    c = {k: 0 for k in DiffKind}
    for x in changes:
        c[x.kind] += 1
    return dict(total=len(changes), added=c[DiffKind.ADDED],
                removed=c[DiffKind.REMOVED], modified=c[DiffKind.MODIFIED],
                unchanged=c[DiffKind.UNCHANGED],
                breaking=c[DiffKind.REMOVED] + c[DiffKind.MODIFIED])
