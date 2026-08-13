"""生命周期耦合验证 — 把 free→use 判定建模为对象生死 + 分支互斥。

对象流已处理重绑定/空化/别名: free 后变量重指向新对象或空时,
后续 use 解析到不同键, 自然不构成 UAF。此处只补两条安全信号:
  1. 分支互斥: free 与 use 位于同一 if 的对立分支 → 永不共存
  2. double-free: 同对象二次释放
"""

from __future__ import annotations

from typing import List

from uafov import verdict as V
from uafov.model import Finding
from uafov.flow import extract_events


def branch_exclusive(p1, p2) -> bool:
    """两分支路径是否在同一 if 的对立分支。"""
    m1 = dict(p1)
    m2 = dict(p2)
    for k, side in m1.items():
        if k in m2 and m2[k] != side:
            return True
    return False


def verify_func(func) -> List[Finding]:
    ex = extract_events(func)
    findings: List[Finding] = []

    # double-free: 同对象相邻释放对, 且不在互斥分支
    frees_by_key: dict = {}
    for f in ex.frees:
        frees_by_key.setdefault(f.obj_key, []).append(f)
    for key, fs in frees_by_key.items():
        fs.sort(key=lambda e: e.pos)
        for i in range(1, len(fs)):
            prev = fs[i - 1]
            if branch_exclusive(prev.path, fs[i].path):
                continue
            findings.append(Finding(
                func=func.name, base_var=fs[i].base_var, obj_key=key,
                free_pos=prev.pos, use_pos=fs[i].pos, verdict=V.DOUBLE_FREE,
                confidence=V.CONF_DOUBLE_FREE, reasons=['double-free'],
                description=f'free({fs[i].base_var}) 重复释放', kind='double_free'))

    for f in ex.frees:
        for u in ex.uses:
            if u.pos <= f.pos:
                continue
            if u.obj_key != f.obj_key:
                continue
            if branch_exclusive(f.path, u.path):
                continue
            conf = V.CONF_UAF if u.kind in ('deref', 'write') else 0.80
            findings.append(Finding(
                func=func.name, base_var=u.base_var, obj_key=u.obj_key,
                free_pos=f.pos, use_pos=u.pos, verdict=V.UAF,
                confidence=conf, reasons=['free-then-use'],
                description=f'free({f.base_var}) 后 {u.kind} 使用',
                kind='uaf'))
    return findings
