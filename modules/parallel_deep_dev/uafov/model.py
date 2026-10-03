"""UAF 检测数据模型 — 分配/释放/使用/重绑定事件与结论。

对象键: 变量分配为整数 oid; 字段指针 p->f 为 "oid:f"。
事件携带分支路径, 供分支互斥判定。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class AllocSite:
    var: str
    pos: int
    oid: int


@dataclass
class FreeEvent:
    base_var: str
    obj_key: str          # oid 或 "oid:field"
    pos: int
    path: Tuple[Tuple[int, str], ...]
    double_free: bool = False


@dataclass
class UseEvent:
    base_var: str
    obj_key: str
    pos: int
    path: Tuple[Tuple[int, str], ...]
    kind: str = 'deref'   # deref / callarg / write


@dataclass
class RebindEvent:
    base_var: str
    obj_key: str          # 新对象键或 None(空化)
    pos: int
    kind: str = 'alloc'   # alloc / null / alias / other


@dataclass
class Finding:
    func: str
    base_var: str
    obj_key: str
    free_pos: int
    use_pos: int
    verdict: str
    confidence: float
    reasons: List[str] = field(default_factory=list)
    description: str = ''
    kind: str = 'uaf'     # uaf / double_free
