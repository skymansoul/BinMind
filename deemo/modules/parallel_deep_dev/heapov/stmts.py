"""语句模型 — 解析器与各分析阶段共享的数据结构。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .expr_ast import Expr


@dataclass
class Assign:
    target: Expr
    op: str
    value: Expr
    pos: int


@dataclass
class CallStmt:
    call: Expr
    pos: int


@dataclass
class ExprStmt:
    expr: Expr
    pos: int


@dataclass
class If:
    cond: Expr
    then_b: 'Block'
    else_b: Optional['Block']
    pos: int


@dataclass
class For:
    init: Optional[object]
    cond: Optional[Expr]
    incr: Optional[Expr]
    body: 'Block'
    pos: int


@dataclass
class While:
    cond: Expr
    body: 'Block'
    pos: int


@dataclass
class Return:
    value: Optional[Expr]
    pos: int


@dataclass
class Block:
    stmts: List[object] = field(default_factory=list)
    pos: int = 0


@dataclass
class Decl:
    name: str
    base_type: str
    is_pointer: bool
    array_size: Optional[int]
    init: Optional[Expr]
    pos: int


@dataclass
class Func:
    name: str
    params: List[str]
    body: Block
    pos: int
