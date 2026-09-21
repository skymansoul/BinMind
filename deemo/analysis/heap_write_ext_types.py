"""
写模式扩展检测的数据结构. 与堆写模式验证的 HeapAllocSite/HeapWriteSite
解耦, 供各写模式检测模块独立使用.
"""


from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ExtAlloc:
    """扩展分配点 — 含别名根与分配大小常量."""
    line: int = 0
    func: str = ""
    var: str = ""
    size_expr: str = ""
    size_const: int = -1
    root: str = ""            # 经别名解析后的根变量
    usable: int = -1          # ptmalloc2 有效容量


@dataclass
class ExtWrite:
    """扩展写入点 — 游走/结构体数组/无界输入/工厂绑定."""
    line: int = 0
    target: str = ""          # 写入目标 (别名后归一到根)
    kind: str = ""            # walk_write/struct_idx/unbounded_io/factory_write
    max_write: int = -1       # 最大写入量 (字节); -1=无法定界
    alloc_line: int = 0       # 关联分配点行号
    reason: str = ""
    confidence: float = 0.0


@dataclass
class ExtResult:
    """扩展验证结果 — VULN/SAFE/UNCERTAIN 判定."""
    verdict: str = "UNCERTAIN"
    alloc_line: int = 0
    write_line: int = 0
    var_name: str = ""
    alloc_size: int = -1
    write_size: int = -1
    overflow_bytes: int = 0
    confidence: float = 0.5
    reason: str = ""
    kind: str = ""

    def as_tuple(self) -> tuple:
        """兼容堆写模式验证的 HoResult 形状 (用于去重)."""
        return (self.alloc_line, self.write_line, self.var_name)


@dataclass
class WalkWrite:
    """指针游走写候选 — p 从 buf 出发, 经 p++/*p++ 移动."""
    base: str = ""            # 游走起点 (分配变量)
    ptr: str = ""             # 游走指针变量
    loop_line: int = 0
    write_line: int = 0
    max_steps_per_iter: int = 1   # 每次迭代最大游走步数
    loop_bound: int = -1          # 循环次数上界; -1=未知
    trailing_write: int = 0       # 循环后的额外写入 (如 *p=0)
    elem_size: int = 1            # 单次游走写入字节数
    driver: str = ""              # 驱动变量 (字符串指针/长度变量)
    is_str_loop: bool = False     # 循环按字符串指针扫描驱动


__all__ = [
    'ExtAlloc', 'ExtWrite', 'ExtResult', 'WalkWrite',
]
