"""
流敏感分配大小追踪 —— 跨基本块追踪malloc分配大小的流动。

核心问题: 现有代码在HeapContextTracker中追踪malloc/free/realloc调用,
但有两个关键局限:
  1. 只追踪精确常量大小的分配, 遇到动态大小(size来自变量)就放弃
  2. 不追踪变量赋值对指针的影响: p=q意味着两者指向同一缓冲区,
     对q的store应与对p的alloc size比较

方法: 扩展size追踪至两阶段:
  F1: 聚合分配事件 —— 记录每个变量的完整分配历史, 含动态size的表达式
  F2: 指针别名 —— 追踪 p=q 级联, 建立等价类; 任一等效变量的分配大小
      对所有同类成员适用

不实现完整SSA或别名分析 —— 仅追踪函数内的直接赋值链。
O(n) 单遍扫描。

  - "Demand-Driven Pointer Analysis"
  - Steensgaard: unification-based alias analysis
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class AllocRecord:
    """单次分配的完整记录。"""
    pc: int = 0
    var_name: str = ''
    alloc_func: str = ''         # malloc / calloc / realloc
    size_expr: str = ''           # 原始size表达式
    size_value: int = -1          # -1=动态, >=0=常量
    is_dynamic: bool = True
    # 回溯链: size_var的赋值链
    size_chain: List[str] = field(default_factory=list)

@dataclass
class VarsEquivClass:
    """指针等价类 —— 通过p=q赋值关联的一组变量。"""
    canonical: str = ''           # 代表变量
    members: Set[str] = field(default_factory=set)
    alloc_records: List[AllocRecord] = field(default_factory=list)

class FlowSensitiveTracker:
    """流敏感的分配大小追踪器。

    在一次IR扫描中同时完成:
      - 分配记录收集 (F1)
      - 指针等价类构建 (F2)
    """

    _ASSIGN_RE = re.compile(r'(\w[\w\d_]*)\s*=\s*(\w[\w\d_]*)\s*;?$')
    _MALLOC_RE = re.compile(
        r'(?:(\w[\w\d_]*)\s*=\s*)?(malloc|calloc|realloc)\s*\(\s*(.+?)\s*\)',
        re.IGNORECASE)
    _FREE_RE = re.compile(r'free\s*\(\s*(\w[\w\d_]*)\s*\)', re.IGNORECASE)

    def __init__(self):
        self.alloc_records: Dict[str, List[AllocRecord]] = {}
        self.equiv_classes: Dict[str, VarsEquivClass] = {}
        self.var_to_equiv: Dict[str, str] = {}  # var → canonical
        self.active_sizes: Dict[str, int] = {}    # var → effective size at current pc

    def track(self, ir_lines: List[str]) -> 'FlowSensitiveTracker':
        """扫描IR行, 构建完整的分配追踪图。"""
        for pc, line in enumerate(ir_lines):
            stripped = line.strip()
            self._process_line(stripped, pc)
        return self

    def _process_line(self, line: str, pc: int) -> None:
        # 分配调用
        m = self._MALLOC_RE.search(line)
        if m:
            var = m.group(1) or ''
            func = m.group(2).lower()
            size_expr = m.group(3).strip()
            size_val = self._eval_size(size_expr)
            record = AllocRecord(
                pc=pc, var_name=var, alloc_func=func,
                size_expr=size_expr, size_value=size_val,
                is_dynamic=(size_val < 0),
            )
            if var:
                self.alloc_records.setdefault(var, []).append(record)
                if not record.is_dynamic:
                    self.active_sizes[var] = size_val
                    canon = self._ensure_equiv(var)
                    self.equiv_classes[canon].alloc_records.append(record)
                else:
                    self.active_sizes[var] = -1
            return

        # 释放
        m = self._FREE_RE.search(line)
        if m:
            var = m.group(1)
            self.active_sizes[var] = 0
            return

        # 指针赋值: p = q
        m = self._ASSIGN_RE.match(line)
        if m:
            lhs = m.group(1)
            rhs = m.group(2)
            if rhs in self.active_sizes:
                self.active_sizes[lhs] = self.active_sizes[rhs]
                self._merge_equiv(lhs, rhs)

    def get_effective_size(self, var: str) -> int:
        """查询变量的有效分配大小。"""
        canon = self.var_to_equiv.get(var, var)
        size = self.active_sizes.get(canon, -1)
        if size >= 0:
            return size
        return self.active_sizes.get(var, -1)

    def get_allocation_history(self, var: str) -> List[AllocRecord]:
        """获取变量(及其等价类)的完整分配历史。"""
        canon = self.var_to_equiv.get(var, var)
        records = list(self.alloc_records.get(canon, []))
        records.extend(self.alloc_records.get(var, []))
        records.sort(key=lambda r: r.pc)
        return records

    def is_allocated_var(self, var: str) -> bool:
        """检查变量是否由malloc返回(曾经被分配过)。"""
        if var in self.alloc_records and self.alloc_records[var]:
            return True
        canon = self.var_to_equiv.get(var, '')
        return canon in self.alloc_records and bool(self.alloc_records[canon])

    def get_equiv_members(self, var: str) -> Set[str]:
        """获取与var等价的变量集。"""
        canon = self.var_to_equiv.get(var, var)
        if canon in self.equiv_classes:
            return self.equiv_classes[canon].members | {canon}
        return {var}

    def _ensure_equiv(self, var: str) -> str:
        if var not in self.var_to_equiv:
            self.var_to_equiv[var] = var
            self.equiv_classes[var] = VarsEquivClass(
                canonical=var, members={var})
        return self.var_to_equiv[var]

    def _merge_equiv(self, a: str, b: str) -> None:
        ca = self._ensure_equiv(a)
        cb = self._ensure_equiv(b)
        if ca == cb:
            return
        # union by size: 更大的类吸收更小的
        cls_a = self.equiv_classes[ca]
        cls_b = self.equiv_classes[cb]
        if len(cls_a.members) >= len(cls_b.members):
            cls_a.members |= cls_b.members
            cls_a.alloc_records.extend(cls_b.alloc_records)
            for m in cls_b.members:
                self.var_to_equiv[m] = ca
            self.equiv_classes.pop(cb)
        else:
            cls_b.members |= cls_a.members
            cls_b.alloc_records.extend(cls_a.alloc_records)
            for m in cls_a.members:
                self.var_to_equiv[m] = cb
            self.equiv_classes.pop(ca)

    @staticmethod
    def _eval_size(expr: str) -> int:
        expr = expr.strip()
        try:
            return int(expr)
        except ValueError:
            pass
        try:
            return int(expr, 16)
        except ValueError:
            pass
        # sizeof(type) 映射
        m = re.match(r'sizeof\s*\(\s*(\w+)\s*\)', expr, re.IGNORECASE)
        if m:
            sizes = {'int': 4, 'long': 8, 'char': 1, 'short': 2,
                     'float': 4, 'double': 8, 'void': 1, 'size_t': 8}
            return sizes.get(m.group(1).lower(), -1)
        return -1
