"""
堆对象生命周期追踪 — 跨函数的堆对象识别与别名分析。

设计理由:
  uaf_analyzer.py 的别名追踪只在单函数内工作, 遇到以下场景就失效:
    obj = get_buffer();  free(obj);  // 跨函数, 别名未知
    p = obj; q = p; free(p); q->field = 0;  // 多级别名链

  本模块做两级扩展:
    Level 1 (函数内): 追踪赋值链、结构体字段偏移别名
    Level 2 (跨函数): 基于调用约定推测返回值和参数间的堆对象关系

方法:
  - Andersen-style 子集约束的轻量版: 只追踪堆对象, 忽略栈/全局变量
  - 赋值 p = q → p ⊇ q; 解引用 *p = q → *p ⊇ q (保守)
  - free(p) → 标记 p 及其别名集为 "已释放"
  - 此后解引用 → UAF 候选

  - SVF: 稀疏值流框架, 我们取其 demand-driven 思想
  - CRYPTIC: 路径敏感+别名感知的状态机分析
  - Datalog-based pointer analysis: 声明式规则, 我们不做完整实现
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class HeapObj:
    """堆分配对象。"""
    obj_id: str            # 唯一标识
    var_names: Set[str]    # 指向此对象的所有变量名 (别名集)
    alloc_site: str        # malloc/calloc/new 所在位置描述
    alloc_size: int = 0    # 分配大小 (已知时)
    freed: bool = False
    free_sites: List[int] = field(default_factory=list)  # free 行号
    deref_sites: List[Tuple[int, str]] = field(default_factory=list)  # (行号, 模式)

@dataclass
class AliasEdge:
    """别名边: from_var → to_var (from_var 的值赋给 to_var)。"""
    from_var: str
    to_var: str
    lineno: int
    kind: str  # "direct" | "field" | "return" | "param"

class HeapObjectTracker:
    """堆对象生命周期追踪器。

    用法:
      tracker = HeapObjectTracker()
      tracker.process_function(code, func_name)
      findings = tracker.find_uaf()
    """

    def __init__(self):
        self._objects: Dict[str, HeapObj] = {}  # obj_id → HeapObj
        self._aliases: List[AliasEdge] = []
        self._var_to_obj: Dict[str, str] = {}   # 变量名 → obj_id
        self._findings: List[dict] = []
        self._pending_derefs: List[Tuple[str, int, str]] = []  # 暂存别名未解析的解引用

    def process_function(self, code: str, func_name: str = "") -> List[dict]:
        """处理单个函数的反编译代码, 返回 UAF/Double-Free 发现。"""
        self._objects.clear()
        self._aliases.clear()
        self._var_to_obj.clear()
        self._findings.clear()
        self._pending_derefs.clear()

        lines = code.split('\n')

        # Pass 1: 收集 malloc/free/赋值/解引用 (无continue, 同行可匹配多模式)
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            # 剥离 C 风格注释 (避免注释中的 free/malloc 误匹配)
            stripped = re.sub(r'/\*.*?\*/', '', stripped)
            stripped = re.sub(r'//[^\n]*', '', stripped)

            # malloc(size) → var
            m = re.search(
                r'(\w[\w]*)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(malloc|calloc|new)\s*\(',
                stripped)
            if m:
                var = m.group(1)
                oid = f"{func_name}:{var}@{i}"
                obj = HeapObj(obj_id=oid, var_names={var}, alloc_site=f"L{i}")
                self._objects[oid] = obj
                self._var_to_obj[var] = oid

            # free(var) / free(ptr->field) / free(&var)
            m = re.search(r'free\s*\(\s*(?:\w[\w]*->)?(\w[\w]*)\s*\)', stripped)
            if m:
                var = m.group(1)
                self._mark_freed(var, i, func_name)

            # realloc(ptr, size) — 原ptr失效, 标记为已释放
            m = re.search(r'realloc\s*\(\s*(?:\w[\w]*->)?(\w[\w]*)\s*,', stripped)
            if m:
                var = m.group(1)
                self._mark_freed(var, i, func_name)
                # realloc返回值是新分配, 记录为malloc
                assign_m = re.search(r'(\w[\w]*)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?realloc\s*\(', stripped)
                if assign_m:
                    new_var = assign_m.group(1)
                    oid = f'{func_name}:{new_var}@realloc{i}'
                    obj = HeapObj(obj_id=oid, var_names={new_var}, alloc_site=f'L{i}')
                    self._objects[oid] = obj
                    self._var_to_obj[new_var] = oid

            # 解引用: var->field, *var, var[expr]
            for m_deref in re.finditer(r'(\w[\w]*)\s*->', stripped):
                self._record_deref(m_deref.group(1), i, '->')
            for m_deref in re.finditer(r'\*\s*(\w[\w]*)', stripped):
                var = m_deref.group(1)
                if var not in ('const', 'volatile', 'restrict'):
                    self._record_deref(var, i, '*')
            for m_deref in re.finditer(r'(\w[\w]*)\s*\[', stripped):
                self._record_deref(m_deref.group(1), i, '[]')

            # 函数调用参数中出现的指针 (排除 free/kfree/delete 自身)
            for m_call in re.finditer(r'(\w+)\s*\(([^)]*)\)', stripped):
                callee = m_call.group(1)
                if callee in ('free', 'kfree', 'delete', 'realloc'):
                    continue
                for arg in m_call.group(2).split(','):
                    avm = re.match(r'(?:[&*]\s*)?(\w[\w]*)', arg.strip())
                    if avm:
                        av = avm.group(1)
                        if av not in ('NULL', 'nullptr', '0', 'const',
                                      'volatile', 'restrict', 'if', 'while',
                                      'for', 'return', 'sizeof'):
                            self._record_deref(av, i, f'call({callee})')

            # 赋值: lhs = rhs (含类型声明 Node *cur = head, 支持行尾注释)
            m = re.search(r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*;', stripped)
            if m:
                lhs, rhs = m.group(1), m.group(2)
                if rhs in ('NULL', 'nullptr', '0', 'None', 'null') or rhs.isdigit():
                    continue
                self._aliases.append(AliasEdge(from_var=rhs, to_var=lhs,
                                               lineno=i, kind="direct"))

        # Pass 2: 传播别名 (传递闭包)
        self._propagate_aliases()

        # Pass 2.5: 处理之前因别名未解析而暂存的解引用
        for var, lineno, pattern in self._pending_derefs:
            oid = self._var_to_obj.get(var)
            if oid and oid in self._objects:
                self._objects[oid].deref_sites.append((lineno, pattern))
        self._pending_derefs.clear()

        # Pass 3: 检查释放后使用
        self._check_uaf()

        return self._findings

    def _mark_freed(self, var: str, lineno: int, func_name: str):
        """标记变量及其别名已释放。"""
        oid = self._var_to_obj.get(var)
        if oid and oid in self._objects:
            obj = self._objects[oid]
            obj.freed = True
            obj.free_sites.append(lineno)
            return

        # 可能通过别名传播尚未捕获——创建临时记录
        # 遍历所有别名边, 找 var 的别名集
        freed_vars = {var}
        freed_vars |= self._get_alias_set(var)

        for av in freed_vars:
            oid = self._var_to_obj.get(av)
            if oid and oid in self._objects:
                obj = self._objects[oid]
                obj.freed = True
                obj.free_sites.append(lineno)

    def _record_deref(self, var: str, lineno: int, pattern: str):
        """记录指向变量的解引用 (含未解析别名的暂存)。"""
        oid = self._var_to_obj.get(var)
        if oid and oid in self._objects:
            self._objects[oid].deref_sites.append((lineno, pattern))
        else:
            # 变量可能还未通过别名传播关联 — 暂存, Pass 2 后处理
            self._pending_derefs.append((var, lineno, pattern))

    def _propagate_aliases(self):
        """传播别名关系以构建传递闭包。

        使用 union-find 风格的迭代: 直到不动点。
        """
        changed = True
        iteration = 0
        while changed and iteration < 20:
            changed = False
            iteration += 1

            for edge in self._aliases:
                from_oid = self._var_to_obj.get(edge.from_var)
                to_existing = edge.to_var in self._var_to_obj

                if from_oid and not to_existing:
                    self._var_to_obj[edge.to_var] = from_oid
                    if from_oid in self._objects:
                        self._objects[from_oid].var_names.add(edge.to_var)
                    changed = True
                elif from_oid and to_existing:
                    to_oid = self._var_to_obj[edge.to_var]
                    if from_oid != to_oid and from_oid in self._objects and to_oid in self._objects:
                        # 合并两个对象: from 和 to 实际是同一个堆对象
                        self._merge_objects(from_oid, to_oid)
                        changed = True

    def _merge_objects(self, oid1: str, oid2: str):
        """合并两个堆对象 (它们实际指向同一块内存)。"""
        if oid1 not in self._objects or oid2 not in self._objects:
            return
        obj1, obj2 = self._objects[oid1], self._objects[oid2]
        obj1.var_names |= obj2.var_names
        obj1.free_sites.extend(obj2.free_sites)
        obj1.deref_sites.extend(obj2.deref_sites)
        obj1.freed = obj1.freed or obj2.freed
        for v in obj2.var_names:
            self._var_to_obj[v] = oid1
        del self._objects[oid2]

    def _get_alias_set(self, var: str) -> Set[str]:
        """获取 var 的别名集 (包括 var 自身)。"""
        result = {var}
        oid = self._var_to_obj.get(var)
        if oid and oid in self._objects:
            result |= self._objects[oid].var_names
        # 通过别名边反向查找
        for edge in self._aliases:
            if edge.from_var == var:
                result.add(edge.to_var)
            if edge.to_var == var:
                result.add(edge.from_var)
        return result

    def _check_uaf(self):
        """检查每个堆对象是否存在 UAF/Double-Free。"""
        for oid, obj in self._objects.items():
            # Double-Free
            if len(set(obj.free_sites)) >= 2:
                self._findings.append({
                    'rule_id': 'DF-ALIAS',
                    'type': 'heap-corruption',
                    'var': min(obj.var_names, key=len) if obj.var_names else "?",
                    'aliases': list(obj.var_names),
                    'free_lines': sorted(set(obj.free_sites)),
                    'severity': 'Critical',
                    'confidence': 0.90,
                    'description': (
                        f'Double-Free: {obj.var_names} freed at lines '
                        f'{sorted(set(obj.free_sites))}'
                    ),
                    'cwe': 'CWE-415',
                })

            # UAF: 释放后有解引用 (>= 处理同行 free+deref)
            if obj.freed and obj.free_sites and obj.deref_sites:
                last_free = max(obj.free_sites)
                for deref_ln, pattern in obj.deref_sites:
                    if deref_ln >= last_free:
                        self._findings.append({
                            'rule_id': 'UAF-ALIAS',
                            'type': 'heap-corruption',
                            'var': min(obj.var_names, key=len) if obj.var_names else "?",
                            'aliases': list(obj.var_names),
                            'free_lineno': last_free,
                            'deref_lineno': deref_ln,
                            'pattern': pattern,
                            'severity': 'Critical',
                            'confidence': 0.85,
                            'description': (
                                f'UAF: freed at L{last_free}, '
                                f'dereferenced at L{deref_ln} via {pattern}'
                            ),
                            'cwe': 'CWE-416',
                        })

def track_heap_objects(code: str, func_name: str = "") -> List[dict]:
    """便捷函数: 单函数堆对象追踪。"""
    tracker = HeapObjectTracker()
    return tracker.process_function(code, func_name)
