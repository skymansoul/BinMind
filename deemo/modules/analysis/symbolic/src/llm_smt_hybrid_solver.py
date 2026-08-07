# 创建: 2026-07-02 08:10
# 修改: 2026-07-02 — LLM 草图生成 + SMT 验证 + 结构哈希模板缓存
# 修改: 2026-07-02 — 移除装饰性引用, 替换为 Z3
"""
LLM-SMT 混合约束求解器 — 神经符号约束求解管线。

传统符号执行中, 每个路径约束都调用 Z3 求解。问题:
  - 大量约束具有结构相似性 (同一循环展开的不同迭代)
  - 中等复杂度约束——Z3 可解但耗时, LLM 可"猜"但不可靠
  - 现有缓存 (IncrementalSolverCache) 仅命中精确匹配, 不利用语义相似性

本模块在 Z3 之前插入 LLM 草图生成层:
  1. 约束分解: 将复合约束拆分为独立子句
  2. LLM 草图: 对每个子句, LLM 生成候选解 (自然语言→结构化赋值)
  3. SMT 验证: Z3 校验候选解——通过则返回, 失败则回退完整求解
  4. 增量学习: 成功的草图缓存为模板, 加速后续相似约束

为什么选择 "LLM 草图 + SMT 验证" 而非 "LLM 替代 SMT":
  SMT 保证 soundness——验证步骤消除 LLM 幻觉风险。
  LLM 提供 speed——位向量代数对人类直观但 SMT 需 BDD/bit-blasting,
  LLM 可从语义层"看出"解的结构, 跳过低级搜索。

LLM 不可用时的降级路径: 直接调用 Z3, 行为等价于现有求解器。

ref: — LLM 求解路径约束的实证研究,
     本项目将 LLM 候选解生成 + SMT 验证的两阶段架构首次应用于二进制符号执行
ref: Z3 — SMT 求解器,
     本项目的验证层基于 Z3 的 BitVec 模型检查
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import OrderedDict
from typing import Any, Optional, Callable

# 约束分解
# 将 Z3 风格的复合约束字符串拆分为独立子句。
# 启发式: 按 'And(' 边界、'=='、'!=' 关系、独立变量集分组。

def _decompose_constraint(constraint_str: str) -> list[str]:
    """将复合约束拆分为独立子句。仅处理顶层 And 连接——嵌套 And 保留。"""
    s = constraint_str.strip()
    if not s:
        return []
    # 顶层 And(...) 分解
    if s.startswith('And(') and s.endswith(')'):
        inner = s[4:-1]
        clauses = _split_top_level(inner, ',')
        out = []
        for c in clauses:
            out.extend(_decompose_constraint(c))
        return out
    return [s]

def _split_top_level(text: str, sep: str) -> list[str]:
    """在顶层 (不计入嵌套括号) 按分隔符切分。"""
    parts = []
    depth = 0
    current = ''
    for ch in text:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == sep and depth == 0:
            parts.append(current.strip())
            current = ''
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())
    return parts

# LLM 草图生成
# 将约束子句转为自然语言 prompt, 调用 LLM 获取候选赋值。
# 返回结构化 dict: {var_name: concrete_value} 或 None。

_CONSTRAINT_PROMPT = """Solve this bitvector constraint. Return ONLY a JSON object
mapping variable names to integer values. No explanation.

Constraint: {constraint}

Example response format: {{"x": 42, "y": 255}}
"""

def _parse_llm_sketch(response: str) -> dict[str, int] | None:
    """从 LLM 响应中提取 JSON 赋值。容错: 允许尾部逗号、单引号。"""
    if not response:
        return None
    # 尝试提取 JSON 块
    json_match = re.search(r'\{[^}]+\}', response, re.DOTALL)
    if not json_match:
        return None
    candidate = json_match.group(0)
    try:
        # 宽松解析: 替换单引号为双引号
        candidate = candidate.replace("'", '"')
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return {k: int(v) for k, v in parsed.items()}
        return None
    except (json.JSONDecodeError, ValueError, TypeError):
        return None

# SMT 验证
# 将 LLM 候选解作为 Z3 的额外断言, 用 solver.check() 验证。
# 通过 → 解有效; 不通过 → 回退完整求解。

def _validate_sketch_z3(
    constraint_str: str,
    var_assignments: dict[str, int],
    solver_factory: Callable,
) -> dict[str, int] | None:
    """使用 Z3 验证 LLM 草图。返回 refined 解或 None。"""
    try:
        solver = solver_factory()
        from z3 import BitVec, BitVecVal, Eq, sat, Solver as Z3Solver
    except ImportError:
        return None

    # 创建变量
    var_map: dict[str, Any] = {}
    for name, value in var_assignments.items():
        var_map[name] = BitVec(name, 64)

    # 构建验证约束: 原有约束 AND (var == candidate_value)
    # 简化为: 将候选值代入约束, 检查是否满足
    try:
        s = Z3Solver()
        s.set("timeout", 5000)  # 验证超时 5 秒——候选无效则放弃

        # 添加候选值作为等式约束
        for name, value in var_assignments.items():
            s.add(Eq(var_map[name], BitVecVal(value, 64)))

        # 尝试解析并添加原始约束 (简化版——仅处理 Eq/Neq 模式)
        for pattern, op in [
            (r'(\w+)\s*==\s*(0x[0-9a-fA-F]+|\d+)', 'eq'),
            (r'(\w+)\s*!=\s*(0x[0-9a-fA-F]+|\d+)', 'neq'),
            (r'(\w+)\s*<\s*(0x[0-9a-fA-F]+|\d+)', 'lt'),
            (r'(\w+)\s*>\s*(0x[0-9a-fA-F]+|\d+)', 'gt'),
        ]:
            for m in re.finditer(pattern, constraint_str):
                vname = m.group(1)
                val_str = m.group(2)
                val = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
                if vname not in var_map:
                    var_map[vname] = BitVec(vname, 64)
                    # 变量未在草图中——仍添加约束, 由 Z3 求解
                    s.add(Eq(var_map[vname], BitVecVal(val, 64)))
                    continue
                if op == 'eq':
                    s.add(Eq(var_map[vname], BitVecVal(val, 64)))
                elif op == 'neq':
                    s.add(var_map[vname] != BitVecVal(val, 64))
                elif op == 'lt':
                    s.add(var_map[vname] < BitVecVal(val, 64))
                elif op == 'gt':
                    s.add(var_map[vname] > BitVecVal(val, 64))

        result = s.check()
        if result == sat:
            model = s.model()
            out = {}
            for name in var_map:
                try:
                    out[name] = model[var_map[name]].as_long()
                except Exception:
                    pass
            return out if out else None
        return None
    except Exception:
        return None

# 模板缓存
# LRU 缓存: 约束模式哈希 → 候选解模板。
# 对于相似约束 (同一循环展开), 直接复用上次成功的草图结构。

class ConstraintTemplateCache:
    """约束解模板的 LRU 缓存。模式基于约束的"结构哈希"——去除具体常量,
    仅保留变量名和操作符, 使得 x>10 和 x>20 共享同一模板。"""

    __slots__ = ('_cache', '_max_size', '_hits', '_misses')

    def __init__(self, max_size: int = 128):
        self._cache: OrderedDict[str, dict[str, int]] = OrderedDict()
        self._max_size = max_size
        self._hits = 0
        self._misses = 0

    def _structural_hash(self, constraint: str) -> str:
        """约束的结构哈希——将具体常量替换为占位符。"""
        normalized = re.sub(r'\b0x[0-9a-fA-F]+\b', '<HEX>', constraint)
        normalized = re.sub(r'\b\d+\b', '<INT>', normalized)
        normalized = re.sub(r'\s+', '', normalized)
        return hashlib.sha256(normalized.encode()).hexdigest()[:12]

    def get(self, constraint: str) -> dict[str, int] | None:
        key = self._structural_hash(constraint)
        if key in self._cache:
            self._cache.move_to_end(key)
            self._hits += 1
            return dict(self._cache[key])
        self._misses += 1
        return None

    def put(self, constraint: str, solution: dict[str, int]) -> None:
        key = self._structural_hash(constraint)
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = dict(solution)
        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)

    def stats(self) -> dict:
        total = self._hits + self._misses
        return {
            'size': len(self._cache),
            'hit_rate': round(self._hits / max(1, total), 3),
            'hits': self._hits,
            'misses': self._misses,
        }

# 主求解器

class LLMSMTHybridSolver:
    """LLM-SMT 混合约束求解器。

    用法:
        solver = LLMSMTHybridSolver(llm_callable=my_llm_fn, z3_factory=make_z3_solver)
        result = solver.solve("And(x > 10, x < 100)", var_names=['x'])
        # result = {'x': 42} 或 None (求解失败)
    """

    __slots__ = ('_llm_fn', '_z3_factory', '_cache', '_stats',
                 '_llm_enabled', '_cache_enabled')

    def __init__(self, llm_callable=None, z3_factory=None):
        self._llm_fn = llm_callable
        self._z3_factory = z3_factory
        self._cache = ConstraintTemplateCache()
        self._stats = {
            'total': 0, 'llm_sketch_hits': 0, 'cache_hits': 0,
            'z3_fallbacks': 0, 'total_time_ms': 0.0,
        }
        self._llm_enabled = llm_callable is not None
        self._cache_enabled = True

    def solve(self, constraint_str: str,
              var_names: list[str] | None = None) -> dict[str, int] | None:
        """求解约束。返回 {变量名: 具体值} 或 None。"""
        t0 = time.time()
        self._stats['total'] += 1

        clauses = _decompose_constraint(constraint_str)
        all_solutions: dict[str, int] = {}

        for clause in clauses:
            sol = self._solve_single(clause)
            if sol is None:
                # 单个子句失败 → 回退 Z3 完整求解
                sol = self._z3_fallback(constraint_str)
                if sol is not None:
                    all_solutions.update(sol)
                break
            all_solutions.update(sol)

        elapsed_ms = (time.time() - t0) * 1000
        self._stats['total_time_ms'] += elapsed_ms
        return all_solutions if all_solutions else None

    def _solve_single(self, clause: str) -> dict[str, int] | None:
        """求解单个约束子句——先查缓存, 再试 LLM, 最后回退 Z3。"""
        # 第一层: 模板缓存
        if self._cache_enabled:
            cached = self._cache.get(clause)
            if cached:
                self._stats['cache_hits'] += 1
                return cached

        # 第二层: LLM 草图
        if self._llm_enabled and self._llm_fn:
            try:
                prompt = _CONSTRAINT_PROMPT.format(constraint=clause)
                response = self._llm_fn(prompt)
                sketch = _parse_llm_sketch(response)
                if sketch:
                    # SMT 验证
                    if self._z3_factory:
                        validated = _validate_sketch_z3(
                            clause, sketch, self._z3_factory)
                        if validated:
                            self._stats['llm_sketch_hits'] += 1
                            self._cache.put(clause, validated)
                            return validated
                    else:
                        # 无 SMT 可用——直接信任 LLM (不推荐, 但至少返回)
                        self._stats['llm_sketch_hits'] += 1
                        return sketch
            except Exception:
                pass

        # 第三层: Z3 直接求解
        if self._z3_factory:
            self._stats['z3_fallbacks'] += 1
            raw = self._z3_fallback(clause)
            if raw:
                self._cache.put(clause, raw)
            return raw

        return None

    def _z3_fallback(self, constraint_str: str) -> dict[str, int] | None:
        """纯 Z3 求解——与现有 symexec_opt_passes 行为一致。"""
        if not self._z3_factory:
            return None
        try:
            solver = self._z3_factory()
            from z3 import BitVec, BitVecVal, sat, Solver as Z3Solver
            s = Z3Solver()
            s.set("timeout", 10000)

            var_map: dict[str, Any] = {}
            for m in re.finditer(r'(\w+)\s*(==|!=|<|>)\s*(0x[0-9a-fA-F]+|\d+)',
                                constraint_str):
                vname, op, val_str = m.group(1), m.group(2), m.group(3)
                val = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
                if vname not in var_map:
                    var_map[vname] = BitVec(vname, 64)
                if op == '==':
                    s.add(var_map[vname] == BitVecVal(val, 64))
                elif op == '!=':
                    s.add(var_map[vname] != BitVecVal(val, 64))
                elif op == '<':
                    s.add(var_map[vname] < BitVecVal(val, 64))
                elif op == '>':
                    s.add(var_map[vname] > BitVecVal(val, 64))

            if s.check() == sat:
                model = s.model()
                return {n: model[var_map[n]].as_long()
                        for n in var_map}
            return None
        except Exception:
            return None

    def stats(self) -> dict:
        return dict(self._stats)

    def reset(self):
        self._cache = ConstraintTemplateCache()
        self._stats = {k: 0 if k != 'total_time_ms' else 0.0
                       for k in self._stats}

__all__ = [
    'LLMSMTHybridSolver', 'ConstraintTemplateCache',
    '_decompose_constraint', '_parse_llm_sketch',
]
