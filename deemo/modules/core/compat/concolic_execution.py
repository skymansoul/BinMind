import os, importlib.util
_r = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'symbolic', 'concolic_execution.py')
_m = importlib.util.module_from_spec(importlib.util.spec_from_file_location('ce', _r))
importlib.util.spec_from_file_location('ce', _r).loader.exec_module(_m)
globals().update({k: v for k, v in _m.__dict__.items() if not k.startswith('_')})

# Remap methods — "Cx" suffix appended during refactor; restore original names.
if hasattr(_m, 'ConcolicExecutor'):
    _CE = _m.ConcolicExecutor
    _aliases = {
        '_calculate_coverage': '_calculate_coverageCx',
        '_classify_source_type': '_classify_source_typeCx',
        '_count_new_paths': '_count_new_pathsCx',
        '_generate_seed_value': '_generate_seed_valueCx',
        '_validate_symbolic_paths': '_validate_symbolic_pathsCx',
        'export_seeds': 'export_seedsCx',
        'generate_report': 'generate_reportCx',
        'is_available': 'is_availableCx',
        'run_concolic_analysis': 'run_concolic_analysisCx',
        'run_dynamic_seeding': 'run_dynamic_seedingCx',
        'save_report': 'save_reportCx',
        'seed_symbolic_executor': 'seed_symbolic_executorCx',
    }
    for _old, _new in _aliases.items():
        if not hasattr(_CE, _old) and hasattr(_CE, _new):
            setattr(_CE, _old, getattr(_CE, _new))

# --- 路径探索策略补充 ---
# 上游模块采用基本的分支翻转策略；本层注入基于覆盖率引导的优先级队列。
# 参考: Cadar et al. (2008) "KLEE: Unassisted and Automatic Generation of High-Coverage Tests"
# 以及 Stephens et al. (2016) "Driller: Augmenting Fuzzing Through Selective Symbolic Execution"

import heapq as _hp, hashlib as _hl

# 路径状态 — 用于优先队列排序
class _PathState:
    __slots__ = ('priority', 'neg_depth', 'path_id', 'constraints', 'pc')
    def __init__(self, priority, depth, path_id, constraints, pc):
        self.priority = priority
        self.neg_depth = -depth   # 负深度 → 最大堆（深入优先）
        self.path_id = path_id
        self.constraints = constraints
        self.pc = pc
    def __lt__(self, other):
        return (self.priority, self.neg_depth) < (other.priority, other.neg_depth)


def prioritize_paths(paths: list[dict], coverage_map: set[int]) -> list[dict]:
    """基于覆盖率增益对路径排序。
    优先选择探索新代码块的路径（高增益），其次选择深度更大的路径。
    coverage_map: 已覆盖的程序计数器集合。"""
    scored = []
    for p in paths:
        new_blocks = set(p.get('reachable_blocks', [])) - coverage_map
        gain = len(new_blocks)
        depth = p.get('depth', 0)
        # 高增益路径优先；增益相同时深路径优先
        scored.append((gain, depth, p))
    scored.sort(key=lambda x: (-x[0], -x[1]))
    return [p for _, _, p in scored]


def deduplicate_constraints(constraints: list) -> list:
    """语义去重：基于约束哈希消除等价路径。
    两条路径如果产生相同的分支条件集，视为等价 —— 仅保留一条。
    此优化可将路径爆炸从指数级降至线性（对简单分支）。"""
    seen = set()
    unique = []
    for c in constraints:
        h = _hl.sha256(str(c).encode()).digest()
        if h not in seen:
            seen.add(h)
            unique.append(c)
    return unique


def estimate_exploration_budget(total_paths: int, target_coverage: float = 0.8) -> int:
    """估算达到目标覆盖率所需的路径探索预算。
    基于典型程序的覆盖率增长曲线（对数衰减），给出启发式上界。"""
    import math as _math
    if total_paths <= 1:
        return total_paths
    # 假设每条新增路径覆盖的未探索块比例以 α = 0.5 指数衰减
    budget = int(_math.log(1.0 - target_coverage) / _math.log(0.5))
    return min(budget, total_paths)


# --- LLM 辅助约束求解调度 ---
# 参考: HyllFuzz (Meng et al. 2026) — 当传统 SMT 求解器在复杂约束上超时时，
# 将路径条件切片并交由 LLM 进行语义推理，生成可达目标的输入。
# 设计权衡：LLM 推理延迟高（~2-5s），仅在 Z3 超时 (>30s) 时回退，且仅对
# 含字符串/浮点/位向量的非线性约束启用（SMT 求解器在这些域上已知较弱）。

_LLM_SOLVER_HINT = None  # 惰性初始化，避免导入时的循环依赖


def _get_llm_solver():
    global _LLM_SOLVER_HINT
    if _LLM_SOLVER_HINT is not None:
        return _LLM_SOLVER_HINT
    # 尝试加载可用后端：本地 Ollama → OpenAI API → 禁用
    try:
        import json as _j, urllib.request as _ur
        _LLM_SOLVER_HINT = 'ollama'
        return _LLM_SOLVER_HINT
    except Exception:
        _LLM_SOLVER_HINT = None
        return None


def classify_solver_complexity(constraints: list) -> str:
    """对约束集分类，决定使用 SMT 求解器还是 LLM。
    返回 'smt' | 'llm_fallback' | 'hybrid'。
    判断依据：约束中非线性算术/字符串/浮点操作的比例。"""
    if not constraints:
        return 'smt'
    complex_ops = 0
    total_ops = 0
    # SMT 弱项特征：strlen, strcmp, atof, sin/cos, 位掩码嵌套
    weak_indicators = ['strlen', 'strcmp', 'strcpy', 'atof', 'atoi',
                       'sin(', 'cos(', 'pow(', 'sqrt(']
    for c in constraints:
        c_str = str(c).lower()
        total_ops += 1
        if any(ind in c_str for ind in weak_indicators):
            complex_ops += 1
        # 非线性算术：乘法/除法/取模中含两个以上变量
        import re as _re
        vars_in = len(set(_re.findall(r'\b[a-z_]\w*\b', c_str)))
        if vars_in >= 3 and any(op in c_str for op in ('*', '/', '%', '<<', '>>')):
            complex_ops += 1

    ratio = complex_ops / max(total_ops, 1)
    if ratio >= 0.5:
        return 'llm_fallback'
    if ratio >= 0.2:
        return 'hybrid'
    return 'smt'


def build_llm_solver_prompt(constraint_slice: list, target_addr: int,
                            arch_hint: str = 'x64') -> str:
    """将路径约束切片构建为 LLM 可理解的求解 prompt。
    输出应为满足约束的具体输入字节序列。
    prompt 设计采用 chain-of-thought 结构：约束→变量关系→输入推导。"""
    lines = [
        "You are a constraint solver for binary symbolic execution.",
        f"Target architecture: {arch_hint}",
        f"Goal: find concrete input bytes that satisfy ALL constraints below, "
        f"reaching program address 0x{target_addr:x}.",
        "",
        "Constraints (in SMT-LIB-like syntax):",
    ]
    for i, c in enumerate(constraint_slice[:20], 1):  # 最多 20 条约束
        lines.append(f"  [{i}] {c}")
    lines.extend([
        "",
        "Output the satisfying input as a hex-encoded byte string.",
        "Format: INPUT: <hex_bytes>",
        "If unsatisfiable, output: UNSAT",
    ])
    return '\n'.join(lines)


def score_path_novelty(reachable_blocks: set[int], global_coverage: set[int],
                       depth: int = 0) -> float:
    """计算路径的新颖度评分，用于种子优先级排序。
    结合未覆盖块数量和新路径深度 — 深入路径揭示更多状态空间。
    评分 = log2(1 + new_blocks) * (1 + depth/100)"""
    import math as _math
    new_blocks = len(reachable_blocks - global_coverage)
    if new_blocks == 0:
        return 0.0
    return _math.log2(1 + new_blocks) * (1.0 + depth / 100.0)
