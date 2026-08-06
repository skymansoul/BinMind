# stub_adversarial_fuzzer.py — 蜕变关系导向的启发式模糊测试
# 创建于 2026-07-29
# 修改于 2026-08-04: 重命名，消除"对抗性"夸大表述；增加MR类别引导的变异选择
#
# 不满足于被动验证（给固定输入、检查输出是否满足 MR），
# 用 MR 违反数作为适应度函数，启发式搜索失效率更高的输入区域。
#
# 搜索策略: 爬山 + 随机重启 + MR类别引导的变异算子选择
#   - 基础变异: 按参数类型的领域感知算子
#   - 引导变异: 根据当前违反的MR类别选择针对性算子
#     (e.g., 违反 idempotence → 强化数值幂跳和重复操作)
#   - 适应度: 违反的 MR 数量
#   - 收敛: plateau_limit 轮无改善 → 重启
#
# 注意: 这是启发式搜索，非形式化对抗攻击。
#   真正对抗性样本生成 (如 Madry et al. 2018 的 PGD) 需要
#   可微分的输入-输出映射。桩函数的黑盒特性使得梯度不可用，
#   因此使用零阶启发式搜索作为替代。
#
# 区别于 CPS 测试 (arXiv:2412.03330) 的遗传规划:
#   该论文用 GP 搜索 CPS 输入空间。
#   本模块用更轻量的爬山+重启，适应度绑定到 stub_metamorphic_oracle
#   推导的 MR 集合。
import math as _math
import random as _random
import struct as _struct
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt, Callable

from modules.stubs.stub_contract import FuncContract as _FuncContract


@_dc
class FuzzCounterexample:
    """单条模糊测试发现的反例。"""
    func_name: str
    mr_category: str
    mr_description: str = ''
    adversarial_input: tuple = ()
    transformed_input: tuple = ()
    original_output: object = None
    transformed_output: object = None
    fitness: int = 0     # 该输入违反的 MR 总数


@_dc
class AdversarialFuzzResult:
    """一次对抗性模糊测试的完整结果。"""
    func_name: str
    iterations: int = 0
    seeds_tried: int = 0
    counterexamples: list = _field(default_factory=list)
    total_mr_violations: int = 0
    best_fitness: int = 0


# ---- 领域感知变异算子 ----
def _mutate_int(v: int) -> int:
    r = _random.random()
    if r < 0.25:
        return v * 10
    elif r < 0.45:
        return max(1, v // 10) if v != 0 else 1
    elif r < 0.60:
        return -v
    elif r < 0.75:
        return v + _random.randint(-100, 100)
    elif r < 0.88:
        return 0
    else:
        return (1 << _random.randint(0, 31)) - _random.randint(0, 1 << 30)


def _mutate_float(v: float) -> float:
    r = _random.random()
    if r < 0.25:
        return v * 10.0
    elif r < 0.45:
        return v / 10.0 if abs(v) > 1e-9 else 1.0
    elif r < 0.60:
        return -v
    elif r < 0.75:
        return v + _random.uniform(-100.0, 100.0)
    elif r < 0.88:
        return 0.0
    else:
        return _math.nan


def _mutate_str(s: str) -> str:
    if not s:
        return _random.choice(['\x00', '\xff', 'A' * 256, ''])
    op = _random.randint(0, 6)
    if op == 0:
        return s + s
    elif op == 1:
        return s[:max(1, len(s) // 2)]
    elif op == 2:
        return s[::-1]
    elif op == 3:
        return s.replace(s[0], '\x00') if s else '\x00'
    elif op == 4:
        return '\x00' * _random.randint(1, 1024)
    elif op == 5:
        return ''.join(chr(_random.randint(0, 255)) for _ in range(len(s)))
    else:
        return s * _random.randint(2, 5)


def _mutate_bytes(b: bytes) -> bytes:
    if not b:
        return _random.choice([b'\x00', b'\xff' * 256, b''])
    op = _random.randint(0, 4)
    if op == 0:
        return b + b
    elif op == 1:
        return b[:max(1, len(b) // 2)]
    elif op == 2:
        return bytes(reversed(b))
    elif op == 3:
        ba = bytearray(b)
        for i in range(min(5, len(ba))):
            ba[_random.randint(0, len(ba) - 1)] ^= 0xff
        return bytes(ba)
    else:
        return b'\x00' * _random.randint(1, 512)


def _mutate_list(lst: list) -> list:
    if not lst:
        return [[0], [None] * _random.randint(1, 10)]
    op = _random.randint(0, 5)
    if op == 0:
        return lst + lst
    elif op == 1:
        return lst[:max(1, len(lst) // 2)]
    elif op == 2:
        return lst[::-1]
    elif op == 3:
        return [lst[0]] * _random.randint(10, 100)
    elif op == 4:
        return [[]]
    else:
        new = list(lst)
        _random.shuffle(new)
        return new


_MUTATORS = {
    int: _mutate_int,
    float: _mutate_float,
    str: _mutate_str,
    bytes: _mutate_bytes,
    list: _mutate_list,
}


def _mutate_tuple(args: tuple) -> tuple:
    """对元组中每个元素施加类型对应变异。"""
    mutated = []
    for v in args:
        m = _MUTATORS.get(type(v))
        if m is not None:
            mutated.append(m(v))
        else:
            mutated.append(v)
    return tuple(mutated)


# ---- MR导向的变异算子 ----
# 根据当前违反的MR类别选择针对性变异
_MR_GUIDED_MUTATORS = {
    'idempotence': lambda v: v * 2 if isinstance(v, int) else
                    (v + v if isinstance(v, (str, bytes, list)) else v),
    'involution': lambda v: -v if isinstance(v, (int, float)) else
                   (v[::-1] if isinstance(v, (str, bytes, list)) else v),
    'commutative': lambda v: v,  # 交换性靠参数顺序变换，不是值变换
    'monotonic': lambda v: v * 10 if isinstance(v, (int, float)) else v,
    'structure': lambda v: (v * 3 if isinstance(v, (str, list, bytes))
                           else (v + 100 if isinstance(v, int) else v)),
    'null': lambda v: type(v)() if isinstance(v, (str, bytes, list, dict, set, tuple)) else v,
}


def _mutate_tuple_guided(args: tuple, mr_categories: list[str]) -> tuple:
    """MR类别引导的变异: 对违反的MR类别施加针对性变换。"""
    mutated = list(args)
    for i, v in enumerate(mutated):
        # 对每个违反的MR类别，50%概率施加该类别引导变换
        import random as _rnd
        for cat in mr_categories[:2]:  # 最多应用前2个类别的引导
            guide = _MR_GUIDED_MUTATORS.get(cat)
            if guide and _rnd.random() < 0.5:
                try:
                    mutated[i] = guide(v)
                except Exception:
                    pass
    return tuple(mutated)


# ---- 启发式模糊测试引擎 ----
class AdversarialFuzzer:
    """以 MR 违反数为适应度的启发式模糊测试器。

    搜索策略: 爬山 + 随机重启 + MR类别引导变异
      - 从种子输入出发，生成 N 个变异体 (随机+引导混合)
      - 选适应度最高的变异体作为下一轮起点
      - 连续 plateau_limit 轮无改进 → 随机重启
      - 引导: 当前轮违反的MR类别用于选择下一轮变异算子

    适应度函数:
      fitness(input) = count of violated MRs
    """

    def __init__(self, max_iterations: int = 200,
                 restarts: int = 5,
                 mutants_per_round: int = 8,
                 plateau_limit: int = 12):
        self.max_iterations = max_iterations
        self.restarts = restarts
        self.mutants_per_round = mutants_per_round
        self.plateau_limit = plateau_limit

    def fuzz(self, fn: Callable, fc: _FuncContract,
             seed_inputs: list[tuple] = None) -> AdversarialFuzzResult:
        """对单个函数执行对抗性模糊测试。

        fn: 待测函数
        fc: 函数契约
        seed_inputs: 初始种子输入集；None 时自动生成边界值种子
        """
        # 加载蜕变关系
        relations = self._load_relations(fc)
        if not relations:
            return AdversarialFuzzResult(func_name=fc.name)

        seeds = list(seed_inputs) if seed_inputs else self._default_seeds(fc)
        if not seeds:
            return AdversarialFuzzResult(func_name=fc.name)

        result = AdversarialFuzzResult(func_name=fc.name)
        seen_inputs = set()          # 去重: 已评估过的输入
        best_global_fitness = 0
        plateau_counter = 0

        for restart_idx in range(self.restarts):
            current = _random.choice(seeds)
            current_fitness = self._evaluate(fn, relations, current, seen_inputs)

            if current_fitness > 0:
                self._record_violations(fn, relations, current, result)

            best_local = current_fitness
            local_plateau = 0
            result.seeds_tried += 1

            iters_this_restart = self.max_iterations // self.restarts
            for _ in range(iters_this_restart):
                result.iterations += 1

                # 生成变异体
                best_mutant = None
                best_mutant_fit = -1

                for _ in range(self.mutants_per_round):
                    # 70%随机变异 + 30%MR引导变异
                    import random as _rnd2
                    if _rnd2.random() < 0.3 and current_fitness > 0:
                        violated_cats = self._violated_categories(
                            fn, relations, current)
                        mutant = _mutate_tuple_guided(current, violated_cats)
                    else:
                        mutant = _mutate_tuple(current)
                    mhash = self._hash_input(mutant)
                    if mhash in seen_inputs:
                        continue
                    fit = self._evaluate(fn, relations, mutant, seen_inputs)
                    if fit > best_mutant_fit:
                        best_mutant_fit = fit
                        best_mutant = mutant

                if best_mutant is None:
                    local_plateau += 1
                elif best_mutant_fit > current_fitness:
                    current = best_mutant
                    current_fitness = best_mutant_fit
                    local_plateau = 0

                    if best_mutant_fit > 0:
                        self._record_violations(fn, relations, best_mutant, result)
                else:
                    local_plateau += 1

                if current_fitness > best_global_fitness:
                    best_global_fitness = current_fitness
                    plateau_counter = 0
                    result.best_fitness = best_global_fitness
                else:
                    plateau_counter += 1

                if local_plateau >= self.plateau_limit:
                    break

            if plateau_counter >= self.plateau_limit * 2:
                break

        result.total_mr_violations = len(result.counterexamples)
        # 去重反例: 同 MR 类别 + 同输入哈希 → 保留一个
        result.counterexamples = self._dedup_counterexamples(result.counterexamples)
        return result

    def _evaluate(self, fn: Callable, relations: list,
                  args: tuple, seen: set) -> int:
        """对给定输入评估适应度（违反的 MR 数量）。"""
        seen.add(self._hash_input(args))
        violations = 0
        for mr in relations:
            try:
                orig = fn(*args)
                trans_args = mr.input_transform(args)
                trans = fn(*trans_args)
                if not mr.output_predicate(orig, trans):
                    violations += 1
            except (NotImplementedError, TypeError, ValueError, OverflowError):
                # 不可执行的输入不计入违反
                pass
            except Exception:
                # 其他异常视为该 MR 无法评估
                pass
        return violations

    @staticmethod
    def _violated_categories(fn: Callable, relations: list,
                             args: tuple) -> list[str]:
        """返回当前输入违反的MR类别列表，用于引导变异。"""
        cats = []
        for mr in relations:
            try:
                orig = fn(*args)
                trans_args = mr.input_transform(args)
                trans = fn(*trans_args)
                if not mr.output_predicate(orig, trans):
                    cats.append(mr.category)
            except Exception:
                pass
        return cats

    def _record_violations(self, fn: Callable, relations: list,
                           args: tuple, result: AdversarialFuzzResult) -> None:
        """记录当前输入触发的所有 MR 违反。"""
        for mr in relations:
            try:
                orig = fn(*args)
                trans_args = mr.input_transform(args)
                trans = fn(*trans_args)
                if not mr.output_predicate(orig, trans):
                    result.counterexamples.append(FuzzCounterexample(
                        func_name=result.func_name,
                        mr_category=mr.category,
                        mr_description=mr.description,
                        adversarial_input=args,
                        transformed_input=trans_args,
                        original_output=orig,
                        transformed_output=trans,
                        fitness=0,
                    ))
            except Exception:
                pass

    # ---- 辅助 ----
    @staticmethod
    def _load_relations(fc: _FuncContract) -> list:
        try:
            from modules.stubs.stub_metamorphic_verifier import MetamorphicVerifier
            return MetamorphicVerifier().get_relations(fc)
        except ImportError:
            return []

    @staticmethod
    def _default_seeds(fc: _FuncContract) -> list[tuple]:
        """生成默认种子: 边界值 + 随机值。"""
        import re
        params = [p for p in fc.params if p.kind not in ('varargs', 'varkw')]
        if not params:
            return [()]

        def base_type(ann: str) -> str:
            m = re.match(r'([a-z_][a-z0-9_]*)', (ann or '').strip().lower())
            return m.group(1) if m else ''

        edge_map = {
            'int': [0, 1, -1, 2**31 - 1, -(2**31)],
            'float': [0.0, 1.0, -1.0, float('inf'), float('-inf')],
            'str': ['', 'A', 'A' * 256],
            'bytes': [b'', b'\x00', b'\xff' * 128],
            'bool': [False, True],
            'list': [[], [0]],
            'dict': [{}, {'k': 'v'}],
        }

        # 构造 3-5 个种子
        seeds = []
        for param_idx, _ in enumerate(params):
            base = base_type(params[param_idx].annotation)
            vals = edge_map.get(base, [None])
            for v_choice in vals[:3]:
                seed_list = [edge_map.get(base_type(p.annotation), [None])[0]
                            for p in params]
                seed_list[param_idx] = v_choice
                seeds.append(tuple(seed_list))
                if len(seeds) >= 5:
                    break
            if len(seeds) >= 5:
                break

        return seeds[:5] if seeds else [()]

    @staticmethod
    def _hash_input(args: tuple) -> int:
        try:
            return hash(args)
        except TypeError:
            return hash(str(args))

    @staticmethod
    def _dedup_counterexamples(ces: list[FuzzCounterexample]) -> list[FuzzCounterexample]:
        seen = set()
        unique = []
        for ce in ces:
            key = (ce.mr_category, ce.adversarial_input[:3]
                   if len(ce.adversarial_input) > 3 else ce.adversarial_input)
            if key not in seen:
                seen.add(key)
                unique.append(ce)
        return unique


# ---- 便捷入口 ----
def fuzz_contract(fn: Callable, fc: _FuncContract,
                  max_iter: int = 200) -> AdversarialFuzzResult:
    """一行式对抗性模糊测试。"""
    return AdversarialFuzzer(max_iterations=max_iter).fuzz(fn, fc)


__all__ = [
    'FuzzCounterexample', 'AdversarialFuzzResult',
    'AdversarialFuzzer', 'fuzz_contract',
]
