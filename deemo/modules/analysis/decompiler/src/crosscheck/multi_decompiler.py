# 修改记录:
# 2025-08-07 11:08 - 初始实现：多反编译器输出交叉验证+分歧投票

"""多反编译器交叉验证 — Ghidra/IDA/R2三引擎输出对比+不一致检测。

单一反编译器存在系统性偏差：
- Ghidra: 对C++异常处理重构偏弱。
- IDA Pro: 对混淆代码的常量传播可能过度激进。
- R2: 对大型switch表的跳转表解析不稳定。

当三个独立实现的反编译器对同一代码段产生不同输出时——
分歧本身就是信息。它告诉我们"此处不应盲目信任任一输出"。

本模块的方案——三引擎交叉验证：
1. 对每个函数收集三个反编译器的输出。
2. 逐函数比较: CFG结构(Jaccard)、变量数量、函数调用集。
3. 三个引擎一致→高置信。两个一致一个分歧→中等置信+分歧标注。
   三个各自不同→低置信→标记为"需人工审查"。
4. 为每个引擎维护历史准确率(EMA)，用于加权多数表决。

参考：
- decompiler_validator.py: 单反编译器输出与真实源码的比较验证。
- 本模块: 多反编译器之间的交叉验证——不依赖源码ground truth。
"""

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


class ConsensusLevel(Enum):
    FULL = "full"           # 三引擎一致
    MAJORITY = "majority"   # 二对一
    DIVERGENT = "divergent" # 三个全不同


@dataclass
class DecompOutput:
    """一个反编译器对一个函数的输出摘要。"""
    engine: str           # "ghidra" / "ida" / "r2"
    function_name: str
    function_address: int
    # 可比较的特征
    cfg_edge_count: int
    var_count: int
    call_targets: FrozenSet[str]
    branch_count: int
    has_return: bool
    # 引擎特定置信度
    engine_confidence: float = 0.5


@dataclass
class CrossCheckResult:
    """多引擎交叉验证的输出。"""
    function_name: str
    consensus: ConsensusLevel
    agreement_matrix: Dict[str, float]  # {(engine_a, engine_b): similarity}
    best_engine: str
    divergent_engine: str = ""
    recommendation: str = ""


class MultiDecompilerCrossCheck:
    """多反编译器交叉验证器。"""

    def __init__(self):
        # 引擎准确率追踪
        self._engine_scores: Dict[str, float] = defaultdict(lambda: 0.5)
        self._engine_counts: Dict[str, int] = defaultdict(int)

    def cross_check(
        self, outputs: List[DecompOutput],
    ) -> CrossCheckResult:
        """对多个反编译器输出执行交叉验证。"""
        if len(outputs) < 2:
            return CrossCheckResult(
                function_name=outputs[0].function_name if outputs else "",
                consensus=ConsensusLevel.DIVERGENT,
                agreement_matrix={},
                best_engine="",
                recommendation="need at least 2 engines",
            )

        # 成对相似度计算
        _engine_outputs = {o.engine: o for o in outputs}
        _similarities: Dict[Tuple[str, str], float] = {}

        _engines = list(_engine_outputs.keys())
        for _i in range(len(_engines)):
            for _j in range(_i + 1, len(_engines)):
                _a = _engine_outputs[_engines[_i]]
                _b = _engine_outputs[_engines[_j]]
                _sim = self._similarity(_a, _b)
                _similarities[(_engines[_i], _engines[_j])] = _sim

        _agreement = {
            f"{a}↔{b}": round(sim, 3)
            for (a, b), sim in _similarities.items()
        }

        # 判定共识级别
        _sim_values = list(_similarities.values())
        _high_pairs = sum(1 for s in _sim_values if s > 0.8)
        _mid_pairs = sum(1 for s in _sim_values if 0.5 < s <= 0.8)

        if len(_engines) >= 3:
            if _high_pairs == 3:
                _consensus = ConsensusLevel.FULL
            elif _high_pairs + _mid_pairs >= 2:
                _consensus = ConsensusLevel.MAJORITY
            else:
                _consensus = ConsensusLevel.DIVERGENT
        else:
            _consensus = (
                ConsensusLevel.FULL if _high_pairs >= 1
                else ConsensusLevel.DIVERGENT
            )

        # 找出最优引擎（与其他引擎平均相似度最高）
        _avg_sims: Dict[str, float] = {}
        for _eng in _engines:
            _sims = [
                s for (a, b), s in _similarities.items()
                if a == _eng or b == _eng
            ]
            _avg_sims[_eng] = sum(_sims) / max(len(_sims), 1) if _sims else 0.0

        _best_engine = max(_avg_sims, key=_avg_sims.get)
        _worst = min(_avg_sims, key=_avg_sims.get)

        # 推荐
        if _consensus == ConsensusLevel.FULL:
            _rec = "high confidence — all engines agree"
        elif _consensus == ConsensusLevel.MAJORITY:
            _rec = f"majority consensus — {_worst} output may have errors"
        else:
            _rec = f"all engines diverge — manual review required"

        return CrossCheckResult(
            function_name=outputs[0].function_name,
            consensus=_consensus,
            agreement_matrix=_agreement,
            best_engine=_best_engine,
            divergent_engine=_worst if _consensus != ConsensusLevel.FULL else "",
            recommendation=_rec,
        )

    def update_engine_accuracy(self, engine: str, was_correct: bool):
        """更新引擎准确率——用于后续加权。"""
        _ema = 0.2
        _prev = self._engine_scores[engine]
        self._engine_scores[engine] = (
            _ema * (1.0 if was_correct else 0.0) + (1 - _ema) * _prev
        )
        self._engine_counts[engine] += 1

    @staticmethod
    def _similarity(a: DecompOutput, b: DecompOutput) -> float:
        """计算两个反编译输出的结构相似度。"""
        _score = 0.0
        _total_weight = 0.0

        # CFG边数相似度
        _max_edges = max(a.cfg_edge_count, b.cfg_edge_count, 1)
        _score += 1.0 - abs(a.cfg_edge_count - b.cfg_edge_count) / _max_edges
        _total_weight += 1.0

        # 调用集Jaccard
        _a_calls = set(a.call_targets)
        _b_calls = set(b.call_targets)
        _union = _a_calls | _b_calls
        if _union:
            _score += len(_a_calls & _b_calls) / len(_union)
        else:
            _score += 1.0
        _total_weight += 1.0

        # 变量数相似度
        _max_vars = max(a.var_count, b.var_count, 1)
        _score += 1.0 - abs(a.var_count - b.var_count) / _max_vars
        _total_weight = 1.0 + 1.0 + 0.5

        return min(1.0, _score / _total_weight)


# ---- 冒烟测试 ----
def _smoke_test():
    _checker = MultiDecompilerCrossCheck()

    _outputs = [
        DecompOutput("ghidra", "decrypt_payload", 0x401000,
                     12, 5, frozenset({"malloc","memcpy","xor_loop"}), 3, True, 0.8),
        DecompOutput("ida", "decrypt_payload", 0x401000,
                     12, 5, frozenset({"malloc","memcpy","xor_loop"}), 3, True, 0.85),
        DecompOutput("r2", "decrypt_payload", 0x401000,
                     10, 4, frozenset({"malloc","xor","free"}), 2, True, 0.5),
    ]

    _result = _checker.cross_check(_outputs)
    print(f"[cross] consensus: {_result.consensus.value}")
    print(f"[cross] agreement: {_result.agreement_matrix}")
    print(f"[cross] best engine: {_result.best_engine}")
    print(f"[cross] recommendation: {_result.recommendation}")

    assert _result.consensus in (ConsensusLevel.MAJORITY, ConsensusLevel.FULL)
    print("[OK] MultiDecompilerCrossCheck smoke test passed.")


if __name__ == "__main__":
    _smoke_test()
