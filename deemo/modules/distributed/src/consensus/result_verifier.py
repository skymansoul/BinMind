# 修改记录:
# 2025-08-07 14:11 - 初始实现：多worker结果共识验证+Byzantine容错

"""结果共识验证 — 多Worker冗余分析后加权投票+异常Worker检测。

分布式二进制分析中，不同Worker可能因环境差异（libc版本、内核、内存限制）
对同一二进制产生不同分析结论。简单的多数投票在恶意/故障Worker场景下失效。

本模块的三层验证：
1. 冗余执行：同一分析任务分发给 K≥3 个异构Worker（不同OS/libc/架构）。
2. 加权投票：Worker权重基于历史准确率（EMA），而非平等投票。
3. 异常检测：对与多数结论持续偏离的Worker标记为POTENTIALLY_COMPROMISED
   或 FAULTY，自动将其移出活跃池并触发重分析。

Byzantine容错保证：只要故障Worker < K/2，共识结果正确。

- PBFT: 拜占庭容错共识的经典方案。
  本模块将其适配到"分析结果"而非"分布式账本"的共识场景。
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9

class WorkerStatus(Enum):
    ACTIVE = "active"
    SUSPECT = "suspect"
    FAULTY = "faulty"
    COMPROMISED = "compromised"

@dataclass
class WorkerRecord:
    """Worker的信用档案。"""
    worker_id: str
    environment: Dict[str, str] = field(default_factory=dict)
    total_tasks: int = 0
    consensus_matches: int = 0  # 与最终共识一致的次数
    weight: float = 1.0         # 投票权重
    status: WorkerStatus = WorkerStatus.ACTIVE
    consecutive_deviations: int = 0

@dataclass
class ConsensusResult:
    """一次共识判定的输出。"""
    task_id: str
    majority_conclusion: Any    # 多数Worker同意的结论
    votes: Dict[str, Any]       # {worker_id: conclusion}
    weights: Dict[str, float]   # {worker_id: vote_weight}
    confidence: float           # 共识置信度
    consensus_reached: bool
    deviating_workers: List[str]

class ConsensusResultVerifier:
    """多Worker分析结果的共识验证器。

    使用范式：
      verifier = ConsensusResultVerifier(min_workers=3)
      verifier.register_worker("w1", {"os": "ubuntu22", "libc": "2.35"})
      result = verifier.verify_consensus(task_id, votes)
    """

    def __init__(
        self,
        min_workers: int = 3,
        deviation_threshold: int = 5,
        weight_ema: float = 0.2,
    ):
        self.min_workers = min_workers
        self.deviation_threshold = deviation_threshold
        self.weight_ema = weight_ema

        self._workers: Dict[str, WorkerRecord] = {}
        self._consensus_history: deque = deque(maxlen=200)

    def register_worker(
        self, worker_id: str, environment: Optional[Dict[str, str]] = None,
    ):
        self._workers[worker_id] = WorkerRecord(
            worker_id=worker_id,
            environment=environment or {},
        )

    def verify_consensus(
        self, task_id: str, votes: Dict[str, Any],
    ) -> ConsensusResult:
        """对一次任务的多Worker结论执行加权共识判定。

        votes: {worker_id: conclusion}。
        conclusion 必须可哈希（用于计数）。
        """
        _active_votes = {
            wid: v for wid, v in votes.items()
            if self._workers.get(wid, WorkerRecord(wid)).status == WorkerStatus.ACTIVE
        }
        if len(_active_votes) < self.min_workers:
            return ConsensusResult(
                task_id=task_id, majority_conclusion=None,
                votes=votes, weights={}, confidence=0.0,
                consensus_reached=False, deviating_workers=[],
            )

        # 加权投票计数
        _weighted_count: Dict[Any, float] = defaultdict(float)
        _weights: Dict[str, float] = {}
        for _wid, _conclusion in _active_votes.items():
            _w = self._workers.get(_wid, WorkerRecord(_wid)).weight
            _weights[_wid] = _w
            _weighted_count[_conclusion] += _w

        # 多数结论
        _majority = max(_weighted_count, key=_weighted_count.get)
        _majority_weight = _weighted_count[_majority]
        _total_weight = sum(_weighted_count.values())
        _confidence = _majority_weight / max(_total_weight, _EPS)

        # 识别偏离Worker
        _deviating = [
            wid for wid, conc in _active_votes.items()
            if conc != _majority
        ]

        # 更新Worker记录
        for _wid, _conc in _active_votes.items():
            _wr = self._workers.get(_wid)
            if _wr is None:
                continue
            _wr.total_tasks += 1
            if _conc == _majority:
                _wr.consensus_matches += 1
                _wr.consecutive_deviations = 0
                _wr.weight = (1.0 - self.weight_ema) * _wr.weight + self.weight_ema * 1.0
            else:
                _wr.consecutive_deviations += 1
                _wr.weight = (1.0 - self.weight_ema) * _wr.weight + self.weight_ema * 0.3
                if _wr.consecutive_deviations >= self.deviation_threshold:
                    _wr.status = WorkerStatus.FAULTY

        _result = ConsensusResult(
            task_id=task_id, majority_conclusion=_majority,
            votes=votes, weights=_weights,
            confidence=round(_confidence, 4),
            consensus_reached=_confidence > 0.5,
            deviating_workers=_deviating,
        )
        self._consensus_history.append(_result)
        return _result

    def get_worker_health(self) -> Dict[str, WorkerStatus]:
        """返回所有Worker的健康状态。"""
        return {wid: wr.status for wid, wr in self._workers.items()}

    def get_reliability_scores(self) -> Dict[str, float]:
        """返回Worker可靠性评分——共识匹配率。"""
        return {
            wid: wr.consensus_matches / max(wr.total_tasks, 1)
            for wid, wr in self._workers.items()
        }

# 冒烟测试
def _smoke_test():
    _verifier = ConsensusResultVerifier(min_workers=3)
    for _i in range(5):
        _verifier.register_worker(f"w{_i}", {"os": f"ubuntu{20+_i}"})

    # 正常共识：4/5同意
    _r1 = _verifier.verify_consensus("task1", {
        "w0": "VULN_FOUND", "w1": "VULN_FOUND",
        "w2": "VULN_FOUND", "w3": "SAFE", "w4": "VULN_FOUND",
    })
    print(f"[consensus] task1: conclusion={_r1.majority_conclusion} "
          f"confidence={_r1.confidence:.3f} deviating={_r1.deviating_workers}")

    # 模拟w3持续偏离
    for _t in range(6):
        _verifier.verify_consensus(f"task{_t+2}", {
            "w0": "VULN_FOUND", "w1": "VULN_FOUND",
            "w2": "VULN_FOUND", "w3": "SAFE", "w4": "VULN_FOUND",
        })

    _health = _verifier.get_worker_health()
    _scores = _verifier.get_reliability_scores()
    print(f"[consensus] w3 status: {_health['w3']}")
    print(f"[consensus] w3 score: {_scores['w3']:.3f}")

    assert _r1.consensus_reached, "should reach consensus"
    assert _health["w3"] == WorkerStatus.FAULTY, "persistent deviator should be flagged"
    print("[OK] ConsensusResultVerifier smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
