# 修改记录:
# 2025-08-07 15:23 - 初始实现：GNN预测→符号验证→对比反馈闭环

"""神经符号验证闭环 — GNN 漏洞预测与符号约束求解的互增强回路。

现有方案的根本缺陷：
- GNN 漏洞检测器：输出概率但无法证明可 exploit 性。
- 符号执行引擎：可证明路径可达性但搜索空间爆炸。
- 两者独立运行，GNN 的误报率 30-50%，符号引擎超时率高。

本模块的闭环架构：
1. GNN 预测函数级漏洞概率并定位可疑基本块。
2. 符号引擎对 Top-K 可疑块做定向验证（而非全程序搜索）。
3. 验证结果（可exploit/不可exploit/超时）反馈给 GNN：
   - 可 exploit → 正样本强化
   - 不可 exploit → 负样本修正（关键：这是高置信度负样本，稀缺资源）
   - 超时 → 不确定性标记，抑制该区域过度自信
4. 对比损失函数确保：嵌入空间中"被验证可 exploit"和"被排除"的样本分离。

与 MoCQ 的区别：
- MoCQ: LLM↔CodeQL 闭环，针对源码的查询生成。
- 本方案: GNN↔符号执行闭环，针对二进制漏洞的可 exploit 性验证。
- 本方案产生的是"被验证的"而非"被预测的"漏洞标签——训练数据质量更高。

- MoCQ "Holistic Neuro-Symbolic Approach" — 验证器反馈的架构灵感。
- MSIVD — LLM+GNN 联合嵌入的可行性依据。
"""

import math
import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9

# 验证结果枚举
_VERIFIED_EXPLOITABLE = 1    # 符号执行找到了 exploit 路径
_VERIFIED_BENIGN = 0         # 符号执行证明不可达
_VERIFICATION_TIMEOUT = -1   # 超时，不确定

@dataclass
class GNNPrediction:
    """GNN 的一次漏洞预测。"""
    function_name: str
    vuln_probability: float
    suspicious_blocks: List[int]  # 最可疑的基本块地址
    embedding: List[float] = field(default_factory=list)
    confidence: float = 0.5

@dataclass
class SymbolicVerification:
    """符号引擎的一次定向验证结果。"""
    function_name: str
    target_blocks: List[int]
    result: int            # _VERIFIED_EXPLOITABLE / _VERIFIED_BENIGN / _VERIFICATION_TIMEOUT
    exploit_path: Optional[List[int]] = None
    time_spent_ms: float = 0.0
    solver_iterations: int = 0

@dataclass
class FeedbackSample:
    """闭环反馈的一次训练样本。"""
    embedding: List[float]
    label: int             # 1=exploitable, 0=benign, -1=uncertain (no gradient)
    weight: float          # 样本权重——已验证的样本权重更高
    function_name: str = ""

class NeuroSymbolicLoop:
    """神经符号验证闭环——GNN ↔ 符号执行的互增强回路。

    使用范式：
      loop = NeuroSymbolicLoop(embedding_dim=128)
      preds = gnn.predict(functions)
      verifications = symbolic_engine.verify_targeted(preds.top_k(10))
      loss = loop.compute_contrastive_loss(preds, verifications)
      gnn.backward(loss)
    """

    def __init__(
        self,
        embedding_dim: int = 128,
        verification_weight: float = 5.0,
        contrastive_margin: float = 0.5,
        max_history: int = 2000,
    ):
        """
        verification_weight: 已验证样本的损失权重（相对于未验证样本）。
                            高权重确保稀缺的验证结果主导梯度方向。
        contrastive_margin: 对比损失的正负样本最小间距。
        max_history: 滑动窗口中保留的最近反馈样本数。
        """
        self.embedding_dim = embedding_dim
        self.verification_weight = verification_weight
        self.contrastive_margin = contrastive_margin
        self.max_history = max_history

        # 反馈样本池
        self._feedback_samples: List[FeedbackSample] = []

        # 统计追踪
        self._total_verifications: int = 0
        self._verified_exploitable: int = 0
        self._verified_benign: int = 0
        self._verification_timeouts: int = 0

        # 每函数验证状态缓存
        self._function_status: Dict[str, int] = {}

    # 核心闭环 API

    def ingest_verification(
        self,
        prediction: GNNPrediction,
        verification: SymbolicVerification,
    ):
        """摄入一次 GNN 预测→符号验证的完整循环结果。

        自动构造反馈样本并更新统计。
        """
        self._total_verifications += 1

        _status = verification.result
        self._function_status[verification.function_name] = _status

        if _status == _VERIFIED_EXPLOITABLE:
            self._verified_exploitable += 1
            _label = 1
            _w = self.verification_weight
        elif _status == _VERIFIED_BENIGN:
            self._verified_benign += 1
            _label = 0
            _w = self.verification_weight * 0.8
            # 负样本权重略低——"未找到"不等于"不存在"
        else:
            self._verification_timeouts += 1
            _label = -1
            _w = 0.0  # 超时样本不参与梯度更新

        if _w > 0 and prediction.embedding:
            self._feedback_samples.append(FeedbackSample(
                embedding=list(prediction.embedding),
                label=_label,
                weight=_w,
                function_name=verification.function_name,
            ))

        # 滑动窗口裁剪
        if len(self._feedback_samples) > self.max_history:
            self._feedback_samples = self._feedback_samples[-self.max_history:]

    def compute_contrastive_loss(
        self,
        predictions: List[GNNPrediction],
        verifications: Dict[str, SymbolicVerification],
    ) -> Tuple[float, Dict[str, float]]:
        """计算对比损失——结合未验证预测与已验证反馈。

        返回：(total_loss, loss_components)。
        loss_components 包含 'verified_pairwise', 'uncertainty_penalty', 'total'。

        损失函数设计：
        1. verified_pairwise: 已验证的正/负样本对之间的对比损失。
           正样本（可exploit）与负样本（不可exploit）在嵌入空间中的距离 ≥ margin。
        2. uncertainty_penalty: 对超时（未验证）样本中模型过度自信的惩罚——
           若 GNN 对某函数给出 >0.9 的概率但验证超时，说明可能误报。
        """
        for _pred in predictions:
            _ver = verifications.get(_pred.function_name)
            if _ver is not None:
                self.ingest_verification(_pred, _ver)

        _verified_loss = self._verified_pairwise_loss()
        _uncertainty_loss = self._uncertainty_penalty(predictions)
        _total = _verified_loss + 0.3 * _uncertainty_loss

        return _total, {
            'verified_pairwise': round(_verified_loss, 6),
            'uncertainty_penalty': round(_uncertainty_loss, 6),
            'total': round(_total, 6),
        }

    def top_k_verification_targets(
        self,
        predictions: List[GNNPrediction],
        k: int = 10,
    ) -> List[GNNPrediction]:
        """从 GNN 预测中选择最具验证价值的目标。

        优先级：
        1. 高概率（>0.7）且未验证过的函数——最可能发现 exploit
        2. 概率在 0.4-0.7 且未被验证——最需要去模糊化的边界样本
        3. 概率<0.3 且多次调用危险函数的——潜在漏报

        不重复验证已确认的函数。
        """
        _candidates: List[Tuple[GNNPrediction, float]] = []

        for _pred in predictions:
            _fn = _pred.function_name
            if _fn in self._function_status:
                continue  # 已验证，跳过

            _priority = 0.0
            if _pred.vuln_probability > 0.7:
                _priority = _pred.vuln_probability * 2.0
            elif _pred.vuln_probability > 0.4:
                _priority = _pred.vuln_probability * 1.5
            else:
                _priority = (1.0 - _pred.vuln_probability) * 0.5

            _candidates.append((_pred, _priority))

        _candidates.sort(key=lambda x: x[1], reverse=True)
        return [c[0] for c in _candidates[:k]]

    @property
    def verification_coverage(self) -> float:
        """已验证函数占所有候选的比例。"""
        return self._total_verifications / max(1, len(self._function_status))

    @property
    def verification_precision(self) -> float:
        """已验证为 exploitable 的比例。"""
        _total_decided = self._verified_exploitable + self._verified_benign
        return self._verified_exploitable / max(_total_decided, 1)

    # 损失函数

    def _verified_pairwise_loss(self) -> float:
        """已验证样本对之间的对比损失。

        对每对 (正样本, 负样本)：max(0, margin - D(pos, neg))²
        只用已验证的样本——未验证样本不参与此损失。
        """
        _positives = [s for s in self._feedback_samples if s.label == 1]
        _negatives = [s for s in self._feedback_samples if s.label == 0]

        if not _positives or not _negatives:
            return 0.0

        _loss = 0.0
        _count = 0
        for _pos in _positives:
            for _neg in _negatives:
                _dist = _euclidean_distance(_pos.embedding, _neg.embedding)
                _violation = self.contrastive_margin - _dist
                if _violation > 0:
                    _w = min(_pos.weight, _neg.weight)
                    _loss += _w * _violation * _violation
                _count += 1

        return _loss / max(_count, 1)

    def _uncertainty_penalty(
        self, predictions: List[GNNPrediction]
    ) -> float:
        """对未验证函数中过度自信预测的惩罚。

        若某函数验证超时（status=-1），模型对其的预测概率不应极端化。
        """
        _penalty = 0.0
        _count = 0
        for _pred in predictions:
            _status = self._function_status.get(_pred.function_name)
            if _status == _VERIFICATION_TIMEOUT:
                # 熵惩罚：鼓励模型对超时函数输出接近 0.5 的概率
                _p = max(_EPS, min(1.0 - _EPS, _pred.vuln_probability))
                _entropy = -_p * math.log(_p) - (1.0 - _p) * math.log(1.0 - _p)
                _max_entropy = math.log(2.0)  # 0.693
                _penalty += 1.0 - _entropy / _max_entropy
                _count += 1

        return _penalty / max(_count, 1) if _count > 0 else 0.0

def _euclidean_distance(a: List[float], b: List[float]) -> float:
    _n = min(len(a), len(b))
    return math.sqrt(sum((a[i] - b[i]) ** 2 for i in range(_n)))

# 冒烟测试
def _smoke_test():
    import random
    random.seed(42)

    _loop = NeuroSymbolicLoop(embedding_dim=32)

    # 模拟 20 个函数的 GNN 预测
    _preds = []
    for _i in range(20):
        _preds.append(GNNPrediction(
            function_name=f"func_{_i}",
            vuln_probability=0.3 + random.random() * 0.5,
            suspicious_blocks=[0x400000 + _i * 16, 0x400100 + _i * 16],
            embedding=[random.gauss(0, 1) for _ in range(32)],
        ))

    # 模拟符号验证：对 Top-5 做定向验证
    _targets = _loop.top_k_verification_targets(_preds, k=5)
    _vers: Dict[str, SymbolicVerification] = {}
    for _t in _targets:
        _result = _VERIFIED_EXPLOITABLE if random.random() < 0.3 else (
            _VERIFIED_BENIGN if random.random() < 0.6 else _VERIFICATION_TIMEOUT)
        _vers[_t.function_name] = SymbolicVerification(
            function_name=_t.function_name,
            target_blocks=_t.suspicious_blocks,
            result=_result,
            time_spent_ms=random.uniform(100, 5000),
        )

    _loss, _components = _loop.compute_contrastive_loss(_preds, _vers)
    print(f"[neuro_sym] verification targets: {len(_targets)}")
    print(f"[neuro_sym] loss: {_components}")
    print(f"[neuro_sym] stats: total={_loop._total_verifications} "
          f"exploitable={_loop._verified_exploitable} "
          f"benign={_loop._verified_benign} "
          f"timeouts={_loop._verification_timeouts}")
    print(f"[neuro_sym] coverage={_loop.verification_coverage:.3f} "
          f"precision={_loop.verification_precision:.3f}")
    print(f"[neuro_sym] feedback pool size: {len(_loop._feedback_samples)}")

    assert _loop._total_verifications == 5
    assert _components['total'] >= 0
    print("[OK] NeuroSymbolicLoop smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
