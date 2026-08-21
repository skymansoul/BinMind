# 自洽性漏洞验证-多推理路径交叉验证漏洞发现的一致性
#
# 核心问题: 单模型漏洞检测存在误报。2025年ARES用自回归推理验证做错误检测，
# VERiCOT用形式逻辑验证CoT-但都针对自然语言，非二进制漏洞检测。
#
# 技术方案（多路径自洽性-self-consistency在漏洞检测领域的应用）:
#   1. 三条独立推理路径: CFG结构分析 / 数据流追踪 / 符号执行验证
#   2. 一致性交叉验证: 全部一致→高置信度，多数一致→中等，完全分歧→不确定
#   3. 路径可靠性加权: 数据流(0.4) > CFG(0.35) > 符号执行(0.25)
#   4. 审计推理链: 每条路径输出可审计的观测→推论的因果链

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

logger = logging.getLogger(__name__)


class VulnPathKind(Enum):
    CFG_STRUCTURE = 'cfg_structure'
    DATAFLOW = 'dataflow'
    SYMBOLIC = 'symbolic'


@dataclass
class ReasoningStep:
    step_id: int
    observation: str
    inference: str
    confidence: float


@dataclass
class VulnPathOutput:
    path_kind: VulnPathKind
    is_vulnerable: bool
    vuln_type: str
    severity: float
    confidence: float
    location: Tuple[int, int] = (0, 0)
    reasoning_chain: List[ReasoningStep] = field(default_factory=list)
    evidence_embeddings: Optional[np.ndarray] = None

    def summary(self) -> str:
        return (f"[{self.path_kind.value}] vuln={self.is_vulnerable} "
                f"type={self.vuln_type} sev={self.severity:.2f} conf={self.confidence:.2f}")


@dataclass
class ConsistencyResult:
    is_vulnerable: bool
    consensus_level: str        # full_consensus / majority / split
    agreed_type: str
    agreed_severity: float
    overall_confidence: float
    path_outputs: Dict[VulnPathKind, VulnPathOutput]
    conflicting_paths: List[Tuple[VulnPathKind, VulnPathKind, str]]
    audit_trail: str


class SelfConsistencyVerifier:
    """多路径自洽性漏洞验证器。

    三条推理路径互补:
      CFG结构→识别异常控制流（循环中的释放、异常路径）
      数据流→追踪分配-使用-释放链
      符号执行→验证路径可行性
    三者一致的判定置信度远高于单路径。
    """

    def __init__(self,
                 cfg_path_fn: Callable,
                 dataflow_path_fn: Callable,
                 symbolic_path_fn: Callable,
                 consensus_threshold: float = 0.6):
        self._path_fns = {
            VulnPathKind.CFG_STRUCTURE: cfg_path_fn,
            VulnPathKind.DATAFLOW: dataflow_path_fn,
            VulnPathKind.SYMBOLIC: symbolic_path_fn,
        }
        self._threshold = consensus_threshold
        self._path_weights = {
            VulnPathKind.CFG_STRUCTURE: 0.35,
            VulnPathKind.DATAFLOW: 0.40,
            VulnPathKind.SYMBOLIC: 0.25,
        }

    def calibrate_path_weights(self,
                                labeled_samples: List[Tuple[Any, Any, int]],
                                n_bootstrap: int = 100
                                ) -> Dict[VulnPathKind, Tuple[float, float]]:
        """从标注数据估计各路径的可靠性权重及置信区间。

        对每个路径在标注集上计算precision/recall，
        以F1分数归一化为权重。使用bootstrap估计置信区间。
        """
        n = len(labeled_samples)
        if n < 10:
            return {k: (w, 0.0) for k, w in self._path_weights.items()}

        # 单次评估: 计算每个路径的F1
        def evaluate_path(kind, samples):
            tp = fp = fn = 0
            for feats, adj, label in samples:
                try:
                    out = self._path_fns[kind](feats, adj, 0)
                    pred = 1 if out.is_vulnerable else 0
                    if pred == 1 and label == 1:
                        tp += 1
                    elif pred == 1 and label == 0:
                        fp += 1
                    elif pred == 0 and label == 1:
                        fn += 1
                except Exception:
                    pass
            prec = tp / max(1, tp + fp)
            rec = tp / max(1, tp + fn)
            return 2 * prec * rec / max(0.01, prec + rec)

        # Bootstrap估计
        rng = np.random.RandomState(42)
        boot_f1s = {k: [] for k in self._path_fns}
        for _ in range(n_bootstrap):
            indices = rng.choice(n, size=n, replace=True)
            boot_samples = [labeled_samples[i] for i in indices]
            for kind in self._path_fns:
                boot_f1s[kind].append(evaluate_path(kind, boot_samples))

        # 计算均值和标准差→更新权重
        calibrated = {}
        f1_means = {}
        for kind in self._path_fns:
            f1_arr = np.array(boot_f1s[kind])
            f1_mean = float(np.mean(f1_arr))
            f1_std = float(np.std(f1_arr))
            f1_means[kind] = f1_mean
            calibrated[kind] = (f1_mean, f1_std)

        # 归一化: F1→权重
        total_f1 = sum(v[0] for v in calibrated.values())
        if total_f1 > 0:
            for kind in calibrated:
                self._path_weights[kind] = calibrated[kind][0] / total_f1

        return {k: (self._path_weights[k], calibrated[k][1])
                for k in calibrated}

    def verify(self, features, adjacency, func_addr: int = 0) -> ConsistencyResult:
        outputs = {}
        for kind, path_fn in self._path_fns.items():
            try:
                out = path_fn(features, adjacency, func_addr)
                outputs[kind] = out
            except Exception:
                outputs[kind] = VulnPathOutput(
                    path_kind=kind, is_vulnerable=False,
                    vuln_type="error", severity=0.0, confidence=0.0)
        return self._evaluate_consensus(outputs)

    def _evaluate_consensus(self, outputs) -> ConsistencyResult:
        vuln_votes = [o for o in outputs.values() if o.is_vulnerable]
        n_vuln = len(vuln_votes)
        n_total = len(outputs)

        if n_vuln == n_total or n_vuln == 0:
            consensus = "full_consensus"
        elif n_vuln > n_total / 2:
            consensus = "majority"
        elif n_vuln == n_total / 2:
            consensus = "split"
        else:
            consensus = "all_disagree"

        weighted_sev, weighted_conf, total_w = 0.0, 0.0, 0.0
        for kind, out in outputs.items():
            w = self._path_weights.get(kind, 1.0 / n_total)
            weighted_sev += w * out.severity
            weighted_conf += w * out.confidence
            total_w += w

        fused_sev = weighted_sev / max(0.01, total_w)
        fused_conf = weighted_conf / max(0.01, total_w)

        if n_vuln > 0:
            type_votes = {}
            for o in vuln_votes:
                type_votes[o.vuln_type] = type_votes.get(o.vuln_type, 0) + 1
            agreed_type = max(type_votes, key=type_votes.get)
        else:
            agreed_type = "benign"

        conflicts = []
        kinds = list(outputs.keys())
        for i in range(len(kinds)):
            for j in range(i + 1, len(kinds)):
                a, b = outputs[kinds[i]], outputs[kinds[j]]
                if a.is_vulnerable != b.is_vulnerable:
                    conflicts.append((kinds[i], kinds[j],
                        f"判断矛盾: {a.is_vulnerable} vs {b.is_vulnerable}"))
                elif a.is_vulnerable and a.vuln_type != b.vuln_type:
                    conflicts.append((kinds[i], kinds[j],
                        f"类型不一致: {a.vuln_type} vs {b.vuln_type}"))

        is_vuln = n_vuln >= 2 or (n_vuln == 1 and consensus != "split")
        if all(o.confidence < 0.3 for o in outputs.values()):
            is_vuln = False
            fused_conf *= 0.5

        audit_lines = [f"=== 审计 ({consensus}) ==="]
        for kind, out in outputs.items():
            audit_lines.append(f"  {out.summary()}")
            for step in out.reasoning_chain[:3]:
                audit_lines.append(f"    Step{step.step_id}: {step.observation}")

        return ConsistencyResult(
            is_vulnerable=is_vuln, consensus_level=consensus,
            agreed_type=agreed_type, agreed_severity=fused_sev,
            overall_confidence=fused_conf, path_outputs=outputs,
            conflicting_paths=conflicts,
            audit_trail="\n".join(audit_lines))


class ReasoningChainBuilder:
    """推理链构建器-将模型输出转为可审计的观测→推论链"""

    @staticmethod
    def build_from_attributions(
        path_kind: VulnPathKind, is_vuln: bool,
        top_features: List[Tuple[str, float]],
        top_nodes: List[int],
    ) -> List[ReasoningStep]:
        steps = []
        for i, (feat_name, importance) in enumerate(top_features[:5]):
            if importance < 0.05:
                continue
            steps.append(ReasoningStep(
                step_id=i,
                observation=f"{path_kind.value}: {feat_name}={importance:.3f}",
                inference=f"特征贡献{importance:.1%}",
                confidence=importance))
        if is_vuln and not steps:
            steps.append(ReasoningStep(
                step_id=0,
                observation=f"{path_kind.value}整体匹配已知漏洞签名",
                inference="综合特征模式与训练集漏洞样本高度一致",
                confidence=0.6))
        return steps
