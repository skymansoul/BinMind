# 机器学习引导的符号执行 — 用学习到的模式指导符号执行路径选择
# 基于: SyML [Zotero: "Guiding Symbolic Execution Toward Vulnerable States Through Pattern Learning"]
# Learning to Explore Paths for Symbolic Execution [Zotero]
# 核心: 从已知漏洞中学习路径特征 → 预测新程序中可能存在漏洞的路径 → 优先探索

from __future__ import annotations
import re
import math
import hashlib
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class PathFeature:
    """路径特征 — 用于ML预测的路径表示"""
    length: int                          # 路径长度 (基本块数)
    branch_types: Dict[str, int]         # 分支类型计数
    api_calls: List[str]                 # 路径上的API调用
    memory_ops: int                      # 内存操作次数
    loop_depth: int                      # 最大循环深度
    has_tainted_input: bool              # 是否接触污点数据
    constraint_complexity: int            # 路径约束复杂度 (操作符数)

    def to_vector(self) -> List[float]:
        return [
            self.length / 100.0,
            sum(self.branch_types.values()) / 50.0,
            len(self.api_calls) / 20.0,
            self.memory_ops / 50.0,
            self.loop_depth / 10.0,
            1.0 if self.has_tainted_input else 0.0,
            self.constraint_complexity / 30.0,
        ]


class PathVulnerabilityPredictor:
    """路径漏洞预测器 — SyML风格的ML路径评分

    使用逻辑回归风格的特征加权, 评估每条路径到达漏洞状态的可能性。
    训练数据: 已知漏洞的路径特征 (正例) + 安全代码的路径特征 (负例)
    """

    def __init__(self, n_features: int = 7):
        self.n_feat = n_features
        # 特征权重 (从已知漏洞模式初始化)
        self.weights = [
            0.15,   # length: 长路径有更多交互
            0.30,   # branch_types: 复杂分支→更多边界情况
            0.35,   # api_calls: 危险API调用密度
            0.25,   # memory_ops: 内存操作→内存错误风险
            0.10,   # loop_depth: 深层循环→更复杂逻辑
            0.40,   # has_tainted_input: 污点数据
            0.20,   # constraint_complexity: 复杂约束→难测试
        ]
        self.bias = -0.5
        self._trained = False

    def predict_score(self, features: PathFeature) -> float:
        """预测路径的漏洞可能性分数 [0, 1]"""
        vec = features.to_vector()
        logit = sum(self.weights[i] * vec[i] for i in range(min(len(self.weights), len(vec))))
        logit += self.bias
        return 1.0 / (1.0 + math.exp(-logit))  # sigmoid

    def rank_paths(self, paths: List[PathFeature]) -> List[Tuple[int, float]]:
        """对路径按漏洞可能性排序"""
        scored = [(i, self.predict_score(p)) for i, p in enumerate(paths)]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def train_from_examples(self, positive_paths: List[PathFeature],
                            negative_paths: List[PathFeature],
                            learning_rate: float = 0.01, epochs: int = 50):
        """从正负例训练权重 (简化SGD)"""
        all_examples = [(p, 1.0) for p in positive_paths] + [(p, 0.0) for p in negative_paths]

        import random
        for ep in range(epochs):
            random.shuffle(all_examples)
            total_loss = 0.0
            for path, label in all_examples:
                pred = self.predict_score(path)
                error = pred - label
                total_loss += error ** 2

                vec = path.to_vector()
                for i in range(min(len(self.weights), len(vec))):
                    grad = error * pred * (1.0 - pred) * vec[i]
                    self.weights[i] -= learning_rate * grad
                self.bias -= learning_rate * error * pred * (1.0 - pred)

            if ep % 10 == 0:
                logger.debug(f"epoch {ep}: loss={total_loss/len(all_examples):.4f}")

        self._trained = True


class MLCoverageGuidedExplorer:
    """ML覆盖引导探索器

    将传统覆盖引导fuzzing与ML路径评分结合:
      1. SyML预测器为每条候选路径打分
      2. 高评分路径优先执行
      3. 执行结果反馈更新预测器
    """

    def __init__(self, predictor: PathVulnerabilityPredictor = None):
        self.predictor = predictor or PathVulnerabilityPredictor()
        self.exploration_history: List[Tuple[PathFeature, float, bool]] = []
        self.coverage_set: Set[int] = set()  # 已覆盖的地址哈希

    def select_next_path(self, candidate_paths: List[PathFeature],
                         top_k: int = 3) -> List[int]:
        """选择下一条要探索的路径 (SyML优先 + 覆盖多样性)"""
        if not candidate_paths:
            return []

        # ML评分
        scored = self.predictor.rank_paths(candidate_paths)

        # 多样性过滤: 去重相似路径
        selected = []
        seen_sigs = set()

        for idx, score in scored:
            path = candidate_paths[idx]
            # 简单路径指纹
            sig = hashlib.md5(
                f"{path.length}:{path.loop_depth}:{path.constraint_complexity}".encode()
            ).hexdigest()[:8]

            if sig not in seen_sigs:
                selected.append(idx)
                seen_sigs.add(sig)

            if len(selected) >= top_k:
                break

        return selected

    def record_exploration(self, path: PathFeature, score: float,
                           found_vuln: bool):
        """记录探索结果以改进未来预测"""
        self.exploration_history.append((path, score, found_vuln))

        # 在线学习: 如果发现漏洞, 强化类似路径的权重
        if found_vuln and len(self.exploration_history) >= 5:
            recent_positives = [p for p, s, v in self.exploration_history[-20:] if v]
            recent_negatives = [p for p, s, v in self.exploration_history[-20:] if not v]
            if recent_positives and recent_negatives:
                self.predictor.train_from_examples(
                    recent_positives, recent_negatives,
                    learning_rate=0.005, epochs=5)


def extract_path_features(basic_blocks: List[Dict],
                          api_calls: List[str] = None,
                          has_tainted: bool = False) -> PathFeature:
    """从基本块列表提取路径特征"""
    length = len(basic_blocks)
    branch_types = Counter()
    memory_count = 0
    max_loop = 0
    constraint_count = 0
    current_loop = 0

    for bb in basic_blocks:
        code = bb.get('code', '') if isinstance(bb, dict) else str(bb)

        for kw in ['je', 'jne', 'jg', 'jl', 'jge', 'jle', 'jb', 'ja',
                   'jbe', 'jae', 'jz', 'jnz', 'if', 'else', 'switch', 'case']:
            if kw in code.lower():
                branch_types[kw] += 1

        for kw in ['mov', 'lea', 'store', 'load', 'push', 'pop']:
            if kw in code.lower():
                memory_count += 1

        if 'loop' in code.lower() or 'for' in code.lower() or 'while' in code.lower():
            current_loop += 1
        if 'endloop' in code.lower() or '}' in code:
            current_loop = max(0, current_loop - 1)
        max_loop = max(max_loop, current_loop)

        constraint_count += len(re.findall(r'(==|!=|<|>|<=|>=|\+|-)', code))

    return PathFeature(
        length=length,
        branch_types=dict(branch_types),
        api_calls=api_calls or [],
        memory_ops=memory_count,
        loop_depth=max_loop,
        has_tainted_input=has_tainted,
        constraint_complexity=constraint_count,
    )


def create_syml_predictor() -> PathVulnerabilityPredictor:
    return PathVulnerabilityPredictor()
