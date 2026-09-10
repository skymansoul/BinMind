# stub_strategy_predictor.py — 实现策略成功预测
# 从历史实现尝试中学习，预测给定桩合约用哪种策略最可能成功。
# 不依赖深度学习，使用轻量特征工程 + 加权评分，
# 适合"冷数据"场景（历史记录少，无需 GPU）。
#
# 方法:
#   1. 从 ProvenanceChain 提取历史 (特征, 策略, 成功/失败) 三元组
#   2. 特征: func_count, has_high_complexity, type_annotation_coverage,
#      has_compat_target, dependency_depth, contract_merkle_root_age
#   3. 对每条策略计算加权得分:
#      score(s, f) = Σ w_i × similarity(f, success_cases_of_s)
#      其中 similarity 用归一化欧氏距离
#   4. 输出按得分排序的策略列表 + 最高分策略的预估成功率
import math as _math
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt


@_dc
class StubFeatures:
    """一个桩模块的特征向量（用于策略匹配）。"""
    module_name: str
    func_count: int = 0
    high_complexity_ratio: float = 0.0    # high 复杂度函数占比
    type_annotation_coverage: float = 0.0  # 有类型注解的参数占比
    has_compat_target: bool = False
    dependency_depth: int = 0             # 拓扑深度
    param_count_mean: float = 0.0         # 平均参数数
    is_re_export: bool = False            # 纯转发桩
    status_code: int = 0                  # 实现状态编码


@_dc
class StrategyPrediction:
    """一次策略预测的结果。"""
    module_name: str
    features: StubFeatures
    # 各策略的预测得分
    scores: dict = _field(default_factory=dict)   # {strategy: score}
    # 推荐顺序
    recommended_order: list = _field(default_factory=list)
    # 最优策略的预估成功率 (0~1)
    best_confidence: float = 0.0
    # 是否建议跳过所有自动策略（人工实现）
    recommend_manual: bool = False


class StrategyPredictor:
    """基于历史数据的策略成功预测器。

    从 ProvenanceChain 加载历史记录，提取特征与结果，
    对新的 StubFeatures 做加权 KNN 风格评分。

    若无历史数据，返回基于启发式的默认预测:
      - 简单桩 (≤2 funcs, 高注解覆盖) → template 优先
      - 复杂桩 (≥4 funcs, 低注解覆盖) → LLM 优先（若有）
      - re_export → 跳过自动实现
    """

    def __init__(self, provenance_chain=None):
        if provenance_chain is not None:
            self.pchain = provenance_chain
        else:
            try:
                from modules.stubs.stub_provenance_chain import ProvenanceChain
                self.pchain = ProvenanceChain()
            except ImportError:
                self.pchain = None
        self._history: list[tuple[StubFeatures, str, bool]] = []

    def _load_history(self) -> None:
        """从溯源链加载历史 (特征, 策略, 成功) 三元组。"""
        if self._history:
            return
        if self.pchain is None:
            return
        # 遍历所有已记录的模块
        for module_name in list(getattr(self.pchain, '_chains', {})):
            for entry in self.pchain.history(module_name):
                features = self._extract_features(module_name)
                if features is not None:
                    self._history.append(
                        (features, entry.strategy, entry.verification_ok))

    def predict(self, module_name: str,
                contract=None) -> StrategyPrediction:
        """预测指定模块的最佳实现策略。"""
        features = self._extract_features(module_name, contract)
        if features is None:
            return StrategyPrediction(
                module_name=module_name,
                features=StubFeatures(module_name=module_name),
                recommend_manual=True)

        self._load_history()

        if not self._history:
            return self._heuristic_predict(features)

        # 按策略分组历史成功案例
        successes = {}
        totals = {}
        for hist_f, strat, ok in self._history:
            totals[strat] = totals.get(strat, 0) + 1
            if ok:
                successes.setdefault(strat, []).append(hist_f)

        scores = {}
        for strat in totals:
            if strat not in successes:
                scores[strat] = 0.0
                continue
            # 计算特征向量与成功案例的加权相似度
            sims = [self._feature_similarity(features, sf)
                   for sf in successes[strat]]
            if not sims:
                scores[strat] = 0.0
                continue
            # 得分 = top-k 平均相似度 × 该策略历史成功率
            k = min(3, len(sims))
            top_k = sorted(sims, reverse=True)[:k]
            avg_sim = sum(top_k) / k
            success_rate = len(successes[strat]) / totals[strat]
            scores[strat] = avg_sim * success_rate

        # 排序
        ordered = sorted(scores, key=lambda s: -scores[s])
        best_conf = scores[ordered[0]] if ordered else 0.0

        # 判定: 最优分 < 0.3 → 建议人工实现
        recommend_manual = best_conf < 0.3 and features.func_count > 0

        return StrategyPrediction(
            module_name=module_name,
            features=features,
            scores={s: round(v, 3) for s, v in scores.items()},
            recommended_order=ordered,
            best_confidence=round(best_conf, 3),
            recommend_manual=recommend_manual,
        )

    def _extract_features(self, module_name: str,
                          contract=None) -> _Opt[StubFeatures]:
        """从模块合约中提取特征向量。"""
        if contract is None:
            try:
                from modules.stubs.stub_contract import get_contractor
                contract = get_contractor().get(module_name)
            except Exception:
                return None

        if contract is None:
            return None

        feats = StubFeatures(module_name=module_name)
        feats.func_count = len(contract.functions)
        feats.has_compat_target = contract.has_compat_target

        high_count = sum(1 for f in contract.functions
                        if f.complexity == 'high')
        feats.high_complexity_ratio = (high_count / max(feats.func_count, 1))

        total_params = sum(len(f.params) for f in contract.functions)
        annotated = sum(
            sum(1 for p in f.params if p.annotation and p.annotation.strip())
            for f in contract.functions)
        feats.type_annotation_coverage = (
            annotated / max(total_params, 1))

        feats.param_count_mean = total_params / max(feats.func_count, 1)
        feats.is_re_export = (contract.status == 're_export')

        # 状态编码
        status_map = {'missing': 0, 'placeholder': 1, 'unparseable': 2,
                     're_export': 3, 'mixed': 4, 'implemented': 5}
        feats.status_code = status_map.get(contract.status, -1)

        # 依赖深度（从依赖图获取）
        try:
            from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
            g = ModuleDependencyGraph()
            g.build()
            node = g.nodes.get(module_name)
            if node is not None:
                feats.dependency_depth = node.topo_depth
        except ImportError:
            pass

        return feats

    @staticmethod
    def _feature_similarity(a: StubFeatures, b: StubFeatures) -> float:
        """计算两个特征向量的归一化相似度 (0~1)。

        用加权欧氏距离的倒数: sim = 1/(1 + weighted_l2)
        """
        feats = [
            ('func_count', 0.15, 10.0),
            ('high_complexity_ratio', 0.20, 1.0),
            ('type_annotation_coverage', 0.25, 1.0),
            ('param_count_mean', 0.15, 5.0),
            ('dependency_depth', 0.10, 5.0),
            ('status_code', 0.05, 5.0),
        ]

        # 离散特征的独立处理
        w2 = 0.0
        if a.has_compat_target != b.has_compat_target:
            w2 += 0.05
        if a.is_re_export != b.is_re_export:
            w2 += 0.05

        for attr, weight, scale in feats:
            va = getattr(a, attr)
            vb = getattr(b, attr)
            diff = (va - vb) / max(scale, 0.01)
            w2 += weight * diff * diff

        return 1.0 / (1.0 + _math.sqrt(w2))

    @staticmethod
    def _heuristic_predict(features: StubFeatures) -> StrategyPrediction:
        """无历史数据时的启发式预测。"""
        scores = {}
        ordered = []

        if features.is_re_export:
            scores = {'template': 0.1, 'llm': 0.05}
            ordered = []
            return StrategyPrediction(
                module_name=features.module_name, features=features,
                scores=scores, recommended_order=ordered,
                best_confidence=0.0, recommend_manual=True)

        if features.func_count <= 2 and features.type_annotation_coverage > 0.5:
            scores['template'] = 0.8
            scores['llm'] = 0.4
            ordered = ['template', 'llm']
        elif features.func_count >= 4 or features.high_complexity_ratio > 0.3:
            scores['llm'] = 0.65
            scores['template'] = 0.35
            ordered = ['llm', 'template']
        else:
            scores['template'] = 0.55
            scores['llm'] = 0.5
            ordered = ['template', 'llm']

        best_conf = scores[ordered[0]] if ordered else 0.0
        return StrategyPrediction(
            module_name=features.module_name, features=features,
            scores=scores, recommended_order=ordered,
            best_confidence=round(best_conf, 3),
            recommend_manual=best_conf < 0.3,
        )


__all__ = ['StubFeatures', 'StrategyPrediction', 'StrategyPredictor']
