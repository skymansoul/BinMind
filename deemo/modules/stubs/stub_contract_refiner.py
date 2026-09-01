# stub_contract_refiner.py — 运行时类型观测驱动的贝叶斯契约精化
# 在桩模块被调用时观测实参/返回值类型，用 Dirichlet-分类分布模型
# 更新对各可能类型的信念，置信度足够时向下游契约写入精化后的类型注解。
#
# 问题背景:
#   桩模块普遍以宽松类型标注（Any、无标注、Optional[...]）起步。
#   运行时观测可提供"实际被怎么用"的地面真相，但单次观测有噪声。
#   需要一种在观测累积后逐步收窄类型的不确定性量化机制。
#
# 方法:
#   1. 每个参数/返回位置维护一个 Dirichlet(α₁,...,αₖ) 先验，
#      类别 = {int, str, bytes, float, bool, list, dict, set, tuple, NoneType, other}
#   2. 每次调用观测到具体类型后，α_c += 1（后验更新）。
#   3. 当 max(posterior_mean) > confidence_threshold 时，
#      输出精化类型注解（单一类型或 Union）。
#   4. 精化结果以保守合并策略写回 StubContract：
#      若原注解为 Any → 替换为精化注解；
#      若原注解为 Optional[X] → 仅在 X 兼容时保留 Optional 包装。
#
# 区别于 RunTyper:
# 不做深度学习推断，纯概率更新。
# 在线运行（每次调用即更新），无需离线 trace 收集阶段。
# 与 StubGradual 的渐进实现闭环紧耦合 —— 精化后的合约
#     直接改善下轮 TemplateGenerator 的代码生成质量。
from collections import defaultdict as _dd
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    StubContract as _StubContract,
    FuncContract as _FuncContract,
    ParamSpec as _ParamSpec,
)


# 类型观测类别
# 可观测的 11 类基础类型，覆盖 Python 桩模块中 >95% 的实际类型使用。
_TYPE_CATEGORIES = [
    'int', 'str', 'bytes', 'float', 'bool',
    'list', 'dict', 'set', 'tuple',
    'NoneType', 'other',
]

_TYPE_TO_CAT = {
    int: 'int', str: 'str', bytes: 'bytes', float: 'float', bool: 'bool',
    list: 'list', dict: 'dict', set: 'set', tuple: 'tuple',
    type(None): 'NoneType',
}


def _classify(value: object) -> str:
    """将运行时值映射到类型类别。"""
    return _TYPE_TO_CAT.get(type(value), 'other')


# 贝叶斯类型模型
@_dc
class BayesianTypeBelief:
    """单个参数位置（或返回位置）的 Dirichlet-分类信念。

    alpha 向量: 每个类型类别的伪计数。
    初始值 α₀ = prior_strength * prior_probs[c]。
    默认先验: 均匀（无偏好），prior_strength=1（弱先验，数据主导）。
    """

    position: str = ''            # 参数名或 '__return__'
    alphas: list = _field(default_factory=lambda: [1.0] * len(_TYPE_CATEGORIES))
    prior_strength: float = 1.0   # 先验等效样本量
    total_observations: int = 0
    # 精化阈值: 后验均值最高类需超过此值才输出精化类型
    confidence_threshold: float = 0.75

    def observe(self, value: object) -> None:
        """记录一次类型观测: α[cat] += 1。"""
        cat = _classify(value)
        idx = _TYPE_CATEGORIES.index(cat)
        self.alphas[idx] += 1.0
        self.total_observations += 1

    def posterior_means(self) -> list[float]:
        """Dirichlet 后验均值: α_i / Σα_j。"""
        total = sum(self.alphas)
        if total <= 0:
            return [1.0 / len(self.alphas)] * len(self.alphas)
        return [a / total for a in self.alphas]

    def is_confident(self) -> bool:
        """后验是否足够集中以输出精化类型。"""
        return max(self.posterior_means()) >= self.confidence_threshold

    def refined_type(self) -> str:
        """基于当前后验输出精化类型注解字符串。

        规则:
          - NoneType 单独 > threshold → 'None'（罕见但合法）
          - 最高类为主类型；次高类若 > 0.10 → Union[主, 次]
          - NoneType 占比显著 → 包装为 Optional
          - other 类忽略（不纳入输出）
        """
        means = self.posterior_means()
        ranked = sorted(
            [(means[i], _TYPE_CATEGORIES[i]) for i in range(len(means))
             if _TYPE_CATEGORIES[i] != 'other'],
            key=lambda x: -x[0],
        )

        if not ranked:
            return 'Any'

        top_prob, top_cat = ranked[0]
        if top_cat == 'NoneType' and top_prob >= 0.9:
            return 'None'

        # 构建输出类型列表
        components = []
        none_prob = 0.0

        for prob, cat in ranked:
            if cat == 'NoneType':
                none_prob = prob
                continue
            if prob >= 0.10:
                components.append(cat)
            elif prob >= 0.05 and len(components) == 0:
                # 主类型未达 0.10 但无其他候选 — 使用最高
                components.append(cat)

        if not components and none_prob > 0:
            return 'None'

        if not components:
            return 'Any'

        if len(components) == 1:
            base = components[0]
            return f'Optional[{base}]' if none_prob >= 0.10 else base

        # Union
        union_str = ', '.join(components)
        return f'Optional[Union[{union_str}]]' if none_prob >= 0.10 else f'Union[{union_str}]'

    def merge_with_annotation(self, original_ann: str) -> str:
        """将精化类型与原注解合并，保留原注解中的语义信息。

        合并策略:
          - 原注解为 '' 或 'Any' → 直接用精化类型
          - 原注解以 Optional 开头 → 保留 Optional 包装
          - 其余: 优先原注解（精化为建议性，非强制性覆盖）
        """
        if not original_ann or original_ann.strip().lower() in ('', 'any'):
            return self.refined_type()

        refined = self.refined_type()
        if refined == 'Any':
            return original_ann

        ann_lower = original_ann.strip().lower()
        if ann_lower.startswith('optional['):
            # 原注解已是 Optional，保留包装语义
            if refined.startswith('Optional['):
                return refined
            return f'Optional[{refined}]'

        # 原注解更具体时保留
        return refined

    def snapshot(self) -> dict:
        return {
            'position': self.position,
            'alphas': list(self.alphas),
            'total_observations': self.total_observations,
            'refined_type': self.refined_type(),
        }

    @classmethod
    def from_snapshot(cls, data: dict) -> 'BayesianTypeBelief':
        belief = cls(position=data.get('position', ''))
        belief.alphas = data.get('alphas', [1.0] * len(_TYPE_CATEGORIES))
        belief.total_observations = data.get('total_observations', 0)
        return belief


# 契约精化器
class ContractRefiner:
    """观测驱动的合约精化管道。

    维护每个模块-函数-参数位置的 BayesianTypeBelief。
    每次 record_observation() 调用触发贝叶斯更新；
    当某位置的信念足够集中时，refine_contract() 输出精化后的合约。
    """

    def __init__(self, confidence_threshold: float = 0.75):
        self.confidence_threshold = confidence_threshold
        # {(module_name, func_name, param_name_or_return): BayesianTypeBelief}
        self._beliefs: dict[tuple, BayesianTypeBelief] = {}
        self._pending_refinements: dict[str, dict] = _dd(dict)

    def record_observation(self, module_name: str, func_name: str,
                           args: tuple, kwargs: dict, result: object) -> None:
        """从一次函数调用中记录所有参数与返回值的类型观测。

        args/kwargs: 传入的实参（按位置和关键字）
        result: 函数返回值
        """
        contract = self._get_contract(module_name)
        if contract is None:
            return

        fc = next((f for f in contract.functions if f.name == func_name), None)
        if fc is None:
            return

        # 记录每个参数的类型
        params = [p for p in fc.params if p.kind not in ('varargs', 'varkw')]
        for i, p in enumerate(params):
            if i < len(args):
                key = (module_name, func_name, p.name)
                self._get_belief(key, p.name).observe(args[i])
            elif p.name in kwargs:
                key = (module_name, func_name, p.name)
                self._get_belief(key, p.name).observe(kwargs[p.name])

        # 记录返回类型
        ret_key = (module_name, func_name, '__return__')
        self._get_belief(ret_key, '__return__').observe(result)

    def _get_belief(self, key: tuple, position: str) -> BayesianTypeBelief:
        if key not in self._beliefs:
            self._beliefs[key] = BayesianTypeBelief(
                position=position,
                confidence_threshold=self.confidence_threshold,
            )
        return self._beliefs[key]

    @staticmethod
    def _get_contract(module_name: str) -> _Opt[_StubContract]:
        """获取模块契约（防御性懒加载）。"""
        try:
            from modules.stubs.stub_contract import get_contractor
            return get_contractor().get(module_name)
        except Exception:
            return None

    def refine_contract(self, module_name: str) -> _Opt[_StubContract]:
        """对指定模块输出精化后的契约（不修改原契约，返回新对象）。

        精化条件: 至少 5 次观测 + 后验置信度达标。
        返回 None 表示无任何可精化位置。
        """
        contract = self._get_contract(module_name)
        if contract is None:
            return None

        refined = False
        for fc in contract.functions:
            for p in fc.params:
                if p.kind in ('varargs', 'varkw'):
                    continue
                key = (module_name, fc.name, p.name)
                belief = self._beliefs.get(key)
                if belief is None or belief.total_observations < 5:
                    continue
                if belief.is_confident():
                    new_ann = belief.merge_with_annotation(p.annotation)
                    if new_ann != p.annotation:
                        p.annotation = new_ann
                        refined = True

            # 精化返回注解
            ret_key = (module_name, fc.name, '__return__')
            ret_belief = self._beliefs.get(ret_key)
            if ret_belief is not None and ret_belief.total_observations >= 5:
                if ret_belief.is_confident():
                    new_ret = ret_belief.merge_with_annotation(fc.return_ann)
                    if new_ret != fc.return_ann:
                        fc.return_ann = new_ret
                        refined = True

        return contract if refined else None

    def refinement_report(self, module_name: str) -> dict:
        """生成该模块的类型精化可读报告。"""
        contract = self._get_contract(module_name)
        report = {'module_name': module_name, 'refinements': []}
        if contract is None:
            return report

        for fc in contract.functions:
            for p in fc.params:
                if p.kind in ('varargs', 'varkw'):
                    continue
                key = (module_name, fc.name, p.name)
                belief = self._beliefs.get(key)
                if belief is None:
                    continue
                report['refinements'].append({
                    'function': fc.name,
                    'param': p.name,
                    'original': p.annotation or '(none)',
                    'refined': belief.refined_type(),
                    'observations': belief.total_observations,
                    'confidence': round(max(belief.posterior_means()), 3),
                    'type_distribution': {
                        _TYPE_CATEGORIES[i]: round(v, 3)
                        for i, v in enumerate(belief.posterior_means())
                        if v > 0.01
                    },
                })

            ret_key = (module_name, fc.name, '__return__')
            ret_belief = self._beliefs.get(ret_key)
            if ret_belief is not None:
                report['refinements'].append({
                    'function': fc.name,
                    'param': '(return)',
                    'original': fc.return_ann or '(none)',
                    'refined': ret_belief.refined_type(),
                    'observations': ret_belief.total_observations,
                    'confidence': round(max(ret_belief.posterior_means()), 3),
                    'type_distribution': {
                        _TYPE_CATEGORIES[i]: round(v, 3)
                        for i, v in enumerate(ret_belief.posterior_means())
                        if v > 0.01
                    },
                })

        return report

    def all_beliefs(self) -> dict:
        """导出全部信念状态（序列化用）。"""
        return {
            f'{mod}.{func}.{pos}': b.snapshot()
            for (mod, func, pos), b in self._beliefs.items()
        }

    def load_beliefs(self, data: dict) -> None:
        """从序列化快照恢复信念状态。"""
        for key_str, snap in data.items():
            parts = key_str.rsplit('.', 2)
            if len(parts) == 3:
                mod, func, pos = parts
                self._beliefs[(mod, func, pos)] = BayesianTypeBelief.from_snapshot(snap)


# 观测装饰器
# 轻量观测钩子，可直接装饰桩模块中的函数。
class ObserveAndRefine:
    """透明的调用观测包装器。

    用法:
        refiner = ContractRefiner()
        wrapped = ObserveAndRefine(refiner, 'my_module', 'my_func')(original_fn)
        result = wrapped(arg1, arg2)  # 自动记录类型观测
    """

    def __init__(self, refiner: ContractRefiner, module_name: str, func_name: str):
        self.refiner = refiner
        self.module_name = module_name
        self.func_name = func_name

    def __call__(self, fn):
        import functools as _ft

        @_ft.wraps(fn)
        def wrapper(*args, **kwargs):
            result = fn(*args, **kwargs)
            self.refiner.record_observation(
                self.module_name, self.func_name, args, kwargs, result)
            return result

        return wrapper


__all__ = [
    'BayesianTypeBelief', 'ContractRefiner', 'ObserveAndRefine',
]
