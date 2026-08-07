# stub_metamorphic_verifier.py — 蜕变关系执行引擎
# 从 stub_metamorphic_oracle 加载合成的关系，
# 对已实现函数执行蜕变测试并报告语义异常。
#
# 与 MetamorphicSynthesizer 的关系:
#   Synthesizer 负责推导（从签名到关系），本模块负责执行（从关系到判定）。
#   分离原因: 合成是纯符号计算（无副作用），执行涉及函数调用与异常处理，
#   两者的错误模型和资源边界不同。
import itertools as _it
from typing import Optional as _Opt, Callable

from modules.stubs.stub_contract import FuncContract as _FuncContract
from modules.stubs.stub_metamorphic_oracle import (
    MetamorphicRelation,
    MetamorphicSynthesizer,
)


class MetamorphicVerifier:
    """基于蜕变关系的增强契约验证。

    在标准 ContractVerifier 的"签名核对 + IO 类型检查"之上，
    增加蜕变关系测试。每条 MR 使用构造的边界输入执行，
    验证变换前后输出满足预期谓词。

    MR 验证非精确: 单次失败不推翻合约（MR 可能为假），
    但连续失败或大面积违反高置信度 MR → 信号不可忽略 —
    该信号在 stub_gradual_engine 的验证回溯闭环中用作降级判据。
    """

    def __init__(self, synthesizer: _Opt[MetamorphicSynthesizer] = None):
        self.synthesizer = synthesizer or MetamorphicSynthesizer()
        self._cache: dict[str, list[MetamorphicRelation]] = {}

    def get_relations(self, fc: _FuncContract) -> list[MetamorphicRelation]:
        key = f'{fc.name}:{fc.return_ann}:{len(fc.params)}'
        if key not in self._cache:
            self._cache[key] = self.synthesizer.synthesize(fc)
        return self._cache[key]

    def verify(self, fn, fc: _FuncContract,
               input_gen: Callable = None) -> dict:
        """对函数执行蜕变关系验证。

        fn: 实际可调用函数对象
        fc: 对应的契约定义
        input_gen: 可选，输入生成器；默认使用边界值

        返回: {status, relations_tested, test_cases_per_relation,
                anomalies, results}
        """
        relations = self.get_relations(fc)
        if not relations:
            return {'status': 'no_relations', 'results': {}}

        test_inputs = self._gen_test_inputs(fc, input_gen)
        results = {}

        for mr in relations:
            mr_result = {'passed': 0, 'total': 0, 'violations': []}
            for args in test_inputs:
                try:
                    orig_out = fn(*args)
                    transformed_args = mr.input_transform(args)
                    trans_out = fn(*transformed_args)
                    if mr.output_predicate(orig_out, trans_out):
                        mr_result['passed'] += 1
                    else:
                        mr_result['violations'].append({
                            'input': self._safe_repr(args),
                            'transformed_input': self._safe_repr(transformed_args),
                            'orig_output': self._safe_repr(orig_out),
                            'transformed_output': self._safe_repr(trans_out),
                        })
                    mr_result['total'] += 1
                except NotImplementedError:
                    # 未实现的桩函数 — 终止该 MR 测试，不能无限等待
                    break
                except Exception:
                    # 调用异常视为测试用例执行（不计入通过，但计入 total）
                    mr_result['total'] += 1
            results[mr.category] = mr_result

        anomalies = self._detect_anomalies(results, relations)

        return {
            'status': 'anomalies_found' if anomalies else 'passed',
            'relations_tested': len(relations),
            'test_cases_per_relation': len(test_inputs),
            'anomalies': anomalies,
            'results': results,
        }

    @staticmethod
    def _detect_anomalies(results: dict, relations: list) -> list[dict]:
        """>50% 失败率且 MR 置信度 >0.6 → 语义异常。"""
        anomalies = []
        for cat, r in results.items():
            if r['total'] == 0:
                continue
            fail_rate = (r['total'] - r['passed']) / r['total']
            mr_conf = next((m.confidence for m in relations
                          if m.category == cat), 0.5)
            if fail_rate > 0.5 and mr_conf > 0.6:
                anomalies.append({
                    'category': cat,
                    'fail_rate': round(fail_rate, 3),
                    'confidence': mr_conf,
                })
        return anomalies

# 测试输入生成
    def _gen_test_inputs(self, fc: _FuncContract,
                         custom_gen: Callable = None) -> list[tuple]:
        """为蜕变测试构造输入组合。

        策略: 每个参数取 2~3 个代表性值，参数少时取笛卡尔积，
        参数多时取默认组合 + 逐参数变体。上限 12 组。
        """
        if custom_gen is not None:
            return custom_gen(fc)

        params = [p for p in fc.params if p.kind not in ('varargs', 'varkw')]
        if not params:
            return [()]

        candidates = []
        for p in params:
            base = self.synthesizer._simple_base(p.annotation)
            candidates.append(self._representative_values(base))

        max_combos = 12
        combo_count = 1
        for c in candidates:
            combo_count *= len(c)

        if combo_count <= max_combos:
            return [t for t in _it.product(*candidates)][:max_combos]

        # 超限: 基准 + 逐参数变体
        inputs = []
        defaults = tuple(c[0] for c in candidates)
        inputs.append(defaults)
        for i, c_vals in enumerate(candidates):
            for v in c_vals[1:]:
                variant = list(defaults)
                variant[i] = v
                inputs.append(tuple(variant))
                if len(inputs) >= max_combos:
                    break
            if len(inputs) >= max_combos:
                break
        return inputs[:max_combos]

    @staticmethod
    def _representative_values(base_type: str) -> list:
        table = {
            'int':   [0, 42, -1],
            'float': [0.0, 3.14, -1.0],
            'str':   ['', 'test', 'hello world'],
            'bytes': [b'', b'test', b'\x00\xff'],
            'bool':  [False, True],
            'list':  [[], [1], [1, 2, 3]],
            'dict':  [{}, {'k': 'v'}],
            'set':   [set(), {1}],
            'tuple': [(), (1,)],
        }
        return table.get(base_type, [None])

    @staticmethod
    def _safe_repr(obj) -> str:
        try:
            s = repr(obj)
            return s[:120] + '...' if len(s) > 120 else s
        except Exception:
            return '<unrepresentable>'


__all__ = ['MetamorphicVerifier']
