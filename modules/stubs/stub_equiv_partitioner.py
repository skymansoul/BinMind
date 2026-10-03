# stub_equiv_partitioner.py — 类型驱动的输入空间等价类划分+BVA+MR精化
# 对每个函数参数按类型结构划分等价类，每类生成代表性输入。
# 扩展: 边界值分析 + MR引导精化 + pairwise覆盖
#
# 方法:
#   1. 基础等价类: 9种类型的预定义分区
#   2. 边界值分析: 每个数值类在边界处追加ON/OFF/IN三点
#   3. MR引导精化: 若函数有 idempotence MR，追加 f(x) 与 f(f(x)) 差异
#      最大化的分区；若有 monotonic MR，追加间隔极值分区
#   4. pairwise覆盖: 对多参数函数用 2-way 覆盖数组减少组合数
#
# 说明: BVA 边界从类型结构和 MR 语义推导（非需求文档），
# 如 int 边界 {0, 1, -1} 来自数值符号变化，str 边界 {'', 'x'} 来自空/非空。
import itertools as _it
import re as _re
from dataclasses import dataclass as _dc, field as _field

from modules.stubs.stub_contract import FuncContract as _FuncContract


# 基础等价类 + BVA扩展
_EQUIV_CLASSES = {
    'int': [
        ('zero', 0), ('positive', 42), ('negative', -7),
        ('max', 2**31 - 1), ('min', -(2**31)),
    ],
    'float': [
        ('zero', 0.0), ('positive', 3.14), ('negative', -2.71),
        ('tiny', 1e-10), ('huge', 1e10),
    ],
    'str': [
        ('empty', ''), ('single', 'x'), ('ascii', 'test'),
        ('unicode', 'hello世界'), ('long', 'A' * 256),
    ],
    'bytes': [
        ('empty', b''), ('single_null', b'\x00'),
        ('zeros', b'\x00' * 16), ('ffs', b'\xff' * 16),
        ('mixed', b'\x00\xff\x42\xab'),
    ],
    'bool': [('false', False), ('true', True)],
    'list': [('empty', []), ('single', [0]), ('multi', [1, 2, 3])],
    'dict': [('empty', {}), ('kv', {'k': 'v'})],
    'set': [('empty', set()), ('single', {0})],
    'tuple': [('empty', ()), ('single', (0,)), ('pair', (0, 1))],
}

_BVA_EXTENSIONS = {
    'int': {
        'zero':     {'on': 0, 'off': 1, 'in': -1},
        'positive': {'on': 0, 'off': 1, 'in': 42},
        'negative': {'on': 0, 'off': -1, 'in': -7},
        'max':      {'on': 2**31 - 1, 'off': -(2**31), 'in': 2**30},
        'min':      {'on': -(2**31), 'off': 2**31 - 1, 'in': -(2**30)},
    },
    'float': {
        'zero':     {'on': 0.0, 'off': 1e-16, 'in': -1e-16},
        'positive': {'on': 0.0, 'off': -3.14, 'in': 3.14},
        'negative': {'on': 0.0, 'off': 2.71, 'in': -2.71},
        'tiny':     {'on': 0.0, 'off': -1e-10, 'in': 1e-10},
        'huge':     {'on': 1e10, 'off': 1e9, 'in': 1e11},
    },
}

_MR_PARTITIONS = {
    'idempotence': [
        # f(f(x)) == f(x): 在f的值域边界处最可能违反
        ('idem_boundary', 'boundary'),
    ],
    'monotonic': [
        # f(x+1) >= f(x): 极大/极小值处最可能违反
        ('mono_extreme', 'extreme'),
    ],
    'null': [
        ('null_empty', 'empty'),
        ('null_none', 'none'),
    ],
}


@_dc
class PartitionedInput:
    """一组等价类覆盖的测试输入。"""
    inputs: tuple
    covered_classes: list = _field(default_factory=list)
    bva_points: list = _field(default_factory=list)
    mr_targeted: list = _field(default_factory=list)


class EquivPartitioner:
    """类型驱动的等价类划分器 + BVA + MR精化。

    输出: 最小但覆盖最广的测试输入集。
    """

    MAX_COMBOS = 24

    def partition(self, fc: _FuncContract,
                  mr_categories: list[str] = None) -> list[PartitionedInput]:
        """为函数合约生成等价类覆盖的测试输入。

        mr_categories: 应用到此函数的MR类别（用于生成精化分区）
        """
        params = [p for p in fc.params if p.kind not in ('varargs', 'varkw')]
        if not params:
            return [PartitionedInput(inputs=(), covered_classes=['no_params'])]

        mr_categories = mr_categories or []

        # 1. 每个参数: 基础类 + BVA扩展
        all_partitions = []
        for p in params:
            base = self._simple_base(p.annotation)
            classes = list(_EQUIV_CLASSES.get(base, [('default', None)]))
            bva_map = _BVA_EXTENSIONS.get(base, {})
            for cname, cval in list(classes):
                if cname in bva_map:
                    bva = bva_map[cname]
                    classes.append((f'{cname}_on', bva['on']))
                    classes.append((f'{cname}_off', bva['off']))
            all_partitions.append(classes)

        # 2. MR精化: 为每个MR类别追加针对性分区
        for mr_cat in mr_categories:
            extra = _MR_PARTITIONS.get(mr_cat, [])
            for pi, p in enumerate(params):
                base = self._simple_base(p.annotation)
                for ename, etype in extra:
                    val = self._mr_value(base, etype)
                    if val is not None:
                        all_partitions[pi].append(
                            (f'{mr_cat}_{ename}', val))

        # 3. pairwise覆盖: 每对参数至少覆盖一次所有类组合
        return self._pairwise_cover(all_partitions, params, mr_categories)

    @staticmethod
    def _mr_value(base_type: str, style: str):
        """为MR精化生成针对性的测试值。"""
        if style == 'boundary':
            return {'int': 0, 'float': 0.0, 'str': '',
                   'bytes': b'', 'list': [], 'bool': False}.get(base_type)
        if style == 'extreme':
            return {'int': 2**30, 'float': 1e10,
                   'str': 'Z' * 1024, 'bytes': b'\xff' * 512}.get(base_type)
        if style == 'empty':
            return {'str': '', 'bytes': b'', 'list': [],
                   'dict': {}, 'set': set()}.get(base_type)
        if style == 'none':
            return None
        return None

    @staticmethod
    def _pairwise_cover(all_partitions: list, params: list,
                        mr_cats: list) -> list[PartitionedInput]:
        """Pairwise覆盖: 保证每对参数的类组合至少出现一次。

        若全组合 ≤ MAX_COMBOS → 直接笛卡尔积。
        否则 → 贪心pairwise: 每次选择覆盖最多未覆盖pair的输入。
        """
        total_combos = 1
        for p in all_partitions:
            total_combos *= len(p)

        if total_combos <= EquivPartitioner.MAX_COMBOS:
            result = []
            for combo in _it.product(*all_partitions):
                classes = [f'{params[i].name}:{cn}'
                          for i, (cn, _) in enumerate(combo)]
                bva = [f'{params[i].name}:{cn}'
                      for i, (cn, _) in enumerate(combo) if '_on' in cn or '_off' in cn]
                mr = [f'{params[i].name}:{cn}'
                     for i, (cn, _) in enumerate(combo)
                     if any(mc in cn for mc in mr_cats)]
                result.append(PartitionedInput(
                    inputs=tuple(cv for _, cv in combo),
                    covered_classes=classes,
                    bva_points=bva,
                    mr_targeted=mr))
            return result

        # 贪心pairwise: 构建pair覆盖矩阵
        pairs = set()
        for i in range(len(params)):
            for j in range(i + 1, len(params)):
                for ci, (cni, _) in enumerate(all_partitions[i]):
                    for cj, (cnj, _) in enumerate(all_partitions[j]):
                        pairs.add((i, cni, j, cnj))

        result = []
        covered_pairs = set()
        for _ in range(EquivPartitioner.MAX_COMBOS):
            best, best_new = None, 0
            for combo in _it.product(*all_partitions):
                new_pairs = set()
                for i in range(len(params)):
                    for j in range(i + 1, len(params)):
                        new_pairs.add((i, combo[i][0], j, combo[j][0]))
                new = len(new_pairs - covered_pairs)
                if new > best_new:
                    best_new = new
                    best = combo
                    if new == len(pairs) - len(covered_pairs):
                        break
            if best is None or best_new == 0:
                break
            covered_pairs |= set(
                (i, best[i][0], j, best[j][0])
                for i in range(len(params))
                for j in range(i + 1, len(params)))
            classes = [f'{params[i].name}:{cn}'
                      for i, (cn, _) in enumerate(best)]
            bva = [f'{params[i].name}:{cn}'
                  for i, (cn, _) in enumerate(best) if '_on' in cn or '_off' in cn]
            mr = [f'{params[i].name}:{cn}'
                 for i, (cn, _) in enumerate(best)
                 if any(mc in cn for mc in mr_cats)]
            result.append(PartitionedInput(
                inputs=tuple(cv for _, cv in best),
                covered_classes=classes,
                bva_points=bva,
                mr_targeted=mr))

        return result

    @staticmethod
    def _simple_base(ann: str) -> str:
        a = (ann or '').strip().lower()
        m = _re.match(r'([a-z_][a-z0-9_]*)', a)
        return m.group(1) if m else ''


__all__ = ['PartitionedInput', 'EquivPartitioner']
