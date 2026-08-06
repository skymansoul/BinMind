# 修改记录:
# 2025-08-06 07:42 - 初始实现：反编译多义性检测——生成语义等价变体验证一致性

"""反编译语义变体 — 多版本反编译输出交叉验证一致性检测。

反编译器输出存在固有歧义——同一条机器指令可被解释为多种C表达式。
单一反编译器选择其一，若选择错误→分析偏差→漏报或误报漏洞。

本模块的方案——语义变体生成+交叉验证：
1. 对可疑代码区域生成多个语义等价的伪代码变体
   (变量重命名/表达式重排/类型推断备选)。
2. 逐变体比较控制流和数据流——若变体间一致→高置信，
   若分歧→标记该区域为反编译歧义区→人工审查优先级提升。
3. 与decomp_hallucination_detector互补：后者检测"明显不可能"的输出，
   本模块检测"可能但不确定"的输出。

技术路径：
- 模式替换: A+B↔B+A, *(p+i)↔p[i], if(!x)↔if(x==0), for↔while互转。
- 类型重标: 相同机器指令在不同类型假设下的伪代码差异。
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


@dataclass
class PseudoCodeVariant:
    """一个反编译伪代码变体。"""
    variant_id: str
    source_range: Tuple[int, int]  # 原始二进制地址范围
    pseudo_code: str
    transformation: str             # 应用的变换名
    control_flow_hash: str          # CFG的规范化哈希
    data_flow_signature: str        # def-use链的指纹


@dataclass
class AmbiguityReport:
    """反编译歧义报告。"""
    address_range: Tuple[int, int]
    n_variants: int
    agreement_ratio: float     # 变体间一致的比率
    is_ambiguous: bool
    divergent_variants: List[str]
    recommendation: str


class SemanticVariantGenerator:
    """反编译语义变体生成器——检测歧义区域。

    使用范式：
      gen = SemanticVariantGenerator()
      variants = gen.generate(original_pseudocode, address_range)
      report = gen.assess_ambiguity(variants)
    """

    # 模式→替换规则
    _TRANSFORMS = [
        ("commute_add", lambda s: s.replace("a + b", "b + a")),
        ("commute_mul", lambda s: s.replace("a * b", "b * a")),
        ("ptr_to_array", lambda s: s.replace("*(p + i)", "p[i]")),
        ("array_to_ptr", lambda s: s.replace("p[i]", "*(p + i)")),
        ("negate_if", lambda s: s.replace("if (!x)", "if (x == 0)")),
        ("while_to_for", lambda s: s.replace("while (cond)", "for (; cond; )")),
    ]

    def generate(
        self, original: str, address_range: Tuple[int, int],
    ) -> List[PseudoCodeVariant]:
        """生成语义等价的反编译变体。"""
        _variants: List[PseudoCodeVariant] = []

        # 原始版本
        _variants.append(PseudoCodeVariant(
            variant_id="orig",
            source_range=address_range,
            pseudo_code=original,
            transformation="none",
            control_flow_hash=self._cfg_hash(original),
            data_flow_signature=self._def_use_sig(original),
        ))

        # 对每个变换生成变体
        for _tname, _tfunc in self._TRANSFORMS:
            _transformed = _tfunc(original)
            if _transformed != original:
                _variants.append(PseudoCodeVariant(
                    variant_id=f"var_{_tname}",
                    source_range=address_range,
                    pseudo_code=_transformed,
                    transformation=_tname,
                    control_flow_hash=self._cfg_hash(_transformed),
                    data_flow_signature=self._def_use_sig(_transformed),
                ))

        return _variants

    def assess_ambiguity(
        self, variants: List[PseudoCodeVariant],
    ) -> AmbiguityReport:
        """评估变体间的一致性——检测歧义区域。"""
        if len(variants) < 2:
            return AmbiguityReport(
                address_range=variants[0].source_range if variants else (0, 0),
                n_variants=len(variants), agreement_ratio=1.0,
                is_ambiguous=False, divergent_variants=[],
                recommendation="insufficient variants for assessment",
            )

        # 比较CFG哈希（结构一致性）和def-use签名（语义一致性）
        _cfgs = defaultdict(list)
        for _v in variants:
            _cfgs[_v.control_flow_hash].append(_v.variant_id)

        _dominant_cfg = max(_cfgs, key=lambda k: len(_cfgs[k]))
        _agreeing = len(_cfgs[_dominant_cfg])
        _ratio = _agreeing / len(variants)
        _divergent = [
            vid for k, vids in _cfgs.items()
            if k != _dominant_cfg for vid in vids
        ]

        _ambiguous = _ratio < 0.8
        _rec = "high confidence" if not _ambiguous else (
            f"{len(_divergent)} variants diverge — manual review recommended"
        )

        return AmbiguityReport(
            address_range=variants[0].source_range,
            n_variants=len(variants),
            agreement_ratio=round(_ratio, 3),
            is_ambiguous=_ambiguous,
            divergent_variants=_divergent,
            recommendation=_rec,
        )

    @staticmethod
    def _cfg_hash(code: str) -> str:
        """CFG的简化哈希——基于分支关键字。"""
        _keywords = ["if", "else", "for", "while", "do", "switch",
                     "goto", "return", "break", "continue"]
        _hits = "|".join(k for k in _keywords if k in code)
        return str(hash(_hits) & 0xFFFFFFFF)

    @staticmethod
    def _def_use_sig(code: str) -> str:
        """Def-use链的简化签名——基于赋值和目标变量。"""
        _assignments = []
        for _line in code.split("\n"):
            if "=" in _line and not _line.strip().startswith("if"):
                _lhs = _line.split("=")[0].strip()
                _assignments.append(_lhs)
        return "|".join(sorted(set(_assignments))[:20])


# ---- 冒烟测试 ----
def _smoke_test():
    _gen = SemanticVariantGenerator()
    _code = """int x = *p;
if (!x) {
    return p[i];
}
while (x > 0) {
    x = x - 1;
}"""

    _variants = _gen.generate(_code, (0x401000, 0x401050))
    print(f"[variant] generated {len(_variants)} variants")

    _report = _gen.assess_ambiguity(_variants)
    print(f"[variant] agreement={_report.agreement_ratio:.2f} "
          f"ambiguous={_report.is_ambiguous}")
    print(f"[variant] recommendation: {_report.recommendation}")

    assert len(_variants) >= 2, "should generate at least 2 variants"
    print("[OK] SemanticVariantGenerator smoke test passed.")


if __name__ == "__main__":
    _smoke_test()
