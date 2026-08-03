# 反事实增强器 —— 对漏洞样本施加最小扰动以构造对抗变体，评估检测器鲁棒性分数。
#
# 对应论文: VISION (arXiv:2508.18933 [待验证]) 用反事实增强提升漏洞检测的鲁棒性与可解释性
# (最小扰动下保持语义等价, 但改变攻击面语法); NatGVD (arXiv:2510.04987 [待验证]) 论证
# 基于图结构的漏洞检测对自然对抗样本的脆弱性 —— 名称重命名、边界偏移等攻击。
#
# 设计意图:
#   LLM 不可用时退化为启发式变换(边界条件偏移/标识符重命名/去注释/常量扰动/
#   独立语句重排), 保证管线无外部依赖仍可运行; LLM 可用时额外产出
#   语义等价的对抗改写样本, 逼近真实攻击者的逃逸手段。
#
# 鲁棒性定义 (VISION 反事实一致性):
#   vulnerable 样本: 变体分数需保持在 原分 - tolerance 之上;
#   benign 样本:    变体分数需保持在 阈值 + tolerance 之下;
#   robustness = 一致变体比例; 判定为 robust 需同时满足
#   一致率下限与最坏偏移上限。

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


class CounterfactualTransform(str, Enum):
    """反事实变换类型 —— 与 VISION 的最小扰动类别对应。"""
    BOUNDARY_SHIFT = "boundary_shift"        # 条件边界偏移(> vs >=, ±1)
    RENAME = "rename"                        # 标识符重命名
    DECOMMENT = "decomment"                  # 去注释
    CONSTANT_PERTURB = "constant_perturb"    # 常量扰动
    STATEMENT_REORDER = "statement_reorder"  # 独立语句重排
    LLM_REWRITE = "llm_rewrite"              # LLM 语义等价改写


@dataclass
class CounterfactualSample:
    """单个反事实变体。"""
    variant: str
    transform: CounterfactualTransform
    edit_distance: float                    # 归一化编辑距离(0..1), 越小扰动越微
    minimality: float                       # 1 - edit_distance, 最大扰动预算约束
    score_variant: float = 0.0              # 检测器对变体的打分(评估后填充)
    delta_score: float = 0.0                # 变体分数 - 原分数


@dataclass
class RobustnessReport:
    """检测器对扰动集的鲁棒性报告。"""
    original_score: float
    verdict_threshold: float
    samples: List[CounterfactualSample] = field(default_factory=list)
    consistency_rate: float = 1.0           # 一致变体比例
    worst_delta: float = 0.0                # 最大分数偏移
    avg_delta: float = 0.0                  # 平均分数偏移
    robust: bool = True
    model_used: str = "heuristic"           # heuristic / llm / hybrid

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_score": round(self.original_score, 3),
            "consistency_rate": round(self.consistency_rate, 3),
            "worst_delta": round(self.worst_delta, 3),
            "avg_delta": round(self.avg_delta, 3),
            "robust": self.robust,
            "model_used": self.model_used,
            "variant_count": len(self.samples),
            "transforms": [s.transform.value for s in self.samples],
            "deltas": [round(s.delta_score, 3) for s in self.samples],
        }


def _levenshtein_ratio(a: str, b: str) -> float:
    """归一化编辑距离 —— O(mn) DP, 结果归一化到 [0,1]。

    算法依据: Wagner-Fischer 动态规划, 空间优化为两行滚动数组。
    """
    if not a and not b:
        return 0.0
    m, n = len(a), len(b)
    if m < n:
        a, b = b, a
        m, n = n, m
    prev = list(range(n + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[-1] / max(m, n, 1)


class CounterfactualAugmenter:
    """反事实样本构造与鲁棒性评估器。

    边界条件:
      - 启发式变换仅在文本层面成立, 不保证语义严格等价 —— 用于鲁棒性
        评估而非精确对抗样本构造, 与 VISION 的最小扰动约束相容。
      - 语句重排仅交换相邻"简单语句"(非分支/非 return), 避免破坏控制流。
    """

    def __init__(self, edit_budget: float = 0.15, max_variants: int = 6,
                 backend: Any = None):
        self.edit_budget = edit_budget          # 归一化编辑距离上限
        self.max_variants = max_variants
        self.backend = backend                  # 可选LLM后端，缺省回退至启发式

    # ---- 启发式变换 ----

    def augment(self, code: str) -> List[CounterfactualSample]:
        """对样本施加最小扰动, 输出反事实变体列表。

        变换顺序与扰动预算:
          边界偏移 -> 重命名 -> 去注释 -> 常量扰动 -> 重排。
        每类变换只保留编辑距离 <= budget 的变体 —— 保证扰动"最小"。
        """
        samples: List[CounterfactualSample] = []
        if not code or len(code.strip()) < 4:
            return samples

        generators: List[Tuple[CounterfactualTransform, Callable[[str], Optional[str]]]] = [
            (CounterfactualTransform.BOUNDARY_SHIFT, self._shift_boundary),
            (CounterfactualTransform.RENAME, self._rename_identifier),
            (CounterfactualTransform.DECOMMENT, self._decomment),
            (CounterfactualTransform.CONSTANT_PERTURB, self._perturb_constant),
            (CounterfactualTransform.STATEMENT_REORDER, self._reorder_statements),
        ]

        for transform, gen in generators:
            if len(samples) >= self.max_variants:
                break
            variant = gen(code)
            if variant is None or variant == code:
                continue
            dist = _levenshtein_ratio(code, variant)
            if dist <= self.edit_budget:
                samples.append(CounterfactualSample(
                    variant=variant, transform=transform,
                    edit_distance=round(dist, 4),
                    minimality=round(1.0 - dist, 4)))

        # LLM 增强(可选)
        if len(samples) < self.max_variants and self._llm_available():
            for v in self._llm_adversarial(code):
                if len(samples) >= self.max_variants:
                    break
                if v and v != code:
                    dist = _levenshtein_ratio(code, v)
                    samples.append(CounterfactualSample(
                        variant=v, transform=CounterfactualTransform.LLM_REWRITE,
                        edit_distance=round(dist, 4),
                        minimality=round(1.0 - dist, 4)))
                    self._llm_used = True

        return samples[:self._max_alloc()]

    def _max_alloc(self) -> int:
        return max(1, self.max_variants)

    def _llm_available(self) -> bool:
        if self.backend is None:
            return False
        try:
            return bool(self.backend.is_available())
        except Exception:
            return False

    def _llm_adversarial(self, code: str) -> List[str]:
        """LLM 构造语义等价但改变表面语法的对抗变体。

        目的:
          NatGVD 指出自然对抗样本(保留语义的重命名/结构调整)能绕过
          纯文本检测器; 此路径让 LLM 扮演攻击者构造此类改写。
        异常路径:
          LLM 不可用或调用失败时返回空列表, 由启发式路径兜底。
        """
        prompt = (
            "Rewrite the following C pseudocode so that it is semantically "
            "equivalent but syntactically perturbed (rename identifiers, "
            "reorder safe statements, adjust a boundary check). "
            "Output ONLY the rewritten code, no explanation.\n\n"
            f"```c\n{code[:1500]}\n```")
        try:
            raw = self.backend.generate(prompt, max_tokens=700)
        except Exception as e:
            logger.debug(f"LLM 对抗改写失败: {e}")
            return []
        if not raw:
            return []
        cleaned = re.sub(r'^```(?:c)?\s*|\s*```$', '', raw.strip(), flags=re.M)
        cleaned = re.sub(r'```', '', cleaned)
        return [cleaned] if len(cleaned) > 10 else []

    # ---- 具体启发式变换实现 ----

    @staticmethod
    def _shift_boundary(code: str) -> Optional[str]:
        """条件边界偏移: `>` -> `>=`, `<` -> `<=`, 并同步偏移相邻常量 ±1。

        参考:
          VISION 的"改变条件边界"最小扰动 —— 使脆弱边界检查在攻击者视角
          下可被绕过(off-by-one), 是缓冲区溢出类漏洞的典型逃逸手法。
        """
        repl = [
            (r'\bif\s*\(([^()]*?)\s*>\s*([0-9]+)\s*\)', r'if (\1 >= \2)'),
            (r'\bif\s*\(([^()]*?)\s*<\s*([0-9]+)\s*\)', r'if (\1 <= \2)'),
            (r'\bif\s*\(([^()]*?)\s*>=\s*([0-9]+)\s*\)', r'if (\1 > \2)'),
            (r'\bif\s*\(([^()]*?)\s*<=\s*([0-9]+)\s*\)', r'if (\1 < \2)'),
            (r'\bif\s*\(([^()]*?)\s*!=\s*([0-9]+)\s*\)', r'if (\1 == \2)'),
            (r'\bif\s*\(([^()]*?)\s*==\s*([0-9]+)\s*\)', r'if (\1 != \2)'),
        ]
        for pat, rep in repl:
            if re.search(pat, code):
                return re.sub(pat, rep, code, count=1)
        return None

    @staticmethod
    def _rename_identifier(code: str) -> Optional[str]:
        """一致重命名一个局部标识符。

        约束:
          仅对词频 >= 2 的标识符生效, 避免改名单次出现造成语义漂移;
          跳过危险函数名与关键字, 防止改变调用语义。
        """
        toks = re.findall(r'[A-Za-z_]\w*', code)
        _skip = {"if", "else", "while", "for", "return", "char", "int", "void",
                 "strcpy", "memcpy", "sprintf", "printf", "NULL", "sizeof"}
        counts: Dict[str, int] = {}
        for t in toks:
            counts[t] = counts.get(t, 0) + 1
        candidates = [t for t, c in counts.items()
                      if c >= 2 and t not in _skip and not t.startswith("__")]
        if not candidates:
            return None
        target = candidates[0]
        new_name = target + "_v"
        # 仅替换完整标识符(token 边界)
        return re.sub(rf'\b{re.escape(target)}\b', new_name, code, count=len(toks))

    @staticmethod
    def _decomment(code: str) -> Optional[str]:
        """去除注释 —— 使检测器无法依赖注释中的线索词。"""
        if "//" not in code and "/*" not in code and "#" not in code:
            return None
        cleaned = re.sub(r'//[^\n]*', '', code)
        cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.S)
        cleaned = re.sub(r'^\s*#.*$', '', cleaned, flags=re.M)
        return cleaned if cleaned != code else None

    @staticmethod
    def _perturb_constant(code: str) -> Optional[str]:
        """常量 ±1 扰动 —— 针对边界检查附近的常量。

        原理:
          边界常量是漏洞根因(如缓冲区大小/最大长度), 扰动后检测器若仍
          判定危险则说明依赖的是结构性证据而非常量字面量。
        """
        m = re.search(r'\b(1[0-9]|[2-9][0-9])\b', code)
        if not m:
            return None
        val = int(m.group(1))
        new_val = val - 1 if val > 1 else val + 1
        return re.sub(rf'\b{val}\b', str(new_val), code, count=1)

    @staticmethod
    def _reorder_statements(code: str) -> Optional[str]:
        """交换两条相邻的简单赋值语句。

        前置条件:
          仅交换不含调用、不含条件的关键字的赋值行, 保证控制无关。
        """
        lines = code.splitlines()
        for i in range(len(lines) - 1):
            a, b = lines[i].strip(), lines[i + 1].strip()
            if (re.match(r'^[A-Za-z_]\w*\s*=', a) and re.match(r'^[A-Za-z_]\w*\s*=', b)
                    and "(" not in a and "(" not in b):
                lines[i], lines[i + 1] = lines[i + 1], lines[i]
                return "\n".join(lines)
        return None

    # ---- 鲁棒性评估 ----

    def evaluate_robustness(self, code: str, scorer: Callable[[str], float],
                            threshold: float = 0.5,
                            tolerance: float = 0.15) -> RobustnessReport:
        """评估检测器对该样本扰动集的鲁棒性。

        参数:
            code: 原始样本
            scorer: 检测器打分函数, 输入代码返回 [0,1] 风险分
            threshold: 脆弱/良性判定阈值
            tolerance: 允许的分数漂移容忍度

        判定规则 (VISION 反事实一致性):
            原分 >= threshold(脆弱): 变体需保持 >= 原分 - tolerance;
            原分 <  threshold(良性): 变体需保持 <  threshold + tolerance。
        """
        original_score = max(0.0, min(1.0, float(scorer(code))))
        samples = self.augment(code)
        if not samples:
            return RobustnessReport(
                original_score=original_score, verdict_threshold=threshold,
                samples=[], consistency_rate=1.0, worst_delta=0.0,
                avg_delta=0.0, robust=True,
                model_used="llm" if getattr(self, "_llm_used", False) else "heuristic")

        consistent = 0
        deltas: List[float] = []
        for s in samples:
            s.score_variant = max(0.0, min(1.0, float(scorer(s.variant))))
            s.delta_score = s.score_variant - original_score
            deltas.append(abs(s.delta_score))
            if original_score >= threshold:
                ok = s.score_variant >= original_score - tolerance
            else:
                ok = s.score_variant < threshold + tolerance
            consistent += 1 if ok else 0

        consistency_rate = consistent / len(samples)
        worst_delta = max(deltas) if deltas else 0.0
        avg_delta = sum(deltas) / len(deltas) if deltas else 0.0
        robust = consistency_rate >= 0.6 and worst_delta <= 0.35

        return RobustnessReport(
            original_score=original_score, verdict_threshold=threshold,
            samples=samples, consistency_rate=round(consistency_rate, 3),
            worst_delta=round(worst_delta, 3), avg_delta=round(avg_delta, 3),
            robust=robust,
            model_used="llm" if getattr(self, "_llm_used", False) else "heuristic")


def augment_counterfactuals(code: str, max_variants: int = 6,
                            backend: Any = None) -> List[CounterfactualSample]:
    """便捷函数 —— 构造反事实变体。"""
    return CounterfactualAugmenter(max_variants=max_variants,
                                   backend=backend).augment(code)


def evaluate_detector_robustness(code: str, scorer: Callable[[str], float],
                                 threshold: float = 0.5) -> RobustnessReport:
    """便捷函数 —— 单次鲁棒性评估。"""
    return CounterfactualAugmenter().evaluate_robustness(code, scorer, threshold)
