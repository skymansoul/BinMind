# 漏洞置信度评分 (Vulnerability Confidence Scoring & FP Suppression)
#
# 多引擎分析结果聚合为统一置信度评分, 抑制误报.
# 各独立检测器(taint/stack/uaf/fmt)产出原始发现,
# 本模块负责: (1)跨引擎交叉验证 (2)误报模式过滤 (3)置信度校准.
#
# 决策依据:
#   1. 交叉验证加分: 同一地址被 ≥2 个引擎标记 → 置信度 +0.2.
#      独立的检测视角(数据流+控制流+类型)得出相同结论,
#      误报概率乘积级下降.
#   2. 误报模式扣分: 识别已知误报模式并扣分.
# 编译器生成的栈保护代码 (__stack_chk_fail附近)
# 单元测试/benchmark中的故意溢出
# 递归调用中的重复报告 (去重)
#   3. 上下文加权: 从用户输入可直接到达的漏洞 (taint_reach=True)
#      比理论可达的漏洞权重大.
#   4. 可解释输出: 每个评分附带 decomposition (分项得分明细),
#      供分析师复核.
#
# 创建: 2026-06-07  初始版本

from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple


class VulnScore:
    """单条漏洞发现的可解释评分."""
    __slots__ = ("address","vuln_type","score","decomposition","engines")
    def __init__(self, address: int, vuln_type: str, score: float,
                 decomposition: dict, engines: List[str]):
        self.address = address; self.vuln_type = vuln_type
        self.score = score; self.decomposition = decomposition
        self.engines = engines

    @property
    def severity(self) -> str:
        if self.score >= 0.8: return "critical"
        elif self.score >= 0.6: return "high"
        elif self.score >= 0.4: return "medium"
        return "low"

    def to_dict(self) -> dict:
        return {"address":hex(self.address),"type":self.vuln_type,
                "score":round(self.score,4),"severity":self.severity,
                "decomposition":self.decomposition,"engines":self.engines}


class VulnScoreCalibrator:
    """漏洞评分校准器: 多引擎交叉验证 + 误报过滤."""

    # 引擎报告的基线权重
    ENGINE_WEIGHTS = {
        "taint_engine": 0.30,
        "stack_overflow": 0.25,
        "uaf_detector": 0.25,
        "format_string": 0.20,
    }

    # 已知误报特征
    FP_PATTERNS = {
        "stack_protector": {"func_contains": ["__stack_chk", "canary"]},
        "unit_test":       {"func_prefix": ["test_", "bench_", "mock_"]},
        "recursive_dup":   {"max_duplicates": 1},
    }

    def __init__(self, cross_val_bonus: float = 0.15,
                 taint_reach_bonus: float = 0.10):
        self._cross_val = cross_val_bonus
        self._taint_bonus = taint_reach_bonus

    def calibrate(self, findings: List[dict],
                   taint_map: Dict[int, bool] = None) -> List[VulnScore]:
        """聚合多引擎发现 → 校准后的评分列表.

        findings: 来自各检测器的原始发现列表.
                  每项含: {"type", "address", "engine", "severity", ...}
        taint_map: {address: bool} 指示该地址是否可从用户输入到达.
        """
        if taint_map is None:
            taint_map = {}

        # 按地址分组: 同一地址可能被多个引擎报告
        grouped: Dict[int, List[dict]] = defaultdict(list)
        for f in findings:
            addr = f.get("address", 0)
            grouped[addr].append(f)

        scores = []
        for addr, group in grouped.items():
            # 去重: 过滤递归/循环中的重复报告
            if len(group) > 3:
                group = group[:3]

            engines = list(set(f.get("engine", "unknown") for f in group))
            vuln_type = self._majority_type(group)

            # 基础分: 各引擎权重的加权平均
            base = sum(self.ENGINE_WEIGHTS.get(e, 0.15) for e in engines)

            # 交叉验证加分
            cross = 0.0
            if len(engines) >= 2:
                cross = self._cross_val * (len(engines) - 1)

            # 污点可达加分
            taint = 0.0
            if taint_map.get(addr, False):
                taint = self._taint_bonus

            # 误报扣分
            fp_penalty = self._check_fp(group)
            score = max(0.0, min(1.0, base + cross + taint - fp_penalty))

            scores.append(VulnScore(
                address=addr, vuln_type=vuln_type, score=score,
                decomposition={
                    "base_weight": round(base, 4),
                    "cross_validation": round(cross, 4),
                    "taint_reachable": round(taint, 4),
                    "fp_penalty": round(fp_penalty, 4),
                },
                engines=engines,
            ))

        scores.sort(key=lambda s: s.score, reverse=True)
        return scores

    @staticmethod
    def _majority_type(findings: List[dict]) -> str:
        types = [f.get("type", "unknown") for f in findings]
        return max(set(types), key=types.count)

    def _check_fp(self, findings: List[dict]) -> float:
        """误报模式匹配: 返回扣分值 [0, 0.5]."""
        penalty = 0.0
        for f in findings:
            func = f.get("function", "")
            # 栈保护代码
            if any(p in func for p in self.FP_PATTERNS["stack_protector"]["func_contains"]):
                penalty += 0.2
            # 测试代码
            if any(func.startswith(p) for p in self.FP_PATTERNS["unit_test"]["func_prefix"]):
                penalty += 0.15
        return min(penalty, 0.5)


__all__ = ["VulnScoreCalibrator", "VulnScore"]
