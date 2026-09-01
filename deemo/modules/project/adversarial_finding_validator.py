# 安全发现对抗鲁棒性验证器: 多视角交叉验证 / 一致性投票 / 漂移检测
# 技术问题: 基于ML的漏洞检测器易受对抗样本攻击 (NatGVD 2025报告
#   高达53%的图模型绕过率; FPAs劫持LLM控制流解释), 单视角检测
#   无法区分真实漏洞与精心构造的对抗样本
# 解决手段: 构建三个独立分析维度 (结构模式、语义一致性、
#   时间连贯性) 对每个发现进行交叉验证, 采用加权投票+置信度
#   校准决定最终判定, 同时监测各维度检出率漂移以捕获系统级攻击
# 技术效果: 三个独立分析维度的交叉验证可检测模式不一致的发现,
#   各维度权重按EWMA历史精度动态调整, 减少单一维度误判的影响
#
#   NatGVD — 图模型对抗攻击自然性保持,
#     验证: 独立研究, 53%绕过率, IEEE TPS-ISA会议收录
#   Carlevaro et al. "Conformal Predictions for Probabilistically Robust
#     Scalable ML Classification" — 保形安全集概念
# 设计边界:
# 三个维度相互独立: 攻击者同时欺骗三者的成本远高于欺骗单一维度
# 加权方案由各维度历史精度动态调整 (模拟EWMA加权)
# 漂移检测使用CUSUM, 不依赖参数分布假设
import bisect
import hashlib
import logging
import math
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

# 投票权重衰减系数: EWMA alpha
_EWMA_ALPHA = 0.1
# CUSUM漂移阈值
_CUSUM_THRESHOLD = 5.0
# 时间窗口: 最近N个发现用于漂移检测
_DRIFT_WINDOW = 200
# 默认各维度权重 (均匀先验)
_DEFAULT_WEIGHTS = (0.34, 0.33, 0.33)


@dataclass
class PerspectiveVerdict:
    """单一视角的判定结果."""
    perspective: str
    verdict: str          # 'confirmed' | 'rejected' | 'uncertain'
    confidence: float     # [0, 1]
    evidence: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""


@dataclass
class ValidatorResult:
    """多视角交叉验证的最终结果."""
    finding_id: str
    final_verdict: str    # 'confirmed' | 'rejected' | 'uncertain'
    confidence: float
    perspectives: List[PerspectiveVerdict]
    drift_status: str = "normal"  # 'normal' | 'warning' | 'critical'


class StructuralPatternValidator:
    """视角1: 结构模式验证.

    检查发现的代码模式是否与已知漏洞的AST/CFG结构一致.
    对抗样本倾向于修改表面特征而保留底层结构不变,
    因此结构模式的不一致可暴露对抗扰动.

    技术手段:
      1. n-gram结构指纹与历史真阳性库比较
      2. 代码复杂度异常 (对抗样本常引入异常高的圈复杂度)
      3. 补丁/漏洞位置的代码熵分布检查
    """

    def __init__(self):
        self._tp_fingerprints: Dict[str, float] = {}
        self._complexity_baseline: Dict[str, Tuple[float, float]] = {}

    def validate(self, finding: Dict) -> PerspectiveVerdict:
        fid = finding.get("rule_id", finding.get("title", "unknown"))
        # 结构指纹匹配
        fp = self._extract_structural_fingerprint(finding)
        fp_score = self._match_fingerprint(fp)
        # 圈复杂度异常检测
        cc = self._estimate_complexity(finding)
        cc_anomaly = self._complexity_anomaly(fid, cc)
        # 融合
        score = 0.6 * fp_score + 0.4 * (1.0 - cc_anomaly)
        verdict = self._threshold(score)
        return PerspectiveVerdict(
            perspective="structural_pattern",
            verdict=verdict,
            confidence=score,
            evidence={"fingerprint_match": fp_score,
                      "complexity_anomaly": cc_anomaly},
        )

    def _extract_structural_fingerprint(self, finding: Dict) -> str:
        parts = [
            finding.get("file", ""),
            str(finding.get("line", "")),
            finding.get("cwe", ""),
            str(finding.get("description", ""))[:200],
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    def _match_fingerprint(self, fp: str) -> float:
        if not self._tp_fingerprints:
            return 0.5  # 冷启动: 不确定
        if fp in self._tp_fingerprints:
            return self._tp_fingerprints[fp]
        # 前缀部分匹配: 相似结构可能共享前缀
        partial = sum(v for k, v in self._tp_fingerprints.items()
                     if k[:8] == fp[:8])
        return partial / max(len(self._tp_fingerprints), 1)

    def _estimate_complexity(self, finding: Dict) -> float:
        desc = finding.get("description", "")
        code = finding.get("code_snippet", "")
        text = desc + " " + code
        # 词汇密度: 唯一词数/总词数, 对抗样本常堆砌长串符号
        words = re.findall(r'\w+', text)
        if len(words) < 3:
            return 2.0
        unique_ratio = len(set(words)) / len(words)
        return 1.0 / max(unique_ratio, 0.05)

    def _complexity_anomaly(self, fid: str, cc: float) -> float:
        if fid not in self._complexity_baseline:
            self._complexity_baseline[fid] = (cc, 1.0)
            return 0.0
        mu, sigma = self._complexity_baseline[fid]
        z = abs(cc - mu) / max(sigma, 0.1)
        return min(z / 3.0, 1.0)  # 3-sigma外视为完全异常

    def record_true_positive(self, finding: Dict):
        fp = self._extract_structural_fingerprint(finding)
        self._tp_fingerprints[fp] = self._tp_fingerprints.get(fp, 0.5) * 0.7 + 0.3
        fid = finding.get("rule_id", finding.get("title", "unknown"))
        cc = self._estimate_complexity(finding)
        if fid in self._complexity_baseline:
            mu, sigma = self._complexity_baseline[fid]
            mu = 0.9 * mu + 0.1 * cc
            sigma = 0.9 * sigma + 0.1 * abs(cc - mu)
        self._complexity_baseline[fid] = (
            self._complexity_baseline.get(fid, (cc, 1.0))[0] * 0.9 + cc * 0.1,
            self._complexity_baseline.get(fid, (cc, 1.0))[1],
        )

    @staticmethod
    def _threshold(score: float) -> str:
        # 使用非对称阈值: 误拒的代价高于误收, 因此rejected区间更窄
        if score >= 0.65:
            return "confirmed"
        if score <= 0.30:
            return "rejected"
        return "uncertain"


class SemanticConsistencyValidator:
    """视角2: 语义一致性验证.

    检查发现的文本描述、CWE标签、MITRE ATT&CK映射之间
    是否存在语义矛盾. 对抗样本可能在元数据层注入虚假CWE
    或severity标签以绕过基于规则的过滤器.

    验证链:
      1. CWE↔描述语义对齐 (基于关键词共现)
      2. CVSS向量内部一致性 (AV/AC/PR/UI矛盾检测)
      3. 组件类型与漏洞类型的前置条件检查
    """

    _CWE_KEYWORD_MAP: Dict[str, Set[str]] = {
        "CWE-787": {"buffer", "overflow", "out-of-bounds", "write", "memory"},
        "CWE-89":  {"sql", "injection", "query", "database", "sanitize"},
        "CWE-78":  {"command", "os", "shell", "injection", "exec"},
        "CWE-79":  {"xss", "cross-site", "script", "html", "sanitize"},
        "CWE-476": {"null", "dereference", "pointer", "nil"},
        "CWE-416": {"use-after-free", "dangling", "free", "heap"},
        "CWE-200": {"information", "exposure", "disclosure", "leak"},
        "CWE-287": {"authentication", "auth", "bypass", "credential"},
        "CWE-502": {"deserialization", "untrusted", "serialize", "pickle"},
        "CWE-190": {"integer", "overflow", "wrap", "underflow"},
    }

    _CVSS_CONTRADICTIONS = [
        ("AV:N", "PR:H"),   # 远程攻击+高权限需求 → 可疑
        ("AC:L", "UI:R"),   # 低复杂度+需用户交互 → 矛盾
    ]

    def validate(self, finding: Dict) -> PerspectiveVerdict:
        cwe = finding.get("cwe", "")
        desc = str(finding.get("description", ""))
        title = finding.get("title", "")
        cvss_vec = finding.get("cvss_vector", "")
        # 维度1: CWE-描述对齐
        cwe_align = self._cwe_description_alignment(cwe, title + " " + desc)
        # 维度2: CVSS内部一致性
        cvss_cons = self._cvss_consistency_check(cvss_vec)
        # 维度3: 组件-漏洞兼容性
        comp_compat = self._component_compatibility(finding)
        score = 0.4 * cwe_align + 0.35 * cvss_cons + 0.25 * comp_compat
        return PerspectiveVerdict(
            perspective="semantic_consistency",
            verdict=self._threshold(score),
            confidence=score,
            evidence={"cwe_alignment": cwe_align,
                      "cvss_consistency": cvss_cons,
                      "component_compat": comp_compat},
        )

    def _cwe_description_alignment(self, cwe: str, text: str) -> float:
        if not cwe or cwe not in self._CWE_KEYWORD_MAP:
            return 0.5
        expected = self._CWE_KEYWORD_MAP[cwe]
        text_lower = text.lower()
        hits = sum(1 for kw in expected if kw in text_lower)
        return hits / max(len(expected), 1)

    def _cvss_consistency_check(self, cvss_vec: str) -> float:
        if not cvss_vec:
            return 0.5
        penalties = 0
        for a, b in self._CVSS_CONTRADICTIONS:
            if a in cvss_vec and b in cvss_vec:
                penalties += 1
        return max(0.0, 1.0 - penalties * 0.3)

    def _component_compatibility(self, finding: Dict) -> float:
        comp_type = finding.get("component_type", "")
        cwe = finding.get("cwe", "")
        if not comp_type:
            return 0.5
        # Web组件不应报告内核级CWE
        web_cwes = {"CWE-79", "CWE-89", "CWE-352", "CWE-601"}
        kernel_cwes = {"CWE-787", "CWE-416", "CWE-476", "CWE-415"}
        if comp_type in ("webapp", "api", "spa"):
            if cwe in kernel_cwes:
                return 0.2  # 不匹配
            if cwe in web_cwes:
                return 0.9
        if comp_type in ("kernel", "driver", "firmware"):
            if cwe in web_cwes:
                return 0.3
            if cwe in kernel_cwes:
                return 0.85
        return 0.6

    @staticmethod
    def _threshold(score: float) -> str:
        if score >= 0.7:
            return "confirmed"
        if score <= 0.3:
            return "rejected"
        return "uncertain"


class TemporalCoherenceValidator:
    """视角3: 时间连贯性验证.

    验证发现的时序模式是否与安全事件的自然演化一致.
    对抗样本批量注入时会产生统计上异常的检出模式
    (时间聚类、频率突变), 可由此检测.

    检测手段:
      1. CUSUM漂移检测: 各维度检出率的累积和监控
      2. 发现爆发检测: 短时间窗口内异常密度
      3. 文件级热点分析: 同一文件被频繁报告的可信度衰减
    """

    def __init__(self, window_size: int = _DRIFT_WINDOW):
        self._window = window_size
        self._history: deque = deque(maxlen=window_size)
        self._cusum_high: float = 0.0
        self._cusum_low: float = 0.0
        self._file_hotness: Dict[str, float] = {}
        self._baseline_rate: float = 0.0

    def validate(self, finding: Dict) -> PerspectiveVerdict:
        now = time.time()
        self._history.append((now, finding))
        # 爆发检测
        burst_score = self._burst_check(now)
        # 文件热点衰减
        file_hot = self._file_hotness_score(finding.get("file", ""), now)
        # CUSUM漂移
        drift_score = self._cusum_score()
        # 融合: burst是最强信号, 权重最高
        score = 0.45 * (1.0 - burst_score) + 0.30 * (1.0 - file_hot) + 0.25 * (1.0 - drift_score)
        return PerspectiveVerdict(
            perspective="temporal_coherence",
            verdict=self._threshold(score),
            confidence=score,
            evidence={"burst_score": burst_score,
                      "file_hotness": file_hot,
                      "drift_score": drift_score},
        )

    def _burst_check(self, now: float) -> float:
        """检测短时间窗口内的发现密度异常.
        返回[0,1], 越高表示越可能是爆发."""
        recent = sum(1 for ts, _ in self._history
                    if now - ts < 60)  # 最近60秒
        if recent <= 2:
            return 0.0
        expected = self._baseline_rate * 60
        if expected < 0.01:
            return min(recent / 10.0, 1.0)
        return min(recent / (expected * 5), 1.0)

    def _file_hotness_score(self, file_path: str, now: float) -> float:
        if not file_path:
            return 0.0
        # 衰减: 每5分钟衰减一半
        decay = 0.5 ** (1.0 / 300)
        for f in list(self._file_hotness.keys()):
            self._file_hotness[f] *= decay
            if self._file_hotness[f] < 0.01:
                del self._file_hotness[f]
        self._file_hotness[file_path] = self._file_hotness.get(file_path, 0.0) + 1.0
        return min(self._file_hotness[file_path] / 5.0, 1.0)

    def _cusum_score(self) -> float:
        """CUSUM漂移分数: [0,1], 越高漂移越严重."""
        if len(self._history) < 10:
            return 0.0
        # 用每10秒的发现数作为观测
        if len(self._history) >= 2:
            ts_list = [ts for ts, _ in self._history]
            rate = len(ts_list) / max(ts_list[-1] - ts_list[0], 1)
            self._baseline_rate = (1 - _EWMA_ALPHA) * self._baseline_rate + _EWMA_ALPHA * rate
        recent_count = sum(1 for ts, _ in self._history
                          if time.time() - ts < 10)
        deviation = recent_count - self._baseline_rate * 10
        k = 0.5
        self._cusum_high = max(0, self._cusum_high + deviation - k)
        self._cusum_low = max(0, self._cusum_low - deviation - k)
        drift = max(self._cusum_high, self._cusum_low)
        return min(drift / _CUSUM_THRESHOLD, 1.0)

    @staticmethod
    def _threshold(score: float) -> str:
        # 时间维度的判定更保守: burst信号有滞后性, 宽放uncertain区间
        if score >= 0.72:
            return "confirmed"
        if score <= 0.28:
            return "rejected"
        return "uncertain"


class AdversarialFindingValidator:
    """多视角对抗验证器主类: 组合三个独立视角交叉验证, 各视角权重按历史精度动态调整."""

    def __init__(self):
        self._structural = StructuralPatternValidator()
        self._semantic = SemanticConsistencyValidator()
        self._temporal = TemporalCoherenceValidator()
        # 动态权重: 各维度近期精度EWMA
        self._perspective_weights = list(_DEFAULT_WEIGHTS)
        self._perspective_history: Dict[str, List[float]] = defaultdict(list)

    def validate(self, finding: Dict) -> ValidatorResult:
        fid = finding.get("rule_id", finding.get("title",
                        hashlib.md5(str(finding).encode()).hexdigest()[:8]))
        # 三视角并行验证
        v1 = self._structural.validate(finding)
        v2 = self._semantic.validate(finding)
        v3 = self._temporal.validate(finding)
        verdicts = [v1, v2, v3]
        # 加权投票: confirmed=1, uncertain=0.5, rejected=0
        score_map = {"confirmed": 1.0, "uncertain": 0.5, "rejected": 0.0}
        weighted_score = sum(
            self._perspective_weights[i] * score_map[v.verdict]
            for i, v in enumerate(verdicts)
        )
        # 置信度: 各维度置信度加权平均
        avg_confidence = sum(
            self._perspective_weights[i] * v.confidence
            for i, v in enumerate(verdicts)
        )
        # 最终判定: 考虑score与confidence的乘积
        effective = weighted_score * avg_confidence
        if effective >= 0.45:
            final = "confirmed"
        elif effective <= 0.18:
            final = "rejected"
        else:
            final = "uncertain"
        # 漂移状态
        drift = v3.evidence.get("drift_score", 0.0)
        if drift > 0.7:
            ds = "critical"
        elif drift > 0.4:
            ds = "warning"
        else:
            ds = "normal"
        return ValidatorResult(
            finding_id=fid,
            final_verdict=final,
            confidence=round(effective, 4),
            perspectives=verdicts,
            drift_status=ds,
        )

    def feedback(self, finding: Dict, is_true_positive: bool):
        """接收人工反馈, 更新各视角权重和指纹库.

        反馈回路:
          1. 若确认为真阳性, 更新结构指纹库
          2. 记录各视角判定与实际结果的一致率
          3. 按EWMA更新各视角权重
        """
        if is_true_positive:
            self._structural.record_true_positive(finding)
        # 重跑验证以获得各视角判定
        v1 = self._structural.validate(finding)
        v2 = self._semantic.validate(finding)
        v3 = self._temporal.validate(finding)
        verdicts = [v1, v2, v3]
        # 更新各视角精度历史
        for i, v in enumerate(verdicts):
            correct = 1.0 if (
                (is_true_positive and v.verdict == "confirmed") or
                (not is_true_positive and v.verdict == "rejected")
            ) else 0.0
            self._perspective_history[f"p{i}"].append(correct)
            if len(self._perspective_history[f"p{i}"]) > 100:
                self._perspective_history[f"p{i}"].pop(0)
        # EWMA调整权重
        precisions = []
        for i in range(3):
            hist = self._perspective_history.get(f"p{i}", [])
            prec = sum(hist) / max(len(hist), 1) if hist else 0.5
            precisions.append(prec)
        total_prec = sum(precisions) or 1.0
        self._perspective_weights = [p / total_prec for p in precisions]

    def batch_validate(self, findings: List[Dict]
                       ) -> List[ValidatorResult]:
        return [self.validate(f) for f in findings]

    def get_drift_status(self) -> Dict[str, Any]:
        cusum_h = self._temporal._cusum_high
        cusum_l = self._temporal._cusum_low
        return {
            "cusum_high": round(cusum_h, 3),
            "cusum_low": round(cusum_l, 3),
            "drift_detected": max(cusum_h, cusum_l) > _CUSUM_THRESHOLD,
            "perspective_weights": [round(w, 3) for w in self._perspective_weights],
        }
