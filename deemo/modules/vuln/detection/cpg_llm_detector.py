# CPG-LLM-Vuln - CPG 引导的 LLM 漏洞检测器 + 反事实增强鲁棒性评估。
#
# 创新点相对现有 LLMVulnerabilityDetector(纯文本输入):
#   1. CPG 结构上下文: 将伪代码构建为代码属性图, 序列化关键数据流/控制流路径
#      拼接进 LLM prompt - 提升跨函数数据流理解。
#   2. 多特征融合注意力: 文本嵌入 + CPG 结构特征经 softmax 注意力加权融合打分
#   3. 反事实增强鲁棒性: 对样本做最小扰动(边界偏移/重命名/去注释等)评估检测器
#      一致性, 无 LLM 时退化为启发式变换 (VISION, [待验证];
#      NatGVD, [待验证])。
#
# 边界条件:
#   - LLM 后端不可用时, 检测降级为 结构+文本 融合打分(纯统计路径), 仍可用。
# 鲁棒性评估默认使用快速打分器(结构+文本), 避免对每个变体重复调用 LLM。

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


def _import_cpg_builder():
    try:
        from modules.vuln.detection.cpg_builder import (
            CodePropertyGraph, DEFAULT_SINKS, build_cpg)
        return CodePropertyGraph, DEFAULT_SINKS, build_cpg
    except ImportError:
        from deemo.modules.vuln.detection.cpg_builder import (
            CodePropertyGraph, DEFAULT_SINKS, build_cpg)
        return CodePropertyGraph, DEFAULT_SINKS, build_cpg


def _import_path_serializer():
    try:
        from modules.vuln.detection.cpg_path_serializer import build_cpg_context
        return build_cpg_context
    except ImportError:
        from deemo.modules.vuln.detection.cpg_path_serializer import build_cpg_context
        return build_cpg_context


def _import_augmenter():
    try:
        from modules.vuln.detection.counterfactual_augmenter import (
            CounterfactualAugmenter, RobustnessReport)
        return CounterfactualAugmenter, RobustnessReport
    except ImportError:
        from deemo.modules.vuln.detection.counterfactual_augmenter import (
            CounterfactualAugmenter, RobustnessReport)
        return CounterfactualAugmenter, RobustnessReport


def _import_fusion():
    try:
        from modules.vuln.detection.multi_feature_fusion import (
            FeatureAttentionFuser, FusionResult, extract_structure_features,
            extract_text_features, structural_risk_score, text_risk_score)
        return (FeatureAttentionFuser, FusionResult,
                extract_structure_features, extract_text_features,
                structural_risk_score, text_risk_score)
    except ImportError:
        from deemo.modules.vuln.detection.multi_feature_fusion import (
            FeatureAttentionFuser, FusionResult, extract_structure_features,
            extract_text_features, structural_risk_score, text_risk_score)
        return (FeatureAttentionFuser, FusionResult,
                extract_structure_features, extract_text_features,
                structural_risk_score, text_risk_score)


def _import_llm_detector():
    """加载既有 LLM 检测器 - 双路径兼容 import。

    框架内 `vuln_detection.*` 别名与独立运行时的 `modules.vuln.detection.*`
    均可能生效; 两者都失败时返回 None, 由调用方走纯统计降级路径。
    """
    try:
        from modules.vuln.detection.llm_vuln_detector import (
            LLMVulnerabilityDetector, LLMVulnReport)
        return LLMVulnerabilityDetector, LLMVulnReport
    except ImportError:
        try:
            from deemo.modules.vuln.detection.llm_vuln_detector import (
                LLMVulnerabilityDetector, LLMVulnReport)
            return LLMVulnerabilityDetector, LLMVulnReport
        except ImportError:
            return None, None


@dataclass
class CPGVulnReport:
    """CPG 引导漏洞检测的综合报告。"""
    function_name: str
    verdict: str                            # VULNERABLE / BENIGN / UNCERTAIN
    fused_score: float
    text_score: float
    structure_score: float
    attention_weights: Dict[str, float]
    cpg_stats: Dict[str, Any] = field(default_factory=dict)
    path_context: str = ""                  # 序列化路径文本(LLMxCPG 上下文)
    base_report: Any = None                 # 底层 LLMVulnReport(可选)
    robustness: Any = None                  # RobustnessReport(可选)
    analysis_time_ms: float = 0.0
    model_used: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_name": self.function_name,
            "verdict": self.verdict,
            "fused_score": self.fused_score,
            "text_score": self.text_score,
            "structure_score": self.structure_score,
            "attention_weights": self.attention_weights,
            "cpg_stats": self.cpg_stats,
            "path_context_len": len(self.path_context),
            "robustness": self.robustness.to_dict() if self.robustness else None,
            "analysis_time_ms": self.analysis_time_ms,
            "model_used": self.model_used,
        }


class CPGLLMVulnDetector:
    """CPG 引导的 LLM 漏洞检测器。

    核心流程:
        1. CPG 构建: build_cpg(pseudocode)
        2. 路径序列化: build_cpg_context, 结构上下文
        3. LLM 检测: 既有 LLMVulnerabilityDetector, prompt 拼接结构上下文
        4. 融合打分: 文本风险分 + 结构风险分, softmax 注意力加权
        5. 鲁棒性评估: 反事实扰动, 一致性/最坏偏移

    参考:
        - LLMxCPG: CPG 路径序列化增强 LLM 上下文
        - CodeSAGE: 多特征融合注意力打分
        - VISION / NatGVD: 反事实鲁棒性
    """

    def __init__(self, llm_detector: Any = None,
                 prefer_local: bool = False,
                 model_name: str = "",
                 use_robustness: bool = True,
                 robustness_with_llm: bool = False):
        self._CPG, self._SINKS, self._build_cpg = _import_cpg_builder()
        self._build_ctx = _import_path_serializer()
        self._Augmenter, self._RobustnessReport = _import_augmenter()
        (self._Fuser, self._FusionResult, self._extract_sf,
         self._extract_tf, self._struct_score, self._text_score) = _import_fusion()

        self._LLMCls, self._LLMReportCls = _import_llm_detector()
        self.llm_detector = None
        if llm_detector is not None:
            self.llm_detector = llm_detector
        elif self._LLMCls is not None:
            try:
                self.llm_detector = self._LLMCls(prefer_local=prefer_local)
                if model_name:
                    self.llm_detector.backend.model_name = model_name
            except Exception as e:
                # 既有 LLM 检测器在无 API key 时可能抛错 - 视为不可用
                logger.debug(f"LLM 检测器初始化失败, 降级为纯统计路径: {e}")
                self.llm_detector = None

        self.fuser = self._Fuser()
        self.augmenter = self._Augmenter()
        self.use_robustness = use_robustness
        self.robustness_with_llm = robustness_with_llm

    @property
    def llm_available(self) -> bool:
        if self.llm_detector is None:
            return False
        try:
            return bool(self.llm_detector.available)
        except Exception:
            return False

    def build_cpg(self, pseudocode: str, source_name: str = "") -> Any:
        return self._build_cpg(pseudocode, source_name)

    def build_path_context(self, cpg: Any, pseudocode: str,
                           function_names: Optional[Sequence[str]] = None,
                           max_chars: int = 2000) -> str:
        return self._build_ctx(cpg, pseudocode, function_names,
                               self._SINKS, max_chars=max_chars)

# 快速打分器(供鲁棒性评估与纯统计降级)

    def fast_score(self, pseudocode: str,
                   function_names: Optional[Sequence[str]] = None) -> Tuple[float, Dict]:
        """快速结构+文本融合打分 - 不调用 LLM。

        用于鲁棒性评估的 scorer 与无 LLM 时的降级路径。
        返回 (fused_score, detail_dict)。
        """
        if not pseudocode or len(pseudocode.strip()) < 4:
            return 0.0, {}
        cpg = self._build_cpg(pseudocode)
        text_s = self._text_score(pseudocode)
        struct_s = self._struct_score(cpg, function_names)
        tf = self._extract_tf(pseudocode)
        sf = self._extract_sf(cpg, function_names)
        res = self.fuser.fuse(text_s, struct_s, tf, sf)
        return res.fused_score, {
            "text": res.text_score, "structure": res.structure_score,
            "attention": res.attention_weights, "cpg_stats": cpg.stats()}

# 主检测入口

    def detect(self, function_name: str = "", pseudocode: str = "",
               arch: str = "x86_64", fmt: str = "ELF",
               danger_funcs: List[str] = None,
               checksec_info: Dict[str, Any] = None,
               function_names: Optional[Sequence[str]] = None,
               max_path_chars: int = 2000) -> CPGVulnReport:
        """CPG 引导的漏洞检测。

        参数与 LLMVulnerabilityDetector.detect 对齐, 新增:
            function_names: 参与路径序列化的目标函数名列表(跨函数分析),
                            为空时自动取 CPG 中全部非外部函数。
        """
        t0 = time.time()
        dgs = danger_funcs or []

        if not pseudocode or len(pseudocode.strip()) < 10:
            return CPGVulnReport(
                function_name=function_name, verdict="UNCERTAIN",
                fused_score=0.0, text_score=0.0, structure_score=0.0,
                attention_weights={}, analysis_time_ms=0.0,
                model_used="cpg_llm_vuln")

        cpg = self._build_cpg(pseudocode, function_name or "fn")
        cpg_stats = cpg.stats()

        # 结构上下文(LLMxCPG 路径序列化)
        if function_names is None:
            fn_list = [cpg.functions[n] for n in list(cpg.functions)
                       if not cpg.node(cpg.functions[n]).attrs.get("is_external")]
            ctx_names = [cpg.node(fid).label for fid in fn_list]
        else:
            ctx_names = list(function_names)
        path_context = self.build_path_context(
            cpg, pseudocode, ctx_names or None, max_chars=max_path_chars)

        # 文本/结构双通道风险分
        text_score = self._text_score(pseudocode)
        struct_score = self._struct_score(cpg, ctx_names or None)
        tf = self._extract_tf(pseudocode)
        sf = self._extract_sf(cpg, ctx_names or None)

        # LLM 通道(可用时)
        base_report = None
        llm_conf = None
        if self.llm_detector is not None and self.llm_available:
            llm_prompt = self._inject_cpg_context(pseudocode, path_context)
            try:
                base_report = self.llm_detector.detect(
                    function_name=function_name, pseudocode=llm_prompt,
                    arch=arch, fmt=fmt, danger_funcs=dgs,
                    checksec_info=checksec_info)
                llm_conf = 0.3 + 0.7 * base_report.false_positive_risk
                llm_conf = 1.0 - llm_conf   # 低误报风险 => 高置信
            except Exception as e:
                logger.warning(f"LLM 检测失败, 降级为纯统计: {e}")
                base_report = None

        # LLM 分与结构+文本分的二次融合
        fusion_res = self.fuser.fuse(text_score, struct_score, tf, sf,
                                     confidence=llm_conf)
        fused_score = fusion_res.fused_score
        if base_report is not None:
            llm_score = base_report.overall_score
            w_struct = fusion_res.attention_weights.get("structure", 0.5)
            w_llm = 0.35                       # LLM 判断权重(经验值)
            fused_score = (fused_score * (1.0 - w_llm) * (1.0 - w_struct)
                           + llm_score * w_llm
                           + struct_score * w_struct)
            fused_score = max(0.0, min(1.0, fused_score))

        # 判定阈值与 LLMVulnerabilityDetector 保持一致
        if fused_score >= 0.7:
            verdict = "VULNERABLE"
        elif fused_score <= 0.3:
            verdict = "BENIGN"
        else:
            verdict = "UNCERTAIN"

        # 反事实鲁棒性评估(可选, 默认快速打分器)
        robustness = None
        if self.use_robustness:
            scorer = self._make_scorer(function_names)
            try:
                robustness = self.augmenter.evaluate_robustness(
                    pseudocode, scorer, threshold=0.5)
            except Exception as e:
                logger.warning(f"鲁棒性评估失败: {e}")

        elapsed_ms = (time.time() - t0) * 1000
        return CPGVulnReport(
            function_name=function_name, verdict=verdict,
            fused_score=round(fused_score, 4),
            text_score=round(text_score, 4),
            structure_score=round(struct_score, 4),
            attention_weights=fusion_res.attention_weights,
            cpg_stats=cpg_stats,
            path_context=path_context,
            base_report=base_report,
            robustness=robustness,
            analysis_time_ms=round(elapsed_ms, 1),
            model_used="cpg_llm_vuln")

    def _inject_cpg_context(self, pseudocode: str, path_context: str) -> str:
        """将 CPG 序列化路径拼接进 LLM prompt 的伪代码段。

        保留原始源码, 附加结构线索注释块 - LLM 可同时利用
        表面文本与结构路径, 对应 LLMxCPG 的上下文增强方式。
        """
        if not path_context or len(path_context) < 20:
            return pseudocode
        return f"{pseudocode}\n\n/* === CPG structure context === */\n{path_context}"

    def _make_scorer(self, function_names: Optional[Sequence[str]]
                     ) -> Callable[[str], float]:
        """构造鲁棒性评估用打分器。

        默认使用 fast_score(结构+文本), 避免对每个反事实变体触发 LLM;
        robustness_with_llm 为 True 时, 变体走完整 LLM 检测路径。
        """
        if self.robustness_with_llm and self.llm_available:
            def scorer(code: str) -> float:
                try:
                    rep = self.detect(function_name="cf_variant",
                                      pseudocode=code,
                                      function_names=function_names,
                                      use_robustness=False)
                    return rep.fused_score
                except Exception:
                    return self.fast_score(code, function_names)[0]
            return scorer
        return lambda code: self.fast_score(code, function_names)[0]

    def batch_detect(self, functions: List[Dict]) -> List[CPGVulnReport]:
        """批量检测 - 顺序执行(结构构建为轻量操作, 无需线程池)。"""
        results = []
        for func in functions:
            try:
                results.append(self.detect(
                    function_name=func.get("name", ""),
                    pseudocode=func.get("pseudocode", ""),
                    arch=func.get("arch", "x86_64"),
                    fmt=func.get("fmt", "ELF"),
                    danger_funcs=func.get("danger_funcs"),
                    checksec_info=func.get("checksec")))
            except Exception as e:
                logger.warning(f"批量检测子项失败: {e}")
        results.sort(key=lambda r: r.fused_score, reverse=True)
        return results


def detect_with_cpg(pseudocode: str, function_name: str = "",
                    danger_funcs: List[str] = None,
                    arch: str = "x86_64",
                    use_robustness: bool = True) -> CPGVulnReport:
    """便捷函数 - 单次 CPG 引导漏洞检测。"""
    detector = CPGLLMVulnDetector(use_robustness=use_robustness)
    return detector.detect(function_name=function_name,
                           pseudocode=pseudocode, arch=arch,
                           danger_funcs=danger_funcs)


def analyze_cpg_robustness(pseudocode: str,
                           function_names: Optional[Sequence[str]] = None
                           ) -> Any:
    """便捷函数 - 仅做结构+文本融合与反事实鲁棒性评估(不调用 LLM)。"""
    detector = CPGLLMVulnDetector()
    cpg = detector.build_cpg(pseudocode)
    score, _detail = detector.fast_score(pseudocode, function_names)
    scorer = detector._make_scorer(function_names)
    report = detector.augmenter.evaluate_robustness(pseudocode, scorer,
                                                    threshold=0.5)
    report.original_score = score
    return report
