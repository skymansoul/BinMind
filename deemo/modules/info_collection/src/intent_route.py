"""
意图推断采集路由。

链路: 分类 -> 歧义处理 -> 动作路由。
1. 意图分类: 用户请求映射为结构化类别 (static/dynamic/intel/file/unknown) 与动作参数 (target/method/depth/constraints)。
2. 语义分类: 配置远端 api 后调用远端模型分类; 无配置时降级为关键词规则匹配。
3. 歧义处理: 信息不足时返回澄清问题, 远端优先, 模板兜底。
4. 动作路由: 参数映射到采集器规格, 校验必填项, 补默认值。
5. 与 llm_intent_infer 衔接: IntentRoute.infer_malice 对函数附加杀伤链阶段标注。

模块位置: info_collection/src/intent_route.py
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

# 意图类别与动作参数


class IntentCategory(Enum):
    """采集意图类别。"""
    STATIC_COLLECTION = "static"      # 静态采集: 主机/网络/服务信息
    DYNAMIC_INTERACTION = "dynamic"   # 动态交互: IOCTL/驱动/模糊测试
    INTEL_CORRELATION = "intel"       # 情报关联: CVE/IOC/OSINT
    FILE_ANALYSIS = "file"            # 文件分析: PE/字符串/哈希
    UNKNOWN = "unknown"


_CATEGORY_ALIASES: Dict[str, IntentCategory] = {
    "static": IntentCategory.STATIC_COLLECTION,
    "静态采集": IntentCategory.STATIC_COLLECTION,
    "动态采集": IntentCategory.STATIC_COLLECTION,
    "dynamic": IntentCategory.DYNAMIC_INTERACTION,
    "动态交互": IntentCategory.DYNAMIC_INTERACTION,
    "intel": IntentCategory.INTEL_CORRELATION,
    "情报关联": IntentCategory.INTEL_CORRELATION,
    "情报": IntentCategory.INTEL_CORRELATION,
    "file": IntentCategory.FILE_ANALYSIS,
    "文件分析": IntentCategory.FILE_ANALYSIS,
    "文件": IntentCategory.FILE_ANALYSIS,
    "unknown": IntentCategory.UNKNOWN,
    "未知": IntentCategory.UNKNOWN,
}


@dataclass
class ActionParams:
    """结构化动作参数。"""
    target: str = ""                 # 采集目标: IP/域名/文件路径/哈希
    method: str = ""                 # 采集方式: scan/enum/query/probe/...
    depth: str = "standard"          # 采集深度: shallow/standard/deep
    constraints: Dict[str, str] = field(default_factory=dict)  # 附加约束: timeout/limit
    raw_text: str = ""               # 原始请求文本


@dataclass
class IntentResult:
    """意图分类结果。"""
    category: IntentCategory
    confidence: float
    params: ActionParams
    matched_categories: List[IntentCategory] = field(default_factory=list)
    clarification_questions: List[str] = field(default_factory=list)
    missing_params: List[str] = field(default_factory=list)
    ambiguous: bool = False
    used_llm: bool = False


@dataclass
class CollectorSpec:
    """采集器规格, 用于路由映射与参数校验。"""
    action_id: str
    description: str
    category: IntentCategory
    required_params: Tuple[str, ...] = ()
    defaults: Dict[str, str] = field(default_factory=dict)


@dataclass
class RoutePlan:
    """动作路由计划。"""
    intent: IntentResult
    actions: List[Dict[str, Any]] = field(default_factory=list)
    missing_params: List[str] = field(default_factory=list)
    valid: bool = False


# 规则分类器 (降级路径)

_CATEGORY_KEYWORDS: Dict[IntentCategory, Tuple[str, ...]] = {
    IntentCategory.STATIC_COLLECTION: (
        "主机", "hostname", "系统信息", "systeminfo", "ipconfig", "whoami",
        "端口", "服务", "进程", "netstat", "arp", "route", "枚举", "采集",
        "配置", "注册表", "registry",
    ),
    IntentCategory.DYNAMIC_INTERACTION: (
        "交互", "动态", "探测", "触发", "运行", "执行", "注入", "ioctl",
        "驱动", "device", "fuzz", "模糊", "输入", "测试", "probe",
    ),
    IntentCategory.INTEL_CORRELATION: (
        "cve", "漏洞情报", "ioc", "哈希", "hash", "关联", "情报", "溯源",
        "威胁", "匹配", "查询", "lookup", "osint", "nvd", "virustotal",
    ),
    IntentCategory.FILE_ANALYSIS: (
        "文件", "pe", "样本", "malware", "静态分析", "字符串", "strings",
        "反编译", "decompile", "二进制", "binary", "dll", "exe", "elf",
    ),
}

_METHOD_ALIASES: Dict[str, str] = {
    "扫描": "scan", "枚举": "enum", "查询": "query", "分析": "analyze",
    "交互": "interact", "探测": "probe", "执行": "exec", "提取": "extract",
    "匹配": "correlate", "关联": "correlate",
}

_AMBIGUITY_TEMPLATES: Dict[str, str] = {
    "target": "请提供采集目标（IP 地址 / 域名 / 文件路径 / 主机名）",
    "method": "请指定采集方式（如：端口扫描、进程枚举、PE 静态分析、IOCTL 交互）",
    "depth": "请指定采集深度（shallow / standard / deep）",
}


def _extract_target(text: str) -> str:
    """从请求文本提取采集目标: URL -> IP -> 文件路径 -> 域名 -> CVE -> 哈希。"""
    m = re.search(r"https?://([^\s\"']+)", text)
    if m:
        host = m.group(1).rstrip("/,.;")
        return host.split("/")[0].split(":")[0]
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    if m:
        return m.group(0)
    m = re.search(r"(?:[A-Za-z]:\\[^\s\"']+|[~/][^\s\"']+|[\w.-]+\.(?:exe|dll|bin|apk|so|py|elf|json|txt))", text)
    if m:
        return m.group(0)
    m = re.search(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
    if m:
        return m.group(0)
    m = re.search(r"CVE-\d{4}-\d+", text, re.IGNORECASE)
    if m:
        return m.group(0)
    m = re.search(r"\b[a-fA-F0-9]{32,64}\b", text)
    if m:
        return m.group(0)
    return ""


def _detect_method(text: str) -> str:
    """从请求文本提取采集方式关键词。"""
    low = text.lower()
    for kw, method in _METHOD_ALIASES.items():
        if kw in low:
            return method
    return ""


def _detect_depth(text: str) -> str:
    """从请求文本推断采集深度 (shallow/standard/deep)。"""
    low = text.lower()
    if re.search(r"深度|deep|深入", low):
        return "deep"
    if re.search(r"浅|shallow|quick|快速", low):
        return "shallow"
    return "standard"


def _extract_constraints(text: str) -> Dict[str, str]:
    """提取显式约束字段 (timeout/limit)。"""
    out: Dict[str, str] = {}
    m = re.search(r"timeout[:：]?\s*(\d+)", text, re.IGNORECASE)
    if m:
        out["timeout"] = m.group(1) + "s"
    m = re.search(r"limit[:：]?\s*(\d+)", text, re.IGNORECASE)
    if m:
        out["limit"] = m.group(1)
    return out


def _missing_params(params: ActionParams) -> List[str]:
    """校验必填参数: target 与 method 任一缺失视为信息不足。"""
    missing: List[str] = []
    if not params.target:
        missing.append("target")
    if not params.method:
        missing.append("method")
    return missing


def _template_clarifications(missing: List[str]) -> List[str]:
    """按缺失参数生成模板澄清问题。"""
    return [_AMBIGUITY_TEMPLATES[k] for k in missing if k in _AMBIGUITY_TEMPLATES]


class RuleIntentClassifier:
    """关键词规则分类器, 当远端模型不可用时自动降级至此。"""

    def classify(self, text: str) -> IntentResult:
        low = text.lower()
        params = ActionParams(raw_text=text)
        params.target = _extract_target(text)
        params.method = _detect_method(text)
        params.depth = _detect_depth(text)
        params.constraints = _extract_constraints(text)
        scores: Dict[IntentCategory, int] = {}
        for cat, kws in _CATEGORY_KEYWORDS.items():
            scores[cat] = sum(1 for kw in kws if kw in low)
        ranked = sorted((c for c, s in scores.items() if s > 0), key=lambda c: scores[c], reverse=True)
        if not ranked:
            result = IntentResult(
                category=IntentCategory.UNKNOWN, confidence=0.3,
                params=params, matched_categories=[],
            )
        else:
            total = max(1, sum(scores.values()))
            best = ranked[0]
            conf = min(0.95, scores[best] / total + (0.1 if len(ranked) == 1 else 0.0))
            result = IntentResult(
                category=best, confidence=conf,
                params=params, matched_categories=ranked,
            )
        result.missing_params = _missing_params(params)
        result.ambiguous = bool(result.missing_params)
        result.clarification_questions = _template_clarifications(result.missing_params)
        return result


# 远端语义分类器

_LLM_CLASSIFY_SYSTEM = (
    "你是网络威胁情报采集路由的意图分类器。"
    "将用户请求映射为结构化采集动作, 仅输出 JSON, 不要任何额外文本。\n"
    'JSON 结构: {"category": "static|dynamic|intel|file|unknown", '
    '"confidence": 0.0, "target": "", "method": "", '
    '"depth": "shallow|standard|deep", "constraints": {}, '
    '"clarifying_questions": [], "reason": ""}\n'
    "类别定义: static=静态采集(主机/网络/服务信息), "
    "dynamic=动态交互(IOCTL/驱动/模糊测试), "
    "intel=情报关联(CVE/IOC/OSINT), file=文件分析(PE/哈希/字符串)。"
)


def _extract_json_obj(text: Optional[str]) -> Optional[Dict[str, Any]]:
    """从远端模型返回文本中提取 JSON 对象, 兼容 ```json 围栏。"""
    if not text:
        return None
    t = re.sub(r"^```(?:json)?\s*", "", text.strip())
    t = re.sub(r"\s*```$", "", t)
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(t[start:end + 1])
    except json.JSONDecodeError:
        return None


class LLMIntentClassifier:
    """远端语义意图分类器, 复用 OpenAI 兼容 chat/completions 接口。"""

    def __init__(self, api_key: str, base_url: str, model: str):
        self._api_key = api_key
        self._base_url = base_url
        self._model = model

    @property
    def enabled(self) -> bool:
        return bool(self._api_key and self._base_url)

    def _chat(self, messages: List[Dict[str, str]], max_tokens: int) -> Optional[str]:
        if not self.enabled:
            return None
        payload = {
            "model": self._model, "messages": messages,
            "temperature": 0.1, "max_tokens": max_tokens,
        }
        url = self._base_url.rstrip("/") + "/chat/completions"
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), method="POST",
        )
        req.add_header("Content-Type", "application/json")
        if self._api_key:
            req.add_header("Authorization", "Bearer " + self._api_key)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            return body["choices"][0]["message"]["content"]
        except Exception:
            _log.debug("LLM classify call failed; fallback to rules", exc_info=True)
            return None

    def classify(self, text: str) -> Optional[IntentResult]:
        content = self._chat(
            [
                {"role": "system", "content": _LLM_CLASSIFY_SYSTEM},
                {"role": "user", "content": text},
            ],
            max_tokens=400,
        )
        data = _extract_json_obj(content)
        if not data:
            return None
        params = ActionParams(
            target=str(data.get("target", "")),
            method=str(data.get("method", "")),
            depth=str(data.get("depth", "standard")) or "standard",
            constraints=dict(data.get("constraints") or {}),
            raw_text=text,
        )
        cat = _CATEGORY_ALIASES.get(str(data.get("category", "")).lower(), IntentCategory.UNKNOWN)
        try:
            conf = float(data.get("confidence", 0.5))
        except (TypeError, ValueError):
            conf = 0.5
        missing = _missing_params(params)
        return IntentResult(
            category=cat,
            confidence=min(0.99, max(0.0, conf)),
            params=params,
            matched_categories=[cat],
            clarification_questions=list(data.get("clarifying_questions") or []),
            missing_params=missing,
            ambiguous=bool(missing),
            used_llm=True,
        )


# 采集器注册表与动作路由

DEFAULT_COLLECTORS: List[CollectorSpec] = [
    CollectorSpec("host_enum", "主机信息采集 (systeminfo/ipconfig/whoami)", IntentCategory.STATIC_COLLECTION, ("target",)),
    CollectorSpec("net_mapping", "网络拓扑采集 (netstat/arp/route)", IntentCategory.STATIC_COLLECTION, ("target",)),
    CollectorSpec("service_enum", "服务/进程枚举", IntentCategory.STATIC_COLLECTION, ("target",)),
    CollectorSpec("ioctl_probe", "设备 IOCTL 交互探测", IntentCategory.DYNAMIC_INTERACTION, ("target",), {"timeout": "5s"}),
    CollectorSpec("driver_probe", "驱动层动态交互", IntentCategory.DYNAMIC_INTERACTION, ("target",), {"timeout": "5s"}),
    CollectorSpec("input_fuzz", "输入模糊测试", IntentCategory.DYNAMIC_INTERACTION, ("target",), {"seed": "0"}),
    CollectorSpec("cve_lookup", "CVE 漏洞情报查询", IntentCategory.INTEL_CORRELATION, ("target",)),
    CollectorSpec("ioc_lookup", "IOC 关联匹配", IntentCategory.INTEL_CORRELATION, ("target",)),
    CollectorSpec("osint_recon", "OSINT 侦察", IntentCategory.INTEL_CORRELATION, ("target",)),
    CollectorSpec("pe_analyze", "PE 静态分析", IntentCategory.FILE_ANALYSIS, ("target",)),
    CollectorSpec("strings_extract", "字符串提取", IntentCategory.FILE_ANALYSIS, ("target",)),
    CollectorSpec("hash_compute", "样本哈希计算", IntentCategory.FILE_ANALYSIS, ("target",)),
]


class CollectorRegistry:
    """采集器注册表, 按意图类别编组, 支持外部扩展。"""

    def __init__(self, specs: Optional[List[CollectorSpec]] = None):
        self._by_category: Dict[IntentCategory, List[CollectorSpec]] = defaultdict(list)
        for spec in specs or DEFAULT_COLLECTORS:
            self.register(spec)

    def register(self, spec: CollectorSpec) -> None:
        self._by_category[spec.category].append(spec)

    def for_categories(self, categories: List[IntentCategory]) -> List[CollectorSpec]:
        out: List[CollectorSpec] = []
        for cat in categories:
            out.extend(self._by_category.get(cat, []))
        return out


class IntentRoute:
    """意图推断采集路由主入口。"""

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "",
        model: str = "",
        collectors: Optional[List[CollectorSpec]] = None,
    ):
        api_key = api_key or os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
        base_url = base_url or os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1")
        model = model or os.environ.get("LLM_MODEL", "gpt-4o-mini")
        self._api_key = api_key
        self._base_url = base_url
        self._model = model
        self._rule = RuleIntentClassifier()
        self._llm = LLMIntentClassifier(api_key, base_url, model)
        self._registry = CollectorRegistry(collectors)
        self._legacy: Optional[Any] = None  # 延迟加载遗留推断器

    @property
    def llm_enabled(self) -> bool:
        return self._llm.enabled

    def classify(self, text: str) -> IntentResult:
        """意图分类: 远端优先, 失败或未配置时降级为规则分类器。"""
        if self._llm.enabled:
            res = self._llm.classify(text)
            if res is not None:
                return res
        return self._rule.classify(text)

    def clarify(self, text: str) -> List[str]:
        """歧义处理: 返回澄清问题列表, 远端未给出时模板兜底。"""
        result = self.classify(text)
        if result.clarification_questions:
            return result.clarification_questions
        return _template_clarifications(_missing_params(result.params))

    def build_action_plan(self, result: IntentResult) -> RoutePlan:
        """动作路由: 校验必填参数, 补默认值, 映射采集器调用。"""
        if result.ambiguous:
            return RoutePlan(intent=result, actions=[], missing_params=result.missing_params, valid=False)
        categories = result.matched_categories or [result.category]
        actions: List[Dict[str, Any]] = []
        for spec in self._registry.for_categories(categories):
            if "target" in spec.required_params and not result.params.target:
                continue
            action: Dict[str, Any] = {
                "action_id": spec.action_id,
                "target": result.params.target,
                "depth": result.params.depth,
            }
            if result.params.method:
                action["method"] = result.params.method
            for k, v in spec.defaults.items():
                action.setdefault(k, v)
            for k, v in result.params.constraints.items():
                action.setdefault(k, v)
            actions.append(action)
        return RoutePlan(intent=result, actions=actions, missing_params=[], valid=True)

    def route(self, text: str) -> RoutePlan:
        """完整链路: 分类 -> 歧义处理 -> 动作路由。"""
        return self.build_action_plan(self.classify(text))

    def infer_malice(self, func_name: str, pseudocode: str, api_calls: List[str]) -> Optional[Any]:
        """对函数/样本附加杀伤链阶段推断, 复用遗留推断器。"""
        if self._legacy is None:
            try:
                from .llm_intent_infer import LLMIntentInferrer
                self._legacy = LLMIntentInferrer(api_key=self._api_key)
            except Exception:
                self._legacy = False
        if not self._legacy:
            return None
        return self._legacy.infer_intent(func_name, pseudocode, api_calls)


def create_default_route(config: Optional[Dict[str, str]] = None) -> IntentRoute:
    """按配置字典创建默认路由实例。"""
    cfg = config or {}
    return IntentRoute(
        api_key=cfg.get("api_key", ""),
        base_url=cfg.get("base_url", ""),
        model=cfg.get("model", ""),
    )


# 增强意图路由 (AugmentedIntentRoute)
#
# 将 EGACD / AICV / CC-RCR / MSIGC / SIFT-D 五项创新集成到统一入口。
# IntentRoute 保留不动, 维持向下兼容。
# AugmentedIntentRoute 在 classify → route 链路中插入:
#   1. 语义指纹去重与漂移检测
#   2. 置信度校准 + 风险控制路由决策
#   3. 多阶段信息增益级联调度
#   4. 多轮上下文歧义解析
#   5. 熵引导自适应深度


class AugmentedIntentRoute(IntentRoute):
    """
    基于 IntentRoute 的扩展, 集成了五个子模块。

    与基类 IntentRoute 的差异:
    - route() 在分类后自动执行置信度校准和风险控制
    - route_with_cascade() 替代原 build_action_plan, 输出级联执行计划
    - resolve_with_context() 利用多轮会话历史消解歧义
    - verify_consistency() 提供对抗性意图一致性校验
    - 对外的 classify() / route() 接口完全兼容基类
    """

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._fingerprint_tracker: Optional[Any] = None
        self._calibrator: Optional[Any] = None
        self._scheduler: Optional[Any] = None
        self._depth_controller: Optional[Any] = None
        self._consistency_verifier: Optional[Any] = None
        self._session_ctx: Optional[Any] = None
        self._augmented_initialized = False

    def _ensure_augmented(self) -> None:
        """惰性初始化增强组件, 避免在无需增强功能时加载额外模块。"""
        if self._augmented_initialized:
            return
        from . import semantic_fingerprint as _sf
        from . import confidence_calibrate as _cc
        from . import info_gain_cascade as _ig
        from . import entropy_depth as _ed
        from . import intent_consistency as _ic
        from . import session_context as _sc

        self._fingerprint_tracker = _sf.SemanticFingerprintTracker()
        self._calibrator = _cc.ConfidenceCalibrator()
        self._scheduler = _ig.InfoGainScheduler()
        self._depth_controller = _ed.EntropyDepthController()
        self._consistency_verifier = _ic.IntentConsistencyVerifier()
        self._session_ctx = _sc.SessionContext()
        self._augmented_initialized = True

    def _ensure_batch2(self) -> None:
        """第二批组件的惰性初始化 —— 仅在显式调用时加载。"""
        if hasattr(self, "_prompt_defender") and self._prompt_defender is not None:
            return
        self._ensure_augmented()
        from . import prompt_defense as _pd
        from . import online_calibrate as _oc
        from . import causal_chain as _cc2
        from . import evidence_fusion as _ef

        self._prompt_defender = _pd.PromptInjectionDefender()
        self._online_calibrator = _oc.OnlineCalibrator()
        self._causal_reconstructor = _cc2.CausalChainReconstructor()
        self._evidence_fuser = _ef.EvidenceFusionEngine()

    def _ensure_batch3(self) -> None:
        """第三批组件 —— 溯源、探测检测、策略守卫。"""
        if hasattr(self, "_provenance_engine") and self._provenance_engine is not None:
            return
        self._ensure_augmented()
        from . import decision_provenance as _dp
        from . import probing_detection as _prd
        from . import policy_guard as _pg

        self._provenance_engine = _dp.DecisionProvenanceEngine()
        self._probing_detector = _prd.ProbingDetector()
        self._policy_guard = _pg.PolicyGuard()

    def _ensure_batch4(self) -> None:
        """第四批组件 —— 自愈监控、规则提取。"""
        if hasattr(self, "_health_monitor") and self._health_monitor is not None:
            return
        self._ensure_augmented()
        from . import self_healing as _sh
        from . import rule_extractor as _re

        self._health_monitor = _sh.SelfHealingMonitor()
        self._rule_extractor = _re.RuleExtractor()

    def _ensure_batch5(self) -> None:
        """第五批组件 —— 嵌入缓存、边界加固。"""
        if hasattr(self, "_embed_cache") and self._embed_cache is not None:
            return
        self._ensure_augmented()
        from . import embed_cache as _ec
        from . import boundary_harden as _bh

        self._embed_cache = _ec.IntentEmbeddingCache()
        self._boundary_hardener = _bh.BoundaryHardener()

    def _ensure_batch5b(self) -> None:
        if hasattr(self, "_bandit_router") and self._bandit_router is not None:
            return
        self._ensure_augmented()
        from . import bandit_router as _br
        self._bandit_router = _br.BanditCollectorRouter()

    def _ensure_batch5c(self) -> None:
        if hasattr(self, "_taxonomy_refiner") and self._taxonomy_refiner is not None:
            return
        self._ensure_augmented()
        from . import taxonomy_refine as _tr
        from . import phase_sequence as _ps
        from . import api_argument_phase as _ap
        from . import param_calibrator as _pc
        self._taxonomy_refiner = _tr.TaxonomyRefiner()
        self._phase_matcher = _ps.PhaseSequenceMatcher()
        self._arg_extractor = _ap.ArgumentPhaseExtractor()
        self._param_calibrator = _pc.ParameterCalibrator()

# 分类法精化

    def feed_taxonomy(self, category: IntentCategory, confidence: float) -> None:
        self._ensure_batch5c()
        import time
        self._taxonomy_refiner.feed(category, confidence, time.time())

    def analyze_taxonomy(self) -> "TaxonomyReport":
        self._ensure_batch5c()
        return self._taxonomy_refiner.analyze()

# 杀伤链阶段推断增强

    def infer_phase_by_sequence(self, api_calls: List[str]) -> "SequencePhaseReport":
        self._ensure_batch5c()
        return self._phase_matcher.infer(api_calls)

    def infer_phase_by_arguments(
        self, api_args: List[Tuple[str, str]],
    ) -> "ArgumentPhaseReport":
        self._ensure_batch5c()
        return self._arg_extractor.extract(api_args)

# 参数自校准

    def calibrate_gain(self, action_id: str, intent: IntentCategory, utility: float) -> None:
        self._ensure_batch5c()
        self._param_calibrator.observe_gain(action_id, intent, utility)

    def calibrate_entropy(
        self, intent: IntentCategory, uniqueness: float, items: int, depth: int,
    ) -> None:
        self._ensure_batch5c()
        self._param_calibrator.observe_entropy(intent, uniqueness, items, depth)

    def get_calibrated_gain(self, action_id: str, intent: IntentCategory, base: float) -> float:
        self._ensure_batch5c()
        return self._param_calibrator.get_calibrated_gain(action_id, intent, base)

    def get_calibrated_entropy(self, intent: IntentCategory, base: float, decay: float) -> Tuple[float, float]:
        self._ensure_batch5c()
        return (
            self._param_calibrator.get_calibrated_entropy_base(intent, base),
            self._param_calibrator.get_calibrated_decay_rate(intent, decay),
        )

    def convergence_ready(self) -> bool:
        self._ensure_batch5c()
        return self._param_calibrator.convergence_report()["overall_ready"]

    def save_calibration(self, path: str) -> None:
        self._ensure_batch5c()
        self._param_calibrator.save(path)

# Bandit 采集器选择

    def bandit_select(self, candidates: List[str], intent: IntentCategory) -> "BanditSelection":
        self._ensure_batch5b()
        return self._bandit_router.select(candidates, intent)

    def bandit_observe(self, action_id: str, useful: bool, latency_ms: float, cost: float = 1.0) -> None:
        self._ensure_batch5b()
        self._bandit_router.observe(action_id, useful, latency_ms, cost)

    def bandit_stats(self) -> List[Dict[str, Any]]:
        self._ensure_batch5b()
        return self._bandit_router.get_arm_stats()

# 嵌入缓存

    def cache_lookup(self, text: str) -> "CacheLookupResult":
        self._ensure_batch5()
        return self._embed_cache.lookup(text)

    def cache_insert(self, text: str, result: IntentResult) -> None:
        self._ensure_batch5()
        self._embed_cache.insert(text, result)

    def classify_with_cache(self, text: str) -> IntentResult:
        """带缓存的分类: 命中则复用, 未命中则分类并缓存。"""
        self._ensure_batch5()
        lookup = self._embed_cache.lookup(text)
        if lookup.hit and lookup.entry is not None:
            return lookup.entry.result
        result = self.classify(text)
        self._embed_cache.insert(text, result)
        return result

# 边界加固

    def generate_boundary_queries(self) -> List["BoundaryQuery"]:
        self._ensure_batch5()
        return self._boundary_hardener.generate_queries()

    def test_boundary(
        self, queries: List["BoundaryQuery"],
    ) -> List["BoundaryTestResult"]:
        self._ensure_batch5()
        def llm_fn(text):
            r = self._llm.classify(text)
            if r is None:
                r = self._rule.classify(text)
                return r.category, r.confidence
            return r.category, r.confidence
        def rule_fn(text):
            r = self._rule.classify(text)
            return r.category, r.confidence
        return self._boundary_hardener.test(queries, llm_fn, rule_fn)

    def harden_analysis(self) -> "HardeningReport":
        self._ensure_batch5()
        return self._boundary_hardener.analyze()

# 自愈监控

    def record_classifier_health(
        self, llm_conf: float, rule_conf: float,
        llm_cat: IntentCategory, rule_cat: IntentCategory, deferral: str,
    ) -> Optional["HealthReport"]:
        self._ensure_batch4()
        return self._health_monitor.record(llm_conf, rule_conf, llm_cat, rule_cat, deferral)

    @property
    def classifier_health(self) -> Optional["HealthReport"]:
        self._ensure_batch4()
        return self._health_monitor.last_health

    def reset_health_baseline(self) -> None:
        self._ensure_batch4()
        self._health_monitor.reset_baseline()

# 规则提取

    def feed_rule_history(self, text: str, llm_category: IntentCategory, llm_confidence: float) -> None:
        self._ensure_batch4()
        self._rule_extractor.feed(text, llm_category, llm_confidence)

    def extract_rules(
        self,
        existing: Optional[Dict[IntentCategory, Tuple[str, ...]]] = None,
    ) -> "RuleExtractionReport":
        self._ensure_batch4()
        return self._rule_extractor.extract(existing)

    def suggest_rules(
        self, existing: Dict[IntentCategory, Tuple[str, ...]],
    ) -> Dict[IntentCategory, List[str]]:
        self._ensure_batch4()
        return self._rule_extractor.suggest_rule_update(existing)

# 决策溯源

    def open_provenance_chain(self, input_text: str) -> str:
        self._ensure_batch3()
        return self._provenance_engine.open_chain(input_text)

    def record_classify_provenance(self, chain_id: str, category: IntentCategory, confidence: float, used_llm: bool) -> Optional[str]:
        self._ensure_batch3()
        return self._provenance_engine.record_classify(chain_id, category, confidence, used_llm)

    def record_route_provenance(self, chain_id: str, action_ids: List[str], target: str) -> Optional[str]:
        self._ensure_batch3()
        return self._provenance_engine.append_route(chain_id, action_ids, target)

    def record_outcome_provenance(self, chain_id: str, useful: bool, quality: float, latency_ms: float) -> Optional[str]:
        self._ensure_batch3()
        return self._provenance_engine.append_outcome(chain_id, useful, quality, latency_ms)

    def get_provenance_chain(self, chain_id: str) -> Optional["ProvenanceChain"]:
        self._ensure_batch3()
        return self._provenance_engine.get_chain(chain_id)

# 探测检测

    def check_probing(
        self, category: IntentCategory, confidence: float,
        target: str, method: str, text: str,
    ) -> "ProbingReport":
        self._ensure_batch3()
        return self._probing_detector.feed(category, confidence, target, method, text)

# 策略守卫

    def check_policy(self, result: IntentResult) -> "PolicyVerdict":
        self._ensure_batch3()
        return self._policy_guard.check(result)

    def check_collector_policy(self, result: IntentResult, spec: CollectorSpec) -> "PolicyVerdict":
        self._ensure_batch3()
        return self._policy_guard.check_collector(result, spec)

# 提示注入防御

    def assess_injection_risk(self, text: str) -> "InjectionReport":
        """评估请求文本的注入风险, 返回 InjectionReport。"""
        self._ensure_batch2()
        return self._prompt_defender.assess(text, self.classify)

    def quick_injection_scan(self, text: str) -> float:
        """快速结构扫描 (无分类器调用)。返回风险评分 [0,1]。"""
        self._ensure_batch2()
        return self._prompt_defender.quick_scan(text)

# 在线校准

    def record_collection_outcome(
        self, action_id: str, intent: IntentCategory,
        useful: bool, quality: float = 0.5, latency_ms: float = 0.0, items: int = 0,
    ) -> None:
        """提交采集结果观测, 更新在线校准器的 Beta 后验。"""
        self._ensure_batch2()
        from .online_calibrate import OutcomeObservation
        obs = OutcomeObservation(
            action_id=action_id, intent=intent, useful=useful,
            quality_score=quality, latency_ms=latency_ms, items_returned=items,
        )
        self._online_calibrator.observe(obs)

    def get_dynamic_gain(self, action_id: str, intent: IntentCategory, base: float = 0.5) -> float:
        """获取经在线校准的动态增益估计 (Thompson 采样)。"""
        self._ensure_batch2()
        return self._online_calibrator.sample_gain(action_id, intent, base)

# 因果链重建

    def reconstruct_chain(
        self,
        intent_sequence: List[Tuple[IntentCategory, float, str]],
    ) -> "CausalChainReport":
        """从意图序列重建攻击因果链。"""
        self._ensure_batch2()
        return self._causal_reconstructor.reconstruct(intent_sequence)

# 证据融合

    def fuse_collector_results(
        self, bodies: List["EvidenceBody"],
    ) -> "FusionResult":
        """融合多个采集器的证据体。"""
        self._ensure_batch2()
        return self._evidence_fuser.fuse(bodies)

# 增强分类与路由

    def classify_calibrated(self, text: str) -> "CalibratedResult":
        """分类 + 置信度校准, 返回校准后的结果。"""
        self._ensure_augmented()
        from .confidence_calibrate import CalibratedResult

        llm_res: Optional[IntentResult] = None
        rule_res: Optional[IntentResult] = None

        if self._llm.enabled:
            llm_res = self._llm.classify(text)
        rule_res = self._rule.classify(text)

        return self._calibrator.calibrate_result(llm_res, rule_res)

    def route(self, text: str) -> RoutePlan:
        """
        扩展路由: 分类 → 校准 → 歧义解析 → 级联调度。

        与基类 route() 接口完全兼容, 返回 RoutePlan。
        内部自动执行置信度校准和风险控制。
        """
        self._ensure_augmented()

        # 1. 分类 + 校准
        calibrated = self.classify_calibrated(text)
        if calibrated.deferral.value in ("defer", "escalate"):
            # 置信度不足, 回退到基类路由
            result = self.classify(text)
            plan = self.build_action_plan(result)
            # 附加校准信息到 plan 的元数据
            plan.actions.append({
                "_calibration_note": f"路由降级: {calibrated.deferral.value}",
                "_calibrated_probability": calibrated.calibrated_probability,
            })
            return plan

        # 2. 解析歧义
        result = self.classify(text)
        resolved, _ = self._session_ctx.resolve(result)

        # 3. 语义指纹去重
        fp = self._fingerprint_tracker.fingerprint(resolved, text)
        if self._fingerprint_tracker.is_duplicate(text):
            # 重复查询, 直接返回空计划
            return RoutePlan(
                intent=resolved, actions=[], missing_params=[],
                valid=True,
            )
        self._fingerprint_tracker.add(fp)

        # 4. 级联调度
        cascade = self._scheduler.plan(
            resolved.category,
            [s.action_id for s in self._registry.for_categories(
                resolved.matched_categories or [resolved.category]
            )],
        )

        # 5. 转换为 RoutePlan
        actions: List[Dict[str, Any]] = []
        for stage in cascade.stages:
            for node in stage:
                actions.append({
                    "action_id": node.action_id,
                    "target": resolved.params.target,
                    "depth": resolved.params.depth,
                    "priority": node.priority,
                    "estimated_gain": node.gain,
                    "estimated_cost": node.cost,
                    "stage": cascade.stages.index(stage),
                })

        return RoutePlan(
            intent=resolved, actions=actions, missing_params=resolved.missing_params,
            valid=not resolved.ambiguous,
        )

# 增强歧义处理

    def clarify(self, text: str) -> List[str]:
        """增强歧义处理: 利用多轮会话历史生成上下文感知的澄清问题。"""
        self._ensure_augmented()
        result = self.classify(text)
        _, resolved_params = self._session_ctx.resolve(result)

        unresolved = []
        if not resolved_params.target:
            unresolved.append("target")
        if not resolved_params.method:
            unresolved.append("method")

        if unresolved:
            ctx_questions = self._session_ctx.suggest_clarification(unresolved)
            if ctx_questions:
                return ctx_questions

        return super().clarify(text)

# 对抗性意图一致性校验

    def verify_consistency(
        self,
        api_calls: List[str],
        cfg_features: Optional[Dict[str, float]] = None,
        code_patterns: Optional[Dict[str, int]] = None,
        strings: Optional[List[str]] = None,
    ) -> "ConsistencyReport":
        """对函数/样本执行多信号意图一致性校验。"""
        self._ensure_augmented()
        return self._consistency_verifier.verify(
            api_calls, cfg_features, code_patterns, strings,
        )

# 级联计划

    def route_with_cascade(self, text: str, budget: Optional[float] = None) -> "CascadePlan":
        """直接返回信息增益级联执行计划 (而非 RoutePlan)。"""
        self._ensure_augmented()
        result = self.classify(text)
        resolved, _ = self._session_ctx.resolve(result)
        action_ids = [
            s.action_id for s in self._registry.for_categories(
                resolved.matched_categories or [resolved.category]
            )
        ]
        return self._scheduler.plan(resolved.category, action_ids, budget)

# 会话管理

    def commit_to_session(self, result: IntentResult, source: str = "") -> None:
        """将当前分类结果提交到会话上下文。"""
        self._ensure_augmented()
        self._session_ctx.add_from_result(result, source)

    def clear_session(self) -> None:
        """重置会话上下文与指纹追踪器。"""
        if self._augmented_initialized:
            self._session_ctx.clear()
            self._fingerprint_tracker.clear()

# 增强 infer_malice: 追加一致性校验

    def infer_malice(
        self, func_name: str, pseudocode: str, api_calls: List[str]
    ) -> Optional[Any]:
        """推断恶意意图, 附加多信号一致性校验结果。"""
        base = super().infer_malice(func_name, pseudocode, api_calls)
        if base is None:
            return None

        self._ensure_augmented()
        consistency = self._consistency_verifier.verify(api_calls)
        # 将一致性报告注入到返回的 IntentReport 中
        base.consistency = consistency  # type: ignore[attr-defined]
        return base


__all__ = [
    "IntentCategory", "ActionParams", "IntentResult", "CollectorSpec", "RoutePlan",
    "RuleIntentClassifier", "LLMIntentClassifier", "CollectorRegistry", "IntentRoute",
    "AugmentedIntentRoute", "create_default_route",
]
