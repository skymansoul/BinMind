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

# ---------------------------------------------------------------------------
# 意图类别与动作参数
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# 规则分类器 (降级路径)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# 远端语义分类器
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# 采集器注册表与动作路由
# ---------------------------------------------------------------------------

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


__all__ = [
    "IntentCategory", "ActionParams", "IntentResult", "CollectorSpec", "RoutePlan",
    "RuleIntentClassifier", "LLMIntentClassifier", "CollectorRegistry", "IntentRoute",
    "create_default_route",
]
