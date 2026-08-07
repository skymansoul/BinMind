# LLM驱动漏洞检测模块。通过远程/本地LLM推理补充静态分析的语义盲区。
# ANVIL 异常评分范式：以LLM预测困惑度
# 作为漏洞信号——漏洞代码的重构损失高于正常代码。
# 借鉴Multi-LLM IoT 三模块融合架构：结构分析
# + 语义推理 + 证据合成，各维度贡献独立证据。
#
# 初版仅支持OpenAI兼容API + 本地Ollama fallback。
# 新增困惑度评分与多轮self-consistency投票。

import json, os, re, time, logging, hashlib, threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

class VulnSignalType(str, Enum):
    """LLM漏洞信号类型枚举——与ANVIL异常维度对应。"""
    ANOMALY_SCORE = "anomaly_score"       # 困惑度/重构损失
    STRUCTURAL_RISK = "structural_risk"   # 控制流/数据流异常
    SEMANTIC_RISK = "semantic_risk"        # 语义层面漏洞指示
    PATTERN_MATCH = "pattern_match"        # 已知漏洞模式匹配
    LLM_JUDGMENT = "llm_judgment"          # LLM直接判断

@dataclass
class VulnSignal:
    """LLM产出的单条漏洞信号。"""
    signal_type: VulnSignalType
    score: float                         # 0.0-1.0
    confidence: float                    # LLM自报置信度
    location: str = ""                   # 函数名/地址
    evidence: str = ""                   # 证据描述
    cwe_hint: str = ""                   # 推测CWE类别
    raw_response: str = ""

@dataclass
class LLMVulnReport:
    """LLM漏洞检测综合报告——多信号聚合结果。"""
    function_name: str
    overall_score: float
    signals: List[VulnSignal] = field(default_factory=list)
    verdict: str = "UNCERTAIN"           # VULNERABLE / BENIGN / UNCERTAIN
    false_positive_risk: float = 0.5
    analysis_time_ms: float = 0.0
    model_used: str = ""

# LLM后端抽象层——支持OpenAI兼容API与本地Ollama，工厂函数自动选择。
# 温度0.1——代码分析需确定性输出，保留微小随机性用于self-consistency。

class LLMBackend:
    """LLM后端基类——子类实现_generate_raw。"""

    def __init__(self, model_name: str = "", temperature: float = 0.1):
        self.model_name = model_name
        self.temperature = temperature

    def generate(self, prompt: str, max_tokens: int = 1024) -> str:
        raise NotImplementedError

    def is_available(self) -> bool:
        return False

class OpenAICompatBackend(LLMBackend):
    """OpenAI兼容API后端——覆盖OpenAI/Ollama/vLLM/LiteLLM。"""

    def __init__(self, model_name: str = "gpt-4o-mini", base_url: str = "",
                 api_key: str = "", temperature: float = 0.1):
        super().__init__(model_name, temperature)
        self.base_url = base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._available = bool(self.api_key)
        try:
            import openai
            self._client = openai.OpenAI(base_url=self.base_url, api_key=self.api_key)
        except ImportError:
            self._client = None
            self._available = False

    def is_available(self):
        return self._available and self._client is not None

    def generate(self, prompt, max_tokens=1024):
        if not self.is_available():
            return ""
        try:
            resp = self._client.chat.completions.create(
                model=self.model_name, temperature=self.temperature,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens)
            return resp.choices[0].message.content or ""
        except Exception as e:
            logger.warning(f"LLM API调用失败: {e}")
            return ""

class OllamaFallbackBackend(LLMBackend):
    """Ollama本地后端——远程API不可用时的降级方案。"""

    def __init__(self, model_name="codellama:7b", host=""):
        super().__init__(model_name)
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    def is_available(self):
        try:
            import urllib.request
            req = urllib.request.Request(f"{self.host}/api/tags", headers={'User-Agent': 'deemo/1.0'})
            with urllib.request.urlopen(req, timeout=3) as r:
                return r.status == 200
        except Exception:
            return False

    def generate(self, prompt, max_tokens=1024):
        if not self.is_available():
            return ""
        try:
            import urllib.request
            payload = json.dumps({
                "model": self.model_name, "prompt": prompt,
                "stream": False,
                "options": {"temperature": self.temperature, "num_predict": max_tokens}
            }).encode()
            req = urllib.request.Request(f"{self.host}/api/generate",
                                        data=payload,
                                        headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.loads(r.read()).get("response", "")
        except Exception as e:
            logger.debug(f"Ollama调用失败: {e}")
            return ""

def _make_backend(prefer_local: bool = False) -> LLMBackend:
    """后端工厂函数——按优先级顺序探测可用后端。返回不可用实例由调用方处理。"""
    if not prefer_local:
        be = OpenAICompatBackend()
        if be.is_available():
            return be
    fb = OllamaFallbackBackend()
    if fb.is_available():
        return fb
    return OpenAICompatBackend()  # 返回一个不可用的，由调用方处理

# 提示词模板——参考ANVIL设计：LLM扮演代码安全审计员，输出结构化JSON供解析。

_VULN_DETECT_TEMPLATE = """You are a binary security auditor analyzing decompiled pseudocode.
Examine the following function for memory corruption vulnerabilities.

Function: {function_name}
Pseudocode:
```
{pseudocode}
```

Context: Architecture={arch}, Format={fmt}, Dangerous functions detected: {danger_funcs}

Analyze for:
1. Buffer overflow (stack/heap)
2. Use-after-free / double-free
3. Format string vulnerabilities
4. Integer overflow/underflow leading to memory corruption
5. Missing bounds checks before memory operations

Return a JSON object with:
{{
  "verdict": "VULNERABLE|BENIGN|UNCERTAIN",
  "confidence": 0.0-1.0,
  "cwe_guess": "CWE-XXX",
  "vulnerability_type": "buffer_overflow|use_after_free|...",
  "location_hint": "function name or address",
  "explanation": "brief reasoning in 1-2 sentences",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW"
}}

JSON:"""

_PERPLXITY_TEMPLATE = """Complete the following pseudocode snippet with the most likely next line.
Only output the completed line, no explanation.

{prefix}"""

_SELF_CONSISTENCY_TEMPLATE = """As a binary security auditor, determine if this function contains
a memory corruption vulnerability. Provide only a single word: YES or NO.

Function: {function_name}
{pseudocode_summary}
Dangerous calls: {danger_funcs}

Answer (YES/NO):"""

class LLMVulnerabilityDetector:
    """LLM驱动漏洞检测器。

    核心流程:
        1. 伪代码送入LLM做端到端漏洞判断（VulnSignalType.LLM_JUDGMENT）
        2. 统计LLM对代码片段的预测困惑度（VulnSignalType.ANOMALY_SCORE）
        3. 多轮self-consistency投票抑制LLM随机性噪声
        4. 各维度信号加权聚合产出最终评分

    参考:
        - ANVIL: 漏洞检测建模为异常检测问题 (arXiv:2408.16028)
        - Multi-LLM IoT: 三模块语义融合架构 (arXiv:2512.19945)
        - Self-consistency prompting (Wang et al., 2023)
    """

    def __init__(self, model_name: str = "", prefer_local: bool = False,
                 self_consistency_rounds: int = 3):
        self.backend = _make_backend(prefer_local)
        if model_name:
            self.backend.model_name = model_name
        self.consistency_rounds = self_consistency_rounds
        self._cache: Dict[str, Dict] = {}  # prompt_hash → cached_result
        self._stats = defaultdict(int)

    # 核心检测入口

    def detect(self, function_name: str = "", pseudocode: str = "",
               arch: str = "x86_64", fmt: str = "ELF",
               danger_funcs: List[str] = None,
               checksec_info: Dict[str, str] = None) -> LLMVulnReport:
        """对单个函数执行LLM漏洞检测。

        参数:
            function_name: 函数名
            pseudocode: 反编译伪代码
            arch: 目标架构
            fmt: 二进制格式
            danger_funcs: 检测到的危险函数列表
            checksec_info: 二进制保护机制信息

        返回LLMVulnReport，含聚合评分与多维信号。
        """
        t0 = time.time()
        dgs = danger_funcs or []
        signals: List[VulnSignal] = []

        if not pseudocode or len(pseudocode.strip()) < 10:
            return LLMVulnReport(
                function_name=function_name, overall_score=0.0,
                signals=[], verdict="UNCERTAIN", false_positive_risk=0.5,
                analysis_time_ms=0.0, model_used=self.backend.model_name)

        # 信号1: LLM直接判断
        s_direct = self._signal_direct_judgment(function_name, pseudocode,
                                                 arch, fmt, dgs)
        if s_direct:
            signals.append(s_direct)

        # 信号2: 基于危险函数模式做LLM增强判断
        if dgs:
            s_pattern = self._signal_pattern_enhanced(function_name, dgs, pseudocode[:500])
            if s_pattern:
                signals.append(s_pattern)

        # 信号3: self-consistency投票——直接判断低置信度时触发
        if s_direct and s_direct.confidence < 0.7:
            s_votes = self._signal_self_consistency(function_name, pseudocode, dgs)
            if s_votes:
                signals.append(s_votes)

        # 信号4: 困惑度异常评分——token数足够时计算
        if len(pseudocode) > 200:
            s_perpl = self._signal_perplexity_anomaly(pseudocode)
            if s_perpl:
                signals.append(s_perpl)

        # 加权平均聚合——直接判断权重最高
        if signals:
            weights = {
                VulnSignalType.LLM_JUDGMENT: 0.40,
                VulnSignalType.PATTERN_MATCH: 0.25,
                VulnSignalType.SEMANTIC_RISK: 0.20,
                VulnSignalType.ANOMALY_SCORE: 0.15,
            }
            total_weight = sum(weights.get(s.signal_type, 0.10) for s in signals)
            overall = (sum(s.score * weights.get(s.signal_type, 0.10) for s in signals)
                       / max(total_weight, 0.01))
        else:
            overall = 0.0

        # 严重度裁决
        if overall >= 0.7:
            verdict = "VULNERABLE"
        elif overall <= 0.3:
            verdict = "BENIGN"
        else:
            verdict = "UNCERTAIN"

        # 误报风险评估——检查项多但无确凿证据时风险更高
        checksec = checksec_info or {}
        protection_level = sum(1 for v in checksec.values() if v in ("yes", "full"))
        fp_risk = 0.3 if protection_level >= 3 else 0.6

        elapsed_ms = (time.time() - t0) * 1000
        self._stats['total_analyses'] += 1
        if verdict == "VULNERABLE":
            self._stats['vulnerable_found'] += 1

        return LLMVulnReport(
            function_name=function_name, overall_score=round(overall, 3),
            signals=signals, verdict=verdict, false_positive_risk=round(fp_risk, 2),
            analysis_time_ms=round(elapsed_ms, 1),
            model_used=self.backend.model_name)

    # 各信号生成方法

    def _signal_direct_judgment(self, fname: str, pcode: str,
                                 arch: str, fmt: str,
                                 danger_funcs: List[str]) -> Optional[VulnSignal]:
        """LLM端到端漏洞判断——核心信号源。

        使用结构化JSON输出prompt，引导LLM做分类而非自由文本。
        """
        prompt = _VULN_DETECT_TEMPLATE.format(
            function_name=fname, pseudocode=pcode[:3000],
            arch=arch, fmt=fmt,
            danger_funcs=", ".join(danger_funcs[:20]) if danger_funcs else "none")

        cache_key = hashlib.md5(prompt.encode()).hexdigest()
        if cache_key in self._cache:
            logger.debug(f"LLM cache hit for {fname}")
            return self._cache[cache_key]

        raw = self.backend.generate(prompt, max_tokens=512)
        if not raw:
            return None

        parsed = self._parse_json_response(raw)
        if not parsed:
            return None

        score_map = {"CRITICAL": 0.95, "HIGH": 0.75, "MEDIUM": 0.50, "LOW": 0.25}
        sev = parsed.get("severity", "MEDIUM").upper()
        base_score = score_map.get(sev, 0.4)
        # 置信度加权: LLM自报confidence乘入基础分数
        conf = float(parsed.get("confidence", 0.5))
        score = min(1.0, base_score * (0.7 + 0.3 * conf))

        sig = VulnSignal(
            signal_type=VulnSignalType.LLM_JUDGMENT,
            score=round(score, 3), confidence=round(conf, 2),
            location=parsed.get("location_hint", fname),
            evidence=parsed.get("explanation", ""),
            cwe_hint=parsed.get("cwe_guess", ""),
            raw_response=raw[:500])

        self._cache[cache_key] = sig
        return sig

    def _signal_pattern_enhanced(self, fname: str, danger_funcs: List[str],
                                   pcode_preview: str) -> Optional[VulnSignal]:
        # 危险函数模式增强——LLM语义结合静态模式匹配，LLM不可用时回退纯静态评分。
        high_risk = {'gets', 'strcpy', 'sprintf', 'system', 'popen', 'execve',
                      'scanf', 'memcpy', 'strcat', 'getsockopt'}
        med_risk = {'read', 'write', 'fgets', 'snprintf', 'malloc', 'free',
                     'realloc', 'calloc', 'strncpy'}

        dgset = set(d.lower() for d in danger_funcs)
        high_hits = high_risk & dgset
        med_hits = med_risk & dgset

        if not high_hits and not med_hits:
            return None

        # 基础分数——危险函数计数加权
        base_score = min(1.0, len(high_hits) * 0.30 + len(med_hits) * 0.10)

        # LLM增强——判断危险函数使用上下文是否构成实际威胁
        boost = 0.0
        ctx_prompt = (
            f"Function {fname} calls these potentially dangerous functions: "
            f"{', '.join(danger_funcs)}.\n"
            f"Code preview:\n{pcode_preview[:300]}\n"
            f"In one word, does this code contain a vulnerability? YES/NO:")
        raw = self.backend.generate(ctx_prompt, max_tokens=5)
        if raw and "YES" in raw.upper():
            boost = 0.15

        score = min(1.0, base_score + boost)
        return VulnSignal(
            signal_type=VulnSignalType.PATTERN_MATCH,
            score=round(score, 3), confidence=0.6 + 0.2 * boost,
            location=fname,
            evidence=f"Dangerous functions: {', '.join(sorted(high_hits | med_hits))}",
            cwe_hint="CWE-119" if high_hits else "CWE-20")

    def _signal_self_consistency(self, fname: str, pcode: str,
                                   danger_funcs: List[str]) -> Optional[VulnSignal]:
        """Self-consistency投票——同一函数多次独立判断。

        Wang et al. (2023) 论证多次采样取众数可降低LLM随机性噪声。
        简化版：3轮投票，每轮prompt微调以增加多样性。
        """
        if self.consistency_rounds < 2:
            return None

        summary = pcode[:400].replace('\n', ' ')
        dgs_str = ", ".join(danger_funcs[:10]) if danger_funcs else "none"
        votes_yes = 0
        total_votes = 0

        perturbations = ["", " (think step by step)", " (be conservative)"]
        for i in range(min(self.consistency_rounds, len(perturbations))):
            pfx = perturbations[i]
            prompt = _SELF_CONSISTENCY_TEMPLATE.format(
                function_name=fname+f" round {i+1}",
                pseudocode_summary=summary, danger_funcs=dgs_str) + pfx
            raw = self.backend.generate(prompt, max_tokens=5)
            if raw:
                total_votes += 1
                if "YES" in raw.upper():
                    votes_yes += 1

        if total_votes == 0:
            return None

        vote_ratio = votes_yes / total_votes
        # 偏离0.5越远置信度越高，范围0-1
        conf = abs(vote_ratio - 0.5) * 2
        score = vote_ratio

        return VulnSignal(
            signal_type=VulnSignalType.SEMANTIC_RISK,
            score=round(score, 3), confidence=round(conf, 2),
            location=fname,
            evidence=f"Self-consistency: {votes_yes}/{total_votes} voted VULNERABLE",
            cwe_hint="")

    def _signal_perplexity_anomaly(self, pcode: str) -> Optional[VulnSignal]:
        """基于LLM预测困惑度的异常评分。

        ANVIL (arXiv:2408.16028) 核心发现：LLM对漏洞代码的预测损失
        高于正常代码。简化版：计算LLM对代码片段续写的偏差。
        """
        lines = pcode.strip().split('\n')
        if len(lines) < 5:
            return None
        # 采样中间行做预测——排除头尾行
        mid_start = max(1, len(lines) // 3)
        mid_end = min(len(lines) - 1, 2 * len(lines) // 3)
        sample_lines = lines[mid_start:mid_end]
        if len(sample_lines) < 3:
            return None

        anomaly_scores = []
        # 最多采样5行
        for line in sample_lines[:5]:
            prompt = _PERPLXITY_TEMPLATE.format(prefix=line.strip())
            completion = self.backend.generate(prompt, max_tokens=64)
            if not completion:
                continue
            # 编辑距离近似困惑度——差异越大越异常
            dist = _levenshtein(line.strip()[:50], completion.strip()[:50])
            anomaly_scores.append(min(1.0, dist / max(len(line.strip()), 1)))

        if not anomaly_scores:
            return None

        avg_anomaly = sum(anomaly_scores) / len(anomaly_scores)
        return VulnSignal(
            signal_type=VulnSignalType.ANOMALY_SCORE,
            score=round(avg_anomaly, 3), confidence=0.55,
            location="line_anomaly",
            evidence=f"Perplexity anomaly avg={avg_anomaly:.3f} over {len(anomaly_scores)} samples",
            cwe_hint="")

    # 辅助方法

    @staticmethod
    def _parse_json_response(raw: str) -> Optional[Dict]:
        """从LLM回复中提取JSON——容忍markdown代码块包裹。"""
        text = raw.strip()
        # 去除markdown代码块包裹
        for marker in ("```json", "```"):
            if marker in text:
                start = text.find(marker) + len(marker)
                end = text.rfind("```")
                if end > start:
                    text = text[start:end].strip()
                    break
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # 修复常见JSON格式错误（缺少引号、尾部逗号等）
            try:
                # 宽松正则逐字段提取
                import re as _re
                result = {}
                for key in ("verdict", "confidence", "cwe_guess",
                           "vulnerability_type", "location_hint",
                           "explanation", "severity"):
                    pat = _re.search(rf'"{key}"\s*:\s*"?([^",\n}}]+)"?', text)
                    if pat:
                        val = pat.group(1).strip().strip('"')
                        if key == "confidence":
                            try:
                                result[key] = float(val)
                            except ValueError:
                                result[key] = 0.5
                        else:
                            result[key] = val
                return result if result else None
            except Exception:
                return None

    def batch_detect(self, functions: List[Dict]) -> List[LLMVulnReport]:
        """批量漏洞检测——并行处理多个函数。

        每函数参数: {name, pseudocode, arch?, fmt?, danger_funcs?, checksec?}
        返回按overall_score降序排列的报告列表。
        """
        results = []
        # 最大并行数3——避免API限流
        with ThreadPoolExecutor(max_workers=min(3, len(functions))) as pool:
            futures = {}
            for i, func in enumerate(functions):
                f = pool.submit(self.detect,
                                function_name=func.get("name", f"func_{i}"),
                                pseudocode=func.get("pseudocode", ""),
                                arch=func.get("arch", "x86_64"),
                                fmt=func.get("fmt", "ELF"),
                                danger_funcs=func.get("danger_funcs"),
                                checksec_info=func.get("checksec"))
                futures[f] = func

            for future in as_completed(futures):
                try:
                    report = future.result(timeout=60)
                    results.append(report)
                except Exception as e:
                    logger.warning(f"批量检测子任务失败: {e}")

        results.sort(key=lambda r: r.overall_score, reverse=True)
        return results

    def get_stats(self) -> Dict[str, int]:
        """返回检测器运行统计。"""
        return dict(self._stats)

    @property
    def available(self) -> bool:
        return self.backend.is_available()

def _levenshtein(s1: str, s2: str) -> int:
    """编辑距离——DP实现。O(mn)时间，O(min(m,n))空间。"""
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr.append(min(curr[-1] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[-1]

# 模块级便捷函数

def detect_vulnerability_llm(pseudocode: str, function_name: str = "",
                               danger_funcs: List[str] = None,
                               arch: str = "x86_64") -> LLMVulnReport:
    """便捷函数——单次LLM漏洞检测。返回LLMVulnReport。"""
    detector = LLMVulnerabilityDetector()
    return detector.detect(function_name=function_name,
                           pseudocode=pseudocode, arch=arch,
                           danger_funcs=danger_funcs)

def batch_detect_llm(functions: List[Dict]) -> List[LLMVulnReport]:
    """便捷函数——批量LLM漏洞检测。"""
    return LLMVulnerabilityDetector().batch_detect(functions)

# 混合检测器：LLM + 静态分析联合

class HybridVulnDetector:
    """LLM+静态分析混合检测器。

    传统危险函数评分与LLM语义判断融合——LLM发现逻辑漏洞与
    非显式边界条件错误，静态分析捕捉确定性模式。
    参考ANVIL  监督-无监督混合范式。
    """

    def __init__(self, static_scorer=None, llm_detector=None):
        self.static_scorer = static_scorer
        self.llm_detector = llm_detector or LLMVulnerabilityDetector()
        # LLM权重低于静态——代码分析任务LLM仍有幻觉
        self._fusion_weight_llm = 0.45

    def analyze(self, function_name: str, pseudocode: str,
                danger_funcs: List[str] = None,
                static_score: float = 0.0,
                arch: str = "x86_64", checksec: Dict = None) -> Dict[str, Any]:
        """混合分析——产出静态与LLM双维度评分。

        返回:
            {
                "static_score": ..., "llm_score": ..., "hybrid_score": ...,
                "llm_report": LLMVulnReport, "verdict": str,
                "signals_detail": List[str]
            }
        """
        dgs = danger_funcs or []

        # LLM检测
        llm_report = self.llm_detector.detect(
            function_name=function_name, pseudocode=pseudocode,
            arch=arch, danger_funcs=dgs, checksec_info=checksec)

        # 加权融合——静态与LLM分数加权和
        hybrid = static_score * (1 - self._fusion_weight_llm) + \
                 llm_report.overall_score * self._fusion_weight_llm

        if hybrid >= 0.65:
            verdict = "VULNERABLE"
        elif hybrid <= 0.25:
            verdict = "BENIGN"
        else:
            verdict = "REVIEW_NEEDED"

        signals_detail = []
        for sig in llm_report.signals:
            signals_detail.append(
                f"[{sig.signal_type.value}] score={sig.score:.2f} "
                f"conf={sig.confidence:.2f} -> {sig.evidence[:80]}")

        return {
            "function_name": function_name,
            "static_score": round(static_score, 3),
            "llm_score": round(llm_report.overall_score, 3),
            "hybrid_score": round(hybrid, 3),
            "llm_report": llm_report,
            "verdict": verdict,
            "signals_detail": signals_detail,
            "model_used": llm_report.model_used,
            "analysis_time_ms": llm_report.analysis_time_ms,
        }
