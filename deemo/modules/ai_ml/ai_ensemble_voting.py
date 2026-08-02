# Multi-provider ensemble voting — aggregates verdicts from OpenAI, Ollama, and local heuristics.
# 2026-07-20: fixed indentation bugs, added provider diversity scoring for uncertainty estimation.
# 2026-07-23: 跨模态对比置信度校准（CLAP范式）— 将异源provider视为不同模态，利用 pairwise 一致性矩阵反推信息冗余度，惩罚高度相关provider间的一致性虚高。
# 2026-07-23: EMA时间衰减精度追踪 — 替换简单滑动平均，增强对模型概念漂移的响应速度。
# 2026-07-23: 熵基不确定性量化 — Shannon熵归一化替代CV变异系数，后验概率空间的置信度调节更符合贝叶斯纠偏。
import logging
import os
import time
import json
import math
import threading
from collections import defaultdict, deque

g__log = logging.getLogger(__name__)

def _clamp(val, lo, hi):
    if val is None or lo is None or hi is None:
        return val
    if val < lo:
        return lo
    if val > hi:
        return hi
    return val

class VoteStrategy:
    HARD = "hard"
    SOFT = "soft"
    WEIGHTED_SOFT = "weighted_soft"
    CONFIDENCE_MAX = "confidence_max"
    CONTRASTIVE_RECALIBRATED = "contrastive_recalibrated"

class ModelVerdict:
    __slots__ = ('provider', 'model', 'is_vulnerable', 'confidence', 'vuln_type', 'cwe_id', 'severity', 'explanation', 'latency_ms', 'raw')
    def __init__(self, provider, model, is_vulnerable, confidence, vuln_type="", cwe_id="", severity="low", explanation="", latency_ms=0.0, raw=None):
        self.provider = provider; self.model = model; self.is_vulnerable = is_vulnerable
        self.confidence = confidence; self.vuln_type = vuln_type; self.cwe_id = cwe_id
        self.severity = severity; self.explanation = explanation; self.latency_ms = latency_ms
        self.raw = raw if raw is not None else {}

class EnsembleResult:
    __slots__ = ('is_vulnerable', 'confidence', 'vuln_type', 'cwe_id', 'severity', 'votes', 'strategy', 'agreement_score', 'entropy_uncertainty', 'contrastive_penalty',)
    def __init__(self, is_vulnerable, confidence, vuln_type, cwe_id, severity, votes, strategy, agreement_score,
                 entropy_uncertainty=0.0, contrastive_penalty=0.0):
        self.is_vulnerable = is_vulnerable; self.confidence = confidence; self.vuln_type = vuln_type
        self.cwe_id = cwe_id; self.severity = severity; self.votes = votes
        self.strategy = strategy; self.agreement_score = agreement_score
        self.entropy_uncertainty = entropy_uncertainty; self.contrastive_penalty = contrastive_penalty

class BaseProvider:
    def __init__(self, name, model, weight=1.0, ema_alpha=0.15):
        """ema_alpha: EMA平滑系数，值越大历史衰减越快，对近期反馈更敏感"""
        if name is None: raise ValueError("provider name must not be empty")
        self.name = name; self.model = model; self.weight = weight
        self._accuracy_window = deque(maxlen=200); self._lock = threading.Lock()
        # EMA时间衰减追踪 — 区别于简单滑动平均，赋予近期样本指数级更高的权重
        self._ema_accuracy = 0.7           # 先验值，避免冷启动归零
        self._ema_alpha = ema_alpha
    def analyze(self, code, context): raise NotImplementedError
    def record_feedback(self, correct):
        with self._lock:
            self._accuracy_window.append(1.0 if correct else 0.0)
            # EMA: new_ema = α * sample + (1-α) * old_ema
            self._ema_accuracy = self._ema_alpha * (1.0 if correct else 0.0) + (1.0 - self._ema_alpha) * self._ema_accuracy
    def accuracy(self):
        """返回混合精度：EMA为主，窗口均值作为正则项防止EMA过度漂移"""
        acc_win = self._accuracy_window
        with self._lock:
            if not acc_win:
                return self._ema_accuracy
            total = 0.0; i = 0
            while i < len(acc_win): total += acc_win[i]; i += 1
            window_mean = total / len(acc_win)
            # 0.7 * EMA + 0.3 * window_mean — EMA响应快，窗口均值防过拟合
            return 0.7 * self._ema_accuracy + 0.3 * window_mean
    def dynamic_weight(self):
        a = self.accuracy()
        return max(0.2, min(2.0, a * 1.7 - 0.1))

class OpenAIProvider(BaseProvider):
    def __init__(self, model="gpt-4o-mini", api_key=None, base_url=None, weight=1.0):
        super().__init__("openai", model, weight)
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY"); self.base_url = base_url
    def analyze(self, code, context):
        if code is None: code = ""
        if context is None: context = {}
        start = time.time()
        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key, base_url=self.base_url)
            sys_prompt = "你是一个binarysecurity analysis专家。请based on以下pseudocode/汇编判断是否存在漏洞。严格以 JSON 输出 {vulnerable: bool, confidence: float(0-1), vuln_type: str, cwe_id: str, severity: str, explanation: str}。"
            user_prompt = "代码:\n```\n{}\n```\n\ncontext:\n{}".format(code[:6000], json.dumps(context, ensure_ascii=False)[:1500])
            resp = client.chat.completions.create(model=self.model, messages=[{"role":"system","content":sys_prompt},{"role":"user","content":user_prompt}], temperature=0.0, response_format={"type":"json_object"})
            content = resp.choices[0].message.content; data = json.loads(content)
            latency = (time.time() - start) * 1000
            return ModelVerdict(provider=self.name, model=self.model, is_vulnerable=bool(data.get("vulnerable",False)), confidence=float(data.get("confidence",0.5)), vuln_type=str(data.get("vuln_type","")), cwe_id=str(data.get("cwe_id","")), severity=str(data.get("severity","low")), explanation=str(data.get("explanation","")), latency_ms=latency, raw=data)
        except Exception as e:
            g__log.warning("OpenAI analysis failed: %s", e)
            return ModelVerdict(provider=self.name, model=self.model, is_vulnerable=False, confidence=0.0, latency_ms=(time.time()-start)*1000, raw={"error":str(e)})

class OllamaProvider(BaseProvider):
    def __init__(self, model="qwen2.5-coder:7b", host="http://localhost:11434", weight=1.0):
        super().__init__("ollama", model, weight); self.host = host.rstrip("/")
    def analyze(self, code, context):
        if code is None: code = ""
        if context is None: context = {}
        start = time.time()
        try:
            import requests
            sys_prompt = "你是一个binarysecurity analysis专家。请based on以下pseudocode/汇编判断是否存在漏洞。严格以 JSON 输出。"
            user_prompt = "代码:\n```\n{}\n```\ncontext:\n{}\n输出 JSON: {{\"vulnerable\": bool, \"confidence\": float, \"vuln_type\": str, \"cwe_id\": str, \"severity\": str, \"explanation\": str}}".format(code[:4000], json.dumps(context, ensure_ascii=False)[:1000])
            r = requests.post("{}/api/chat".format(self.host), json={"model":self.model,"messages":[{"role":"system","content":sys_prompt},{"role":"user","content":user_prompt}],"format":"json","stream":False}, timeout=120)
            r.raise_for_status(); data = json.loads(r.json()["message"]["content"])
            latency = (time.time() - start) * 1000
            return ModelVerdict(provider=self.name, model=self.model, is_vulnerable=bool(data.get("vulnerable",False)), confidence=float(data.get("confidence",0.5)), vuln_type=str(data.get("vuln_type","")), cwe_id=str(data.get("cwe_id","")), severity=str(data.get("severity","low")), explanation=str(data.get("explanation","")), latency_ms=latency, raw=data)
        except Exception as e:
            g__log.warning("Ollama analysis failed: %s", e)
            return ModelVerdict(provider=self.name, model=self.model, is_vulnerable=False, confidence=0.0, latency_ms=(time.time()-start)*1000, raw={"error":str(e)})

class LocalHeuristicProvider(BaseProvider):
    s_DANGEROUS_PATTERNS = {"strcpy":("CWE-120","high","buffer_overflow"),"strcat":("CWE-120","high","buffer_overflow"),"sprintf":("CWE-120","high","format_string_buffer"),"gets":("CWE-242","critical","buffer_overflow"),"memcpy":("CWE-805","medium","buffer_overflow"),"system":("CWE-78","high","command_injection"),"execve":("CWE-78","high","command_injection"),"popen":("CWE-78","high","command_injection"),"free":("CWE-416","medium","use_after_free")}
    def __init__(self, weight=0.3): super().__init__("local_heuristic", "rule-v1", weight)
    def analyze(self, code, context):
        if code is None: code = ""
        if context is None: context = {}
        start = time.time(); text = code.lower(); hits = []
        pat_keys = list(self.s_DANGEROUS_PATTERNS.keys()); i = 0
        while i < len(pat_keys):
            pat = pat_keys[i]
            if pat in text: cwe, sev, vt = self.s_DANGEROUS_PATTERNS[pat]; hits.append((cwe, sev, vt))
            i += 1
        if hits:
            cwe, sev, vt = hits[0]; conf = min(0.9, 0.4 + 0.15 * len(hits))
            return ModelVerdict(provider=self.name, model=self.model, is_vulnerable=True, confidence=conf, vuln_type=vt, cwe_id=cwe, severity=sev, explanation="Dangerous function matched: {}".format([h[0] for h in hits]), latency_ms=(time.time()-start)*1000, raw={'matches':[h[2] for h in hits]})
        return ModelVerdict(provider=self.name, model=self.model, is_vulnerable=False, confidence=0.3, latency_ms=(time.time()-start)*1000)

class AIEnsembleVoter:
    """
    多源集成投票器 — 新版支持五种策略（含跨模态对比重校准）。

    跨模态对比校准思路（CLAP范式映射）：
    - 各provider视为异质"模态"（OpenAI/GPT视觉-语言、Ollama本地-推理、Heuristic符号-规则）
    - 维护 pairwise 一致性矩阵 C[pi][pj]，跟踪历史决策中两两provider的标签一致性
    - 高一致性 → 模态间存在信息冗余 → 一致性虚高应被惩罚
    - 重校准因子 = 1 - normalized_correlation，降低冗余provider对后验置信度的过度贡献
    """
    def __init__(self, providers=None, strategy=VoteStrategy.WEIGHTED_SOFT, min_providers=2, max_concurrency=4):
        self.providers = providers or [LocalHeuristicProvider(weight=0.3)]
        self.strategy = strategy; self.min_providers = min_providers; self.max_concurrency = max_concurrency
        # 跨模态 pairwise 一致性矩阵 — 键为 (pi_name, pj_name) 按字典序排序，值为 (一致次数, 总次数)
        self._pairwise_agreement = defaultdict(lambda: [0, 0])
        self._contrastive_lock = threading.Lock()
        self._contrastive_counter = 0  # 触发周期：每 N 次分析才重算一次矩阵，降低计算开销
    def add_provider(self, p):
        if p is None: return
        self.providers.append(p)
    def _vote_hard(self, verdicts):
        if verdicts is None or len(verdicts) == 0: return False, 0.0
        v_cnt = 0; i = 0
        while i < len(verdicts):
            if verdicts[i].is_vulnerable: v_cnt += 1
            i += 1
        nv_cnt = len(verdicts) - v_cnt; denom = max(1, len(verdicts))
        return v_cnt > nv_cnt, max(v_cnt, nv_cnt) / denom
    def _vote_soft(self, verdicts, weighted):
        if verdicts is None or len(verdicts) == 0: return False, 0.0, []
        ws = [v.confidence for v in verdicts]
        ww = [p.dynamic_weight() for p in self.providers[:len(verdicts)]]
        if weighted:
            num = 0.0; den = 0.0; i = 0
            while i < len(ws): num += ws[i] * ww[i]; den += ww[i]; i += 1
        else:
            num = 0.0; i = 0
            while i < len(ws): num += ws[i]; i += 1
            den = len(ws)
        avg = num / max(1e-9, den); return avg >= 0.5, avg, ws
    def _agreement(self, verdicts):
        if verdicts is None or len(verdicts) == 0: return 0.0
        pos = 0; i = 0
        while i < len(verdicts):
            if verdicts[i].is_vulnerable: pos += 1
            i += 1
        return max(pos, len(verdicts) - pos) / len(verdicts)
    def _provider_diversity(self, verdicts):
        """保留兼容旧接口"""
        if verdicts is None or len(verdicts) < 2: return 0.0
        confs = [v.confidence for v in verdicts]; n = len(confs)
        mean = sum(confs) / n
        if mean < 1e-6: return 0.0
        variance = sum((c - mean) ** 2 for c in confs) / n
        return (variance ** 0.5) / mean

    # ========== 熵基不确定性量化 — Shannon entropy over posterior ==========
    def _entropy_uncertainty(self, verdicts):
        """
        将每个provider的输出视为二项后验概率 p_vuln = conf（若标记为vulnerable）或 1-conf（若标记为safe）。
        对所有provider的[p_vuln, 1-p_vuln]做均值得到集成后验分布，计算其Shannon熵。
        最大熵 = ln(2) ≈ 0.693（完全不确定的二项分布），归一化到[0,1]。

        熵高（>0.7归一化）→ providers输出的概率分布分歧大 → 不确定性高 → 应压低置信度。
        这是对原始CV方法的贝叶斯替代，熵在信息论上是最小充分统计量。
        """
        if verdicts is None or len(verdicts) < 2:
            return 0.0
        n = len(verdicts); p_vuln_agg = 0.0
        idx = 0
        while idx < n:
            v = verdicts[idx]
            # 每个provider的二项后验：P(vuln) = 其conf如果判vuln，否则=1-conf
            p = v.confidence if v.is_vulnerable else (1.0 - v.confidence)
            p_vuln_agg += _clamp(p, 0.001, 0.999)
            idx += 1
        p_mean = p_vuln_agg / n
        p_safe = 1.0 - p_mean
        if p_mean <= 1e-6 or p_safe <= 1e-6:
            return 0.0
        # Shannon entropy: H = -(p*ln(p) + (1-p)*ln(1-p))
        entropy = -(p_mean * math.log(p_mean) + p_safe * math.log(p_safe))
        max_entropy = math.log(2.0)  # ≈ 0.693147
        return min(1.0, entropy / max_entropy)

    # ========== 跨模态对比一致性矩阵 & 重校准惩罚因子 ==========
    def _record_pairwise_agreement(self, verdicts):
        """每次集成分析后更新pairwise一致性矩阵 — 低开销，只统计二元标签"""
        prov_names = [v.provider for v in verdicts]
        m = len(prov_names)
        pi = 0
        while pi < m:
            pj = pi + 1
            while pj < m:
                key = (prov_names[pi], prov_names[pj]) if prov_names[pi] < prov_names[pj] else (prov_names[pj], prov_names[pi])
                same_label = 1 if verdicts[pi].is_vulnerable == verdicts[pj].is_vulnerable else 0
                with self._contrastive_lock:
                    self._pairwise_agreement[key][0] += same_label
                    self._pairwise_agreement[key][1] += 1
                pj += 1
            pi += 1

    def _contrastive_recalibration_penalty(self):
        """
        计算跨模态冗余惩罚因子 ∈ [0, 1)。

        CLAP范式核心：不同"模态"的provider如果历史一致性异常高 → 它们的信息源可能高度重叠
        （例如OpenAI和Ollama都被相同的预训练数据偏向）→ 它们的一致性不具备独立证据价值。

        对每对(pi, pj)，计算 agreed_ratio = agreed / total。
        若 agreed_ratio > 0.5（超随机基线），差值累计作为冗余信号。
        最终 penalty = mean(agreed_ratio - 0.5, across all pairs, clamped to positive)。

        penalty = 0  → 各模态完全独立，无需惩罚
        penalty → 1  → 高冗余，大幅压低集成置信度
        """
        with self._contrastive_lock:
            items = list(self._pairwise_agreement.items())
        if not items:
            return 0.0
        excess_sum = 0.0
        pair_count = 0
        idx = 0
        while idx < len(items):
            _, (agreed, total) = items[idx]
            if total >= 3:  # 最少观测数，避免小样本噪声
                agreed_ratio = agreed / total
                excess = max(0.0, agreed_ratio - 0.5)  # 0.5 = 随机二项基线
                excess_sum += excess
                pair_count += 1
            idx += 1
        if pair_count == 0:
            return 0.0
        # 最大可能excess = 0.5 (100%一致 - 50%基线)
        return min(excess_sum / (pair_count * 0.5), 0.95) if pair_count else 0.0

    def ensemble_analyze(self, code, context=None):
        if code is None: code = ""
        context = context or {}; verdicts = []
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.max_concurrency) as pool:
            futures = {pool.submit(p.analyze, code, context): p for p in self.providers}
            fut_items = list(futures.items()); i = 0
            while i < len(fut_items):
                fut, provider = fut_items[i]
                try: v = fut.result(timeout=120); verdicts.append(v)
                except Exception as e:
                    g__log.warning("%s analysis exception: %s", provider.name, e)
                    verdicts.append(ModelVerdict(provider=provider.name, model=provider.model, is_vulnerable=False, confidence=0.0, raw={"error":str(e)}))
                i += 1
        if not verdicts: return EnsembleResult(False, 0.0, "", "", "low", [], self.strategy, 0.0, 0.0, 0.0)

        # 传统投票逻辑 — 四种已有策略 + 新增跨模态重校准
        if self.strategy == VoteStrategy.HARD:
            is_vuln, conf = self._vote_hard(verdicts)
        elif self.strategy == VoteStrategy.SOFT:
            is_vuln, conf, _ = self._vote_soft(verdicts, weighted=False)
        elif self.strategy == VoteStrategy.WEIGHTED_SOFT:
            is_vuln, conf, _ = self._vote_soft(verdicts, weighted=True)
        elif self.strategy == VoteStrategy.CONTRASTIVE_RECALIBRATED:
            # 先按加权软投票得到基础置信度，再以跨模态校准因子压制冗余
            is_vuln, conf, _ = self._vote_soft(verdicts, weighted=True)
        else:
            best = verdicts[0]; i = 1
            while i < len(verdicts):
                if verdicts[i].confidence > best.confidence: best = verdicts[i]
                i += 1
            is_vuln, conf = best.is_vulnerable, best.confidence

        # 聚合漏洞类型/CWE/严重度
        vt_counter = defaultdict(int); cwe_counter = defaultdict(int); sev_counter = defaultdict(int); i = 0
        while i < len(verdicts):
            v = verdicts[i]
            if v.is_vulnerable: vt_counter[v.vuln_type] += 1; cwe_counter[v.cwe_id] += 1; sev_counter[v.severity] += 1
            i += 1
        vt = max(vt_counter.items(), key=lambda kv: kv[1])[0] if vt_counter else ""
        cwe = max(cwe_counter.items(), key=lambda kv: kv[1])[0] if cwe_counter else ""
        sev = max(sev_counter.items(), key=lambda kv: kv[1])[0] if sev_counter else "low"

        # 更新跨模态pairwise一致性矩阵
        self._record_pairwise_agreement(verdicts)

        # 熵基不确定性量化
        entropy_uncertainty = self._entropy_uncertainty(verdicts)

        # 跨模态对比重校准惩罚
        contrastive_penalty = self._contrastive_recalibration_penalty()

        # 置信度综合调节:
        #   基础调节：original CV diversity（保留向后兼容）
        #   增强调节：(1 - entropy_uncertainty) * (1 - contrastive_penalty)
        diversity = self._provider_diversity(verdicts)
        entropy_damp = max(0.25, 1.0 - entropy_uncertainty)       # 高熵 → damp < 1，压低置信度
        contrastive_damp = max(0.3, 1.0 - contrastive_penalty)    # 高冗余 → damp < 1，压低置信度
        # 综合damp取几何平均，平衡两种不确定性来源
        combined_damp = (entropy_damp * contrastive_damp) ** 0.5
        # 保留原有diversity damp，给新调节器留渐入空间 — 取最保守者
        legacy_damp = max(0.4, 1.0 - diversity)
        final_damp = min(combined_damp, legacy_damp)
        adjusted_conf = conf * final_damp

        return EnsembleResult(
            is_vulnerable=is_vuln,
            confidence=round(adjusted_conf, 3),
            vuln_type=vt, cwe_id=cwe, severity=sev,
            votes=verdicts, strategy=self.strategy,
            agreement_score=self._agreement(verdicts),
            entropy_uncertainty=round(entropy_uncertainty, 4),
            contrastive_penalty=round(contrastive_penalty, 4),
        )

def build_default_ensemble(openai_model=None, ollama_model=None):
    providers = [LocalHeuristicProvider(weight=0.3)]
    if openai_model and os.environ.get("OPENAI_API_KEY"): providers.append(OpenAIProvider(model=openai_model, weight=1.0))
    if ollama_model: providers.append(OllamaProvider(model=ollama_model, weight=0.8))
    return AIEnsembleVoter(providers=providers, strategy=VoteStrategy.WEIGHTED_SOFT)
