import json
import logging
import math
import os
import re
import subprocess
import time as _time_mod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class ObfuscationKind(Enum):
    OLLVM_BCF = "ollvm_bcf"
    OLLVM_CFF = "ollvm_cff"
    OLLVM_SUB = "ollvm_sub"
    OLLVM_ALL = "ollvm_all"
    CUSTOM_VM = "custom_vm"
    MBA = "mba"
    STRING_ENC = "string_enc"
    TIGRESS_VM = "tigress_vm"
    TIGRESS_JIT = "tigress_jit"
    TIGRESS_ENCODE = "tigress_encode"
    NONE = "none"
    UNKNOWN = "unknown"

class StrategyKind(Enum):
    SYMBOLIC = "symbolic"; PATTERN = "pattern"; EMULATOR = "emulator"
    ML = "ml"; HYBRID = "hybrid"


@dataclass
class DeobfStrategy:
    name: str
    kind: StrategyKind
    obfuscation: ObfuscationKind
    parameters: Dict[str, Any] = field(default_factory=dict)
    expected_recovery: float = 0.5
    cost_seconds: float = 60.0
    priority: float = 0.0

    def __post_init__(self):
        if self.cost_seconds > 0:
            efficiency = self.expected_recovery / math.sqrt(max(self.cost_seconds, 1.0))
            self.priority = round(min(efficiency, 1.0), 3)


@dataclass
class DeobfAttempt:
    strategy: DeobfStrategy; success: bool; recovery_rate: float
    before_score: float; after_score: float; elapsed: float
    error: Optional[str] = None; output_path: Optional[str] = None


@dataclass
class DeobfResult:
    detected_kind: ObfuscationKind; confidence: float
    attempts: List[DeobfAttempt]
    best_attempt: Optional[DeobfAttempt] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    compiler_hint: str = ""


# 编译器指纹
_COMPILER_FINGERPRINTS = {
    "gcc": [rb"lea\s+\w+,\s*\[\w+\+0x[\da-f]+\]", rb"endbr64",
            rb"mov\s+eax,\s*0", rb"rep\s+ret"],
    "clang": [rb"xor\s+eax,\s*eax", rb"mov\s+al,\s*1", rb"cmov", rb"set"],
    "msvc": [rb"push\s+ebp\s*\n\s*mov\s+ebp,\s*esp", rb"int\s+3",
             rb"__security_cookie", rb"call\s+__chkstk"],
}
_OLLVM_CLANG_VERSIONS = {
    "ollvm_4": rb"LLVM 4\.0", "ollvm_9": rb"LLVM 9\.0", "ollvm_14": rb"LLVM 14",
}

# 持久化策略有效性存储路径
_DEFAULT_EFFECTIVENESS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".strategy_effectiveness.json")


class ObfuscationDetector:
    """混淆 type detection using heuristic analysis r2 反汇编"""

    DEFAULT_TIMEOUT = 60

    def detect(self, binary_path: str, func_name: str) -> Tuple[ObfuscationKind, float]:
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', f'pdf @ {func_name}; q', binary_path],
                capture_output=True, text=True, timeout=self.DEFAULT_TIMEOUT,
                encoding='utf-8', errors='replace')
        except Exception as e:
            logger.warning(f"Decompilation failed: {e}")
            return ObfuscationKind.NONE, 0.0
        text = r.stdout
        if not text:
            return ObfuscationKind.NONE, 0.0

        features = self._extract_features(text)
        scores: Dict[ObfuscationKind, float] = {}
        indirect = features.get("indirect_jmp", 0)
        total = features.get("total_jmp", 1)
        cmp = features.get("cmp", 0)
        xor_count = features.get("xor_count", 0)
        arith_count = features.get("arith_count", 0)
        instructions = max(features.get("instructions", 1), 1)
        jmp_density = (cmp + indirect) / instructions
        if jmp_density > 0.4 and indirect > 5:
            scores[ObfuscationKind.OLLVM_CFF] = 0.8
        if cmp > 30 and indirect / max(1, total) > 0.3:
            scores[ObfuscationKind.OLLVM_BCF] = 0.7
        if xor_count > 10 and cmp > 5:
            scores[ObfuscationKind.OLLVM_SUB] = 0.4
        if features.get("dispatch_loop", 0) > 0:
            scores[ObfuscationKind.CUSTOM_VM] = 0.7
        if arith_count > 50:
            scores[ObfuscationKind.MBA] = 0.5
        push_count = features.get("push_count", 0)
        pop_count = features.get("pop_count", 0)
        mov_count = features.get("mov_count", 0)
        if push_count > 20 and mov_count / max(1, instructions) > 0.3:
            if push_count > pop_count * 2:
                scores[ObfuscationKind.TIGRESS_VM] = 0.65
        if xor_count > 30 and arith_count / max(1, instructions) > 0.25:
            scores[ObfuscationKind.TIGRESS_ENCODE] = 0.5
        mba_pattern_count = features.get("mba_pattern", 0)
        if mba_pattern_count > 5:
            scores[ObfuscationKind.MBA] = max(scores.get(ObfuscationKind.MBA, 0), 0.7)
        if not scores:
            return ObfuscationKind.NONE, 0.0
        best = max(scores.items(), key=lambda kv: kv[1])
        return best[0], best[1]

    def _extract_features(self, text: str) -> Dict[str, int]:
        features = {
            "instructions": 0, "indirect_jmp": 0, "total_jmp": 0,
            "cmp": 0, "xor_count": 0, "arith_count": 0, "dispatch_loop": 0,
            "push_count": 0, "pop_count": 0, "mov_count": 0, "mba_pattern": 0}
        for line in text.split("\n"):
            stripped = line.strip()
            if stripped.startswith("0x"):
                features["instructions"] += 1
            if "jmp" in stripped:
                features["total_jmp"] += 1
                if re.search(r"jmp\s+(?!0x)\w+", stripped):
                    features["indirect_jmp"] += 1
            if "cmp" in stripped or "test" in stripped:
                features["cmp"] += 1
            if "xor" in stripped:
                features["xor_count"] += 1
            if re.search(r"\b(add|sub|imul|idiv)\b", stripped):
                features["arith_count"] += 1
            if "push" in stripped:
                features["push_count"] += 1
            if "pop" in stripped:
                features["pop_count"] += 1
            if "mov" in stripped:
                features["mov_count"] += 1
            if re.search(r"(and|or|not|xor|shl|shr|rol|ror)\s", stripped):
                combo = re.findall(r"\b(and|or|not|xor|shl|shr)\b", stripped)
                if len(combo) >= 2:
                    features["mba_pattern"] += 1
        if re.search(r"cmp\s+\w+,\s*0x[0-9a-f]+", text) and features["indirect_jmp"] > 5:
            features["dispatch_loop"] = 1
        return features

    def detect_compiler(self, binary_path: str) -> str:
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'pD 2000 @@f; q', binary_path],
                capture_output=True, text=True, timeout=self.DEFAULT_TIMEOUT,
                encoding='utf-8', errors='replace')
            text = r.stdout if r.stdout else ""
        except Exception:
            return ""
        best_compiler, best_score = "", 0
        for compiler, patterns in _COMPILER_FINGERPRINTS.items():
            score = sum(1 for p in patterns if re.search(p, text))
            if score > best_score:
                best_score, best_compiler = score, compiler
        for ver_str, ver_pat in _OLLVM_CLANG_VERSIONS.items():
            if re.search(ver_pat, text):
                return f"clang_{ver_str}"
        return best_compiler if best_score >= 2 else ""


class RecoveryScorer:
    MIN_SCORE = 0.0; MAX_SCORE = 1.0

    def score(self, code: str) -> float:
        if not code:
            return self.MIN_SCORE
        cmp_count = code.count("cmp") + code.count("test")
        total_lines = max(1, code.count("\n"))
        indirect = len(re.findall(r"jmp\s+(?!0x)\w+", code))
        entropy = self._entropy(code)
        complexity_penalty = min(max(cmp_count / total_lines * 2.0, 0.0), 1.0)
        indirect_penalty = min(max(indirect / 20.0, 0.0), 1.0)
        entropy_penalty = min(max(max(0, entropy - 3.0) / 5.0, 0.0), 1.0)
        score = self.MAX_SCORE - 0.4 * complexity_penalty - 0.3 * indirect_penalty - 0.3 * entropy_penalty
        n_strings = len(re.findall(r'"([^"]*)"', code))
        if n_strings > 2:
            score = min(score + min(0.1, n_strings * 0.02), self.MAX_SCORE)
        return min(max(score, self.MIN_SCORE), self.MAX_SCORE)

    def _entropy(self, s: str) -> float:
        if not s:
            return 0.0
        cnt = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in cnt.values())


# 持久化策略有效性存储 - 跨会话学习
# 将每次运行的策略效果存入 JSON，下次运行时用历史数据调整
# 预期恢复率。使用指数衰减权重（最近 10 次会话权重更高）

class _PersistentEffectiveness:
    """JSON-backed persistent storage for strategy effectiveness across sessions"""

    def __init__(self, path: str = _DEFAULT_EFFECTIVENESS_PATH):
        self._path = path
        self._data: Dict[str, Dict[str, List[float]]] = {}
        self._load()

    def _load(self):
        try:
            with open(self._path, 'r', encoding='utf-8') as f:
                self._data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._data = {}

    def save(self):
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            with open(self._path, 'w', encoding='utf-8') as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except OSError as e:
            logger.debug("Cannot persist effectiveness: %s", e)

    def record(self, obf_kind: str, strategy_name: str, recovery: float):
        key = f"{obf_kind}:{strategy_name}"
        if key not in self._data:
            self._data[key] = []
        self._data[key].append(recovery)
        # 只保留最近 20 次记录
        if len(self._data[key]) > 20:
            self._data[key] = self._data[key][-20:]

    def get_historical_recovery(self, obf_kind: str, strategy_name: str) -> Optional[float]:
        key = f"{obf_kind}:{strategy_name}"
        records = self._data.get(key, [])
        if not records:
            return None
        # 指数衰减加权平均：最新记录权重最高
        n = len(records)
        weights = [0.8 ** (n - 1 - i) for i in range(n)]
        weighted_sum = sum(r * w for r, w in zip(records, weights))
        weight_sum = sum(weights)
        return weighted_sum / weight_sum if weight_sum > 0 else None


class StrategySelector:
    def __init__(self, persistence_path: Optional[str] = None):
        self.recovery_scorer = RecoveryScorer()
        self._effectiveness: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._persistence = _PersistentEffectiveness(
            persistence_path or _DEFAULT_EFFECTIVENESS_PATH)

    def record_effectiveness(self, obf_kind: str, strategy_name: str, recovery: float):
        prev = self._effectiveness[obf_kind].get(strategy_name, recovery)
        self._effectiveness[obf_kind][strategy_name] = prev * 0.7 + recovery * 0.3
        self._persistence.record(obf_kind, strategy_name, recovery)

    def candidate_strategies(self, obf_kind: ObfuscationKind) -> List[DeobfStrategy]:
        strategies: List[DeobfStrategy] = []
        if obf_kind == ObfuscationKind.OLLVM_CFF:
            strategies = [
                DeobfStrategy("cff_symbolic", StrategyKind.SYMBOLIC, obf_kind,
                              {"max_iter": 1000}, expected_recovery=0.7, cost_seconds=300),
                DeobfStrategy("cff_pattern", StrategyKind.PATTERN, obf_kind,
                              {"dispatch_pattern": True}, expected_recovery=0.6, cost_seconds=60),
                DeobfStrategy("cff_emulator", StrategyKind.EMULATOR, obf_kind,
                              {"max_steps": 100000}, expected_recovery=0.5, cost_seconds=120)]
        elif obf_kind == ObfuscationKind.OLLVM_BCF:
            strategies = [
                DeobfStrategy("bcf_symbolic", StrategyKind.SYMBOLIC, obf_kind,
                              {"simplify": True}, expected_recovery=0.6, cost_seconds=120),
                DeobfStrategy("bcf_pattern", StrategyKind.PATTERN, obf_kind,
                              {"remove_opaque": True}, expected_recovery=0.5, cost_seconds=30)]
        elif obf_kind == ObfuscationKind.OLLVM_SUB:
            strategies = [
                DeobfStrategy("sub_simplify", StrategyKind.SYMBOLIC, obf_kind,
                              {"arith_id": True}, expected_recovery=0.8, cost_seconds=60)]
        elif obf_kind == ObfuscationKind.CUSTOM_VM:
            strategies = [
                DeobfStrategy("vm_pattern", StrategyKind.PATTERN, obf_kind,
                              {"trace_dispatch": True}, expected_recovery=0.5, cost_seconds=600),
                DeobfStrategy("vm_symbolic", StrategyKind.SYMBOLIC, obf_kind,
                              {"max_iter": 5000}, expected_recovery=0.4, cost_seconds=900)]
        elif obf_kind == ObfuscationKind.MBA:
            strategies = [
                DeobfStrategy("mba_simplify", StrategyKind.SYMBOLIC, obf_kind,
                              {"arith_id": True, "bitblasting": True}, expected_recovery=0.65, cost_seconds=120),
                DeobfStrategy("mba_ml", StrategyKind.ML, obf_kind,
                              {"model": "mba_identity"}, expected_recovery=0.5, cost_seconds=90)]
        elif obf_kind == ObfuscationKind.TIGRESS_VM:
            strategies = [
                DeobfStrategy("tigress_trace", StrategyKind.EMULATOR, obf_kind,
                              {"max_steps": 200000}, expected_recovery=0.35, cost_seconds=1200),
                DeobfStrategy("tigress_pattern", StrategyKind.PATTERN, obf_kind,
                              {"dispatch_detect": True}, expected_recovery=0.4, cost_seconds=300)]
        elif obf_kind == ObfuscationKind.TIGRESS_ENCODE:
            strategies = [
                DeobfStrategy("tigress_decode", StrategyKind.PATTERN, obf_kind,
                              {"xor_key_scan": True, "depth": 3}, expected_recovery=0.55, cost_seconds=45)]
        else:
            strategies = [
                DeobfStrategy("general_simplify", StrategyKind.SYMBOLIC, obf_kind,
                              {}, expected_recovery=0.5, cost_seconds=60)]

        # 融合历史数据
        hist = self._effectiveness.get(obf_kind.value, {})
        for s in strategies:
            if s.name in hist:
                s.expected_recovery = max(s.expected_recovery, hist[s.name])
            # 跨会话持久化数据
            persistent_rec = self._persistence.get_historical_recovery(
                obf_kind.value, s.name)
            if persistent_rec is not None:
                s.expected_recovery = max(s.expected_recovery,
                                          s.expected_recovery * 0.6 + persistent_rec * 0.4)
            s.priority = round(min(
                s.expected_recovery / math.sqrt(max(s.cost_seconds, 1.0)), 1.0), 3)

        strategies.sort(key=lambda s: (s.priority, -s.cost_seconds), reverse=True)
        return strategies

    def persist(self):
        """将内存中的有效性数据写入磁盘。在分析会话结束时调用"""
        self._persistence.save()


class DeobfOrchestrator:
    EARLY_STOP_RECOVERY = 0.7
    MIN_SUCCESS_SCORE = 0.3

    def __init__(self, runner: Optional[Any] = None):
        self.detector = ObfuscationDetector()
        self.selector = StrategySelector()
        self.scorer = RecoveryScorer()
        self.runner = runner

    def _try_strategy(self, strategy: DeobfStrategy,
                      binary_path: str, func_name: str) -> DeobfAttempt:
        start = _time_mod.time()
        if self.runner:
            try:
                result = self.runner(strategy, binary_path, func_name)
                after_code = result.get("deobf_code", "")
            except Exception as e:
                return DeobfAttempt(strategy=strategy, success=False,
                    recovery_rate=0.0, before_score=0.0, after_score=0.0,
                    elapsed=_time_mod.time() - start, error=str(e))
        else:
            after_code = ""
        before_score = 0.0
        after_score = self.scorer.score(after_code) if after_code else 0.0
        recovery = max(0.0, after_score - before_score)
        attempt = DeobfAttempt(strategy=strategy,
            success=bool(after_code) and after_score > self.MIN_SUCCESS_SCORE,
            recovery_rate=recovery, before_score=before_score,
            after_score=after_score, elapsed=_time_mod.time() - start)
        if recovery > 0:
            self.selector.record_effectiveness(
                strategy.obfuscation.value, strategy.name, recovery)
        return attempt

    def deobfuscate(self, binary_path: str, func_name: str) -> DeobfResult:
        kind, conf = self.detector.detect(binary_path, func_name)
        compiler = self.detector.detect_compiler(binary_path)
        candidates = self.selector.candidate_strategies(kind)
        attempts: List[DeobfAttempt] = []
        total_budget, spent = 1800.0, 0.0
        for strat in candidates:
            if spent + strat.cost_seconds > total_budget:
                logger.info("Strategy budget exhausted at %d/%d",
                           len(attempts), len(candidates))
                break
            attempt = self._try_strategy(strat, binary_path, func_name)
            attempts.append(attempt)
            spent += attempt.elapsed if attempt.elapsed > 0 else strat.cost_seconds
            if attempt.recovery_rate >= self.EARLY_STOP_RECOVERY:
                break
        best = max(attempts, key=lambda a: a.recovery_rate) if attempts else None
        self.selector.persist()
        return DeobfResult(detected_kind=kind, confidence=conf,
            attempts=attempts, best_attempt=best,
            metadata={'binary': binary_path, 'func': func_name},
            compiler_hint=compiler)


def auto_deobfuscate(binary_path: str, func_name: str) -> Dict[str, Any]:
    orch = DeobfOrchestrator()
    result = orch.deobfuscate(binary_path, func_name)
    return {
        'success': True,
        'detected_kind': result.detected_kind.value,
        'confidence': result.confidence,
        'compiler_hint': result.compiler_hint,
        'attempts': [{'strategy': a.strategy.name, 'kind': a.strategy.kind.value,
                      'success': a.success, 'recovery_rate': a.recovery_rate,
                      'elapsed': a.elapsed, 'error': a.error} for a in result.attempts],
        'best': {'strategy': result.best_attempt.strategy.name,
                 'recovery_rate': result.best_attempt.recovery_rate}
        if result.best_attempt else None}
