import logging
import os
import re
import json
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class ObfuscationKind(Enum):
    OLLVM_BCF = "ollvm_bcf"
    OLLVM_CFF = "ollvm_cff"
    OLLVM_SUB = "ollvm_sub"
    OLLVM_ALL = "ollvm_all"
    CUSTOM_VM = "custom_vm"
    MBA = "mba"
    STRING_ENC = "string_enc"
    NONE = "none"
    UNKNOWN = "unknown"

class StrategyKind(Enum):
    SYMBOLIC = "symbolic"
    PATTERN = "pattern"
    EMULATOR = "emulator"
    ML = "ml"
    HYBRID = "hybrid"


@dataclass
class DeobfStrategy:
    name: str
    kind: StrategyKind
    obfuscation: ObfuscationKind
    parameters: Dict[str, Any] = field(default_factory=dict)
    expected_recovery: float = 0.5
    cost_seconds: float = 60.0


@dataclass
class DeobfAttempt:
    strategy: DeobfStrategy
    success: bool
    recovery_rate: float
    before_score: float
    after_score: float
    elapsed: float
    error: Optional[str] = None
    output_path: Optional[str] = None


@dataclass
class DeobfResult:
    detected_kind: ObfuscationKind
    confidence: float
    attempts: List[DeobfAttempt]
    best_attempt: Optional[DeobfAttempt] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ObfuscationDetector:
    """Obfuscation type detection using heuristic analysis of r2 disassembly."""

    DEFAULT_TIMEOUT = 60

    def detect(self, binary_path: str, func_name: str) -> Tuple[ObfuscationKind, float]:
        try:
            import subprocess
            r = subprocess.run(
                ['r2', '-q', '-c', f'pdf @ {func_name}; q', binary_path],
                capture_output=True, text=True, timeout=self.DEFAULT_TIMEOUT,
                encoding='utf-8', errors='replace'
            )
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
        jmp_density = (cmp + indirect) / max(1, features.get("instructions", 1))
        if jmp_density > 0.4 and indirect > 5:
            scores[ObfuscationKind.OLLVM_CFF] = 0.8
        if cmp > 30 and indirect / max(1, total) > 0.3:
            scores[ObfuscationKind.OLLVM_BCF] = 0.7
        if features.get("xor_count", 0) > 10 and cmp > 5:
            scores[ObfuscationKind.OLLVM_SUB] = 0.4
        if features.get("dispatch_loop", 0) > 0:
            scores[ObfuscationKind.CUSTOM_VM] = 0.7
        if features.get("arith_count", 0) > 50:
            scores[ObfuscationKind.MBA] = 0.5
        if not scores:
            return ObfuscationKind.NONE, 0.0
        best = max(scores.items(), key=lambda kv: kv[1])
        return best[0], best[1]

    def _extract_features(self, text: str) -> Dict[str, int]:
        features = {
            "instructions": 0,
            "indirect_jmp": 0,
            "total_jmp": 0,
            "cmp": 0,
            "xor_count": 0,
            "arith_count": 0,
            "dispatch_loop": 0
        }
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
        if re.search(r"cmp\s+\w+,\s*0x[0-9a-f]+", text) and \
           features["indirect_jmp"] > 5:
            features["dispatch_loop"] = 1
        return features


class RecoveryScorer:
    """Recovery quality scoring."""

    MIN_SCORE = 0.0
    MAX_SCORE = 1.0

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
        score = self.MAX_SCORE - 0.4 * complexity_penalty - \
                0.3 * indirect_penalty - 0.3 * entropy_penalty
        return min(max(score, self.MIN_SCORE), self.MAX_SCORE)

    def _entropy(self, s: str) -> float:
        from collections import Counter
        if not s:
            return 0.0
        cnt = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in cnt.values())


class StrategySelector:
    """Deobfuscation strategy selector."""

    def __init__(self):
        self.recovery_scorer = RecoveryScorer()

    def candidate_strategies(self, obf_kind: ObfuscationKind
                               ) -> List[DeobfStrategy]:
        strategies: List[DeobfStrategy] = []
        if obf_kind == ObfuscationKind.OLLVM_CFF:
            strategies = [
                DeobfStrategy("cff_symbolic", StrategyKind.SYMBOLIC,
                              obf_kind, {"max_iter": 1000},
                              expected_recovery=0.7, cost_seconds=300),
                DeobfStrategy("cff_pattern", StrategyKind.PATTERN,
                              obf_kind, {"dispatch_pattern": True},
                              expected_recovery=0.6, cost_seconds=60),
                DeobfStrategy("cff_emulator", StrategyKind.EMULATOR,
                              obf_kind, {"max_steps": 100000},
                              expected_recovery=0.5, cost_seconds=120)
            ]
        elif obf_kind == ObfuscationKind.OLLVM_BCF:
            strategies = [
                DeobfStrategy("bcf_symbolic", StrategyKind.SYMBOLIC,
                              obf_kind, {"simplify": True},
                              expected_recovery=0.6, cost_seconds=120),
                DeobfStrategy("bcf_pattern", StrategyKind.PATTERN,
                              obf_kind, {"remove_opaque": True},
                              expected_recovery=0.5, cost_seconds=30)
            ]
        elif obf_kind == ObfuscationKind.OLLVM_SUB:
            strategies = [
                DeobfStrategy("sub_simplify", StrategyKind.SYMBOLIC,
                              obf_kind, {"arith_id": True},
                              expected_recovery=0.8, cost_seconds=60)
            ]
        elif obf_kind == ObfuscationKind.CUSTOM_VM:
            strategies = [
                DeobfStrategy("vm_pattern", StrategyKind.PATTERN,
                              obf_kind, {"trace_dispatch": True},
                              expected_recovery=0.5, cost_seconds=600),
                DeobfStrategy("vm_symbolic", StrategyKind.SYMBOLIC,
                              obf_kind, {"max_iter": 5000},
                              expected_recovery=0.4, cost_seconds=900)
            ]
        else:
            strategies = [
                DeobfStrategy("general_simplify", StrategyKind.SYMBOLIC,
                              obf_kind, {}, expected_recovery=0.5,
                              cost_seconds=60)
            ]
        strategies.sort(key=lambda s: s.expected_recovery, reverse=True)
        return strategies


class DeobfOrchestrator:
    """Deobfuscation orchestrator: detect + select + try + pick best."""

    EARLY_STOP_RECOVERY = 0.7
    MIN_SUCCESS_SCORE = 0.3

    def __init__(self, runner: Optional[Any] = None):
        self.detector = ObfuscationDetector()
        self.selector = StrategySelector()
        self.scorer = RecoveryScorer()
        self.runner = runner

    def _try_strategy(self, strategy: DeobfStrategy,
                        binary_path: str, func_name: str) -> DeobfAttempt:
        import time
        start = time.time()
        if self.runner:
            try:
                result = self.runner(strategy, binary_path, func_name)
                after_code = result.get("deobf_code", "")
            except Exception as e:
                return DeobfAttempt(
                    strategy=strategy, success=False,
                    recovery_rate=0.0, before_score=0.0,
                    after_score=0.0, elapsed=time.time() - start,
                    error=str(e)
                )
        else:
            after_code = ""
        before_score = 0.0
        after_score = self.scorer.score(after_code) if after_code else 0.0
        recovery = max(0.0, after_score - before_score)
        return DeobfAttempt(
            strategy=strategy,
            success=bool(after_code) and after_score > self.MIN_SUCCESS_SCORE,
            recovery_rate=recovery,
            before_score=before_score,
            after_score=after_score,
            elapsed=time.time() - start,
            output_path=None
        )

    def deobfuscate(self, binary_path: str, func_name: str) -> DeobfResult:
        kind, conf = self.detector.detect(binary_path, func_name)
        candidates = self.selector.candidate_strategies(kind)
        attempts: List[DeobfAttempt] = []
        for strat in candidates:
            attempt = self._try_strategy(strat, binary_path, func_name)
            attempts.append(attempt)
            if attempt.recovery_rate >= self.EARLY_STOP_RECOVERY:
                break
        best = max(attempts, key=lambda a: a.recovery_rate) if attempts else None
        return DeobfResult(
            detected_kind=kind,
            confidence=conf,
            attempts=attempts,
            best_attempt=best,
            metadata={'binary': binary_path, 'func': func_name}
        )


def auto_deobfuscate(binary_path: str, func_name: str) -> Dict[str, Any]:
    orch = DeobfOrchestrator()
    result = orch.deobfuscate(binary_path, func_name)
    return {
        'success': True,
        'detected_kind': result.detected_kind.value,
        'confidence': result.confidence,
        'attempts': [
            {
                'strategy': a.strategy.name,
                'kind': a.strategy.kind.value,
                'success': a.success,
                'recovery_rate': a.recovery_rate,
                'elapsed': a.elapsed,
                'error': a.error
            }
            for a in result.attempts
        ],
        'best': {
            'strategy': result.best_attempt.strategy.name,
            'recovery_rate': result.best_attempt.recovery_rate
        } if result.best_attempt else None
    }
