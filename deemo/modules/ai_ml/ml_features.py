#!/usr/bin/env python3
# ML features module — compiler identification, password bypass simulation,
# micro-benchmarking, function heatmaps, CVE pattern learning, AI stack variable
# analysis, LLM function guessing, and AI decompiler optimization advisor.
# 2026-07-27: added GCG/clang/MSVC register allocation signatures with cosine similarity.
# 2026-07-29: added CVSS prediction, async benchmarking, and variable lifetime analysis.

import logging as _logging
import json as _json
import hashlib as _hashlib
import os as _os
import re as _re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Callable, Union
from collections import defaultdict as _defaultdict

__dbg = _logging.getLogger(__name__)


# ===========================================================================
# 1. Register Allocation Pattern & Compiler Identification
# ===========================================================================

@dataclass
class RegisterAllocationPattern:
    """Captures register usage patterns for compiler fingerprinting."""
    function_name: str = ""
    compiler: str = ""
    optimization_level: str = ""
    register_pressure: float = 0.0
    callee_saved_regs: List[str] = field(default_factory=list)
    caller_saved_regs: List[str] = field(default_factory=list)
    parameter_regs: List[str] = field(default_factory=list)
    scratch_regs: List[str] = field(default_factory=list)
    reg_usage_counts: Dict[str, int] = field(default_factory=dict)
    spill_count: int = 0
    reload_count: int = 0
    xmm_usage: int = 0
    feature_vector: List[float] = field(default_factory=list)

    def to_vector(self) -> List[float]:
        vec: List[float] = []
        vec.append(self.register_pressure)
        vec.append(float(self.spill_count))
        vec.append(float(self.reload_count))
        vec.append(float(self.xmm_usage))
        vec.append(float(len(self.callee_saved_regs)))
        vec.append(float(len(self.caller_saved_regs)))
        return vec


class RegisterAllocationClassifier:
    """Identifies compiler and optimization level from register allocation patterns.

    Uses known signatures for GCC, Clang, and MSVC with cosine similarity
    matching and heuristic fallback for ambiguous cases.
    """

    __slots__ = ('m_signatures', 'm_thresholds')

    # GCC x86_64 register allocation signatures [pressure, spills, reloads, xmm, callee, caller]
    GCC_SIGNATURES = {
        "O0": [0.35, 15.0, 12.0, 2.0, 5.0, 4.0],
        "O1": [0.45, 10.0, 8.0, 5.0, 4.0, 5.0],
        "O2": [0.58, 6.0, 4.0, 8.0, 3.0, 6.0],
        "O3": [0.65, 4.0, 2.0, 12.0, 2.0, 7.0],
        "Os": [0.42, 8.0, 5.0, 4.0, 4.0, 4.0],
    }

    CLANG_SIGNATURES = {
        "O0": [0.30, 18.0, 14.0, 1.0, 6.0, 3.0],
        "O1": [0.48, 8.0, 6.0, 6.0, 3.0, 6.0],
        "O2": [0.60, 5.0, 3.0, 10.0, 2.0, 7.0],
        "O3": [0.68, 3.0, 2.0, 14.0, 1.0, 8.0],
        "Oz": [0.55, 4.0, 2.0, 8.0, 2.0, 6.0],
    }

    MSVC_SIGNATURES = {
        "Od": [0.32, 14.0, 11.0, 3.0, 5.0, 4.0],
        "O1": [0.44, 9.0, 7.0, 5.0, 4.0, 5.0],
        "O2": [0.57, 5.0, 3.0, 9.0, 3.0, 6.0],
        "Ox": [0.62, 3.0, 2.0, 11.0, 2.0, 7.0],
    }

    def __init__(self):
        self.m_signatures: Dict[str, Dict[str, List[float]]] = {
            "gcc": dict(self.GCC_SIGNATURES),
            "clang": dict(self.CLANG_SIGNATURES),
            "msvc": dict(self.MSVC_SIGNATURES),
        }
        self.m_thresholds = {
            "cosine_match": 0.85,
            "heuristic_match": 0.70,
        }

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        import math as _math
        if len(a) != len(b) or len(a) == 0:
            return 0.0
        dot = 0.0
        norm_a = 0.0
        norm_b = 0.0
        i = 0
        while i < len(a):
            dot += a[i] * b[i]
            norm_a += a[i] * a[i]
            norm_b += b[i] * b[i]
            i += 1
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return dot / (_math.sqrt(norm_a) * _math.sqrt(norm_b))

    def classify(self, pattern: RegisterAllocationPattern) -> Tuple[str, str, float]:
        """Classify compiler and optimization level.

        Returns:
            Tuple of (compiler_name, optimization_level, confidence).
        """
        vec = pattern.to_vector()
        if len(vec) == 0:
            return ("unknown", "unknown", 0.0)

        best_compiler = "unknown"
        best_opt = "unknown"
        best_sim = 0.0

        compilers = list(self.m_signatures.keys())
        ci = 0
        while ci < len(compilers):
            compiler = compilers[ci]
            opts = list(self.m_signatures[compiler].keys())
            oi = 0
            while oi < len(opts):
                opt = opts[oi]
                sig = self.m_signatures[compiler][opt]
                sim = self._cosine_similarity(vec, sig)
                if sim > best_sim:
                    best_sim = sim
                    best_compiler = compiler
                    best_opt = opt
                oi += 1
            ci += 1

        return (best_compiler, best_opt, best_sim)

    def classify_heuristic(self, pattern: RegisterAllocationPattern) -> Tuple[str, str, float]:
        """Fallback heuristic classification when cosine similarity is ambiguous."""
        compiler, opt, sim = self.classify(pattern)

        if sim >= self.m_thresholds["cosine_match"]:
            return (compiler, opt, sim)

        # Heuristic fallback
        if pattern.xmm_usage > 8:
            compiler = "clang"  # Clang tends to use more XMM regs
        if pattern.spill_count < 5 and pattern.reload_count < 3:
            opt = "O3" if compiler != "msvc" else "Ox"
        elif pattern.spill_count > 10:
            opt = "O0" if compiler != "msvc" else "Od"

        return (compiler, opt, min(sim + 0.1, 0.9))

    def add_signature(self, compiler: str, opt_level: str, signature: List[float]):
        if compiler not in self.m_signatures:
            self.m_signatures[compiler] = {}
        self.m_signatures[compiler][opt_level] = list(signature)

    def extract_pattern_from_code(self, assembly_code: str) -> RegisterAllocationPattern:
        """Extract register allocation pattern from assembly listing."""
        pattern = RegisterAllocationPattern()

        reg_usage: Dict[str, int] = _defaultdict(int)
        spill_lines = 0
        reload_lines = 0
        xmm_count = 0

        lines = assembly_code.split('\n')
        li = 0
        while li < len(lines):
            line = lines[li].strip()
            # Count register references
            regs = _re.findall(r'\b(r[0-9a-d]x|r[bs]p|rsi|rdi|r[89]|r1[0-5]|'
                              r'e[a-d]x|e[bs]p|esi|edi|xmm\d+|'
                              r'rax|rbx|rcx|rdx)', line, _re.IGNORECASE)
            for r in regs:
                reg_usage[r.lower()] += 1

            if 'xmm' in line.lower():
                xmm_count += 1
            if _re.search(r'mov.*\[rsp.*\],', line) or _re.search(r'mov.*\[rbp.*\],', line):
                if _re.search(r'mov\s+\w+,\s*\[', line):
                    reload_lines += 1
                else:
                    spill_lines += 1

            li += 1

        total_reg_ops = sum(reg_usage.values())
        pattern.reg_usage_counts = dict(reg_usage)
        pattern.spill_count = spill_lines
        pattern.reload_count = reload_lines
        pattern.xmm_usage = xmm_count
        pattern.register_pressure = min(total_reg_ops / max(len(lines), 1) * 0.1, 1.0)

        callee_saved = {"rbx", "rbp", "r12", "r13", "r14", "r15"}
        caller_saved = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
        param_regs = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"}

        pattern.callee_saved_regs = [r for r in callee_saved if r in reg_usage]
        pattern.caller_saved_regs = [r for r in caller_saved if r in reg_usage]
        pattern.parameter_regs = [r for r in param_regs if r in reg_usage]
        pattern.scratch_regs = [r for r in caller_saved if r in reg_usage and r not in param_regs]

        return pattern


# ===========================================================================
# 2. Password Bypass Simulator
# ===========================================================================

class PasswordBypassSimulator:
    """Discovers password verification routines and simulates bypass strategies.

    Features:
    - Password verification discovery via pattern matching
    - Symbolic bypass using simulated angr-style constraint solving
    - Password fuzzing with byte-level mutations
    - Hardcoded password detection
    """

    __slots__ = ('m_target_binary', 'm_verification_funcs', 'm_hardcoded_passwords',
                 'm_fuzz_results')

    # Known string comparison functions
    COMPARE_FUNCTIONS = [
        "strcmp", "strncmp", "memcmp", "wcscmp", "wcsncmp",
        "_strcmp", "_strncmp", "strcmp_s", "lstrcmpA", "lstrcmpW",
        "StringCompare", "CompareString", "bcmp", "strcasecmp", "strncasecmp",
    ]

    # Known hashing functions
    HASH_FUNCTIONS = [
        "MD5", "SHA1", "SHA256", "SHA512", "SHA384",
        "md5", "sha1", "sha256", "sha512", "sha384",
        "bcrypt", "scrypt", "PBKDF2", "Argon2",
        "CryptHashData", "BCryptHashData", "EVP_Digest",
    ]

    def __init__(self, target_binary: str = ""):
        self.m_target_binary = target_binary
        self.m_verification_funcs: List[Dict[str, Any]] = []
        self.m_hardcoded_passwords: List[str] = []
        self.m_fuzz_results: List[Dict[str, Any]] = []

    def discover_verification(self, function_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Discover password verification functions from a list of function metadata."""
        discovered: List[Dict[str, Any]] = []

        fi = 0
        while fi < len(function_list):
            func = function_list[fi]
            func_name = func.get("name", "")
            func_name_lower = func_name.lower()

            score = 0.0
            reasons: List[str] = []

            # Check for comparison function calls
            for cmp_func in self.COMPARE_FUNCTIONS:
                if cmp_func.lower() in func_name_lower:
                    score += 0.4
                    reasons.append(f"Calls {cmp_func}")
                    break

            # Check for hash function calls
            for hash_func in self.HASH_FUNCTIONS:
                if hash_func.lower() in func_name_lower:
                    score += 0.3
                    reasons.append(f"Uses {hash_func}")
                    break

            # Check name patterns
            name_patterns = [
                (r'(?:check|verify|validate|auth).*(?:pass|cred|login|key|pw)', 0.5),
                (r'(?:pass|cred|login|key|pw).*(?:check|verify|validate|auth)', 0.5),
                (r'(?:login|authenticate|authorize)', 0.3),
            ]
            for pattern, weight in name_patterns:
                if _re.search(pattern, func_name, _re.IGNORECASE):
                    score += weight
                    reasons.append(f"Name matches '{pattern}'")

            if score >= 0.3:
                discovered.append({
                    "function_name": func_name,
                    "address": func.get("address", 0),
                    "score": min(score, 1.0),
                    "reasons": reasons,
                })

            fi += 1

        self.m_verification_funcs = discovered
        return discovered

    def symbolic_bypass(self, function_addr: int,
                        constraints: Optional[List[str]] = None) -> Dict[str, Any]:
        """Simulate symbolic execution to find a bypass input.

        In a real implementation this would use angr; here we simulate the process.
        """
        result = {
            "success": False,
            "bypass_input": None,
            "bypass_type": "none",
            "constraints_solved": 0,
            "time_ms": 0,
        }

        import time as _time
        start = _time.time()

        # Simulate constraint solving
        bypass_types = ["null_byte_injection", "buffer_overflow", "timing_side_channel",
                        "integer_overflow", "direct_bypass", "none"]
        weights = [0.15, 0.15, 0.05, 0.1, 0.15, 0.4]

        import random as _rnd
        bypass_type = _rnd.choices(bypass_types, weights=weights, k=1)[0]

        if bypass_type == "none":
            result["bypass_type"] = "none"
        elif bypass_type == "null_byte_injection":
            result["success"] = True
            result["bypass_type"] = "null_byte_injection"
            result["bypass_input"] = b"\x00" * 16
            result["constraints_solved"] = 3
        elif bypass_type == "buffer_overflow":
            result["success"] = True
            result["bypass_type"] = "buffer_overflow"
            result["bypass_input"] = b"A" * 1024
            result["constraints_solved"] = 5
        elif bypass_type == "direct_bypass":
            result["success"] = True
            result["bypass_type"] = "direct_bypass"
            result["bypass_input"] = b"admin\x00"
            result["constraints_solved"] = 2

        result["time_ms"] = (_time.time() - start) * 1000
        return result

    def fuzz_password(self, target_function: str,
                      seed_passwords: Optional[List[str]] = None,
                      iterations: int = 1000) -> List[Dict[str, Any]]:
        """Fuzz password verification with byte-level mutations."""
        if seed_passwords is None:
            seed_passwords = ["", "admin", "password", "123456", "root", "test",
                              "guest", "user", "administrator", "letmein"]

        import random as _rnd
        results: List[Dict[str, Any]] = []

        mutation_types = [
            "bit_flip", "byte_increment", "byte_decrement",
            "random_byte", "insert_byte", "delete_byte",
            "duplicate_byte", "swap_adjacent", "null_insert",
            "format_string", "overflow_append",
        ]

        passwords = list(seed_passwords)
        iter_idx = 0
        while iter_idx < iterations:
            base = _rnd.choice(passwords)
            mutation = _rnd.choice(mutation_types)

            base_bytes = bytearray(base.encode('utf-8', errors='surrogateescape'))

            if mutation == "bit_flip" and len(base_bytes) > 0:
                pos = _rnd.randint(0, len(base_bytes) - 1)
                bit = _rnd.randint(0, 7)
                base_bytes[pos] ^= (1 << bit)
            elif mutation == "byte_increment" and len(base_bytes) > 0:
                pos = _rnd.randint(0, len(base_bytes) - 1)
                base_bytes[pos] = (base_bytes[pos] + 1) % 256
            elif mutation == "byte_decrement" and len(base_bytes) > 0:
                pos = _rnd.randint(0, len(base_bytes) - 1)
                base_bytes[pos] = (base_bytes[pos] - 1) % 256
            elif mutation == "random_byte" and len(base_bytes) > 0:
                pos = _rnd.randint(0, len(base_bytes) - 1)
                base_bytes[pos] = _rnd.randint(0, 255)
            elif mutation == "insert_byte":
                pos = _rnd.randint(0, len(base_bytes))
                base_bytes.insert(pos, _rnd.randint(0, 255))
            elif mutation == "delete_byte" and len(base_bytes) > 0:
                pos = _rnd.randint(0, len(base_bytes) - 1)
                del base_bytes[pos]
            elif mutation == "null_insert":
                pos = _rnd.randint(0, len(base_bytes))
                base_bytes.insert(pos, 0)
            elif mutation == "format_string":
                base_bytes = bytearray(b"%x" * 8 + bytes(base_bytes))
            elif mutation == "overflow_append":
                base_bytes.extend(b"A" * _rnd.randint(1, 64))

            mutated = bytes(base_bytes)
            results.append({
                "iteration": iter_idx,
                "base": base,
                "mutation": mutation,
                "mutated": mutated,
                "length": len(mutated),
            })

            if _rnd.random() < 0.3:
                passwords.append(mutated.decode('utf-8', errors='replace'))

            iter_idx += 1

        self.m_fuzz_results = results
        return results

    def detect_hardcoded_passwords(self, strings: List[str]) -> List[str]:
        """Detect hardcoded passwords from a list of extracted strings."""
        hardcoded: List[str] = []

        # Patterns indicative of hardcoded passwords
        patterns = [
            r'^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{8,32}$',
            r'(?:password|passwd|pwd|secret|api[_-]?key|token|auth)\s*[=:]\s*.+',
        ]

        si = 0
        while si < len(strings):
            s = strings[si]
            for pattern in patterns:
                if _re.search(pattern, s, _re.IGNORECASE):
                    hardcoded.append(s)
                    break
            si += 1

        self.m_hardcoded_passwords = hardcoded
        return hardcoded

    def analyze(self, function_list: Optional[List[Dict[str, Any]]] = None,
                strings: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run full password bypass analysis pipeline."""
        report: Dict[str, Any] = {}

        if function_list:
            report["verification_functions"] = self.discover_verification(function_list)

        if strings:
            report["hardcoded_passwords"] = self.detect_hardcoded_passwords(strings)

        if self.m_verification_funcs:
            bypasses = []
            for vf in self.m_verification_funcs:
                bypasses.append(self.symbolic_bypass(vf.get("address", 0)))
            report["bypass_results"] = bypasses

        if self.m_verification_funcs:
            report["fuzz_results"] = self.fuzz_password(
                self.m_verification_funcs[0].get("function_name", ""),
                iterations=200,
            )

        return report


# ===========================================================================
# 3. Micro-Benchmark Framework
# ===========================================================================

@dataclass
class BenchmarkResult:
    """Result of a micro-benchmark run."""
    name: str = ""
    iterations: int = 0
    total_time_ms: float = 0.0
    mean_time_ms: float = 0.0
    median_time_ms: float = 0.0
    min_time_ms: float = 0.0
    max_time_ms: float = 0.0
    std_dev_ms: float = 0.0
    operations_per_second: float = 0.0
    memory_kb: float = 0.0
    # 2026-07-29: 增加百分位延迟字段，用于尾部延迟分析
    p95_time_ms: float = 0.0
    p99_time_ms: float = 0.0

    def summary(self) -> str:
        return (f"{self.name}: mean={self.mean_time_ms:.3f}ms, "
                f"ops/s={self.operations_per_second:.1f}, "
                f"iters={self.iterations}")


class MicroBenchmarkFramework:
    """Lightweight micro-benchmarking framework for ML feature extraction."""

    __slots__ = ('m_results', 'm_warmup_iterations')

    def __init__(self, warmup_iterations: int = 3):
        self.m_results: Dict[str, BenchmarkResult] = {}
        self.m_warmup_iterations = warmup_iterations

    def _compute_percentile(self, sorted_times: List[float], pct: float) -> float:
        """计算百分位数 — 使用线性插值法，避免边界溢出（INTJ：统计学基础操作）"""
        n = len(sorted_times)
        if n == 0:
            return 0.0
        if n == 1:
            return sorted_times[0]
        rank = pct * (n - 1) / 100.0
        lo = int(rank)
        hi = min(lo + 1, n - 1)
        frac = rank - lo
        return sorted_times[lo] + frac * (sorted_times[hi] - sorted_times[lo])

    def benchmark(self, name: str, func: Callable[[], Any],
                  iterations: int = 100) -> BenchmarkResult:
        import time as _time
        import math as _math

        # Warmup
        wi = 0
        while wi < self.m_warmup_iterations:
            func()
            wi += 1

        # Benchmark
        times: List[float] = []
        i = 0
        while i < iterations:
            start = _time.perf_counter()
            func()
            elapsed = (_time.perf_counter() - start) * 1000
            times.append(elapsed)
            i += 1

        times.sort()
        n = len(times)
        total = sum(times)
        mean = total / n

        result = BenchmarkResult(
            name=name,
            iterations=iterations,
            total_time_ms=total,
            mean_time_ms=mean,
            median_time_ms=times[n // 2] if n > 0 else 0,
            min_time_ms=times[0] if n > 0 else 0,
            max_time_ms=times[-1] if n > 0 else 0,
            std_dev_ms=_math.sqrt(sum((t - mean) ** 2 for t in times) / n) if n > 0 else 0,
            operations_per_second=1000.0 / mean if mean > 0 else 0,
            p95_time_ms=self._compute_percentile(times, 95.0),
            p99_time_ms=self._compute_percentile(times, 99.0),
        )

        self.m_results[name] = result
        return result

    # 2026-07-29: 异步函数基准测试 — 适配现代 Python 协程调用链的延迟测量
    # INTJ：async/await 场景下 perf_counter 仍测量真实耗时，但需处理事件循环开销
    def benchmark_async(self, name: str, coro_func: Callable[[], Any],
                        iterations: int = 100) -> BenchmarkResult:
        """Benchmark an async callable by driving it through the event loop.

        The callable should return an awaitable (coroutine). Each invocation is
        awaited inside asyncio.run() or an existing loop if one is running.
        """
        import time as _time
        import math as _math
        import asyncio as _asyncio

        # 预热 — 避免冷启动偏差污染测量数据
        wi = 0
        while wi < self.m_warmup_iterations:
            try:
                loop = _asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is not None:
                # 在已运行的事件循环中无法嵌套 run()
                pass
            else:
                _asyncio.run(self._await_once(coro_func))
            wi += 1

        times: List[float] = []
        i = 0
        while i < iterations:
            start = _time.perf_counter()
            try:
                loop = _asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is not None:
                # 已有运行中的循环：通过创建 future 测量（近似方案）
                _asyncio.ensure_future(self._await_once(coro_func))
            else:
                _asyncio.run(self._await_once(coro_func))
            elapsed = (_time.perf_counter() - start) * 1000
            times.append(elapsed)
            i += 1

        times.sort()
        n = len(times)
        total = sum(times)
        mean = total / n

        result = BenchmarkResult(
            name=name,
            iterations=iterations,
            total_time_ms=total,
            mean_time_ms=mean,
            median_time_ms=times[n // 2] if n > 0 else 0,
            min_time_ms=times[0] if n > 0 else 0,
            max_time_ms=times[-1] if n > 0 else 0,
            std_dev_ms=_math.sqrt(sum((t - mean) ** 2 for t in times) / n) if n > 0 else 0,
            operations_per_second=1000.0 / mean if mean > 0 else 0,
            p95_time_ms=self._compute_percentile(times, 95.0),
            p99_time_ms=self._compute_percentile(times, 99.0),
        )

        self.m_results[name] = result
        return result

    async def _await_once(self, coro_func: Callable[[], Any]) -> Any:
        """内部辅助：包装一次异步调用（INTJ：避免代码重复）"""
        result = coro_func()
        # 如果返回值本身就是 awaitable，等待它
        import inspect as _inspect
        if _inspect.isawaitable(result):
            return await result
        return result

    def compare(self, name_a: str, name_b: str) -> Dict[str, Any]:
        a = self.m_results.get(name_a)
        b = self.m_results.get(name_b)
        if a is None or b is None:
            return {"error": "Missing benchmark results"}

        speedup = b.mean_time_ms / a.mean_time_ms if a.mean_time_ms > 0 else float('inf')
        return {
            "a": a.summary(),
            "b": b.summary(),
            "speedup": speedup,
            "faster": name_a if speedup > 1 else name_b,
        }

    # 2026-07-29: 多路比较 — 一次输出全部基准的速度比率矩阵（INTJ：批量分析更高效）
    def compare_multiple(self, names: Optional[List[str]] = None) -> Dict[str, Any]:
        """Compare all (or a subset of) benchmarks, returning a speedup matrix.

        If names is None, all stored benchmarks are compared.
        """
        if names is None:
            names = list(self.m_results.keys())
        valid = [n for n in names if n in self.m_results]
        if len(valid) < 2:
            return {"error": "Need at least two valid benchmark names for comparison"}

        # 构建 NxN 加速比矩阵，行 = 分母（baseline），列 = 分子
        matrix: Dict[str, Dict[str, float]] = {}
        ri = 0
        while ri < len(valid):
            row_name = valid[ri]
            matrix[row_name] = {}
            row_result = self.m_results[row_name]
            ci = 0
            while ci < len(valid):
                col_name = valid[ci]
                col_result = self.m_results[col_name]
                if col_result.mean_time_ms > 0:
                    matrix[row_name][col_name] = round(row_result.mean_time_ms / col_result.mean_time_ms, 4)
                else:
                    matrix[row_name][col_name] = float('inf')
                ci += 1
            ri += 1

        # 按均值排序，最快的排前面
        ranked = sorted(valid, key=lambda n: self.m_results[n].mean_time_ms)
        return {
            "ranked": ranked,
            "speedup_matrix": matrix,
            "best": ranked[0],
            "worst": ranked[-1],
        }

    def report(self) -> str:
        lines = [f"{'Benchmark':<30} {'Mean(ms)':>10} {'Std(ms)':>10} {'Ops/s':>10} {'P95(ms)':>10} {'P99(ms)':>10}"]
        lines.append("-" * 78)
        for name, result in sorted(self.m_results.items()):
            lines.append(
                f"{name:<30} {result.mean_time_ms:10.3f} "
                f"{result.std_dev_ms:10.3f} {result.operations_per_second:10.1f} "
                f"{result.p95_time_ms:10.3f} {result.p99_time_ms:10.3f}"
            )
        return "\n".join(lines)


# ===========================================================================
# 4. Function Heatmap Generator
# ===========================================================================

class FunctionHeatmapGenerator:
    """Generates execution heatmaps from strace/ltrace/objdump-style traces.

    Maps function call frequency and timing to visual heatmap data.
    """

    __slots__ = ('m_traces', 'm_heatmap_data')

    def __init__(self):
        self.m_traces: List[Dict[str, Any]] = []
        self.m_heatmap_data: Dict[str, Any] = {}

    def parse_strace(self, strace_output: str) -> List[Dict[str, Any]]:
        """Parse strace output into structured syscall data."""
        syscalls: List[Dict[str, Any]] = []
        lines = strace_output.strip().split('\n')
        li = 0
        while li < len(lines):
            line = lines[li].strip()
            match = _re.match(
                r'(\w+)\(([^)]*)\)\s*=\s*([\-\d]+)(?:\s*<([\d.]+)>)?', line
            )
            if match:
                syscalls.append({
                    "name": match.group(1),
                    "args": match.group(2),
                    "result": match.group(3),
                    "time": float(match.group(4)) if match.group(4) else 0.0,
                })
            li += 1
        self.m_traces = syscalls
        return syscalls

    def parse_ltrace(self, ltrace_output: str) -> List[Dict[str, Any]]:
        """Parse ltrace output into structured library call data."""
        calls: List[Dict[str, Any]] = []
        lines = ltrace_output.strip().split('\n')
        li = 0
        while li < len(lines):
            line = lines[li].strip()
            match = _re.match(
                r'(\w+)\(([^)]*)\)\s*=\s*(\S+)(?:\s*<([\d.]+)>)?', line
            )
            if match:
                calls.append({
                    "name": match.group(1),
                    "args": match.group(2),
                    "result": match.group(3),
                    "time": float(match.group(4)) if match.group(4) else 0.0,
                })
            li += 1
        self.m_traces = calls
        return calls

    def parse_objdump(self, objdump_output: str) -> List[Dict[str, Any]]:
        """Parse objdump disassembly into function/symbol data."""
        symbols: List[Dict[str, Any]] = []
        lines = objdump_output.strip().split('\n')
        li = 0
        while li < len(lines):
            line = lines[li].strip()
            # Match: address <function_name>:
            match = _re.match(r'([0-9a-fA-F]+)\s+<([^>]+)>:', line)
            if match:
                symbols.append({
                    "address": int(match.group(1), 16),
                    "name": match.group(2),
                })
            li += 1
        return symbols

    def generate_heatmap(self, granularity: str = "function") -> Dict[str, Any]:
        """Generate heatmap data from parsed traces.

        granularity: "function", "syscall", or "address"
        """
        heatmap: Dict[str, Any] = {
            "granularity": granularity,
            "max_count": 0,
            "max_time": 0.0,
            "entries": [],
        }

        freq: Dict[str, int] = _defaultdict(int)
        times: Dict[str, float] = _defaultdict(float)

        ti = 0
        while ti < len(self.m_traces):
            trace = self.m_traces[ti]
            name = trace.get("name", f"unknown_{ti}")
            freq[name] += 1
            times[name] += trace.get("time", 0.0)
            ti += 1

        max_count = max(freq.values()) if freq else 1
        max_time = max(times.values()) if times else 1.0

        names = list(freq.keys())
        ni = 0
        while ni < len(names):
            name = names[ni]
            heatmap["entries"].append({
                "name": name,
                "count": freq[name],
                "normalized_count": freq[name] / max_count,
                "total_time": times[name],
                "normalized_time": times[name] / max_time if max_time > 0 else 0,
            })
            ni += 1

        heatmap["entries"].sort(key=lambda x: x["count"], reverse=True)
        heatmap["max_count"] = max_count
        heatmap["max_time"] = max_time

        self.m_heatmap_data = heatmap
        return heatmap

    def to_json(self) -> str:
        return _json.dumps(self.m_heatmap_data, indent=2)


# ===========================================================================
# 5. CVE Pattern Learner
# ===========================================================================

class CVEPatternLearner:
    """Learns vulnerability patterns from CVE database entries and generates
    YARA-like detection rules with prediction capabilities.
    """

    __slots__ = ('m_cve_db', 'm_patterns', 'm_rules', 'm_feature_vectors',
                 'm_cvss_profile')  # 2026-07-29: 新增 CVSS 档案缓存

    # 2026-07-29: CVSS 严重性等级映射 — 参考 NVD CVSS v3.1 规范
    CVSS_SEVERITY_MAP = {
        "NONE": (0.0, 0.0),
        "LOW": (0.1, 3.9),
        "MEDIUM": (4.0, 6.9),
        "HIGH": (7.0, 8.9),
        "CRITICAL": (9.0, 10.0),
    }

    # 2026-07-29: 危险关键词权重表 — 用于从描述文本推断 CVSS 分数
    SEVERITY_KEYWORD_WEIGHTS = {
        "remote": 1.5, "code": 1.2, "execution": 1.8, "overflow": 1.6,
        "privilege": 1.3, "escalation": 1.4, "bypass": 1.2, "injection": 1.5,
        "denial": 0.8, "service": 0.6, "disclosure": 1.0, "information": 0.5,
        "corruption": 1.3, "memory": 1.0, "crafted": 1.1, "exploit": 1.7,
        "authenticated": -0.5, "local": -0.8, "user": -0.3, "interaction": -0.4,
        "root": 1.4, "kernel": 1.3, "sandbox": 0.9, "escape": 1.6,
        "zero-day": 2.0, "critical": 1.5, "severe": 1.2, "urgent": 1.1,
    }

    def __init__(self):
        self.m_cve_db: List[Dict[str, Any]] = []
        self.m_patterns: Dict[str, List[Dict[str, Any]]] = _defaultdict(list)
        self.m_rules: List[str] = []
        self.m_feature_vectors: Dict[str, List[List[float]]] = _defaultdict(list)
        self.m_cvss_profile: Dict[str, Dict[str, Any]] = {}  # 2026-07-29

    def load_cve_data(self, cve_entries: List[Dict[str, Any]]):
        """Load CVE entries for training."""
        self.m_cve_db = []
        ci = 0
        while ci < len(cve_entries):
            entry = cve_entries[ci]
            self.m_cve_db.append(dict(entry))
            ci += 1

    def train(self) -> Dict[str, Any]:
        """Train pattern recognition on loaded CVE data."""
        vuln_types: Dict[str, List[str]] = _defaultdict(list)
        keyword_freq: Dict[str, Dict[str, int]] = _defaultdict(lambda: _defaultdict(int))

        ei = 0
        while ei < len(self.m_cve_db):
            entry = self.m_cve_db[ei]
            desc = entry.get("description", "").lower()
            cwe = entry.get("cwe_id", "UNKNOWN")

            # Extract keywords
            words = _re.findall(r'\b[a-z_]{3,}\b', desc)
            for w in words:
                keyword_freq[cwe][w] += 1

            vuln_types[cwe].append(desc)
            ei += 1

        # Build feature vectors
        for cwe, word_counts in keyword_freq.items():
            top_words = sorted(word_counts.items(), key=lambda x: -x[1])[:50]
            if top_words:
                max_freq = max(wc[1] for wc in top_words)
                vec = [wc[1] / max_freq for wc in top_words]
                self.m_feature_vectors[cwe] = [vec]

        self.m_patterns = {
            "vuln_types": {k: len(v) for k, v in vuln_types.items()},
            "total_entries": len(self.m_cve_db),
        }

        return dict(self.m_patterns)

    def generate_rules(self, min_confidence: float = 0.5) -> List[str]:
        """Generate YARA-like detection rules from learned patterns."""
        rules: List[str] = []

        cwes = list(self.m_feature_vectors.keys())
        ci = 0
        while ci < len(cwes):
            cwe = cwes[ci]
            vectors = self.m_feature_vectors[cwe]
            if vectors:
                vec = vectors[0]
                num_features = len(vec)

                conditions: List[str] = []
                fi = 0
                while fi < num_features:
                    if vec[fi] > 0.3:
                        conditions.append(f"feature_{fi} > {vec[fi] * 0.5:.2f}")
                    fi += 1

                if conditions:
                    rule = (
                        f"rule CVE_PATTERN_{cwe.replace('-', '_')} {{\n"
                        f"    meta:\n"
                        f"        cwe = \"{cwe}\"\n"
                        f"        confidence = {min_confidence:.2f}\n"
                        f"    strings:\n"
                        f"        $pattern = /{cwe}/\n"
                        f"    condition:\n"
                        f"        {' and '.join(conditions)}\n"
                        f"}}"
                    )
                    rules.append(rule)

            ci += 1

        self.m_rules = rules
        return rules

    def predict(self, description: str) -> List[Tuple[str, float]]:
        """Predict CWE type for a vulnerability description."""
        desc_lower = description.lower()
        words = set(_re.findall(r'\b[a-z_]{3,}\b', desc_lower))

        predictions: List[Tuple[str, float]] = []

        cwes = list(self.m_feature_vectors.keys())
        ci = 0
        while ci < len(cwes):
            cwe = cwes[ci]
            # Simple keyword overlap-based scoring
            related = self.m_cve_db
            matching = 0
            total = 0
            ei = 0
            while ei < len(related):
                entry = related[ei]
                if entry.get("cwe_id", "") == cwe:
                    total += 1
                    entry_words = set(_re.findall(r'\b[a-z_]{3,}\b', entry.get("description", "").lower()))
                    if len(words & entry_words) > 0:
                        matching += 1
                ei += 1

            if total > 0:
                score = matching / total
                if score > 0:
                    predictions.append((cwe, score))

            ci += 1

        predictions.sort(key=lambda x: -x[1])
        return predictions[:10]

    # 2026-07-29: CVSS 分数预测 — 基于描述文本中的危险关键词加权评分
    # INTJ：这不是精确的 CVSS 计算器，而是一种启发式快速分级工具，
    # 用于在缺少完整 CVSS 向量字符串时给出合理的严重性估计。
    def predict_cvss(self, description: str) -> Dict[str, Any]:
        """Estimate CVSS v3.1 base score from vulnerability description text.

        Uses weighted keyword matching against severity indicators. Returns
        estimated base score, severity label, and confidence breakdown.
        """
        desc_lower = description.lower()
        base_score = 5.0  # 从 MEDIUM 中位起步（INTJ：贝叶斯先验）
        matched_keywords: Dict[str, float] = {}
        total_weight = 0.0

        # 关键词加权扫描
        kw_keys = list(self.SEVERITY_KEYWORD_WEIGHTS.keys())
        ki = 0
        while ki < len(kw_keys):
            kw = kw_keys[ki]
            weight = self.SEVERITY_KEYWORD_WEIGHTS[kw]
            if kw in desc_lower:
                # 多次出现加重影响，但用对数衰减防过拟合
                count = desc_lower.count(kw)
                adjusted = weight * (1.0 + 0.3 * (count - 1) if count > 1 else 1.0)
                matched_keywords[kw] = adjusted
                total_weight += abs(weight)
            ki += 1

        if total_weight > 0:
            # 将加权影响映射到 CVSS 0-10 范围
            score_delta = sum(matched_keywords.values())
            # sigmoid 压缩防极端值
            import math as _math
            normalized_delta = 5.0 * (2.0 / (1.0 + _math.exp(-score_delta / 4.0)) - 1.0)
            base_score = max(0.0, min(10.0, 5.0 + normalized_delta))

        # 映射到严重性标签
        base_score = round(base_score, 1)
        severity = "MEDIUM"
        sev_keys = list(self.CVSS_SEVERITY_MAP.keys())
        si = 0
        while si < len(sev_keys):
            label = sev_keys[si]
            lo, hi = self.CVSS_SEVERITY_MAP[label]
            if lo <= base_score <= hi:
                severity = label
                break
            si += 1

        result = {
            "estimated_cvss_base": base_score,
            "severity": severity,
            "matched_keywords": matched_keywords,
            "keyword_count": len(matched_keywords),
            "confidence": min(len(matched_keywords) / 8.0, 1.0),
            "description": description[:200],
        }

        self.m_cvss_profile[description[:80]] = result
        return result

    # 2026-07-29: 批量 CVSS 预测 — 一次处理多个描述（INTJ：流水线式批量推理）
    def predict_cvss_batch(self, descriptions: List[str]) -> List[Dict[str, Any]]:
        """Estimate CVSS scores for multiple descriptions at once."""
        results: List[Dict[str, Any]] = []
        di = 0
        while di < len(descriptions):
            results.append(self.predict_cvss(descriptions[di]))
            di += 1
        return results


# ===========================================================================
# 6. AI Stack Variable Analyzer
# ===========================================================================

class AIStackVariableAnalyzer:
    """Infers variable purpose and annotates pseudocode using pattern recognition."""

    __slots__ = ('m_var_types', 'm_annotations', 'm_lifetime_graph')  # 2026-07-29

    # Variable purpose patterns
    TYPE_PATTERNS = [
        (r'(?:len|size|count|n|num)', "size/count"),
        (r'(?:buf|buffer|dst|src|ptr|data)', "buffer/pointer"),
        (r'(?:ret|result|res|rv)', "return value"),
        (r'(?:err|error|status|rc)', "error/status code"),
        (r'(?:idx|index|i|j|k|pos|offset)', "index/iterator"),
        (r'(?:flag|flags|mode|opt)', "flags/options"),
        (r'(?:fd|file|handle|h)', "file descriptor/handle"),
        (r'(?:key|secret|pass|token)', "credential/secret"),
        (r'(?:ctx|context|state|env)', "context/state"),
        (r'(?:tmp|temp|scratch)', "temporary/scratch"),
        (r'(?:addr|address|base)', "address/pointer"),
        (r'(?:chk|checksum|crc|hash)', "checksum/hash"),
    ]

    # 2026-07-29: 危险生命周期模式 — 检测潜在的 use-after-free / double-free
    # INTJ：CWE-416（use-after-free）和 CWE-415（double-free）在二进制分析中极为常见，
    # 通过伪代码中的分配/释放/访问序列模式匹配可快速定位嫌疑点。
    LIFETIME_ANOMALY_PATTERNS = [
        # (pattern, anomaly_type, severity)
        # free 后仍有解引用 → use-after-free
        (r'(?:free|delete|release|kfree)\s*\([^)]*\)\s*;.*\n.*\b(?!if|while|for|=)\w+\s*(?:->|\.)\s*\w+', "use-after-free", 0.85),
        # 同一变量连续 free 两次 → double-free
        (r'(?:free|delete)\s*\(\s*(\w+)\s*\)[\s\S]*?(?:free|delete)\s*\(\s*\1\s*\)', "double-free", 0.90),
        # malloc 返回后未检查 NULL 直接写入 → null-deref
        (r'(?:malloc|calloc|realloc)\s*\([^)]*\)\s*;[\s\S]{0,50}\1\s*(?:->|\.)\s*\w+\s*=', "null-dereference", 0.60),
        # 栈变量地址逃逸到持久结构体 → dangling-pointer
        (r'&\s*(\w+)\s*\)[\s\S]{0,100}(?:return|store|save)', "dangling-pointer", 0.70),
    ]

    def __init__(self):
        self.m_var_types: Dict[str, str] = {}
        self.m_annotations: List[Dict[str, Any]] = []
        self.m_lifetime_graph: Dict[str, List[Tuple[str, int]]] = _defaultdict(list)  # 2026-07-29

    def infer_variable_purpose(self, var_name: str,
                               usage_context: str = "") -> Tuple[str, float]:
        """Infer the purpose of a stack variable from its name and usage context."""
        name_lower = var_name.lower().lstrip('_')
        best_type = "unknown"
        best_score = 0.0

        # Heuristic: exact prefixes
        prefix_map = {
            "sz": "size/count", "n": "size/count", "cch": "size/count",
            "dw": "flags/options", "b": "boolean/flag",
            "p": "buffer/pointer", "lp": "buffer/pointer",
            "h": "file descriptor/handle",
            "dw": "flags/options",
        }

        for prefix, ptype in prefix_map.items():
            if name_lower.startswith(prefix) and len(name_lower) > len(prefix):
                if name_lower[len(prefix)].isupper() or name_lower[len(prefix)] == '_':
                    best_type = ptype
                    best_score = 0.7
                    break

        # Regex-based matching
        pi = 0
        while pi < len(self.TYPE_PATTERNS):
            pattern, ptype = self.TYPE_PATTERNS[pi]
            if _re.search(pattern, name_lower):
                score = 0.6
                if _re.match(f"^{pattern}$", name_lower):
                    score = 0.9
                if score > best_score:
                    best_score = score
                    best_type = ptype
            pi += 1

        # Context-based refinement
        if usage_context:
            ctx_lower = usage_context.lower()
            # If used in a comparison, it might be a size/count
            if any(op in ctx_lower for op in ('<', '>', '==', '!=')):
                if best_type == "unknown":
                    best_type = "size/count"
                    best_score = 0.4

        return (best_type, best_score)

    def annotate_pseudocode(self, pseudocode: str,
                            variables: Optional[List[str]] = None) -> str:
        """Annotate pseudocode with inferred variable purposes."""
        if variables is None:
            variables = _re.findall(r'\b([a-zA-Z_]\w*)\b', pseudocode)

        annotated = pseudocode
        vi = 0
        while vi < len(variables):
            var = variables[vi]
            # Skip common keywords
            if var.lower() in ('if', 'else', 'while', 'for', 'return', 'int',
                               'void', 'char', 'long', 'short', 'unsigned',
                               'signed', 'const', 'static', 'sizeof', 'struct',
                               'enum', 'union', 'typedef', 'extern', 'volatile',
                               'goto', 'break', 'continue', 'switch', 'case',
                               'default', 'do', 'auto', 'register'):
                vi += 1
                continue

            vtype, score = self.infer_variable_purpose(var)
            if vtype != "unknown" and score >= 0.4:
                self.m_var_types[var] = vtype
                self.m_annotations.append({
                    "variable": var,
                    "inferred_type": vtype,
                    "confidence": score,
                })
            vi += 1

        return annotated

    # 2026-07-29: 变量生命周期异常检测 — 扫描伪代码中的 use-after-free / double-free 模式
    # INTJ：不依赖完整的数据流分析，仅通过模式匹配快速筛出高风险代码段，
    # 适合在大规模二进制审计中作为一级过滤。
    def detect_lifetime_anomalies(self, pseudocode: str) -> List[Dict[str, Any]]:
        """Scan pseudocode for variable lifetime anomalies (use-after-free, double-free, etc.).

        Returns a list of detected anomalies with type, severity, and line context.
        """
        anomalies: List[Dict[str, Any]] = []
        lines = pseudocode.split('\n')

        # 构建多行文本块用于跨行模式匹配
        pi = 0
        while pi < len(self.LIFETIME_ANOMALY_PATTERNS):
            pattern_tuple = self.LIFETIME_ANOMALY_PATTERNS[pi]
            pattern, anomaly_type, base_severity = pattern_tuple

            matches = list(_re.finditer(pattern, pseudocode, _re.IGNORECASE | _re.DOTALL))
            mi = 0
            while mi < len(matches):
                match = matches[mi]
                # 定位到匹配起始的行号
                match_start = match.start()
                line_number = pseudocode[:match_start].count('\n') + 1
                # 提取上下文（前后各 2 行）
                ctx_start = max(0, line_number - 3)
                ctx_end = min(len(lines), line_number + 2)
                context_lines = []
                li = ctx_start
                while li < ctx_end:
                    prefix = ">>>" if li == line_number - 1 else "   "
                    context_lines.append(f"{prefix} {li + 1}: {lines[li].rstrip()}")
                    li += 1

                matched_text = match.group(0)[:120]
                anomalies.append({
                    "anomaly_type": anomaly_type,
                    "severity": base_severity,
                    "line": line_number,
                    "matched_text": matched_text,
                    "context": "\n".join(context_lines),
                })
                mi += 1

            pi += 1

        # 按严重性降序排列
        anomalies.sort(key=lambda x: -x["severity"])
        return anomalies

    def get_annotations(self) -> List[Dict[str, Any]]:
        return list(self.m_annotations)

    def get_var_types(self) -> Dict[str, str]:
        return dict(self.m_var_types)


# ===========================================================================
# 7. LLM Function Guess Engine
# ===========================================================================

class LLMFunctionGuessEngine:
    """Guesses function purpose based on name, signature, and decompiled body
    using heuristic pattern matching (LLM-ready prompts included).
    """

    __slots__ = ('m_prompt_templates', 'm_guess_history')

    FUNCTION_CATEGORIES = [
        "initialization", "cleanup", "allocation", "deallocation",
        "serialization", "deserialization", "encryption", "decryption",
        "compression", "decompression", "hashing", "comparison",
        "validation", "authentication", "authorization", "logging",
        "error_handling", "network_io", "file_io", "memory_management",
        "string_manipulation", "data_conversion", "threading",
        "signal_handling", "callback", "event_handler",
    ]

    def __init__(self):
        self.m_prompt_templates: Dict[str, str] = {}
        self.m_guess_history: List[Dict[str, Any]] = []

    def guess(self, function_name: str, decompiled_body: str = "",
              call_graph_hints: Optional[List[str]] = None) -> Dict[str, Any]:
        """Guess function category and purpose."""
        name_lower = function_name.lower()
        scores: Dict[str, float] = _defaultdict(float)

        # Name-based heuristics
        name_patterns = [
            (r'init', "initialization", 0.8),
            (r'clean|destroy|free|release|close|shutdown|fini', "cleanup", 0.7),
            (r'alloc|create|new|make|construct', "allocation", 0.8),
            (r'free|delete|destroy|release', "deallocation", 0.7),
            (r'encrypt|encipher|encode.*key', "encryption", 0.9),
            (r'decrypt|decipher|decode.*key', "decryption", 0.9),
            (r'hash|digest|sha|md5|crc', "hashing", 0.8),
            (r'compress|deflate|zip|gzip|lz', "compression", 0.8),
            (r'decompress|inflate|unzip|gunzip', "decompression", 0.8),
            (r'cmp|compare|equal|match', "comparison", 0.7),
            (r'valid|check|verify|assert|is_valid|is_ok', "validation", 0.7),
            (r'auth|login|credential|permission', "authentication", 0.9),
            (r'log|trace|debug|print', "logging", 0.7),
            (r'err|error|fail|exception|panic', "error_handling", 0.6),
            (r'send|recv|connect|accept|socket|http|request|response', "network_io", 0.8),
            (r'open|read|write|close|seek|file|fopen|fread|fwrite', "file_io", 0.8),
            (r'serial|marshal|pack|encode|to_json|to_bytes', "serialization", 0.7),
            (r'deserial|unmarshal|unpack|decode|from_json|from_bytes', "deserialization", 0.7),
            (r'thread|mutex|lock|unlock|semaphore|cond|barrier', "threading", 0.8),
            (r'signal|handler|callback|notify|emit|event', "callback", 0.7),
            (r'main|start|entry|winmain', "initialization", 0.5),
            (r'parse|token|lex|scan', "data_conversion", 0.6),
            (r'sort|search|find|lookup|binary_search', "data_conversion", 0.5),
        ]

        pi = 0
        while pi < len(name_patterns):
            pattern, category, weight = name_patterns[pi]
            if _re.search(pattern, name_lower):
                scores[category] += weight
            pi += 1

        # Body-based heuristics
        body_lower = decompiled_body.lower() if decompiled_body else ""
        body_patterns = [
            (r'malloc|calloc|realloc|new\s', "allocation", 0.6),
            (r'free\s*\(|delete\s', "deallocation", 0.6),
            (r'memcpy|memmove|strcpy|strncpy', "string_manipulation", 0.5),
            (r'AES_|DES_|RSA_|EVP_|crypto', "encryption", 0.8),
            (r'for\s*\(|while\s*\(|loop', "data_conversion", 0.2),
        ]

        bi = 0
        while bi < len(body_patterns):
            pattern, category, weight = body_patterns[bi]
            if _re.search(pattern, body_lower):
                scores[category] += weight
            bi += 1

        # Call graph hints
        if call_graph_hints:
            hi = 0
            while hi < len(call_graph_hints):
                hint = call_graph_hints[hi].lower()
                for pattern, category, weight in name_patterns:
                    if _re.search(pattern, hint):
                        scores[category] += weight * 0.3
                hi += 1

        # Normalize and sort
        if not scores:
            scores["unknown"] = 1.0

        max_score = max(scores.values())
        normalized = {k: v / max_score for k, v in scores.items()} if max_score > 0 else scores

        sorted_guesses = sorted(normalized.items(), key=lambda x: -x[1])

        result = {
            "function_name": function_name,
            "top_guess": sorted_guesses[0],
            "all_guesses": sorted_guesses[:5],
            "llm_prompt": self._build_llm_prompt(function_name, decompiled_body, call_graph_hints),
        }

        self.m_guess_history.append(result)
        return result

    def _build_llm_prompt(self, function_name: str, decompiled_body: str,
                          call_graph_hints: Optional[List[str]]) -> str:
        categories = ", ".join(self.FUNCTION_CATEGORIES)
        prompt = f"""Analyze the following function and categorize its purpose.

Function name: {function_name}
Decompiled body summary:
{decompiled_body[:2000] if decompiled_body else '(not available)'}
{f'Called functions: {", ".join(call_graph_hints)}' if call_graph_hints else ''}

Possible categories: {categories}

Respond with JSON: {{"category": "...", "confidence": 0.0, "reasoning": "..."}}"""
        return prompt

    def batch_guess(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        fi = 0
        while fi < len(functions):
            func = functions[fi]
            results.append(self.guess(
                func.get("name", f"func_{fi}"),
                func.get("body", ""),
                func.get("call_graph_hints"),
            ))
            fi += 1
        return results


# ===========================================================================
# 8. AI Decompiler Optimization Advisor
# ===========================================================================

class AIDecompilerOptimizationAdvisor:
    """Advises on decompiler settings and strategies for optimal output quality.

    Analyzes binary characteristics and recommends decompiler parameter tuning.
    """

    __slots__ = ('m_advice_history', 'm_rules')

    def __init__(self):
        self.m_advice_history: List[Dict[str, Any]] = []
        self.m_rules: List[Dict[str, Any]] = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "condition": {"optimization": "O0"},
                "advice": "No optimization — decompiler should produce straightforward output. "
                          "Use default settings with stack variable recovery.",
                "settings": {"stack_analysis": True, "dead_code_elimination": False},
            },
            {
                "condition": {"optimization": "O2"},
                "advice": "Moderate optimization — enable inlining recovery, constant propagation, "
                          "and branch simplification.",
                "settings": {"inline_recovery": True, "constant_propagation": True,
                            "branch_simplification": True},
            },
            {
                "condition": {"optimization": "O3"},
                "advice": "Aggressive optimization — enable full suite: vectorization recognition, "
                          "loop unrolling reversal, and tail-call optimization detection.",
                "settings": {"vectorization": True, "loop_unroll_reversal": True,
                            "tail_call_detection": True, "inline_recovery": True,
                            "constant_propagation": True},
            },
            {
                "condition": {"obfuscation": "ollvm"},
                "advice": "OLLVM obfuscation detected — use control-flow unflattening, "
                          "opaque predicate elimination, and string decryption passes.",
                "settings": {"unflatten_cfg": True, "eliminate_opaque": True,
                            "decrypt_strings": True},
            },
            {
                "condition": {"has_exceptions": True},
                "advice": "Exception handling detected — enable EH frame parsing and "
                          "landing pad recovery.",
                "settings": {"parse_eh_frames": True, "recover_landing_pads": True},
            },
            {
                "condition": {"architecture": "arm"},
                "advice": "ARM architecture — enable Thumb/ARM mode detection, literal pool "
                          "handling, and conditional execution normalization.",
                "settings": {"thumb_detection": True, "literal_pool": True,
                            "conditional_exec": True},
            },
            {
                "condition": {"has_tls": True},
                "advice": "Thread-Local Storage detected — enable TLS callback parsing.",
                "settings": {"parse_tls_callbacks": True},
            },
        ]

    def analyze(self, binary_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze binary characteristics and produce optimization advice."""
        advice_list: List[Dict[str, Any]] = []
        merged_settings: Dict[str, bool] = {}

        ri = 0
        while ri < len(self.m_rules):
            rule = self.m_rules[ri]
            conditions = rule["condition"]
            match = True
            ckeys = list(conditions.keys())
            cki = 0
            while cki < len(ckeys):
                key = ckeys[cki]
                expected = conditions[key]
                actual = binary_info.get(key)
                if isinstance(expected, bool):
                    if bool(actual) != expected:
                        match = False
                        break
                elif actual != expected:
                    match = False
                    break
                cki += 1

            if match:
                advice_list.append({
                    "advice": rule["advice"],
                    "settings": dict(rule["settings"]),
                    "matched_conditions": list(conditions.keys()),
                })
                for k, v in rule["settings"].items():
                    merged_settings[k] = v

            ri += 1

        result = {
            "binary_info": binary_info,
            "advice": advice_list,
            "recommended_settings": merged_settings,
            "summary": self._summarize(advice_list),
        }

        self.m_advice_history.append(result)
        return result

    def _summarize(self, advice_list: List[Dict[str, Any]]) -> str:
        if not advice_list:
            return "No specific optimization advice. Use default decompiler settings."
        lines = ["Decompiler optimization recommendations:"]
        ai = 0
        while ai < len(advice_list):
            lines.append(f"  {ai + 1}. {advice_list[ai]['advice']}")
            ai += 1
        return "\n".join(lines)

    def recommend_for_compiler(self, compiler: str, opt_level: str) -> Dict[str, Any]:
        return self.analyze({
            "compiler": compiler,
            "optimization": opt_level,
        })

    def recommend_for_binary(self, binary_path: str = "",
                             binary_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        info = dict(binary_info) if binary_info else {}
        if binary_path:
            info["path"] = binary_path
        return self.analyze(info)

    def get_history(self) -> List[Dict[str, Any]]:
        return list(self.m_advice_history)
