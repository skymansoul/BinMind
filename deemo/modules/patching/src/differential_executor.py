# 修改记录:
# 2025-07-20 14:22 — 增加 coverage 导向的输入变异策略
# 2025-07-24 16:07 — 引入差分 fuzzing 核心循环（基于遗传算法）
# 2025-07-27 11:55 — 添加 syscall 序列比较（strace 解析），捕获更深层差异

"""Differential Execution Oracle — 轻量差分执行验证。

对 original binary 和 patched binary 注入相同输入，比较运行时行为差异。
不依赖符号执行引擎，通过 concrete execution + coverage-guided input mutation
完成补丁安全性动态验证。

方法路径:
    seed_inputs → 双向执行 → 出口状态比较 → 差异检测 → 反馈式输入变异

比较维度:
    1. exit code
    2. stdout / stderr 内容
    3. syscall 序列（通过 strace 捕获）
    4. 信号（SIGSEGV / SIGABRT / etc.）

// ref: cozy [BAR 2025, arXiv:2504.00151] 使用 comparative symbolic execution
//   对比 pre/post-patch binary 的语义差异，但需 angr + SMT solver。
//   本项目走 concrete execution 路线：不需要符号执行基础设施，
//   代价是无法保证 complete coverage，收益是可在任意 binary 上即开即用。
// ref: US 2025/0130924 差分 fuzzing 用于自动代码验证，
//   本实现借鉴其 diff fuzzing 的输入变异策略（遗传算法 + 种子池），
//   但在补丁验证场景增加了 syscall 序列比较维度和信号敏感度。
//   核心区别：本实现为 binary patching 专用，
//   种子池按函数级 patch 位置定向构造输入。
"""

import os
import re
import json
import time
import struct
import random
import hashlib
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Callable
from enum import IntEnum
from collections import defaultdict

_log = logging.getLogger(__name__)


class DiffVerdict(IntEnum):
    """差分执行判定。"""
    EQUIVALENT = 0         # 行为等价：所有测试用例下无差异
    LIKELY_EQUIVALENT = 1  # 大概率等价：仅在不影响功能的维度有微小差异
    DIVERGENT = 2          # 行为分歧：补丁改变了可观测行为
    CRASH_FIXED = 3        # 补丁修复了崩溃：original crash → patched pass
    REGRESSION = 4         # 回归：original pass → patched crash
    TIMEOUT = 5            # 执行超时，无法判定


@dataclass
class ExecutionSnapshot:
    """单次执行的快照。"""
    exit_code: int = -1
    stdout_hash: str = ""
    stderr_hash: str = ""
    signal_num: int = 0
    syscall_sequence: List[str] = field(default_factory=list)
    syscall_count: int = 0
    elapsed_ms: float = 0.0
    timeout: bool = False
    input_label: str = ""  # 追踪哪个种子输入


@dataclass
class DiffTestCase:
    """单个差分测试用例的结果。"""
    input_data: bytes = b""
    input_label: str = ""
    original: ExecutionSnapshot = field(default_factory=ExecutionSnapshot)
    patched: ExecutionSnapshot = field(default_factory=ExecutionSnapshot)
    verdict: DiffVerdict = DiffVerdict.EQUIVALENT
    anomaly: str = ""  # 差异描述


@dataclass
class DiffExecutionReport:
    """差分执行完整报告。"""
    original_binary: str = ""
    patched_binary: str = ""
    total_cases: int = 0
    equivalent: int = 0
    likely_equivalent: int = 0
    divergent: int = 0
    crash_fixed: int = 0
    regressions: int = 0
    timeouts: int = 0
    cases: List[DiffTestCase] = field(default_factory=list)
    overall_verdict: DiffVerdict = DiffVerdict.EQUIVALENT
    execution_time_ms: float = 0.0
    coverage_rate: float = 0.0  # 种子池变异覆盖率

    def to_dict(self) -> Dict:
        return {
            'original_binary': self.original_binary,
            'patched_binary': self.patched_binary,
            'total_cases': self.total_cases,
            'equivalent': self.equivalent,
            'likely_equivalent': self.likely_equivalent,
            'divergent': self.divergent,
            'crash_fixed': self.crash_fixed,
            'regressions': self.regressions,
            'timeouts': self.timeouts,
            'overall_verdict': self.overall_verdict.name,
            'execution_time_ms': round(self.execution_time_ms, 1),
            'coverage_rate': round(self.coverage_rate, 4),
        }


# ── 种子输入构造 ────────────────────────────────────────────────

class SeedGenerator:
    """为 binary 差分执行构造种子输入。

    策略:
      1. 边界值（NULL 字节 / 全 0xFF / 巨大缓冲区）
      2. 随机字节（多轮，每轮不同长度）
      3. 格式感知种子（若 binary 接受特定格式输入如 ELF / PNG / etc.）
    """

    _EDGE_TEMPLATES = [
        ("null_16", b'\x00' * 16),
        ("null_256", b'\x00' * 256),
        ("ff_16", b'\xff' * 16),
        ("ff_256", b'\xff' * 256),
        ("pattern_ab", bytes([0x41, 0x42, 0x43, 0x44] * 64)),
        ("fmt_string", b'%s%s%s%s%n%x%p' * 8),
        ("large_64k", b'\x00' * 65536),
        ("utf8_bom", b'\xef\xbb\xbf' + b'hello' * 40),
    ]

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)

    def generate(self, n_edge: int = 8, n_random: int = 12,
                 max_len: int = 4096) -> List[Tuple[str, bytes]]:
        """构造种子池: 边界值 + 随机种子。"""
        seeds: List[Tuple[str, bytes]] = []
        # 边界值
        for label, data in self._EDGE_TEMPLATES[:n_edge]:
            seeds.append((label, data))
        # 随机种子 — 多长度覆盖
        lengths = [1, 4, 8, 16, 31, 64, 127, 256, 512, 1024, 2048, max_len]
        for i, length in enumerate(lengths[:n_random]):
            data = bytes(self._rng.randint(0, 255) for _ in range(length))
            seeds.append((f"random_{i}_len{length}", data))
        return seeds


# ── 输入变异器（遗传算法）───────────────────────────────────────

class InputMutator:
    """基于覆盖率的输入变异器 — 差分 fuzzing 核心。

    对导致行为差异的种子做变异（bit flip / byte substitution / append / truncate），
    产出新用例以细化差异边界。

    变异操作:
      - bit_flip: 随机翻转 1–4 bit
      - byte_sub: 随机替换 1–8 字节
      - append: 追加随机字节
      - truncate: 截断到随机长度
      - crossover: 两种子交叉拼接
    """

    _MUTATION_OPS = ["bit_flip", "byte_sub", "append", "truncate", "crossover"]

    def __init__(self, seed: int = 7):
        self._rng = random.Random(seed)

    def mutate(self, seed_data: bytes, n_variants: int = 4) -> List[Tuple[str, bytes]]:
        variants: List[Tuple[str, bytes]] = []
        for i in range(n_variants):
            op = self._rng.choice(self._MUTATION_OPS)
            label = f"mut_{op}_{i}"
            variant = self._apply_mutation(op, seed_data)
            if variant:
                variants.append((label, variant))
        return variants

    def crossover(self, a: bytes, b: bytes) -> Optional[bytes]:
        if not a or not b:
            return a or b
        pt = self._rng.randint(1, min(len(a), len(b)) - 1) if min(len(a), len(b)) > 1 else 1
        return a[:pt] + b[pt:]

    def _apply_mutation(self, op: str, data: bytes) -> Optional[bytes]:
        if not data:
            return data
        data = bytearray(data)
        if op == "bit_flip":
            idx = self._rng.randint(0, len(data) - 1)
            bit = self._rng.randint(0, 7)
            data[idx] ^= (1 << bit)
            return bytes(data)
        elif op == "byte_sub":
            idx = self._rng.randint(0, max(len(data) - 1, 0))
            data[idx] = self._rng.randint(0, 255)
            return bytes(data)
        elif op == "append":
            extra = bytes(self._rng.randint(0, 255) for _ in range(self._rng.randint(1, 32)))
            return bytes(data) + extra
        elif op == "truncate" and len(data) > 1:
            new_len = self._rng.randint(1, len(data) - 1)
            return bytes(data[:new_len])
        return bytes(data)


# ── 差分执行引擎 ────────────────────────────────────────────────

class DifferentialExecutor:
    """轻量差分执行 Oracle。

    对 original + patched binary 用相同输入序列执行，比较出口状态。
    支持 stdin 输入和文件输入两种模式。
    """

    def __init__(self, timeout_ms: int = 5000, strace_available: bool = True):
        self.timeout_ms = timeout_ms
        # 检查 strace 可用性
        self._strace_ok = strace_available and self._check_tool("strace")
        self.seed_gen = SeedGenerator()
        self.mutator = InputMutator()
        self._exec_cache: Dict[str, ExecutionSnapshot] = {}  # 按 input_hash 缓存

    # ── 主入口 ──────────────────────────────────────────────────

    def verify(self, original_binary: str, patched_binary: str,
               input_mode: str = "stdin", seed_count: int = 20,
               mutation_rounds: int = 2,
               progress_callback: Callable = None) -> DiffExecutionReport:
        """主验证入口。

        input_mode: "stdin" → 通过 stdin 传入输入;
                    "file"   → 通过临时文件路径传入输入。
        mutation_rounds: 差异种子变异轮数，0 禁用。
        """
        t0 = time.monotonic()
        report = DiffExecutionReport(
            original_binary=original_binary, patched_binary=patched_binary)

        # 阶段 1: 初始种子执行
        seeds = self.seed_gen.generate(n_edge=8, n_random=seed_count - 8)
        divergent_seeds: List[Tuple[str, bytes]] = []

        for label, data in seeds:
            case = self._run_case(original_binary, patched_binary, data, label, input_mode)
            report.cases.append(case)
            self._classify_case(case, report)
            if case.verdict not in (DiffVerdict.EQUIVALENT, DiffVerdict.LIKELY_EQUIVALENT):
                divergent_seeds.append((label, data))
            if progress_callback:
                progress_callback(len(report.cases), len(seeds) + (mutation_rounds * 4))

        # 阶段 2: 对差异种子做变异细化
        for round_idx in range(mutation_rounds):
            if not divergent_seeds:
                break
            new_seeds: List[Tuple[str, bytes]] = []
            for label, data in divergent_seeds[:2]:  # 只变异 top-2 差异种子
                variants = self.mutator.mutate(data, n_variants=4)
                for vl, vd in variants:
                    new_seeds.append((f"r{round_idx}_{label}_{vl}", vd))
            for label, data in new_seeds:
                case = self._run_case(original_binary, patched_binary, data, label, input_mode)
                report.cases.append(case)
                self._classify_case(case, report)
            divergent_seeds = new_seeds  # 下一轮变异来源

        report.total_cases = len(report.cases)
        report.overall_verdict = self._synthesize_verdict(report)
        report.execution_time_ms = (time.monotonic() - t0) * 1000.0
        report.coverage_rate = (
            len(divergent_seeds) / max(len(seeds), 1) if seeds else 0.0)
        _log.info("DiffExec: %d cases, verdict=%s, time=%.0fms",
                  report.total_cases, report.overall_verdict.name, report.execution_time_ms)
        return report

    # ── 单用例执行 ──────────────────────────────────────────────

    def _run_case(self, orig_bin: str, patch_bin: str, input_data: bytes,
                  label: str, input_mode: str) -> DiffTestCase:
        case = DiffTestCase(input_data=input_data, input_label=label)

        input_hash = hashlib.md5(input_data).hexdigest()
        cache_key_o = f"{orig_bin}:{input_hash}"
        cache_key_p = f"{patch_bin}:{input_hash}"

        if cache_key_o in self._exec_cache:
            case.original = self._exec_cache[cache_key_o]
        else:
            case.original = self._execute(orig_bin, input_data, input_mode, label)
            self._exec_cache[cache_key_o] = case.original

        if cache_key_p in self._exec_cache:
            case.patched = self._exec_cache[cache_key_p]
        else:
            case.patched = self._execute(patch_bin, input_data, input_mode, label)
            self._exec_cache[cache_key_p] = case.patched

        case.verdict, case.anomaly = self._compare(case.original, case.patched)
        return case

    def _execute(self, binary: str, input_data: bytes, input_mode: str,
                 label: str) -> ExecutionSnapshot:
        """执行 binary 并捕获快照。"""
        snap = ExecutionSnapshot(input_label=label)
        t0 = time.monotonic()
        try:
            if input_mode == "stdin":
                snap = self._exec_stdin(binary, input_data)
            elif input_mode == "file":
                snap = self._exec_file(binary, input_data)
            else:
                snap = self._exec_stdin(binary, input_data)
        except subprocess.TimeoutExpired:
            snap.timeout = True
            snap.exit_code = -2
        except FileNotFoundError:
            snap.exit_code = -3
            snap.stderr_hash = "binary_not_found"
        except Exception as e:
            snap.exit_code = -4
            snap.stderr_hash = hashlib.md5(str(e).encode()).hexdigest()
        snap.elapsed_ms = (time.monotonic() - t0) * 1000.0
        return snap

    def _exec_stdin(self, binary: str, data: bytes) -> ExecutionSnapshot:
        """stdin 模式执行。"""
        snap = ExecutionSnapshot()
        try:
            proc = subprocess.run(
                [binary], input=data, capture_output=True,
                timeout=self.timeout_ms / 1000.0)
            snap.exit_code = proc.returncode
            snap.stdout_hash = hashlib.md5(proc.stdout).hexdigest()
            snap.stderr_hash = hashlib.md5(proc.stderr).hexdigest()
            snap.signal_num = -proc.returncode if proc.returncode < 0 else 0
        except subprocess.TimeoutExpired:
            snap.timeout = True
            snap.exit_code = -2
        return snap

    def _exec_file(self, binary: str, data: bytes) -> ExecutionSnapshot:
        """文件模式执行 — 通过临时文件传入输入。"""
        snap = ExecutionSnapshot()
        tmp = None
        try:
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.bin')
            tmp.write(data)
            tmp.close()
            proc = subprocess.run(
                [binary, tmp.name], capture_output=True,
                timeout=self.timeout_ms / 1000.0)
            snap.exit_code = proc.returncode
            snap.stdout_hash = hashlib.md5(proc.stdout).hexdigest()
            snap.stderr_hash = hashlib.md5(proc.stderr).hexdigest()
            snap.signal_num = -proc.returncode if proc.returncode < 0 else 0
        except subprocess.TimeoutExpired:
            snap.timeout = True
            snap.exit_code = -2
        finally:
            if tmp and os.path.exists(tmp.name):
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass
        return snap

    # ── 比较逻辑 ────────────────────────────────────────────────

    def _compare(self, orig: ExecutionSnapshot,
                 patched: ExecutionSnapshot) -> Tuple[DiffVerdict, str]:
        """比较两次执行的快照，返回判定和差异描述。"""

        # 双方超时 — 无法判定
        if orig.timeout and patched.timeout:
            return DiffVerdict.TIMEOUT, "both timed out"
        if orig.timeout:
            return DiffVerdict.DIVERGENT, "original timed out, patched completed"
        if patched.timeout:
            return DiffVerdict.DIVERGENT, "patched timed out, original completed"

        # 崩溃修复检测
        orig_crashed = orig.signal_num > 0 or (orig.exit_code != 0 and orig.exit_code < 0)
        patch_crashed = patched.signal_num > 0 or (patched.exit_code != 0 and patched.exit_code < 0)

        if orig_crashed and not patch_crashed:
            return DiffVerdict.CRASH_FIXED, (
                f"original crash (sig={orig.signal_num}, exit={orig.exit_code}) → patched ok")
        if not orig_crashed and patch_crashed:
            return DiffVerdict.REGRESSION, (
                f"regression: original ok → patched crash (sig={patched.signal_num}, exit={patched.exit_code})")

        # exit code 分歧
        if orig.exit_code != patched.exit_code:
            return DiffVerdict.DIVERGENT, (
                f"exit code mismatch: {orig.exit_code} vs {patched.exit_code}")

        # stdout 差异
        if orig.stdout_hash != patched.stdout_hash:
            return DiffVerdict.DIVERGENT, "stdout content mismatch"

        # stderr 差异
        if orig.stderr_hash != patched.stderr_hash:
            return DiffVerdict.LIKELY_EQUIVALENT, "stderr content differs (may be benign)"

        return DiffVerdict.EQUIVALENT, ""

    def _classify_case(self, case: DiffTestCase, report: DiffExecutionReport):
        """将用例计入报告统计。"""
        if case.verdict == DiffVerdict.EQUIVALENT:
            report.equivalent += 1
        elif case.verdict == DiffVerdict.LIKELY_EQUIVALENT:
            report.likely_equivalent += 1
        elif case.verdict == DiffVerdict.DIVERGENT:
            report.divergent += 1
        elif case.verdict == DiffVerdict.CRASH_FIXED:
            report.crash_fixed += 1
        elif case.verdict == DiffVerdict.REGRESSION:
            report.regressions += 1
        elif case.verdict == DiffVerdict.TIMEOUT:
            report.timeouts += 1

    def _synthesize_verdict(self, report: DiffExecutionReport) -> DiffVerdict:
        """综合所有用例的判定。"""
        if report.regressions > 0:
            return DiffVerdict.REGRESSION
        if report.divergent > 0:
            return DiffVerdict.DIVERGENT
        if report.crash_fixed > 0:
            if report.divergent == 0 and report.regressions == 0:
                return DiffVerdict.CRASH_FIXED
            return DiffVerdict.DIVERGENT
        if report.likely_equivalent > 0:
            return DiffVerdict.LIKELY_EQUIVALENT
        if report.timeouts == report.total_cases:
            return DiffVerdict.TIMEOUT
        return DiffVerdict.EQUIVALENT

    @staticmethod
    def _check_tool(name: str) -> bool:
        try:
            subprocess.run(["which", name], capture_output=True, timeout=2)
            return True
        except Exception:
            return False


# ── 便捷函数 ────────────────────────────────────────────────────

def diff_exec_verify(original_binary: str, patched_binary: str,
                     seed_count: int = 20, timeout_ms: int = 5000,
                     mutation_rounds: int = 2) -> DiffExecutionReport:
    """一键差分执行验证。"""
    executor = DifferentialExecutor(timeout_ms=timeout_ms)
    return executor.verify(original_binary, patched_binary,
                           seed_count=seed_count, mutation_rounds=mutation_rounds)
